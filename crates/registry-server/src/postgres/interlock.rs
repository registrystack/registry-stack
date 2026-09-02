// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeSet, time::Duration};

use registry_platform_audit::AuditProfile;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
#[cfg(feature = "postgres-test")]
use tokio_postgres::NoTls;
use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;

use crate::audit::append_envelope;
use crate::event_destination::EventDestinationCompatibilityInventory;
use crate::generated_ddl::DdlStatementKind;
use crate::history_commit::{install_empty_history_baseline, install_history_commit_schema};
use crate::history_migration::{
    ensure_successor_history_ready as ensure_successor_history_ready_state,
    finish_bounded_history_update, prepare_bounded_history_update,
};
use crate::history_schema::HistorySchemaDescriptor;
use crate::history_store::{install_history_schema_store, retain_descriptor};
use crate::migration_plan::{
    AffectedRowBounds, ReviewedMigrationStepDescriptor, ValidatedReviewedMigrationAssertion,
    ValidatedReviewedMigrationPlan, ValidatedReviewedMigrationStep,
};
use crate::model::CompiledRegistry;
use crate::mutation::install_mutation_schema;
use crate::package::CompiledRegistryMigrationBaseline;

use super::{
    catalog::{install_registry_state_schema, verify_managed_catalog, ExpectedManagedCatalog},
    config::ConnectionTls,
    migration_ledger::{
        migration_phase_state, reconcile_migration_ledger_metadata_only_constraints,
        record_applied, record_chunk_progress, record_failed, record_postconditions_complete,
        record_preconditions_complete, record_started, record_step_complete, statement_checksum,
        step_progress, verify_resumable, MigrationLedgerEntry, MigrationLedgerStep,
        MigrationLedgerStepKind,
    },
    schema::{
        execute_compiled_ddl_statement, is_spatial_candidate_view_drop_sql,
        is_spatial_candidate_view_sql, reconcile_compiled_runtime_acl,
    },
    verify_btree_gist, verify_migration_role, verify_postgis, ConnectionConfig,
    ExpectedRegistryIdentity, PostgresKernelError, Result, SqlIdentifier,
};

// These defense-in-depth bounds match the verified package manifest envelope:
// at most 1,024 migration statements inside at most 4 MiB of manifest bytes.
const MAX_VERIFIED_DDL_STATEMENTS: usize = 1024;
const MAX_VERIFIED_DDL_STATEMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_VERIFIED_DDL_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// The finding reported when the live managed schema fingerprint differs from
/// the one an expected package binds. Activation verification signals that
/// mismatch as an unavailable Registry, which carries no wording of its own.
const SCHEMA_FINGERPRINT_FINDING: &str =
    "managed schema fingerprint differs from the expected package";

/// One chained audit record appended inside the same transaction as the
/// maintenance transition it records, so a committed transition can never be
/// missing from the journal.
pub(crate) struct MaintenanceAuditRecord<'a> {
    pub profile: &'a AuditProfile,
    pub record: Value,
}

/// The durable ledger row one maintenance transition records, together with
/// the exact catalog and roles it verifies in the same transaction.
pub(crate) struct MaintenanceTransition<'a> {
    pub ledger: &'a MigrationLedgerEntry,
    pub expected_catalog: &'a ExpectedManagedCatalog,
    pub migration_role: &'a SqlIdentifier,
    pub runtime_role: &'a SqlIdentifier,
}

/// The durable maintenance state of the singleton Registry state row, read
/// under the exclusive apply lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MaintenanceSnapshot {
    pub identity: ExpectedRegistryIdentity,
    pub maintenance_status: String,
    pub maintenance_target_revision: Option<String>,
}

/// How far a reviewed plan durably progressed for one pinned target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReviewedMigrationProgress {
    /// Every precondition, step, and postcondition the ledger binds completed.
    pub closed: bool,
    /// At least one step committed rows, a checkpoint, or its completion.
    pub durable_step_progress: bool,
}

pub(crate) struct PackageDdlStatement<'a> {
    pub sql: &'a str,
    pub checksum: &'a str,
    pub kind: DdlStatementKind,
    pub ordinal: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewedExecutionOutcome {
    Complete,
    Interrupted,
}

pub(crate) struct ReviewedPackageExecutionRequest<'a> {
    pub registry: &'a CompiledRegistry,
    pub current: &'a ExpectedRegistryIdentity,
    pub target_package_revision: &'a str,
    pub plan: &'a ValidatedReviewedMigrationPlan,
    pub predecessor_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
    pub predecessor_history_descriptor: Option<&'a HistorySchemaDescriptor>,
    pub runtime_role: &'a SqlIdentifier,
    pub compiler_statements: &'a [PackageDdlStatement<'a>],
    pub ledger: &'a MigrationLedgerEntry,
    pub prior_tables: &'a [String],
    pub candidate_tables: &'a [String],
    pub compiler_lock_timeout: Duration,
    pub compiler_statement_timeout: Duration,
    pub fault_after_committed_chunks: Option<u64>,
}

struct ReviewedChunkExecutionRequest<'a> {
    step: &'a ValidatedReviewedMigrationStep,
    ledger: &'a MigrationLedgerEntry,
    ledger_step: &'a MigrationLedgerStep,
    table: &'a str,
    chunk_size: u32,
    max_total_rows: u64,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
}

/// Stable Registry-scoped PostgreSQL advisory lock key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryLockKey(i64);

impl RegistryLockKey {
    pub fn derive(registry_id: &str) -> Result<Self> {
        if registry_id.is_empty() || registry_id.len() > 255 {
            return Err(PostgresKernelError::Configuration(
                "Registry id is missing or outside its bound",
            ));
        }
        let digest =
            Sha256::digest([b"registry-server/advisory-lock/v1/", registry_id.as_bytes()].concat());
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        Ok(Self(i64::from_be_bytes(bytes)))
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

/// One unpooled connection holding the session-level exclusive apply lock.
pub struct DedicatedApplyConnection {
    client: Client,
    connection_task: JoinHandle<()>,
    lock_key: RegistryLockKey,
    locked: bool,
    verified_migration_role: bool,
    migration_role: Option<SqlIdentifier>,
}

impl DedicatedApplyConnection {
    #[cfg(feature = "postgres-test")]
    pub async fn acquire(
        config: &ConnectionConfig,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
    ) -> Result<Self> {
        Self::acquire_inner(config, lock_key, lock_timeout, None, None).await
    }

    /// Acquires the product apply connection only after proving that it uses
    /// the exact configured migration role. Role verification deliberately
    /// precedes the maintenance transition, control-plane bootstrap, and DDL.
    pub(crate) async fn acquire_for_verified_package(
        config: &ConnectionConfig,
        lock_key: RegistryLockKey,
        migration_role: &SqlIdentifier,
        lock_timeout: Duration,
        statement_timeout: Duration,
    ) -> Result<Self> {
        Self::acquire_inner(
            config,
            lock_key,
            lock_timeout,
            Some(migration_role),
            Some(statement_timeout),
        )
        .await
    }

    pub(crate) fn client_for_request_retention_guard(&self) -> &Client {
        &self.client
    }

    async fn acquire_inner(
        config: &ConnectionConfig,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        migration_role: Option<&SqlIdentifier>,
        statement_timeout: Option<Duration>,
    ) -> Result<Self> {
        validate_timeout(
            lock_timeout,
            Duration::from_secs(300),
            "apply lock timeout must be between 1 millisecond and 5 minutes",
        )?;
        if let Some(timeout) = statement_timeout {
            validate_timeout(
                timeout,
                MAX_VERIFIED_DDL_STATEMENT_TIMEOUT,
                "verified DDL statement timeout must be between 1 millisecond and 1 hour",
            )?;
        }
        let (client, connection_task) = connect_dedicated(config).await?;
        if let Some(role) = migration_role {
            verify_migration_role(&client, role).await?;
        }
        client
            .execute(
                "SELECT pg_catalog.set_config('search_path',
                         'pg_catalog, registry_internal, registry_data, pg_temp', false)",
                &[],
            )
            .await?;
        set_session_timeout(&client, "lock_timeout", lock_timeout).await?;
        if let Some(timeout) = statement_timeout {
            set_session_timeout(&client, "statement_timeout", timeout).await?;
        }
        client
            .execute("SELECT pg_catalog.pg_advisory_lock($1)", &[&lock_key.get()])
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        Ok(Self {
            client,
            connection_task,
            lock_key,
            locked: true,
            verified_migration_role: migration_role.is_some(),
            migration_role: migration_role.cloned(),
        })
    }

    /// Executes already package-verified DDL atomically while retaining the
    /// dedicated session-level apply lock.
    #[cfg(any(test, feature = "postgres-test"))]
    #[allow(dead_code)]
    pub(crate) async fn execute_verified_ddl(
        &mut self,
        statements: &[&str],
        statement_timeout: Duration,
    ) -> Result<()> {
        validate_verified_ddl_request(self.locked, statements, statement_timeout)?;
        let transaction = self.client.transaction().await?;
        let timeout_millis = u64::try_from(statement_timeout.as_millis()).map_err(|_| {
            PostgresKernelError::Configuration(
                "verified DDL statement timeout is outside PostgreSQL bounds",
            )
        })?;
        transaction
            .execute(
                "SELECT set_config('statement_timeout', $1, true)",
                &[&format!("{timeout_millis}ms")],
            )
            .await?;
        for statement in statements {
            if transaction.batch_execute(statement).await.is_err() {
                transaction.rollback().await?;
                return Err(PostgresKernelError::Connection);
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Executes only the ordered, checksum-bound successor statements carried
    /// by a verified package. No caller SQL enters this path.
    pub(crate) async fn execute_successor_package_ddl(
        &mut self,
        statements: &[PackageDdlStatement<'_>],
        runtime_role: &SqlIdentifier,
        statement_timeout: Duration,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        validate_package_ddl(statements, statement_timeout)?;
        let transaction = self.client.transaction().await?;
        set_local_statement_timeout(&transaction, statement_timeout).await?;
        for statement in statements {
            validate_statement_checksum(statement)?;
            if execute_compiled_ddl_statement(
                &transaction,
                statement.sql,
                statement.kind,
                runtime_role,
            )
            .await
            .is_err()
            {
                transaction.rollback().await?;
                return Err(PostgresKernelError::Connection);
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Executes the AST-validated reviewed plan and only its package-derived
    /// compiler DDL. Every durable checkpoint is committed with the exact
    /// chunk update that advances it.
    pub(crate) async fn execute_reviewed_package_plan(
        &mut self,
        request: ReviewedPackageExecutionRequest<'_>,
    ) -> Result<ReviewedExecutionOutcome> {
        let ReviewedPackageExecutionRequest {
            registry,
            current,
            target_package_revision,
            plan,
            predecessor_baseline,
            predecessor_history_descriptor,
            runtime_role,
            compiler_statements,
            ledger,
            prior_tables,
            candidate_tables,
            compiler_lock_timeout,
            compiler_statement_timeout,
            fault_after_committed_chunks,
        } = request;
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        ledger.validate()?;
        if plan.migrations().is_empty() {
            return Err(PostgresKernelError::RegistryUnavailable);
        }

        self.ensure_successor_history_ready(
            current,
            predecessor_baseline,
            predecessor_history_descriptor,
            runtime_role,
        )
        .await?;

        self.execute_reviewed_assertion_phase(plan, ledger, prior_tables, false)
            .await?;
        self.execute_reviewed_compiler_steps(
            compiler_statements,
            ledger,
            compiler_lock_timeout,
            compiler_statement_timeout,
            false,
            runtime_role,
        )
        .await?;
        let refresh_views = compiler_statements.iter().any(|statement| {
            statement.kind == DdlStatementKind::View
                && !is_spatial_candidate_view_sql(statement.sql)
        });
        let post_manual_compiler_steps = compiler_statements
            .iter()
            .any(|statement| compiler_statement_runs_after_reviewed_steps(statement));
        if refresh_views {
            self.drop_managed_read_views(compiler_lock_timeout, compiler_statement_timeout)
                .await?;
        }

        let mut committed_chunks = 0_u64;
        for (migration_index, migration) in plan.migrations().iter().enumerate() {
            let migration_ordinal = i32::try_from(migration_index + 1)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            for (step_index, step) in migration.steps.iter().enumerate() {
                let step_ordinal = i32::try_from(step_index)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
                let ledger_step = ledger_step(ledger, migration_ordinal, step_ordinal)?;
                match &step.descriptor {
                    ReviewedMigrationStepDescriptor::TransactionalSql { affected_rows, .. } => {
                        if ledger_step.kind != MigrationLedgerStepKind::TransactionalSql {
                            return Err(PostgresKernelError::RegistryUnavailable);
                        }
                        self.execute_reviewed_transactional_step(
                            registry,
                            target_package_revision,
                            &migration.descriptor_path,
                            step,
                            affected_rows.as_ref(),
                            ledger,
                            ledger_step,
                            migration.descriptor.lock_timeout_ms,
                            migration.descriptor.statement_timeout_ms,
                        )
                        .await?;
                    }
                    ReviewedMigrationStepDescriptor::ChunkedBackfill {
                        entity_id,
                        chunk_size,
                        max_total_rows,
                        lock_timeout_ms,
                        statement_timeout_ms,
                        ..
                    } => {
                        if ledger_step.kind != MigrationLedgerStepKind::ChunkedBackfill {
                            return Err(PostgresKernelError::RegistryUnavailable);
                        }
                        let table = &registry
                            .entities()
                            .get(entity_id)
                            .ok_or(PostgresKernelError::RegistryUnavailable)?
                            .physical_table;
                        loop {
                            let advanced = self
                                .execute_reviewed_chunk(ReviewedChunkExecutionRequest {
                                    step,
                                    ledger,
                                    ledger_step,
                                    table,
                                    chunk_size: *chunk_size,
                                    max_total_rows: *max_total_rows,
                                    lock_timeout_ms: *lock_timeout_ms,
                                    statement_timeout_ms: *statement_timeout_ms,
                                })
                                .await?;
                            if !advanced {
                                break;
                            }
                            committed_chunks = committed_chunks
                                .checked_add(1)
                                .ok_or(PostgresKernelError::RegistryUnavailable)?;
                            if fault_after_committed_chunks == Some(committed_chunks) {
                                return Ok(ReviewedExecutionOutcome::Interrupted);
                            }
                        }
                    }
                }
            }
        }

        if post_manual_compiler_steps {
            self.execute_reviewed_compiler_steps(
                compiler_statements,
                ledger,
                compiler_lock_timeout,
                compiler_statement_timeout,
                true,
                runtime_role,
            )
            .await?;
        }
        self.execute_reviewed_assertion_phase(plan, ledger, candidate_tables, true)
            .await?;
        Ok(ReviewedExecutionOutcome::Complete)
    }

    async fn execute_reviewed_assertion_phase(
        &mut self,
        plan: &ValidatedReviewedMigrationPlan,
        ledger: &MigrationLedgerEntry,
        tables: &[String],
        postconditions: bool,
    ) -> Result<()> {
        let transaction = self.client.transaction().await?;
        let phase = migration_phase_state(&transaction, ledger).await?;
        if if postconditions {
            phase.postconditions_complete
        } else {
            phase.preconditions_complete
        } {
            transaction.commit().await?;
            return Ok(());
        }
        if postconditions && !phase.preconditions_complete {
            return Err(PostgresKernelError::RegistryUnavailable);
        }

        let first = plan
            .migrations()
            .first()
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        set_local_migration_timeouts(
            &transaction,
            first.descriptor.lock_timeout_ms,
            first.descriptor.statement_timeout_ms,
        )
        .await?;
        set_force_row_security(&transaction, tables, false).await?;
        for migration in plan.migrations() {
            set_local_migration_timeouts(
                &transaction,
                migration.descriptor.lock_timeout_ms,
                migration.descriptor.statement_timeout_ms,
            )
            .await?;
            let assertions = if postconditions {
                &migration.post_assertions
            } else {
                &migration.pre_assertions
            };
            for assertion in assertions {
                execute_boolean_assertion(&transaction, assertion).await?;
            }
        }
        set_force_row_security(&transaction, tables, true).await?;
        if postconditions {
            record_postconditions_complete(&transaction, ledger).await?;
        } else {
            record_preconditions_complete(&transaction, ledger).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn execute_reviewed_compiler_steps(
        &mut self,
        statements: &[PackageDdlStatement<'_>],
        ledger: &MigrationLedgerEntry,
        lock_timeout: Duration,
        statement_timeout: Duration,
        views: bool,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        validate_timeout(
            lock_timeout,
            Duration::from_secs(300),
            "compiler DDL lock timeout is outside its bound",
        )?;
        validate_timeout(
            statement_timeout,
            MAX_VERIFIED_DDL_STATEMENT_TIMEOUT,
            "compiler DDL statement timeout is outside its bound",
        )?;
        for statement in statements
            .iter()
            .filter(|statement| compiler_statement_runs_after_reviewed_steps(statement) == views)
        {
            validate_statement_checksum(statement)?;
            let ledger_step = ledger_step(ledger, 0, statement.ordinal)?;
            if ledger_step.kind != MigrationLedgerStepKind::CompilerDdl
                || ledger_step.checksum != statement.checksum
            {
                return Err(PostgresKernelError::RegistryUnavailable);
            }
            let transaction = self.client.transaction().await?;
            set_local_duration_timeouts(&transaction, lock_timeout, statement_timeout).await?;
            let complete = step_progress(&transaction, ledger, ledger_step)
                .await?
                .complete;
            let rerun_when_complete = views
                && statement.kind == DdlStatementKind::View
                && !is_spatial_candidate_view_sql(statement.sql);
            if complete && !rerun_when_complete {
                transaction.commit().await?;
                continue;
            }
            execute_compiled_ddl_statement(
                &transaction,
                statement.sql,
                statement.kind,
                runtime_role,
            )
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
            if !complete {
                record_step_complete(&transaction, ledger, ledger_step, 0).await?;
            }
            transaction.commit().await?;
        }
        Ok(())
    }

    async fn drop_managed_read_views(
        &mut self,
        lock_timeout: Duration,
        statement_timeout: Duration,
    ) -> Result<()> {
        // These two schemas are a closed compiler-owned boundary. Reviewed
        // column changes may require their dependent views to be removed
        // first; exact package DDL recreates every candidate view afterward.
        let transaction = self.client.transaction().await?;
        set_local_duration_timeouts(&transaction, lock_timeout, statement_timeout).await?;
        let rows = transaction
            .query(
                "SELECT schemaname, viewname
                   FROM pg_catalog.pg_views
                  WHERE schemaname IN ('registry_derived', 'registry_source')
                  ORDER BY CASE schemaname WHEN 'registry_derived' THEN 0 ELSE 1 END,
                           viewname",
                &[],
            )
            .await?;
        for row in rows {
            let schema = row
                .try_get::<_, String>(0)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            let view = row
                .try_get::<_, String>(1)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            if !matches!(schema.as_str(), "registry_derived" | "registry_source") {
                return Err(PostgresKernelError::RegistryUnavailable);
            }
            let schema = SqlIdentifier::parse(&schema)?;
            let view = SqlIdentifier::parse(&view)?;
            transaction
                .batch_execute(&format!(
                    "DROP VIEW {}.{} RESTRICT",
                    schema.quoted(),
                    view.quoted()
                ))
                .await
                .map_err(|_| PostgresKernelError::Connection)?;
        }
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // The ledger and history use distinct verified bindings.
    async fn execute_reviewed_transactional_step(
        &mut self,
        registry: &CompiledRegistry,
        target_package_revision: &str,
        descriptor_path: &str,
        step: &ValidatedReviewedMigrationStep,
        affected_bounds: Option<&AffectedRowBounds>,
        ledger: &MigrationLedgerEntry,
        ledger_step: &MigrationLedgerStep,
        lock_timeout_ms: u64,
        statement_timeout_ms: u64,
    ) -> Result<()> {
        if step.sha256 != statement_checksum(&step.sql) || ledger_step.checksum != step.sha256 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        let transaction = self.client.transaction().await?;
        set_local_migration_timeouts(&transaction, lock_timeout_ms, statement_timeout_ms).await?;
        if step_progress(&transaction, ledger, ledger_step)
            .await?
            .complete
        {
            transaction.commit().await?;
            return Ok(());
        }

        let affected = if let Some(bounds) = affected_bounds {
            let tables = step_tables(step)?;
            set_force_row_security(&transaction, &tables, false).await?;
            let history_capture =
                prepare_bounded_history_update(&transaction, registry, descriptor_path, step)
                    .await
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            let affected = transaction
                .execute(&step.sql, &[])
                .await
                .map_err(|_| PostgresKernelError::Connection)?;
            if affected < bounds.min || affected > bounds.max {
                return Err(PostgresKernelError::RegistryUnavailable);
            }
            finish_bounded_history_update(
                &transaction,
                registry,
                target_package_revision,
                history_capture,
            )
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            set_force_row_security(&transaction, &tables, true).await?;
            affected
        } else {
            transaction
                .batch_execute(&step.sql)
                .await
                .map_err(|_| PostgresKernelError::Connection)?;
            0
        };
        record_step_complete(&transaction, ledger, ledger_step, affected).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn execute_reviewed_chunk(
        &mut self,
        request: ReviewedChunkExecutionRequest<'_>,
    ) -> Result<bool> {
        let ReviewedChunkExecutionRequest {
            step,
            ledger,
            ledger_step,
            table,
            chunk_size,
            max_total_rows,
            lock_timeout_ms,
            statement_timeout_ms,
        } = request;
        if step.sha256 != statement_checksum(&step.sql)
            || ledger_step.checksum != step.sha256
            || chunk_size == 0
            || max_total_rows == 0
        {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        let table = SqlIdentifier::parse(table)?;
        let transaction = self.client.transaction().await?;
        set_local_migration_timeouts(&transaction, lock_timeout_ms, statement_timeout_ms).await?;
        let progress = step_progress(&transaction, ledger, ledger_step).await?;
        if progress.complete {
            transaction.commit().await?;
            return Ok(false);
        }
        if progress.affected_rows > max_total_rows {
            return Err(PostgresKernelError::RegistryUnavailable);
        }

        set_force_row_security(&transaction, &[table.as_str().to_owned()], false).await?;
        let limit = i64::from(chunk_size);
        let select_sql = format!(
            "SELECT record_id
             FROM registry_data.{}
             WHERE ($1::pg_catalog.uuid IS NULL OR record_id > $1)
             ORDER BY record_id
             LIMIT $2
             FOR UPDATE",
            table.quoted()
        );
        let rows = transaction
            .query(&select_sql, &[&progress.checkpoint_record_id, &limit])
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        let ids = rows
            .iter()
            .map(|row| row.try_get::<_, Uuid>(0))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        if ids.is_empty() {
            set_force_row_security(&transaction, &[table.as_str().to_owned()], true).await?;
            record_step_complete(&transaction, ledger, ledger_step, progress.affected_rows).await?;
            transaction.commit().await?;
            return Ok(false);
        }
        let selected =
            u64::try_from(ids.len()).map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        let total = progress
            .affected_rows
            .checked_add(selected)
            .filter(|total| *total <= max_total_rows)
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        let affected = transaction
            .execute(&step.sql, &[&ids])
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        set_force_row_security(&transaction, &[table.as_str().to_owned()], true).await?;
        if affected != selected {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        let checkpoint = ids
            .last()
            .copied()
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        record_chunk_progress(&transaction, ledger, ledger_step, checkpoint, total).await?;
        transaction.commit().await?;
        Ok(true)
    }

    /// Installs the product-owned mutation tables and every compiler-produced
    /// initial DDL statement in one bounded transaction. The state and ledger
    /// control plane has already been committed before this method begins.
    pub(crate) async fn execute_initial_package_ddl(
        &mut self,
        registry: &CompiledRegistry,
        package_revision: &str,
        statements: &[PackageDdlStatement<'_>],
        runtime_role: &SqlIdentifier,
        statement_timeout: Duration,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        validate_package_ddl(statements, statement_timeout)?;
        if statements.len() != registry.ddl().statements.len()
            || statements
                .iter()
                .zip(&registry.ddl().statements)
                .any(|(package, compiled)| package.sql != compiled.sql)
        {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        let transaction = self.client.transaction().await?;
        set_local_statement_timeout(&transaction, statement_timeout).await?;
        verify_compiled_prerequisites_for_client(
            &transaction,
            registry,
            self.migration_role
                .as_ref()
                .ok_or(PostgresKernelError::RegistryUnavailable)?,
            runtime_role,
        )
        .await?;
        install_mutation_schema(&transaction, runtime_role)
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        install_history_schema_store(&transaction, runtime_role)
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        install_history_commit_schema(&transaction, runtime_role)
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        let mut spatial_candidate_view_statements = Vec::new();
        for (statement, compiled) in statements.iter().zip(&registry.ddl().statements) {
            validate_statement_checksum(statement)?;
            // The two managed schemas are administrator-provisioned and owned
            // by the migration role before apply. Requiring database CREATE
            // here would violate that role boundary, so the exact compiler
            // schema statement is checksum-validated above but not rerun.
            if compiled.kind == DdlStatementKind::Schema {
                continue;
            }
            if is_spatial_candidate_view_sql(statement.sql) {
                spatial_candidate_view_statements.push(statement);
                continue;
            }
            if execute_compiled_ddl_statement(
                &transaction,
                statement.sql,
                statement.kind,
                runtime_role,
            )
            .await
            .is_err()
            {
                transaction.rollback().await?;
                return Err(PostgresKernelError::Connection);
            }
        }
        for statement in spatial_candidate_view_statements {
            if execute_compiled_ddl_statement(
                &transaction,
                statement.sql,
                statement.kind,
                runtime_role,
            )
            .await
            .is_err()
            {
                transaction.rollback().await?;
                return Err(PostgresKernelError::Connection);
            }
        }
        reconcile_compiled_runtime_acl(&transaction, registry, runtime_role).await?;
        retain_descriptor(&transaction, registry, package_revision)
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        for table in &registry.ddl().tables {
            let table_name = SqlIdentifier::parse(&table.physical_name)?;
            let row = transaction
                .query_one(
                    &format!(
                        "SELECT count(*)::bigint FROM registry_data.{}",
                        table_name.quoted()
                    ),
                    &[],
                )
                .await?;
            if row.get::<_, i64>(0) != 0 {
                return Err(PostgresKernelError::RegistryUnavailable);
            }
        }
        install_empty_history_baseline(&transaction, package_revision)
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Establishes or verifies successor history readiness while the durable
    /// maintenance boundary and dedicated session-level apply lock are held.
    pub(crate) async fn ensure_successor_history_ready(
        &mut self,
        current: &ExpectedRegistryIdentity,
        predecessor_baseline: Option<&CompiledRegistryMigrationBaseline>,
        predecessor_history_descriptor: Option<&HistorySchemaDescriptor>,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        let transaction = self.client.transaction().await?;
        let predecessor_tables = predecessor_baseline
            .map(|baseline| {
                baseline
                    .entities
                    .values()
                    .map(|entity| entity.physical_table.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !predecessor_tables.is_empty() {
            set_force_row_security(&transaction, &predecessor_tables, false).await?;
        }
        let readiness = ensure_successor_history_ready_state(
            &transaction,
            current,
            predecessor_baseline,
            predecessor_history_descriptor,
            runtime_role,
        )
        .await;
        if !predecessor_tables.is_empty() {
            set_force_row_security(&transaction, &predecessor_tables, true).await?;
        }
        readiness.map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Retains the target package history descriptor before the target can be
    /// made ready, including exact-target recovery paths where DDL already ran.
    pub(crate) async fn retain_target_history_descriptor(
        &mut self,
        registry: &CompiledRegistry,
        package_revision: &str,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        let transaction = self.client.transaction().await?;
        retain_descriptor(&transaction, registry, package_revision)
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn verify_compiled_prerequisites(
        &self,
        registry: &CompiledRegistry,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        verify_compiled_prerequisites_for_client(
            &self.client,
            registry,
            self.migration_role
                .as_ref()
                .ok_or(PostgresKernelError::RegistryUnavailable)?,
            runtime_role,
        )
        .await
    }

    /// Reconciles the exact compiler-owned runtime ACL inventory while the
    /// dedicated session-level apply lock remains held.
    pub(crate) async fn reconcile_runtime_acl(
        &mut self,
        registry: &CompiledRegistry,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        validate_runtime_acl_reconciliation_request(self.locked)?;
        let transaction = self.client.transaction().await?;
        install_mutation_schema(&transaction, runtime_role)
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        reconcile_compiled_runtime_acl(&transaction, registry, runtime_role).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Bootstraps only durable state and ledger structures, then records the
    /// initial applying state before any entity or mutation DDL can run.
    pub(crate) async fn begin_initial_package(
        &mut self,
        target: &ExpectedRegistryIdentity,
        ledger: &MigrationLedgerEntry,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        target.validate()?;
        ledger.validate()?;
        if ledger.source_revision.is_some()
            || ledger.target_revision != target.package_revision
            || ledger.package_sequence != target.package_sequence
        {
            return Err(PostgresKernelError::Configuration(
                "initial package and migration ledger differ",
            ));
        }
        let transaction = self.client.transaction().await?;
        install_registry_state_schema(&transaction, runtime_role).await?;
        let changed = transaction
            .execute(
                "INSERT INTO registry_internal.registry_state (
                     singleton, package_id, environment, instance_id, database_id,
                     active_package_revision, schema_fingerprint, package_sequence,
                     maintenance_status, maintenance_target_revision
                 ) VALUES (true, $1, $2, $3, $4, $5, $6, $7, 'applying', $5)
                 ON CONFLICT (singleton) DO NOTHING",
                &[
                    &target.package_id,
                    &target.environment,
                    &target.instance_id,
                    &target.database_id,
                    &target.package_revision,
                    &target.schema_fingerprint,
                    &target.package_sequence,
                ],
            )
            .await?;
        if changed == 1 {
            record_started(&transaction, ledger).await?;
        } else {
            verify_initial_resumable_state(&transaction, target).await?;
            verify_resumable(&transaction, ledger).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Records or resumes a successor only when the durable source identity,
    /// exact target, ordered checksums, and package sequence all agree.
    pub(crate) async fn begin_successor_package(
        &mut self,
        current: &ExpectedRegistryIdentity,
        target: &ExpectedRegistryIdentity,
        ledger: &MigrationLedgerEntry,
        event_destination_compatibility_inventory: Option<&EventDestinationCompatibilityInventory>,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        current.validate()?;
        target.validate()?;
        ledger.validate()?;
        if ledger.source_revision.as_deref() != Some(current.package_revision.as_str())
            || ledger.target_revision != target.package_revision
            || ledger.package_sequence != target.package_sequence
            || target.package_sequence <= current.package_sequence
        {
            return Err(PostgresKernelError::Configuration(
                "successor package and migration ledger differ",
            ));
        }
        let transaction = self.client.transaction().await?;
        verify_retained_webhook_delivery_bindings(
            &transaction,
            event_destination_compatibility_inventory,
        )
        .await?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET maintenance_status = 'applying', maintenance_target_revision = $1,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND maintenance_status = 'ready'
                   AND package_id = $2
                   AND environment = $3
                   AND instance_id = $4
                   AND database_id = $5
                   AND active_package_revision = $6
                   AND schema_fingerprint = $7
                   AND package_sequence = $8",
                &[
                    &target.package_revision,
                    &current.package_id,
                    &current.environment,
                    &current.instance_id,
                    &current.database_id,
                    &current.package_revision,
                    &current.schema_fingerprint,
                    &current.package_sequence,
                ],
            )
            .await?;
        reconcile_migration_ledger_metadata_only_constraints(&transaction).await?;
        if changed == 1 {
            record_started(&transaction, ledger).await?;
        } else {
            verify_successor_resumable_state(&transaction, current, target).await?;
            verify_resumable(&transaction, ledger).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Records maintenance in its own committed transaction while retaining
    /// the session lock.
    #[cfg(feature = "postgres-test")]
    pub async fn mark_applying(
        &mut self,
        current: &ExpectedRegistryIdentity,
        target_revision: &str,
    ) -> Result<()> {
        current.validate()?;
        if target_revision.is_empty() || target_revision == current.package_revision {
            return Err(PostgresKernelError::Configuration(
                "apply target revision must be non-empty and different",
            ));
        }
        let transaction = self.client.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET maintenance_status = 'applying', maintenance_target_revision = $1,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND maintenance_status = 'ready'
                   AND package_id = $2
                   AND environment = $3
                   AND instance_id = $4
                   AND database_id = $5
                   AND active_package_revision = $6
                   AND schema_fingerprint = $7
                   AND package_sequence = $8",
                &[
                    &target_revision,
                    &current.package_id,
                    &current.environment,
                    &current.instance_id,
                    &current.database_id,
                    &current.package_revision,
                    &current.schema_fingerprint,
                    &current.package_sequence,
                ],
            )
            .await?;
        if changed != 1 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Confirms that a durable failed apply is being resumed for the exact
    /// previous active identity and the same maintenance target. The failed
    /// state is deliberately left unchanged.
    #[cfg(any(test, feature = "postgres-test"))]
    #[allow(dead_code)]
    pub(crate) async fn resume_failed(
        &mut self,
        current: &ExpectedRegistryIdentity,
        target_revision: &str,
    ) -> Result<()> {
        validate_failed_resume_request(self.locked, current, target_revision)?;
        let transaction = self.client.transaction().await?;
        let accepted = transaction
            .query_opt(
                "SELECT 1
                 FROM registry_internal.registry_state
                 WHERE singleton
                   AND maintenance_status = 'failed'
                   AND maintenance_target_revision = $1
                   AND package_id = $2
                   AND environment = $3
                   AND instance_id = $4
                   AND database_id = $5
                   AND active_package_revision = $6
                   AND schema_fingerprint = $7
                   AND package_sequence = $8
                 FOR UPDATE",
                &[
                    &target_revision,
                    &current.package_id,
                    &current.environment,
                    &current.instance_id,
                    &current.database_id,
                    &current.package_revision,
                    &current.schema_fingerprint,
                    &current.package_sequence,
                ],
            )
            .await?;
        if accepted.is_none() {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Explicit W2 compatibility wrapper for the feasibility kernel catalog.
    #[cfg(feature = "postgres-test")]
    pub async fn activate(
        &mut self,
        target: &ExpectedRegistryIdentity,
        migration_role: &SqlIdentifier,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        self.activate_for_catalog(
            target,
            &ExpectedManagedCatalog::kernel(),
            migration_role,
            runtime_role,
        )
        .await
    }

    /// Atomically records the immutable applied-ledger outcome and makes the
    /// exact signed package identity ready only after closed catalog, RLS, ACL,
    /// ownership, and schema-fingerprint verification succeeds.
    pub(crate) async fn activate_verified_package(
        &mut self,
        current: Option<&ExpectedRegistryIdentity>,
        target: &ExpectedRegistryIdentity,
        transition: MaintenanceTransition<'_>,
        audit: Option<MaintenanceAuditRecord<'_>>,
    ) -> Result<()> {
        let MaintenanceTransition {
            ledger,
            expected_catalog,
            migration_role,
            runtime_role,
        } = transition;
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        target.validate()?;
        ledger.validate()?;
        let transaction = self.client.transaction().await?;
        verify_managed_catalog(
            &transaction,
            target,
            expected_catalog,
            migration_role,
            runtime_role,
        )
        .await?;
        record_applied(&transaction, ledger).await?;
        let changed = if let Some(current) = current {
            current.validate()?;
            transaction
                .execute(
                    "UPDATE registry_internal.registry_state
                     SET active_package_revision = $1,
                         schema_fingerprint = $2,
                         package_sequence = $3,
                         maintenance_status = 'ready',
                         maintenance_target_revision = NULL,
                         updated_at = transaction_timestamp()
                     WHERE singleton
                       AND package_id = $4
                       AND environment = $5
                       AND instance_id = $6
                       AND database_id = $7
                       AND active_package_revision = $8
                       AND schema_fingerprint = $9
                       AND package_sequence = $10
                       AND maintenance_status IN ('applying', 'failed')
                       AND maintenance_target_revision = $1",
                    &[
                        &target.package_revision,
                        &target.schema_fingerprint,
                        &target.package_sequence,
                        &target.package_id,
                        &target.environment,
                        &target.instance_id,
                        &target.database_id,
                        &current.package_revision,
                        &current.schema_fingerprint,
                        &current.package_sequence,
                    ],
                )
                .await?
        } else {
            transaction
                .execute(
                    "UPDATE registry_internal.registry_state
                     SET maintenance_status = 'ready',
                         maintenance_target_revision = NULL,
                         updated_at = transaction_timestamp()
                     WHERE singleton
                       AND package_id = $1
                       AND environment = $2
                       AND instance_id = $3
                       AND database_id = $4
                       AND active_package_revision = $5
                       AND schema_fingerprint = $6
                       AND package_sequence = $7
                       AND maintenance_status IN ('applying', 'failed')
                       AND maintenance_target_revision = $5",
                    &[
                        &target.package_id,
                        &target.environment,
                        &target.instance_id,
                        &target.database_id,
                        &target.package_revision,
                        &target.schema_fingerprint,
                        &target.package_sequence,
                    ],
                )
                .await?
        };
        if changed != 1 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        if let Some(audit) = audit {
            append_envelope(&transaction, audit.profile, audit.record)
                .await
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Activates the target only after exact package-catalog verification in
    /// the same transaction as the Registry state transition.
    #[cfg(feature = "postgres-test")]
    pub(crate) async fn activate_for_catalog(
        &mut self,
        target: &ExpectedRegistryIdentity,
        expected_catalog: &ExpectedManagedCatalog,
        migration_role: &SqlIdentifier,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        ensure_apply_lock(self.locked)?;
        let transaction = self.client.transaction().await?;
        target.validate()?;
        verify_managed_catalog(
            &transaction,
            target,
            expected_catalog,
            migration_role,
            runtime_role,
        )
        .await?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET active_package_revision = $1,
                     schema_fingerprint = $2,
                     package_sequence = $3,
                     maintenance_status = 'ready',
                     maintenance_target_revision = NULL,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND package_id = $4
                   AND environment = $5
                   AND instance_id = $6
                   AND database_id = $7
                   AND maintenance_status IN ('applying', 'failed')
                   AND maintenance_target_revision = $1
                   AND package_sequence < $3",
                &[
                    &target.package_revision,
                    &target.schema_fingerprint,
                    &target.package_sequence,
                    &target.package_id,
                    &target.environment,
                    &target.instance_id,
                    &target.database_id,
                ],
            )
            .await?;
        if changed != 1 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Leaves a durable failed-maintenance state. There is intentionally no
    /// API that clears failed maintenance without a reconciled activation.
    #[cfg(feature = "postgres-test")]
    pub async fn mark_failed(&mut self) -> Result<()> {
        let transaction = self.client.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET maintenance_status = 'failed', updated_at = transaction_timestamp()
                 WHERE singleton AND maintenance_status = 'applying'",
                &[],
            )
            .await?;
        if changed != 1 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Leaves both maintenance state and the exact package ledger durably
    /// failed. Applied ledger rows cannot match the update predicate.
    pub(crate) async fn mark_verified_package_failed(
        &mut self,
        target: &ExpectedRegistryIdentity,
        ledger: &MigrationLedgerEntry,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        target.validate()?;
        ledger.validate()?;
        let transaction = self.client.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET maintenance_status = 'failed', updated_at = transaction_timestamp()
                 WHERE singleton
                   AND package_id = $1
                   AND environment = $2
                   AND instance_id = $3
                   AND database_id = $4
                   AND maintenance_status IN ('applying', 'failed')
                   AND maintenance_target_revision = $5",
                &[
                    &target.package_id,
                    &target.environment,
                    &target.instance_id,
                    &target.database_id,
                    &target.package_revision,
                ],
            )
            .await?;
        if changed != 1 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        record_failed(&transaction, ledger).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Reads the durable maintenance state while this session holds the
    /// exclusive apply lock, so a reconciling operator can be told what the
    /// database actually records rather than inferring it from a failure.
    pub(crate) async fn maintenance_snapshot(&mut self) -> Result<MaintenanceSnapshot> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        let row = self
            .client
            .query_opt(
                "SELECT package_id, environment, instance_id, database_id,
                        active_package_revision, schema_fingerprint, package_sequence,
                        maintenance_status, maintenance_target_revision
                 FROM registry_internal.registry_state
                 WHERE singleton",
                &[],
            )
            .await?
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        Ok(MaintenanceSnapshot {
            identity: ExpectedRegistryIdentity {
                package_id: row.try_get(0)?,
                environment: row.try_get(1)?,
                instance_id: row.try_get(2)?,
                database_id: row.try_get(3)?,
                package_revision: row.try_get(4)?,
                schema_fingerprint: row.try_get(5)?,
                package_sequence: row.try_get(6)?,
            },
            maintenance_status: row.try_get(7)?,
            maintenance_target_revision: row.try_get(8)?,
        })
    }

    /// Compares the live managed catalog with one expected package catalog
    /// using the exact activation verification, and reports the invariant that
    /// differs instead of activating. The comparison transaction is always
    /// rolled back, so an assessment changes nothing.
    pub(crate) async fn managed_catalog_finding(
        &mut self,
        expected: &ExpectedRegistryIdentity,
        expected_catalog: &ExpectedManagedCatalog,
        migration_role: &SqlIdentifier,
        runtime_role: &SqlIdentifier,
    ) -> Result<Option<&'static str>> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        expected.validate()?;
        let transaction = self.client.transaction().await?;
        let finding = match verify_managed_catalog(
            &transaction,
            expected,
            expected_catalog,
            migration_role,
            runtime_role,
        )
        .await
        {
            Ok(()) => None,
            Err(PostgresKernelError::CatalogInvariant(finding)) => Some(finding),
            Err(PostgresKernelError::RegistryUnavailable) => Some(SCHEMA_FINGERPRINT_FINDING),
            Err(error) => return Err(error),
        };
        transaction.rollback().await?;
        Ok(finding)
    }

    /// Reads how far a reviewed plan durably progressed. Chunked backfills and
    /// transactional steps change records without changing the catalog, so a
    /// reverting decision needs this in addition to the catalog comparison.
    pub(crate) async fn reviewed_migration_progress(
        &mut self,
        ledger: &MigrationLedgerEntry,
    ) -> Result<ReviewedMigrationProgress> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        ledger.validate()?;
        let transaction = self.client.transaction().await?;
        let phase = migration_phase_state(&transaction, ledger).await?;
        let mut progress = ReviewedMigrationProgress {
            closed: phase.preconditions_complete && phase.postconditions_complete,
            durable_step_progress: false,
        };
        for step in &ledger.steps {
            let state = step_progress(&transaction, ledger, step).await?;
            if state.complete || state.checkpoint_record_id.is_some() || state.affected_rows > 0 {
                progress.durable_step_progress = true;
            }
            if !state.complete {
                progress.closed = false;
            }
        }
        transaction.rollback().await?;
        Ok(progress)
    }

    /// Abandons a pinned maintenance target, after proving in the same
    /// transaction that the live managed catalog is still exactly the active
    /// package's. The active identity is left unchanged and the target's
    /// ledger row stays durably failed, so an abandoned revision is never
    /// activated later under the same identity.
    pub(crate) async fn revert_failed_package(
        &mut self,
        current: &ExpectedRegistryIdentity,
        target_revision: &str,
        transition: MaintenanceTransition<'_>,
        audit: MaintenanceAuditRecord<'_>,
    ) -> Result<()> {
        let MaintenanceTransition {
            ledger,
            expected_catalog,
            migration_role,
            runtime_role,
        } = transition;
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        validate_failed_resume_request(self.locked, current, target_revision)?;
        ledger.validate()?;
        if ledger.target_revision != target_revision
            || ledger.source_revision.as_deref() != Some(current.package_revision.as_str())
        {
            return Err(PostgresKernelError::Configuration(
                "abandoned target and migration ledger differ",
            ));
        }
        let transaction = self.client.transaction().await?;
        verify_managed_catalog(
            &transaction,
            current,
            expected_catalog,
            migration_role,
            runtime_role,
        )
        .await?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET maintenance_status = 'ready',
                     maintenance_target_revision = NULL,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND package_id = $1
                   AND environment = $2
                   AND instance_id = $3
                   AND database_id = $4
                   AND active_package_revision = $5
                   AND schema_fingerprint = $6
                   AND package_sequence = $7
                   AND maintenance_status IN ('applying', 'failed')
                   AND maintenance_target_revision = $8",
                &[
                    &current.package_id,
                    &current.environment,
                    &current.instance_id,
                    &current.database_id,
                    &current.package_revision,
                    &current.schema_fingerprint,
                    &current.package_sequence,
                    &target_revision,
                ],
            )
            .await?;
        if changed != 1 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        record_failed(&transaction, ledger).await?;
        append_envelope(&transaction, audit.profile, audit.record)
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn release(mut self) -> Result<()> {
        let unlocked: bool = self
            .client
            .query_one("SELECT pg_advisory_unlock($1)", &[&self.lock_key.get()])
            .await?
            .get(0);
        if !unlocked {
            return Err(PostgresKernelError::CatalogInvariant(
                "dedicated apply connection did not hold its Registry lock",
            ));
        }
        self.locked = false;
        self.connection_task.abort();
        Ok(())
    }
}

/// Refuse a successor before changing maintenance state when its activated
/// non-secret destination bindings cannot finish every retained non-terminal
/// delivery. The package session's exclusive advisory lock prevents Registry
/// workers or mutations from changing this inventory while the check and
/// maintenance transition commit together.
async fn verify_retained_webhook_delivery_bindings(
    transaction: &impl GenericClient,
    inventory: Option<&EventDestinationCompatibilityInventory>,
) -> Result<()> {
    let tables = transaction
        .query_one(
            "SELECT to_regclass('registry_internal.registry_webhook_deliveries') IS NOT NULL,
                    to_regclass('registry_internal.registry_webhook_delivery_state') IS NOT NULL",
            &[],
        )
        .await?;
    let deliveries_exist = tables.try_get::<_, bool>(0)?;
    let states_exist = tables.try_get::<_, bool>(1)?;
    if !deliveries_exist && !states_exist {
        return Ok(());
    }
    if !deliveries_exist || !states_exist {
        return Err(PostgresKernelError::RegistryUnavailable);
    }

    let (logical_destination_ids, binding_digests): (Vec<String>, Vec<String>) = inventory
        .into_iter()
        .flat_map(EventDestinationCompatibilityInventory::binding_digests)
        .map(|(logical_id, digest)| (logical_id.to_owned(), digest.to_owned()))
        .unzip();
    let incompatible = transaction
        .query_opt(
            "SELECT 1
             FROM registry_internal.registry_webhook_delivery_state AS state
             JOIN registry_internal.registry_webhook_deliveries AS delivery
               ON delivery.event_id = state.event_id
              AND delivery.compiled_delivery_id = state.compiled_delivery_id
             JOIN registry_internal.registry_outbox AS outbox
               ON outbox.event_id = delivery.event_id
             WHERE (
                       state.state IN ('pending', 'leased')
                       OR (
                           state.state = 'dead_lettered'
                           AND delivery.operator_replay
                       )
                   )
               AND outbox.payload IS NOT NULL
               AND outbox.payload_expires_at > transaction_timestamp()
               AND NOT EXISTS (
                   SELECT 1
                   FROM unnest($1::text[], $2::text[])
                       AS activated(logical_destination_id, binding_digest)
                   WHERE activated.logical_destination_id = delivery.logical_destination_id
                     AND activated.binding_digest = delivery.destination_binding_digest
               )
             LIMIT 1",
            &[&logical_destination_ids, &binding_digests],
        )
        .await?;
    if incompatible.is_some() {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

fn compiler_statement_runs_after_reviewed_steps(statement: &PackageDdlStatement<'_>) -> bool {
    if is_spatial_candidate_view_drop_sql(statement.sql) {
        return false;
    }
    statement.kind == DdlStatementKind::View
        || is_spatial_projection_addition(statement)
        || is_deferred_not_null(statement)
}

/// A column a successor adds for a required field arrives accepting NULL, so
/// the reviewed backfill can populate the rows the entity already holds. The
/// statement that constrains it belongs after those steps.
fn is_deferred_not_null(statement: &PackageDdlStatement<'_>) -> bool {
    statement.kind == DdlStatementKind::Column
        && statement.sql.contains(" ALTER COLUMN ")
        && statement.sql.ends_with(" SET NOT NULL")
}

fn is_spatial_projection_addition(statement: &PackageDdlStatement<'_>) -> bool {
    (statement.kind == DdlStatementKind::Column
        && statement.sql.contains(" ADD COLUMN ")
        && statement
            .sql
            .contains("registry_spatial_ext.geometry(Point,4326)"))
        || (statement.kind == DdlStatementKind::Index
            && statement.sql.contains(" USING gist ")
            && statement.sql.contains("\"rs_spgeom_"))
}

async fn verify_compiled_prerequisites_for_client(
    client: &impl GenericClient,
    registry: &CompiledRegistry,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    if registry.ddl().requires_btree_gist {
        verify_btree_gist(client).await?;
    }
    if registry.ddl().requires_postgis {
        verify_postgis(client, migration_role, runtime_role).await?;
    }
    Ok(())
}

fn ledger_step(
    ledger: &MigrationLedgerEntry,
    migration_ordinal: i32,
    step_ordinal: i32,
) -> Result<&MigrationLedgerStep> {
    let matches = ledger
        .steps
        .iter()
        .filter(|step| {
            step.migration_ordinal == migration_ordinal && step.step_ordinal == step_ordinal
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(matches[0])
}

fn step_tables(step: &ValidatedReviewedMigrationStep) -> Result<Vec<String>> {
    let objects = match &step.descriptor {
        ReviewedMigrationStepDescriptor::TransactionalSql { objects, .. }
        | ReviewedMigrationStepDescriptor::ChunkedBackfill { objects, .. } => objects,
    };
    let tables = objects
        .iter()
        .map(|object| object.table.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if tables.is_empty() {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(tables)
}

async fn execute_boolean_assertion(
    transaction: &impl GenericClient,
    assertion: &ValidatedReviewedMigrationAssertion,
) -> Result<()> {
    if assertion.sha256 != statement_checksum(&assertion.sql) {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    let rows = transaction
        .query(&assertion.sql, &[])
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    if rows.len() != 1 || rows[0].len() != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    let accepted = rows[0]
        .try_get::<_, Option<bool>>(0)
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    if accepted != Some(true) {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

/// Toggle `FORCE ROW LEVEL SECURITY` on entity tables for the duration of one
/// maintenance transaction, so the migration authority that owns the tables can
/// read and write the rows it must reconcile. Non-owner roles keep every policy
/// either way, and the `ALTER TABLE` holds the table exclusively until the
/// caller commits or rolls back.
pub(crate) async fn set_force_row_security(
    transaction: &impl GenericClient,
    tables: &[String],
    forced: bool,
) -> Result<()> {
    let action = if forced { "FORCE" } else { "NO FORCE" };
    for table in tables {
        let table = SqlIdentifier::parse(table)?;
        transaction
            .batch_execute(&format!(
                "ALTER TABLE registry_data.{} {action} ROW LEVEL SECURITY",
                table.quoted()
            ))
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
    }
    Ok(())
}

async fn set_local_migration_timeouts(
    transaction: &impl GenericClient,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
) -> Result<()> {
    set_local_duration_timeouts(
        transaction,
        Duration::from_millis(lock_timeout_ms),
        Duration::from_millis(statement_timeout_ms),
    )
    .await
}

async fn set_local_duration_timeouts(
    transaction: &impl GenericClient,
    lock_timeout: Duration,
    statement_timeout: Duration,
) -> Result<()> {
    validate_timeout(
        lock_timeout,
        Duration::from_secs(300),
        "reviewed migration lock timeout is outside its bound",
    )?;
    validate_timeout(
        statement_timeout,
        MAX_VERIFIED_DDL_STATEMENT_TIMEOUT,
        "reviewed migration statement timeout is outside its bound",
    )?;
    let lock_timeout = u64::try_from(lock_timeout.as_millis())
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    let statement_timeout = u64::try_from(statement_timeout.as_millis())
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    transaction
        .execute(
            "SELECT pg_catalog.set_config('lock_timeout', $1, true),
                    pg_catalog.set_config('statement_timeout', $2, true)",
            &[
                &format!("{lock_timeout}ms"),
                &format!("{statement_timeout}ms"),
            ],
        )
        .await?;
    Ok(())
}

fn ensure_apply_lock(lock_held: bool) -> Result<()> {
    if !lock_held {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

fn ensure_verified_package_session(lock_held: bool, role_verified: bool) -> Result<()> {
    ensure_apply_lock(lock_held)?;
    if !role_verified {
        return Err(PostgresKernelError::RoleInvariant(
            "package apply did not verify the configured migration role",
        ));
    }
    Ok(())
}

fn validate_timeout(timeout: Duration, maximum: Duration, message: &'static str) -> Result<()> {
    if timeout < Duration::from_millis(1) || timeout > maximum {
        return Err(PostgresKernelError::Configuration(message));
    }
    Ok(())
}

async fn set_session_timeout(client: &Client, name: &str, timeout: Duration) -> Result<()> {
    let timeout_millis = u64::try_from(timeout.as_millis()).map_err(|_| {
        PostgresKernelError::Configuration("apply timeout is outside PostgreSQL bounds")
    })?;
    client
        .execute(
            "SELECT pg_catalog.set_config($1, $2, false)",
            &[&name, &format!("{timeout_millis}ms")],
        )
        .await?;
    Ok(())
}

async fn set_local_statement_timeout(client: &impl GenericClient, timeout: Duration) -> Result<()> {
    let timeout_millis = u64::try_from(timeout.as_millis()).map_err(|_| {
        PostgresKernelError::Configuration(
            "verified DDL statement timeout is outside PostgreSQL bounds",
        )
    })?;
    client
        .execute(
            "SELECT pg_catalog.set_config('statement_timeout', $1, true)",
            &[&format!("{timeout_millis}ms")],
        )
        .await?;
    Ok(())
}

fn validate_package_ddl(
    statements: &[PackageDdlStatement<'_>],
    statement_timeout: Duration,
) -> Result<()> {
    let sql = statements
        .iter()
        .map(|statement| statement.sql)
        .collect::<Vec<_>>();
    validate_verified_ddl_request(true, &sql, statement_timeout)?;
    if statements
        .iter()
        .any(|statement| statement.checksum != statement_checksum(statement.sql))
    {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

fn validate_statement_checksum(statement: &PackageDdlStatement<'_>) -> Result<()> {
    if statement.checksum != statement_checksum(statement.sql) {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

async fn verify_initial_resumable_state(
    client: &impl GenericClient,
    target: &ExpectedRegistryIdentity,
) -> Result<()> {
    let row = client
        .query_opt(
            "SELECT 1
             FROM registry_internal.registry_state
             WHERE singleton
               AND maintenance_status IN ('applying', 'failed')
               AND maintenance_target_revision = $1
               AND package_id = $2
               AND environment = $3
               AND instance_id = $4
               AND database_id = $5
               AND active_package_revision = $1
               AND schema_fingerprint = $6
               AND package_sequence = $7
             FOR UPDATE",
            &[
                &target.package_revision,
                &target.package_id,
                &target.environment,
                &target.instance_id,
                &target.database_id,
                &target.schema_fingerprint,
                &target.package_sequence,
            ],
        )
        .await?;
    if row.is_none() {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

async fn verify_successor_resumable_state(
    client: &impl GenericClient,
    current: &ExpectedRegistryIdentity,
    target: &ExpectedRegistryIdentity,
) -> Result<()> {
    let row = client
        .query_opt(
            "SELECT 1
             FROM registry_internal.registry_state
             WHERE singleton
               AND maintenance_status IN ('applying', 'failed')
               AND maintenance_target_revision = $1
               AND package_id = $2
               AND environment = $3
               AND instance_id = $4
               AND database_id = $5
               AND active_package_revision = $6
               AND schema_fingerprint = $7
               AND package_sequence = $8
             FOR UPDATE",
            &[
                &target.package_revision,
                &current.package_id,
                &current.environment,
                &current.instance_id,
                &current.database_id,
                &current.package_revision,
                &current.schema_fingerprint,
                &current.package_sequence,
            ],
        )
        .await?;
    if row.is_none() {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

fn validate_runtime_acl_reconciliation_request(lock_held: bool) -> Result<()> {
    ensure_apply_lock(lock_held)
}

fn validate_failed_resume_request(
    lock_held: bool,
    current: &ExpectedRegistryIdentity,
    target_revision: &str,
) -> Result<()> {
    ensure_apply_lock(lock_held)?;
    current.validate()?;
    if target_revision.is_empty() || target_revision == current.package_revision {
        return Err(PostgresKernelError::Configuration(
            "resume target revision must be non-empty and different",
        ));
    }
    Ok(())
}

fn validate_verified_ddl_request(
    lock_held: bool,
    statements: &[&str],
    statement_timeout: Duration,
) -> Result<()> {
    ensure_apply_lock(lock_held)?;
    if statement_timeout < Duration::from_millis(1)
        || statement_timeout > MAX_VERIFIED_DDL_STATEMENT_TIMEOUT
    {
        return Err(PostgresKernelError::Configuration(
            "verified DDL statement timeout must be between 1 millisecond and 1 hour",
        ));
    }
    if statements.is_empty() || statements.len() > MAX_VERIFIED_DDL_STATEMENTS {
        return Err(PostgresKernelError::Configuration(
            "verified DDL statement count is outside its bound",
        ));
    }
    if statements.iter().any(|statement| {
        statement.trim().is_empty() || statement.len() > MAX_VERIFIED_DDL_STATEMENT_BYTES
    }) {
        return Err(PostgresKernelError::Configuration(
            "verified DDL statement text is empty or outside its bound",
        ));
    }
    Ok(())
}

impl Drop for DedicatedApplyConnection {
    fn drop(&mut self) {
        if self.locked {
            self.connection_task.abort();
        }
    }
}

async fn connect_dedicated(config: &ConnectionConfig) -> Result<(Client, JoinHandle<()>)> {
    match config.tls_connector() {
        ConnectionTls::Rustls(connector) => {
            let (client, connection) = config.postgres().connect(connector).await?;
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((client, task))
        }
        #[cfg(feature = "postgres-test")]
        ConnectionTls::TestOnlyPlaintext => {
            let (client, connection) = config.postgres().connect(NoTls).await?;
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((client, task))
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "postgres-test")]
    use std::{env, str::FromStr, time::SystemTime};

    #[cfg(feature = "postgres-test")]
    use tokio_postgres::Config;

    #[cfg(feature = "postgres-test")]
    use crate::postgres::PoolBounds;

    use super::*;

    #[test]
    fn advisory_lock_key_is_deterministic_and_registry_scoped() {
        let first = RegistryLockKey::derive("registry-a").expect("Registry id is valid");
        let repeated = RegistryLockKey::derive("registry-a").expect("Registry id is valid");
        let other = RegistryLockKey::derive("registry-b").expect("Registry id is valid");
        assert_eq!(first, repeated);
        assert_ne!(first, other);
        assert!(RegistryLockKey::derive("").is_err());
    }

    #[test]
    fn verified_ddl_requires_the_apply_lock_and_bounded_nonempty_statements() {
        assert!(matches!(
            validate_verified_ddl_request(
                false,
                &["CREATE TABLE registry_data.probe (id int)"],
                Duration::from_secs(1),
            ),
            Err(PostgresKernelError::RegistryUnavailable)
        ));
        assert!(matches!(
            validate_verified_ddl_request(true, &[], Duration::from_secs(1)),
            Err(PostgresKernelError::Configuration(_))
        ));
        assert!(matches!(
            validate_verified_ddl_request(true, &[" \n\t"], Duration::from_secs(1)),
            Err(PostgresKernelError::Configuration(_))
        ));

        let excessive_count =
            vec!["CREATE TABLE registry_data.probe (id int)"; MAX_VERIFIED_DDL_STATEMENTS + 1];
        assert!(matches!(
            validate_verified_ddl_request(true, &excessive_count, Duration::from_secs(1)),
            Err(PostgresKernelError::Configuration(_))
        ));
        let oversized = "x".repeat(MAX_VERIFIED_DDL_STATEMENT_BYTES + 1);
        assert!(matches!(
            validate_verified_ddl_request(true, &[oversized.as_str()], Duration::from_secs(1)),
            Err(PostgresKernelError::Configuration(_))
        ));
        assert!(validate_verified_ddl_request(
            true,
            &["CREATE TABLE registry_data.probe (id int)"],
            Duration::from_millis(1),
        )
        .is_ok());
        assert!(validate_verified_ddl_request(
            true,
            &["CREATE TABLE registry_data.probe (id int)"],
            MAX_VERIFIED_DDL_STATEMENT_TIMEOUT,
        )
        .is_ok());
        assert!(matches!(
            validate_verified_ddl_request(
                true,
                &["CREATE TABLE registry_data.probe (id int)"],
                Duration::from_nanos(1),
            ),
            Err(PostgresKernelError::Configuration(_))
        ));
        assert!(matches!(
            validate_verified_ddl_request(
                true,
                &["CREATE TABLE registry_data.probe (id int)"],
                MAX_VERIFIED_DDL_STATEMENT_TIMEOUT + Duration::from_millis(1),
            ),
            Err(PostgresKernelError::Configuration(_))
        ));
    }

    #[test]
    fn deferred_requiredness_runs_after_the_reviewed_steps() {
        let statement = |sql, kind| PackageDdlStatement {
            sql,
            checksum: "",
            kind,
            ordinal: 0,
        };
        assert!(compiler_statement_runs_after_reviewed_steps(&statement(
            "ALTER TABLE registry_data.\"rs_e_asset\" ALTER COLUMN \"rs_f_batch\" SET NOT NULL",
            DdlStatementKind::Column,
        )));
        assert!(!compiler_statement_runs_after_reviewed_steps(&statement(
            "ALTER TABLE registry_data.\"rs_e_asset\" ADD COLUMN \"rs_f_batch\" varchar(16)",
            DdlStatementKind::Column,
        )));
        assert!(!compiler_statement_runs_after_reviewed_steps(&statement(
            "ALTER TABLE registry_data.\"rs_e_asset\" ALTER COLUMN \"rs_f_batch\" DROP NOT NULL",
            DdlStatementKind::Column,
        )));
    }

    #[test]
    fn catalog_activation_requires_the_dedicated_apply_lock() {
        assert!(matches!(
            ensure_apply_lock(false),
            Err(PostgresKernelError::RegistryUnavailable)
        ));
        assert!(ensure_apply_lock(true).is_ok());
    }

    #[test]
    fn runtime_acl_reconciliation_requires_the_dedicated_apply_lock() {
        assert!(matches!(
            validate_runtime_acl_reconciliation_request(false),
            Err(PostgresKernelError::RegistryUnavailable)
        ));
        assert!(validate_runtime_acl_reconciliation_request(true).is_ok());
    }

    #[cfg(feature = "postgres-test")]
    #[tokio::test]
    async fn failed_resume_and_ddl_timeout_are_fail_closed_on_real_postgres() {
        let database = InterlockTestDatabase::create().await;
        let current = ExpectedRegistryIdentity {
            package_id: "package-under-test".to_owned(),
            environment: "test".to_owned(),
            instance_id: "instance-under-test".to_owned(),
            database_id: "database-under-test".to_owned(),
            package_revision: "revision-current".to_owned(),
            schema_fingerprint: "fingerprint-current".to_owned(),
            package_sequence: 7,
        };
        let target_revision = "revision-target";
        database
            .install_failed_state(&current, target_revision)
            .await;
        let initial_state = database.state_snapshot().await;

        let lock_key = RegistryLockKey::derive(database.database.as_str())
            .expect("isolated database name is a valid Registry lock scope");
        let mut apply = DedicatedApplyConnection::acquire(
            &database.migration_config,
            lock_key,
            Duration::from_secs(1),
        )
        .await
        .expect("isolated migration role can acquire the apply lock");

        assert!(matches!(
            apply.resume_failed(&current, "wrong-target").await,
            Err(PostgresKernelError::RegistryUnavailable)
        ));
        let mut wrong_current = current.clone();
        wrong_current.package_sequence += 1;
        assert!(matches!(
            apply.resume_failed(&wrong_current, target_revision).await,
            Err(PostgresKernelError::RegistryUnavailable)
        ));
        assert_eq!(database.state_snapshot().await, initial_state);
        apply
            .resume_failed(&current, target_revision)
            .await
            .expect("the exact durable failed apply can be resumed");
        assert_eq!(database.state_snapshot().await, initial_state);

        let timed_out = apply
            .execute_verified_ddl(
                &[
                    "CREATE TEMP TABLE verified_ddl_timeout_probe (id integer)",
                    "SELECT pg_sleep(0.2)",
                ],
                Duration::from_millis(20),
            )
            .await;
        assert!(matches!(timed_out, Err(PostgresKernelError::Connection)));
        assert_eq!(database.state_snapshot().await, initial_state);
        apply
            .resume_failed(&current, target_revision)
            .await
            .expect("a timed-out DDL transaction leaves failed recovery state intact");

        let competing_lock = DedicatedApplyConnection::acquire(
            &database.migration_config,
            lock_key,
            Duration::from_millis(20),
        )
        .await;
        assert!(matches!(
            competing_lock,
            Err(PostgresKernelError::RegistryUnavailable)
        ));

        apply
            .execute_verified_ddl(
                &[
                    "CREATE TEMP TABLE verified_ddl_timeout_probe (id integer)",
                    "DROP TABLE verified_ddl_timeout_probe",
                ],
                Duration::from_secs(1),
            )
            .await
            .expect("the timed-out transaction rolls back and the locked session remains usable");
        apply
            .release()
            .await
            .expect("the original apply connection releases its lock");

        let mut reacquired = DedicatedApplyConnection::acquire(
            &database.migration_config,
            lock_key,
            Duration::from_secs(1),
        )
        .await
        .expect("the released apply lock can be acquired again");
        reacquired
            .resume_failed(&current, target_revision)
            .await
            .expect("failed recovery remains exact after lock handoff");
        reacquired
            .release()
            .await
            .expect("the replacement apply connection releases its lock");
        assert_eq!(database.state_snapshot().await, initial_state);
        database.cleanup().await;
    }

    #[cfg(feature = "postgres-test")]
    struct InterlockTestDatabase {
        admin_root: Config,
        admin: Client,
        admin_task: JoinHandle<()>,
        migration_config: ConnectionConfig,
        migration_raw: Config,
        database: SqlIdentifier,
        migration_role: SqlIdentifier,
    }

    #[cfg(feature = "postgres-test")]
    impl InterlockTestDatabase {
        async fn create() -> Self {
            let url = env::var("REGISTRY_SERVER_TEST_DATABASE_URL").expect(
                "REGISTRY_SERVER_TEST_DATABASE_URL is required for the real interlock test",
            );
            let admin_root = Config::from_str(&url)
                .expect("REGISTRY_SERVER_TEST_DATABASE_URL must be a valid PostgreSQL URL");
            let nanos = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the Unix epoch")
                .as_nanos();
            let suffix = format!("{}_{nanos}", std::process::id());
            let database = SqlIdentifier::parse(&format!("rs_interlock_{suffix}"))
                .expect("generated database identifier is valid");
            let migration_role = SqlIdentifier::parse(&format!("rs_il_migration_{suffix}"))
                .expect("generated migration role identifier is valid");
            let password = format!("rs{suffix}password");

            let (root, root_task) = connect_plaintext(admin_root.clone()).await;
            root.batch_execute(&format!(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{}';",
                migration_role.quoted(),
                password,
            ))
            .await
            .expect("test administrator can create an isolated migration role");
            root.batch_execute(&format!("CREATE DATABASE {};", database.quoted()))
                .await
                .expect("test administrator can create an isolated database");
            root_task.abort();

            let mut database_admin = admin_root.clone();
            database_admin.dbname(database.as_str());
            let (admin, admin_task) = connect_plaintext(database_admin).await;
            admin
                .batch_execute(&format!(
                    "REVOKE ALL ON DATABASE {} FROM PUBLIC;
                     GRANT CONNECT, TEMPORARY ON DATABASE {} TO {};
                     CREATE SCHEMA registry_internal AUTHORIZATION {};",
                    database.quoted(),
                    database.quoted(),
                    migration_role.quoted(),
                    migration_role.quoted(),
                ))
                .await
                .expect("test administrator can constrain and provision the isolated database");

            let mut migration_raw = admin_root.clone();
            migration_raw.dbname(database.as_str());
            migration_raw.user(migration_role.as_str());
            migration_raw.password(password);
            let bounds = PoolBounds::new(
                1,
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .expect("interlock test pool bounds are valid");
            let migration_config =
                ConnectionConfig::from_test_config(migration_raw.clone(), bounds)
                    .expect("interlock test migration configuration is valid");
            Self {
                admin_root,
                admin,
                admin_task,
                migration_config,
                migration_raw,
                database,
                migration_role,
            }
        }

        async fn install_failed_state(
            &self,
            current: &ExpectedRegistryIdentity,
            target_revision: &str,
        ) {
            let (migration, migration_task) = connect_plaintext(self.migration_raw.clone()).await;
            migration
                .batch_execute(
                    "CREATE TABLE registry_internal.registry_state (
                         singleton boolean PRIMARY KEY CHECK (singleton),
                         environment text NOT NULL,
                         package_id text NOT NULL,
                         instance_id text NOT NULL,
                         database_id text NOT NULL,
                         active_package_revision text NOT NULL,
                         schema_fingerprint text NOT NULL,
                         package_sequence bigint NOT NULL,
                         maintenance_status text NOT NULL,
                         maintenance_target_revision text,
                         updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
                     );",
                )
                .await
                .expect("isolated migration role can install the state fixture");
            migration
                .execute(
                    "INSERT INTO registry_internal.registry_state (
                         singleton, package_id, environment, instance_id, database_id,
                         active_package_revision, schema_fingerprint, package_sequence,
                         maintenance_status, maintenance_target_revision
                     ) VALUES (true, $1, $2, $3, $4, $5, $6, $7, 'failed', $8)",
                    &[
                        &current.package_id,
                        &current.environment,
                        &current.instance_id,
                        &current.database_id,
                        &current.package_revision,
                        &current.schema_fingerprint,
                        &current.package_sequence,
                        &target_revision,
                    ],
                )
                .await
                .expect("isolated migration role can seed durable failed state");
            migration_task.abort();
        }

        async fn state_snapshot(
            &self,
        ) -> (
            String,
            String,
            String,
            String,
            String,
            String,
            i64,
            String,
            Option<String>,
        ) {
            let row = self
                .admin
                .query_one(
                    "SELECT package_id, environment, instance_id, database_id,
                            active_package_revision, schema_fingerprint, package_sequence,
                            maintenance_status, maintenance_target_revision
                     FROM registry_internal.registry_state
                     WHERE singleton",
                    &[],
                )
                .await
                .expect("isolated failed state remains queryable");
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
                row.get(6),
                row.get(7),
                row.get(8),
            )
        }

        async fn cleanup(self) {
            self.admin_task.abort();
            let (root, root_task) = connect_plaintext(self.admin_root).await;
            root.batch_execute(&format!(
                "DROP DATABASE {} WITH (FORCE);",
                self.database.quoted(),
            ))
            .await
            .expect("isolated interlock test database can be removed");
            root.batch_execute(&format!("DROP ROLE {};", self.migration_role.quoted()))
                .await
                .expect("isolated interlock test role can be removed");
            root_task.abort();
        }
    }

    #[cfg(feature = "postgres-test")]
    async fn connect_plaintext(config: Config) -> (Client, JoinHandle<()>) {
        let (client, connection) = config
            .connect(NoTls)
            .await
            .expect("real PostgreSQL interlock test connection succeeds");
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        (client, task)
    }
}
