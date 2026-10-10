// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
#[cfg(feature = "postgres-test")]
use tokio_postgres::NoTls;
use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;

use crate::event_destination::EventDestinationCompatibilityInventory;
use crate::field_encryption::{FieldEncryptionProvider, FieldEncryptionService};
use crate::generated_ddl::DdlStatementKind;
use crate::history_commit::{install_empty_history_baseline, install_history_commit_schema};
use crate::history_migration::{
    ensure_successor_history_ready as ensure_successor_history_ready_state,
    finish_bounded_history_update, finish_reviewed_page_update, prepare_bounded_history_update,
    prepare_reviewed_page_capture,
};
use crate::history_schema::HistorySchemaDescriptor;
use crate::history_store::{install_history_schema_store, retain_descriptor};
use crate::migration_plan::{
    AffectedRowBounds, ReviewedFieldEncryptionHistory, ReviewedMigrationStepDescriptor,
    ValidatedReviewedMigrationAssertion, ValidatedReviewedMigrationPlan,
    ValidatedReviewedMigrationStep,
};
use crate::model::{CompiledBlindIndex, CompiledEntity, CompiledField, CompiledRegistry};
use crate::mutation::install_mutation_schema;
use crate::package::CompiledRegistryMigrationBaseline;

use super::{
    catalog::{
        install_registry_state_schema, registry_state_shape, verify_managed_catalog,
        ExpectedManagedCatalog, RegistryStateShape,
    },
    config::ConnectionTls,
    migration_ledger::{
        in_flight_activation, migration_phase_state, record_applied, record_chunk_progress,
        record_failed, record_postconditions_complete, record_preconditions_complete,
        record_reverted, record_started, record_step_complete, statement_checksum, step_progress,
        verify_resumable, ActivationPlanKind, MigrationLedgerEntry, MigrationLedgerStep,
        MigrationLedgerStepKind,
    },
    schema::{
        execute_compiled_ddl_statement, is_spatial_candidate_view_drop_sql,
        is_spatial_candidate_view_sql, map_pattern_database_error, pattern_field_for_constraint,
        reconcile_compiled_runtime_acl, retire_spatial_bbox_role, transfer_spatial_candidate_views,
    },
    verify_btree_gist, verify_migration_role, verify_postgis, ConnectionConfig,
    ExpectedRegistryIdentity, PostgresKernelError, Result, SqlIdentifier,
};

// These defense-in-depth bounds match the verified package manifest envelope:
// at most 1,024 migration statements inside at most 4 MiB of manifest bytes.
const MAX_VERIFIED_DDL_STATEMENTS: usize = 1024;
const MAX_VERIFIED_DDL_STATEMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_VERIFIED_DDL_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// Final field-encryption verification must inspect every affected row without
/// materializing an entity in process memory. A live envelope is bounded near
/// 64 KiB, keeping one page near 32 MiB at its declared maximum.
const FIELD_ENCRYPTION_LIVE_VERIFICATION_PAGE_SIZE: i64 = 512;
/// Journal snapshots can reach 3 MiB, so use a smaller page that remains near
/// 48 MiB even when every retained boundary snapshot is at its maximum size.
const FIELD_ENCRYPTION_JOURNAL_VERIFICATION_PAGE_SIZE: i64 = 16;
/// Unique-index preflight values share the live encrypted-value bound. Each
/// page keeps at most about 32 MiB of plaintext in process before retaining
/// only keyed 32-byte digests in the transaction-local database table.
const FIELD_ENCRYPTION_DUPLICATE_PREFLIGHT_PAGE_SIZE: i64 = 512;

/// The finding reported when the live managed schema fingerprint differs from
/// the one an expected package binds. Activation verification signals that
/// mismatch as an unavailable Registry, which carries no wording of its own.
const SCHEMA_FINGERPRINT_FINDING: &str =
    "managed schema fingerprint differs from the expected package";

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
    pub maintenance_target_package_digest: Option<String>,
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
    pub pattern_field: Option<(&'a str, &'a str)>,
    pub ordinal: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewedExecutionOutcome {
    Complete,
    Interrupted,
}

/// The borrowed field-encryption key source one field-encryption backfill
/// resolves its data-encryption key through. It carries no authority beyond
/// reading the configured provider during this apply.
pub(crate) struct ReviewedFieldEncryptionContext<'a> {
    pub provider: &'a FieldEncryptionProvider,
    pub secrets: &'a registry_platform_config::SecretResolver,
}

pub(crate) struct ReviewedPackageExecutionRequest<'a> {
    pub registry: &'a CompiledRegistry,
    pub current: &'a ExpectedRegistryIdentity,
    pub target_package_revision: &'a str,
    pub plan: &'a ValidatedReviewedMigrationPlan,
    pub predecessor_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
    pub predecessor_history_descriptor: Option<&'a HistorySchemaDescriptor>,
    pub field_encryption: Option<ReviewedFieldEncryptionContext<'a>>,
    pub runtime_role: &'a SqlIdentifier,
    pub compiler_statements: &'a [PackageDdlStatement<'a>],
    pub ledger: &'a MigrationLedgerEntry,
    pub prior_tables: &'a [String],
    pub candidate_tables: &'a [String],
    pub compiler_lock_timeout: Duration,
    pub compiler_statement_timeout: Duration,
    pub fault_after_committed_chunks: Option<u64>,
}

/// One covered field of a field-encryption backfill step: the successor field
/// that owns the envelope and blind-index columns, paired with the predecessor
/// field that owns the plaintext column being sealed.
pub(crate) struct FieldEncryptionCoveredField<'a> {
    pub(crate) entity_id: &'a str,
    pub(crate) candidate: &'a CompiledField,
    pub(crate) prior: &'a CompiledField,
    pub(crate) blind: Option<&'a CompiledBlindIndex>,
    /// The successor API name reported to the operator.
    pub(crate) api_name: &'a str,
    /// The predecessor API name retained in pre-flip idempotency responses.
    pub(crate) predecessor_api_name: &'a str,
    /// The stable logical field id retained in outbox projections.
    pub(crate) logical_field_id: &'a str,
}

/// The per-chunk request one field-encryption backfill execution carries.
struct FieldEncryptionChunkRequest<'a> {
    registry: &'a CompiledRegistry,
    step: &'a ValidatedReviewedMigrationStep,
    ledger: &'a MigrationLedgerEntry,
    ledger_step: &'a MigrationLedgerStep,
    descriptor_path: &'a str,
    target_package_revision: &'a str,
    table: &'a str,
    covered: &'a [FieldEncryptionCoveredField<'a>],
    service: &'a FieldEncryptionService,
    history_choice: ReviewedFieldEncryptionHistory,
    chunk_size: u32,
    max_total_rows: u64,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
}

struct ReviewedChunkExecutionRequest<'a> {
    registry: &'a CompiledRegistry,
    target_package_revision: &'a str,
    descriptor_path: &'a str,
    step: &'a ValidatedReviewedMigrationStep,
    ledger: &'a MigrationLedgerEntry,
    ledger_step: &'a MigrationLedgerStep,
    table: &'a str,
    chunk_size: u32,
    max_total_rows: u64,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
}

/// One covered field's sealed pair for one row: the envelope bytes and the
/// recomputed blind index, each absent when the row carries no value.
type FieldEncryptionSeal = (Option<Vec<u8>>, Option<Vec<u8>>);

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
        let digest = Sha256::digest([b"breg/advisory-lock/v1/", registry_id.as_bytes()].concat());
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
        // Every failure other than a held lock keeps its own refusal.
        client
            .execute("SELECT pg_catalog.pg_advisory_lock($1)", &[&lock_key.get()])
            .await
            .map_err(|error| {
                if lock_wait_ended(&error) {
                    PostgresKernelError::MigrationLockHeld
                } else {
                    PostgresKernelError::RegistryUnavailable
                }
            })?;
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
            if let Err(error) = transaction.batch_execute(statement).await {
                transaction.rollback().await?;
                return Err(PostgresKernelError::from_statement_error(&error));
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
            if let Err(error) = execute_compiled_ddl_statement(
                &transaction,
                statement.sql,
                statement.kind,
                statement.pattern_field,
                runtime_role,
            )
            .await
            {
                transaction.rollback().await?;
                return Err(error);
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
            field_encryption,
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
                                    registry,
                                    target_package_revision,
                                    descriptor_path: &migration.descriptor_path,
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
                    ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
                        entity_id,
                        chunk_size,
                        max_total_rows,
                        lock_timeout_ms,
                        statement_timeout_ms,
                        ..
                    } => {
                        if ledger_step.kind != MigrationLedgerStepKind::FieldEncryptionBackfill {
                            return Err(PostgresKernelError::RegistryUnavailable);
                        }
                        let context = field_encryption
                            .as_ref()
                            .ok_or(PostgresKernelError::RegistryUnavailable)?;
                        let history_choice = migration
                            .descriptor
                            .history
                            .ok_or(PostgresKernelError::RegistryUnavailable)?;
                        let service = self
                            .initialize_field_encryption_service(
                                context,
                                registry,
                                target_package_revision,
                            )
                            .await?;
                        let covered = covered_field_encryption_fields(
                            registry,
                            predecessor_baseline,
                            entity_id,
                            step,
                        )?;
                        let table = &registry
                            .entities()
                            .get(entity_id)
                            .ok_or(PostgresKernelError::RegistryUnavailable)?
                            .physical_table;
                        self.refuse_retained_plaintext_request_snapshots(history_choice, &covered)
                            .await?;
                        self.field_encryption_duplicate_preflight(&service, table, &covered)
                            .await?;
                        loop {
                            let advanced = self
                                .execute_field_encryption_chunk(FieldEncryptionChunkRequest {
                                    registry,
                                    step,
                                    ledger,
                                    ledger_step,
                                    descriptor_path: &migration.descriptor_path,
                                    target_package_revision,
                                    table,
                                    covered: &covered,
                                    service: &service,
                                    history_choice,
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
                statement.pattern_field,
                runtime_role,
            )
            .await?;
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
        let transaction = self.client.transaction().await?;
        set_local_duration_timeouts(&transaction, lock_timeout, statement_timeout).await?;
        drop_managed_read_view_set(&transaction).await?;
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

        let objects = match &step.descriptor {
            ReviewedMigrationStepDescriptor::TransactionalSql { objects, .. }
            | ReviewedMigrationStepDescriptor::ChunkedBackfill { objects, .. }
            | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { objects, .. } => objects,
        };
        for object in objects {
            let Some((entity_id, field_id)) =
                pattern_field_for_constraint(registry, &object.physical_name)
            else {
                continue;
            };
            if let Some(pattern) = &registry.entities()[entity_id].fields[field_id].pattern {
                // A reviewed replacement also validates native syntax when
                // the target table is empty. PostgreSQL evaluates the exact
                // candidate expression, as in the compiler installer.
                transaction
                    .query_one("SELECT '' ~ $1::text", &[pattern])
                    .await
                    .map_err(|error| {
                        map_pattern_database_error(error, Some((entity_id, field_id)))
                    })?;
            }
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
                .map_err(|error| map_reviewed_pattern_error(error, registry, step))?;
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
                .map_err(|error| map_reviewed_pattern_error(error, registry, step))?;
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
            registry,
            target_package_revision,
            descriptor_path,
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
        // Each chunk journals the rows it changed as one history commit in
        // the chunk's own transaction, so a resumed backfill never journals a
        // committed chunk twice.
        let capture =
            prepare_reviewed_page_capture(&transaction, registry, descriptor_path, step, &ids)
                .await
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        let affected = transaction
            .execute(&step.sql, &[&ids])
            .await
            .map_err(|error| map_reviewed_pattern_error(error, registry, step))?;
        if affected != selected {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        finish_reviewed_page_update(&transaction, registry, target_package_revision, capture)
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        set_force_row_security(&transaction, &[table.as_str().to_owned()], true).await?;
        let checkpoint = ids
            .last()
            .copied()
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        record_chunk_progress(&transaction, ledger, ledger_step, checkpoint, total).await?;
        transaction.commit().await?;
        Ok(true)
    }

    /// Activate the package's field-encryption key state on the dedicated
    /// migration connection. Runtime startup and diagnostics are read-only;
    /// only governed apply may select the first custodian.
    pub(crate) async fn activate_field_encryption_key_state(
        &self,
        context: &ReviewedFieldEncryptionContext<'_>,
        registry: &CompiledRegistry,
        target_package_revision: &str,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        FieldEncryptionService::activate(
            context.provider,
            registry.registry_id(),
            target_package_revision,
            context.secrets,
            &self.client,
        )
        .await
        .map(drop)
        .map_err(|_| PostgresKernelError::RegistryUnavailable)
    }

    /// Open the already-activated field-encryption key for one backfill step.
    /// The package-level apply path above has created or verified the singleton
    /// row before any reviewed step can run.
    async fn initialize_field_encryption_service(
        &self,
        context: &ReviewedFieldEncryptionContext<'_>,
        registry: &CompiledRegistry,
        _target_package_revision: &str,
    ) -> Result<FieldEncryptionService> {
        FieldEncryptionService::open_existing(
            context.provider,
            registry.registry_id(),
            context.secrets,
            &self.client,
        )
        .await
        .map_err(|_| PostgresKernelError::RegistryUnavailable)
    }

    /// Refuse the whole step, before any sealing, when normalizing two
    /// existing records onto one unique blind index would collide. The refusal
    /// names record ids only, never field values, and caps the named set so a
    /// bulk collision cannot flood an operator surface.
    async fn field_encryption_duplicate_preflight(
        &mut self,
        service: &FieldEncryptionService,
        table: &str,
        covered: &[FieldEncryptionCoveredField<'_>],
    ) -> Result<()> {
        if !covered
            .iter()
            .any(|field| field.blind.is_some_and(|blind| blind.unique))
        {
            return Ok(());
        }
        let table = SqlIdentifier::parse(table)?;
        let projection = covered
            .iter()
            .map(|field| prior_plaintext_projection(field.prior))
            .collect::<Vec<_>>()
            .join(", ");
        let select_sql = format!(
            "SELECT record_id, {projection}
             FROM registry_data.{}
             WHERE ($1::uuid IS NULL OR record_id > $1::uuid)
             ORDER BY record_id
             LIMIT $2",
            table.quoted()
        );
        let transaction = self.client.transaction().await?;
        // The migration role owns the table, but every prior step leaves FORCE
        // ROW LEVEL SECURITY on, which would subject this read to the default
        // deny and hide the rows whose duplicates must refuse the step.
        set_force_row_security(&transaction, &[table.as_str().to_owned()], false).await?;
        // Blind indexes are derived from text the projection renders in the
        // session time zone, so pin it exactly as the runtime read path does.
        transaction
            .execute("SELECT set_config('TimeZone', 'UTC', true)", &[])
            .await?;
        prepare_unique_blind_index_preflight(&transaction).await?;
        let mut after_record_id: Option<Uuid> = None;
        loop {
            let rows = transaction
                .query(
                    &select_sql,
                    &[
                        &after_record_id,
                        &FIELD_ENCRYPTION_DUPLICATE_PREFLIGHT_PAGE_SIZE,
                    ],
                )
                .await
                .map_err(|_| PostgresKernelError::Connection)?;
            if rows.is_empty() {
                break;
            }
            for (field_index, field) in covered.iter().enumerate() {
                let Some(blind) = field.blind.filter(|blind| blind.unique) else {
                    continue;
                };
                let mut digests = Vec::with_capacity(rows.len());
                let mut record_ids = Vec::with_capacity(rows.len());
                for row in &rows {
                    let record_id: Uuid = row
                        .try_get(0)
                        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
                    let value = row
                        .try_get::<_, Option<Value>>(field_index + 1)
                        .map_err(|_| PostgresKernelError::RegistryUnavailable)?
                        .unwrap_or(Value::Null);
                    let Some(plaintext) = field_plaintext_string(field.prior, &value)? else {
                        continue;
                    };
                    digests.push(
                        service
                            .blind_index(
                                field.entity_id,
                                field.candidate.id.as_str(),
                                &FieldEncryptionService::normalize(
                                    &blind.normalization,
                                    &plaintext,
                                ),
                            )
                            .to_vec(),
                    );
                    record_ids.push(record_id);
                }
                let field_slot = i16::try_from(field_index)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
                let duplicates = record_unique_blind_index_page(
                    &transaction,
                    field_slot,
                    &digests,
                    &record_ids,
                    64,
                )
                .await?;
                if !duplicates.is_empty() {
                    return Err(PostgresKernelError::FieldEncryptionBlindCollision {
                        entity_id: field.entity_id.to_owned(),
                        record_ids: duplicates,
                    });
                }
            }
            after_record_id = Some(
                rows.last()
                    .and_then(|row| row.try_get(0).ok())
                    .ok_or(PostgresKernelError::RegistryUnavailable)?,
            );
        }
        set_force_row_security(&transaction, &[table.as_str().to_owned()], true).await?;
        transaction
            .commit()
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        Ok(())
    }

    /// Phase 1 cannot safely reinterpret retained change-request copies after
    /// a plaintext-to-envelope boundary. Refuse before the first chunk commits,
    /// while the operator-facing preflight counts identify what must be cleared.
    async fn refuse_retained_plaintext_request_snapshots(
        &mut self,
        history_choice: ReviewedFieldEncryptionHistory,
        covered: &[FieldEncryptionCoveredField<'_>],
    ) -> Result<()> {
        if history_choice != ReviewedFieldEncryptionHistory::RetainPlaintextHistory {
            return Ok(());
        }
        let transaction = self.client.transaction().await?;
        for field in covered {
            let retained: bool = transaction
                .query_one(
                    "SELECT
                         EXISTS (
                             SELECT 1
                               FROM registry_internal.registry_request_targets
                              WHERE target_entity_id = $1
                                AND (base_snapshot ? $2 OR after_snapshot ? $2)
                         )
                         OR EXISTS (
                             SELECT 1
                               FROM registry_internal.registry_request_proposals AS proposal
                              WHERE proposal.snapshot IS NOT NULL
                                AND (
                                    EXISTS (
                                        SELECT 1
                                          FROM jsonb_array_elements(
                                              COALESCE(
                                                  proposal.snapshot -> 'effects',
                                                  '[]'::jsonb
                                              )
                                          ) AS effect
                                          CROSS JOIN LATERAL jsonb_array_elements(
                                              COALESCE(
                                                  effect -> 'fieldChanges',
                                                  '[]'::jsonb
                                              )
                                          ) AS field_change
                                         WHERE effect -> 'target' ->> 'entityId' = $1
                                           AND field_change ->> 'field' = $2
                                    )
                                    OR EXISTS (
                                        SELECT 1
                                          FROM jsonb_array_elements(
                                              COALESCE(
                                                  proposal.snapshot #> '{applicationPreconditions,targets}',
                                                  '[]'::jsonb
                                              )
                                          ) AS guard
                                         WHERE guard ->> 'entityId' = $1
                                           AND guard -> 'values' ? $2
                                    )
                                )
                         )",
                    &[&field.entity_id, &field.candidate.id.as_str()],
                )
                .await
                .map_err(|_| PostgresKernelError::Connection)?
                .get(0);
            if retained {
                return Err(
                    PostgresKernelError::FieldEncryptionRetainedRequestSnapshots {
                        entity_id: field.entity_id.to_owned(),
                        field_id: field.candidate.id.clone(),
                    },
                );
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Seal one chunk of rows: select the keyset page under lock, capture its
    /// pre-change history shape, seal every covered field's plaintext into the
    /// envelope and blind-index columns, journal the change as first-class
    /// internal revisions, and advance the durable cursor, all in one
    /// transaction. The draining chunk, which selects no rows, instead runs the
    /// pre-drop content verification, records the flip boundary rows, and
    /// closes the step.
    async fn execute_field_encryption_chunk(
        &mut self,
        request: FieldEncryptionChunkRequest<'_>,
    ) -> Result<bool> {
        let FieldEncryptionChunkRequest {
            registry,
            step,
            ledger,
            ledger_step,
            descriptor_path,
            target_package_revision,
            table,
            covered,
            service,
            history_choice,
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
        // Plaintext text, journal projections, and the sealed-value check all
        // render typed columns through the session time zone; pin it to the
        // same UTC the runtime read path pins.
        transaction
            .execute("SELECT set_config('TimeZone', 'UTC', true)", &[])
            .await?;

        let prior_projection = covered
            .iter()
            .map(|field| prior_plaintext_projection(field.prior))
            .collect::<Vec<_>>()
            .join(", ");
        let limit = i64::from(chunk_size);
        let select_sql = format!(
            "SELECT record_id, {prior_projection}
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
        if rows.is_empty() {
            // Draining chunk: verify stored content before any reviewed DROP
            // COLUMN can run, record the flip boundary, and close the step in
            // this one transaction so a failure leaves the step resumable.
            let history_commit_position = transaction
                .query_one(
                    "SELECT latest_position
                       FROM registry_internal.registry_commit_head
                      WHERE singleton
                      FOR UPDATE",
                    &[],
                )
                .await
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?
                .get::<_, i64>(0)
                .checked_add(1)
                .ok_or(PostgresKernelError::RegistryUnavailable)?;
            for field in covered {
                let verification = verify_field_encryption_content(
                    &transaction,
                    service,
                    field,
                    &table,
                    target_package_revision,
                )
                .await?;
                record_field_encryption_flip(
                    &transaction,
                    field,
                    target_package_revision,
                    history_choice,
                    history_commit_position,
                    &verification,
                )
                .await?;
            }
            set_force_row_security(&transaction, &[table.as_str().to_owned()], true).await?;
            record_step_complete(&transaction, ledger, ledger_step, progress.affected_rows).await?;
            transaction.commit().await?;
            return Ok(false);
        }

        let ids = rows
            .iter()
            .map(|row| row.try_get::<_, Uuid>(0))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        let selected =
            u64::try_from(ids.len()).map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        let total = progress
            .affected_rows
            .checked_add(selected)
            .filter(|total| *total <= max_total_rows)
            .ok_or(PostgresKernelError::RegistryUnavailable)?;

        let capture =
            prepare_reviewed_page_capture(&transaction, registry, descriptor_path, step, &ids)
                .await
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;

        let update_sql = field_encryption_update_statement(&table, covered);
        for (row_index, record_id) in ids.iter().enumerate() {
            let mut parameters: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![record_id];
            let mut seals: Vec<FieldEncryptionSeal> = Vec::new();
            let mut any_value = false;
            for (field_index, field) in covered.iter().enumerate() {
                let value = rows[row_index]
                    .try_get::<_, Option<Value>>(field_index + 1)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?
                    .unwrap_or(Value::Null);
                let Some(plaintext) = field_plaintext_string(field.prior, &value)? else {
                    seals.push((None, None));
                    continue;
                };
                let envelope = service
                    .seal(
                        field.entity_id,
                        field.candidate.id.as_str(),
                        &record_id.to_string(),
                        plaintext.as_bytes(),
                    )
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
                let blind = field.blind.map(|blind| {
                    service.blind_index(
                        field.entity_id,
                        field.candidate.id.as_str(),
                        &FieldEncryptionService::normalize(&blind.normalization, &plaintext),
                    )
                });
                seals.push((Some(envelope), blind.map(|index| index.to_vec())));
                any_value = true;
            }
            if !any_value {
                // Every covered field is null for this row: nothing to seal,
                // so no revision, no envelope, and no blind index.
                continue;
            }
            for ((envelope, blind), field) in seals.iter().zip(covered) {
                parameters.push(envelope);
                if field.blind.is_some() {
                    parameters.push(blind);
                }
            }
            let changed = transaction
                .execute(&update_sql, &parameters)
                .await
                .map_err(|_| PostgresKernelError::Connection)?;
            if changed != 1 {
                return Err(PostgresKernelError::RegistryUnavailable);
            }
        }

        finish_reviewed_page_update(&transaction, registry, target_package_revision, capture)
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        set_force_row_security(&transaction, &[table.as_str().to_owned()], true).await?;
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
            if let Err(error) = execute_compiled_ddl_statement(
                &transaction,
                statement.sql,
                statement.kind,
                statement.pattern_field,
                runtime_role,
            )
            .await
            {
                transaction.rollback().await?;
                return Err(error);
            }
        }
        for statement in spatial_candidate_view_statements {
            if let Err(error) = execute_compiled_ddl_statement(
                &transaction,
                statement.sql,
                statement.kind,
                statement.pattern_field,
                runtime_role,
            )
            .await
            {
                transaction.rollback().await?;
                return Err(error);
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
        reconcile_runtime_acl_in(&transaction, registry, runtime_role).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Activates a re-apply that changes only the roles the registry serves
    /// with. The move of each spatial candidate view to the serving bbox
    /// role, the control-plane and runtime grants, the retirement of the
    /// runtime role the activation stops serving with and of its bbox role,
    /// and the activation commit in one transaction, so a refused activation
    /// leaves the role the ledger still names with every view and grant it
    /// serves with, and the role it would have served with holds nothing.
    pub(crate) async fn activate_role_change(
        &mut self,
        registry: &CompiledRegistry,
        current: Option<&ExpectedRegistryIdentity>,
        target: &ExpectedRegistryIdentity,
        transition: MaintenanceTransition<'_>,
        retired_runtime_role: Option<&SqlIdentifier>,
    ) -> Result<Vec<Value>> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        target.validate()?;
        transition.ledger.validate()?;
        let transaction = self.client.transaction().await?;
        if let Some(retired) = retired_runtime_role {
            transfer_spatial_candidate_views(
                &transaction,
                registry,
                retired,
                transition.runtime_role,
            )
            .await?;
        }
        install_registry_state_schema(&transaction, transition.runtime_role).await?;
        install_history_schema_store(&transaction, transition.runtime_role)
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        reconcile_runtime_acl_in(&transaction, registry, transition.runtime_role).await?;
        if let Some(retired) = retired_runtime_role {
            retire_runtime_role_in(&transaction, retired, transition.migration_role).await?;
        }
        let superseded =
            activate_verified_package_in(&transaction, current, target, transition).await?;
        transaction.commit().await?;
        Ok(superseded)
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
        if ledger.plan_kind != ActivationPlanKind::Initial
            || ledger.package_digest != target.package_digest
            || ledger.activation_id != target.activation_uuid()?
        {
            return Err(PostgresKernelError::Configuration(
                "initial package and migration ledger differ",
            ));
        }
        let transaction = self.client.transaction().await?;
        begin_initial_in(&transaction, target, ledger, runtime_role).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Runs every check and write [`Self::begin_initial_package`] runs, in
    /// one transaction it rolls back, so a plan reports what the begin would
    /// refuse and leaves the database as it was.
    pub(crate) async fn rehearse_initial_package(
        &mut self,
        target: &ExpectedRegistryIdentity,
        ledger: &MigrationLedgerEntry,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        target.validate()?;
        ledger.validate()?;
        if ledger.plan_kind != ActivationPlanKind::Initial
            || ledger.package_digest != target.package_digest
            || ledger.activation_id != target.activation_uuid()?
        {
            return Err(PostgresKernelError::Configuration(
                "initial package and migration ledger differ",
            ));
        }
        let transaction = self.client.transaction().await?;
        let rehearsed = begin_initial_in(&transaction, target, ledger, runtime_role).await;
        transaction.rollback().await?;
        rehearsed
    }

    /// The kernel state shape this database holds.
    pub(crate) async fn registry_state_shape(&mut self) -> Result<RegistryStateShape> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        Ok(registry_state_shape(&self.client).await?)
    }

    /// The first way the split-role runtime role could write the activation
    /// ledger or the registry state, read under the apply lock.
    pub(crate) async fn runtime_write_authority(
        &mut self,
        migration_role: &SqlIdentifier,
        runtime_role: &SqlIdentifier,
    ) -> Result<Option<super::RuntimeWriteAuthority>> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        super::find_runtime_write_authority(&self.client, migration_role, runtime_role).await
    }

    /// Whether the split-role runtime role lacks a grant the compiled catalog
    /// gives it, read under the apply lock.
    pub(crate) async fn runtime_grants_missing(
        &mut self,
        runtime_role: &SqlIdentifier,
        expected_catalog: &ExpectedManagedCatalog,
    ) -> Result<bool> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        super::runtime_grants_missing(&self.client, runtime_role, expected_catalog).await
    }

    /// Reconciles product-owned control tables before a successor enters
    /// maintenance. This upgrades registries initialized by an older binary,
    /// including installations that predate field-encryption key and flip
    /// state, without giving the runtime role write authority.
    pub(crate) async fn reconcile_successor_control_plane(
        &mut self,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        let transaction = self.client.transaction().await?;
        install_registry_state_schema(&transaction, runtime_role).await?;
        install_history_schema_store(&transaction, runtime_role)
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Records or resumes a successor only when the durable source identity,
    /// exact target, ordered checksums, and activation all agree.
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
        if ledger.plan_kind != ActivationPlanKind::Successor
            || ledger.predecessor_package_digest.as_deref() != Some(current.package_digest.as_str())
            || ledger.package_digest != target.package_digest
            || ledger.activation_id != target.activation_uuid()?
            || target.activation_id == current.activation_id
        {
            return Err(PostgresKernelError::Configuration(
                "successor package and migration ledger differ",
            ));
        }
        let transaction = self.client.transaction().await?;
        begin_successor_in(
            &transaction,
            current,
            target,
            ledger,
            event_destination_compatibility_inventory,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Runs every check and write [`Self::reconcile_successor_control_plane`]
    /// and [`Self::begin_successor_package`] run, in one transaction it rolls
    /// back, so a plan reports what the begin would refuse and leaves the
    /// database as it was.
    pub(crate) async fn rehearse_successor_package(
        &mut self,
        current: &ExpectedRegistryIdentity,
        target: &ExpectedRegistryIdentity,
        ledger: &MigrationLedgerEntry,
        event_destination_compatibility_inventory: Option<&EventDestinationCompatibilityInventory>,
        runtime_role: &SqlIdentifier,
    ) -> Result<()> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        current.validate()?;
        target.validate()?;
        ledger.validate()?;
        if ledger.plan_kind != ActivationPlanKind::Successor
            || ledger.predecessor_package_digest.as_deref() != Some(current.package_digest.as_str())
            || ledger.package_digest != target.package_digest
            || ledger.activation_id != target.activation_uuid()?
            || target.activation_id == current.activation_id
        {
            return Err(PostgresKernelError::Configuration(
                "successor package and migration ledger differ",
            ));
        }
        let transaction = self.client.transaction().await?;
        let rehearsed = async {
            install_registry_state_schema(&transaction, runtime_role).await?;
            install_history_schema_store(&transaction, runtime_role)
                .await
                .map_err(|_| PostgresKernelError::Connection)?;
            begin_successor_in(
                &transaction,
                current,
                target,
                ledger,
                event_destination_compatibility_inventory,
            )
            .await
        }
        .await;
        transaction.rollback().await?;
        rehearsed
    }

    /// Records maintenance in its own committed transaction while retaining
    /// the session lock.
    #[cfg(feature = "postgres-test")]
    pub async fn mark_applying(
        &mut self,
        current: &ExpectedRegistryIdentity,
        target_package_digest: &str,
    ) -> Result<()> {
        current.validate()?;
        if target_package_digest.is_empty() {
            return Err(PostgresKernelError::Configuration(
                "apply target package digest must be non-empty",
            ));
        }
        let transaction = self.client.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET maintenance_status = 'applying', maintenance_target_package_digest = $1,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND maintenance_status = 'ready'
                   AND package_id = $2
                   AND database_id = $3
                   AND active_package_digest = $4
                   AND active_activation_id = $5
                   AND schema_fingerprint = $6",
                &[
                    &target_package_digest,
                    &current.package_id,
                    &current.database_id,
                    &current.package_digest,
                    &current.activation_uuid()?,
                    &current.schema_fingerprint,
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
        target_package_digest: &str,
    ) -> Result<()> {
        validate_failed_resume_request(self.locked, current, target_package_digest)?;
        let transaction = self.client.transaction().await?;
        let accepted = transaction
            .query_opt(
                "SELECT 1
                 FROM registry_internal.registry_state
                 WHERE singleton
                   AND maintenance_status = 'failed'
                   AND maintenance_target_package_digest = $1
                   AND package_id = $2
                   AND database_id = $3
                   AND active_package_digest = $4
                   AND active_activation_id = $5
                   AND schema_fingerprint = $6
                 FOR UPDATE",
                &[
                    &target_package_digest,
                    &current.package_id,
                    &current.database_id,
                    &current.package_digest,
                    &current.activation_uuid()?,
                    &current.schema_fingerprint,
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
    /// exact package digest and its activation ready only after closed
    /// catalog, RLS, ACL, ownership, and schema-fingerprint verification
    /// succeeds. Answers the supersession record of every import authority
    /// the activation retired, which the caller appends to the audit once
    /// the activation has committed.
    pub(crate) async fn activate_verified_package(
        &mut self,
        current: Option<&ExpectedRegistryIdentity>,
        target: &ExpectedRegistryIdentity,
        transition: MaintenanceTransition<'_>,
    ) -> Result<Vec<Value>> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        target.validate()?;
        transition.ledger.validate()?;
        let transaction = self.client.transaction().await?;
        let superseded =
            activate_verified_package_in(&transaction, current, target, transition).await?;
        transaction.commit().await?;
        Ok(superseded)
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
                 SET active_package_digest = $1,
                     active_activation_id = $2,
                     schema_fingerprint = $3,
                     maintenance_status = 'ready',
                     maintenance_target_package_digest = NULL,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND package_id = $4
                   AND database_id = $5
                   AND maintenance_status IN ('applying', 'failed')
                   AND maintenance_target_package_digest = $1
                   AND active_activation_id <> $2",
                &[
                    &target.package_digest,
                    &target.activation_uuid()?,
                    &target.schema_fingerprint,
                    &target.package_id,
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
                   AND database_id = $2
                   AND maintenance_status IN ('applying', 'failed')
                   AND maintenance_target_package_digest = $3",
                &[
                    &target.package_id,
                    &target.database_id,
                    &target.package_digest,
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

    /// The activation a retry of `package_digest` resumes: the open
    /// activation the ledger records for it, if any. A database with no
    /// ledger yet has none.
    pub(crate) async fn in_flight_activation(
        &mut self,
        package_digest: &str,
    ) -> Result<Option<super::migration_ledger::InFlightActivation>> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        let ledger_exists: bool = self
            .client
            .query_one(
                "SELECT to_regclass('registry_internal.registry_migrations') IS NOT NULL",
                &[],
            )
            .await?
            .try_get(0)?;
        if !ledger_exists {
            return Ok(None);
        }
        in_flight_activation(&self.client, package_digest).await
    }

    /// The role mode and runtime role the ledger records for the active
    /// activation. A database whose active activation has no applied ledger
    /// row answers none.
    pub(crate) async fn active_activation_roles(&mut self) -> Result<Option<(String, String)>> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        let row = self
            .client
            .query_opt(
                "SELECT migration.role_mode, migration.runtime_role
                 FROM registry_internal.registry_state AS state
                 JOIN registry_internal.registry_migrations AS migration
                   ON migration.activation_id = state.active_activation_id
                 WHERE state.singleton AND migration.outcome = 'applied'",
                &[],
            )
            .await?;
        Ok(row.map(|row| (row.get(0), row.get(1))))
    }

    /// Whether a role of this name exists. A runtime role the ledger records
    /// can be dropped or renamed by an administrator after its activation.
    pub(crate) async fn role_exists(&mut self, role: &SqlIdentifier) -> Result<bool> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        Ok(self
            .client
            .query_one("SELECT to_regrole($1) IS NOT NULL", &[&role.as_str()])
            .await?
            .try_get(0)?)
    }

    /// Reads the durable maintenance state while this session holds the
    /// exclusive apply lock, so a reconciling operator can be told what the
    /// database actually records rather than inferring it from a failure.
    pub(crate) async fn maintenance_snapshot(&mut self) -> Result<MaintenanceSnapshot> {
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        let row = self
            .client
            .query_opt(
                "SELECT package_id, database_id, active_package_digest,
                        active_activation_id::text, schema_fingerprint,
                        maintenance_status, maintenance_target_package_digest
                 FROM registry_internal.registry_state
                 WHERE singleton",
                &[],
            )
            .await
            .map_err(|error| {
                // A provisioned database that was never activated has no
                // registry state table. The database answered, so this is
                // absent state like a missing singleton row, not a lost
                // connection; every other driver error stays a connection
                // failure.
                if error.code() == Some(&tokio_postgres::error::SqlState::UNDEFINED_TABLE) {
                    PostgresKernelError::RegistryUnavailable
                } else {
                    PostgresKernelError::from(error)
                }
            })?
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        Ok(MaintenanceSnapshot {
            identity: ExpectedRegistryIdentity {
                package_id: row.try_get(0)?,
                database_id: row.try_get(1)?,
                package_digest: row.try_get(2)?,
                activation_id: row.try_get(3)?,
                schema_fingerprint: row.try_get(4)?,
            },
            maintenance_status: row.try_get(5)?,
            maintenance_target_package_digest: row.try_get(6)?,
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
    /// ledger row is closed as reverted, so a later apply of the same package
    /// is a separate activation with its own id and never resumes the
    /// abandoned one.
    pub(crate) async fn revert_failed_package(
        &mut self,
        current: &ExpectedRegistryIdentity,
        target_package_digest: &str,
        transition: MaintenanceTransition<'_>,
    ) -> Result<()> {
        let MaintenanceTransition {
            ledger,
            expected_catalog,
            migration_role,
            runtime_role,
        } = transition;
        ensure_verified_package_session(self.locked, self.verified_migration_role)?;
        validate_failed_resume_request(self.locked, current, target_package_digest)?;
        ledger.validate()?;
        if ledger.package_digest != target_package_digest
            || ledger.predecessor_package_digest.as_deref() != Some(current.package_digest.as_str())
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
                     maintenance_target_package_digest = NULL,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND package_id = $1
                   AND database_id = $2
                   AND active_package_digest = $3
                   AND active_activation_id = $4
                   AND schema_fingerprint = $5
                   AND maintenance_status IN ('applying', 'failed')
                   AND maintenance_target_package_digest = $6",
                &[
                    &current.package_id,
                    &current.database_id,
                    &current.package_digest,
                    &current.activation_uuid()?,
                    &current.schema_fingerprint,
                    &target_package_digest,
                ],
            )
            .await?;
        if changed != 1 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        record_reverted(&transaction, ledger).await?;
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

/// The activation transaction's work: closed catalog verification, the
/// applied ledger outcome, and the registry state transition. Answers the
/// supersession record of every import authority the activation retired.
async fn activate_verified_package_in(
    transaction: &tokio_postgres::Transaction<'_>,
    current: Option<&ExpectedRegistryIdentity>,
    target: &ExpectedRegistryIdentity,
    transition: MaintenanceTransition<'_>,
) -> Result<Vec<Value>> {
    let MaintenanceTransition {
        ledger,
        expected_catalog,
        migration_role,
        runtime_role,
    } = transition;
    verify_managed_catalog(
        transaction,
        target,
        expected_catalog,
        migration_role,
        runtime_role,
    )
    .await?;
    // A field-encryption erase lifecycle marks coverage incomplete before
    // releasing its first lock transaction. Refusing successor activation
    // until rebaseline completes freezes the durable flip manifest used to
    // correlate crash-resumable audit counts.
    if current.is_some() {
        verify_complete_history_coverage(transaction).await?;
    }
    record_applied(transaction, ledger).await?;
    // A registry that has never recorded a claim, as one upgraded from a
    // release before the claim, is claimed by the activation that runs in
    // it. A recorded claim is kept, so a restored copy stays a copy until
    // an operator adopts it.
    crate::instance_claim::record_if_unclaimed(transaction).await?;
    let changed = if let Some(current) = current {
        current.validate()?;
        transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET active_package_digest = $1,
                     active_activation_id = $2,
                     schema_fingerprint = $3,
                     maintenance_status = 'ready',
                     maintenance_target_package_digest = NULL,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND package_id = $4
                   AND database_id = $5
                   AND active_package_digest = $6
                   AND active_activation_id = $7
                   AND schema_fingerprint = $8
                   AND maintenance_status IN ('applying', 'failed')
                   AND maintenance_target_package_digest = $1",
                &[
                    &target.package_digest,
                    &target.activation_uuid()?,
                    &target.schema_fingerprint,
                    &target.package_id,
                    &target.database_id,
                    &current.package_digest,
                    &current.activation_uuid()?,
                    &current.schema_fingerprint,
                ],
            )
            .await?
    } else {
        transaction
            .execute(
                "UPDATE registry_internal.registry_state
                 SET maintenance_status = 'ready',
                     maintenance_target_package_digest = NULL,
                     updated_at = transaction_timestamp()
                 WHERE singleton
                   AND package_id = $1
                   AND database_id = $2
                   AND active_package_digest = $3
                   AND active_activation_id = $4
                   AND schema_fingerprint = $5
                   AND maintenance_status IN ('applying', 'failed')
                   AND maintenance_target_package_digest = $3",
                &[
                    &target.package_id,
                    &target.database_id,
                    &target.package_digest,
                    &target.activation_uuid()?,
                    &target.schema_fingerprint,
                ],
            )
            .await?
    };
    if changed != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    // A model change retires every grant an operator opened under the
    // activation it replaces, so the transaction that makes the target
    // active also supersedes every open import authority.
    let mut superseded = Vec::new();
    crate::import_authority::supersede_every_open(
        transaction,
        &mut superseded,
        &target.activation_id,
    )
    .await
    .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    Ok(superseded)
}

/// Installs the mutation schema and the compiled runtime grants inside the
/// caller's transaction.
async fn reconcile_runtime_acl_in(
    transaction: &tokio_postgres::Transaction<'_>,
    registry: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    install_mutation_schema(transaction, runtime_role)
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    reconcile_compiled_runtime_acl(transaction, registry, runtime_role).await
}

/// Retires the runtime role an activation stops serving with, so the role
/// a registry stops serving with keeps no access it held as the runtime.
/// A separate runtime role loses every privilege on the managed schemas
/// and their tables, sequences, and functions; a role that no longer
/// exists holds nothing to revoke. When the retired runtime role is the
/// migration role, it keeps its ownership and loses only the column
/// grants it held as the runtime, which the serving runtime role now holds.
/// The spatial bbox role of the retired runtime role, which no longer owns a
/// candidate view once the activation moved them, loses every privilege on
/// the managed schemas either way.
async fn retire_runtime_role_in(
    transaction: &tokio_postgres::Transaction<'_>,
    retired: &SqlIdentifier,
    migration_role: &SqlIdentifier,
) -> Result<()> {
    if retired == migration_role {
        let revokes = transaction
            .query(
                "SELECT DISTINCT format(
                     'REVOKE ALL (%I) ON TABLE %I.%I FROM %I',
                     attribute.attname, namespace.nspname, class.relname,
                     pg_catalog.pg_get_userbyid(class.relowner)
                 )
                 FROM pg_catalog.pg_class AS class
                 JOIN pg_catalog.pg_namespace AS namespace
                   ON namespace.oid = class.relnamespace
                 JOIN pg_catalog.pg_attribute AS attribute
                   ON attribute.attrelid = class.oid
                  AND attribute.attnum > 0
                  AND NOT attribute.attisdropped
                 CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
                 WHERE namespace.nspname = ANY($1::text[])
                   AND acl.grantee = class.relowner",
                &[&super::catalog::MANAGED_SCHEMAS],
            )
            .await?;
        for revoke in revokes {
            let revoke: String = revoke.try_get(0)?;
            transaction.batch_execute(&revoke).await?;
        }
    } else {
        let exists: bool = transaction
            .query_one("SELECT to_regrole($1) IS NOT NULL", &[&retired.as_str()])
            .await?
            .try_get(0)?;
        if exists {
            let schemas = super::catalog::MANAGED_SCHEMAS.join(", ");
            let role = retired.quoted();
            transaction
                .batch_execute(&format!(
                    "REVOKE ALL ON ALL TABLES IN SCHEMA {schemas} FROM {role};
                     REVOKE ALL ON ALL SEQUENCES IN SCHEMA {schemas} FROM {role};
                     REVOKE ALL ON ALL FUNCTIONS IN SCHEMA {schemas} FROM {role};
                     REVOKE ALL ON SCHEMA {schemas} FROM {role};"
                ))
                .await?;
        }
    }
    retire_spatial_bbox_role(transaction, retired, super::catalog::MANAGED_SCHEMAS).await?;
    Ok(())
}

/// Refuse a successor unless history coverage is complete or narrowed only by
/// a recorded standalone erasure. An absent commit head is refused here; only
/// the begin check admits it.
async fn verify_complete_history_coverage(
    client: &impl tokio_postgres::GenericClient,
) -> Result<()> {
    if !history_coverage_admits_successor(client)
        .await?
        .unwrap_or(false)
    {
        return Err(PostgresKernelError::HistoryCoverageIncomplete);
    }
    Ok(())
}

/// The begin of an initial activation, inside the caller's transaction.
async fn begin_initial_in(
    transaction: &tokio_postgres::Transaction<'_>,
    target: &ExpectedRegistryIdentity,
    ledger: &MigrationLedgerEntry,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    install_registry_state_schema(transaction, runtime_role).await?;
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_state (
                 singleton, package_id, database_id, active_package_digest,
                 active_activation_id, schema_fingerprint,
                 maintenance_status, maintenance_target_package_digest
             ) VALUES (true, $1, $2, $3, $4, $5, 'applying', $3)
             ON CONFLICT (singleton) DO NOTHING",
            &[
                &target.package_id,
                &target.database_id,
                &target.package_digest,
                &target.activation_uuid()?,
                &target.schema_fingerprint,
            ],
        )
        .await?;
    if changed == 1 {
        crate::instance_claim::record_if_unclaimed(transaction).await?;
        record_started(transaction, ledger).await?;
    } else {
        verify_initial_resumable_state(transaction, target).await?;
        verify_resumable(transaction, ledger).await?;
    }
    Ok(())
}

/// The begin of a successor activation, inside the caller's transaction.
async fn begin_successor_in(
    transaction: &tokio_postgres::Transaction<'_>,
    current: &ExpectedRegistryIdentity,
    target: &ExpectedRegistryIdentity,
    ledger: &MigrationLedgerEntry,
    event_destination_compatibility_inventory: Option<&EventDestinationCompatibilityInventory>,
) -> Result<()> {
    // Refuse before maintenance or ledger state can start: otherwise a
    // successor could add new flip rows while an erase lifecycle is using
    // the current durable flip manifest for crash-resumable correlation.
    verify_history_coverage_can_begin_successor(transaction).await?;
    verify_retained_webhook_delivery_bindings(
        transaction,
        event_destination_compatibility_inventory,
    )
    .await?;
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_state
             SET maintenance_status = 'applying', maintenance_target_package_digest = $1,
                 updated_at = transaction_timestamp()
             WHERE singleton
               AND maintenance_status = 'ready'
               AND package_id = $2
               AND database_id = $3
               AND active_package_digest = $4
               AND active_activation_id = $5
               AND schema_fingerprint = $6",
            &[
                &target.package_digest,
                &current.package_id,
                &current.database_id,
                &current.package_digest,
                &current.activation_uuid()?,
                &current.schema_fingerprint,
            ],
        )
        .await?;
    if changed == 1 {
        record_started(transaction, ledger).await?;
    } else {
        verify_successor_resumable_state(transaction, current, target).await?;
        verify_resumable(transaction, ledger).await?;
    }
    Ok(())
}

/// Permit a legacy registry with no commit head to enter the successor path
/// that establishes its first baseline. Once a head exists, coverage that is
/// not ready means an erase lifecycle may be active and must freeze successors.
async fn verify_history_coverage_can_begin_successor(
    client: &impl tokio_postgres::GenericClient,
) -> Result<()> {
    if !history_coverage_admits_successor(client)
        .await?
        .unwrap_or(true)
    {
        return Err(PostgresKernelError::HistoryCoverageIncomplete);
    }
    Ok(())
}

/// Whether the locked commit head admits a successor package, or `None` when
/// the registry has no commit head yet.
///
/// Complete coverage admits it. So does coverage that a standalone erasure
/// narrowed after the baseline: that erasure leaves the head ready with an
/// unavailable-after position, and records the same position in
/// `registry_history_erasure_coverage` in its own commit. A lifecycle erasure,
/// an erasure at or before the baseline, and every other gap leave the head
/// not ready or unrecorded, and still freeze successors until a rebaseline.
async fn history_coverage_admits_successor(
    client: &impl tokio_postgres::GenericClient,
) -> Result<Option<bool>> {
    let Some(head) = client
        .query_opt(
            "SELECT coverage_ready, unavailable_after_position
               FROM registry_internal.registry_commit_head
              WHERE singleton
              FOR UPDATE",
            &[],
        )
        .await?
    else {
        return Ok(None);
    };
    let coverage_ready: bool = head.get(0);
    let unavailable_after_position: Option<i64> = head.get(1);
    let Some(unavailable_after_position) = unavailable_after_position else {
        return Ok(Some(coverage_ready));
    };
    if !coverage_ready {
        return Ok(Some(false));
    }
    let recorded = client
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM registry_internal.registry_history_erasure_coverage
                  WHERE unavailable_after_position = $1
             )",
            &[&unavailable_after_position],
        )
        .await?
        .get::<_, bool>(0);
    Ok(Some(recorded))
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

/// Drop every view in the two compiler-owned read schemas.
pub(super) async fn drop_managed_read_view_set(client: &impl GenericClient) -> Result<()> {
    // These two schemas are a closed compiler-owned boundary. Reviewed
    // column changes may require their dependent views to be removed
    // first; exact package DDL recreates every candidate view afterward.
    let rows = client
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
        client
            .batch_execute(&format!(
                "DROP VIEW {}.{} RESTRICT",
                schema.quoted(),
                view.quoted()
            ))
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
    }
    Ok(())
}

pub(super) fn compiler_statement_runs_after_reviewed_steps(
    statement: &PackageDdlStatement<'_>,
) -> bool {
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
            && statement.sql.contains("\"breg_spgeom_"))
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

fn map_reviewed_pattern_error(
    error: tokio_postgres::Error,
    registry: &CompiledRegistry,
    step: &ValidatedReviewedMigrationStep,
) -> PostgresKernelError {
    let field = error
        .as_db_error()
        .and_then(|error| error.constraint())
        .and_then(|constraint| pattern_field_for_constraint(registry, constraint))
        .or_else(|| {
            if error.code() != Some(&tokio_postgres::error::SqlState::INVALID_REGULAR_EXPRESSION) {
                return None;
            }
            let objects = match &step.descriptor {
                ReviewedMigrationStepDescriptor::TransactionalSql { objects, .. }
                | ReviewedMigrationStepDescriptor::ChunkedBackfill { objects, .. }
                | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { objects, .. } => {
                    objects
                }
            };
            let mut fields = objects
                .iter()
                .filter_map(|object| pattern_field_for_constraint(registry, &object.physical_name));
            let field = fields.next()?;
            // A PostgreSQL syntax error has no constraint name. Keep a field
            // address only when the reviewed step binds one unambiguous rule.
            fields.all(|other| other == field).then_some(field)
        });
    map_pattern_database_error(error, field)
}

fn step_tables(step: &ValidatedReviewedMigrationStep) -> Result<Vec<String>> {
    let objects = match &step.descriptor {
        ReviewedMigrationStepDescriptor::TransactionalSql { objects, .. }
        | ReviewedMigrationStepDescriptor::ChunkedBackfill { objects, .. }
        | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { objects, .. } => objects,
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

/// Resolve the covered fields of one field-encryption backfill step: the
/// successor fields the step's objects name, each paired with its predecessor
/// plaintext field from the verified baseline. A predecessor that is already
/// encrypted names a key rotation, which this engine step does not implement,
/// so it fails closed.
pub(crate) fn covered_field_encryption_fields<'a>(
    registry: &'a CompiledRegistry,
    predecessor_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
    entity_id: &'a str,
    step: &ValidatedReviewedMigrationStep,
) -> Result<Vec<FieldEncryptionCoveredField<'a>>> {
    let entity: &CompiledEntity = registry
        .entities()
        .get(entity_id)
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    let baseline = predecessor_baseline.ok_or(PostgresKernelError::RegistryUnavailable)?;
    let prior_entity = baseline
        .entities
        .get(entity_id)
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    let objects = match &step.descriptor {
        ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { objects, .. } => objects,
        _ => return Err(PostgresKernelError::RegistryUnavailable),
    };
    let mut covered = Vec::new();
    for object in objects {
        let member_id = object
            .member_id
            .as_deref()
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        if member_id.ends_with("#lookup") {
            continue;
        }
        let candidate = entity
            .fields
            .get(member_id)
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        if candidate.encryption.is_none() {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        let prior = prior_entity
            .fields
            .get(member_id)
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        if prior.encryption.is_some() {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
        let api_name = entity
            .stored_fields
            .iter()
            .find(|field| field.logical.id == member_id)
            .map(|field| field.logical.api_name.as_str())
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        let predecessor_api_name = prior_entity
            .stored_fields
            .iter()
            .find(|field| field.logical.id == member_id)
            .map(|field| field.logical.api_name.as_str())
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        covered.push(FieldEncryptionCoveredField {
            entity_id,
            candidate,
            prior,
            blind: candidate
                .encryption
                .as_ref()
                .and_then(|encryption| encryption.blind_index.as_ref()),
            api_name,
            predecessor_api_name,
            logical_field_id: candidate.id.as_str(),
        });
    }
    if covered.is_empty() {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(covered)
}

/// The JSON projection of one predecessor plaintext column, matching the shape
/// the mutation read path serves, so sealing derives exactly the canonical
/// string a re-submitted current value would carry.
pub(crate) fn prior_plaintext_projection(prior: &CompiledField) -> String {
    let column = crate::generated_ddl::quote_identifier(&prior.physical_name);
    match &prior.field_type {
        crate::contract::FieldTypeSource::Decimal { .. } => format!("to_jsonb({column}::text)"),
        _ => format!("to_jsonb({column})"),
    }
}

/// The canonical plaintext string of one projected column value, or `None` for
/// null. Validation is the same field-type validation a write passes, so a
/// stored value that no longer parses fails the apply closed instead of
/// sealing an unusable string.
pub(crate) fn field_plaintext_string(
    prior: &CompiledField,
    value: &Value,
) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }
    if !crate::data::validate_field_value(crate::data::FieldValue::Json(value), &prior.field_type) {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    let text = match &prior.field_type {
        crate::contract::FieldTypeSource::Boolean => value
            .as_bool()
            .ok_or(PostgresKernelError::RegistryUnavailable)?
            .to_string(),
        crate::contract::FieldTypeSource::Int64 => value
            .as_i64()
            .ok_or(PostgresKernelError::RegistryUnavailable)?
            .to_string(),
        crate::contract::FieldTypeSource::Crs84Point { .. }
        | crate::contract::FieldTypeSource::Structured { .. } => String::from_utf8(
            registry_platform_canonical_json::canonicalize_json(value)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
        )
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
        _ => value
            .as_str()
            .ok_or(PostgresKernelError::RegistryUnavailable)?
            .to_owned(),
    };
    Ok(Some(text))
}

/// Prepare transaction-local, value-free collision state shared by the apply
/// and operator preflights. The migration role contract includes temporary
/// table authority. Only keyed 32-byte digests and record ids cross into it;
/// normalized plaintext remains in the bounded client page that derived them.
pub(crate) async fn prepare_unique_blind_index_preflight(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<()> {
    transaction
        .batch_execute(
            "CREATE TEMPORARY TABLE IF NOT EXISTS field_encryption_preflight_unique_values (
                 field_slot smallint NOT NULL,
                 digest bytea NOT NULL,
                 first_record_id uuid NOT NULL,
                 PRIMARY KEY (field_slot, digest)
             ) ON COMMIT DROP;
             TRUNCATE pg_temp.field_encryption_preflight_unique_values",
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    Ok(())
}

/// Insert one bounded digest page, retaining only the first record for each
/// field/digest pair, then return the bounded record ids participating in a
/// collision introduced by this page. The insert and lookup are separate
/// statements so the lookup sees rows the insert just committed to the
/// transaction-local table.
pub(crate) async fn record_unique_blind_index_page(
    transaction: &tokio_postgres::Transaction<'_>,
    field_slot: i16,
    digests: &[Vec<u8>],
    record_ids: &[Uuid],
    maximum_named_records: i64,
) -> Result<Vec<String>> {
    if digests.len() != record_ids.len() || maximum_named_records <= 0 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    if digests.is_empty() {
        return Ok(Vec::new());
    }
    // `tokio-postgres` encodes PostgreSQL arrays from owned vectors. These
    // clones remain page-bounded and avoid handing it a doubly borrowed slice.
    let page_digests = digests.to_vec();
    let page_record_ids = record_ids.to_vec();
    transaction
        .execute(
            "INSERT INTO pg_temp.field_encryption_preflight_unique_values
                 (field_slot, digest, first_record_id)
             SELECT DISTINCT ON (page.digest) $1, page.digest, page.record_id
               FROM unnest($2::bytea[], $3::uuid[]) WITH ORDINALITY
                    AS page(digest, record_id, ordinal)
              ORDER BY page.digest, page.ordinal
             ON CONFLICT (field_slot, digest) DO NOTHING",
            &[&field_slot, &page_digests, &page_record_ids],
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    transaction
        .query(
            "WITH page AS (
                 SELECT digest, record_id
                   FROM unnest($2::bytea[], $3::uuid[]) AS value(digest, record_id)
             ), collision_records AS (
                 SELECT stored.first_record_id AS record_id
                   FROM page
                   JOIN pg_temp.field_encryption_preflight_unique_values AS stored
                     ON stored.field_slot = $1
                    AND stored.digest = page.digest
                  WHERE stored.first_record_id <> page.record_id
                 UNION
                 SELECT page.record_id
                   FROM page
                   JOIN pg_temp.field_encryption_preflight_unique_values AS stored
                     ON stored.field_slot = $1
                    AND stored.digest = page.digest
                  WHERE stored.first_record_id <> page.record_id
             )
             SELECT record_id::text
               FROM collision_records
              ORDER BY record_id
              LIMIT $4",
            &[
                &field_slot,
                &page_digests,
                &page_record_ids,
                &maximum_named_records,
            ],
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?
        .into_iter()
        .map(|row| {
            row.try_get(0)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)
        })
        .collect()
}

/// The fixed per-row sealing statement of one step: every covered field's
/// envelope column and blind-index column are set together with the plaintext
/// column being nulled, in the same row update.
fn field_encryption_update_statement(
    table: &SqlIdentifier,
    covered: &[FieldEncryptionCoveredField<'_>],
) -> String {
    let mut assignments = Vec::new();
    let mut parameter = 2;
    for field in covered {
        let envelope = crate::generated_ddl::quote_identifier(&field.candidate.physical_name);
        assignments.push(format!("{envelope} = ${parameter}"));
        parameter += 1;
        if let Some(blind) = field.blind {
            let blind_column = crate::generated_ddl::quote_identifier(&blind.physical_name);
            assignments.push(format!("{blind_column} = ${parameter}"));
            parameter += 1;
        }
        let plaintext = crate::generated_ddl::quote_identifier(&field.prior.physical_name);
        assignments.push(format!("{plaintext} = NULL"));
    }
    format!(
        "UPDATE registry_data.{}
            SET {}
          WHERE record_id = $1",
        table.quoted(),
        assignments.join(", ")
    )
}

/// The value-free content counts one field's pre-drop verification produced.
/// Every count names rows, never values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FieldEncryptionContentVerification {
    sealed_rows: u64,
    sealed_journal_rows: u64,
    accepted_plaintext_journal_rows: u64,
    accepted_request_target_rows: u64,
    accepted_request_proposal_rows: u64,
    accepted_idempotency_rows: u64,
    accepted_outbox_rows: u64,
}

/// Verify one covered field's stored content, by counting every affected row,
/// before any reviewed DROP COLUMN of the plaintext column can run.
///
/// The live table is authoritative: every row either carries no value, or an
/// envelope that authenticates and whose recomputed blind index matches the
/// stored one. Any remaining live plaintext fails closed. The journal, change
/// request targets and proposals, cached responses, and retained outbox
/// payloads are counted per copy and classified as sealed or as plaintext the
/// declared history choice explicitly accepts; nothing is decrypted into a
/// row it did not already seal.
async fn verify_field_encryption_content(
    transaction: &tokio_postgres::Transaction<'_>,
    service: &FieldEncryptionService,
    field: &FieldEncryptionCoveredField<'_>,
    table: &SqlIdentifier,
    target_package_revision: &str,
) -> Result<FieldEncryptionContentVerification> {
    let mut verification = FieldEncryptionContentVerification::default();
    let entity_id = field.entity_id;
    let field_id = field.logical_field_id;

    let envelope_column = crate::generated_ddl::quote_identifier(&field.candidate.physical_name);
    let plaintext_projection = prior_plaintext_projection(field.prior);
    let blind_selection = field
        .blind
        .map(|blind| {
            format!(
                ", {}",
                crate::generated_ddl::quote_identifier(&blind.physical_name)
            )
        })
        .unwrap_or_default();
    let live_sql = format!(
        "SELECT record_id, {envelope_column}{blind_selection}, {plaintext_projection}
           FROM registry_data.{}
          WHERE ($1::uuid IS NULL OR record_id > $1::uuid)
          ORDER BY record_id",
        table.quoted()
    );
    let live_sql = format!("{live_sql} LIMIT $2");
    let mut after_record_id: Option<Uuid> = None;
    loop {
        let live_rows = transaction
            .query(
                &live_sql,
                &[
                    &after_record_id,
                    &FIELD_ENCRYPTION_LIVE_VERIFICATION_PAGE_SIZE,
                ],
            )
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        if live_rows.is_empty() {
            break;
        }
        for row in &live_rows {
            let record_uuid: Uuid = row
                .try_get(0)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            let record_id = record_uuid.to_string();
            let envelope: Option<Vec<u8>> = row
                .try_get(1)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            let blind: Option<Vec<u8>> = if field.blind.is_some() {
                row.try_get(2)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?
            } else {
                None
            };
            let plaintext_column_index = if field.blind.is_some() { 3 } else { 2 };
            let plaintext = row
                .try_get::<_, Option<Value>>(plaintext_column_index)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?
                .unwrap_or(Value::Null);
            if !plaintext.is_null() {
                // The live row still holds plaintext this step was required to seal.
                return Err(PostgresKernelError::RegistryUnavailable);
            }
            let Some(envelope) = envelope else {
                if blind.is_some() {
                    return Err(PostgresKernelError::RegistryUnavailable);
                }
                after_record_id = Some(record_uuid);
                continue;
            };
            let opened = service
                .open(entity_id, field_id, &record_id, &envelope)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            if let Some(blind_config) = field.blind {
                let plaintext = String::from_utf8(opened.to_vec())
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
                let expected = service.blind_index(
                    entity_id,
                    field_id,
                    &FieldEncryptionService::normalize(&blind_config.normalization, &plaintext),
                );
                match blind {
                    Some(stored) if stored.as_slice() == expected.as_slice() => {}
                    _ => return Err(PostgresKernelError::RegistryUnavailable),
                }
            } else if blind.is_some() {
                return Err(PostgresKernelError::RegistryUnavailable);
            }
            verification.sealed_rows = verification
                .sealed_rows
                .checked_add(1)
                .ok_or(PostgresKernelError::RegistryUnavailable)?;
            after_record_id = Some(record_uuid);
        }
    }

    // Journal rows this apply wrote at the target revision must carry the
    // tagged envelope member and authenticate; a plaintext member at or after
    // the boundary is the masquerade direction and fails closed.
    let journal_sql = "SELECT record_id, record_revision, snapshot
                         FROM registry_internal.registry_revisions
                        WHERE entity_id = $1
                          AND package_revision = $2
                          AND (
                              $3::uuid IS NULL
                              OR (record_id, record_revision) > ($3::uuid, $4::bigint)
                          )
                        ORDER BY record_id, record_revision
                        LIMIT $5";
    let mut after_journal_record_id: Option<Uuid> = None;
    let mut after_journal_revision: Option<i64> = None;
    loop {
        let journal_rows = transaction
            .query(
                journal_sql,
                &[
                    &entity_id,
                    &target_package_revision,
                    &after_journal_record_id,
                    &after_journal_revision,
                    &FIELD_ENCRYPTION_JOURNAL_VERIFICATION_PAGE_SIZE,
                ],
            )
            .await
            .map_err(|_| PostgresKernelError::Connection)?;
        if journal_rows.is_empty() {
            break;
        }
        for row in &journal_rows {
            let record_uuid: Uuid = row
                .try_get(0)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            let record_revision: i64 = row
                .try_get(1)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            let snapshot: Option<Vec<u8>> = row
                .try_get(2)
                .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
            if let Some(snapshot) = snapshot {
                let snapshot: Value = serde_json::from_slice(&snapshot)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
                if let Some(member) = snapshot.get(field_id) {
                    let Some(envelope) =
                        registry_platform_crypto::field_encryption::parse_envelope_member(member)
                    else {
                        return Err(PostgresKernelError::RegistryUnavailable);
                    };
                    service
                        .open(entity_id, field_id, &record_uuid.to_string(), &envelope)
                        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
                    verification.sealed_journal_rows = verification
                        .sealed_journal_rows
                        .checked_add(1)
                        .ok_or(PostgresKernelError::RegistryUnavailable)?;
                }
            }
            after_journal_record_id = Some(record_uuid);
            after_journal_revision = Some(record_revision);
        }
    }

    let accepted_plaintext_journal = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1
                AND package_revision <> $2
                AND convert_from(snapshot, 'UTF8')::jsonb ? $3",
            &[&entity_id, &target_package_revision, &field_id],
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    verification.accepted_plaintext_journal_rows =
        u64::try_from(accepted_plaintext_journal.get::<_, i64>(0))
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;

    // Every target copy present while the flip transaction holds the apply
    // lock predates the flip. A structured plaintext value can legitimately
    // have the envelope tag's JSON shape, so value shape cannot subtract it
    // from the accepted pre-flip count. Proposal copies include both frozen
    // effect changes and application-precondition guard values.
    let request_targets = transaction
        .query_one(
            "SELECT count(*) FILTER (
                        WHERE base_snapshot ? $2 OR after_snapshot ? $2
                    )::bigint
               FROM registry_internal.registry_request_targets
              WHERE target_entity_id = $1",
            &[&entity_id, &field_id],
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    let target_mentions: i64 = request_targets.get(0);
    verification.accepted_request_target_rows =
        u64::try_from(target_mentions).map_err(|_| PostgresKernelError::RegistryUnavailable)?;

    let request_proposals = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_request_proposals AS proposal
              WHERE snapshot IS NOT NULL
                AND (
                    EXISTS (
                        SELECT 1
                          FROM jsonb_array_elements(
                                   COALESCE(proposal.snapshot -> 'effects', '[]'::jsonb)
                               ) AS effect
                          CROSS JOIN LATERAL jsonb_array_elements(
                              COALESCE(effect -> 'fieldChanges', '[]'::jsonb)
                          ) AS field_change
                         WHERE effect -> 'target' ->> 'entityId' = $1
                           AND field_change ->> 'field' = $2
                    )
                    OR EXISTS (
                        SELECT 1
                          FROM jsonb_array_elements(
                              COALESCE(
                                  proposal.snapshot #> '{applicationPreconditions,targets}',
                                  '[]'::jsonb
                              )
                          ) AS guard
                         WHERE guard ->> 'entityId' = $1
                           AND guard -> 'values' ? $2
                    )
                )",
            &[&entity_id, &field_id],
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    verification.accepted_request_proposal_rows = u64::try_from(request_proposals.get::<_, i64>(0))
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;

    // The recursive path binds as text and casts in the server: no client
    // parameter type maps to jsonpath, and the explicit I/O cast is exact.
    let cached_responses = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_idempotency
              WHERE convert_from(response_body, 'UTF8')::jsonb @? ($1::text)::jsonpath",
            &[&recursive_member_path(field.predecessor_api_name)?],
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    verification.accepted_idempotency_rows = u64::try_from(cached_responses.get::<_, i64>(0))
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;

    let retained_payloads = transaction
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_outbox
              WHERE payload IS NOT NULL
                AND convert_from(payload, 'UTF8')::jsonb @? ($1::text)::jsonpath",
            &[&recursive_member_path(field.logical_field_id)?],
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    verification.accepted_outbox_rows = u64::try_from(retained_payloads.get::<_, i64>(0))
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;

    Ok(verification)
}

/// The recursive JSONPath that matches one api-named member anywhere in a
/// response or payload document. Api names are compiler identifiers, so a
/// quote or backslash refuses rather than escaping.
pub(crate) fn recursive_member_path(api_name: &str) -> Result<String> {
    if api_name.is_empty()
        || api_name
            .chars()
            .any(|character| matches!(character, '"' | '\\'))
    {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(format!("$.**.\"{api_name}\""))
}

/// Record one field's flip boundary and its value-free verification counts.
/// The row lands in the same transaction as the step's completion, so a
/// verified step and its boundary are atomic.
async fn record_field_encryption_flip(
    transaction: &tokio_postgres::Transaction<'_>,
    field: &FieldEncryptionCoveredField<'_>,
    boundary_package_revision: &str,
    history_choice: ReviewedFieldEncryptionHistory,
    history_commit_position: i64,
    verification: &FieldEncryptionContentVerification,
) -> Result<()> {
    let history_choice = match history_choice {
        ReviewedFieldEncryptionHistory::EraseAndRebaseline => "erase-and-rebaseline",
        ReviewedFieldEncryptionHistory::RetainPlaintextHistory => "retain-plaintext-history",
    };
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_field_encryption_flips (
                 entity_id, field_id, boundary_package_revision, history_choice,
                 history_commit_position,
                 sealed_row_count, sealed_journal_row_count,
                 accepted_plaintext_journal_row_count, accepted_request_target_row_count,
                 accepted_request_proposal_row_count, accepted_idempotency_row_count,
                 accepted_outbox_row_count
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &field.entity_id,
                &field.candidate.id,
                &boundary_package_revision,
                &history_choice,
                &history_commit_position,
                &i64::try_from(verification.sealed_rows)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
                &i64::try_from(verification.sealed_journal_rows)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
                &i64::try_from(verification.accepted_plaintext_journal_rows)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
                &i64::try_from(verification.accepted_request_target_rows)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
                &i64::try_from(verification.accepted_request_proposal_rows)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
                &i64::try_from(verification.accepted_idempotency_rows)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
                &i64::try_from(verification.accepted_outbox_rows)
                    .map_err(|_| PostgresKernelError::RegistryUnavailable)?,
            ],
        )
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    if changed != 1 {
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

pub(super) async fn set_local_migration_timeouts(
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

/// Whether a failed advisory lock statement means another session holds the
/// lock. The lock statement waits only for the lock, so the lock timeout, or
/// a shorter statement timeout, ending that wait is the only way it fails
/// with either code. Only a statement that waits for nothing but the lock
/// may be read this way.
pub(crate) fn lock_wait_ended(error: &tokio_postgres::Error) -> bool {
    matches!(
        error.code(),
        Some(code)
            if code == &tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE
                || code == &tokio_postgres::error::SqlState::QUERY_CANCELED
    )
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
               AND maintenance_target_package_digest = $1
               AND package_id = $2
               AND database_id = $3
               AND active_package_digest = $1
               AND active_activation_id = $4
               AND schema_fingerprint = $5
             FOR UPDATE",
            &[
                &target.package_digest,
                &target.package_id,
                &target.database_id,
                &target.activation_uuid()?,
                &target.schema_fingerprint,
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
               AND maintenance_target_package_digest = $1
               AND package_id = $2
               AND database_id = $3
               AND active_package_digest = $4
               AND active_activation_id = $5
               AND schema_fingerprint = $6
             FOR UPDATE",
            &[
                &target.package_digest,
                &current.package_id,
                &current.database_id,
                &current.package_digest,
                &current.activation_uuid()?,
                &current.schema_fingerprint,
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
    target_package_digest: &str,
) -> Result<()> {
    ensure_apply_lock(lock_held)?;
    current.validate()?;
    if target_package_digest.is_empty() {
        return Err(PostgresKernelError::Configuration(
            "resume target package digest must be non-empty",
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

/// The activation state the database records, as `bregctl status` reports
/// it: the singleton state row and every ledger entry in apply order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecordedActivationStatus {
    pub snapshot: MaintenanceSnapshot,
    pub ledger: Vec<RecordedLedgerEntry>,
}

/// One activation ledger entry, without its checksums, artifact bindings,
/// backup references, or operator reference hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecordedLedgerEntry {
    pub activation_id: String,
    pub apply_order: i64,
    pub package_digest: String,
    pub predecessor_package_digest: Option<String>,
    pub registry_revision: String,
    pub plan_kind: String,
    pub migration_kind: String,
    pub outcome: String,
    pub role_mode: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub applied_at: Option<String>,
}

/// The outcome of reading the activation state without the apply lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActivationStatusRead {
    /// No package was ever applied.
    Uninitialized,
    /// The database holds registry state this release does not recognise.
    Unrecognized,
    Recorded(RecordedActivationStatus),
}

/// Reads the activation state as the migration role in one read-only
/// repeatable-read transaction. It takes no apply lock, so it answers while
/// an apply holds that lock, and it writes nothing.
pub(crate) async fn read_activation_status(
    config: &ConnectionConfig,
    migration_role: &SqlIdentifier,
    statement_timeout: Duration,
) -> Result<ActivationStatusRead> {
    validate_timeout(
        statement_timeout,
        MAX_VERIFIED_DDL_STATEMENT_TIMEOUT,
        "status statement timeout must be between 1 millisecond and 1 hour",
    )?;
    let (mut client, connection_task) = connect_dedicated(config).await?;
    let result = async {
        verify_migration_role(&client, migration_role).await?;
        client
            .execute(
                "SELECT pg_catalog.set_config('search_path',
                         'pg_catalog, registry_internal, registry_data, pg_temp', false)",
                &[],
            )
            .await?;
        set_session_timeout(&client, "statement_timeout", statement_timeout).await?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        let status = read_activation_status_in(&transaction).await?;
        transaction.rollback().await?;
        Ok(status)
    }
    .await;
    connection_task.abort();
    result
}

async fn read_activation_status_in(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<ActivationStatusRead> {
    match registry_state_shape(transaction).await? {
        RegistryStateShape::Absent => return Ok(ActivationStatusRead::Uninitialized),
        RegistryStateShape::Unrecognized => return Ok(ActivationStatusRead::Unrecognized),
        RegistryStateShape::Ledger => {}
    }
    let Some(row) = transaction
        .query_opt(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint,
                    maintenance_status, maintenance_target_package_digest
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await?
    else {
        return Ok(ActivationStatusRead::Uninitialized);
    };
    let snapshot = MaintenanceSnapshot {
        identity: ExpectedRegistryIdentity {
            package_id: row.try_get(0)?,
            database_id: row.try_get(1)?,
            package_digest: row.try_get(2)?,
            activation_id: row.try_get(3)?,
            schema_fingerprint: row.try_get(4)?,
        },
        maintenance_status: row.try_get(5)?,
        maintenance_target_package_digest: row.try_get(6)?,
    };
    let rows = transaction
        .query(
            "SELECT activation_id::text, apply_order, package_digest,
                    predecessor_package_digest, registry_revision, plan_kind,
                    migration_kind, outcome, role_mode,
                    to_char(started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    to_char(completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                    to_char(applied_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
             FROM registry_internal.registry_migrations
             ORDER BY apply_order",
            &[],
        )
        .await?;
    let ledger = rows
        .iter()
        .map(|row| {
            Ok(RecordedLedgerEntry {
                activation_id: row.try_get(0)?,
                apply_order: row.try_get(1)?,
                package_digest: row.try_get(2)?,
                predecessor_package_digest: row.try_get(3)?,
                registry_revision: row.try_get(4)?,
                plan_kind: row.try_get(5)?,
                migration_kind: row.try_get(6)?,
                outcome: row.try_get(7)?,
                role_mode: row.try_get(8)?,
                started_at: row.try_get(9)?,
                completed_at: row.try_get(10)?,
                applied_at: row.try_get(11)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ActivationStatusRead::Recorded(RecordedActivationStatus {
        snapshot,
        ledger,
    }))
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

    use serde_json::json;
    #[cfg(feature = "postgres-test")]
    use tokio_postgres::Config;

    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::parse_project_json;
    use crate::migration_plan::{
        ChunkCursorProtocol, ReviewedMigrationObject, ReviewedMigrationObjectKind,
    };
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
            pattern_field: None,
            ordinal: 0,
        };
        assert!(compiler_statement_runs_after_reviewed_steps(&statement(
            "ALTER TABLE registry_data.\"breg_e_asset\" ALTER COLUMN \"breg_f_batch\" SET NOT NULL",
            DdlStatementKind::Column,
        )));
        assert!(!compiler_statement_runs_after_reviewed_steps(&statement(
            "ALTER TABLE registry_data.\"breg_e_asset\" ADD COLUMN \"breg_f_batch\" varchar(16)",
            DdlStatementKind::Column,
        )));
        assert!(!compiler_statement_runs_after_reviewed_steps(&statement(
            "ALTER TABLE registry_data.\"breg_e_asset\" ALTER COLUMN \"breg_f_batch\" DROP NOT NULL",
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

    #[test]
    fn field_encryption_scan_keys_preserve_predecessor_api_name_and_logical_id() {
        fn compile(api_name: &str, encrypted: bool) -> CompiledRegistry {
            let mut secret = json!({
                "id": "secret",
                "apiName": api_name,
                "type": "string",
                "maxLength": 256,
                "classification": "restricted"
            });
            if encrypted {
                secret["encrypted"] = json!(true);
            }
            let source = json!({
                "apiVersion": "registry.registrystack.org/v1alpha1",
                "kind": "RegistryProject",
                "registry": {
                    "id": "field-encryption-scan-keys",
                    "version": "1",
                    "defaultLanguage": "en",
                    "canonicalBaseIri": "https://scan-keys.example.test"
                },
                "entities": [{
                    "id": "case",
                    "primaryDataset": "test-dataset",
                    "route": "cases",
                    "mutationMode": "mutable",
                    "fields": [secret]
                }],
                "accessProfiles": [{
                    "id": "caseworker",
                    "default": true,
                    "principalClaim": "principal",
                    "requiredScopes": "unrestricted",
                    "permissions": [{
                        "entity": "case",
                        "rowBoundaries": "unrestricted",
                        "operations": ["get", "list", "create", "patch"],
                        "readableFields": ["secret"],
                        "writableFields": ["secret"]
                    }]
                }]
            });
            let project = parse_project_json(&serde_json::to_vec(&source).unwrap())
                .expect("scan-key fixture parses");
            compile_project(&project, &[], CompileProfile::Authoring)
                .expect("scan-key fixture compiles")
        }

        let prior = compile("legacySecret", false);
        let candidate = compile("renamedSecret", true);
        let baseline = CompiledRegistryMigrationBaseline::from_compiled("prior", &prior);
        let entity = &candidate.entities()["case"];
        let field = &entity.fields["secret"];
        let step = ValidatedReviewedMigrationStep {
            descriptor: ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
                id: "seal-secret".to_owned(),
                entity_id: "case".to_owned(),
                objects: vec![ReviewedMigrationObject {
                    schema: "registry_data".to_owned(),
                    table: entity.physical_table.clone(),
                    entity_id: "case".to_owned(),
                    kind: ReviewedMigrationObjectKind::Field,
                    member_id: Some("secret".to_owned()),
                    physical_name: field.physical_name.clone(),
                }],
                cursor: ChunkCursorProtocol::RecordIdUuidArray,
                chunk_size: 2,
                max_total_rows: 10,
                lock_timeout_ms: 50,
                statement_timeout_ms: 5_000,
            },
            sql: String::new(),
            sha256: String::new(),
        };

        let covered = covered_field_encryption_fields(&candidate, Some(&baseline), "case", &step)
            .expect("rename plus encryption resolves one covered field");
        let covered = &covered[0];
        assert_eq!(covered.api_name, "renamedSecret");
        assert_eq!(covered.predecessor_api_name, "legacySecret");
        assert_eq!(covered.logical_field_id, "secret");
    }

    #[cfg(feature = "postgres-test")]
    #[tokio::test]
    async fn failed_resume_and_ddl_timeout_are_fail_closed_on_real_postgres() {
        let database = InterlockTestDatabase::create().await;
        let current = ExpectedRegistryIdentity {
            package_id: "package-under-test".to_owned(),
            database_id: "database-under-test".to_owned(),
            package_digest: format!("sha256:{}", "c".repeat(64)),
            activation_id: "7b0c2b1e-4a1f-4c55-9f0e-2d5f1c1a9b01".to_owned(),
            schema_fingerprint: "fingerprint-current".to_owned(),
        };
        let target_revision = &format!("sha256:{}", "d".repeat(64));
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
        wrong_current.activation_id = "7b0c2b1e-4a1f-4c55-9f0e-2d5f1c1a9b02".to_owned();
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
        assert!(
            matches!(
                &timed_out,
                Err(PostgresKernelError::Statement(failure))
                    if failure.sqlstate.as_deref() == Some("57014")
            ),
            "a statement timeout is a refused statement, as on the package DDL path: {timed_out:?}"
        );
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
            Err(PostgresKernelError::MigrationLockHeld)
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
            let url = env::var("BREG_TEST_DATABASE_URL")
                .expect("BREG_TEST_DATABASE_URL is required for the real interlock test");
            let admin_root = Config::from_str(&url)
                .expect("BREG_TEST_DATABASE_URL must be a valid PostgreSQL URL");
            let nanos = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the Unix epoch")
                .as_nanos();
            let suffix = format!("{}_{nanos}", std::process::id());
            let database = SqlIdentifier::parse(&format!("breg_interlock_{suffix}"))
                .expect("generated database identifier is valid");
            let migration_role = SqlIdentifier::parse(&format!("breg_il_migration_{suffix}"))
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
                         package_id text NOT NULL,
                         database_id text NOT NULL,
                         active_package_digest text NOT NULL,
                         active_activation_id uuid NOT NULL,
                         schema_fingerprint text NOT NULL,
                         maintenance_status text NOT NULL,
                         maintenance_target_package_digest text,
                         updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
                     );",
                )
                .await
                .expect("isolated migration role can install the state fixture");
            migration
                .execute(
                    "INSERT INTO registry_internal.registry_state (
                         singleton, package_id, database_id, active_package_digest,
                         active_activation_id, schema_fingerprint,
                         maintenance_status, maintenance_target_package_digest
                     ) VALUES (true, $1, $2, $3, $4, $5, 'failed', $6)",
                    &[
                        &current.package_id,
                        &current.database_id,
                        &current.package_digest,
                        &current
                            .activation_uuid()
                            .expect("the fixture activation id is a canonical UUID"),
                        &current.schema_fingerprint,
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
            Option<String>,
        ) {
            let row = self
                .admin
                .query_one(
                    "SELECT package_id, database_id, active_package_digest,
                            active_activation_id::text, schema_fingerprint,
                            maintenance_status, maintenance_target_package_digest
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
