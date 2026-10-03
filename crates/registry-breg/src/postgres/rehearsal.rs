// SPDX-License-Identifier: Apache-2.0

//! Rolled-back rehearsal of a successor package's migration.
//!
//! `bregctl test` installs the verified predecessor schema into an empty
//! schema-test database, runs the candidate's compiler DDL and reviewed steps
//! in the order activation runs them, and measures the result against the
//! candidate's fresh-install fingerprint. Everything happens inside one
//! transaction that is always rolled back, so the database stays clean for the
//! schema test that follows. The predecessor tables are empty, so the
//! rehearsal proves statement validity, ordering, and the final catalog; it
//! does not prove the data-dependent behavior of a step over live rows.

use std::fmt;

use tokio_postgres::{types::Type, GenericClient};
use uuid::Uuid;

use crate::generated_ddl::DdlStatementKind;
use crate::history_migration::check_reviewed_history_step;
use crate::migration_plan::{ReviewedMigrationStepDescriptor, ValidatedReviewedMigrationPlan};
use crate::model::CompiledRegistry;
use crate::mutation::install_mutation_schema;
use crate::package::PreparedPackage;

use super::{
    catalog::{managed_schema_fingerprint, ExpectedManagedCatalog},
    failure::PostgresFailure,
    interlock::{
        compiler_statement_runs_after_reviewed_steps, drop_managed_read_view_set,
        set_force_row_security, set_local_migration_timeouts, PackageDdlStatement,
    },
    migration_ledger::statement_checksum,
    schema::{
        compiled_pattern_field, connect_schema_test, execute_compiled_ddl_statement,
        install_compiled_schema, is_spatial_candidate_view_sql, pattern_field_for_constraint,
        reconcile_compiled_runtime_acl, refuse_existing_managed_objects,
    },
    verify_migration_role, ConnectionConfig, SqlIdentifier,
};

/// The lock timeout, in milliseconds, for the predecessor install and the
/// compiler statements. Activation runs those under the operator's apply
/// timeouts, which a rehearsal does not know, so it bounds them itself.
const COMPILER_LOCK_TIMEOUT_MS: u64 = 5_000;
/// The statement timeout, in milliseconds, paired with
/// [`COMPILER_LOCK_TIMEOUT_MS`].
const COMPILER_STATEMENT_TIMEOUT_MS: u64 = 300_000;

/// The verified predecessor and the prepared candidate one rehearsal binds.
pub struct SuccessorMigrationRehearsal<'a> {
    /// The predecessor registry compiled from its package's sources. The
    /// rehearsal installs it with the schema of the baseline the candidate's
    /// migration plan binds.
    pub predecessor: &'a CompiledRegistry,
    /// The schema fingerprint the predecessor package manifest binds.
    pub predecessor_schema_fingerprint: &'a str,
    /// The prepared successor candidate, before it is written as a package.
    pub candidate: &'a PreparedPackage,
}

/// What a successful rehearsal reports beside its success.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RehearsalOutcome {
    /// The predecessor schema this compiler installs does not measure to the
    /// fingerprint its package manifest binds. The manifest does not record
    /// which engine release built it, and the managed catalog includes
    /// engine-owned tables, so a predecessor built by an earlier release
    /// always drifts. The comparison is advisory: the rehearsal still
    /// installs the predecessor, runs the successor migration, and holds the
    /// result to the candidate fingerprint, and apply checks the live database.
    pub baseline_fingerprint_drift: Option<BaselineFingerprintDrift>,
}

/// The two predecessor schema fingerprints a drifted rehearsal compared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineFingerprintDrift {
    /// The fingerprint the predecessor package manifest binds.
    pub signed: String,
    /// The fingerprint of the predecessor schema this compiler installed.
    pub measured: String,
}

/// Which assertion set of a reviewed migration a refusal names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RehearsalAssertionPhase {
    Pre,
    Post,
}

impl fmt::Display for RehearsalAssertionPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pre => "pre",
            Self::Post => "post",
        })
    }
}

/// Why a rehearsal refused a successor. Every variant is value-free: it names
/// reviewed identifiers, compiler statement identifiers, SQLSTATE codes, and
/// schema objects only.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MigrationRehearsalError {
    #[error(
        "the schema-test database is unavailable, not clean, or not owned by the migration role"
    )]
    Database,
    #[error("the candidate package does not carry a successor migration plan")]
    NotSuccessor,
    #[error("the candidate package's reviewed migration plan could not be rederived")]
    ReviewedPlan,
    #[error("the current compiler cannot install the verified predecessor schema")]
    BaselineNotReproducible,
    #[error("compiler statement {statement_id} failed: {failure}")]
    CompilerStatement {
        statement_id: String,
        failure: PostgresFailure,
    },
    #[error(
        "reviewed migration {migration_id} {phase}-assertion {assertion_id} failed: {failure}"
    )]
    Assertion {
        migration_id: String,
        phase: RehearsalAssertionPhase,
        assertion_id: String,
        failure: PostgresFailure,
    },
    #[error(
        "reviewed migration {migration_id} {phase}-assertion {assertion_id} does not return exactly one boolean column"
    )]
    AssertionShape {
        migration_id: String,
        phase: RehearsalAssertionPhase,
        assertion_id: String,
    },
    #[error("reviewed migration {migration_id} step {step_id} failed: {failure}")]
    Step {
        migration_id: String,
        step_id: String,
        failure: PostgresFailure,
    },
    #[error("reviewed migration {migration_id} step {step_id} cannot be journaled: {reason}")]
    HistoryStep {
        migration_id: String,
        step_id: String,
        reason: String,
    },
    #[error(
        "the rehearsed migration does not reach the candidate schema fingerprint; activation would refuse it"
    )]
    FinalSchemaMismatch,
}

type RehearsalResult<T> = std::result::Result<T, MigrationRehearsalError>;

/// Rehearse one successor candidate over an empty reproduction of its verified
/// predecessor schema. The transaction is rolled back on every path.
pub async fn rehearse_successor_migration(
    migration_connection: &ConnectionConfig,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
    rehearsal: SuccessorMigrationRehearsal<'_>,
) -> RehearsalResult<RehearsalOutcome> {
    let candidate = rehearsal.candidate;
    let manifest = candidate.manifest();
    if manifest.migration_plan.from_package_digest.is_none()
        || manifest.migration_plan.prior_baseline.is_none()
    {
        return Err(MigrationRehearsalError::NotSuccessor);
    }
    let plan = candidate
        .reviewed_migration_plan()
        .map_err(|_| MigrationRehearsalError::ReviewedPlan)?;
    let checksums = manifest
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement_checksum(&statement.sql))
        .collect::<Vec<_>>();
    let statements = manifest
        .migration_plan
        .statements
        .iter()
        .zip(&checksums)
        .enumerate()
        .map(|(ordinal, (statement, checksum))| {
            Some(RehearsedStatement {
                id: &statement.id,
                ddl: PackageDdlStatement {
                    sql: &statement.sql,
                    checksum,
                    kind: statement.kind,
                    pattern_field: compiled_pattern_field(candidate.registry(), &statement.id),
                    ordinal: i32::try_from(ordinal).ok()?,
                },
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(MigrationRehearsalError::NotSuccessor)?;

    let (mut client, task) = connect_schema_test(migration_connection)
        .await
        .map_err(|_| MigrationRehearsalError::Database)?;
    let result = async {
        verify_migration_role(&client, migration_role)
            .await
            .map_err(|_| MigrationRehearsalError::Database)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| MigrationRehearsalError::Database)?;
        let outcome = rehearse_in_transaction(
            &transaction,
            runtime_role,
            &rehearsal,
            plan.as_ref(),
            &statements,
        )
        .await;
        // The rehearsal never commits; a failed statement has already aborted
        // the transaction, and rollback discards it either way.
        let _ = transaction.rollback().await;
        outcome
    }
    .await;
    task.abort();
    result
}

struct RehearsedStatement<'a> {
    id: &'a str,
    ddl: PackageDdlStatement<'a>,
}

async fn rehearse_in_transaction(
    transaction: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    rehearsal: &SuccessorMigrationRehearsal<'_>,
    plan: Option<&ValidatedReviewedMigrationPlan>,
    statements: &[RehearsedStatement<'_>],
) -> RehearsalResult<RehearsalOutcome> {
    set_compiler_timeouts(transaction).await?;
    refuse_existing_managed_objects(transaction)
        .await
        .map_err(|_| MigrationRehearsalError::Database)?;
    // The successor plan was computed from the baseline its manifest binds,
    // so the rehearsal installs that schema rather than the one the
    // predecessor's sources compile to under this compiler.
    let prior_baseline = rehearsal
        .candidate
        .manifest()
        .migration_plan
        .prior_baseline
        .as_ref()
        .ok_or(MigrationRehearsalError::NotSuccessor)?;
    let predecessor = rehearsal
        .predecessor
        .with_migration_baseline_schema(prior_baseline);
    install_compiled_schema(transaction, &predecessor, runtime_role)
        .await
        .map_err(|_| MigrationRehearsalError::BaselineNotReproducible)?;
    let predecessor_fingerprint = managed_schema_fingerprint(
        transaction,
        runtime_role,
        &ExpectedManagedCatalog::compiled(&predecessor),
    )
    .await
    .map_err(|_| MigrationRehearsalError::BaselineNotReproducible)?;
    let outcome = RehearsalOutcome {
        baseline_fingerprint_drift: (predecessor_fingerprint
            != rehearsal.predecessor_schema_fingerprint)
            .then(|| BaselineFingerprintDrift {
                signed: rehearsal.predecessor_schema_fingerprint.to_owned(),
                measured: predecessor_fingerprint,
            }),
    };

    let candidate = rehearsal.candidate.registry();
    match plan {
        Some(plan) => {
            let prior_tables = entity_tables(&predecessor);
            let candidate_tables = entity_tables(candidate);
            rehearse_assertions(
                transaction,
                plan,
                &prior_tables,
                RehearsalAssertionPhase::Pre,
            )
            .await?;
            for statement in statements
                .iter()
                .filter(|statement| !compiler_statement_runs_after_reviewed_steps(&statement.ddl))
            {
                rehearse_compiler_statement(transaction, statement, runtime_role).await?;
            }
            if statements.iter().any(|statement| {
                statement.ddl.kind == DdlStatementKind::View
                    && !is_spatial_candidate_view_sql(statement.ddl.sql)
            }) {
                drop_managed_read_view_set(transaction)
                    .await
                    .map_err(|_| MigrationRehearsalError::Database)?;
            }
            rehearse_reviewed_steps(transaction, candidate, plan).await?;
            for statement in statements
                .iter()
                .filter(|statement| compiler_statement_runs_after_reviewed_steps(&statement.ddl))
            {
                rehearse_compiler_statement(transaction, statement, runtime_role).await?;
            }
            rehearse_assertions(
                transaction,
                plan,
                &candidate_tables,
                RehearsalAssertionPhase::Post,
            )
            .await?;
        }
        None => {
            for statement in statements {
                rehearse_compiler_statement(transaction, statement, runtime_role).await?;
            }
        }
    }

    install_mutation_schema(transaction, runtime_role)
        .await
        .map_err(|_| MigrationRehearsalError::Database)?;
    reconcile_compiled_runtime_acl(transaction, candidate, runtime_role)
        .await
        .map_err(|_| MigrationRehearsalError::Database)?;
    let measured = managed_schema_fingerprint(
        transaction,
        runtime_role,
        &ExpectedManagedCatalog::compiled(candidate),
    )
    .await
    .map_err(|_| MigrationRehearsalError::FinalSchemaMismatch)?;
    if measured != rehearsal.candidate.manifest().schema_fingerprint {
        return Err(MigrationRehearsalError::FinalSchemaMismatch);
    }
    Ok(outcome)
}

/// Sets the bound for statements that are not part of a reviewed migration.
async fn set_compiler_timeouts(transaction: &impl GenericClient) -> RehearsalResult<()> {
    set_timeouts(
        transaction,
        COMPILER_LOCK_TIMEOUT_MS,
        COMPILER_STATEMENT_TIMEOUT_MS,
    )
    .await
}

/// Sets the lock and statement timeouts for the statements that follow, as
/// activation sets them from a reviewed migration's descriptor or step.
async fn set_timeouts(
    transaction: &impl GenericClient,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
) -> RehearsalResult<()> {
    set_local_migration_timeouts(transaction, lock_timeout_ms, statement_timeout_ms)
        .await
        .map_err(|_| MigrationRehearsalError::Database)
}

fn entity_tables(registry: &CompiledRegistry) -> Vec<String> {
    registry
        .entities()
        .values()
        .map(|entity| entity.physical_table.clone())
        .collect()
}

async fn rehearse_compiler_statement(
    transaction: &impl GenericClient,
    statement: &RehearsedStatement<'_>,
    runtime_role: &SqlIdentifier,
) -> RehearsalResult<()> {
    let failed = |failure| MigrationRehearsalError::CompilerStatement {
        statement_id: statement.id.to_owned(),
        failure,
    };
    if statement.ddl.kind == DdlStatementKind::View
        && is_spatial_candidate_view_sql(statement.ddl.sql)
    {
        return execute_compiled_ddl_statement(
            transaction,
            statement.ddl.sql,
            statement.ddl.kind,
            None,
            runtime_role,
        )
        .await
        .map_err(|_| failed(PostgresFailure::default()));
    }
    transaction
        .batch_execute(statement.ddl.sql)
        .await
        .map_err(|error| failed(PostgresFailure::from_error(&error)))
}

async fn rehearse_assertions(
    transaction: &impl GenericClient,
    plan: &ValidatedReviewedMigrationPlan,
    tables: &[String],
    phase: RehearsalAssertionPhase,
) -> RehearsalResult<()> {
    set_force_row_security(transaction, tables, false)
        .await
        .map_err(|_| MigrationRehearsalError::Database)?;
    for migration in plan.migrations() {
        // Activation runs each migration's assertions under the timeouts its
        // descriptor declares.
        set_timeouts(
            transaction,
            migration.descriptor.lock_timeout_ms,
            migration.descriptor.statement_timeout_ms,
        )
        .await?;
        let assertions = match phase {
            RehearsalAssertionPhase::Pre => &migration.pre_assertions,
            RehearsalAssertionPhase::Post => &migration.post_assertions,
        };
        for assertion in assertions {
            let named = |failure: Option<PostgresFailure>| match failure {
                Some(failure) => MigrationRehearsalError::Assertion {
                    migration_id: migration.descriptor.id.clone(),
                    phase,
                    assertion_id: assertion.descriptor.id.clone(),
                    failure,
                },
                None => MigrationRehearsalError::AssertionShape {
                    migration_id: migration.descriptor.id.clone(),
                    phase,
                    assertion_id: assertion.descriptor.id.clone(),
                },
            };
            // Activation also requires the value to be true. Over the empty
            // predecessor tables a truthful assertion about live rows may be
            // false, so the rehearsal holds only the shape and executability.
            let prepared = transaction
                .prepare(&assertion.sql)
                .await
                .map_err(|error| named(Some(PostgresFailure::from_error(&error))))?;
            if prepared.columns().len() != 1 || prepared.columns()[0].type_() != &Type::BOOL {
                return Err(named(None));
            }
            transaction
                .query(&prepared, &[])
                .await
                .map_err(|error| named(Some(PostgresFailure::from_error(&error))))?;
        }
    }
    set_force_row_security(transaction, tables, true)
        .await
        .map_err(|_| MigrationRehearsalError::Database)?;
    set_compiler_timeouts(transaction).await
}

async fn rehearse_reviewed_steps(
    transaction: &impl GenericClient,
    candidate: &CompiledRegistry,
    plan: &ValidatedReviewedMigrationPlan,
) -> RehearsalResult<()> {
    for migration in plan.migrations() {
        for step in &migration.steps {
            let (step_id, objects) = match &step.descriptor {
                ReviewedMigrationStepDescriptor::TransactionalSql { id, objects, .. }
                | ReviewedMigrationStepDescriptor::ChunkedBackfill { id, objects, .. }
                | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
                    id, objects, ..
                } => (id, objects),
            };
            // Activation runs a transactional step under its migration's
            // timeouts and a backfill under the step's own.
            let (lock_timeout_ms, statement_timeout_ms) = match &step.descriptor {
                ReviewedMigrationStepDescriptor::TransactionalSql { .. } => (
                    migration.descriptor.lock_timeout_ms,
                    migration.descriptor.statement_timeout_ms,
                ),
                ReviewedMigrationStepDescriptor::ChunkedBackfill {
                    lock_timeout_ms,
                    statement_timeout_ms,
                    ..
                }
                | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
                    lock_timeout_ms,
                    statement_timeout_ms,
                    ..
                } => (*lock_timeout_ms, *statement_timeout_ms),
            };
            set_timeouts(transaction, lock_timeout_ms, statement_timeout_ms).await?;
            let failed = |error: tokio_postgres::Error| MigrationRehearsalError::Step {
                migration_id: migration.descriptor.id.clone(),
                step_id: step_id.clone(),
                failure: PostgresFailure::from_error(&error),
            };
            // Activation journals every row a bounded or chunked update
            // changes, and refuses before the step runs when the journal
            // cannot record it, so the rehearsal applies the same check.
            let journaled = match &step.descriptor {
                ReviewedMigrationStepDescriptor::TransactionalSql { affected_rows, .. } => {
                    affected_rows.is_some()
                }
                ReviewedMigrationStepDescriptor::ChunkedBackfill { .. } => true,
                ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { .. } => false,
            };
            if journaled {
                check_reviewed_history_step(&migration.descriptor_path, step).map_err(|error| {
                    MigrationRehearsalError::HistoryStep {
                        migration_id: migration.descriptor.id.clone(),
                        step_id: step_id.clone(),
                        reason: error.to_string(),
                    }
                })?;
            }
            let tables = objects
                .iter()
                .map(|object| object.table.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            match &step.descriptor {
                ReviewedMigrationStepDescriptor::TransactionalSql { affected_rows, .. } => {
                    for object in objects {
                        let Some((entity_id, field_id)) =
                            pattern_field_for_constraint(candidate, &object.physical_name)
                        else {
                            continue;
                        };
                        if let Some(pattern) =
                            &candidate.entities()[entity_id].fields[field_id].pattern
                        {
                            transaction
                                .query_one("SELECT '' ~ $1::text", &[pattern])
                                .await
                                .map_err(failed)?;
                        }
                    }
                    if affected_rows.is_some() {
                        set_force_row_security(transaction, &tables, false)
                            .await
                            .map_err(|_| MigrationRehearsalError::Database)?;
                        transaction.execute(&step.sql, &[]).await.map_err(failed)?;
                        set_force_row_security(transaction, &tables, true)
                            .await
                            .map_err(|_| MigrationRehearsalError::Database)?;
                    } else {
                        transaction.batch_execute(&step.sql).await.map_err(failed)?;
                    }
                }
                ReviewedMigrationStepDescriptor::ChunkedBackfill { .. } => {
                    // No predecessor row exists, so activation would never run
                    // this statement. Binding an empty chunk still makes
                    // PostgreSQL parse, plan, and type-check it.
                    set_force_row_security(transaction, &tables, false)
                        .await
                        .map_err(|_| MigrationRehearsalError::Database)?;
                    let chunk: Vec<Uuid> = Vec::new();
                    transaction
                        .execute(&step.sql, &[&chunk])
                        .await
                        .map_err(failed)?;
                    set_force_row_security(transaction, &tables, true)
                        .await
                        .map_err(|_| MigrationRehearsalError::Database)?;
                }
                // The engine seals rows it reads; with no predecessor rows the
                // step has nothing to seal and carries no authored SQL.
                ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { .. } => {}
            }
        }
    }
    set_compiler_timeouts(transaction).await
}
