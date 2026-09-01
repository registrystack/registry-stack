// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::{PostgresKernelError, Result, SqlIdentifier};

const MAX_MIGRATION_STATEMENTS: usize = 1024;
const MAX_MIGRATION_ARTIFACTS: usize = 1024;
const MAX_MIGRATION_STEPS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationPlanKind {
    CompiledAdditive,
    MetadataOnly,
    Reviewed,
}

impl MigrationPlanKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::CompiledAdditive => "compiled_additive",
            Self::MetadataOnly => "metadata_only",
            Self::Reviewed => "reviewed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MigrationArtifactBinding {
    pub path: String,
    pub checksum: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationLedgerStepKind {
    CompilerDdl,
    TransactionalSql,
    ChunkedBackfill,
}

impl MigrationLedgerStepKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::CompilerDdl => "compiler_ddl",
            Self::TransactionalSql => "transactional_sql",
            Self::ChunkedBackfill => "chunked_backfill",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MigrationLedgerStep {
    pub migration_ordinal: i32,
    pub step_ordinal: i32,
    pub step_id: String,
    pub kind: MigrationLedgerStepKind,
    pub checksum: String,
}

/// Exact immutable identity of one package migration. Statement and artifact
/// digests are ordered because changing order changes the reviewed plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MigrationLedgerEntry {
    pub source_revision: Option<String>,
    pub target_revision: String,
    pub package_sequence: i64,
    pub plan_kind: MigrationPlanKind,
    pub statement_checksums: Vec<String>,
    pub artifact_bindings: Vec<MigrationArtifactBinding>,
    pub steps: Vec<MigrationLedgerStep>,
}

impl MigrationLedgerEntry {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.target_revision.is_empty()
            || self.package_sequence <= 0
            || self
                .source_revision
                .as_deref()
                .is_some_and(|source| source.is_empty() || source == self.target_revision)
            || self.statement_checksums.len() > MAX_MIGRATION_STATEMENTS
            || self
                .statement_checksums
                .iter()
                .any(|checksum| !valid_sha256(checksum))
            || self.artifact_bindings.len() > MAX_MIGRATION_ARTIFACTS
            || self.steps.len() > MAX_MIGRATION_STEPS
        {
            return invalid_identity();
        }
        if self.artifact_bindings.iter().any(|binding| {
            binding.path.is_empty() || binding.path.len() > 1024 || !valid_sha256(&binding.checksum)
        }) || self
            .artifact_bindings
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return invalid_identity();
        }
        if self.steps.iter().any(|step| {
            step.migration_ordinal < 0
                || step.step_ordinal < 0
                || step.step_id.is_empty()
                || step.step_id.len() > 255
                || !valid_sha256(&step.checksum)
        }) || self.steps.windows(2).any(|pair| {
            (pair[0].migration_ordinal, pair[0].step_ordinal)
                >= (pair[1].migration_ordinal, pair[1].step_ordinal)
        }) {
            return invalid_identity();
        }
        match self.plan_kind {
            MigrationPlanKind::CompiledAdditive
                if self.statement_checksums.is_empty()
                    || !self.artifact_bindings.is_empty()
                    || !self.steps.is_empty() =>
            {
                return invalid_identity();
            }
            MigrationPlanKind::MetadataOnly
                if !self.statement_checksums.is_empty()
                    || !self.artifact_bindings.is_empty()
                    || !self.steps.is_empty() =>
            {
                return invalid_identity();
            }
            MigrationPlanKind::Reviewed if self.artifact_bindings.is_empty() => {
                return invalid_identity();
            }
            _ => {}
        }
        Ok(())
    }

    fn artifact_paths(&self) -> Vec<String> {
        self.artifact_bindings
            .iter()
            .map(|binding| binding.path.clone())
            .collect()
    }

    fn artifact_checksums(&self) -> Vec<String> {
        self.artifact_bindings
            .iter()
            .map(|binding| binding.checksum.clone())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MigrationPhaseState {
    pub preconditions_complete: bool,
    pub postconditions_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MigrationStepProgress {
    pub complete: bool,
    pub checkpoint_record_id: Option<Uuid>,
    pub affected_rows: u64,
}

/// Installs only the product-owned durable migration ledger. This is part of
/// the initial control plane and intentionally contains no entity DDL.
pub(crate) async fn install_migration_ledger(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_migrations (
                 target_package_revision text PRIMARY KEY
                     CONSTRAINT registry_migrations_target_nonempty
                     CHECK (target_package_revision <> ''),
                 source_package_revision text,
                 package_sequence bigint NOT NULL
                     CONSTRAINT registry_migrations_sequence_positive
                     CHECK (package_sequence > 0),
                 plan_kind text NOT NULL
                     CONSTRAINT registry_migrations_plan_kind_closed
                     CHECK (plan_kind IN ('compiled_additive', 'metadata_only', 'reviewed')),
                 statement_checksums text[] NOT NULL
                     CONSTRAINT registry_migrations_checksums_nonempty
                     CHECK (
                         COALESCE(array_ndims(statement_checksums), 1) = 1
                         AND cardinality(statement_checksums) BETWEEN 0 AND 1024
                         AND array_position(statement_checksums, '') IS NULL
                         AND (
                             (plan_kind = 'metadata_only' AND cardinality(statement_checksums) = 0)
                             OR (plan_kind = 'reviewed' AND cardinality(statement_checksums) = 0)
                             OR (plan_kind IN ('compiled_additive', 'reviewed')
                                 AND cardinality(statement_checksums) BETWEEN 1 AND 1024)
                         )
                     ),
                 artifact_paths text[] NOT NULL,
                 artifact_checksums text[] NOT NULL,
                 preconditions_complete boolean NOT NULL DEFAULT false,
                 postconditions_complete boolean NOT NULL DEFAULT false,
                 outcome text NOT NULL
                     CONSTRAINT registry_migrations_outcome_closed
                     CHECK (outcome IN ('applying', 'failed', 'applied')),
                 started_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 completed_at timestamptz,
                 CONSTRAINT registry_migrations_source_target_distinct CHECK (
                     source_package_revision IS NULL
                     OR source_package_revision <> target_package_revision
                 ),
                 CONSTRAINT registry_migrations_artifacts_consistent CHECK (
                     COALESCE(array_ndims(artifact_paths), 1) = 1
                     AND COALESCE(array_ndims(artifact_checksums), 1) = 1
                     AND cardinality(artifact_paths) = cardinality(artifact_checksums)
                     AND cardinality(artifact_paths) BETWEEN 0 AND 1024
                     AND array_position(artifact_paths, '') IS NULL
                     AND array_position(artifact_checksums, '') IS NULL
                     AND (
                         (plan_kind IN ('compiled_additive', 'metadata_only') AND cardinality(artifact_paths) = 0)
                         OR (plan_kind = 'reviewed' AND cardinality(artifact_paths) > 0)
                     )
                 ),
                 CONSTRAINT registry_migrations_phases_consistent CHECK (
                     plan_kind = 'reviewed'
                     OR (NOT preconditions_complete AND NOT postconditions_complete)
                 ),
                 CONSTRAINT registry_migrations_completion_consistent CHECK (
                     (outcome = 'applying' AND completed_at IS NULL)
                     OR (outcome IN ('failed', 'applied') AND completed_at IS NOT NULL)
                 )
             );
             ALTER TABLE registry_internal.registry_migrations
                 DROP CONSTRAINT IF EXISTS registry_migrations_plan_kind_closed,
                 ADD CONSTRAINT registry_migrations_plan_kind_closed
                     CHECK (plan_kind IN ('compiled_additive', 'metadata_only', 'reviewed'));
             ALTER TABLE registry_internal.registry_migrations
                 DROP CONSTRAINT IF EXISTS registry_migrations_checksums_nonempty,
                 ADD CONSTRAINT registry_migrations_checksums_nonempty
                     CHECK (
                         COALESCE(array_ndims(statement_checksums), 1) = 1
                         AND cardinality(statement_checksums) BETWEEN 0 AND 1024
                         AND array_position(statement_checksums, '') IS NULL
                         AND (
                             (plan_kind = 'metadata_only' AND cardinality(statement_checksums) = 0)
                             OR (plan_kind = 'reviewed' AND cardinality(statement_checksums) = 0)
                             OR (plan_kind IN ('compiled_additive', 'reviewed')
                                 AND cardinality(statement_checksums) BETWEEN 1 AND 1024)
                         )
                     );
             ALTER TABLE registry_internal.registry_migrations
                 DROP CONSTRAINT IF EXISTS registry_migrations_artifacts_consistent,
                 ADD CONSTRAINT registry_migrations_artifacts_consistent CHECK (
                     COALESCE(array_ndims(artifact_paths), 1) = 1
                     AND COALESCE(array_ndims(artifact_checksums), 1) = 1
                     AND cardinality(artifact_paths) = cardinality(artifact_checksums)
                     AND cardinality(artifact_paths) BETWEEN 0 AND 1024
                     AND array_position(artifact_paths, '') IS NULL
                     AND array_position(artifact_checksums, '') IS NULL
                     AND (
                         (plan_kind IN ('compiled_additive', 'metadata_only')
                             AND cardinality(artifact_paths) = 0)
                         OR (plan_kind = 'reviewed' AND cardinality(artifact_paths) > 0)
                     )
                 );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_migration_steps (
                 target_package_revision text NOT NULL,
                 migration_ordinal integer NOT NULL CHECK (migration_ordinal >= 0),
                 step_ordinal integer NOT NULL CHECK (step_ordinal >= 0),
                 step_id text NOT NULL CHECK (step_id <> ''),
                 step_kind text NOT NULL
                     CHECK (step_kind IN ('compiler_ddl', 'transactional_sql', 'chunked_backfill')),
                 statement_checksum text NOT NULL CHECK (statement_checksum <> ''),
                 outcome text NOT NULL DEFAULT 'pending'
                     CHECK (outcome IN ('pending', 'applying', 'completed')),
                 checkpoint_record_id uuid,
                 affected_rows bigint NOT NULL DEFAULT 0 CHECK (affected_rows >= 0),
                 completed_at timestamptz,
                 PRIMARY KEY (target_package_revision, migration_ordinal, step_ordinal),
                 CONSTRAINT registry_migration_steps_state_consistent CHECK (
                     (outcome = 'pending' AND checkpoint_record_id IS NULL
                         AND affected_rows = 0 AND completed_at IS NULL)
                     OR (outcome = 'applying' AND step_kind = 'chunked_backfill'
                         AND checkpoint_record_id IS NOT NULL AND completed_at IS NULL)
                     OR (outcome = 'completed' AND completed_at IS NOT NULL
                         AND (step_kind = 'chunked_backfill' OR checkpoint_record_id IS NULL))
                 )
             );
             REVOKE ALL ON TABLE registry_internal.registry_migrations FROM PUBLIC;
             REVOKE ALL ON TABLE registry_internal.registry_migration_steps FROM PUBLIC;",
        )
        .await?;
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON TABLE registry_internal.registry_migrations FROM {};
             REVOKE ALL ON TABLE registry_internal.registry_migration_steps FROM {};",
            runtime_role.quoted(),
            runtime_role.quoted(),
        ))
        .await?;
    Ok(())
}

pub(crate) async fn reconcile_migration_ledger_metadata_only_constraints(
    migration: &impl GenericClient,
) -> Result<()> {
    migration
        .batch_execute(
            "ALTER TABLE registry_internal.registry_migrations
                 DROP CONSTRAINT IF EXISTS registry_migrations_plan_kind_closed,
                 ADD CONSTRAINT registry_migrations_plan_kind_closed
                     CHECK (plan_kind IN ('compiled_additive', 'metadata_only', 'reviewed'));
             ALTER TABLE registry_internal.registry_migrations
                 DROP CONSTRAINT IF EXISTS registry_migrations_checksums_nonempty,
                 ADD CONSTRAINT registry_migrations_checksums_nonempty
                     CHECK (
                         COALESCE(array_ndims(statement_checksums), 1) = 1
                         AND cardinality(statement_checksums) BETWEEN 0 AND 1024
                         AND array_position(statement_checksums, '') IS NULL
                         AND (
                             (plan_kind = 'metadata_only' AND cardinality(statement_checksums) = 0)
                             OR (plan_kind = 'reviewed' AND cardinality(statement_checksums) = 0)
                             OR (plan_kind IN ('compiled_additive', 'reviewed')
                                 AND cardinality(statement_checksums) BETWEEN 1 AND 1024)
                         )
                     );
             ALTER TABLE registry_internal.registry_migrations
                 DROP CONSTRAINT IF EXISTS registry_migrations_artifacts_consistent,
                 ADD CONSTRAINT registry_migrations_artifacts_consistent CHECK (
                     COALESCE(array_ndims(artifact_paths), 1) = 1
                     AND COALESCE(array_ndims(artifact_checksums), 1) = 1
                     AND cardinality(artifact_paths) = cardinality(artifact_checksums)
                     AND cardinality(artifact_paths) BETWEEN 0 AND 1024
                     AND array_position(artifact_paths, '') IS NULL
                     AND array_position(artifact_checksums, '') IS NULL
                     AND (
                         (plan_kind IN ('compiled_additive', 'metadata_only')
                             AND cardinality(artifact_paths) = 0)
                         OR (plan_kind = 'reviewed' AND cardinality(artifact_paths) > 0)
                     )
                 );",
        )
        .await?;
    Ok(())
}

pub(crate) async fn record_started(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<()> {
    entry.validate()?;
    let artifact_paths = entry.artifact_paths();
    let artifact_checksums = entry.artifact_checksums();
    let changed = client
        .execute(
            "INSERT INTO registry_internal.registry_migrations (
                 target_package_revision, source_package_revision, package_sequence,
                 plan_kind, statement_checksums, artifact_paths, artifact_checksums, outcome
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'applying')
             ON CONFLICT (target_package_revision) DO NOTHING",
            &[
                &entry.target_revision,
                &entry.source_revision,
                &entry.package_sequence,
                &entry.plan_kind.as_str(),
                &entry.statement_checksums,
                &artifact_paths,
                &artifact_checksums,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    for step in &entry.steps {
        let changed = client
            .execute(
                "INSERT INTO registry_internal.registry_migration_steps (
                     target_package_revision, migration_ordinal, step_ordinal,
                     step_id, step_kind, statement_checksum
                 ) VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &entry.target_revision,
                    &step.migration_ordinal,
                    &step.step_ordinal,
                    &step.step_id,
                    &step.kind.as_str(),
                    &step.checksum,
                ],
            )
            .await?;
        if changed != 1 {
            return Err(PostgresKernelError::RegistryUnavailable);
        }
    }
    Ok(())
}

/// Accepts only the exact interrupted or failed target. An applied row is
/// immutable through this library and therefore cannot be resumed or cleared.
pub(crate) async fn verify_resumable(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<()> {
    entry.validate()?;
    let artifact_paths = entry.artifact_paths();
    let artifact_checksums = entry.artifact_checksums();
    let row = client
        .query_opt(
            "SELECT 1
             FROM registry_internal.registry_migrations
             WHERE target_package_revision = $1
               AND source_package_revision IS NOT DISTINCT FROM $2
               AND package_sequence = $3
               AND plan_kind = $4
               AND statement_checksums = $5
               AND artifact_paths = $6
               AND artifact_checksums = $7
               AND outcome IN ('applying', 'failed')
             FOR UPDATE",
            &[
                &entry.target_revision,
                &entry.source_revision,
                &entry.package_sequence,
                &entry.plan_kind.as_str(),
                &entry.statement_checksums,
                &artifact_paths,
                &artifact_checksums,
            ],
        )
        .await?;
    if row.is_none() {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    let rows = client
        .query(
            "SELECT migration_ordinal, step_ordinal, step_id, step_kind, statement_checksum
             FROM registry_internal.registry_migration_steps
             WHERE target_package_revision = $1
             ORDER BY migration_ordinal, step_ordinal",
            &[&entry.target_revision],
        )
        .await?;
    let exact = rows.len() == entry.steps.len()
        && rows.iter().zip(&entry.steps).all(|(row, step)| {
            row.get::<_, i32>(0) == step.migration_ordinal
                && row.get::<_, i32>(1) == step.step_ordinal
                && row.get::<_, String>(2) == step.step_id
                && row.get::<_, String>(3) == step.kind.as_str()
                && row.get::<_, String>(4) == step.checksum
        });
    if !exact {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

pub(crate) async fn migration_phase_state(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<MigrationPhaseState> {
    require_reviewed(entry)?;
    let row = client
        .query_opt(
            "SELECT preconditions_complete, postconditions_complete
             FROM registry_internal.registry_migrations
             WHERE target_package_revision = $1
               AND source_package_revision IS NOT DISTINCT FROM $2
               AND package_sequence = $3
               AND plan_kind = 'reviewed'
               AND outcome IN ('applying', 'failed')
             FOR UPDATE",
            &[
                &entry.target_revision,
                &entry.source_revision,
                &entry.package_sequence,
            ],
        )
        .await?;
    let row = row.ok_or(PostgresKernelError::RegistryUnavailable)?;
    Ok(MigrationPhaseState {
        preconditions_complete: row.get(0),
        postconditions_complete: row.get(1),
    })
}

pub(crate) async fn record_preconditions_complete(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<()> {
    update_phase(client, entry, false).await
}

pub(crate) async fn record_postconditions_complete(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<()> {
    update_phase(client, entry, true).await
}

async fn update_phase(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
    postconditions: bool,
) -> Result<()> {
    require_reviewed(entry)?;
    let (column, prerequisite) = if postconditions {
        (
            "postconditions_complete",
            "AND preconditions_complete
             AND NOT EXISTS (
                 SELECT 1
                 FROM registry_internal.registry_migration_steps s
                 WHERE s.target_package_revision = registry_migrations.target_package_revision
                   AND s.outcome <> 'completed'
             )",
        )
    } else {
        ("preconditions_complete", "")
    };
    let sql = format!(
        "UPDATE registry_internal.registry_migrations
         SET {column} = true
         WHERE target_package_revision = $1
           AND source_package_revision IS NOT DISTINCT FROM $2
           AND package_sequence = $3
           AND plan_kind = 'reviewed'
           AND outcome IN ('applying', 'failed')
           AND NOT {column}
           {prerequisite}"
    );
    let changed = client
        .execute(
            &sql,
            &[
                &entry.target_revision,
                &entry.source_revision,
                &entry.package_sequence,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

pub(crate) async fn step_progress(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
    step: &MigrationLedgerStep,
) -> Result<MigrationStepProgress> {
    require_reviewed(entry)?;
    let row = client
        .query_opt(
            "SELECT outcome, checkpoint_record_id, affected_rows
             FROM registry_internal.registry_migration_steps
             WHERE target_package_revision = $1
               AND migration_ordinal = $2
               AND step_ordinal = $3
               AND step_id = $4
               AND step_kind = $5
               AND statement_checksum = $6
             FOR UPDATE",
            &[
                &entry.target_revision,
                &step.migration_ordinal,
                &step.step_ordinal,
                &step.step_id,
                &step.kind.as_str(),
                &step.checksum,
            ],
        )
        .await?;
    let row = row.ok_or(PostgresKernelError::RegistryUnavailable)?;
    let affected_rows = u64::try_from(row.get::<_, i64>(2))
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    Ok(MigrationStepProgress {
        complete: row.get::<_, String>(0) == "completed",
        checkpoint_record_id: row.get(1),
        affected_rows,
    })
}

pub(crate) async fn record_step_complete(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
    step: &MigrationLedgerStep,
    affected_rows: u64,
) -> Result<()> {
    let affected_rows =
        i64::try_from(affected_rows).map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    let changed = client
        .execute(
            "UPDATE registry_internal.registry_migration_steps
             SET outcome = 'completed', affected_rows = $1,
                 completed_at = transaction_timestamp()
             WHERE target_package_revision = $2
               AND migration_ordinal = $3
               AND step_ordinal = $4
               AND step_id = $5
               AND step_kind = $6
               AND statement_checksum = $7
               AND outcome IN ('pending', 'applying')",
            &[
                &affected_rows,
                &entry.target_revision,
                &step.migration_ordinal,
                &step.step_ordinal,
                &step.step_id,
                &step.kind.as_str(),
                &step.checksum,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

pub(crate) async fn record_chunk_progress(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
    step: &MigrationLedgerStep,
    checkpoint_record_id: Uuid,
    affected_rows: u64,
) -> Result<()> {
    if step.kind != MigrationLedgerStepKind::ChunkedBackfill {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    let affected_rows =
        i64::try_from(affected_rows).map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    let changed = client
        .execute(
            "UPDATE registry_internal.registry_migration_steps
             SET outcome = 'applying', checkpoint_record_id = $1, affected_rows = $2
             WHERE target_package_revision = $3
               AND migration_ordinal = $4
               AND step_ordinal = $5
               AND step_id = $6
               AND step_kind = 'chunked_backfill'
               AND statement_checksum = $7
               AND outcome IN ('pending', 'applying')",
            &[
                &checkpoint_record_id,
                &affected_rows,
                &entry.target_revision,
                &step.migration_ordinal,
                &step.step_ordinal,
                &step.step_id,
                &step.checksum,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

pub(crate) async fn record_failed(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<()> {
    update_outcome(client, entry, "failed").await
}

pub(crate) async fn record_applied(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<()> {
    entry.validate()?;
    let closure = match entry.plan_kind {
        MigrationPlanKind::CompiledAdditive | MigrationPlanKind::MetadataOnly => "",
        MigrationPlanKind::Reviewed => {
            "AND preconditions_complete
             AND postconditions_complete
             AND NOT EXISTS (
                 SELECT 1 FROM registry_internal.registry_migration_steps s
                 WHERE s.target_package_revision = registry_migrations.target_package_revision
                   AND s.outcome <> 'completed'
             )"
        }
    };
    let sql = format!(
        "UPDATE registry_internal.registry_migrations
         SET outcome = 'applied', completed_at = transaction_timestamp()
         WHERE target_package_revision = $1
           AND source_package_revision IS NOT DISTINCT FROM $2
           AND package_sequence = $3
           AND outcome IN ('applying', 'failed')
           {closure}"
    );
    let changed = client
        .execute(
            &sql,
            &[
                &entry.target_revision,
                &entry.source_revision,
                &entry.package_sequence,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

async fn update_outcome(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
    outcome: &'static str,
) -> Result<()> {
    entry.validate()?;
    let changed = client
        .execute(
            "UPDATE registry_internal.registry_migrations
             SET outcome = $1, completed_at = transaction_timestamp()
             WHERE target_package_revision = $2
               AND source_package_revision IS NOT DISTINCT FROM $3
               AND package_sequence = $4
               AND outcome IN ('applying', 'failed')",
            &[
                &outcome,
                &entry.target_revision,
                &entry.source_revision,
                &entry.package_sequence,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

fn require_reviewed(entry: &MigrationLedgerEntry) -> Result<()> {
    entry.validate()?;
    if entry.plan_kind != MigrationPlanKind::Reviewed {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

fn invalid_identity() -> Result<()> {
    Err(PostgresKernelError::Configuration(
        "migration ledger identity is incomplete",
    ))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn statement_checksum(sql: &str) -> String {
    let digest = Sha256::digest(sql.as_bytes());
    let mut checksum = String::with_capacity(71);
    checksum.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut checksum, "{byte:02x}").expect("writing to a String cannot fail");
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_ledger_refuses_unbound_statement_checksums_except_metadata_only() {
        let entry = MigrationLedgerEntry {
            source_revision: Some("prior".to_owned()),
            target_revision: "target".to_owned(),
            package_sequence: 2,
            plan_kind: MigrationPlanKind::CompiledAdditive,
            statement_checksums: Vec::new(),
            artifact_bindings: Vec::new(),
            steps: Vec::new(),
        };
        assert!(matches!(
            entry.validate(),
            Err(PostgresKernelError::Configuration(_))
        ));

        let mut metadata_only = entry.clone();
        metadata_only.plan_kind = MigrationPlanKind::MetadataOnly;
        metadata_only
            .validate()
            .expect("metadata-only ledger binds the package transition without DDL");

        let mut malformed = entry;
        malformed.statement_checksums = vec!["sha256:not-a-digest".to_owned()];
        assert!(matches!(
            malformed.validate(),
            Err(PostgresKernelError::Configuration(_))
        ));
    }

    #[test]
    fn reviewed_migration_ledger_identity_requires_ordered_artifacts_and_allows_no_step_reviews() {
        let mut entry = MigrationLedgerEntry {
            source_revision: Some("prior".to_owned()),
            target_revision: "target".to_owned(),
            package_sequence: 2,
            plan_kind: MigrationPlanKind::Reviewed,
            statement_checksums: Vec::new(),
            artifact_bindings: vec![MigrationArtifactBinding {
                path: "modules/core/migrations/change/descriptor.json".to_owned(),
                checksum: statement_checksum("descriptor"),
            }],
            steps: Vec::new(),
        };
        entry
            .validate()
            .expect("closed reviewed metadata-only identity validates");
        entry.statement_checksums = vec![statement_checksum("SELECT true")];
        entry.steps = vec![MigrationLedgerStep {
            migration_ordinal: 1,
            step_ordinal: 0,
            step_id: "backfill".to_owned(),
            kind: MigrationLedgerStepKind::ChunkedBackfill,
            checksum: statement_checksum("UPDATE"),
        }];
        entry
            .validate()
            .expect("closed reviewed SQL identity validates");
        entry
            .artifact_bindings
            .push(entry.artifact_bindings[0].clone());
        assert!(entry.validate().is_err());
    }
}
