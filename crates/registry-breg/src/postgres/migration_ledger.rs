// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::{PostgresKernelError, Result, RuntimeRevoke, SqlIdentifier};

const MAX_MIGRATION_STATEMENTS: usize = 1024;
const MAX_MIGRATION_ARTIFACTS: usize = 1024;
const MAX_MIGRATION_STEPS: usize = 1024;
const MAX_LEDGER_TEXT_BYTES: usize = 512;

/// What one activation changes in the managed catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationKind {
    CompiledAdditive,
    MetadataOnly,
    Reviewed,
}

impl MigrationKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::CompiledAdditive => "compiled-additive",
            Self::MetadataOnly => "metadata-only",
            Self::Reviewed => "reviewed",
        }
    }
}

/// How one activation relates to the package the database ran before it: the
/// first package of an empty database, or the successor of the active package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationPlanKind {
    Initial,
    Successor,
}

impl ActivationPlanKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Successor => "successor",
        }
    }
}

/// Whether the runtime serves with the role that migrates (`single`) or with
/// a separate least-privilege role (`split`). The mode comes from the
/// configured role names; the privileges each mode needs are then asserted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleMode {
    Single,
    Split,
}

impl RoleMode {
    #[must_use]
    pub fn from_roles(migration: &SqlIdentifier, runtime: &SqlIdentifier) -> Self {
        if migration == runtime {
            Self::Single
        } else {
            Self::Split
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Split => "split",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MigrationArtifactBinding {
    pub path: String,
    pub checksum: String,
}

/// One backup a destructive activation was bound to, as the operator's
/// binding described it. The ledger keeps the reference, never the backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BackupReference {
    pub binding_path: String,
    pub backup_file: String,
    pub sha256: String,
    pub byte_length: u64,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationLedgerStepKind {
    CompilerDdl,
    TransactionalSql,
    ChunkedBackfill,
    FieldEncryptionBackfill,
}

impl MigrationLedgerStepKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::CompilerDdl => "compiler_ddl",
            Self::TransactionalSql => "transactional_sql",
            Self::ChunkedBackfill => "chunked_backfill",
            Self::FieldEncryptionBackfill => "field_encryption_backfill",
        }
    }

    /// Whether the step walks a record-id cursor across committed chunks and
    /// therefore carries a checkpoint between chunks.
    pub(crate) fn is_cursor_backfill(self) -> bool {
        matches!(self, Self::ChunkedBackfill | Self::FieldEncryptionBackfill)
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

/// Exact immutable identity of one activation. Statement and artifact digests
/// are ordered because changing order changes the reviewed plan. The
/// activation id is resolved under the apply lock: a retry of the same failed
/// target reuses the id its first attempt recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MigrationLedgerEntry {
    pub activation_id: Uuid,
    pub package_digest: String,
    pub predecessor_package_digest: Option<String>,
    pub registry_revision: String,
    pub plan_kind: ActivationPlanKind,
    pub migration_kind: MigrationKind,
    pub role_mode: RoleMode,
    pub runtime_role: String,
    pub operator_reference_hash: Option<String>,
    pub statement_checksums: Vec<String>,
    pub artifact_bindings: Vec<MigrationArtifactBinding>,
    pub backup_references: Vec<BackupReference>,
    pub steps: Vec<MigrationLedgerStep>,
}

impl MigrationLedgerEntry {
    /// Validates the entry as the ledger records it: a resolved, non-nil
    /// activation id and a well-formed plan.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.activation_id.is_nil() {
            return invalid_identity();
        }
        self.validate_plan()
    }

    /// Validates everything but the activation id, which is resolved only
    /// under the apply lock, so a malformed plan is refused before the lock.
    pub(crate) fn validate_plan(&self) -> Result<()> {
        if !valid_sha256(&self.package_digest)
            || self
                .predecessor_package_digest
                .as_deref()
                .is_some_and(|digest| !valid_sha256(digest))
            || !valid_ledger_text(&self.registry_revision)
            || !valid_ledger_text(&self.runtime_role)
            || self
                .operator_reference_hash
                .as_deref()
                .is_some_and(|hash| !valid_ledger_text(hash))
            || self.statement_checksums.len() > MAX_MIGRATION_STATEMENTS
            || self
                .statement_checksums
                .iter()
                .any(|checksum| !valid_sha256(checksum))
            || self.artifact_bindings.len() > MAX_MIGRATION_ARTIFACTS
            || self.backup_references.len() > MAX_MIGRATION_ARTIFACTS
            || self.backup_references.iter().any(|backup| {
                !valid_ledger_path(&backup.binding_path)
                    || !valid_ledger_path(&backup.backup_file)
                    || !valid_sha256(&backup.sha256)
                    || !valid_ledger_text(&backup.created_at)
            })
            || self.steps.len() > MAX_MIGRATION_STEPS
        {
            return invalid_identity();
        }
        match self.plan_kind {
            ActivationPlanKind::Initial if self.predecessor_package_digest.is_some() => {
                return invalid_identity();
            }
            ActivationPlanKind::Successor if self.predecessor_package_digest.is_none() => {
                return invalid_identity();
            }
            _ => {}
        }
        if self
            .artifact_bindings
            .iter()
            .any(|binding| !valid_ledger_path(&binding.path) || !valid_sha256(&binding.checksum))
            || self
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
        match self.migration_kind {
            MigrationKind::CompiledAdditive
                if self.statement_checksums.is_empty()
                    || !self.artifact_bindings.is_empty()
                    || !self.steps.is_empty() =>
            {
                return invalid_identity();
            }
            MigrationKind::MetadataOnly
                if !self.statement_checksums.is_empty()
                    || !self.artifact_bindings.is_empty()
                    || !self.steps.is_empty() =>
            {
                return invalid_identity();
            }
            MigrationKind::Reviewed if self.artifact_bindings.is_empty() => {
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

    fn backup_references_json(&self) -> String {
        serde_json::Value::Array(
            self.backup_references
                .iter()
                .map(|backup| {
                    serde_json::json!({
                        "bindingPath": backup.binding_path,
                        "backupFile": backup.backup_file,
                        "sha256": backup.sha256,
                        "byteLength": backup.byte_length,
                        "createdAt": backup.created_at,
                    })
                })
                .collect(),
        )
        .to_string()
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

/// Installs only the product-owned durable activation ledger. This is part of
/// the initial control plane and intentionally contains no entity DDL.
///
/// Each row is one activation, keyed by its activation id and numbered by
/// `apply_order`. At most one activation of a package digest is open at a
/// time, so a retry of a failed target resumes the row its first attempt
/// recorded; a reverted target frees its digest for a later activation.
pub(crate) async fn install_migration_ledger(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_migrations (
                 activation_id uuid PRIMARY KEY,
                 apply_order bigint NOT NULL
                     CONSTRAINT registry_migrations_apply_order_unique UNIQUE
                     CONSTRAINT registry_migrations_apply_order_positive
                     CHECK (apply_order > 0),
                 package_digest text NOT NULL
                     CONSTRAINT registry_migrations_package_digest_sha256
                     CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
                 predecessor_package_digest text
                     CONSTRAINT registry_migrations_predecessor_digest_sha256
                     CHECK (predecessor_package_digest ~ '^sha256:[0-9a-f]{64}$'),
                 registry_revision text NOT NULL
                     CONSTRAINT registry_migrations_registry_revision_nonempty
                     CHECK (registry_revision <> ''),
                 plan_kind text NOT NULL
                     CONSTRAINT registry_migrations_plan_kind_closed
                     CHECK (plan_kind IN ('initial', 'successor', 'adopted')),
                 migration_kind text NOT NULL
                     CONSTRAINT registry_migrations_migration_kind_closed
                     CHECK (migration_kind IN ('compiled-additive', 'metadata-only', 'reviewed')),
                 statement_checksums text[] NOT NULL
                     CONSTRAINT registry_migrations_checksums_nonempty
                     CHECK (
                         COALESCE(array_ndims(statement_checksums), 1) = 1
                         AND cardinality(statement_checksums) BETWEEN 0 AND 1024
                         AND array_position(statement_checksums, '') IS NULL
                         AND (
                             (migration_kind = 'metadata-only' AND cardinality(statement_checksums) = 0)
                             OR (migration_kind = 'reviewed' AND cardinality(statement_checksums) = 0)
                             OR (migration_kind IN ('compiled-additive', 'reviewed')
                                 AND cardinality(statement_checksums) BETWEEN 1 AND 1024)
                         )
                     ),
                 artifact_paths text[] NOT NULL,
                 artifact_checksums text[] NOT NULL,
                 preconditions_complete boolean NOT NULL DEFAULT false,
                 postconditions_complete boolean NOT NULL DEFAULT false,
                 outcome text NOT NULL
                     CONSTRAINT registry_migrations_outcome_closed
                     CHECK (outcome IN ('applying', 'failed', 'applied', 'reverted')),
                 started_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 completed_at timestamptz,
                 applied_at timestamptz,
                 operator_reference_hash text
                     CONSTRAINT registry_migrations_operator_reference_nonempty
                     CHECK (operator_reference_hash <> ''),
                 backup_references jsonb NOT NULL DEFAULT '[]'::jsonb
                     CONSTRAINT registry_migrations_backup_references_array
                     CHECK (jsonb_typeof(backup_references) = 'array'),
                 role_mode text NOT NULL
                     CONSTRAINT registry_migrations_role_mode_closed
                     CHECK (role_mode IN ('single', 'split')),
                 runtime_role text NOT NULL
                     CONSTRAINT registry_migrations_runtime_role_nonempty
                     CHECK (runtime_role <> ''),
                 CONSTRAINT registry_migrations_predecessor_consistent CHECK (
                     (plan_kind IN ('initial', 'adopted') AND predecessor_package_digest IS NULL)
                     OR (plan_kind = 'successor' AND predecessor_package_digest IS NOT NULL)
                 ),
                 CONSTRAINT registry_migrations_artifacts_consistent CHECK (
                     COALESCE(array_ndims(artifact_paths), 1) = 1
                     AND COALESCE(array_ndims(artifact_checksums), 1) = 1
                     AND cardinality(artifact_paths) = cardinality(artifact_checksums)
                     AND cardinality(artifact_paths) BETWEEN 0 AND 1024
                     AND array_position(artifact_paths, '') IS NULL
                     AND array_position(artifact_checksums, '') IS NULL
                     AND (
                         (migration_kind IN ('compiled-additive', 'metadata-only')
                             AND cardinality(artifact_paths) = 0)
                         OR (migration_kind = 'reviewed' AND cardinality(artifact_paths) > 0)
                     )
                 ),
                 CONSTRAINT registry_migrations_phases_consistent CHECK (
                     migration_kind = 'reviewed'
                     OR (NOT preconditions_complete AND NOT postconditions_complete)
                 ),
                 CONSTRAINT registry_migrations_completion_consistent CHECK (
                     (outcome = 'applying' AND completed_at IS NULL)
                     OR (outcome IN ('failed', 'applied', 'reverted') AND completed_at IS NOT NULL)
                 ),
                 CONSTRAINT registry_migrations_applied_at_consistent CHECK (
                     (outcome = 'applied') = (applied_at IS NOT NULL)
                 )
             );
             CREATE UNIQUE INDEX IF NOT EXISTS registry_migrations_one_open_activation_per_digest
                 ON registry_internal.registry_migrations (package_digest)
                 WHERE outcome IN ('applying', 'failed');
             CREATE TABLE IF NOT EXISTS registry_internal.registry_migration_steps (
                 activation_id uuid NOT NULL,
                 migration_ordinal integer NOT NULL CHECK (migration_ordinal >= 0),
                 step_ordinal integer NOT NULL CHECK (step_ordinal >= 0),
                 step_id text NOT NULL CHECK (step_id <> ''),
                 step_kind text NOT NULL
                     CONSTRAINT registry_migration_steps_step_kind_closed
                     CHECK (step_kind IN ('compiler_ddl', 'transactional_sql', 'chunked_backfill', 'field_encryption_backfill')),
                 statement_checksum text NOT NULL CHECK (statement_checksum <> ''),
                 outcome text NOT NULL DEFAULT 'pending'
                     CHECK (outcome IN ('pending', 'applying', 'completed')),
                 checkpoint_record_id uuid,
                 affected_rows bigint NOT NULL DEFAULT 0 CHECK (affected_rows >= 0),
                 completed_at timestamptz,
                 PRIMARY KEY (activation_id, migration_ordinal, step_ordinal),
                 CONSTRAINT registry_migration_steps_state_consistent CHECK (
                     (outcome = 'pending' AND checkpoint_record_id IS NULL
                         AND affected_rows = 0 AND completed_at IS NULL)
                     OR (outcome = 'applying'
                         AND step_kind IN ('chunked_backfill', 'field_encryption_backfill')
                         AND checkpoint_record_id IS NOT NULL AND completed_at IS NULL)
                     OR (outcome = 'completed' AND completed_at IS NOT NULL
                         AND (step_kind IN ('chunked_backfill', 'field_encryption_backfill')
                             OR checkpoint_record_id IS NULL))
                 )
             );
             REVOKE ALL ON TABLE registry_internal.registry_migrations FROM PUBLIC;
             REVOKE ALL ON TABLE registry_internal.registry_migration_steps FROM PUBLIC;",
        )
        .await?;
    install_pre_ledger_package_positions(migration).await?;
    let revoke = RuntimeRevoke::detect(migration, runtime_role).await?;
    migration
        .batch_execute(&format!(
            "{}
             {}
             {}",
            revoke.revoke_all_on("TABLE registry_internal.registry_migrations"),
            revoke.revoke_all_on("TABLE registry_internal.registry_migration_steps"),
            revoke.revoke_all_on("TABLE registry_internal.registry_pre_ledger_package_positions"),
        ))
        .await?;
    Ok(())
}

/// Installs the order of the package revisions a pre-ledger database's
/// ledger named, as an earlier release's adoption of it recorded them.
/// Field-encryption flips and request proposals recorded before adoption name
/// those revisions, and erasure orders them against each other here; every
/// position precedes the first activation, so a revision the ledger records
/// always follows them. The table is empty on a database the ledger recorded
/// from its first activation.
async fn install_pre_ledger_package_positions(migration: &impl GenericClient) -> Result<()> {
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_pre_ledger_package_positions (
                 package_revision text PRIMARY KEY
                     CONSTRAINT registry_pre_ledger_package_positions_revision_nonempty
                     CHECK (package_revision <> ''),
                 package_sequence bigint NOT NULL
                     CONSTRAINT registry_pre_ledger_package_positions_precede_the_ledger
                     CHECK (package_sequence < 1)
             );
             REVOKE ALL ON TABLE registry_internal.registry_pre_ledger_package_positions
                 FROM PUBLIC;",
        )
        .await?;
    Ok(())
}

/// The one open (applying or failed) activation of a package digest, with
/// the roles it was started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InFlightActivation {
    pub activation_id: Uuid,
    pub role_mode: String,
    pub runtime_role: String,
}

/// The one open (applying or failed) activation of a package digest, if any.
/// Read under the apply lock, so a retry of the same target resumes the
/// activation its first attempt recorded.
pub(crate) async fn in_flight_activation(
    client: &impl GenericClient,
    package_digest: &str,
) -> Result<Option<InFlightActivation>> {
    let row = client
        .query_opt(
            "SELECT activation_id, role_mode, runtime_role
             FROM registry_internal.registry_migrations
             WHERE package_digest = $1
               AND outcome IN ('applying', 'failed')",
            &[&package_digest],
        )
        .await?;
    row.map(|row| {
        Ok(InFlightActivation {
            activation_id: row.try_get(0)?,
            role_mode: row.try_get(1)?,
            runtime_role: row.try_get(2)?,
        })
    })
    .transpose()
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
                 activation_id, apply_order, package_digest, predecessor_package_digest,
                 registry_revision, plan_kind, migration_kind, statement_checksums,
                 artifact_paths, artifact_checksums, outcome, operator_reference_hash,
                 role_mode, runtime_role, backup_references
             ) VALUES (
                 $1,
                 (SELECT COALESCE(max(apply_order), 0) + 1
                  FROM registry_internal.registry_migrations),
                 $2, $3, $4, $5, $6, $7, $8, $9, 'applying', $10, $11, $12, $13::text::jsonb
             )
             ON CONFLICT DO NOTHING",
            &[
                &entry.activation_id,
                &entry.package_digest,
                &entry.predecessor_package_digest,
                &entry.registry_revision,
                &entry.plan_kind.as_str(),
                &entry.migration_kind.as_str(),
                &entry.statement_checksums,
                &artifact_paths,
                &artifact_checksums,
                &entry.operator_reference_hash,
                &entry.role_mode.as_str(),
                &entry.runtime_role,
                &entry.backup_references_json(),
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
                     activation_id, migration_ordinal, step_ordinal,
                     step_id, step_kind, statement_checksum
                 ) VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &entry.activation_id,
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

/// Accepts only the exact interrupted or failed activation, started with the
/// same roles. An applied or reverted row is immutable through this library
/// and therefore cannot be resumed or cleared. The resumed attempt's operator
/// reference and backup references replace the ones the row recorded, so the
/// ledger names the reference of the attempt that the audit records applying
/// it and the backup that attempt was verified against.
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
             WHERE activation_id = $1
               AND package_digest = $2
               AND predecessor_package_digest IS NOT DISTINCT FROM $3
               AND plan_kind = $4
               AND migration_kind = $5
               AND statement_checksums = $6
               AND artifact_paths = $7
               AND artifact_checksums = $8
               AND role_mode = $9
               AND runtime_role = $10
               AND outcome IN ('applying', 'failed')
             FOR UPDATE",
            &[
                &entry.activation_id,
                &entry.package_digest,
                &entry.predecessor_package_digest,
                &entry.plan_kind.as_str(),
                &entry.migration_kind.as_str(),
                &entry.statement_checksums,
                &artifact_paths,
                &artifact_checksums,
                &entry.role_mode.as_str(),
                &entry.runtime_role,
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
             WHERE activation_id = $1
             ORDER BY migration_ordinal, step_ordinal",
            &[&entry.activation_id],
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
    let changed = client
        .execute(
            "UPDATE registry_internal.registry_migrations
             SET operator_reference_hash = $2,
                 backup_references = $3::text::jsonb
             WHERE activation_id = $1
               AND outcome IN ('applying', 'failed')",
            &[
                &entry.activation_id,
                &entry.operator_reference_hash,
                &entry.backup_references_json(),
            ],
        )
        .await?;
    if changed != 1 {
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
             WHERE activation_id = $1
               AND package_digest = $2
               AND migration_kind = 'reviewed'
               AND outcome IN ('applying', 'failed')
             FOR UPDATE",
            &[&entry.activation_id, &entry.package_digest],
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
                 WHERE s.activation_id = registry_migrations.activation_id
                   AND s.outcome <> 'completed'
             )",
        )
    } else {
        ("preconditions_complete", "")
    };
    let sql = format!(
        "UPDATE registry_internal.registry_migrations
         SET {column} = true
         WHERE activation_id = $1
           AND package_digest = $2
           AND migration_kind = 'reviewed'
           AND outcome IN ('applying', 'failed')
           AND NOT {column}
           {prerequisite}"
    );
    let changed = client
        .execute(&sql, &[&entry.activation_id, &entry.package_digest])
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
             WHERE activation_id = $1
               AND migration_ordinal = $2
               AND step_ordinal = $3
               AND step_id = $4
               AND step_kind = $5
               AND statement_checksum = $6
             FOR UPDATE",
            &[
                &entry.activation_id,
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
             WHERE activation_id = $2
               AND migration_ordinal = $3
               AND step_ordinal = $4
               AND step_id = $5
               AND step_kind = $6
               AND statement_checksum = $7
               AND outcome IN ('pending', 'applying')",
            &[
                &affected_rows,
                &entry.activation_id,
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
    if !step.kind.is_cursor_backfill() {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    let affected_rows =
        i64::try_from(affected_rows).map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    let changed = client
        .execute(
            "UPDATE registry_internal.registry_migration_steps
             SET outcome = 'applying', checkpoint_record_id = $1, affected_rows = $2
             WHERE activation_id = $3
               AND migration_ordinal = $4
               AND step_ordinal = $5
               AND step_id = $6
               AND step_kind IN ('chunked_backfill', 'field_encryption_backfill')
               AND statement_checksum = $7
               AND outcome IN ('pending', 'applying')",
            &[
                &checkpoint_record_id,
                &affected_rows,
                &entry.activation_id,
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

/// Closes an abandoned activation. A reverted row frees its package digest,
/// so a later apply of the same package records a separate activation.
pub(crate) async fn record_reverted(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<()> {
    update_outcome(client, entry, "reverted").await
}

pub(crate) async fn record_applied(
    client: &impl GenericClient,
    entry: &MigrationLedgerEntry,
) -> Result<()> {
    entry.validate()?;
    let closure = match entry.migration_kind {
        MigrationKind::CompiledAdditive | MigrationKind::MetadataOnly => "",
        MigrationKind::Reviewed => {
            "AND preconditions_complete
             AND postconditions_complete
             AND NOT EXISTS (
                 SELECT 1 FROM registry_internal.registry_migration_steps s
                 WHERE s.activation_id = registry_migrations.activation_id
                   AND s.outcome <> 'completed'
             )"
        }
    };
    let sql = format!(
        "UPDATE registry_internal.registry_migrations
         SET outcome = 'applied',
             completed_at = transaction_timestamp(),
             applied_at = transaction_timestamp()
         WHERE activation_id = $1
           AND package_digest = $2
           AND predecessor_package_digest IS NOT DISTINCT FROM $3
           AND role_mode = $4
           AND runtime_role = $5
           AND outcome IN ('applying', 'failed')
           {closure}"
    );
    let changed = client
        .execute(
            &sql,
            &[
                &entry.activation_id,
                &entry.package_digest,
                &entry.predecessor_package_digest,
                &entry.role_mode.as_str(),
                &entry.runtime_role,
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
             WHERE activation_id = $2
               AND package_digest = $3
               AND predecessor_package_digest IS NOT DISTINCT FROM $4
               AND outcome IN ('applying', 'failed')",
            &[
                &outcome,
                &entry.activation_id,
                &entry.package_digest,
                &entry.predecessor_package_digest,
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
    if entry.migration_kind != MigrationKind::Reviewed {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(())
}

fn invalid_identity() -> Result<()> {
    Err(PostgresKernelError::Configuration(
        "migration ledger identity is incomplete",
    ))
}

fn valid_ledger_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LEDGER_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_ledger_path(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    fn stored_migration_kind_words_use_kebab_case() {
        assert_eq!(
            MigrationKind::CompiledAdditive.as_str(),
            "compiled-additive"
        );
        assert_eq!(MigrationKind::MetadataOnly.as_str(), "metadata-only");
        assert_eq!(MigrationKind::Reviewed.as_str(), "reviewed");
    }

    fn entry(migration_kind: MigrationKind) -> MigrationLedgerEntry {
        MigrationLedgerEntry {
            activation_id: Uuid::from_u128(1),
            package_digest: statement_checksum("target"),
            predecessor_package_digest: Some(statement_checksum("prior")),
            registry_revision: "2".to_owned(),
            plan_kind: ActivationPlanKind::Successor,
            migration_kind,
            role_mode: RoleMode::Split,
            runtime_role: "registry_runtime".to_owned(),
            operator_reference_hash: None,
            statement_checksums: Vec::new(),
            artifact_bindings: Vec::new(),
            backup_references: Vec::new(),
            steps: Vec::new(),
        }
    }

    #[test]
    fn migration_ledger_refuses_unbound_statement_checksums_except_metadata_only() {
        let entry = entry(MigrationKind::CompiledAdditive);
        assert!(matches!(
            entry.validate(),
            Err(PostgresKernelError::Configuration(_))
        ));

        let mut metadata_only = entry.clone();
        metadata_only.migration_kind = MigrationKind::MetadataOnly;
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
        let mut entry = entry(MigrationKind::Reviewed);
        entry.artifact_bindings = vec![MigrationArtifactBinding {
            path: "modules/core/migrations/change/descriptor.json".to_owned(),
            checksum: statement_checksum("descriptor"),
        }];
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

    #[test]
    fn activation_ledger_binds_the_plan_kind_to_its_predecessor_and_a_resolved_id() {
        let metadata = entry(MigrationKind::MetadataOnly);
        metadata
            .validate()
            .expect("a successor names its predecessor digest");

        let mut unresolved = metadata.clone();
        unresolved.activation_id = Uuid::nil();
        assert!(
            unresolved.validate().is_err(),
            "the activation id is resolved under the lock"
        );

        let mut orphan = metadata.clone();
        orphan.predecessor_package_digest = None;
        assert!(
            orphan.validate().is_err(),
            "a successor without a predecessor is refused"
        );

        let mut initial = metadata.clone();
        initial.plan_kind = ActivationPlanKind::Initial;
        assert!(
            initial.validate().is_err(),
            "an initial activation has no predecessor"
        );
        initial.predecessor_package_digest = None;
        initial.validate().expect("an initial activation validates");

        let mut reapplied = metadata;
        reapplied.predecessor_package_digest = Some(reapplied.package_digest.clone());
        reapplied
            .validate()
            .expect("a role-change activation succeeds its own package digest");
    }

    #[test]
    fn role_mode_is_single_exactly_when_the_roles_are_equal() {
        let migration = SqlIdentifier::parse("registry_migrator").expect("identifier");
        let runtime = SqlIdentifier::parse("registry_runtime").expect("identifier");
        assert_eq!(
            RoleMode::from_roles(&migration, &migration),
            RoleMode::Single
        );
        assert_eq!(RoleMode::from_roles(&migration, &runtime), RoleMode::Split);
    }
}
