// SPDX-License-Identifier: Apache-2.0
//! Verified package apply coordinator.

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::event_destination::EventDestinationCompatibilityInventory;
use crate::history_schema::HistorySchemaDescriptor;
use crate::migration_plan::{
    ExternalBackupBinding, ReviewedMigrationStepDescriptor, ValidatedReviewedMigrationPlan,
};
use crate::package::{
    CompiledRegistryChangeClass, CompiledRegistryMigrationBaseline, MigrationPlan, PackageFileRole,
    VerifiedPackage,
};
use crate::postgres::{
    statement_checksum, ConnectionConfig, ExpectedManagedCatalog, ExpectedRegistryIdentity,
    MigrationArtifactBinding, MigrationLedgerEntry, MigrationLedgerStep, MigrationLedgerStepKind,
    MigrationPlanKind, PackageDdlStatement, RegistryLockKey, ReviewedExecutionOutcome,
    ReviewedPackageExecutionRequest, SqlIdentifier, VerifiedPackageApplyConnection,
};

const MAX_LOCK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Value-free apply failures. Neither SQL nor database or package values cross
/// this boundary.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum MigrationError {
    #[error("the verified package is not a valid activation successor")]
    PackageBinding,
    #[error("the verified package has no additive migration work")]
    EmptyPlan,
    #[error("the Registry package apply failed")]
    ApplyFailed,
    #[error("active request proposals require rebase or cancellation before this package can be activated")]
    ActiveRequestProposals,
    #[error("destructive backup evidence is invalid")]
    BackupEvidence,
}

pub type Result<T> = std::result::Result<T, MigrationError>;

fn verified_metadata_only_plan(plan: &MigrationPlan) -> bool {
    !plan.changes.is_empty()
        && plan.statements.is_empty()
        && plan.reviewed_descriptors.is_empty()
        && plan
            .changes
            .iter()
            .all(|change| change.class == CompiledRegistryChangeClass::AccessOrDisclosureChange)
}

/// Exact durable precondition under which a verified package may be applied.
pub enum ApplyPrecondition<'a> {
    InitialActivation,
    Successor {
        current: &'a ExpectedRegistryIdentity,
    },
}

/// The configured least-privilege database roles used by one apply.
#[derive(Clone, Copy)]
pub struct ApplyRoles<'a> {
    migration: &'a SqlIdentifier,
    runtime: &'a SqlIdentifier,
}

impl<'a> ApplyRoles<'a> {
    #[must_use]
    pub fn new(migration: &'a SqlIdentifier, runtime: &'a SqlIdentifier) -> Self {
        Self { migration, runtime }
    }
}

/// Bounded lock and per-statement execution timeouts for one apply.
#[derive(Clone, Copy)]
pub struct ApplyTimeouts {
    lock: Duration,
    statement: Duration,
}

/// One local external-backup file bound to the reviewed package artifact that
/// describes it. The path grants authority only to read and retain that exact
/// file for this apply; it cannot add SQL, a checkpoint, or a migration target.
#[derive(Clone, Copy)]
pub struct DestructiveBackupEvidence<'a> {
    binding_path: &'a str,
    local_path: &'a Path,
}

impl<'a> DestructiveBackupEvidence<'a> {
    #[must_use]
    pub fn new(binding_path: &'a str, local_path: &'a Path) -> Self {
        Self {
            binding_path,
            local_path,
        }
    }
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum ReviewedMigrationFaultPoint {
    AfterCommittedChunk(u64),
}

impl ApplyTimeouts {
    pub fn new(lock: Duration, statement: Duration) -> Result<Self> {
        if lock < Duration::from_millis(1)
            || lock > MAX_LOCK_TIMEOUT
            || statement < Duration::from_millis(1)
            || statement > MAX_STATEMENT_TIMEOUT
        {
            return Err(MigrationError::ApplyFailed);
        }
        Ok(Self { lock, statement })
    }
}

/// Closed library request for applying one already verified package. There is
/// no raw path, arbitrary SQL, down-migration, backfill, or destructive-plan
/// entry point in this lifecycle.
pub struct ApplyVerifiedPackageRequest<'a> {
    config: &'a ConnectionConfig,
    package: &'a VerifiedPackage,
    precondition: ApplyPrecondition<'a>,
    roles: ApplyRoles<'a>,
    timeouts: ApplyTimeouts,
    backup_evidence: &'a [DestructiveBackupEvidence<'a>],
    predecessor_history_descriptor: Option<&'a HistorySchemaDescriptor>,
    predecessor_migration_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
    event_destination_compatibility_inventory: Option<&'a EventDestinationCompatibilityInventory>,
    fault_after_committed_chunks: Option<u64>,
}

impl<'a> ApplyVerifiedPackageRequest<'a> {
    #[must_use]
    pub fn new(
        config: &'a ConnectionConfig,
        package: &'a VerifiedPackage,
        precondition: ApplyPrecondition<'a>,
        roles: ApplyRoles<'a>,
        timeouts: ApplyTimeouts,
    ) -> Self {
        Self {
            config,
            package,
            precondition,
            roles,
            timeouts,
            backup_evidence: &[],
            predecessor_history_descriptor: None,
            predecessor_migration_baseline: None,
            event_destination_compatibility_inventory: None,
            fault_after_committed_chunks: None,
        }
    }

    #[must_use]
    pub fn with_destructive_backup_evidence(
        mut self,
        evidence: &'a [DestructiveBackupEvidence<'a>],
    ) -> Self {
        self.backup_evidence = evidence;
        self
    }

    /// Bind successor history readiness to the already verified, read-only
    /// predecessor schema descriptor. This descriptor can be retained and used
    /// to decode historical snapshots, but it never grants runtime authority or
    /// permission to execute predecessor SQL.
    #[must_use]
    pub fn with_predecessor_history_descriptor(
        mut self,
        descriptor: &'a HistorySchemaDescriptor,
    ) -> Self {
        self.predecessor_history_descriptor = Some(descriptor);
        self
    }

    /// Bind successor history readiness to the verified predecessor baseline
    /// when the target manifest cannot carry one. The baseline only describes
    /// historical storage shape; it does not grant startup, runtime, or SQL
    /// execution authority.
    #[must_use]
    pub fn with_predecessor_migration_baseline(
        mut self,
        baseline: &'a CompiledRegistryMigrationBaseline,
    ) -> Self {
        self.predecessor_migration_baseline = Some(baseline);
        self
    }

    /// Bind successor activation to the target runtime's activated,
    /// non-secret logical destination inventory. Omitting this inventory is
    /// equivalent to an empty inventory and therefore fails closed when any
    /// retained non-terminal webhook work exists.
    #[must_use]
    pub fn with_event_destination_compatibility_inventory(
        mut self,
        inventory: &'a EventDestinationCompatibilityInventory,
    ) -> Self {
        self.event_destination_compatibility_inventory = Some(inventory);
        self
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: ReviewedMigrationFaultPoint) -> Self {
        self.fault_after_committed_chunks = match fault {
            ReviewedMigrationFaultPoint::AfterCommittedChunk(chunks) => Some(chunks),
        };
        self
    }
}

/// Apply the exact plan already rederived by the package verifier, verify the
/// resulting managed catalog and signed schema fingerprint, and atomically
/// activate its identity with an immutable applied-ledger outcome.
///
/// Threat: a caller might try to run SQL outside the reviewed package, apply a
/// startup package, skip sequence/prior checks, clear failed maintenance with a
/// different target, or race record work. Enforcement is this package-only
/// coordinator plus the exact-role dedicated session lock and ledger. Failures
/// after the control plane begins leave applying or failed state, so records
/// remain unavailable and recovery is exact-target fix-forward only.
pub async fn apply_verified_package(
    request: ApplyVerifiedPackageRequest<'_>,
) -> Result<ExpectedRegistryIdentity> {
    let manifest = request.package.manifest();
    let target_sequence =
        i64::try_from(manifest.sequence).map_err(|_| MigrationError::PackageBinding)?;
    let target = ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        environment: manifest.environment.clone(),
        instance_id: manifest.instance_id.clone(),
        database_id: manifest.database_id.clone(),
        package_revision: manifest.package_revision.clone(),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
        package_sequence: target_sequence,
    };
    let current = match request.precondition {
        ApplyPrecondition::InitialActivation => {
            if !request.package.verified_for_initial_activation()
                || manifest.sequence != 1
                || manifest.prior_revision.is_some()
                || manifest.migration_plan.from_revision.is_some()
            {
                return Err(MigrationError::PackageBinding);
            }
            None
        }
        ApplyPrecondition::Successor { current } => {
            current
                .validate()
                .map_err(|_| MigrationError::PackageBinding)?;
            let active_sequence = u64::try_from(current.package_sequence)
                .map_err(|_| MigrationError::PackageBinding)?;
            if !request
                .package
                .verified_for_activation(&current.package_revision, active_sequence)
                || manifest.environment != current.environment
                || manifest.package_id != current.package_id
                || manifest.instance_id != current.instance_id
                || manifest.database_id != current.database_id
                || manifest.prior_revision.as_deref() != Some(current.package_revision.as_str())
                || manifest.migration_plan.from_revision.as_deref()
                    != Some(current.package_revision.as_str())
                || target_sequence <= current.package_sequence
            {
                return Err(MigrationError::PackageBinding);
            }
            Some(current)
        }
    };
    let reviewed_plan = request.package.reviewed_migration_plan();
    if manifest.migration_plan.reviewed_descriptors.is_empty() != reviewed_plan.is_none()
        || reviewed_plan.is_some() && current.is_none()
    {
        return Err(MigrationError::PackageBinding);
    }
    let successor_history = if let Some(plan_current) = current {
        let predecessor_baseline = bind_predecessor_baseline(
            manifest.migration_plan.prior_baseline.as_ref(),
            request.predecessor_migration_baseline,
        )?;
        if predecessor_baseline
            .is_some_and(|baseline| baseline.package_revision != plan_current.package_revision)
            || request
                .predecessor_history_descriptor
                .is_some_and(|descriptor| {
                    descriptor.package_revision != plan_current.package_revision
                })
        {
            return Err(MigrationError::PackageBinding);
        }
        Some((predecessor_baseline, request.predecessor_history_descriptor))
    } else {
        None
    };
    if manifest.migration_plan.statements.is_empty()
        && reviewed_plan.is_none()
        && !verified_metadata_only_plan(&manifest.migration_plan)
    {
        return Err(MigrationError::EmptyPlan);
    }

    let metadata_only_plan = verified_metadata_only_plan(&manifest.migration_plan);
    let compiler_checksums = manifest
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement_checksum(&statement.sql))
        .collect::<Vec<_>>();
    let ledger = if let Some(plan) = reviewed_plan {
        reviewed_ledger(
            request.package,
            current.ok_or(MigrationError::PackageBinding)?,
            plan,
        )?
    } else {
        MigrationLedgerEntry {
            source_revision: current.map(|identity| identity.package_revision.clone()),
            target_revision: target.package_revision.clone(),
            package_sequence: target.package_sequence,
            plan_kind: if metadata_only_plan {
                MigrationPlanKind::MetadataOnly
            } else {
                MigrationPlanKind::CompiledAdditive
            },
            statement_checksums: compiler_checksums.clone(),
            artifact_bindings: Vec::new(),
            steps: Vec::new(),
        }
    };
    let statements = manifest
        .migration_plan
        .statements
        .iter()
        .zip(&compiler_checksums)
        .enumerate()
        .map(|(ordinal, (statement, checksum))| {
            Ok(PackageDdlStatement {
                sql: &statement.sql,
                checksum,
                kind: statement.kind,
                ordinal: i32::try_from(ordinal).map_err(|_| MigrationError::PackageBinding)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Threat: a path-only backup check could be swapped between validation
    // and the maintenance transition. The library opens with NOFOLLOW, checks
    // exact package-bound metadata and bytes, and retains every descriptor
    // through activation. It never interprets backup contents or grants them
    // package or migration authority.
    let _retained_backup_evidence = verify_destructive_backup_evidence(
        reviewed_plan,
        current,
        &target,
        request.backup_evidence,
    )
    .await?;

    let lock_key =
        RegistryLockKey::derive(&manifest.package_id).map_err(|_| MigrationError::ApplyFailed)?;
    let mut connection = VerifiedPackageApplyConnection::acquire_for_verified_package(
        request.config,
        lock_key,
        request.roles.migration,
        request.timeouts.lock,
        request.timeouts.statement,
    )
    .await
    .map_err(|_| MigrationError::ApplyFailed)?;
    // Prerequisites are administrator-owned. Refuse a missing extension or
    // spatial role before the existing registry enters maintenance.
    if connection
        .verify_compiled_prerequisites(request.package.registry(), request.roles.runtime)
        .await
        .is_err()
    {
        let _ = connection.release().await;
        return Err(MigrationError::ApplyFailed);
    }
    if current.is_some() {
        if let Err(error) = crate::request_retention::guard_successor_activation(
            connection.client_for_request_retention_guard(),
            request.package.registry(),
        )
        .await
        {
            let _ = connection.release().await;
            return Err(match error {
                crate::request_retention::RequestRetentionError::ActiveProposalRequiresRebase => {
                    MigrationError::ActiveRequestProposals
                }
                _ => MigrationError::ApplyFailed,
            });
        }
    }
    let began = if let Some(current) = current {
        connection
            .begin_successor_package(
                current,
                &target,
                &ledger,
                request.event_destination_compatibility_inventory,
            )
            .await
    } else {
        connection
            .begin_initial_package(&target, &ledger, request.roles.runtime)
            .await
    };
    if began.is_err() {
        let _ = connection.release().await;
        return Err(MigrationError::ApplyFailed);
    }

    if let Some((predecessor_baseline, predecessor_descriptor)) = successor_history {
        if connection
            .ensure_successor_history_ready(
                current.ok_or(MigrationError::PackageBinding)?,
                predecessor_baseline,
                predecessor_descriptor,
                request.roles.runtime,
            )
            .await
            .is_err()
        {
            return fail_and_release(connection, &target, &ledger).await;
        }
        if connection
            .retain_target_history_descriptor(request.package.registry(), &target.package_revision)
            .await
            .is_err()
        {
            return fail_and_release(connection, &target, &ledger).await;
        }
    }

    let expected_catalog = ExpectedManagedCatalog::compiled(request.package.registry());
    if let Some(plan) = reviewed_plan {
        let prior_tables = successor_history
            .and_then(|(baseline, _)| baseline)
            .ok_or(MigrationError::PackageBinding)?
            .entities
            .values()
            .map(|entity| entity.physical_table.clone())
            .collect::<Vec<_>>();
        let candidate_tables = request
            .package
            .registry()
            .entities()
            .values()
            .map(|entity| entity.physical_table.clone())
            .collect::<Vec<_>>();
        let execution = connection
            .execute_reviewed_package_plan(ReviewedPackageExecutionRequest {
                registry: request.package.registry(),
                current: current.ok_or(MigrationError::PackageBinding)?,
                target_package_revision: &target.package_revision,
                plan,
                predecessor_baseline: successor_history.and_then(|(baseline, _)| baseline),
                predecessor_history_descriptor: successor_history
                    .and_then(|(_, descriptor)| descriptor),
                runtime_role: request.roles.runtime,
                compiler_statements: &statements,
                ledger: &ledger,
                prior_tables: &prior_tables,
                candidate_tables: &candidate_tables,
                compiler_lock_timeout: request.timeouts.lock,
                compiler_statement_timeout: request.timeouts.statement,
                fault_after_committed_chunks: request.fault_after_committed_chunks,
            })
            .await;
        match execution {
            Ok(ReviewedExecutionOutcome::Complete) => {}
            Ok(ReviewedExecutionOutcome::Interrupted) => {
                let _ = connection.release().await;
                return Err(MigrationError::ApplyFailed);
            }
            Err(_) => return fail_and_release(connection, &target, &ledger).await,
        }
        if connection
            .reconcile_runtime_acl(request.package.registry(), request.roles.runtime)
            .await
            .is_err()
        {
            return fail_and_release(connection, &target, &ledger).await;
        }
        if connection
            .activate_verified_package(
                current,
                &target,
                &ledger,
                &expected_catalog,
                request.roles.migration,
                request.roles.runtime,
            )
            .await
            .is_err()
        {
            return fail_and_release(connection, &target, &ledger).await;
        }
        connection
            .release()
            .await
            .map_err(|_| MigrationError::ApplyFailed)?;
        return Ok(target);
    }

    if connection
        .reconcile_runtime_acl(request.package.registry(), request.roles.runtime)
        .await
        .is_ok()
        && connection
            .activate_verified_package(
                current,
                &target,
                &ledger,
                &expected_catalog,
                request.roles.migration,
                request.roles.runtime,
            )
            .await
            .is_ok()
    {
        connection
            .release()
            .await
            .map_err(|_| MigrationError::ApplyFailed)?;
        return Ok(target);
    }

    let ddl_result = if current.is_some() {
        connection
            .execute_successor_package_ddl(
                &statements,
                request.roles.runtime,
                request.timeouts.statement,
            )
            .await
    } else {
        connection
            .execute_initial_package_ddl(
                request.package.registry(),
                &target.package_revision,
                &statements,
                request.roles.runtime,
                request.timeouts.statement,
            )
            .await
    };
    if ddl_result.is_err() {
        return fail_and_release(connection, &target, &ledger).await;
    }
    let acl_result = connection
        .reconcile_runtime_acl(request.package.registry(), request.roles.runtime)
        .await;
    if acl_result.is_err() {
        return fail_and_release(connection, &target, &ledger).await;
    }
    let activation_result = connection
        .activate_verified_package(
            current,
            &target,
            &ledger,
            &expected_catalog,
            request.roles.migration,
            request.roles.runtime,
        )
        .await;
    if activation_result.is_err() {
        return fail_and_release(connection, &target, &ledger).await;
    }
    connection
        .release()
        .await
        .map_err(|_| MigrationError::ApplyFailed)?;
    Ok(target)
}

async fn fail_and_release(
    mut connection: VerifiedPackageApplyConnection,
    target: &ExpectedRegistryIdentity,
    ledger: &MigrationLedgerEntry,
) -> Result<ExpectedRegistryIdentity> {
    let marked_failed = connection
        .mark_verified_package_failed(target, ledger)
        .await
        .is_ok();
    let released = connection.release().await.is_ok();
    let _ = (marked_failed, released);
    Err(MigrationError::ApplyFailed)
}

fn reviewed_ledger(
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    plan: &ValidatedReviewedMigrationPlan,
) -> Result<MigrationLedgerEntry> {
    let manifest = package.manifest();
    if plan.migrations().is_empty()
        || manifest.migration_plan.prior_schema_fingerprint.as_deref()
            != Some(current.schema_fingerprint.as_str())
    {
        return Err(MigrationError::PackageBinding);
    }

    let mut statement_checksums = Vec::new();
    for migration in plan.migrations() {
        if migration.rehearsal_receipt.prior_revision != current.package_revision
            || migration.rehearsal_receipt.prior_schema_fingerprint != current.schema_fingerprint
            || migration.rehearsal_receipt.final_schema_fingerprint != manifest.schema_fingerprint
        {
            return Err(MigrationError::PackageBinding);
        }
        statement_checksums.extend(
            migration
                .pre_assertions
                .iter()
                .map(|assertion| assertion.sha256.clone()),
        );
    }
    statement_checksums.extend(
        manifest
            .migration_plan
            .statements
            .iter()
            .map(|statement| statement_checksum(&statement.sql)),
    );
    for migration in plan.migrations() {
        statement_checksums.extend(migration.steps.iter().map(|step| step.sha256.clone()));
    }
    for migration in plan.migrations() {
        statement_checksums.extend(
            migration
                .post_assertions
                .iter()
                .map(|assertion| assertion.sha256.clone()),
        );
    }

    let artifact_bindings = manifest
        .files
        .iter()
        .filter(|file| {
            matches!(
                file.role,
                PackageFileRole::ReviewedMigrationDescriptor
                    | PackageFileRole::ReviewedMigrationStepSql
                    | PackageFileRole::ReviewedMigrationAssertionSql
                    | PackageFileRole::MigrationRehearsalReceipt
                    | PackageFileRole::ExternalBackupBinding
                    | PackageFileRole::MigrationRehearsalFixture
            )
        })
        .map(|file| MigrationArtifactBinding {
            path: file.path.clone(),
            checksum: file.sha256.clone(),
        })
        .collect::<Vec<_>>();

    let mut steps = Vec::new();
    for (step_index, statement) in manifest.migration_plan.statements.iter().enumerate() {
        steps.push(MigrationLedgerStep {
            migration_ordinal: 0,
            step_ordinal: i32::try_from(step_index).map_err(|_| MigrationError::PackageBinding)?,
            step_id: format!("compiler-{step_index:04}"),
            kind: MigrationLedgerStepKind::CompilerDdl,
            checksum: statement_checksum(&statement.sql),
        });
    }
    for (migration_index, migration) in plan.migrations().iter().enumerate() {
        let migration_ordinal =
            i32::try_from(migration_index + 1).map_err(|_| MigrationError::PackageBinding)?;
        for (step_index, step) in migration.steps.iter().enumerate() {
            let (step_id, kind) = match &step.descriptor {
                ReviewedMigrationStepDescriptor::TransactionalSql { id, .. } => {
                    (id.clone(), MigrationLedgerStepKind::TransactionalSql)
                }
                ReviewedMigrationStepDescriptor::ChunkedBackfill { id, .. } => {
                    (id.clone(), MigrationLedgerStepKind::ChunkedBackfill)
                }
            };
            steps.push(MigrationLedgerStep {
                migration_ordinal,
                step_ordinal: i32::try_from(step_index)
                    .map_err(|_| MigrationError::PackageBinding)?,
                step_id,
                kind,
                checksum: step.sha256.clone(),
            });
        }
    }

    let ledger = MigrationLedgerEntry {
        source_revision: Some(current.package_revision.clone()),
        target_revision: manifest.package_revision.clone(),
        package_sequence: i64::try_from(manifest.sequence)
            .map_err(|_| MigrationError::PackageBinding)?,
        plan_kind: MigrationPlanKind::Reviewed,
        statement_checksums,
        artifact_bindings,
        steps,
    };
    ledger
        .validate()
        .map_err(|_| MigrationError::PackageBinding)?;
    Ok(ledger)
}

fn bind_predecessor_baseline<'a>(
    target_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
    verified_baseline: Option<&'a CompiledRegistryMigrationBaseline>,
) -> Result<Option<&'a CompiledRegistryMigrationBaseline>> {
    match (target_baseline, verified_baseline) {
        (Some(target), Some(verified)) => {
            if !predecessor_baselines_match(target, verified) {
                return Err(MigrationError::PackageBinding);
            }
            Ok(Some(verified))
        }
        (Some(target), None) => Ok(Some(target)),
        (None, Some(verified)) => Ok(Some(verified)),
        (None, None) => Ok(None),
    }
}

fn predecessor_baselines_match(
    target: &CompiledRegistryMigrationBaseline,
    verified: &CompiledRegistryMigrationBaseline,
) -> bool {
    target.package_revision == verified.package_revision
        && target.registry_id == verified.registry_id
        && target.registry_version == verified.registry_version
        && target.entities == verified.entities
        && target.physical_names == verified.physical_names
        && target.routes == verified.routes
        && target.access == verified.access
        && target.queries == verified.queries
}

/// The reviewed migrations that require external backup evidence, each paired
/// with the binding path that names it inside the package.
fn required_backup_bindings(
    plan: &ValidatedReviewedMigrationPlan,
) -> Vec<(&str, &ExternalBackupBinding)> {
    plan.migrations()
        .iter()
        .filter_map(|migration| {
            migration
                .descriptor
                .backup_binding_path
                .as_deref()
                .zip(migration.backup_binding.as_ref())
        })
        .collect()
}

/// The package binding paths an apply of this plan requires backup evidence
/// for, in plan order, so a caller that refuses evidence can name the exact set
/// an operator has to supply.
#[must_use]
pub fn required_backup_binding_paths(plan: &ValidatedReviewedMigrationPlan) -> Vec<&str> {
    required_backup_bindings(plan)
        .into_iter()
        .map(|(binding_path, _)| binding_path)
        .collect()
}

/// Pairs every required backup binding with the supplied evidence that names
/// the same binding path, so the order evidence arrives in carries no meaning.
/// The supplied binding paths must be exactly the required set, each named
/// once, and every pair keeps the plan order of the requirement.
fn pair_backup_evidence<'a>(
    required: &[(&'a str, &'a ExternalBackupBinding)],
    evidence: &[DestructiveBackupEvidence<'a>],
) -> Result<Vec<(&'a ExternalBackupBinding, &'a Path)>> {
    if required.len() != evidence.len() {
        return Err(MigrationError::BackupEvidence);
    }
    let mut supplied = BTreeMap::new();
    for entry in evidence {
        if supplied
            .insert(entry.binding_path, entry.local_path)
            .is_some()
        {
            return Err(MigrationError::BackupEvidence);
        }
    }
    required
        .iter()
        .map(|(binding_path, binding)| {
            supplied
                .remove(binding_path)
                .map(|local_path| (*binding, local_path))
                .ok_or(MigrationError::BackupEvidence)
        })
        .collect()
}

async fn verify_destructive_backup_evidence(
    plan: Option<&ValidatedReviewedMigrationPlan>,
    current: Option<&ExpectedRegistryIdentity>,
    target: &ExpectedRegistryIdentity,
    evidence: &[DestructiveBackupEvidence<'_>],
) -> Result<Vec<File>> {
    let Some(plan) = plan else {
        return if evidence.is_empty() {
            Ok(Vec::new())
        } else {
            Err(MigrationError::BackupEvidence)
        };
    };
    let current = current.ok_or(MigrationError::PackageBinding)?;
    let paired = pair_backup_evidence(&required_backup_bindings(plan), evidence)?;

    let mut retained = Vec::with_capacity(paired.len());
    for (binding, local_path) in paired {
        if !local_path.is_absolute()
            || binding.database_id != current.database_id
            || binding.prior_revision != current.package_revision
            || binding.prior_schema_fingerprint != current.schema_fingerprint
            || target.database_id != current.database_id
            || target.package_revision == current.package_revision
        {
            return Err(MigrationError::BackupEvidence);
        }
        let created = OffsetDateTime::parse(&binding.created_at, &Rfc3339)
            .map_err(|_| MigrationError::BackupEvidence)?;
        let now = OffsetDateTime::now_utc();
        if created > now
            || (now - created).whole_seconds()
                > i64::try_from(binding.max_age_seconds)
                    .map_err(|_| MigrationError::BackupEvidence)?
        {
            return Err(MigrationError::BackupEvidence);
        }
        let path = local_path.to_path_buf();
        let binding = binding.clone();
        retained.push(
            tokio::task::spawn_blocking(move || open_bound_backup(path, &binding))
                .await
                .map_err(|_| MigrationError::BackupEvidence)??,
        );
    }
    Ok(retained)
}

#[cfg(unix)]
fn open_bound_backup(path: PathBuf, binding: &ExternalBackupBinding) -> Result<File> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use rustix::fs::{Mode, OFlags};

    let before = std::fs::symlink_metadata(&path).map_err(|_| MigrationError::BackupEvidence)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(MigrationError::BackupEvidence);
    }
    let descriptor = rustix::fs::open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| MigrationError::BackupEvidence)?;
    let file = File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|_| MigrationError::BackupEvidence)?;
    let after = std::fs::symlink_metadata(&path).map_err(|_| MigrationError::BackupEvidence)?;
    if !opened.is_file()
        || after.file_type().is_symlink()
        || !same_backup_file(&before, &opened)
        || !same_backup_file(&opened, &after)
        || opened.uid() != rustix::process::geteuid().as_raw()
        || opened.permissions().mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() != binding.byte_length
    {
        return Err(MigrationError::BackupEvidence);
    }
    verify_backup_digest(file, binding)
}

#[cfg(unix)]
fn same_backup_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn open_bound_backup(_path: PathBuf, _binding: &ExternalBackupBinding) -> Result<File> {
    // The reviewed destructive path requires owner and link-count proofs that
    // this runtime currently obtains only from Unix descriptor metadata.
    Err(MigrationError::BackupEvidence)
}

fn verify_backup_digest(mut file: File, binding: &ExternalBackupBinding) -> Result<File> {
    let mut reader = (&mut file).take(binding.byte_length.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut read = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| MigrationError::BackupEvidence)?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(u64::try_from(count).map_err(|_| MigrationError::BackupEvidence)?)
            .ok_or(MigrationError::BackupEvidence)?;
        hasher.update(&buffer[..count]);
    }
    let mut checksum = String::from("sha256:");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        write!(&mut checksum, "{byte:02x}").expect("writing to a String cannot fail");
    }
    if read != binding.byte_length || checksum != binding.sha256 {
        return Err(MigrationError::BackupEvidence);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::model::{
        CompiledAccessInventory, CompiledActionInventory, CompiledQueryInventory,
        CompiledRouteInventory,
    };
    use crate::package::CompiledRegistryMigrationBaseline;
    use crate::physical_names::PhysicalNameInventory;

    use super::*;

    fn baseline(package_revision: &str, registry_id: &str) -> CompiledRegistryMigrationBaseline {
        CompiledRegistryMigrationBaseline {
            package_revision: package_revision.to_owned(),
            registry_id: registry_id.to_owned(),
            registry_version: "1".to_owned(),
            registry_revision: "ignored-descriptor-revision".to_owned(),
            entities: BTreeMap::new(),
            physical_names: PhysicalNameInventory {
                entities: BTreeMap::new(),
            },
            routes: CompiledRouteInventory { routes: Vec::new() },
            access: CompiledAccessInventory {
                entries: Vec::new(),
            },
            queries: CompiledQueryInventory {
                operations: Vec::new(),
            },
            actions: CompiledActionInventory::default(),
        }
    }

    #[test]
    fn verified_predecessor_baseline_overrides_only_matching_target_baseline() {
        let target = baseline("package-a", "registry-a");
        let mut verified = baseline("package-a", "registry-a");
        verified.registry_revision = "verified-effective-model-digest".to_owned();
        assert!(std::ptr::eq(
            bind_predecessor_baseline(Some(&target), Some(&verified))
                .expect("matching baselines bind")
                .expect("baseline is retained"),
            &verified
        ));

        let forged = baseline("package-a", "registry-b");
        assert_eq!(
            bind_predecessor_baseline(Some(&forged), Some(&verified)),
            Err(MigrationError::PackageBinding)
        );
    }

    fn backup_binding(database_id: &str) -> ExternalBackupBinding {
        ExternalBackupBinding {
            database_id: database_id.to_owned(),
            prior_revision: "package-a".to_owned(),
            prior_schema_fingerprint: "sha256:00".to_owned(),
            sha256: "sha256:11".to_owned(),
            byte_length: 1,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            max_age_seconds: 3600,
        }
    }

    #[test]
    fn backup_evidence_pairs_with_the_binding_path_it_names_in_any_order() {
        let first = backup_binding("database-first");
        let second = backup_binding("database-second");
        let required = [
            ("migrations/first/backup.json", &first),
            ("migrations/second/backup.json", &second),
        ];
        let first_dump = Path::new("/backups/first.dump");
        let second_dump = Path::new("/backups/second.dump");
        let reversed = [
            DestructiveBackupEvidence::new("migrations/second/backup.json", second_dump),
            DestructiveBackupEvidence::new("migrations/first/backup.json", first_dump),
        ];
        assert_eq!(
            pair_backup_evidence(&required, &reversed),
            Ok(vec![(&first, first_dump), (&second, second_dump)])
        );
    }

    #[test]
    fn backup_evidence_naming_an_unrequired_binding_path_is_refused() {
        let binding = backup_binding("database-first");
        let required = [("migrations/first/backup.json", &binding)];
        let misnamed = [DestructiveBackupEvidence::new(
            "migrations/typo/backup.json",
            Path::new("/backups/first.dump"),
        )];
        assert_eq!(
            pair_backup_evidence(&required, &misnamed),
            Err(MigrationError::BackupEvidence)
        );
        let duplicated = [
            DestructiveBackupEvidence::new(
                "migrations/first/backup.json",
                Path::new("/backups/first.dump"),
            ),
            DestructiveBackupEvidence::new(
                "migrations/first/backup.json",
                Path::new("/backups/second.dump"),
            ),
        ];
        assert_eq!(
            pair_backup_evidence(&required, &duplicated),
            Err(MigrationError::BackupEvidence)
        );
        assert!(pair_backup_evidence(&required, &[]).is_err());
    }
}
