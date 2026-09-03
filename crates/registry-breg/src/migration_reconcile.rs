// SPDX-License-Identifier: Apache-2.0

//! Reconciliation of a Registry left pinned by a failed package activation.
//!
//! A failed apply leaves `maintenance_target_revision` pinned, which refuses
//! every other successor until that exact target completes. Fixing forward is
//! the ordinary answer, and this path exists for the two cases where it is not
//! available: an apply whose durable steps all succeeded but whose activation
//! did not commit, and a target that never reached a durable step and must be
//! abandoned so a different successor can be applied.
//!
//! Assessment is the default and changes nothing. It holds the same exclusive
//! migration lock an apply holds, so it cannot observe a half-applied package,
//! and it compares the live managed catalog with the exact verification an
//! activation performs. Execution performs only the one transition the
//! assessment named, through the same interlock an apply uses, and records it
//! in the chained audit journal inside the transition's own transaction.
//!
//! This is not a repair tool. It never writes DDL, never edits catalog
//! objects, never rewrites a ledger row, and never decides that a mismatched
//! catalog is close enough. When the live catalog matches neither package, or
//! a reviewed migration committed steps it cannot finish, the operator is told
//! to restore the pre-activation backup.

use std::time::Duration;

use registry_platform_audit::{AuditChainHasher, AuditKeyHasher, AuditProfile};
use serde_json::json;

use crate::migration::{
    compiler_statement_checksums, package_ledger_entry, target_package_identity,
    verify_successor_package_binding, MigrationError,
};
use crate::model::CompiledRegistry;
use crate::package::VerifiedPackage;
use crate::postgres::{
    ConnectionConfig, ExpectedManagedCatalog, ExpectedRegistryIdentity, MaintenanceAuditRecord,
    MaintenanceSnapshot, MaintenanceTransition, MigrationLedgerEntry, MigrationPlanKind,
    PostgresKernelError, RegistryLockKey, ReviewedMigrationProgress, SqlIdentifier,
    VerifiedPackageApplyConnection,
};

const MAX_LOCK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const AUDIT_OPERATION_ID: &str = "migration-reconcile-maintenance";

/// Why a pinned target can be neither completed nor abandoned. Every reason is
/// a fixed sentence: no database or package value crosses this boundary.
pub const UNRESOLVABLE_IDENTITY_DIFFERS: &str =
    "the durable Registry identity differs from the presented active package";
pub const UNRESOLVABLE_TARGET_DIFFERS: &str =
    "the pinned maintenance target differs from the presented package";
pub const UNRESOLVABLE_STEPS_COMMITTED: &str =
    "a reviewed migration committed steps that only the same target can finish";
pub const UNRESOLVABLE_CATALOG_UNMATCHED: &str =
    "the managed catalog matches neither the pinned target nor the active package";

/// Bounded lock and per-statement execution timeouts for one reconciliation.
#[derive(Clone, Copy)]
pub struct ReconcileTimeouts {
    lock: Duration,
    statement: Duration,
}

impl ReconcileTimeouts {
    pub fn new(lock: Duration, statement: Duration) -> Result<Self, ReconcileError> {
        if lock.is_zero()
            || lock > MAX_LOCK_TIMEOUT
            || statement.is_zero()
            || statement > MAX_STATEMENT_TIMEOUT
        {
            return Err(ReconcileError::InvalidInput);
        }
        Ok(Self { lock, statement })
    }
}

/// One reconciliation of the pinned maintenance target against the two
/// packages that could explain the live managed catalog.
pub struct ReconcileRequest<'a> {
    pub config: &'a ConnectionConfig,
    /// The verified successor package the failed apply pinned.
    pub target_package: &'a VerifiedPackage,
    /// The durable identity the Registry was active on before that apply.
    pub current: &'a ExpectedRegistryIdentity,
    /// The compiled registry of the active package, for its expected catalog.
    pub current_registry: &'a CompiledRegistry,
    pub migration_role: &'a SqlIdentifier,
    pub runtime_role: &'a SqlIdentifier,
    pub timeouts: ReconcileTimeouts,
    pub audit_profile: &'a AuditProfile,
    pub operator_reference: &'a str,
    /// Perform the single safe transition the assessment names. Assessment
    /// alone writes nothing.
    pub execute: bool,
}

/// The one state a pinned Registry is in, as the durable record and the exact
/// activation verification prove it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    /// Nothing is pinned. The Registry is serving its active package.
    Ready,
    /// Another session holds the migration lock, so no assessment is possible.
    InProgress,
    /// Every durable step of the pinned target succeeded and the live catalog
    /// is exactly the target's. Only the activation transition is missing.
    Completable,
    /// The pinned target reached no durable step and the live catalog is
    /// exactly the active package's. The target can be abandoned.
    Revertible,
    /// Neither transition is provably safe. Restore the pre-activation backup.
    Unresolvable,
}

impl ReconcileOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::InProgress => "in_progress",
            Self::Completable => "completable",
            Self::Revertible => "revertible",
            Self::Unresolvable => "unresolvable",
        }
    }
}

/// What the reconciliation found, and what it did if it was told to act.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconcileReport {
    pub outcome: ReconcileOutcome,
    /// The durable maintenance status, absent when the lock was already held.
    pub maintenance_status: Option<String>,
    pub maintenance_target_revision: Option<String>,
    pub active_package_revision: Option<String>,
    pub target_package_revision: String,
    /// The managed-catalog invariant that differs from the pinned target's
    /// expected catalog, absent when the catalog is exactly the target's.
    pub target_catalog_finding: Option<&'static str>,
    /// The same comparison against the active package's expected catalog.
    pub active_catalog_finding: Option<&'static str>,
    pub unresolvable_reason: Option<&'static str>,
    pub plan_kind: &'static str,
    pub migration_step_count: usize,
    pub reviewed_plan_closed: Option<bool>,
    pub durable_step_progress: Option<bool>,
    pub executed: bool,
}

/// Value-free reconciliation failures. Neither SQL nor database or package
/// values cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReconcileError {
    #[error("migration reconciliation input is invalid")]
    InvalidInput,
    #[error("migration reconciliation requires the configured migration authority")]
    MigrationAuthority,
    #[error("the presented package is not a verified successor of the active package")]
    PackageBinding,
    /// The assessed outcome names no safe transition. The outcome travels with
    /// the refusal so a caller can report what it found without acting.
    #[error("migration reconciliation refuses to execute an unresolved outcome")]
    NotExecutable(ReconcileOutcome),
    #[error("migration reconciliation storage is unavailable")]
    Unavailable,
}

impl From<PostgresKernelError> for ReconcileError {
    fn from(error: PostgresKernelError) -> Self {
        match error {
            PostgresKernelError::RoleInvariant(_) => Self::MigrationAuthority,
            PostgresKernelError::Configuration(_) => Self::InvalidInput,
            PostgresKernelError::Connection
            | PostgresKernelError::Pool
            | PostgresKernelError::PoolBuild
            | PostgresKernelError::CatalogInvariant(_)
            | PostgresKernelError::RegistryUnavailable => Self::Unavailable,
        }
    }
}

impl From<MigrationError> for ReconcileError {
    fn from(error: MigrationError) -> Self {
        match error {
            MigrationError::PackageBinding | MigrationError::EmptyPlan => Self::PackageBinding,
            MigrationError::ApplyFailed
            | MigrationError::ActiveRequestProposals
            | MigrationError::BackupEvidence => Self::Unavailable,
        }
    }
}

/// Assess the pinned maintenance target, and perform the one safe transition
/// the assessment names when the request asks for it.
pub async fn reconcile_failed_migration(
    request: ReconcileRequest<'_>,
) -> Result<ReconcileReport, ReconcileError> {
    validate_request(&request)?;
    let target = target_package_identity(request.target_package)?;
    verify_successor_package_binding(request.target_package, request.current, &target)?;
    let checksums = compiler_statement_checksums(request.target_package);
    let ledger = package_ledger_entry(
        request.target_package,
        Some(request.current),
        &target,
        &checksums,
    )?;

    let lock_key = RegistryLockKey::derive(&target.package_id)?;
    // A live apply holds this lock for its whole run. Refusing to wait past
    // the configured lock timeout is what distinguishes an apply in progress
    // from a Registry that is genuinely stuck.
    let mut connection = match VerifiedPackageApplyConnection::acquire_for_verified_package(
        request.config,
        lock_key,
        request.migration_role,
        request.timeouts.lock,
        request.timeouts.statement,
    )
    .await
    {
        Ok(connection) => connection,
        Err(PostgresKernelError::RegistryUnavailable) => {
            return Ok(ReconcileReport {
                outcome: ReconcileOutcome::InProgress,
                maintenance_status: None,
                maintenance_target_revision: None,
                active_package_revision: None,
                target_package_revision: target.package_revision,
                target_catalog_finding: None,
                active_catalog_finding: None,
                unresolvable_reason: None,
                plan_kind: ledger.plan_kind.as_str(),
                migration_step_count: ledger.steps.len(),
                reviewed_plan_closed: None,
                durable_step_progress: None,
                executed: false,
            });
        }
        Err(error) => return Err(error.into()),
    };

    let result = reconcile_under_lock(&mut connection, &request, &target, &ledger).await;
    let released = connection.release().await;
    let report = result?;
    released?;
    Ok(report)
}

async fn reconcile_under_lock(
    connection: &mut VerifiedPackageApplyConnection,
    request: &ReconcileRequest<'_>,
    target: &ExpectedRegistryIdentity,
    ledger: &MigrationLedgerEntry,
) -> Result<ReconcileReport, ReconcileError> {
    let snapshot = connection.maintenance_snapshot().await?;
    let mut report = ReconcileReport {
        outcome: ReconcileOutcome::Unresolvable,
        maintenance_status: Some(snapshot.maintenance_status.clone()),
        maintenance_target_revision: snapshot.maintenance_target_revision.clone(),
        active_package_revision: Some(snapshot.identity.package_revision.clone()),
        target_package_revision: target.package_revision.clone(),
        target_catalog_finding: None,
        active_catalog_finding: None,
        unresolvable_reason: None,
        plan_kind: ledger.plan_kind.as_str(),
        migration_step_count: ledger.steps.len(),
        reviewed_plan_closed: None,
        durable_step_progress: None,
        executed: false,
    };

    if snapshot.maintenance_target_revision.is_none() {
        report.outcome = ReconcileOutcome::Ready;
        return Ok(report);
    }
    if snapshot.identity != *request.current {
        report.unresolvable_reason = Some(UNRESOLVABLE_IDENTITY_DIFFERS);
        return Ok(report);
    }
    if snapshot.maintenance_target_revision.as_deref() != Some(target.package_revision.as_str()) {
        report.unresolvable_reason = Some(UNRESOLVABLE_TARGET_DIFFERS);
        return Ok(report);
    }

    let target_catalog = ExpectedManagedCatalog::compiled(request.target_package.registry());
    let active_catalog = ExpectedManagedCatalog::compiled(request.current_registry);
    report.target_catalog_finding = connection
        .managed_catalog_finding(
            target,
            &target_catalog,
            request.migration_role,
            request.runtime_role,
        )
        .await?;
    report.active_catalog_finding = connection
        .managed_catalog_finding(
            request.current,
            &active_catalog,
            request.migration_role,
            request.runtime_role,
        )
        .await?;

    let progress = if ledger.plan_kind == MigrationPlanKind::Reviewed {
        let progress = connection.reviewed_migration_progress(ledger).await?;
        report.reviewed_plan_closed = Some(progress.closed);
        report.durable_step_progress = Some(progress.durable_step_progress);
        Some(progress)
    } else {
        None
    };
    report.outcome = classify(&report, progress, &snapshot);
    if report.outcome == ReconcileOutcome::Unresolvable && report.unresolvable_reason.is_none() {
        report.unresolvable_reason = Some(unresolvable_reason(progress));
    }

    if !request.execute {
        return Ok(report);
    }
    match report.outcome {
        ReconcileOutcome::Completable => {
            let audit = audit_record(request, target, ledger, "completed", &report)?;
            connection
                .activate_verified_package(
                    Some(request.current),
                    target,
                    MaintenanceTransition {
                        ledger,
                        expected_catalog: &target_catalog,
                        migration_role: request.migration_role,
                        runtime_role: request.runtime_role,
                    },
                    Some(audit),
                )
                .await?;
        }
        ReconcileOutcome::Revertible => {
            let audit = audit_record(request, target, ledger, "reverted", &report)?;
            connection
                .revert_failed_package(
                    request.current,
                    &target.package_revision,
                    MaintenanceTransition {
                        ledger,
                        expected_catalog: &active_catalog,
                        migration_role: request.migration_role,
                        runtime_role: request.runtime_role,
                    },
                    audit,
                )
                .await?;
        }
        outcome @ (ReconcileOutcome::Ready
        | ReconcileOutcome::InProgress
        | ReconcileOutcome::Unresolvable) => return Err(ReconcileError::NotExecutable(outcome)),
    }
    report.executed = true;
    Ok(report)
}

/// Completion is preferred over abandonment: when the live catalog already is
/// the target's, finishing the activation is the transition that leaves the
/// database and its durable record agreeing. Abandonment is offered only when
/// the catalog is still exactly the active package's and no reviewed step
/// committed rows, a checkpoint, or its own completion.
fn classify(
    report: &ReconcileReport,
    progress: Option<ReviewedMigrationProgress>,
    snapshot: &MaintenanceSnapshot,
) -> ReconcileOutcome {
    if snapshot.maintenance_status != "applying" && snapshot.maintenance_status != "failed" {
        return ReconcileOutcome::Unresolvable;
    }
    if report.target_catalog_finding.is_none() && progress.is_none_or(|progress| progress.closed) {
        return ReconcileOutcome::Completable;
    }
    if report.active_catalog_finding.is_none()
        && progress.is_none_or(|progress| !progress.durable_step_progress)
    {
        return ReconcileOutcome::Revertible;
    }
    ReconcileOutcome::Unresolvable
}

fn unresolvable_reason(progress: Option<ReviewedMigrationProgress>) -> &'static str {
    if progress.is_some_and(|progress| progress.durable_step_progress && !progress.closed) {
        UNRESOLVABLE_STEPS_COMMITTED
    } else {
        UNRESOLVABLE_CATALOG_UNMATCHED
    }
}

/// Records identities, the plan shape, and counts. The operator's reference is
/// a keyed hash, and no catalog, package, or record value is written.
fn audit_record<'a>(
    request: &ReconcileRequest<'a>,
    target: &ExpectedRegistryIdentity,
    ledger: &MigrationLedgerEntry,
    action: &'static str,
    report: &ReconcileReport,
) -> Result<MaintenanceAuditRecord<'a>, ReconcileError> {
    let operator_reference = request
        .audit_profile
        .key_hasher()
        .audit_reference_hash(
            "breg-migration-reconcile-operator-v1",
            &request.current.package_revision,
            request.operator_reference,
        )
        .map_err(|_| ReconcileError::InvalidInput)?;
    Ok(MaintenanceAuditRecord {
        profile: request.audit_profile,
        record: json!({
            "schema": "breg-migration-reconcile-audit/v1",
            "phase": "terminal",
            "outcome": "committed",
            "operationId": AUDIT_OPERATION_ID,
            "action": action,
            "packageRevision": request.current.package_revision,
            "targetPackageRevision": target.package_revision,
            "packageSequence": target.package_sequence,
            "planKind": ledger.plan_kind.as_str(),
            "operatorReference": operator_reference,
            "migrationStepCount": ledger.steps.len(),
            "reviewedPlanClosed": report.reviewed_plan_closed,
            "durableStepProgress": report.durable_step_progress,
            "targetCatalogVerified": report.target_catalog_finding.is_none(),
            "activeCatalogVerified": report.active_catalog_finding.is_none(),
        }),
    })
}

fn validate_request(request: &ReconcileRequest<'_>) -> Result<(), ReconcileError> {
    request.current.validate()?;
    if request.operator_reference.is_empty()
        || request.operator_reference.len() > MAX_OPERATOR_REFERENCE_BYTES
        || request.operator_reference.chars().any(char::is_control)
        || !profile_is_keyed(request.audit_profile)
    {
        return Err(ReconcileError::InvalidInput);
    }
    Ok(())
}

fn profile_is_keyed(profile: &AuditProfile) -> bool {
    matches!(profile.chain_hasher(), AuditChainHasher::Keyed(_))
        && matches!(profile.key_hasher(), AuditKeyHasher::Keyed(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(status: &str, target: Option<&str>) -> MaintenanceSnapshot {
        MaintenanceSnapshot {
            identity: ExpectedRegistryIdentity {
                package_id: "registry".to_owned(),
                environment: "production".to_owned(),
                instance_id: "primary".to_owned(),
                database_id: "primary".to_owned(),
                package_revision: "rev-1".to_owned(),
                schema_fingerprint: "fingerprint-1".to_owned(),
                package_sequence: 1,
            },
            maintenance_status: status.to_owned(),
            maintenance_target_revision: target.map(str::to_owned),
        }
    }

    fn report(
        target_catalog_finding: Option<&'static str>,
        active_catalog_finding: Option<&'static str>,
    ) -> ReconcileReport {
        ReconcileReport {
            outcome: ReconcileOutcome::Unresolvable,
            maintenance_status: Some("failed".to_owned()),
            maintenance_target_revision: Some("rev-2".to_owned()),
            active_package_revision: Some("rev-1".to_owned()),
            target_package_revision: "rev-2".to_owned(),
            target_catalog_finding,
            active_catalog_finding,
            unresolvable_reason: None,
            plan_kind: "compiled_additive",
            migration_step_count: 0,
            reviewed_plan_closed: None,
            durable_step_progress: None,
            executed: false,
        }
    }

    #[test]
    fn a_catalog_that_is_already_the_target_is_completable() {
        assert_eq!(
            classify(
                &report(None, Some("differs")),
                None,
                &snapshot("failed", Some("rev-2")),
            ),
            ReconcileOutcome::Completable
        );
    }

    #[test]
    fn a_catalog_that_is_still_the_active_package_is_revertible() {
        assert_eq!(
            classify(
                &report(Some("differs"), None),
                None,
                &snapshot("failed", Some("rev-2")),
            ),
            ReconcileOutcome::Revertible
        );
    }

    #[test]
    fn a_catalog_matching_neither_package_is_unresolvable() {
        assert_eq!(
            classify(
                &report(Some("differs"), Some("differs")),
                None,
                &snapshot("failed", Some("rev-2")),
            ),
            ReconcileOutcome::Unresolvable
        );
        assert_eq!(unresolvable_reason(None), UNRESOLVABLE_CATALOG_UNMATCHED);
    }

    #[test]
    fn a_reviewed_plan_that_committed_steps_can_only_be_completed() {
        let committed = ReviewedMigrationProgress {
            closed: false,
            durable_step_progress: true,
        };
        assert_eq!(
            classify(
                &report(Some("differs"), None),
                Some(committed),
                &snapshot("failed", Some("rev-2")),
            ),
            ReconcileOutcome::Unresolvable
        );
        assert_eq!(
            unresolvable_reason(Some(committed)),
            UNRESOLVABLE_STEPS_COMMITTED
        );
    }

    #[test]
    fn a_reviewed_plan_is_completable_only_once_every_step_closed() {
        let open = ReviewedMigrationProgress {
            closed: false,
            durable_step_progress: false,
        };
        assert_eq!(
            classify(
                &report(None, None),
                Some(open),
                &snapshot("failed", Some("rev-2"))
            ),
            ReconcileOutcome::Revertible
        );
        let closed = ReviewedMigrationProgress {
            closed: true,
            durable_step_progress: true,
        };
        assert_eq!(
            classify(
                &report(None, None),
                Some(closed),
                &snapshot("failed", Some("rev-2")),
            ),
            ReconcileOutcome::Completable
        );
    }

    #[test]
    fn a_ready_registry_is_never_classified_as_actionable() {
        assert_eq!(
            classify(&report(None, None), None, &snapshot("ready", None)),
            ReconcileOutcome::Unresolvable
        );
    }

    #[test]
    fn timeouts_stay_inside_their_bounds() {
        assert!(ReconcileTimeouts::new(Duration::ZERO, Duration::from_secs(1)).is_err());
        assert!(ReconcileTimeouts::new(Duration::from_secs(1), Duration::ZERO).is_err());
        assert!(ReconcileTimeouts::new(
            MAX_LOCK_TIMEOUT + Duration::from_secs(1),
            MAX_STATEMENT_TIMEOUT
        )
        .is_err());
        assert!(ReconcileTimeouts::new(
            MAX_LOCK_TIMEOUT,
            MAX_STATEMENT_TIMEOUT + Duration::from_secs(1)
        )
        .is_err());
        assert!(ReconcileTimeouts::new(MAX_LOCK_TIMEOUT, MAX_STATEMENT_TIMEOUT).is_ok());
    }
}
