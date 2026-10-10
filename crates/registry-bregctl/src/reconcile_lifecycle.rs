// SPDX-License-Identifier: Apache-2.0
//! Operator lifecycle for reconciling a Registry pinned by a failed activation.
//!
//! Assessment is the default and changes nothing. Verification order is
//! security-relevant and matches an activation: the runtime configuration binds
//! the active package, the presented directory is verified as that package's
//! successor, and only then is a database secret resolved or a connection
//! opened. All database work is delegated to
//! `registry_breg::migration_reconcile`.

use std::path::Path;

use registry_breg::audit::RegistryAudit;
use registry_breg::migration_reconcile::{
    reconcile_failed_migration, ReconcileAudit, ReconcileError, ReconcileOutcome, ReconcileReport,
    ReconcileRequest, ReconcileTimeouts,
};
use registry_breg::package::{load_package, PackageError};
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfigError};

use crate::active_registry::{
    observed_identity_for_digest, recorded_identity_for_digest, ActiveRegistryError,
};
use serde::Serialize;

/// The recorded operator reference is a keyed hash in the audit journal, so
/// this bound only keeps an unbounded argument out of the hasher.
const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;

#[derive(Debug)]
pub(crate) enum ReconcileLifecycleError {
    RuntimeConfigPath,
    /// The companion audit destination could not be opened.
    Audit,
    TargetPackagePath,
    OperatorReference,
    RuntimeConfig(RuntimeConfigError),
    ActivePackage(PackageError),
    ActiveRegistry(ActiveRegistryError),
    TargetPackage(PackageError),
    DatabaseConfiguration,
    TimeoutConfiguration,
    Runtime,
    Reconcile(ReconcileError),
}

pub(crate) struct ReconcileLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub package: &'a Path,
    pub operator_reference: &'a str,
    pub execute: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconcileLifecycleOutcome {
    pub outcome: &'static str,
    pub executed: bool,
    pub maintenance_status: Option<String>,
    pub maintenance_target_package_digest: Option<String>,
    pub active_package_digest: Option<String>,
    pub target_package_digest: String,
    pub target_catalog_finding: Option<&'static str>,
    pub active_catalog_finding: Option<&'static str>,
    pub unresolvable_reason: Option<&'static str>,
    pub plan_kind: &'static str,
    pub migration_step_count: usize,
    pub reviewed_plan_closed: Option<bool>,
    pub durable_step_progress: Option<bool>,
}

pub(crate) fn run(
    request: ReconcileLifecycleRequest<'_>,
) -> Result<ReconcileLifecycleOutcome, ReconcileLifecycleError> {
    if !request.runtime_config.is_absolute() {
        return Err(ReconcileLifecycleError::RuntimeConfigPath);
    }
    if !request.package.is_absolute() {
        return Err(ReconcileLifecycleError::TargetPackagePath);
    }
    validate_operator_reference(request.operator_reference)?;
    let config = load_runtime_config(request.runtime_config)
        .map_err(ReconcileLifecycleError::RuntimeConfig)?;

    // The active package may have been compiled before a generated contract
    // changed. Verify it as a historical predecessor and combine its retained
    // schema baseline with the verified current target; its hash-covered
    // engine feature set separately binds whether the statistical release
    // store belongs to the historical catalog.
    let active = config
        .load_active_predecessor_package()
        .map_err(ReconcileLifecycleError::ActivePackage)?;
    let target = load_package(request.package, &config.package_load_context())
        .map_err(ReconcileLifecycleError::TargetPackage)?;
    // The active package is never its own successor, so naming it as the
    // target is refused before any database secret is resolved.
    if target.package_digest() == active.package_digest() {
        return Err(ReconcileLifecycleError::TargetPackage(
            PackageError::Binding,
        ));
    }

    let connection = config
        .migration_database_connection_config()
        .map_err(|_| ReconcileLifecycleError::DatabaseConfiguration)?;
    let audit_profile = config
        .audit_profile()
        .map_err(ReconcileLifecycleError::RuntimeConfig)?;
    let timeouts = ReconcileTimeouts::new(
        config.operational_timeouts().migration_lock,
        config.operational_timeouts().migration_statement,
    )
    .map_err(|_| ReconcileLifecycleError::TimeoutConfiguration)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ReconcileLifecycleError::Runtime)?;
    let active_registry = target
        .registry()
        .with_migration_baseline_schema(active.migration_baseline());
    let active_catalog =
        registry_breg::postgres::ExpectedManagedCatalog::compiled(&active_registry);
    let reconcile = |current, audit| {
        runtime
            .block_on(reconcile_failed_migration(ReconcileRequest {
                config: &connection,
                target_package: &target,
                current: &current,
                current_catalog: &active_catalog,
                migration_role: config.database().roles().migration(),
                runtime_role: config.database().roles().runtime(),
                timeouts,
                audit,
                operator_reference: request.operator_reference,
            }))
            .map_err(ReconcileLifecycleError::Reconcile)
    };
    let report = if request.execute {
        let current = recorded_identity_for_digest(
            &runtime,
            &config,
            &connection,
            active.package_id(),
            active.package_digest(),
        )
        .map_err(execute_preflight_refusal)?;
        let audit = runtime
            .block_on(RegistryAudit::open_companion(&config))
            .map_err(|_| ReconcileLifecycleError::Audit)?;
        reconcile(current, ReconcileAudit::Execute(&audit))?
    } else {
        // Assessment writes nothing, so it reads the active identity without
        // the exclusive lock and opens no audit writer. The reconciliation
        // takes the lock and re-reads the identity under it, refusing a
        // snapshot that no longer matches.
        let current =
            observed_identity_for_digest(&runtime, &config, &connection, active.package_digest())
                .map_err(ReconcileLifecycleError::ActiveRegistry)?;
        reconcile(current, ReconcileAudit::Assess(&audit_profile))?
    };
    Ok(outcome_report(report))
}

/// Execution performs only a transition an assessment under the lock named,
/// so a lock another session holds refuses it as in progress.
fn execute_preflight_refusal(error: ActiveRegistryError) -> ReconcileLifecycleError {
    match error {
        ActiveRegistryError::InProgress => ReconcileLifecycleError::Reconcile(
            ReconcileError::NotExecutable(ReconcileOutcome::InProgress),
        ),
        _ => ReconcileLifecycleError::ActiveRegistry(error),
    }
}

fn outcome_report(report: ReconcileReport) -> ReconcileLifecycleOutcome {
    ReconcileLifecycleOutcome {
        outcome: report.outcome.as_str(),
        executed: report.executed,
        maintenance_status: report.maintenance_status,
        maintenance_target_package_digest: report.maintenance_target_package_digest,
        active_package_digest: report.active_package_digest,
        target_package_digest: report.target_package_digest,
        target_catalog_finding: report.target_catalog_finding,
        active_catalog_finding: report.active_catalog_finding,
        unresolvable_reason: report.unresolvable_reason,
        plan_kind: report.plan_kind,
        migration_step_count: report.migration_step_count,
        reviewed_plan_closed: report.reviewed_plan_closed,
        durable_step_progress: report.durable_step_progress,
    }
}

fn validate_operator_reference(reference: &str) -> Result<(), ReconcileLifecycleError> {
    if reference.is_empty()
        || reference.len() > MAX_OPERATOR_REFERENCE_BYTES
        || reference.chars().any(char::is_control)
    {
        return Err(ReconcileLifecycleError::OperatorReference);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_refuses_a_held_migration_lock_as_in_progress() {
        assert!(matches!(
            execute_preflight_refusal(ActiveRegistryError::InProgress),
            ReconcileLifecycleError::Reconcile(ReconcileError::NotExecutable(
                ReconcileOutcome::InProgress
            ))
        ));
        assert!(matches!(
            execute_preflight_refusal(ActiveRegistryError::Unavailable),
            ReconcileLifecycleError::ActiveRegistry(ActiveRegistryError::Unavailable)
        ));
    }

    #[test]
    fn the_report_names_package_digests_as_digests() {
        let digest = |n: u8| format!("sha256:{}", format!("{n:x}").repeat(64));
        let rendered = serde_json::to_value(outcome_report(ReconcileReport {
            outcome: ReconcileOutcome::Unresolvable,
            maintenance_status: Some("failed".to_owned()),
            maintenance_target_package_digest: Some(digest(2)),
            active_package_digest: Some(digest(1)),
            target_package_digest: digest(2),
            target_catalog_finding: None,
            active_catalog_finding: None,
            unresolvable_reason: None,
            plan_kind: "compiled_additive",
            migration_step_count: 0,
            reviewed_plan_closed: None,
            durable_step_progress: None,
            executed: false,
        }))
        .expect("the report serializes");
        assert_eq!(rendered["maintenanceTargetPackageDigest"], digest(2));
        assert_eq!(rendered["activePackageDigest"], digest(1));
        assert_eq!(rendered["targetPackageDigest"], digest(2));
        for revision in [
            "maintenanceTargetRevision",
            "activePackageRevision",
            "targetPackageRevision",
        ] {
            assert!(
                rendered.get(revision).is_none(),
                "{revision} is not reported"
            );
        }
    }

    #[test]
    fn the_operator_reference_is_present_bounded_and_free_of_control_characters() {
        assert!(validate_operator_reference("change-1").is_ok());
        assert!(validate_operator_reference("").is_err());
        assert!(validate_operator_reference("change\n1").is_err());
        assert!(validate_operator_reference(&"c".repeat(MAX_OPERATOR_REFERENCE_BYTES)).is_ok());
        assert!(
            validate_operator_reference(&"c".repeat(MAX_OPERATOR_REFERENCE_BYTES + 1)).is_err()
        );
    }
}
