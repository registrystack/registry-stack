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

use registry_breg::migration_reconcile::{
    reconcile_failed_migration, ReconcileError, ReconcileReport, ReconcileRequest,
    ReconcileTimeouts,
};
use registry_breg::package::{load_package, PackageError, PackageIntent, PackageLoadContext};
use registry_breg::postgres::ExpectedRegistryIdentity;
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfigError};
use serde::Serialize;

/// The recorded operator reference is a keyed hash in the audit journal, so
/// this bound only keeps an unbounded argument out of the hasher.
const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;

#[derive(Debug)]
pub(crate) enum ReconcileLifecycleError {
    RuntimeConfigPath,
    TargetPackagePath,
    OperatorReference,
    RuntimeConfig(RuntimeConfigError),
    ActivePackage(PackageError),
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
    pub maintenance_target_revision: Option<String>,
    pub active_package_revision: Option<String>,
    pub target_package_revision: String,
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

    // The active package carries the compiled registry whose expected catalog
    // an abandoned target has to leave behind, so it is verified in full under
    // the same startup binding the server itself requires.
    let active = load_package(config.package().root(), &config.package_load_context())
        .map_err(ReconcileLifecycleError::ActivePackage)?;
    let current = active_identity(&active)?;
    let target = load_package(
        request.package,
        &PackageLoadContext {
            environment: config.identity().environment(),
            instance_id: config.identity().instance_id(),
            database_id: config.identity().database_id(),
            database_initialization_environment: config
                .identity()
                .database_initialization_environment(),
            compiler_source_revision: config.package().compiler_source_revision(),
            trust_anchor: config.package_trust_anchor(),
            intent: PackageIntent::Activation {
                active_revision: &current.package_revision,
                active_sequence: u64::try_from(current.package_sequence)
                    .map_err(|_| ReconcileLifecycleError::TargetPackage(PackageError::Binding))?,
            },
        },
    )
    .map_err(ReconcileLifecycleError::TargetPackage)?;

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
    let report = runtime
        .block_on(reconcile_failed_migration(ReconcileRequest {
            config: &connection,
            target_package: &target,
            current: &current,
            current_registry: active.registry(),
            migration_role: config.database().roles().migration(),
            runtime_role: config.database().roles().runtime(),
            timeouts,
            audit_profile: &audit_profile,
            operator_reference: request.operator_reference,
            execute: request.execute,
        }))
        .map_err(ReconcileLifecycleError::Reconcile)?;
    Ok(outcome_report(report))
}

fn outcome_report(report: ReconcileReport) -> ReconcileLifecycleOutcome {
    ReconcileLifecycleOutcome {
        outcome: report.outcome.as_str(),
        executed: report.executed,
        maintenance_status: report.maintenance_status,
        maintenance_target_revision: report.maintenance_target_revision,
        active_package_revision: report.active_package_revision,
        target_package_revision: report.target_package_revision,
        target_catalog_finding: report.target_catalog_finding,
        active_catalog_finding: report.active_catalog_finding,
        unresolvable_reason: report.unresolvable_reason,
        plan_kind: report.plan_kind,
        migration_step_count: report.migration_step_count,
        reviewed_plan_closed: report.reviewed_plan_closed,
        durable_step_progress: report.durable_step_progress,
    }
}

fn active_identity(
    package: &registry_breg::package::VerifiedPackage,
) -> Result<ExpectedRegistryIdentity, ReconcileLifecycleError> {
    let manifest = package.manifest();
    Ok(ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        environment: manifest.environment.clone(),
        instance_id: manifest.instance_id.clone(),
        database_id: manifest.database_id.clone(),
        package_revision: manifest.package_revision.clone(),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
        package_sequence: i64::try_from(manifest.sequence)
            .map_err(|_| ReconcileLifecycleError::ActivePackage(PackageError::Binding))?,
    })
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
