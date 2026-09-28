// SPDX-License-Identifier: Apache-2.0
//! The active registry identity an operator lifecycle acts on.
//!
//! A package names no deployment and no place in the apply order, so the
//! identity a lifecycle expects comes from the database: it records which
//! package is active and its sequence. The configured active package is then
//! bound to that record, so a lifecycle acts only on the package the database
//! runs, in the database the runtime configuration names.

use registry_breg::migration::{
    bind_active_package, read_recorded_registry_state, ActivationDeployment, ApplyTimeouts,
    MigrationError,
};
use registry_breg::package::VerifiedPackage;
use registry_breg::postgres::{ConnectionConfig, ExpectedRegistryIdentity};
use registry_breg::runtime_config::RuntimeConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActiveRegistryError {
    /// The database could not be read under the apply lock.
    Unavailable,
    /// The database records no activated registry for this package id.
    Uninitialized,
    /// The database was installed by a release before the activation ledger
    /// and has not been adopted into it.
    PreLedger,
    /// The database records a different database id than the runtime
    /// configuration names.
    DatabaseMismatch,
    /// The configured active package is not the package the database records
    /// as active.
    PackageMismatch,
}

/// Read the identity the database records for the configured active package
/// and bind that package and the runtime identity to it. Nothing is written.
pub(crate) fn recorded_active_identity(
    runtime: &tokio::runtime::Runtime,
    config: &RuntimeConfig,
    connection: &ConnectionConfig,
    package: &VerifiedPackage,
) -> Result<ExpectedRegistryIdentity, ActiveRegistryError> {
    recorded_identity_for_digest(
        runtime,
        config,
        connection,
        &package.manifest().package_id,
        package.package_digest(),
    )
}

/// As [`recorded_active_identity`], for a caller that holds only the active
/// package's id and digest.
pub(crate) fn recorded_identity_for_digest(
    runtime: &tokio::runtime::Runtime,
    config: &RuntimeConfig,
    connection: &ConnectionConfig,
    package_id: &str,
    package_digest: &str,
) -> Result<ExpectedRegistryIdentity, ActiveRegistryError> {
    let timeouts = ApplyTimeouts::new(
        config.operational_timeouts().migration_lock,
        config.operational_timeouts().migration_statement,
    )
    .map_err(|_| ActiveRegistryError::Unavailable)?;
    let recorded = runtime
        .block_on(read_recorded_registry_state(
            connection,
            package_id,
            config.database().roles().migration(),
            timeouts,
        ))
        .map_err(|error| match error {
            MigrationError::PreLedgerDatabase => ActiveRegistryError::PreLedger,
            _ => ActiveRegistryError::Unavailable,
        })?
        .ok_or(ActiveRegistryError::Uninitialized)?;
    let identity = config.identity();
    bind_active_package(
        &recorded.identity,
        package_digest,
        ActivationDeployment::new(
            identity.environment(),
            identity.instance_id(),
            identity.database_id(),
        ),
    )
    .map_err(|error| match error {
        MigrationError::DatabaseMismatch => ActiveRegistryError::DatabaseMismatch,
        _ => ActiveRegistryError::PackageMismatch,
    })?;
    Ok(recorded.identity)
}
