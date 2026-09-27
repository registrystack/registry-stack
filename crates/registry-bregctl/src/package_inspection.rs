// SPDX-License-Identifier: Apache-2.0

//! Runtime-bound, read-only package inspection shared by CLI operations.

use std::path::Path;

use registry_breg::package::{
    inspect_package_integrity_with_verified_envelope, load_predecessor_package,
    load_predecessor_rehearsal_baseline,
    load_predecessor_rehearsal_baseline_with_verified_envelope, IntegrityInspectedPackage,
    PackageError, PackageLoadContext, VerifiedPredecessorPackage,
};
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};
use registry_breg::CompiledRegistry;
use registry_platform_config::package::VerifiedPackage as SharedVerifiedPackage;

/// A baseline package named by `--baseline-package` is read on the author's
/// machine, where no runtime identity names a database initialization
/// environment, so its closure is held to the local permission rules.
const BASELINE_PACKAGE_CONTEXT: PackageLoadContext<'static> = PackageLoadContext {
    database_initialization_environment: "local",
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuntimePackageInspectionError {
    RuntimeConfigPath,
    RuntimeConfig(RuntimeConfigError),
    Package(PackageError),
    SharedPackage(String),
}

/// Inspect exactly the package selected by one strict runtime configuration.
/// This opens no database, OIDC source, or listener.
pub(crate) fn inspect_runtime_package(
    runtime_config: &Path,
) -> Result<IntegrityInspectedPackage, RuntimePackageInspectionError> {
    let config = load_inspected_runtime_config(runtime_config)?;
    let shared = verify_envelope(&config)?;
    inspect_package_integrity_with_verified_envelope(config.package().root(), &shared)
        .map_err(RuntimePackageInspectionError::Package)
}

/// Verify the package directory named by `--baseline-package` as the
/// predecessor for successor planning.
pub(crate) fn inspect_baseline_package(
    package: &Path,
) -> Result<VerifiedPredecessorPackage, PackageError> {
    if !package.is_absolute() {
        return Err(PackageError::UnsafePath);
    }
    load_predecessor_package(package, &BASELINE_PACKAGE_CONTEXT)
}

/// Verify the same predecessor package as [`inspect_baseline_package`] and
/// compile its packaged sources with the current compiler, so a successor
/// can be rehearsed over the predecessor schema.
pub(crate) fn inspect_baseline_rehearsal(
    package: &Path,
) -> Result<(VerifiedPredecessorPackage, CompiledRegistry), PackageError> {
    if !package.is_absolute() {
        return Err(PackageError::UnsafePath);
    }
    load_predecessor_rehearsal_baseline(package, &BASELINE_PACKAGE_CONTEXT)
}

/// Verify the package selected by one runtime configuration as the
/// predecessor for successor planning, then compile its packaged sources with
/// the current compiler.
pub(crate) fn inspect_runtime_predecessor_rehearsal_baseline(
    runtime_config: &Path,
) -> Result<(VerifiedPredecessorPackage, CompiledRegistry), RuntimePackageInspectionError> {
    let config = load_inspected_runtime_config(runtime_config)?;
    let shared = verify_envelope(&config)?;
    load_predecessor_rehearsal_baseline_with_verified_envelope(
        config.package().root(),
        &config.package_load_context(),
        &shared,
    )
    .map_err(RuntimePackageInspectionError::Package)
}

fn verify_envelope(
    config: &RuntimeConfig,
) -> Result<SharedVerifiedPackage, RuntimePackageInspectionError> {
    config
        .verify_package_envelope()
        .map_err(|error| RuntimePackageInspectionError::SharedPackage(error.to_string()))
}

fn load_inspected_runtime_config(
    runtime_config: &Path,
) -> Result<RuntimeConfig, RuntimePackageInspectionError> {
    if !runtime_config.is_absolute() {
        return Err(RuntimePackageInspectionError::RuntimeConfigPath);
    }
    load_runtime_config(runtime_config).map_err(RuntimePackageInspectionError::RuntimeConfig)
}
