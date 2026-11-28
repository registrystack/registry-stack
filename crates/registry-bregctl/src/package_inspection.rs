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
    posture: registry_platform_config::DeclaredPosture,
    runtime_config: &Path,
) -> Result<
    (
        IntegrityInspectedPackage,
        Vec<registry_platform_yaml::Diagnostic>,
    ),
    RuntimePackageInspectionError,
> {
    let config = load_inspected_runtime_config(posture, runtime_config)?;
    let shared = verify_envelope(&config)?;
    let inspected =
        inspect_package_integrity_with_verified_envelope(config.package().root(), &shared)
            .map_err(RuntimePackageInspectionError::Package)?;
    Ok((
        inspected,
        config.posture_report().diagnostics(runtime_config),
    ))
}

/// Verify the package directory named by `--baseline-package` as the
/// predecessor for successor planning. Its closure follows the declared posture.
pub(crate) fn inspect_baseline_package(
    posture: registry_platform_config::DeclaredPosture,
    package: &Path,
) -> Result<VerifiedPredecessorPackage, PackageError> {
    if !package.is_absolute() {
        return Err(PackageError::UnsafePath);
    }
    load_predecessor_package(
        package,
        &PackageLoadContext {
            posture: posture.posture,
        },
    )
}

/// Verify the same predecessor package as [`inspect_baseline_package`] and
/// compile its packaged sources with the current compiler, so a successor
/// can be rehearsed over the predecessor schema.
pub(crate) fn inspect_baseline_rehearsal(
    posture: registry_platform_config::DeclaredPosture,
    package: &Path,
) -> Result<(VerifiedPredecessorPackage, CompiledRegistry), PackageError> {
    if !package.is_absolute() {
        return Err(PackageError::UnsafePath);
    }
    load_predecessor_rehearsal_baseline(
        package,
        &PackageLoadContext {
            posture: posture.posture,
        },
    )
}

/// Verify the package selected by one runtime configuration as the
/// predecessor for successor planning, then compile its packaged sources with
/// the current compiler.
pub(crate) fn inspect_runtime_predecessor_rehearsal_baseline(
    posture: registry_platform_config::DeclaredPosture,
    runtime_config: &Path,
) -> Result<
    (
        VerifiedPredecessorPackage,
        CompiledRegistry,
        Vec<registry_platform_yaml::Diagnostic>,
    ),
    RuntimePackageInspectionError,
> {
    let config = load_inspected_runtime_config(posture, runtime_config)?;
    let shared = verify_envelope(&config)?;
    let (predecessor, registry) = load_predecessor_rehearsal_baseline_with_verified_envelope(
        config.package().root(),
        &config.package_load_context(),
        &shared,
    )
    .map_err(RuntimePackageInspectionError::Package)?;
    Ok((
        predecessor,
        registry,
        config.posture_report().diagnostics(runtime_config),
    ))
}

fn verify_envelope(
    config: &RuntimeConfig,
) -> Result<SharedVerifiedPackage, RuntimePackageInspectionError> {
    config
        .verify_package_envelope()
        .map_err(|error| RuntimePackageInspectionError::SharedPackage(error.to_string()))
}

fn load_inspected_runtime_config(
    posture: registry_platform_config::DeclaredPosture,
    runtime_config: &Path,
) -> Result<RuntimeConfig, RuntimePackageInspectionError> {
    if !runtime_config.is_absolute() {
        return Err(RuntimePackageInspectionError::RuntimeConfigPath);
    }
    load_runtime_config(runtime_config, posture)
        .map_err(RuntimePackageInspectionError::RuntimeConfig)
}
