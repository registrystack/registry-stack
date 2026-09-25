// SPDX-License-Identifier: Apache-2.0

//! Runtime-bound, read-only package inspection shared by CLI operations.

use std::path::Path;

use registry_breg::package::{
    inspect_package_with_context, load_predecessor_package, load_predecessor_rehearsal_baseline,
    IntegrityInspectedPackage, PackageError, PackageInspectionContext, PredecessorPackageContext,
    VerifiedPredecessorPackage,
};
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};
use registry_breg::CompiledRegistry;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuntimePackageInspectionError {
    RuntimeConfigPath,
    RuntimeConfig(RuntimeConfigError),
    Package(PackageError),
    SharedPackage(String),
}

/// Inspect exactly the package selected and bound by one strict runtime
/// configuration. This opens no database, OIDC source, or listener.
pub(crate) fn inspect_runtime_package(
    runtime_config: &Path,
) -> Result<IntegrityInspectedPackage, RuntimePackageInspectionError> {
    if !runtime_config.is_absolute() {
        return Err(RuntimePackageInspectionError::RuntimeConfigPath);
    }
    let config = load_runtime_config(runtime_config)
        .map_err(RuntimePackageInspectionError::RuntimeConfig)?;
    config
        .verify_package_envelope()
        .map_err(|error| RuntimePackageInspectionError::SharedPackage(error.to_string()))?;
    let context = PackageInspectionContext {
        environment: config.identity().environment(),
        instance_id: config.identity().instance_id(),
        database_id: config.identity().database_id(),
        database_initialization_environment: config
            .identity()
            .database_initialization_environment(),
        compiler_source_revision: config.package().compiler_source_revision(),
        trust_anchor: config.package_trust_anchor(),
        expected_package_revision: config.package().active_revision(),
        expected_sequence: config.package().active_sequence(),
    };
    inspect_package_with_context(config.package().root(), &context)
        .map_err(RuntimePackageInspectionError::Package)
}

/// Verify exactly the package selected by one runtime configuration as a
/// database-active predecessor for successor planning. This preserves signed
/// predecessor bytes without requiring the current compiler to rederive old
/// generated artifacts.
pub(crate) fn inspect_runtime_predecessor_package(
    runtime_config: &Path,
) -> Result<VerifiedPredecessorPackage, RuntimePackageInspectionError> {
    let config = load_predecessor_runtime_config(runtime_config)?;
    load_predecessor_package(config.package().root(), &predecessor_context(&config))
        .map_err(RuntimePackageInspectionError::Package)
}

/// Verify the same predecessor package as [`inspect_runtime_predecessor_package`]
/// and compile its signed sources with the current compiler, so a successor
/// can be rehearsed over the predecessor schema.
pub(crate) fn inspect_runtime_predecessor_rehearsal_baseline(
    runtime_config: &Path,
) -> Result<(VerifiedPredecessorPackage, CompiledRegistry), RuntimePackageInspectionError> {
    let config = load_predecessor_runtime_config(runtime_config)?;
    load_predecessor_rehearsal_baseline(config.package().root(), &predecessor_context(&config))
        .map_err(RuntimePackageInspectionError::Package)
}

fn load_predecessor_runtime_config(
    runtime_config: &Path,
) -> Result<RuntimeConfig, RuntimePackageInspectionError> {
    if !runtime_config.is_absolute() {
        return Err(RuntimePackageInspectionError::RuntimeConfigPath);
    }
    let config = load_runtime_config(runtime_config)
        .map_err(RuntimePackageInspectionError::RuntimeConfig)?;
    config
        .verify_package_envelope()
        .map_err(|error| RuntimePackageInspectionError::SharedPackage(error.to_string()))?;
    Ok(config)
}

fn predecessor_context(config: &RuntimeConfig) -> PredecessorPackageContext<'_> {
    PredecessorPackageContext {
        environment: config.identity().environment(),
        instance_id: config.identity().instance_id(),
        database_id: config.identity().database_id(),
        database_initialization_environment: config
            .identity()
            .database_initialization_environment(),
        trust_anchor: config.package_trust_anchor(),
        expected_package_revision: config.package().active_revision(),
        expected_sequence: config.package().active_sequence(),
    }
}
