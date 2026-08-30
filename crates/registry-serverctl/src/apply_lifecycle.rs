// SPDX-License-Identifier: Apache-2.0
//! Authority-preserving Registry package activation.

use std::path::{Path, PathBuf};

use registry_server::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, DestructiveBackupEvidence, MigrationError,
};
use registry_server::package::{
    load_package, PackageError, PackageIntent, PackageLoadContext, VerifiedPackage,
};
use registry_server::postgres::ExpectedRegistryIdentity;
use registry_server::runtime_config::{load_runtime_config, RuntimeConfigError};

#[derive(Debug)]
pub(crate) enum ApplyLifecycleError {
    RuntimeConfigPath,
    RuntimeConfig,
    TargetPackagePath,
    CurrentPackage(PackageError),
    TargetPackage(PackageError),
    EventDestinations,
    DatabaseConfiguration,
    TimeoutConfiguration,
    BackupArgument,
    Runtime,
    Apply(MigrationError),
}

pub(crate) struct ApplyLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub package: &'a Path,
    pub initial: bool,
    pub backups: &'a [String],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplyLifecycleOutcome {
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub package_sequence: i64,
    pub initial: bool,
}

pub(crate) fn run(
    request: ApplyLifecycleRequest<'_>,
) -> Result<ApplyLifecycleOutcome, ApplyLifecycleError> {
    if !request.runtime_config.is_absolute() {
        return Err(ApplyLifecycleError::RuntimeConfigPath);
    }
    if !request.package.is_absolute() {
        return Err(ApplyLifecycleError::TargetPackagePath);
    }
    let backup_arguments = parse_backup_arguments(request.backups)?;
    let config = load_runtime_config(request.runtime_config)
        .map_err(|_error: RuntimeConfigError| ApplyLifecycleError::RuntimeConfig)?;

    let current_package = if request.initial {
        None
    } else {
        Some(
            load_package(config.package().root(), &config.package_load_context())
                .map_err(ApplyLifecycleError::CurrentPackage)?,
        )
    };
    let current_identity = current_package
        .as_ref()
        .map(expected_identity)
        .transpose()?;
    let target_intent = match current_identity.as_ref() {
        Some(current) => PackageIntent::Activation {
            active_revision: &current.package_revision,
            active_sequence: u64::try_from(current.package_sequence)
                .map_err(|_| ApplyLifecycleError::TargetPackage(PackageError::Binding))?,
        },
        None => PackageIntent::InitialActivation,
    };
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
            intent: target_intent,
        },
    )
    .map_err(ApplyLifecycleError::TargetPackage)?;
    if request.initial
        && (target.manifest().package_revision != config.package().active_revision()
            || target.manifest().sequence != config.package().active_sequence()
            || target.manifest().sequence != 1)
    {
        return Err(ApplyLifecycleError::TargetPackage(PackageError::Binding));
    }
    let activated_event_destinations = config
        .activate_event_destinations(target.registry())
        .map_err(|_| ApplyLifecycleError::EventDestinations)?;
    let event_destination_compatibility = activated_event_destinations.compatibility_inventory();

    let connection = config
        .migration_database_connection_config()
        .map_err(|_| ApplyLifecycleError::DatabaseConfiguration)?;
    let timeouts = ApplyTimeouts::new(
        config.operational_timeouts().migration_lock,
        config.operational_timeouts().migration_statement,
    )
    .map_err(|_| ApplyLifecycleError::TimeoutConfiguration)?;
    let backup_evidence = backup_arguments
        .iter()
        .map(|backup| {
            DestructiveBackupEvidence::new(backup.binding_path.as_str(), &backup.local_path)
        })
        .collect::<Vec<_>>();
    let precondition = current_identity
        .as_ref()
        .map_or(ApplyPrecondition::InitialActivation, |current| {
            ApplyPrecondition::Successor { current }
        });
    let apply = ApplyVerifiedPackageRequest::new(
        &connection,
        &target,
        precondition,
        ApplyRoles::new(
            config.database().roles().migration(),
            config.database().roles().runtime(),
        ),
        timeouts,
    )
    .with_destructive_backup_evidence(&backup_evidence)
    .with_event_destination_compatibility_inventory(&event_destination_compatibility);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ApplyLifecycleError::Runtime)?;
    let activated = runtime
        .block_on(apply_verified_package(apply))
        .map_err(ApplyLifecycleError::Apply)?;
    Ok(ApplyLifecycleOutcome {
        package_revision: activated.package_revision,
        schema_fingerprint: activated.schema_fingerprint,
        package_sequence: activated.package_sequence,
        initial: request.initial,
    })
}

fn expected_identity(
    package: &VerifiedPackage,
) -> Result<ExpectedRegistryIdentity, ApplyLifecycleError> {
    let manifest = package.manifest();
    Ok(ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        environment: manifest.environment.clone(),
        instance_id: manifest.instance_id.clone(),
        database_id: manifest.database_id.clone(),
        package_revision: manifest.package_revision.clone(),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
        package_sequence: i64::try_from(manifest.sequence)
            .map_err(|_| ApplyLifecycleError::CurrentPackage(PackageError::Binding))?,
    })
}

struct BackupArgument {
    binding_path: String,
    local_path: PathBuf,
}

fn parse_backup_arguments(values: &[String]) -> Result<Vec<BackupArgument>, ApplyLifecycleError> {
    values
        .iter()
        .map(|value| {
            let (binding_path, local_path) = value
                .split_once('=')
                .ok_or(ApplyLifecycleError::BackupArgument)?;
            let local_path = PathBuf::from(local_path);
            if binding_path.is_empty()
                || binding_path.starts_with('/')
                || binding_path.contains("..")
                || !local_path.is_absolute()
            {
                return Err(ApplyLifecycleError::BackupArgument);
            }
            Ok(BackupArgument {
                binding_path: binding_path.to_owned(),
                local_path,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_arguments_are_closed_and_require_an_absolute_local_file() {
        let parsed = parse_backup_arguments(&["migrations/backup.json=/tmp/backup.bin".to_owned()])
            .expect("one closed backup binding parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].binding_path, "migrations/backup.json");
        assert_eq!(parsed[0].local_path, Path::new("/tmp/backup.bin"));

        for refused in [
            "migrations/backup.json",
            "../backup.json=/tmp/backup.bin",
            "/backup.json=/tmp/backup.bin",
            "migrations/backup.json=relative.bin",
        ] {
            assert!(parse_backup_arguments(&[refused.to_owned()]).is_err());
        }
    }
}
