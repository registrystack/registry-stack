// SPDX-License-Identifier: Apache-2.0
//! Authority-preserving Registry package activation.

use std::path::{Path, PathBuf};

use registry_breg::audit::RegistryAudit;
use registry_breg::field_encryption::FieldEncryptionProvider;
use registry_breg::migration::{
    apply_verified_package, bind_active_package, read_recorded_registry_state,
    successor_plan_is_empty, ActivationDeployment, AppliedFieldEncryptionKeySource,
    ApplyPrecondition, ApplyRoles, ApplyTimeouts, ApplyVerifiedPackageRequest,
    DestructiveBackupEvidence, MigrationError,
};
use registry_breg::package::{load_package, PackageError, VerifiedPredecessorPackage};
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfigError};

#[derive(Debug)]
pub(crate) enum ApplyLifecycleError {
    RuntimeConfigPath,
    RuntimeConfig(RuntimeConfigError),
    TargetPackagePath,
    CurrentPackage(PackageError),
    TargetPackage(PackageError),
    Uninitialized,
    EventDestinations,
    FieldEncryptionConfiguration,
    FieldEncryptionCustody,
    DatabaseConfiguration,
    TimeoutConfiguration,
    BackupArgument,
    Runtime,
    Audit,
    Apply(MigrationError),
}

pub(crate) struct ApplyLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub package: &'a Path,
    pub initial: bool,
    pub backups: &'a [String],
    pub acknowledge_retired_audit_discard: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyLifecycleActivation {
    Initial,
    Successor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplyLifecycleOutcome {
    pub package_digest: String,
    pub schema_fingerprint: String,
    pub activation_id: String,
    pub activation: ApplyLifecycleActivation,
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
    let config =
        load_runtime_config(request.runtime_config).map_err(ApplyLifecycleError::RuntimeConfig)?;

    let target = load_package(request.package, &config.package_load_context())
        .map_err(ApplyLifecycleError::TargetPackage)?;
    let identity = config.identity();
    let deployment = ActivationDeployment::new(
        identity.environment(),
        identity.instance_id(),
        identity.database_id(),
    );
    // Everything the package and the runtime file decide is checked before
    // any database authority is resolved.
    let current_package = if request.initial {
        None
    } else {
        // An empty successor plan is a property of the package alone.
        if successor_plan_is_empty(&target) {
            return Err(ApplyLifecycleError::Apply(MigrationError::EmptyPlan));
        }
        Some(
            config
                .load_active_predecessor_package()
                .map_err(ApplyLifecycleError::CurrentPackage)?,
        )
    };
    let current_history_descriptor = current_package
        .as_ref()
        .map(VerifiedPredecessorPackage::history_schema_descriptor);
    let declares_encrypted_fields = target.registry().entities().values().any(|entity| {
        entity
            .fields
            .values()
            .any(|field| field.encryption.is_some())
    });
    let field_encryption_provider = if declares_encrypted_fields {
        let provider = config
            .field_encryption()
            .provider()
            .ok_or(ApplyLifecycleError::FieldEncryptionConfiguration)?;
        validate_field_encryption_custody(
            provider,
            config.identity().database_initialization_environment(),
        )?;
        Some(provider)
    } else {
        None
    };
    let field_encryption_secrets = field_encryption_provider
        .map(|_| config.secret_resolver())
        .transpose()
        .map_err(|_| ApplyLifecycleError::FieldEncryptionConfiguration)?;
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ApplyLifecycleError::Runtime)?;

    // A package carries no place in the apply order, so a successor is bound
    // to what the database records: the active package digest, and the
    // configured active package that must be that exact package.
    let current_identity = match current_package.as_ref() {
        None => None,
        Some(current_package) => {
            let recorded = runtime
                .block_on(read_recorded_registry_state(
                    &connection,
                    &target.manifest().package_id,
                    config.database().roles().migration(),
                    timeouts,
                ))
                .map_err(ApplyLifecycleError::Apply)?
                .ok_or(ApplyLifecycleError::Uninitialized)?;
            if target.package_digest() == recorded.identity.package_digest {
                return Err(ApplyLifecycleError::Apply(MigrationError::AlreadyActive));
            }
            bind_active_package(
                &recorded.identity,
                current_package.package_digest(),
                deployment,
            )
            .map_err(ApplyLifecycleError::Apply)?;
            Some(recorded.identity)
        }
    };

    let audit = runtime
        .block_on(RegistryAudit::open_companion(&config))
        .map_err(|_| ApplyLifecycleError::Audit)?;
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
    let mut apply = ApplyVerifiedPackageRequest::new(
        &connection,
        &target,
        deployment,
        precondition,
        ApplyRoles::new(
            config.database().roles().migration(),
            config.database().roles().runtime(),
        ),
        timeouts,
        audit,
    )
    .with_destructive_backup_evidence(&backup_evidence)
    .with_event_destination_compatibility_inventory(&event_destination_compatibility)
    .with_acknowledge_retired_audit_discard(request.acknowledge_retired_audit_discard);
    if let Some(package) = current_package.as_ref() {
        apply = apply.with_predecessor_migration_baseline(package.migration_baseline());
    }
    if let Some(descriptor) = current_history_descriptor.as_ref() {
        apply = apply.with_predecessor_history_descriptor(descriptor);
    }
    if let (Some(provider), Some(secrets)) =
        (field_encryption_provider, field_encryption_secrets.as_ref())
    {
        apply = apply.with_field_encryption_key_source(AppliedFieldEncryptionKeySource::new(
            provider, secrets,
        ));
    }
    let activated = runtime
        .block_on(apply_verified_package(apply))
        .map_err(ApplyLifecycleError::Apply)?;
    Ok(ApplyLifecycleOutcome {
        package_digest: activated.package_digest,
        schema_fingerprint: activated.schema_fingerprint,
        activation_id: activated.activation_id,
        activation: if request.initial {
            ApplyLifecycleActivation::Initial
        } else {
            ApplyLifecycleActivation::Successor
        },
    })
}

fn validate_field_encryption_custody(
    provider: &FieldEncryptionProvider,
    database_initialization_environment: &str,
) -> Result<(), ApplyLifecycleError> {
    validate_field_encryption_custody_kind(
        matches!(provider, FieldEncryptionProvider::LocalFile { .. }),
        database_initialization_environment,
    )
}

fn validate_field_encryption_custody_kind(
    local_file: bool,
    database_initialization_environment: &str,
) -> Result<(), ApplyLifecycleError> {
    if local_file && database_initialization_environment != "local" {
        return Err(ApplyLifecycleError::FieldEncryptionCustody);
    }
    Ok(())
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

    #[test]
    fn plaintext_field_key_custody_is_local_only_during_apply() {
        assert!(validate_field_encryption_custody_kind(true, "local").is_ok());
        assert!(matches!(
            validate_field_encryption_custody_kind(true, "production"),
            Err(ApplyLifecycleError::FieldEncryptionCustody)
        ));
        assert!(validate_field_encryption_custody_kind(false, "production").is_ok());
    }
}
