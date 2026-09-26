// SPDX-License-Identifier: Apache-2.0
//! Authority-preserving Registry package activation.

use std::path::{Path, PathBuf};

use registry_breg::field_encryption::FieldEncryptionProvider;
use registry_breg::migration::{
    apply_verified_package, confirm_active_package, AppliedFieldEncryptionKeySource,
    ApplyPrecondition, ApplyRoles, ApplyTimeouts, ApplyVerifiedPackageRequest,
    DestructiveBackupEvidence, MigrationError,
};
use registry_breg::package::{
    load_package, load_predecessor_package, PackageError, PackageIntent, PackageLoadContext,
    PredecessorPackageContext, VerifiedPredecessorPackage,
};
use registry_breg::postgres::ExpectedRegistryIdentity;
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};

#[derive(Debug)]
pub(crate) enum ApplyLifecycleError {
    RuntimeConfigPath,
    RuntimeConfig(RuntimeConfigError),
    TargetPackagePath,
    CurrentPackage(PackageError),
    TargetPackage(PackageError),
    EventDestinations,
    FieldEncryptionConfiguration,
    FieldEncryptionCustody,
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
    pub acknowledge_retired_audit_discard: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyLifecycleActivation {
    Initial,
    Successor,
    AlreadyActive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplyLifecycleOutcome {
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub package_sequence: i64,
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

    let current_package = if request.initial {
        None
    } else {
        Some(
            load_predecessor_package(
                config.package().root(),
                &PredecessorPackageContext {
                    environment: config.identity().environment(),
                    instance_id: config.identity().instance_id(),
                    database_id: config.identity().database_id(),
                    database_initialization_environment: config
                        .identity()
                        .database_initialization_environment(),
                    trust_anchor: config.package_trust_anchor(),
                    expected_package_revision: config.package().active_revision(),
                    expected_sequence: config.package().active_sequence(),
                },
            )
            .map_err(ApplyLifecycleError::CurrentPackage)?,
        )
    };
    let current_identity = current_package
        .as_ref()
        .map(expected_identity)
        .transpose()?;
    let current_history_descriptor = current_package
        .as_ref()
        .map(VerifiedPredecessorPackage::history_schema_descriptor);
    let target_intent = match current_identity.as_ref() {
        Some(current) => PackageIntent::Activation {
            active_revision: &current.package_revision,
            active_sequence: u64::try_from(current.package_sequence)
                .map_err(|_| ApplyLifecycleError::TargetPackage(PackageError::Binding))?,
        },
        None => PackageIntent::InitialActivation,
    };
    let target = match load_package(request.package, &target_context(&config, target_intent)) {
        Err(PackageError::AlreadyActive) => {
            return confirm_already_active(&config, request.package)
        }
        loaded => loaded.map_err(ApplyLifecycleError::TargetPackage)?,
    };
    if request.initial
        && (target.manifest().package_revision != config.package().active_revision()
            || target.manifest().sequence != config.package().active_sequence()
            || target.manifest().sequence != 1)
    {
        return Err(ApplyLifecycleError::TargetPackage(PackageError::Binding));
    }
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
        precondition,
        ApplyRoles::new(
            config.database().roles().migration(),
            config.database().roles().runtime(),
        ),
        timeouts,
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
        activation: if request.initial {
            ApplyLifecycleActivation::Initial
        } else {
            ApplyLifecycleActivation::Successor
        },
    })
}

fn target_context<'a>(
    config: &'a RuntimeConfig,
    intent: PackageIntent<'a>,
) -> PackageLoadContext<'a> {
    PackageLoadContext {
        environment: config.identity().environment(),
        instance_id: config.identity().instance_id(),
        database_id: config.identity().database_id(),
        database_initialization_environment: config
            .identity()
            .database_initialization_environment(),
        compiler_source_revision: config.package().compiler_source_revision(),
        trust_anchor: config.package_trust_anchor(),
        intent,
    }
}

/// Re-presenting the active package is a no-op, so repeated deploys stay
/// idempotent. The activation load only routed here from an unverified
/// manifest claim; the target is then verified in full as the configured
/// active package, and the database must record that exact identity as active
/// and ready. Nothing is written.
fn confirm_already_active(
    config: &RuntimeConfig,
    package: &Path,
) -> Result<ApplyLifecycleOutcome, ApplyLifecycleError> {
    let target = load_package(
        package,
        &target_context(
            config,
            PackageIntent::Startup {
                active_revision: config.package().active_revision(),
                active_sequence: config.package().active_sequence(),
            },
        ),
    )
    .map_err(ApplyLifecycleError::TargetPackage)?;
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
    let confirmed = runtime
        .block_on(confirm_active_package(
            &connection,
            &target,
            config.database().roles().migration(),
            timeouts,
        ))
        .map_err(ApplyLifecycleError::Apply)?;
    Ok(ApplyLifecycleOutcome {
        package_revision: confirmed.package_revision,
        schema_fingerprint: confirmed.schema_fingerprint,
        package_sequence: confirmed.package_sequence,
        activation: ApplyLifecycleActivation::AlreadyActive,
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

fn expected_identity(
    package: &VerifiedPredecessorPackage,
) -> Result<ExpectedRegistryIdentity, ApplyLifecycleError> {
    Ok(ExpectedRegistryIdentity {
        package_id: package.package_id().to_owned(),
        environment: package.environment().to_owned(),
        instance_id: package.instance_id().to_owned(),
        database_id: package.database_id().to_owned(),
        package_revision: package.package_revision().to_owned(),
        schema_fingerprint: package.schema_fingerprint().to_owned(),
        package_sequence: i64::try_from(package.sequence())
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
