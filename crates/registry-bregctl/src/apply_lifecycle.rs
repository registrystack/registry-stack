// SPDX-License-Identifier: Apache-2.0
//! Authority-preserving Registry package activation.

use std::path::{Path, PathBuf};

use registry_breg::audit::RegistryAudit;
use registry_breg::field_encryption::FieldEncryptionProvider;
use registry_breg::migration::{
    apply_verified_package, bind_active_package, operator_reference_is_well_formed,
    plan_verified_package, read_activation_status, read_recorded_registry_state,
    successor_plan_is_empty, ActivationDeployment, ActivationPlan, ActivationStatus,
    AppliedFieldEncryptionKeySource, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, DestructiveBackupEvidence, MigrationError, RecordedRegistryState,
};
use registry_breg::package::{
    load_package, MigrationInspectionSummary, PackageError, VerifiedPredecessorPackage,
};
use registry_breg::postgres::ConnectionConfig;
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};

#[derive(Debug)]
pub(crate) enum ApplyLifecycleError {
    RuntimeConfigPath,
    RuntimeConfig(RuntimeConfigError),
    TargetPackagePath,
    CurrentPackage(PackageError),
    TargetPackage(PackageError),
    /// The target package is not the one `--expected-digest` names. Both
    /// values are package digests, which are identities and not secrets.
    PackageDigestMismatch {
        expected: String,
        found: String,
    },
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

/// Whether the lifecycle activates the package or only runs the checks an
/// activation runs, writing nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleMode {
    Apply,
    Plan,
}

pub(crate) struct ApplyLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub package: &'a Path,
    pub initial: bool,
    pub backups: &'a [String],
    pub acknowledge_retired_audit_discard: bool,
    pub operator_reference: Option<&'a str>,
    pub expected_digest: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyLifecycleActivation {
    Initial,
    Successor,
    RoleChange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplyLifecycleOutcome {
    pub package_digest: String,
    pub schema_fingerprint: String,
    pub activation_id: String,
    pub activation: ApplyLifecycleActivation,
}

/// What `bregctl plan` reports: the activation `bregctl apply` would make,
/// after the checks it runs passed and were rolled back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlanLifecycleOutcome {
    pub package_digest: String,
    pub registry_revision: String,
    pub active_package_digest: Option<String>,
    pub plan: ActivationPlan,
    pub migration: MigrationInspectionSummary,
}

pub(crate) struct PlanLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub package: &'a Path,
    pub backups: &'a [String],
    pub expected_digest: Option<&'a str>,
}

pub(crate) fn run(
    request: ApplyLifecycleRequest<'_>,
) -> Result<ApplyLifecycleOutcome, ApplyLifecycleError> {
    match execute(request, LifecycleMode::Apply)? {
        Executed::Applied(outcome) => Ok(outcome),
        Executed::Planned(_) => Err(ApplyLifecycleError::Apply(MigrationError::ApplyFailed)),
    }
}

/// Runs every check `run` would for the same package and runtime
/// configuration, including the database checks inside transactions it rolls
/// back, and writes nothing: no ledger entry, no maintenance state, and no
/// audit entry. It holds the apply lock while it checks, as an apply would.
pub(crate) fn plan(
    request: PlanLifecycleRequest<'_>,
) -> Result<PlanLifecycleOutcome, ApplyLifecycleError> {
    match execute(
        ApplyLifecycleRequest {
            runtime_config: request.runtime_config,
            package: request.package,
            initial: false,
            backups: request.backups,
            acknowledge_retired_audit_discard: false,
            operator_reference: None,
            expected_digest: request.expected_digest,
        },
        LifecycleMode::Plan,
    )? {
        Executed::Planned(outcome) => Ok(outcome),
        Executed::Applied(_) => Err(ApplyLifecycleError::Apply(MigrationError::ApplyFailed)),
    }
}

/// Reads what the database records about its activations, as the migration
/// role, without the apply lock. `None` means it was never activated.
pub(crate) fn status(
    runtime_config: &Path,
) -> Result<Option<ActivationStatus>, ApplyLifecycleError> {
    if !runtime_config.is_absolute() {
        return Err(ApplyLifecycleError::RuntimeConfigPath);
    }
    let config = load_runtime_config(runtime_config).map_err(ApplyLifecycleError::RuntimeConfig)?;
    let access = DatabaseAccess::resolve(&config)?;
    access
        .runtime
        .block_on(read_activation_status(
            &access.connection,
            config.database().roles().migration(),
            access.timeouts,
        ))
        .map_err(ApplyLifecycleError::Apply)
}

enum Executed {
    Applied(ApplyLifecycleOutcome),
    Planned(PlanLifecycleOutcome),
}

struct DatabaseAccess {
    connection: ConnectionConfig,
    timeouts: ApplyTimeouts,
    runtime: tokio::runtime::Runtime,
}

impl DatabaseAccess {
    fn resolve(config: &RuntimeConfig) -> Result<Self, ApplyLifecycleError> {
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
        Ok(Self {
            connection,
            timeouts,
            runtime,
        })
    }
}

/// Whether a plan reports the package as the database's first activation:
/// the database was never activated, or its initial activation is
/// unfinished, which the next `apply --initial` resumes.
fn plans_initial_activation(
    recorded: Result<Option<RecordedRegistryState>, MigrationError>,
) -> Result<bool, ApplyLifecycleError> {
    match recorded {
        Ok(None) => Ok(true),
        Ok(Some(recorded)) => Ok(!recorded.activation_applied),
        Err(error) => Err(ApplyLifecycleError::Apply(error)),
    }
}

fn execute(
    request: ApplyLifecycleRequest<'_>,
    mode: LifecycleMode,
) -> Result<Executed, ApplyLifecycleError> {
    if !request.runtime_config.is_absolute() {
        return Err(ApplyLifecycleError::RuntimeConfigPath);
    }
    if !request.package.is_absolute() {
        return Err(ApplyLifecycleError::TargetPackagePath);
    }
    let backup_arguments = parse_backup_arguments(request.backups)?;
    if request
        .operator_reference
        .is_some_and(|reference| !operator_reference_is_well_formed(reference))
    {
        return Err(ApplyLifecycleError::Apply(
            MigrationError::OperatorReference,
        ));
    }
    let config =
        load_runtime_config(request.runtime_config).map_err(ApplyLifecycleError::RuntimeConfig)?;

    let target = load_package(request.package, &config.package_load_context())
        .map_err(ApplyLifecycleError::TargetPackage)?;
    // The operator's reviewed digest binds the command to one package before
    // any database authority is resolved, so a mismatch changes nothing.
    if let Some(expected) = request.expected_digest {
        if expected != target.package_digest() {
            return Err(ApplyLifecycleError::PackageDigestMismatch {
                expected: expected.to_owned(),
                found: target.package_digest().to_owned(),
            });
        }
    }
    let identity = config.identity();
    let deployment = ActivationDeployment::new(
        identity.environment(),
        identity.instance_id(),
        identity.database_id(),
    );
    // A plan learns from the database whether the package would be the first,
    // so it resolves database authority first; an apply is told by --initial
    // and checks everything the package and the runtime file decide before
    // any database authority is resolved.
    let mut access = None;
    let initial = match mode {
        LifecycleMode::Apply => request.initial,
        LifecycleMode::Plan => {
            let resolved = DatabaseAccess::resolve(&config)?;
            let recorded = resolved.runtime.block_on(read_recorded_registry_state(
                &resolved.connection,
                &target.manifest().package_id,
                config.database().roles().migration(),
                resolved.timeouts,
            ));
            let initial = plans_initial_activation(recorded)?;
            access = Some(resolved);
            initial
        }
    };
    let current_package = if initial {
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

    let DatabaseAccess {
        connection,
        timeouts,
        runtime,
    } = match access {
        Some(access) => access,
        None => DatabaseAccess::resolve(&config)?,
    };

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
            bind_active_package(
                &recorded.identity,
                current_package.package_digest(),
                deployment,
            )
            .map_err(ApplyLifecycleError::Apply)?;
            Some(recorded.identity)
        }
    };

    // A plan appends no audit entry, so it never opens the audit destination.
    let audit = match mode {
        LifecycleMode::Apply => Some(
            runtime
                .block_on(RegistryAudit::open_companion(&config))
                .map_err(|_| ApplyLifecycleError::Audit)?,
        ),
        LifecycleMode::Plan => None,
    };
    let backup_evidence = backup_arguments
        .iter()
        .map(|backup| {
            DestructiveBackupEvidence::new(backup.binding_path.as_str(), &backup.local_path)
        })
        .collect::<Vec<_>>();
    // Applying the active package again is a role change: the library
    // refuses it as already active when the configured roles are the ones
    // the active activation serves with.
    let role_change = current_identity
        .as_ref()
        .is_some_and(|current| current.package_digest == target.package_digest());
    let precondition = match current_identity.as_ref() {
        None => ApplyPrecondition::InitialActivation,
        Some(current) if role_change => ApplyPrecondition::RoleChange { current },
        Some(current) => ApplyPrecondition::Successor { current },
    };
    let roles = ApplyRoles::new(
        config.database().roles().migration(),
        config.database().roles().runtime(),
    );
    let mut apply = match audit {
        Some(audit) => ApplyVerifiedPackageRequest::new(
            &connection,
            &target,
            deployment,
            precondition,
            roles,
            timeouts,
            audit,
        ),
        None => ApplyVerifiedPackageRequest::plan(
            &connection,
            &target,
            deployment,
            precondition,
            roles,
            timeouts,
        ),
    }
    .with_destructive_backup_evidence(&backup_evidence)
    .with_event_destination_compatibility_inventory(&event_destination_compatibility)
    .with_acknowledge_retired_audit_discard(request.acknowledge_retired_audit_discard);
    if let Some(reference) = request.operator_reference {
        apply = apply.with_operator_reference(reference);
    }
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
    if mode == LifecycleMode::Plan {
        let plan = runtime
            .block_on(plan_verified_package(apply))
            .map_err(ApplyLifecycleError::Apply)?;
        let migration = target
            .migration_summary()
            .map_err(ApplyLifecycleError::TargetPackage)?;
        return Ok(Executed::Planned(PlanLifecycleOutcome {
            package_digest: target.package_digest().to_owned(),
            registry_revision: target.registry().revision().to_owned(),
            active_package_digest: current_identity.map(|current| current.package_digest),
            plan,
            migration,
        }));
    }
    let activated = runtime
        .block_on(apply_verified_package(apply))
        .map_err(ApplyLifecycleError::Apply)?;
    Ok(Executed::Applied(ApplyLifecycleOutcome {
        package_digest: activated.package_digest,
        schema_fingerprint: activated.schema_fingerprint,
        activation_id: activated.activation_id,
        activation: if initial {
            ApplyLifecycleActivation::Initial
        } else if role_change {
            ApplyLifecycleActivation::RoleChange
        } else {
            ApplyLifecycleActivation::Successor
        },
    }))
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
    fn a_plan_is_initial_until_the_ledger_records_an_applied_activation() {
        let recorded = |activation_applied| {
            Ok(Some(RecordedRegistryState {
                identity: registry_breg::postgres::ExpectedRegistryIdentity {
                    package_id: "registry".to_owned(),
                    database_id: "database".to_owned(),
                    package_digest: "sha256:package".to_owned(),
                    activation_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                    schema_fingerprint: "sha256:schema".to_owned(),
                },
                ready: false,
                activation_applied,
            }))
        };
        assert!(plans_initial_activation(Ok(None)).expect("never activated"));
        assert!(plans_initial_activation(recorded(false)).expect("unfinished initial"));
        assert!(!plans_initial_activation(recorded(true)).expect("activated"));
        assert!(matches!(
            plans_initial_activation(Err(MigrationError::UnrecognizedDatabase)),
            Err(ApplyLifecycleError::Apply(
                MigrationError::UnrecognizedDatabase
            ))
        ));
        assert!(matches!(
            plans_initial_activation(Err(MigrationError::ApplyFailed)),
            Err(ApplyLifecycleError::Apply(MigrationError::ApplyFailed))
        ));
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
