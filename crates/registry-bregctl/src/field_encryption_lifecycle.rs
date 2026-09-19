// SPDX-License-Identifier: Apache-2.0
//! Operator lifecycle around a reviewed field-encryption backfill.
//!
//! Two commands use this module, both exposed as maintenance tooling. The
//! preflight loads the same predecessor and successor packages an apply would
//! bind and delegates every read to `registry_breg::field_encryption_backfill`
//! against the configured migration connection, changing nothing. The
//! erase-history command runs only after the flip's package is active: the
//! runtime configuration names that active package, and the engine path pins
//! it before any erasure. Both open only the configured migration connection
//! and report counts and authored identifiers, never field values.

use std::fs::File;
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use registry_breg::field_encryption_backfill::{
    erase_field_encryption_history_with_connection,
    preflight_field_encryption_backfill_with_connection, FieldEncryptionBackfillPreflightError,
    FieldEncryptionBackfillPreflightReport, FieldEncryptionBackfillPreflightRequest,
    FieldEncryptionBackfillTimeouts, FieldEncryptionHistoryErasureError,
    FieldEncryptionHistoryErasureOutcome, FieldEncryptionHistoryErasureRequest,
};
use registry_breg::migration_plan::ReviewedMigrationStepDescriptor;
use registry_breg::package::{
    load_package, load_predecessor_package, PackageError, PackageIntent, PackageLoadContext,
    PredecessorPackageContext, VerifiedPredecessorPackage,
};
use registry_breg::postgres::{ExpectedRegistryIdentity, RegistryLockKey};
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfigError};
use registry_platform_canonical_json::parse_json_strict;
use serde::{Deserialize, Serialize};

use crate::safe_path::SafeEntry;

const MAX_ERASE_REQUEST_BYTES: u64 = 16 * 1024;

#[derive(Debug)]
pub(crate) enum FieldEncryptionPreflightLifecycleError {
    RuntimeConfigPath,
    PackagePath,
    NoBackfillSteps,
    RuntimeConfig(RuntimeConfigError),
    PredecessorPackage(PackageError),
    TargetPackage(PackageError),
    DatabaseConfiguration,
    TimeoutConfiguration,
    Runtime,
    Preflight(FieldEncryptionBackfillPreflightError),
}

pub(crate) struct FieldEncryptionPreflightLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub package: &'a Path,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FieldEncryptionPreflightLifecycleOutcome {
    pub package_revision: String,
    #[serde(flatten)]
    pub report: FieldEncryptionBackfillPreflightReport,
}

pub(crate) fn run_preflight(
    request: FieldEncryptionPreflightLifecycleRequest<'_>,
) -> Result<FieldEncryptionPreflightLifecycleOutcome, FieldEncryptionPreflightLifecycleError> {
    if !request.runtime_config.is_absolute() {
        return Err(FieldEncryptionPreflightLifecycleError::RuntimeConfigPath);
    }
    if !request.package.is_absolute() {
        return Err(FieldEncryptionPreflightLifecycleError::PackagePath);
    }
    let config = load_runtime_config(request.runtime_config)
        .map_err(FieldEncryptionPreflightLifecycleError::RuntimeConfig)?;
    // The counts are only meaningful against the state the apply would start
    // from, so bind the same predecessor an apply binds and let the engine pin
    // the database to it.
    let predecessor = load_predecessor_package(
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
    .map_err(FieldEncryptionPreflightLifecycleError::PredecessorPackage)?;
    let expected = predecessor_identity(&predecessor)?;
    let target_intent = PackageIntent::Activation {
        active_revision: &expected.package_revision,
        active_sequence: u64::try_from(expected.package_sequence).map_err(|_| {
            FieldEncryptionPreflightLifecycleError::PredecessorPackage(PackageError::Binding)
        })?,
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
    .map_err(FieldEncryptionPreflightLifecycleError::TargetPackage)?;
    let plan = target
        .reviewed_migration_plan()
        .ok_or(FieldEncryptionPreflightLifecycleError::NoBackfillSteps)?;
    if !plan.migrations().iter().any(|migration| {
        migration.steps.iter().any(|step| {
            matches!(
                step.descriptor,
                ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { .. }
            )
        })
    }) {
        return Err(FieldEncryptionPreflightLifecycleError::NoBackfillSteps);
    }
    let connection = config
        .migration_database_connection_config()
        .map_err(|_| FieldEncryptionPreflightLifecycleError::DatabaseConfiguration)?;
    let timeouts = FieldEncryptionBackfillTimeouts::new(
        bounded_timeout(config.operational_timeouts().migration_lock)?,
        bounded_timeout(config.operational_timeouts().migration_statement)?,
    )
    .map_err(|_| FieldEncryptionPreflightLifecycleError::TimeoutConfiguration)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| FieldEncryptionPreflightLifecycleError::Runtime)?;
    let report = runtime
        .block_on(preflight_field_encryption_backfill_with_connection(
            &connection,
            FieldEncryptionBackfillPreflightRequest {
                expected: &expected,
                migration_role: config.database().roles().migration(),
                timeouts,
                registry: target.registry(),
                plan,
                predecessor_baseline: Some(predecessor.migration_baseline()),
                target_package_revision: target.manifest().package_revision.as_str(),
            },
        ))
        .map_err(FieldEncryptionPreflightLifecycleError::Preflight)?;
    Ok(FieldEncryptionPreflightLifecycleOutcome {
        package_revision: target.manifest().package_revision.clone(),
        report,
    })
}

#[derive(Debug)]
pub(crate) enum FieldEncryptionEraseHistoryLifecycleError {
    RuntimeConfigPath,
    RequestFile,
    RequestDocument,
    RuntimeConfig(RuntimeConfigError),
    ActivePackage(PackageError),
    DatabaseConfiguration,
    TimeoutConfiguration,
    Runtime,
    Erase(FieldEncryptionHistoryErasureError),
}

pub(crate) struct FieldEncryptionEraseHistoryLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub request_file: &'a Path,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FieldEncryptionEraseHistoryLifecycleOutcome {
    pub package_revision: String,
    #[serde(flatten)]
    pub outcome: FieldEncryptionHistoryErasureOutcome,
}

pub(crate) fn run_erase_history(
    request: FieldEncryptionEraseHistoryLifecycleRequest<'_>,
) -> Result<FieldEncryptionEraseHistoryLifecycleOutcome, FieldEncryptionEraseHistoryLifecycleError>
{
    if !request.runtime_config.is_absolute() {
        return Err(FieldEncryptionEraseHistoryLifecycleError::RuntimeConfigPath);
    }
    let erase = load_erase_request(request.request_file)?;
    let config = load_runtime_config(request.runtime_config)
        .map_err(FieldEncryptionEraseHistoryLifecycleError::RuntimeConfig)?;
    let package = load_package(config.package().root(), &config.package_load_context())
        .map_err(FieldEncryptionEraseHistoryLifecycleError::ActivePackage)?;
    let manifest = package.manifest();
    let package_sequence = i64::try_from(manifest.sequence).map_err(|_| {
        FieldEncryptionEraseHistoryLifecycleError::ActivePackage(PackageError::Binding)
    })?;
    let expected = ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        environment: manifest.environment.clone(),
        instance_id: manifest.instance_id.clone(),
        database_id: manifest.database_id.clone(),
        package_revision: manifest.package_revision.clone(),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
        package_sequence,
    };
    let migration_connection = config
        .migration_database_connection_config()
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::DatabaseConfiguration)?;
    let audit_profile = config
        .audit_profile()
        .map_err(FieldEncryptionEraseHistoryLifecycleError::RuntimeConfig)?;
    let lock_key = RegistryLockKey::derive(&expected.package_id)
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::DatabaseConfiguration)?;
    let timeouts = FieldEncryptionBackfillTimeouts::new(
        bounded_erase_timeout(config.operational_timeouts().migration_lock)?,
        bounded_erase_timeout(config.operational_timeouts().migration_statement)?,
    )
    .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::TimeoutConfiguration)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::Runtime)?;
    let outcome = runtime
        .block_on(erase_field_encryption_history_with_connection(
            &migration_connection,
            FieldEncryptionHistoryErasureRequest {
                expected: &expected,
                migration_role: config.database().roles().migration(),
                lock_key,
                timeouts,
                audit_profile: &audit_profile,
                operator_reference: &erase.operator_reference,
                reason: &erase.reason,
                registry: package.registry(),
            },
        ))
        .map_err(FieldEncryptionEraseHistoryLifecycleError::Erase)?;
    Ok(FieldEncryptionEraseHistoryLifecycleOutcome {
        package_revision: expected.package_revision,
        outcome,
    })
}

fn predecessor_identity(
    package: &VerifiedPredecessorPackage,
) -> Result<ExpectedRegistryIdentity, FieldEncryptionPreflightLifecycleError> {
    Ok(ExpectedRegistryIdentity {
        package_id: package.package_id().to_owned(),
        environment: package.environment().to_owned(),
        instance_id: package.instance_id().to_owned(),
        database_id: package.database_id().to_owned(),
        package_revision: package.package_revision().to_owned(),
        schema_fingerprint: package.schema_fingerprint().to_owned(),
        package_sequence: i64::try_from(package.sequence()).map_err(|_| {
            FieldEncryptionPreflightLifecycleError::PredecessorPackage(PackageError::Binding)
        })?,
    })
}

fn bounded_timeout(timeout: Duration) -> Result<Duration, FieldEncryptionPreflightLifecycleError> {
    if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
        return Err(FieldEncryptionPreflightLifecycleError::TimeoutConfiguration);
    }
    Ok(timeout)
}

fn bounded_erase_timeout(
    timeout: Duration,
) -> Result<Duration, FieldEncryptionEraseHistoryLifecycleError> {
    if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
        return Err(FieldEncryptionEraseHistoryLifecycleError::TimeoutConfiguration);
    }
    Ok(timeout)
}

/// The erase-history request carries the operator reference and the reason,
/// and nothing else: its scope is the recorded erase-and-rebaseline flips
/// themselves, so a document naming records or fields is refused rather than
/// reinterpreted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawFieldEncryptionEraseRequest {
    operator_reference: String,
    reason: String,
}

fn load_erase_request(
    path: &Path,
) -> Result<RawFieldEncryptionEraseRequest, FieldEncryptionEraseHistoryLifecycleError> {
    if !path.is_absolute() {
        return Err(FieldEncryptionEraseHistoryLifecycleError::RequestFile);
    }
    let bytes = read_owner_only_request_file(path)?;
    parse_erase_request_bytes(&bytes)
}

fn parse_erase_request_bytes(
    bytes: &[u8],
) -> Result<RawFieldEncryptionEraseRequest, FieldEncryptionEraseHistoryLifecycleError> {
    let value: serde_json::Value = parse_json_strict(bytes)
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::RequestDocument)?;
    let request: RawFieldEncryptionEraseRequest = serde_json::from_value(value)
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::RequestDocument)?;
    if request.operator_reference.is_empty() || request.reason.is_empty() {
        return Err(FieldEncryptionEraseHistoryLifecycleError::RequestDocument);
    }
    Ok(request)
}

fn read_owner_only_request_file(
    path: &Path,
) -> Result<Vec<u8>, FieldEncryptionEraseHistoryLifecycleError> {
    let mut file = open_request_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::RequestFile)?;
    if !metadata.file_type().is_file() {
        return Err(FieldEncryptionEraseHistoryLifecycleError::RequestFile);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(FieldEncryptionEraseHistoryLifecycleError::RequestFile);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_ERASE_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::RequestFile)?;
    if bytes.is_empty() || bytes.len() > MAX_ERASE_REQUEST_BYTES as usize {
        return Err(FieldEncryptionEraseHistoryLifecycleError::RequestFile);
    }
    Ok(bytes)
}

fn open_request_file(path: &Path) -> Result<File, FieldEncryptionEraseHistoryLifecycleError> {
    // Descriptor-relative resolution refuses a symbolic link at every
    // component. `O_NOFOLLOW` alone would only have covered the last one, so an
    // ancestor swapped after any check could still redirect this open.
    SafeEntry::resolve(path)
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::RequestFile)?
        .open_read()
        .map_err(|_| FieldEncryptionEraseHistoryLifecycleError::RequestFile)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    #[test]
    fn erase_request_file_carries_the_operator_reference_and_reason_alone() {
        let parsed = parse_erase_request_bytes(
            br#"{"operatorReference":"ops-ticket-1","reason":"flip declared erase-and-rebaseline"}"#,
        )
        .expect("complete request parses");
        assert_eq!(parsed.operator_reference, "ops-ticket-1");
        assert_eq!(parsed.reason, "flip declared erase-and-rebaseline");

        assert!(parse_erase_request_bytes(br#"{"operatorReference":""}"#).is_err());
        assert!(
            parse_erase_request_bytes(br#"{"operatorReference":"ops-ticket-1","reason":""}"#)
                .is_err()
        );
        assert!(parse_erase_request_bytes(br#"{}"#).is_err());
        assert!(parse_erase_request_bytes(
            br#"{
              "operatorReference":"ops-ticket-1",
              "reason":"retention request",
              "entityId":"membership",
              "recordId":"018feaa0-68f9-4a45-b9e3-58436df07af7"
            }"#,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn erase_request_file_refuses_symlink_after_open() {
        let root = std::env::temp_dir().join(format!(
            "bregctl-field-encryption-erase-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("test directory is created");
        let target = root.join("request.json");
        let link = root.join("request-link.json");
        std::fs::write(
            &target,
            br#"{"operatorReference":"ops-ticket-1","reason":"retention request"}"#,
        )
        .expect("target request writes");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("target permissions set");
        symlink(&target, &link).expect("symlink is created");

        assert!(matches!(
            read_owner_only_request_file(&link),
            Err(FieldEncryptionEraseHistoryLifecycleError::RequestFile)
        ));

        std::fs::remove_dir_all(&root).expect("test directory is removed");
    }
}
