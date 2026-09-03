// SPDX-License-Identifier: Apache-2.0
//! Operator lifecycle for one bounded snapshot-coverage rebaseline.
//!
//! The command using this module should be exposed as maintenance tooling. It
//! opens only the configured migration connection, verifies the active package
//! binding from the runtime configuration, and delegates all database mutation
//! to `registry_breg::history_rebaseline`.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use registry_breg::history_rebaseline::{
    rebaseline_history_coverage_with_connection, HistoryRebaselineError, HistoryRebaselineOutcome,
    HistoryRebaselineRequest, HistoryRebaselineTimeouts,
};
use registry_breg::package::{load_package, PackageError};
use registry_breg::postgres::{ExpectedRegistryIdentity, RegistryLockKey};
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfigError};
use registry_platform_canonical_json::parse_json_strict;
use serde::{Deserialize, Serialize};

const MAX_REBASELINE_REQUEST_BYTES: u64 = 16 * 1024;

#[derive(Debug)]
pub(crate) enum HistoryRebaselineLifecycleError {
    RuntimeConfigPath,
    RequestFile,
    RequestDocument,
    RuntimeConfig(RuntimeConfigError),
    Package(PackageError),
    DatabaseConfiguration,
    TimeoutConfiguration,
    Runtime,
    Rebaseline(HistoryRebaselineError),
}

pub(crate) struct HistoryRebaselineLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub request_file: &'a Path,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HistoryRebaselineLifecycleOutcome {
    pub package_revision: String,
    pub baseline_position: i64,
    pub verified_entity_count: u64,
    pub verified_record_count: u64,
    pub previous_coverage_baseline_position: i64,
    pub previous_unavailable_after_position: Option<i64>,
}

pub(crate) fn run(
    request: HistoryRebaselineLifecycleRequest<'_>,
) -> Result<HistoryRebaselineLifecycleOutcome, HistoryRebaselineLifecycleError> {
    if !request.runtime_config.is_absolute() {
        return Err(HistoryRebaselineLifecycleError::RuntimeConfigPath);
    }
    let rebaseline = load_rebaseline_request(request.request_file)?;
    let config = load_runtime_config(request.runtime_config)
        .map_err(HistoryRebaselineLifecycleError::RuntimeConfig)?;
    let package = load_package(config.package().root(), &config.package_load_context())
        .map_err(HistoryRebaselineLifecycleError::Package)?;
    let manifest = package.manifest();
    let package_sequence = i64::try_from(manifest.sequence)
        .map_err(|_| HistoryRebaselineLifecycleError::Package(PackageError::Binding))?;
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
        .map_err(|_| HistoryRebaselineLifecycleError::DatabaseConfiguration)?;
    let audit_profile = config
        .audit_profile()
        .map_err(HistoryRebaselineLifecycleError::RuntimeConfig)?;
    let lock_key = RegistryLockKey::derive(&expected.package_id)
        .map_err(|_| HistoryRebaselineLifecycleError::DatabaseConfiguration)?;
    let timeouts = HistoryRebaselineTimeouts::new(
        bounded_timeout(config.operational_timeouts().migration_lock)?,
        bounded_timeout(config.operational_timeouts().migration_statement)?,
    )
    .map_err(|_| HistoryRebaselineLifecycleError::TimeoutConfiguration)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| HistoryRebaselineLifecycleError::Runtime)?;
    let outcome = runtime
        .block_on(rebaseline_history_coverage_with_connection(
            &migration_connection,
            HistoryRebaselineRequest {
                expected: &expected,
                migration_role: config.database().roles().migration(),
                lock_key,
                timeouts,
                audit_profile: &audit_profile,
                operator_reference: &rebaseline.operator_reference,
                registry: package.registry(),
            },
        ))
        .map_err(HistoryRebaselineLifecycleError::Rebaseline)?;
    Ok(outcome_report(expected.package_revision, outcome))
}

fn outcome_report(
    package_revision: String,
    outcome: HistoryRebaselineOutcome,
) -> HistoryRebaselineLifecycleOutcome {
    HistoryRebaselineLifecycleOutcome {
        package_revision,
        baseline_position: outcome.baseline_position,
        verified_entity_count: outcome.verified_entity_count,
        verified_record_count: outcome.verified_record_count,
        previous_coverage_baseline_position: outcome.previous_coverage_baseline_position,
        previous_unavailable_after_position: outcome.previous_unavailable_after_position,
    }
}

fn bounded_timeout(timeout: Duration) -> Result<Duration, HistoryRebaselineLifecycleError> {
    if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
        return Err(HistoryRebaselineLifecycleError::TimeoutConfiguration);
    }
    Ok(timeout)
}

/// The request carries the operator reference and nothing else: a rebaseline
/// names no record, erases nothing, and reads its scope from the active
/// package, so an erasure-shaped document is refused rather than reinterpreted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawHistoryRebaselineRequest {
    operator_reference: String,
}

fn load_rebaseline_request(
    path: &Path,
) -> Result<RawHistoryRebaselineRequest, HistoryRebaselineLifecycleError> {
    if !path.is_absolute() {
        return Err(HistoryRebaselineLifecycleError::RequestFile);
    }
    let bytes = read_owner_only_request_file(path)?;
    parse_rebaseline_request_bytes(&bytes)
}

fn parse_rebaseline_request_bytes(
    bytes: &[u8],
) -> Result<RawHistoryRebaselineRequest, HistoryRebaselineLifecycleError> {
    let value: serde_json::Value =
        parse_json_strict(bytes).map_err(|_| HistoryRebaselineLifecycleError::RequestDocument)?;
    let request: RawHistoryRebaselineRequest = serde_json::from_value(value)
        .map_err(|_| HistoryRebaselineLifecycleError::RequestDocument)?;
    if request.operator_reference.is_empty() {
        return Err(HistoryRebaselineLifecycleError::RequestDocument);
    }
    Ok(request)
}

fn read_owner_only_request_file(path: &Path) -> Result<Vec<u8>, HistoryRebaselineLifecycleError> {
    let mut file = open_request_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| HistoryRebaselineLifecycleError::RequestFile)?;
    if !metadata.file_type().is_file() {
        return Err(HistoryRebaselineLifecycleError::RequestFile);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(HistoryRebaselineLifecycleError::RequestFile);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_REBASELINE_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HistoryRebaselineLifecycleError::RequestFile)?;
    if bytes.is_empty() || bytes.len() > MAX_REBASELINE_REQUEST_BYTES as usize {
        return Err(HistoryRebaselineLifecycleError::RequestFile);
    }
    Ok(bytes)
}

fn open_request_file(path: &Path) -> Result<File, HistoryRebaselineLifecycleError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(request_file_no_follow_flags());
    }
    options
        .open(path)
        .map_err(|_| HistoryRebaselineLifecycleError::RequestFile)
}

#[cfg(unix)]
fn request_file_no_follow_flags() -> i32 {
    // Do not block on a FIFO before the opened-descriptor file-type check.
    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK)
        .bits() as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    #[test]
    fn outcome_report_preserves_minimized_counts() {
        let report = outcome_report(
            "pkg-1".to_owned(),
            HistoryRebaselineOutcome {
                baseline_position: 4,
                verified_entity_count: 1,
                verified_record_count: 2,
                previous_coverage_baseline_position: 0,
                previous_unavailable_after_position: Some(1),
            },
        );
        assert_eq!(report.package_revision, "pkg-1");
        assert_eq!(report.baseline_position, 4);
        assert_eq!(report.verified_entity_count, 1);
        assert_eq!(report.verified_record_count, 2);
        assert_eq!(report.previous_coverage_baseline_position, 0);
        assert_eq!(report.previous_unavailable_after_position, Some(1));
    }

    #[test]
    fn rebaseline_request_file_carries_the_operator_reference_alone() {
        let parsed = parse_rebaseline_request_bytes(br#"{"operatorReference":"ops-ticket-1"}"#)
            .expect("complete request parses");
        assert_eq!(parsed.operator_reference, "ops-ticket-1");

        assert!(parse_rebaseline_request_bytes(br#"{"operatorReference":""}"#).is_err());
        assert!(parse_rebaseline_request_bytes(br#"{}"#).is_err());
        assert!(parse_rebaseline_request_bytes(
            br#"{
              "operatorReference":"ops-ticket-1",
              "entityId":"membership",
              "recordId":"018feaa0-68f9-4a45-b9e3-58436df07af7",
              "eraseThroughRevision":1
            }"#,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rebaseline_request_file_refuses_symlink_after_open() {
        let root =
            std::env::temp_dir().join(format!("bregctl-history-rebaseline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("test directory is created");
        let target = root.join("request.json");
        let link = root.join("request-link.json");
        std::fs::write(&target, br#"{"operatorReference":"ops-ticket-1"}"#)
            .expect("target request writes");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("target permissions set");
        symlink(&target, &link).expect("symlink is created");

        assert!(matches!(
            read_owner_only_request_file(&link),
            Err(HistoryRebaselineLifecycleError::RequestFile)
        ));

        std::fs::remove_dir_all(&root).expect("test directory is removed");
    }
}
