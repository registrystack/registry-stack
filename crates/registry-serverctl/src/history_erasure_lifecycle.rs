// SPDX-License-Identifier: Apache-2.0
//! Operator lifecycle for one bounded retained-history erasure.
//!
//! The command using this module should be exposed as maintenance tooling. It
//! opens only the configured migration connection, verifies the active package
//! binding from the runtime configuration, and delegates all database mutation
//! to `registry_server::history_erasure`.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use registry_platform_canonical_json::parse_json_strict;
use registry_server::history_erasure::{
    erase_record_history_with_connection, HistoryErasureError, HistoryErasureOutcome,
    HistoryErasureRequest, HistoryErasureTimeouts, RecordHistoryErasureTarget,
};
use registry_server::package::{load_package, PackageError};
use registry_server::postgres::{ExpectedRegistryIdentity, RegistryLockKey};
use registry_server::runtime_config::{load_runtime_config, RuntimeConfigError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_ERASURE_REQUEST_BYTES: u64 = 16 * 1024;

#[derive(Debug)]
pub(crate) enum HistoryErasureLifecycleError {
    RuntimeConfigPath,
    RequestFile,
    RequestDocument,
    RuntimeConfig(RuntimeConfigError),
    Package(PackageError),
    DatabaseConfiguration,
    TimeoutConfiguration,
    Target,
    Runtime,
    Erasure(HistoryErasureError),
}

pub(crate) struct HistoryErasureLifecycleRequest<'a> {
    pub runtime_config: &'a Path,
    pub request_file: &'a Path,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HistoryErasureLifecycleOutcome {
    pub package_revision: String,
    pub coverage_ready: bool,
    pub unavailable_after_position: Option<i64>,
    pub affected_commit_count: u64,
    pub erased_revision_count: u64,
    pub erased_commit_member_count: u64,
    pub scrubbed_change_context_count: u64,
    pub scrubbed_outbox_payload_count: u64,
    pub scrubbed_cached_response_count: u64,
    pub removed_descriptor_count: u64,
}

pub(crate) fn run(
    request: HistoryErasureLifecycleRequest<'_>,
) -> Result<HistoryErasureLifecycleOutcome, HistoryErasureLifecycleError> {
    if !request.runtime_config.is_absolute() {
        return Err(HistoryErasureLifecycleError::RuntimeConfigPath);
    }
    let erasure = load_erasure_request(request.request_file)?;
    let record_id =
        Uuid::parse_str(&erasure.record_id).map_err(|_| HistoryErasureLifecycleError::Target)?;
    let config = load_runtime_config(request.runtime_config)
        .map_err(HistoryErasureLifecycleError::RuntimeConfig)?;
    let package = load_package(config.package().root(), &config.package_load_context())
        .map_err(HistoryErasureLifecycleError::Package)?;
    let manifest = package.manifest();
    let package_sequence = i64::try_from(manifest.sequence)
        .map_err(|_| HistoryErasureLifecycleError::Package(PackageError::Binding))?;
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
        .map_err(|_| HistoryErasureLifecycleError::DatabaseConfiguration)?;
    let audit_profile = config
        .audit_profile()
        .map_err(HistoryErasureLifecycleError::RuntimeConfig)?;
    let lock_key = RegistryLockKey::derive(&expected.package_id)
        .map_err(|_| HistoryErasureLifecycleError::DatabaseConfiguration)?;
    let timeouts = HistoryErasureTimeouts::new(
        bounded_timeout(config.operational_timeouts().migration_lock)?,
        bounded_timeout(config.operational_timeouts().migration_statement)?,
    )
    .map_err(|_| HistoryErasureLifecycleError::TimeoutConfiguration)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| HistoryErasureLifecycleError::Runtime)?;
    let outcome = runtime
        .block_on(erase_record_history_with_connection(
            &migration_connection,
            HistoryErasureRequest {
                expected: &expected,
                migration_role: config.database().roles().migration(),
                lock_key,
                timeouts,
                audit_profile: &audit_profile,
                operator_reference: &erasure.operator_reference,
                reason: &erasure.reason,
                target: RecordHistoryErasureTarget::new(
                    &erasure.entity_id,
                    record_id,
                    erasure.erase_through_revision,
                ),
            },
        ))
        .map_err(HistoryErasureLifecycleError::Erasure)?;
    Ok(outcome_report(expected.package_revision, outcome))
}

fn outcome_report(
    package_revision: String,
    outcome: HistoryErasureOutcome,
) -> HistoryErasureLifecycleOutcome {
    HistoryErasureLifecycleOutcome {
        package_revision,
        coverage_ready: outcome.coverage_ready,
        unavailable_after_position: outcome.unavailable_after_position,
        affected_commit_count: outcome.affected_commit_count,
        erased_revision_count: outcome.erased_revision_count,
        erased_commit_member_count: outcome.erased_commit_member_count,
        scrubbed_change_context_count: outcome.scrubbed_change_context_count,
        scrubbed_outbox_payload_count: outcome.scrubbed_outbox_payload_count,
        scrubbed_cached_response_count: outcome.scrubbed_cached_response_count,
        removed_descriptor_count: outcome.removed_descriptor_count,
    }
}

fn bounded_timeout(timeout: Duration) -> Result<Duration, HistoryErasureLifecycleError> {
    if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
        return Err(HistoryErasureLifecycleError::TimeoutConfiguration);
    }
    Ok(timeout)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawHistoryErasureRequest {
    entity_id: String,
    record_id: String,
    erase_through_revision: i64,
    operator_reference: String,
    reason: String,
}

fn load_erasure_request(
    path: &Path,
) -> Result<RawHistoryErasureRequest, HistoryErasureLifecycleError> {
    if !path.is_absolute() {
        return Err(HistoryErasureLifecycleError::RequestFile);
    }
    let bytes = read_owner_only_request_file(path)?;
    parse_erasure_request_bytes(&bytes)
}

fn parse_erasure_request_bytes(
    bytes: &[u8],
) -> Result<RawHistoryErasureRequest, HistoryErasureLifecycleError> {
    let value: serde_json::Value =
        parse_json_strict(bytes).map_err(|_| HistoryErasureLifecycleError::RequestDocument)?;
    let request: RawHistoryErasureRequest =
        serde_json::from_value(value).map_err(|_| HistoryErasureLifecycleError::RequestDocument)?;
    if request.entity_id.is_empty()
        || request.record_id.is_empty()
        || request.erase_through_revision <= 0
        || request.operator_reference.is_empty()
        || request.reason.is_empty()
    {
        return Err(HistoryErasureLifecycleError::RequestDocument);
    }
    Ok(request)
}

fn read_owner_only_request_file(path: &Path) -> Result<Vec<u8>, HistoryErasureLifecycleError> {
    let mut file = open_request_file(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| HistoryErasureLifecycleError::RequestFile)?;
    if !metadata.file_type().is_file() {
        return Err(HistoryErasureLifecycleError::RequestFile);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(HistoryErasureLifecycleError::RequestFile);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_ERASURE_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| HistoryErasureLifecycleError::RequestFile)?;
    if bytes.is_empty() || bytes.len() > MAX_ERASURE_REQUEST_BYTES as usize {
        return Err(HistoryErasureLifecycleError::RequestFile);
    }
    Ok(bytes)
}

fn open_request_file(path: &Path) -> Result<File, HistoryErasureLifecycleError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(request_file_no_follow_flags());
    }
    options
        .open(path)
        .map_err(|_| HistoryErasureLifecycleError::RequestFile)
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
            HistoryErasureOutcome {
                coverage_ready: true,
                unavailable_after_position: Some(3),
                affected_commit_count: 2,
                erased_revision_count: 2,
                erased_commit_member_count: 2,
                scrubbed_change_context_count: 1,
                scrubbed_outbox_payload_count: 1,
                scrubbed_cached_response_count: 1,
                removed_descriptor_count: 0,
            },
        );
        assert_eq!(report.package_revision, "pkg-1");
        assert!(report.coverage_ready);
        assert_eq!(report.unavailable_after_position, Some(3));
        assert_eq!(report.affected_commit_count, 2);
        assert_eq!(report.scrubbed_change_context_count, 1);
        assert_eq!(report.scrubbed_cached_response_count, 1);
    }

    #[test]
    fn erasure_request_file_is_strict_and_complete() {
        let parsed = parse_erasure_request_bytes(
            br#"{
              "entityId":"membership",
              "recordId":"018feaa0-68f9-4a45-b9e3-58436df07af7",
              "eraseThroughRevision":1,
              "operatorReference":"ops-ticket-1",
              "reason":"retention request"
            }"#,
        )
        .expect("complete request parses");
        assert_eq!(parsed.entity_id, "membership");
        assert_eq!(parsed.erase_through_revision, 1);

        assert!(parse_erasure_request_bytes(
            br#"{
              "entityId":"membership",
              "recordId":"018feaa0-68f9-4a45-b9e3-58436df07af7",
              "eraseThroughRevision":1,
              "operatorReference":"ops-ticket-1",
              "reason":"retention request",
              "extra":"refused"
            }"#,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn erasure_request_file_refuses_symlink_after_open() {
        let root = std::env::temp_dir().join(format!(
            "registry-serverctl-history-erasure-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("test directory is created");
        let target = root.join("request.json");
        let link = root.join("request-link.json");
        std::fs::write(
            &target,
            br#"{
              "entityId":"membership",
              "recordId":"018feaa0-68f9-4a45-b9e3-58436df07af7",
              "eraseThroughRevision":1,
              "operatorReference":"ops-ticket-1",
              "reason":"retention request"
            }"#,
        )
        .expect("target request writes");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("target permissions set");
        symlink(&target, &link).expect("symlink is created");

        assert!(matches!(
            read_owner_only_request_file(&link),
            Err(HistoryErasureLifecycleError::RequestFile)
        ));

        std::fs::remove_dir_all(&root).expect("test directory is removed");
    }
}
