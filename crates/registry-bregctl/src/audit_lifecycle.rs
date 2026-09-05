// SPDX-License-Identifier: Apache-2.0

//! Audit journal operator workflows.
//!
//! The CLI owns argument validation, export file creation, and rendering only.
//! Chain traversal, verification, and retention are delegated to Base Registry
//! Engine so package, catalog, lock, role, and SQL boundaries stay in the
//! product runtime. Refusals carry a closed code and no operator value.

use std::ffi::OsString;
use std::fs::File;
use std::io::BufWriter;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use registry_breg::audit_tooling::{
    AuditExport, AuditOperatorService, AuditPrune, AuditPruneBoundary, AuditToolingError,
    AuditVerification,
};
use serde::Serialize;

use crate::safe_path::SafeEntry;

/// Owner-only permissions for an export the operator has not yet placed.
const EXPORT_FILE_MODE: u32 = 0o600;

static EXPORT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditCliError {
    Operator,
    ChainBroken,
    InvalidEnvelope,
    HeadMismatch,
    Unreachable,
    BoundaryInFuture,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuditVerifyOutcome {
    #[serde(flatten)]
    pub verification: AuditVerification,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuditExportOutcome {
    #[serde(flatten)]
    pub export: AuditExport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuditPruneOutcome {
    #[serde(flatten)]
    pub prune: AuditPrune,
}

pub(crate) fn verify(runtime_config: &Path) -> Result<AuditVerifyOutcome, AuditCliError> {
    if !runtime_config.is_absolute() {
        return Err(AuditCliError::Operator);
    }
    let runtime = operator_runtime()?;
    let verification = runtime.block_on(async {
        let service = service(runtime_config).await?;
        service.verify().await.map_err(map_error)
    })?;
    Ok(AuditVerifyOutcome { verification })
}

pub(crate) fn export(
    runtime_config: &Path,
    output: &Path,
) -> Result<AuditExportOutcome, AuditCliError> {
    if !runtime_config.is_absolute() || !output.is_absolute() || output.exists() {
        return Err(AuditCliError::Operator);
    }
    let runtime = operator_runtime()?;
    let mut staged = create_export_file(output)?;
    let export = {
        let mut sink = BufWriter::new(&mut staged.file);
        let export = runtime.block_on(async {
            let service = service(runtime_config).await?;
            service.export(&mut sink).await.map_err(map_error)
        });
        export.and_then(|export| finish_export_file(sink).map(|()| export))?
    };
    publish_export_file(staged)?;
    Ok(AuditExportOutcome { export })
}

pub(crate) fn prune(
    runtime_config: &Path,
    before: &str,
    dry_run: bool,
) -> Result<AuditPruneOutcome, AuditCliError> {
    if !runtime_config.is_absolute() {
        return Err(AuditCliError::Operator);
    }
    let boundary = AuditPruneBoundary::parse_rfc3339(before).map_err(map_error)?;
    let runtime = operator_runtime()?;
    let prune = runtime.block_on(async {
        let service = service(runtime_config).await?;
        service.prune(boundary, dry_run).await.map_err(map_error)
    })?;
    Ok(AuditPruneOutcome { prune })
}

async fn service(runtime_config: &Path) -> Result<AuditOperatorService, AuditCliError> {
    AuditOperatorService::from_runtime_config(runtime_config)
        .await
        .map_err(map_error)
}

/// An export staged as a sibling of the operator's destination, held through
/// the destination's resolved parent descriptor so neither the staged write nor
/// the publication can be redirected by a later path change.
struct StagedExport {
    destination: SafeEntry,
    temporary: OsString,
    file: File,
}

fn create_export_file(output: &Path) -> Result<StagedExport, AuditCliError> {
    let destination = SafeEntry::resolve(output).map_err(|_| AuditCliError::Operator)?;
    if destination.exists().map_err(|_| AuditCliError::Operator)? {
        return Err(AuditCliError::Operator);
    }
    for _ in 0..64 {
        let counter = EXPORT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = OsString::from(format!(
            ".bregctl-audit-export-{}-{counter}.tmp",
            std::process::id()
        ));
        let file = match destination
            .parent()
            .create_new(&temporary, EXPORT_FILE_MODE)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(AuditCliError::Operator),
        };
        // The create mode is filtered by the process umask, so restate the
        // owner-only permissions on the descriptor itself.
        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(EXPORT_FILE_MODE))
            .map_err(|_| AuditCliError::Operator)?;
        return Ok(StagedExport {
            destination,
            temporary,
            file,
        });
    }
    Err(AuditCliError::Operator)
}

fn finish_export_file(sink: BufWriter<&mut File>) -> Result<(), AuditCliError> {
    let file = sink.into_inner().map_err(|_| AuditCliError::Operator)?;
    file.sync_all().map_err(|_| AuditCliError::Operator)
}

fn publish_export_file(staged: StagedExport) -> Result<(), AuditCliError> {
    let StagedExport {
        destination,
        temporary,
        file,
    } = staged;
    drop(file);
    if destination.publish_from(&temporary).is_err() {
        let _ = destination.parent().remove_file(&temporary);
        return Err(AuditCliError::Operator);
    }
    destination
        .parent()
        .sync()
        .map_err(|_| AuditCliError::Operator)
}

fn map_error(error: AuditToolingError) -> AuditCliError {
    match error {
        AuditToolingError::ChainBroken { .. } => AuditCliError::ChainBroken,
        AuditToolingError::InvalidEnvelope { .. } => AuditCliError::InvalidEnvelope,
        AuditToolingError::HeadMismatch => AuditCliError::HeadMismatch,
        AuditToolingError::Unreachable { .. } => AuditCliError::Unreachable,
        AuditToolingError::BoundaryInFuture => AuditCliError::BoundaryInFuture,
        AuditToolingError::Unavailable => AuditCliError::Operator,
    }
}

fn operator_runtime() -> Result<tokio::runtime::Runtime, AuditCliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AuditCliError::Operator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn export_is_hidden_until_an_owner_only_file_is_published() {
        let directory = tempfile::tempdir().unwrap();
        // The platform temporary directory can itself sit behind a symbolic
        // link, which the export path resolution refuses by design, so name the
        // real directory the operator would name.
        let root = directory.path().canonicalize().unwrap();
        let output = root.join("audit.jsonl");
        let mut staged = create_export_file(&output).unwrap();
        assert!(!output.exists());

        {
            let mut sink = BufWriter::new(&mut staged.file);
            sink.write_all(b"verified\n").unwrap();
            finish_export_file(sink).unwrap();
        }
        assert!(!output.exists());
        publish_export_file(staged).unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), b"verified\n");
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".bregctl-audit-export-")));
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn operator_paths_must_be_absolute_and_the_export_target_must_be_free() {
        let relative = Path::new("audit.jsonl");
        assert_eq!(verify(relative).unwrap_err(), AuditCliError::Operator);
        assert_eq!(
            export(relative, Path::new("/audit-export.jsonl")).unwrap_err(),
            AuditCliError::Operator
        );
        assert_eq!(
            export(Path::new("/registry/runtime.yaml"), relative).unwrap_err(),
            AuditCliError::Operator
        );
        assert_eq!(
            prune(relative, "2024-03-01T00:00:00Z", true).unwrap_err(),
            AuditCliError::Operator
        );
    }

    #[test]
    fn a_boundary_that_is_not_one_rfc_3339_instant_is_refused() {
        assert_eq!(
            prune(Path::new("/registry/runtime.yaml"), "2024-03-01", true).unwrap_err(),
            AuditCliError::Operator
        );
    }

    #[test]
    fn every_runtime_refusal_maps_to_one_closed_operator_code() {
        assert_eq!(
            map_error(AuditToolingError::ChainBroken { position: 2 }),
            AuditCliError::ChainBroken
        );
        assert_eq!(
            map_error(AuditToolingError::InvalidEnvelope { position: 2 }),
            AuditCliError::InvalidEnvelope
        );
        assert_eq!(
            map_error(AuditToolingError::HeadMismatch),
            AuditCliError::HeadMismatch
        );
        assert_eq!(
            map_error(AuditToolingError::Unreachable { records: 1 }),
            AuditCliError::Unreachable
        );
        assert_eq!(
            map_error(AuditToolingError::BoundaryInFuture),
            AuditCliError::BoundaryInFuture
        );
        assert_eq!(
            map_error(AuditToolingError::Unavailable),
            AuditCliError::Operator
        );
    }

    /// Deterministic ancestor-swap regression for the audit export output this
    /// module owns.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod ancestor_swap {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        #[test]
        fn an_export_publication_after_an_ancestor_swap_publishes_only_in_the_named_tree() {
            let tree = race_tree();

            let guard = tree.arm();
            let mut staged = create_export_file(&tree.named("audit.jsonl")).unwrap();
            staged.file.write_all(b"exported\n").unwrap();
            publish_export_file(staged).unwrap();
            drop(guard);

            assert_eq!(
                std::fs::read(tree.moved("audit.jsonl")).unwrap(),
                b"exported\n"
            );
            assert_eq!(tree.outside_entries(), vec!["target".to_owned()]);
        }
    }
}
