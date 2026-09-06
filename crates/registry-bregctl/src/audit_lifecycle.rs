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

use crate::safe_path::{SafeDir, SafeEntry, SafePathError};

/// Owner-only permissions for an export the operator has not yet placed.
const EXPORT_FILE_MODE: u32 = 0o600;

static EXPORT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditCliError {
    Operator,
    OutputPath(SafePathError),
    OutputExists,
    /// The export reached its destination, and the directory entry naming it
    /// could not be made durable.
    OutputNotDurable,
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
    if !runtime_config.is_absolute() || !output.is_absolute() {
        return Err(AuditCliError::Operator);
    }
    let runtime = operator_runtime()?;
    // `create_export_file` refuses a destination that is already taken through
    // the parent descriptor it resolves, so the pathname is never reached a
    // second time to ask the same question.
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
///
/// The staging file belongs to this value: every outcome that is not a
/// publication removes it as the value drops.
#[derive(Debug)]
struct StagedExport {
    destination: SafeEntry,
    temporary: OsString,
    file: File,
    published: bool,
}

impl Drop for StagedExport {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // The refusal that ended this export is already on its way to the
        // operator, and an unlink the kernel refuses leaves this process
        // nothing further to do about the staging name.
        let _ = self.destination.parent().remove_file(&self.temporary);
    }
}

fn create_export_file(output: &Path) -> Result<StagedExport, AuditCliError> {
    let destination = SafeEntry::resolve(output).map_err(AuditCliError::OutputPath)?;
    if destination.exists().map_err(|_| AuditCliError::Operator)? {
        return Err(AuditCliError::OutputExists);
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
        // The staging file exists from here on, so hand it to the value that
        // removes it before anything else can refuse.
        let staged = StagedExport {
            destination,
            temporary,
            file,
            published: false,
        };
        // The create mode is filtered by the process umask, so restate the
        // owner-only permissions on the descriptor itself.
        #[cfg(unix)]
        staged
            .file
            .set_permissions(std::fs::Permissions::from_mode(EXPORT_FILE_MODE))
            .map_err(|_| AuditCliError::Operator)?;
        return Ok(staged);
    }
    Err(AuditCliError::Operator)
}

fn finish_export_file(sink: BufWriter<&mut File>) -> Result<(), AuditCliError> {
    let file = sink.into_inner().map_err(|_| AuditCliError::Operator)?;
    file.sync_all().map_err(|_| AuditCliError::Operator)
}

fn publish_export_file(mut staged: StagedExport) -> Result<(), AuditCliError> {
    // The staged bytes are already flushed, so publication needs the staging
    // name only; the descriptor closes when the staged export drops.
    staged
        .destination
        .publish_new_from(&staged.temporary)
        .map_err(|_| AuditCliError::Operator)?;
    // The link put the export at its destination, so a sync that fails after
    // it cannot be reported as an operation that did nothing.
    sync_publication_parent(staged.destination.parent())?;
    // Publication consumes the staging name, so the cleanup has nothing left
    // to remove.
    staged.published = true;
    Ok(())
}

/// Report an export as published only once the directory entry naming it is
/// durable. The link is already visible to every reader by then, so a failure
/// here reports an export whose survival across a crash is unproven.
fn sync_publication_parent(parent: &SafeDir) -> Result<(), AuditCliError> {
    if publication_sync_faulted() {
        return Err(AuditCliError::OutputNotDurable);
    }
    parent.sync().map_err(|_| AuditCliError::OutputNotDurable)
}

// Test-only seam that stands in for a directory the filesystem could not make
// durable. It fires where the export would be reported as published.
#[cfg(test)]
thread_local! {
    static PUBLICATION_SYNC_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn publication_sync_faulted() -> bool {
    PUBLICATION_SYNC_FAULT.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn publication_sync_faulted() -> bool {
    false
}

/// Make every export publication in this thread fail its parent directory sync
/// until the returned guard drops.
#[cfg(test)]
fn install_publication_sync_fault() -> PublicationSyncFaultGuard {
    PUBLICATION_SYNC_FAULT.with(|faulted| faulted.set(true));
    PublicationSyncFaultGuard
}

/// Clears the fault, so one test cannot leak it into the next test on the same
/// thread.
#[cfg(test)]
struct PublicationSyncFaultGuard;

#[cfg(test)]
impl Drop for PublicationSyncFaultGuard {
    fn drop(&mut self) {
        PUBLICATION_SYNC_FAULT.with(|faulted| faulted.set(false));
    }
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
    fn an_export_whose_directory_cannot_be_synced_is_reported_as_undurable_not_refused() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let output = root.join("audit.jsonl");
        let mut staged = create_export_file(&output).unwrap();

        {
            let mut sink = BufWriter::new(&mut staged.file);
            sink.write_all(b"verified\n").unwrap();
            finish_export_file(sink).unwrap();
        }

        let guard = install_publication_sync_fault();
        // The link runs before the sync, so the export is already where the
        // operator asked for it. The refusal has to say that rather than claim
        // the operation was refused with nothing written.
        assert_eq!(
            publish_export_file(staged).unwrap_err(),
            AuditCliError::OutputNotDurable
        );
        drop(guard);

        assert_eq!(std::fs::read(&output).unwrap(), b"verified\n");
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".bregctl-audit-export-")));
    }

    #[test]
    fn publish_refuses_a_destination_that_appears_after_staging_and_removes_the_temporary() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let output = root.join("audit.jsonl");
        let mut staged = create_export_file(&output).unwrap();

        {
            let mut sink = BufWriter::new(&mut staged.file);
            sink.write_all(b"verified\n").unwrap();
            finish_export_file(sink).unwrap();
        }

        // Another writer claims the destination after this export staged its
        // temporary file but before it publishes.
        std::fs::write(&output, b"raced\n").unwrap();

        assert_eq!(
            publish_export_file(staged).unwrap_err(),
            AuditCliError::Operator
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"raced\n");
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".bregctl-audit-export-")));
    }

    #[test]
    fn an_export_that_fails_before_publication_leaves_no_staging_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let output = root.join("audit.jsonl");
        // An absolute runtime configuration that does not load, so the export
        // refuses after staging its temporary file and before publishing.
        let runtime_config = root.join("runtime.yaml");

        assert_eq!(
            export(&runtime_config, &output).unwrap_err(),
            AuditCliError::Operator
        );

        assert!(!output.exists());
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".bregctl-audit-export-")));
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
    fn create_export_file_reports_an_existing_destination_by_its_own_code() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let output = root.join("audit.jsonl");
        std::fs::write(&output, b"occupied\n").unwrap();

        assert_eq!(
            create_export_file(&output).unwrap_err(),
            AuditCliError::OutputExists
        );
    }

    #[test]
    fn export_reports_an_existing_destination_by_its_own_code() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let output = root.join("audit.jsonl");
        std::fs::write(&output, b"occupied\n").unwrap();
        // An absolute runtime configuration that does not load, so a refusal
        // that came from anywhere but the destination would report the
        // operator code instead.
        let runtime_config = root.join("runtime.yaml");

        assert_eq!(
            export(&runtime_config, &output).unwrap_err(),
            AuditCliError::OutputExists
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"occupied\n");
    }

    #[cfg(unix)]
    #[test]
    fn create_export_file_reports_a_symbolic_link_ancestor_by_its_own_code() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let real = root.join("real-parent");
        let linked = root.join("linked-parent");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &linked).unwrap();
        let output = linked.join("audit.jsonl");

        assert!(matches!(
            create_export_file(&output).unwrap_err(),
            AuditCliError::OutputPath(_)
        ));
        assert!(!real.join("audit.jsonl").exists());
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
