// SPDX-License-Identifier: Apache-2.0

//! Audit journal operator workflows.
//!
//! The CLI owns argument validation, export file creation, and rendering only.
//! Chain traversal, verification, and retention are delegated to Base Registry
//! Engine so package, catalog, lock, role, and SQL boundaries stay in the
//! product runtime. Refusals carry a closed code and no operator value.

use std::fs::File;
use std::io::BufWriter;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use registry_breg::audit_tooling::{
    AuditExport, AuditOperatorService, AuditPrune, AuditPruneBoundary, AuditToolingError,
    AuditVerification,
};
use serde::Serialize;
use tempfile::{Builder, NamedTempFile};

/// Owner-only permissions for an export the operator has not yet placed.
#[cfg(unix)]
const EXPORT_FILE_MODE: u32 = 0o600;

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
    let mut temporary = create_export_file(output)?;
    let export = {
        let mut sink = BufWriter::new(temporary.as_file_mut());
        let export = runtime.block_on(async {
            let service = service(runtime_config).await?;
            service.export(&mut sink).await.map_err(map_error)
        });
        export.and_then(|export| finish_export_file(sink).map(|()| export))?
    };
    publish_export_file(temporary, output)?;
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

fn create_export_file(output: &Path) -> Result<NamedTempFile, AuditCliError> {
    let parent = output.parent().ok_or(AuditCliError::Operator)?;
    let temporary = Builder::new()
        .prefix(".bregctl-audit-export-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|_| AuditCliError::Operator)?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(EXPORT_FILE_MODE))
        .map_err(|_| AuditCliError::Operator)?;
    Ok(temporary)
}

fn finish_export_file(sink: BufWriter<&mut File>) -> Result<(), AuditCliError> {
    let file = sink.into_inner().map_err(|_| AuditCliError::Operator)?;
    file.sync_all().map_err(|_| AuditCliError::Operator)
}

fn publish_export_file(temporary: NamedTempFile, output: &Path) -> Result<(), AuditCliError> {
    temporary
        .persist_noclobber(output)
        .map_err(|_| AuditCliError::Operator)?;
    #[cfg(unix)]
    File::open(output.parent().ok_or(AuditCliError::Operator)?)
        .and_then(|parent| parent.sync_all())
        .map_err(|_| AuditCliError::Operator)?;
    Ok(())
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
        let output = directory.path().join("audit.jsonl");
        let mut temporary = create_export_file(&output).unwrap();
        let temporary_path = temporary.path().to_owned();
        assert!(!output.exists());

        {
            let mut sink = BufWriter::new(temporary.as_file_mut());
            sink.write_all(b"verified\n").unwrap();
            finish_export_file(sink).unwrap();
        }
        assert!(!output.exists());
        publish_export_file(temporary, &output).unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), b"verified\n");
        assert!(!temporary_path.exists());
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
}
