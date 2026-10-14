// SPDX-License-Identifier: Apache-2.0

//! Proposal retention operator workflows.
//!
//! The CLI owns argument validation and rendering only. Live retention work is
//! delegated to Base Registry Engine so package, catalog, lock, audit, and SQL
//! boundaries stay in the product runtime.

use std::path::Path;

use registry_breg::proposal_retention::{
    AttachmentCleanup, MAX_PROPOSAL_RETENTION_OPERATOR_PAGE_SIZE, ProposalDetailErasureScope,
    ProposalRetentionDryRun, ProposalRetentionErase, ProposalRetentionError,
    ProposalRetentionListPage, ProposalRetentionOperatorService,
};
use registry_platform_config::PackageDigestMismatch;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProposalRetentionCliError {
    Operator,
    ActiveDetailPinned,
    RetainMode,
    AttachmentStorageBindingMismatch,
    /// The erasure committed without its audit entry.
    ErasureUnaudited,
    /// Another session held the exclusive migration lock past the lock
    /// timeout.
    MigrationLockHeld,
    /// The configured active package does not match the runtime file's
    /// `package.expectedDigest` pin.
    PackagePinMismatch(PackageDigestMismatch),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProposalRetentionListOutcome {
    #[serde(flatten)]
    pub page: ProposalRetentionListPage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProposalRetentionDryRunOutcome {
    #[serde(flatten)]
    pub dry_run: ProposalRetentionDryRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProposalRetentionEraseOutcome {
    #[serde(flatten)]
    pub erase: ProposalRetentionErase,
}

pub(crate) fn list(
    runtime_config: &Path,
    action_id: Option<&str>,
    after_cursor: Option<&str>,
    limit: u16,
) -> Result<ProposalRetentionListOutcome, ProposalRetentionCliError> {
    if !runtime_config.is_absolute()
        || limit == 0
        || limit > MAX_PROPOSAL_RETENTION_OPERATOR_PAGE_SIZE
        || action_id.is_some_and(str::is_empty)
        || after_cursor.is_some_and(str::is_empty)
    {
        return Err(ProposalRetentionCliError::Operator);
    }
    let runtime = operator_runtime()?;
    let page = runtime.block_on(async {
        let service = ProposalRetentionOperatorService::from_runtime_config(runtime_config)
            .await
            .map_err(map_error)?;
        service
            .list(action_id, after_cursor, limit)
            .await
            .map_err(map_error)
    })?;
    Ok(ProposalRetentionListOutcome { page })
}

pub(crate) fn dry_run(
    runtime_config: &Path,
    action_id: &str,
    proposal_id: &str,
    submission_version: i64,
) -> Result<ProposalRetentionDryRunOutcome, ProposalRetentionCliError> {
    if !runtime_config.is_absolute() {
        return Err(ProposalRetentionCliError::Operator);
    }
    let scope = scope(action_id, proposal_id, submission_version)?;
    let runtime = operator_runtime()?;
    let dry_run = runtime.block_on(async {
        let service = ProposalRetentionOperatorService::from_runtime_config(runtime_config)
            .await
            .map_err(map_error)?;
        service.dry_run(scope).await.map_err(map_error)
    })?;
    Ok(ProposalRetentionDryRunOutcome { dry_run })
}

pub(crate) fn erase(
    runtime_config: &Path,
    action_id: &str,
    proposal_id: &str,
    submission_version: i64,
) -> Result<ProposalRetentionEraseOutcome, ProposalRetentionCliError> {
    if !runtime_config.is_absolute() {
        return Err(ProposalRetentionCliError::Operator);
    }
    let scope = scope(action_id, proposal_id, submission_version)?;
    let runtime = operator_runtime()?;
    let erase = runtime.block_on(async {
        let service = ProposalRetentionOperatorService::from_runtime_config(runtime_config)
            .await
            .map_err(map_error)?;
        service.erase(scope).await.map_err(map_error)
    })?;
    Ok(ProposalRetentionEraseOutcome { erase })
}

pub(crate) fn cleanup_attachments(
    runtime_config: &Path,
) -> Result<AttachmentCleanup, ProposalRetentionCliError> {
    if !runtime_config.is_absolute() {
        return Err(ProposalRetentionCliError::Operator);
    }
    operator_runtime()?.block_on(async {
        ProposalRetentionOperatorService::from_runtime_config(runtime_config)
            .await
            .map_err(map_error)?
            .cleanup_attachments()
            .await
            .map_err(map_error)
    })
}

fn scope<'a>(
    action_id: &'a str,
    proposal_id: &str,
    submission_version: i64,
) -> Result<ProposalDetailErasureScope<'a>, ProposalRetentionCliError> {
    if action_id.is_empty() || submission_version <= 0 {
        return Err(ProposalRetentionCliError::Operator);
    }
    let proposal_id =
        Uuid::parse_str(proposal_id).map_err(|_| ProposalRetentionCliError::Operator)?;
    Ok(ProposalDetailErasureScope {
        action_id,
        proposal_id,
        submission_version,
    })
}

fn map_error(error: ProposalRetentionError) -> ProposalRetentionCliError {
    match error {
        ProposalRetentionError::ActiveDetailPinned => ProposalRetentionCliError::ActiveDetailPinned,
        ProposalRetentionError::RetainMode => ProposalRetentionCliError::RetainMode,
        ProposalRetentionError::AttachmentStorageBindingMismatch => {
            ProposalRetentionCliError::AttachmentStorageBindingMismatch
        }
        ProposalRetentionError::ErasureUnaudited => ProposalRetentionCliError::ErasureUnaudited,
        ProposalRetentionError::MigrationLockHeld => ProposalRetentionCliError::MigrationLockHeld,
        ProposalRetentionError::PackagePinMismatch(mismatch) => {
            ProposalRetentionCliError::PackagePinMismatch(mismatch)
        }
        ProposalRetentionError::ActiveProposalRecoveryUnavailable
        | ProposalRetentionError::Unavailable => ProposalRetentionCliError::Operator,
    }
}

fn operator_runtime() -> Result<tokio::runtime::Runtime, ProposalRetentionCliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ProposalRetentionCliError::Operator)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_unaudited_erasure_stays_distinct_from_a_refused_one() {
        assert_eq!(
            map_error(ProposalRetentionError::ErasureUnaudited),
            ProposalRetentionCliError::ErasureUnaudited
        );
    }

    #[test]
    fn a_held_migration_lock_stays_distinct_from_a_refused_operation() {
        assert_eq!(
            map_error(ProposalRetentionError::MigrationLockHeld),
            ProposalRetentionCliError::MigrationLockHeld
        );
    }

    #[test]
    fn attachment_binding_refusal_preserves_actionable_cli_error() {
        assert_eq!(
            map_error(ProposalRetentionError::AttachmentStorageBindingMismatch),
            ProposalRetentionCliError::AttachmentStorageBindingMismatch
        );
    }
}
