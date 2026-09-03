// SPDX-License-Identifier: Apache-2.0

//! Change-request retention operator workflows.
//!
//! The CLI owns argument validation and rendering only. Live retention work is
//! delegated to Base Registry Engine so package, catalog, lock, audit, and SQL
//! boundaries stay in the product runtime.

use std::path::Path;

use registry_breg::request_retention::{
    RequestDetailErasureScope, RequestRetentionDryRun, RequestRetentionErase,
    RequestRetentionError, RequestRetentionListPage, RequestRetentionOperatorService,
    MAX_REQUEST_RETENTION_OPERATOR_PAGE_SIZE,
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestRetentionCliError {
    Operator,
    ActiveDetailPinned,
    RetainMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestRetentionListOutcome {
    #[serde(flatten)]
    pub page: RequestRetentionListPage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestRetentionDryRunOutcome {
    #[serde(flatten)]
    pub dry_run: RequestRetentionDryRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestRetentionEraseOutcome {
    #[serde(flatten)]
    pub erase: RequestRetentionErase,
}

pub(crate) fn list(
    runtime_config: &Path,
    request_entity: Option<&str>,
    after_cursor: Option<&str>,
    limit: u16,
) -> Result<RequestRetentionListOutcome, RequestRetentionCliError> {
    if !runtime_config.is_absolute()
        || limit == 0
        || limit > MAX_REQUEST_RETENTION_OPERATOR_PAGE_SIZE
        || request_entity.is_some_and(str::is_empty)
        || after_cursor.is_some_and(str::is_empty)
    {
        return Err(RequestRetentionCliError::Operator);
    }
    let runtime = operator_runtime()?;
    let page = runtime
        .block_on(async {
            let service = RequestRetentionOperatorService::from_runtime_config(runtime_config)
                .await
                .map_err(map_error)?;
            service
                .list(request_entity, after_cursor, limit)
                .await
                .map_err(map_error)
        })
        .map_err(|_| RequestRetentionCliError::Operator)?;
    Ok(RequestRetentionListOutcome { page })
}

pub(crate) fn dry_run(
    runtime_config: &Path,
    request_entity: &str,
    request_id: &str,
    proposal_version: i64,
) -> Result<RequestRetentionDryRunOutcome, RequestRetentionCliError> {
    if !runtime_config.is_absolute() {
        return Err(RequestRetentionCliError::Operator);
    }
    let scope = scope(request_entity, request_id, proposal_version)?;
    let runtime = operator_runtime()?;
    let dry_run = runtime
        .block_on(async {
            let service = RequestRetentionOperatorService::from_runtime_config(runtime_config)
                .await
                .map_err(map_error)?;
            service.dry_run(scope).await.map_err(map_error)
        })
        .map_err(|_| RequestRetentionCliError::Operator)?;
    Ok(RequestRetentionDryRunOutcome { dry_run })
}

pub(crate) fn erase(
    runtime_config: &Path,
    request_entity: &str,
    request_id: &str,
    proposal_version: i64,
) -> Result<RequestRetentionEraseOutcome, RequestRetentionCliError> {
    if !runtime_config.is_absolute() {
        return Err(RequestRetentionCliError::Operator);
    }
    let scope = scope(request_entity, request_id, proposal_version)?;
    let runtime = operator_runtime()?;
    let erase = runtime
        .block_on(async {
            let service = RequestRetentionOperatorService::from_runtime_config(runtime_config)
                .await
                .map_err(map_error)?;
            service.erase(scope).await.map_err(map_error)
        })
        .map_err(|_| RequestRetentionCliError::Operator)?;
    Ok(RequestRetentionEraseOutcome { erase })
}

fn scope<'a>(
    request_entity: &'a str,
    request_id: &str,
    proposal_version: i64,
) -> Result<RequestDetailErasureScope<'a>, RequestRetentionCliError> {
    if request_entity.is_empty() || proposal_version <= 0 {
        return Err(RequestRetentionCliError::Operator);
    }
    let request_id = Uuid::parse_str(request_id).map_err(|_| RequestRetentionCliError::Operator)?;
    Ok(RequestDetailErasureScope {
        request_entity_id: request_entity,
        request_id,
        proposal_version,
    })
}

fn map_error(error: RequestRetentionError) -> RequestRetentionCliError {
    match error {
        RequestRetentionError::ActiveDetailPinned => RequestRetentionCliError::ActiveDetailPinned,
        RequestRetentionError::RetainMode => RequestRetentionCliError::RetainMode,
        RequestRetentionError::ActiveProposalRequiresRebase
        | RequestRetentionError::Unavailable => RequestRetentionCliError::Operator,
    }
}

fn operator_runtime() -> Result<tokio::runtime::Runtime, RequestRetentionCliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| RequestRetentionCliError::Operator)
}
