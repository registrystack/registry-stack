// SPDX-License-Identifier: Apache-2.0
//! Operator lifecycle for the instance claim a restored copy must adopt.
//!
//! The command verifies the active package binding from the runtime
//! configuration and delegates every read and write to
//! `registry_breg::instance_claim`. Adoption verifies the audit chain and
//! moves the claim under the migration authority in one transaction.

use std::path::Path;

use registry_breg::instance_claim::{
    InstanceClaimAdoption, InstanceClaimError, InstanceClaimService, InstanceClaimStatus,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstanceClaimCliError {
    RuntimeConfigPath,
    Claim(InstanceClaimError),
}

pub(crate) fn status(runtime_config: &Path) -> Result<InstanceClaimStatus, InstanceClaimCliError> {
    runtime_config_path(runtime_config)?;
    block_on(async {
        service(runtime_config)
            .await?
            .status()
            .await
            .map_err(InstanceClaimCliError::Claim)
    })
}

pub(crate) fn adopt(runtime_config: &Path) -> Result<InstanceClaimAdoption, InstanceClaimCliError> {
    runtime_config_path(runtime_config)?;
    block_on(async {
        service(runtime_config)
            .await?
            .adopt()
            .await
            .map_err(InstanceClaimCliError::Claim)
    })
}

fn runtime_config_path(path: &Path) -> Result<(), InstanceClaimCliError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(InstanceClaimCliError::RuntimeConfigPath)
    }
}

async fn service(runtime_config: &Path) -> Result<InstanceClaimService, InstanceClaimCliError> {
    InstanceClaimService::from_runtime_config(runtime_config)
        .await
        .map_err(InstanceClaimCliError::Claim)
}

fn block_on<T>(
    future: impl std::future::Future<Output = Result<T, InstanceClaimCliError>>,
) -> Result<T, InstanceClaimCliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| InstanceClaimCliError::Claim(InstanceClaimError::Unavailable))?
        .block_on(future)
}
