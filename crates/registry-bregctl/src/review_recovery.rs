// SPDX-License-Identifier: Apache-2.0

//! Operator recovery for a change-request review its authority will not answer.
//!
//! The CLI owns argument validation and rendering only. The recovery itself is
//! delegated to Base Registry Engine so package, catalog, lock, audit, and SQL
//! boundaries stay in the product runtime.

use std::path::Path;

use registry_breg::review_recovery::{
    ReviewRecovery, ReviewRecoveryError, ReviewRecoveryOperatorService, ReviewRecoveryScope,
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReviewRecoveryCliError {
    Operator,
    NotFound,
    Ineligible {
        reason: &'static str,
        state: String,
        code: Option<String>,
    },
    RecoveryUnaudited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewRecoveryOperation {
    Resubmit,
    Close,
    RetryApplication,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewRecoveryOutcome {
    #[serde(flatten)]
    pub recovery: ReviewRecovery,
}

pub(crate) fn recover(
    operation: ReviewRecoveryOperation,
    runtime_config: &Path,
    request_entity: &str,
    request_id: &str,
    proposal_version: i64,
) -> Result<ReviewRecoveryOutcome, ReviewRecoveryCliError> {
    if !runtime_config.is_absolute() || request_entity.is_empty() || proposal_version <= 0 {
        return Err(ReviewRecoveryCliError::Operator);
    }
    let request_id = Uuid::parse_str(request_id).map_err(|_| ReviewRecoveryCliError::Operator)?;
    let scope = ReviewRecoveryScope {
        request_entity_id: request_entity,
        request_id,
        proposal_version,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ReviewRecoveryCliError::Operator)?;
    let recovery = runtime.block_on(async {
        let service = ReviewRecoveryOperatorService::from_runtime_config(runtime_config)
            .await
            .map_err(map_error)?;
        match operation {
            ReviewRecoveryOperation::Resubmit => service.resubmit(scope).await,
            ReviewRecoveryOperation::Close => service.close(scope).await,
            ReviewRecoveryOperation::RetryApplication => service.retry_application(scope).await,
        }
        .map_err(map_error)
    })?;
    Ok(ReviewRecoveryOutcome { recovery })
}

fn map_error(error: ReviewRecoveryError) -> ReviewRecoveryCliError {
    match error {
        ReviewRecoveryError::Unavailable => ReviewRecoveryCliError::Operator,
        ReviewRecoveryError::NotFound => ReviewRecoveryCliError::NotFound,
        ReviewRecoveryError::Ineligible {
            reason,
            state,
            code,
        } => ReviewRecoveryCliError::Ineligible {
            reason: reason.as_str(),
            state,
            code,
        },
        ReviewRecoveryError::RecoveryUnaudited => ReviewRecoveryCliError::RecoveryUnaudited,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_breg::review_recovery::ReviewRecoveryRefusal;

    #[test]
    fn ineligible_refusal_keeps_its_reason_state_and_code() {
        assert_eq!(
            map_error(ReviewRecoveryError::Ineligible {
                reason: ReviewRecoveryRefusal::RequestErased,
                state: "failed".to_owned(),
                code: Some("result-poll-attempts-exhausted".to_owned()),
            }),
            ReviewRecoveryCliError::Ineligible {
                reason: "request-erased",
                state: "failed".to_owned(),
                code: Some("result-poll-attempts-exhausted".to_owned()),
            }
        );
    }

    #[test]
    fn an_unaudited_recovery_stays_distinct_from_a_refused_one() {
        assert_eq!(
            map_error(ReviewRecoveryError::RecoveryUnaudited),
            ReviewRecoveryCliError::RecoveryUnaudited
        );
    }

    #[test]
    fn a_relative_configuration_or_malformed_scope_is_refused_before_any_connection() {
        for (config, entity, id, version) in [
            (
                "runtime.yaml",
                "e",
                "00000000-0000-0000-0000-000000000001",
                1,
            ),
            (
                "/runtime.yaml",
                "",
                "00000000-0000-0000-0000-000000000001",
                1,
            ),
            ("/runtime.yaml", "e", "not-a-uuid", 1),
            (
                "/runtime.yaml",
                "e",
                "00000000-0000-0000-0000-000000000001",
                0,
            ),
        ] {
            assert_eq!(
                recover(
                    ReviewRecoveryOperation::Close,
                    Path::new(config),
                    entity,
                    id,
                    version
                ),
                Err(ReviewRecoveryCliError::Operator)
            );
        }
    }
}
