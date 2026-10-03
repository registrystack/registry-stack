// SPDX-License-Identifier: Apache-2.0
//! Explicit statistical release mutations through the maintained HTTP client.

use std::path::Path;

use registry_breg::statistics::{ReleaseStatus, ReleaseVersionHeader, WithdrawalReason};
use registry_breg_client::{
    BRegIdempotencyKey, BRegReleaseStatus, BRegWithdrawalReason, BaseRegistryClient,
    BaseRegistryClientConfig, BaseRegistryClientError, BearerToken,
};
use reqwest::Url;

use crate::data_lifecycle::read_access_token;

const STATISTICS_USER_AGENT: &str = "bregctl-statistics";

#[derive(Debug)]
pub(crate) enum StatisticsLifecycleError {
    BRegUrl,
    Token,
    IdempotencyKey,
    Runtime,
    Response,
    Client(BaseRegistryClientError),
}

pub(crate) struct StatisticsPublishRequest<'a> {
    pub breg_url: &'a str,
    pub access_token_file: &'a Path,
    pub dataset: &'a str,
    pub period: &'a str,
    pub status: BRegReleaseStatus,
    pub profile: &'a str,
    pub idempotency_key: &'a str,
}

pub(crate) struct StatisticsWithdrawRequest<'a> {
    pub breg_url: &'a str,
    pub access_token_file: &'a Path,
    pub dataset: &'a str,
    pub period: &'a str,
    pub version: u64,
    pub reason: BRegWithdrawalReason,
    pub profile: &'a str,
    pub idempotency_key: &'a str,
}

pub(crate) fn publish(
    request: StatisticsPublishRequest<'_>,
) -> Result<ReleaseVersionHeader, StatisticsLifecycleError> {
    let key = BRegIdempotencyKey::parse(request.idempotency_key)
        .map_err(|_| StatisticsLifecycleError::IdempotencyKey)?;
    let (client, runtime) = client_and_runtime(request.breg_url, request.access_token_file)?;
    let response = runtime
        .block_on(client.statistics_publish(
            request.dataset,
            request.period,
            request.status,
            request.profile,
            &key,
        ))
        .map_err(StatisticsLifecycleError::Client)?;
    decode_publish_header(
        response.value.as_bytes(),
        request.dataset,
        request.period,
        request.status,
    )
}

pub(crate) fn withdraw(
    request: StatisticsWithdrawRequest<'_>,
) -> Result<ReleaseVersionHeader, StatisticsLifecycleError> {
    let key = BRegIdempotencyKey::parse(request.idempotency_key)
        .map_err(|_| StatisticsLifecycleError::IdempotencyKey)?;
    let (client, runtime) = client_and_runtime(request.breg_url, request.access_token_file)?;
    let response = runtime
        .block_on(client.statistics_withdraw(
            request.dataset,
            request.period,
            request.version,
            request.reason,
            request.profile,
            &key,
        ))
        .map_err(StatisticsLifecycleError::Client)?;
    decode_withdraw_header(
        response.value.as_bytes(),
        request.dataset,
        request.period,
        request.version,
        request.reason,
    )
}

fn client_and_runtime(
    breg_url: &str,
    access_token_file: &Path,
) -> Result<(BaseRegistryClient, tokio::runtime::Runtime), StatisticsLifecycleError> {
    let base_url = Url::parse(breg_url).map_err(|_| StatisticsLifecycleError::BRegUrl)?;
    let config = BaseRegistryClientConfig::new(base_url).with_user_agent(STATISTICS_USER_AGENT);
    let client = BaseRegistryClient::new(config).map_err(|_| StatisticsLifecycleError::BRegUrl)?;
    let token =
        read_access_token(access_token_file).map_err(|_| StatisticsLifecycleError::Token)?;
    let token = BearerToken::new(token).map_err(|_| StatisticsLifecycleError::Token)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| StatisticsLifecycleError::Runtime)?;
    Ok((client.with_bearer_token(token), runtime))
}

fn decode_header(bytes: &[u8]) -> Result<ReleaseVersionHeader, StatisticsLifecycleError> {
    let value = registry_platform_canonical_json::parse_json_strict(bytes)
        .map_err(|_| StatisticsLifecycleError::Response)?;
    serde_json::from_value(value).map_err(|_| StatisticsLifecycleError::Response)
}

fn decode_publish_header(
    bytes: &[u8],
    dataset: &str,
    period: &str,
    status: BRegReleaseStatus,
) -> Result<ReleaseVersionHeader, StatisticsLifecycleError> {
    let header = decode_header(bytes)?;
    let status = match status {
        BRegReleaseStatus::Provisional => ReleaseStatus::Provisional,
        BRegReleaseStatus::Final => ReleaseStatus::Final,
    };
    if header.dataset != dataset
        || header.period != period
        || header.version == 0
        || header.version > i64::MAX as u64
        || header.status != status
        || header.withdrawal.is_some()
    {
        return Err(StatisticsLifecycleError::Response);
    }
    Ok(header)
}

fn decode_withdraw_header(
    bytes: &[u8],
    dataset: &str,
    period: &str,
    version: u64,
    reason: BRegWithdrawalReason,
) -> Result<ReleaseVersionHeader, StatisticsLifecycleError> {
    let header = decode_header(bytes)?;
    let reason = match reason {
        BRegWithdrawalReason::ComputationError => WithdrawalReason::ComputationError,
        BRegWithdrawalReason::SourceDataError => WithdrawalReason::SourceDataError,
        BRegWithdrawalReason::DisclosureRisk => WithdrawalReason::DisclosureRisk,
    };
    if header.dataset != dataset
        || header.period != period
        || header.version != version
        || header
            .withdrawal
            .as_ref()
            .is_none_or(|withdrawal| withdrawal.reason != reason)
    {
        return Err(StatisticsLifecycleError::Response);
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> serde_json::Value {
        serde_json::json!({
            "dataset": "population",
            "period": "2025-01",
            "version": 7,
            "status": "final",
            "snapshot": null,
            "computedAt": "2026-10-03T00:00:00Z",
            "packageDigest": format!("sha256:{}", "1".repeat(64)),
            "definitionDigest": format!("sha256:{}", "2".repeat(64)),
            "contentDigest": format!("sha256:{}", "3".repeat(64)),
        })
    }

    fn encoded(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn publish_response_is_bound_to_the_requested_release() {
        let valid = header();
        assert!(decode_publish_header(
            &encoded(&valid),
            "population",
            "2025-01",
            BRegReleaseStatus::Final,
        )
        .is_ok());
        let maximum_exact_version = i64::MAX as u64 - 1023;
        let mut maximum_version = valid.clone();
        maximum_version["version"] = serde_json::json!(maximum_exact_version);
        assert_eq!(
            decode_header(&encoded(&maximum_version)).unwrap().version,
            maximum_exact_version
        );
        assert!(decode_publish_header(
            &encoded(&maximum_version),
            "population",
            "2025-01",
            BRegReleaseStatus::Final,
        )
        .is_ok());

        let withdrawal = serde_json::json!({
            "withdrawnAt": "2026-10-03T00:01:00Z",
            "reason": "computation-error",
        });
        for (field, value) in [
            ("dataset", serde_json::json!("other-population")),
            ("period", serde_json::json!("2025-02")),
            ("version", serde_json::json!(0)),
            ("version", serde_json::json!(i64::MAX as u64 + 1)),
            ("status", serde_json::json!("provisional")),
            ("withdrawal", withdrawal),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(matches!(
                decode_publish_header(
                    &encoded(&invalid),
                    "population",
                    "2025-01",
                    BRegReleaseStatus::Final,
                ),
                Err(StatisticsLifecycleError::Response)
            ));
        }
    }

    #[test]
    fn withdrawal_response_is_bound_to_the_requested_release_and_reason() {
        let mut valid = header();
        valid["status"] = serde_json::json!("provisional");
        valid["withdrawal"] = serde_json::json!({
            "withdrawnAt": "2026-10-03T00:01:00Z",
            "reason": "computation-error",
        });
        assert!(decode_withdraw_header(
            &encoded(&valid),
            "population",
            "2025-01",
            7,
            BRegWithdrawalReason::ComputationError,
        )
        .is_ok());

        let invalid_cases = [
            ("dataset", serde_json::json!("other-population")),
            ("period", serde_json::json!("2025-02")),
            ("version", serde_json::json!(8)),
            ("withdrawal", serde_json::Value::Null),
            (
                "withdrawal",
                serde_json::json!({
                    "withdrawnAt": "2026-10-03T00:01:00Z",
                    "reason": "source-data-error",
                }),
            ),
        ];
        for (field, value) in invalid_cases {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(matches!(
                decode_withdraw_header(
                    &encoded(&invalid),
                    "population",
                    "2025-01",
                    7,
                    BRegWithdrawalReason::ComputationError,
                ),
                Err(StatisticsLifecycleError::Response)
            ));
        }
    }
}
