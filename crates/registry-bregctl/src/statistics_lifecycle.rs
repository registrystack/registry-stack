// SPDX-License-Identifier: Apache-2.0
//! Explicit statistical release mutations through the maintained HTTP client.

use std::path::Path;

use registry_breg::statistics::ReleaseVersionHeader;
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
    decode_header(response.value.as_bytes())
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
    decode_header(response.value.as_bytes())
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
