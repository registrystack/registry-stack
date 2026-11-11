// SPDX-License-Identifier: Apache-2.0
//! Bounded authenticated driver for one managed external refresh plan.

use std::path::Path;
use std::time::{Duration, Instant};

use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httputil::client::{
    build_client, OutboundOptions, ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT,
};
use registry_platform_httputil::{read_bounded, validate_response_headers};
use registry_platform_yaml::LocalId;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::data_lifecycle::read_access_token;

const USER_AGENT: &str = "bregctl-external-refresh";
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
const MAXIMUM_RESPONSE_BYTES: u64 = 64 * 1024;

pub(crate) struct ExternalRefreshRequest<'a> {
    pub(crate) breg_url: &'a str,
    pub(crate) plan: &'a str,
    pub(crate) access_token_file: &'a Path,
    pub(crate) start_sweep: bool,
    pub(crate) maximum_run: Duration,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExternalRefreshOutcome {
    pub(crate) plan: String,
    pub(crate) steps: u64,
    pub(crate) result: ExternalRefreshStepReport,
}

/// The value-free aggregate fields one step is allowed to reach CLI output.
/// Unknown additive response members are accepted but discarded.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExternalRefreshStepReport {
    more_work: bool,
    #[serde(default)]
    processed: u64,
    #[serde(default)]
    published: u64,
    #[serde(default)]
    reused: u64,
    #[serde(default)]
    unavailable: u64,
    #[serde(default)]
    retried: u64,
    #[serde(default)]
    settled: u64,
    #[serde(default)]
    sweep_completed: bool,
    #[serde(default)]
    sweep_acquisition_failures: u64,
}

impl ExternalRefreshStepReport {
    pub(crate) const fn more_work(&self) -> bool {
        self.more_work
    }
}

#[derive(Debug)]
pub(crate) enum ExternalRefreshError {
    BRegUrl,
    Plan,
    Token,
    Runtime,
    Transport,
    Refused,
    Response,
}

pub(crate) fn run(
    request: ExternalRefreshRequest<'_>,
) -> Result<ExternalRefreshOutcome, ExternalRefreshError> {
    let plan = LocalId::new(request.plan).map_err(|_| ExternalRefreshError::Plan)?;
    let base = Url::parse(request.breg_url).map_err(|_| ExternalRefreshError::BRegUrl)?;
    let base = ServiceBaseUrl::new(base).map_err(|_| ExternalRefreshError::BRegUrl)?;
    let endpoint = base
        .join(&format!("v1/external-refresh-plans/{}/step", plan.as_str()))
        .map_err(|_| ExternalRefreshError::BRegUrl)?;
    let token =
        read_access_token(request.access_token_file).map_err(|_| ExternalRefreshError::Token)?;
    let client = build_client(OutboundOptions {
        request_timeout: ATTEMPT_TIMEOUT,
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        user_agent: Some(USER_AGENT),
        trusted_root_certificates: None,
    })
    .map_err(|_| ExternalRefreshError::Transport)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ExternalRefreshError::Runtime)?;
    runtime.block_on(drive(
        &client,
        endpoint,
        &token,
        plan.as_str(),
        request.start_sweep,
        request.maximum_run,
    ))
}

async fn drive(
    client: &Client,
    endpoint: Url,
    token: &str,
    plan: &str,
    start_sweep: bool,
    maximum_run: Duration,
) -> Result<ExternalRefreshOutcome, ExternalRefreshError> {
    let deadline = Instant::now()
        .checked_add(maximum_run)
        .ok_or(ExternalRefreshError::Runtime)?;
    let mut first = true;
    let mut steps = 0_u64;
    let mut result = ExternalRefreshStepReport::default();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let body = if first && start_sweep {
            json!({"startSweep": true})
        } else {
            json!({})
        };
        first = false;
        result = step(
            client,
            endpoint.clone(),
            token,
            &body,
            remaining.min(ATTEMPT_TIMEOUT),
        )
        .await?;
        steps = steps.checked_add(1).ok_or(ExternalRefreshError::Response)?;
        if !result.more_work || Instant::now() >= deadline {
            break;
        }
    }
    Ok(ExternalRefreshOutcome {
        plan: plan.to_owned(),
        steps,
        result,
    })
}

async fn step(
    client: &Client,
    endpoint: Url,
    token: &str,
    body: &Value,
    timeout: Duration,
) -> Result<ExternalRefreshStepReport, ExternalRefreshError> {
    let response = client
        .post(endpoint)
        .timeout(timeout)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(body).map_err(|_| ExternalRefreshError::Response)?)
        .send()
        .await
        .map_err(|_| ExternalRefreshError::Transport)?;
    validate_response_headers(response.headers()).map_err(|_| ExternalRefreshError::Response)?;
    if !response.status().is_success() {
        return Err(ExternalRefreshError::Refused);
    }
    let bytes = read_bounded(response, MAXIMUM_RESPONSE_BYTES)
        .await
        .map_err(|_| ExternalRefreshError::Response)?;
    let value = parse_json_strict(&bytes).map_err(|_| ExternalRefreshError::Response)?;
    serde_json::from_value(value).map_err(|_| ExternalRefreshError::Response)
}
