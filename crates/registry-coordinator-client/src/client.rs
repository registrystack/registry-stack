// SPDX-License-Identifier: Apache-2.0
use std::fmt;

use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, OutboundOptions, ServiceBaseUrl,
};
use registry_platform_httputil::{read_bounded, validate_response_headers};
use reqwest::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Method, StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

use crate::{
    BearerToken, CoordinatorClientConfig, CoordinatorClientError as Error,
    CoordinatorProtocolFailure as Failure, RunInspection, RunStatus, StartRunRequest, Uuid,
};

const MAXIMUM_REQUEST_BYTES: usize = 65_536;
const MAXIMUM_PROBLEM_BYTES: u64 = 8192;

/// A complete authenticated answer. This product does not define a trace field.
pub struct CoordinatorComplete<T> {
    pub value: T,
}

pub struct CoordinatorClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    max_response_bytes: u64,
}

impl fmt::Debug for CoordinatorClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoordinatorClient")
            .field("base_url", &"<validated service URL>")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl CoordinatorClient {
    pub fn new(config: CoordinatorClientConfig) -> Result<Self, Error> {
        let base_url = config.validate()?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| Error::configuration("the HTTP client could not be built"))?;
        Ok(Self {
            http,
            base_url,
            max_response_bytes: config.max_response_bytes,
        })
    }

    /// Admit once under the caller's exact key. HTTP 200 confirms admission, not
    /// a completed workflow or delivery. A lost reply is recovered by the caller
    /// resending this same request under its original identity and key.
    pub async fn start(
        &self,
        token: &BearerToken,
        key: &str,
        request: &StartRunRequest,
    ) -> Result<CoordinatorComplete<RunStatus>, Error> {
        if request.flow.is_empty()
            || request.flow.len() > 64
            || !request
                .flow
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(Error::invalid_request("the flow identifier is invalid"));
        }
        if key.is_empty() || key.len() > 256 || !key.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(Error::invalid_request("the admission key is invalid"));
        }
        let body = request_bytes(request)?;
        let value: RunStatus = self
            .exchange(token, Method::POST, "v1/runs", Some(key), Some(body))
            .await?;
        if value.workflow_id != request.flow {
            return Err(protocol(200, Failure::Body));
        }
        Ok(CoordinatorComplete { value })
    }

    /// Caller-owned progress. It does not grant authority to a source record.
    pub async fn status(
        &self,
        token: &BearerToken,
        run: Uuid,
    ) -> Result<CoordinatorComplete<RunStatus>, Error> {
        let value: RunStatus = self
            .exchange(token, Method::GET, &format!("v1/runs/{run}"), None, None)
            .await?;
        if value.run_id != run {
            return Err(protocol(200, Failure::Body));
        }
        Ok(CoordinatorComplete { value })
    }

    /// Authorized bounded inspection without prepared command bodies.
    pub async fn inspect(
        &self,
        token: &BearerToken,
        run: Uuid,
    ) -> Result<CoordinatorComplete<RunInspection>, Error> {
        let value: RunInspection = self
            .exchange(
                token,
                Method::GET,
                &format!("v1/runs/{run}/inspect"),
                None,
                None,
            )
            .await?;
        if value.run.run_id != run {
            return Err(protocol(200, Failure::Body));
        }
        Ok(CoordinatorComplete { value })
    }

    /// Observe the original receipt using the runtime's saved command. Requires
    /// independently authorized reconciliation and ownership/operator access.
    /// This is never a command resubmission. Unknown receipts remain uncertain.
    pub async fn reconcile(
        &self,
        token: &BearerToken,
        run: Uuid,
        reason: &str,
    ) -> Result<CoordinatorComplete<RunInspection>, Error> {
        if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
            return Err(Error::invalid_request("the recovery reason is invalid"));
        }
        let value: RunInspection = self
            .exchange(
                token,
                Method::POST,
                &format!("v1/runs/{run}/reconcile"),
                None,
                Some(request_bytes(&json!({"reason":reason}))?),
            )
            .await?;
        if value.run.run_id != run {
            return Err(protocol(200, Failure::Body));
        }
        Ok(CoordinatorComplete { value })
    }

    async fn exchange<T: DeserializeOwned>(
        &self,
        token: &BearerToken,
        method: Method,
        path: &str,
        key: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<T, Error> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| Error::invalid_request("the service path is invalid"))?;
        let mut request = self
            .http
            .request(method, url)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, "application/json");
        if let Some(key) = key {
            request = request.header("idempotency-key", key);
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        // One exchange only. Bridge state, not an invisible SDK loop, owns retries.
        let response = request.send().await.map_err(|e| Error::Transport {
            kind: send_failure_kind(&e),
        })?;
        let status = response.status();
        validate_response_headers(response.headers())
            .map_err(|_| protocol(status.as_u16(), Failure::HeaderBounds))?;
        let media: Vec<_> = response.headers().get_all(CONTENT_TYPE).iter().collect();
        if media.len() != 1 || media[0].to_str().ok() != Some("application/json") {
            return Err(protocol(status.as_u16(), Failure::MediaType));
        }
        let bound = if status == StatusCode::OK {
            self.max_response_bytes
        } else {
            self.max_response_bytes.min(MAXIMUM_PROBLEM_BYTES)
        };
        let bytes = read_bounded(response, bound)
            .await
            .map_err(|e| Error::Transport {
                kind: read_failure_kind(&e),
            })?;
        let value =
            parse_json_strict(&bytes).map_err(|_| protocol(status.as_u16(), Failure::Body))?;
        if status != StatusCode::OK {
            if !status.is_client_error() && !status.is_server_error() {
                return Err(protocol(status.as_u16(), Failure::Status));
            }
            let problem: Problem = serde_json::from_value(value)
                .map_err(|_| protocol(status.as_u16(), Failure::Problem))?;
            if problem.code.is_empty()
                || problem.code.len() > 128
                || !problem.code.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
                || problem.message.is_empty()
                || problem.message.len() > 4096
                || problem
                    .suggested_action
                    .as_ref()
                    .is_some_and(|v| v.len() > 4096)
                || problem_status(&problem.code) != status.as_u16()
            {
                return Err(protocol(status.as_u16(), Failure::Problem));
            }
            // The runtime contract owns an open code string, but never exposes
            // protected values through its prose. Discard all prose regardless.
            return Err(Error::Problem {
                status: status.as_u16(),
                code: problem.code,
            });
        }
        serde_json::from_value(value).map_err(|_| protocol(status.as_u16(), Failure::Body))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Problem {
    code: String,
    message: String,
    suggested_action: Option<String>,
}

fn request_bytes(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| Error::invalid_request("the request cannot be encoded"))?;
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(Error::invalid_request(
            "the request body exceeds the accepted bound",
        ));
    }
    parse_json_strict(&bytes)
        .map_err(|_| Error::invalid_request("the request is not bounded unambiguous JSON"))?;
    Ok(bytes)
}

fn protocol(status: u16, failure: Failure) -> Error {
    Error::Protocol { status, failure }
}

// This is Coordinator's HTTP problem mapping, deliberately separate from other
// products' RFC 9457 problem catalogues. Unknown product conflicts remain 409.
fn problem_status(code: &str) -> u16 {
    match code {
        "access.unauthenticated" => 401,
        "access.unavailable"
        | "store-unavailable"
        | "audit-unavailable"
        | "audit-unready"
        | "audit-response-unavailable" => 503,
        "access.denied" => 403,
        "request.content-type-invalid" => 415,
        "run-absent" | "run-not-found" | "run.not_found" | "run.missing" => 404,
        "input-invalid" | "start-key-invalid" | "request.invalid" | "definition.input"
        | "reason-invalid" | "retention-invalid" => 400,
        _ => 409,
    }
}
