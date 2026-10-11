// SPDX-License-Identifier: Apache-2.0
use std::fmt;

use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httputil::client::{
    build_client, classify_keyed_attempt, read_failure_kind, retry_keyed_mutation,
    send_failure_kind, KeyedMutationAttempt, OutboundOptions, RetryAfter, ServiceBaseUrl,
};
use registry_platform_httputil::{read_bounded, validate_response_headers};
use reqwest::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Method, RequestBuilder, Response, StatusCode,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

use crate::{
    BearerToken, CoordinatorClientConfig, CoordinatorClientError as Error,
    CoordinatorProtocolFailure as Failure, RetryScheduled, RunInspection, RunList, RunStatus,
    StartRunRequest, Uuid,
};

const MAXIMUM_REQUEST_BYTES: usize = 65_536;
const MAXIMUM_PROBLEM_BYTES: u64 = 8192;
const MAXIMUM_LIST_LIMIT: u32 = 100;

/// A complete authenticated answer. This product does not define a trace field.
pub struct CoordinatorComplete<T> {
    pub value: T,
}

pub struct CoordinatorClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    max_response_bytes: u64,
    max_mutation_retries: u8,
}

impl fmt::Debug for CoordinatorClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoordinatorClient")
            .field("base_url", &"<validated service URL>")
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_mutation_retries", &self.max_mutation_retries)
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
            max_mutation_retries: config.max_mutation_retries,
        })
    }

    /// Admit `{flow, input}` under the caller's exact key. HTTP 200 confirms
    /// admission, not a completed workflow or delivery. The runtime answers
    /// the same run again for the same caller, flow, key and input, and
    /// refuses the same key with a different input.
    ///
    /// The caller chooses the key; the client never invents one. When the
    /// outcome is unknown, after a timeout or broken exchange or on a 5xx
    /// answer, the client resends the identical request under the same key,
    /// at most `CoordinatorClientConfig::with_max_mutation_retries` times (2
    /// by default; 0 disables it). An error for which
    /// `CoordinatorClientError::is_outcome_unknown` is true may still have
    /// admitted a run: recover with the same identity, key and input, never a
    /// new key.
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
        let prepared = self.prepare(token, Method::POST, "v1/runs", Some(key), Some(body))?;
        let prepared = &prepared;
        let flow = request.flow.as_str();
        let value = retry_keyed_mutation(self.max_mutation_retries, || async move {
            let Some(attempt) = prepared.try_clone() else {
                return KeyedMutationAttempt::Settled(Err(Error::invalid_request(
                    "the request could not be prepared for sending",
                )));
            };
            let response = match self.send(attempt).await {
                Ok(response) => response,
                Err(error) => return keyed_attempt(Err(error), None, RetryAfter::Absent),
            };
            let status = response.status();
            let retry_after = RetryAfter::from_headers(response.headers());
            let answer = self.answer::<RunStatus>(response).await.and_then(|value| {
                if value.workflow_id == flow {
                    Ok(value)
                } else {
                    Err(protocol(status.as_u16(), Failure::Body))
                }
            });
            keyed_attempt(answer, Some(status), retry_after)
        })
        .await?;
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

    /// The latest runs the caller may read, newest admission first. `limit`
    /// is 1 to 100 and is checked before sending; there is no cursor.
    pub async fn list(
        &self,
        token: &BearerToken,
        limit: u32,
    ) -> Result<CoordinatorComplete<RunList>, Error> {
        if !(1..=MAXIMUM_LIST_LIMIT).contains(&limit) {
            return Err(Error::invalid_request("the list limit is outside 1..=100"));
        }
        let request = self
            .prepare(token, Method::GET, "v1/runs", None, None)?
            .query(&[("limit", limit)]);
        let value: RunList = self.answer(self.send(request).await?).await?;
        if value.runs.len() > limit as usize {
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
        let value: RunInspection = self
            .exchange(
                token,
                Method::POST,
                &format!("v1/runs/{run}/reconcile"),
                None,
                Some(reason_body(reason)?),
            )
            .await?;
        if value.run.run_id != run {
            return Err(protocol(200, Failure::Body));
        }
        Ok(CoordinatorComplete { value })
    }

    /// Schedule the run's saved command again, unchanged, when its inspection
    /// allows a retry. The route takes no idempotency key, so the client sends
    /// it exactly once: after an error for which
    /// `CoordinatorClientError::is_outcome_unknown` is true, `inspect` the run
    /// before asking again.
    pub async fn retry_same(
        &self,
        token: &BearerToken,
        run: Uuid,
        reason: &str,
    ) -> Result<CoordinatorComplete<RetryScheduled>, Error> {
        let value: RetryScheduled = self
            .exchange(
                token,
                Method::POST,
                &format!("v1/runs/{run}/retry-same"),
                None,
                Some(reason_body(reason)?),
            )
            .await?;
        if value.run_id != run || value.status != "retry-scheduled" {
            return Err(protocol(200, Failure::Body));
        }
        Ok(CoordinatorComplete { value })
    }

    /// Stop further progression. Cancellation never undoes a product effect,
    /// and an effect in flight stays uncertain until a receipt is observed.
    /// The route takes no idempotency key, so the client sends it exactly
    /// once: after an error for which `CoordinatorClientError::is_outcome_unknown`
    /// is true, read `status` before asking again.
    pub async fn cancel(
        &self,
        token: &BearerToken,
        run: Uuid,
        reason: &str,
    ) -> Result<CoordinatorComplete<RunStatus>, Error> {
        let value: RunStatus = self
            .exchange(
                token,
                Method::POST,
                &format!("v1/runs/{run}/cancel"),
                None,
                Some(reason_body(reason)?),
            )
            .await?;
        if value.run_id != run {
            return Err(protocol(200, Failure::Body));
        }
        Ok(CoordinatorComplete { value })
    }

    /// One exchange, never resent.
    async fn exchange<T: DeserializeOwned>(
        &self,
        token: &BearerToken,
        method: Method,
        path: &str,
        key: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<T, Error> {
        let request = self.prepare(token, method, path, key, body)?;
        let response = self.send(request).await?;
        self.answer(response).await
    }

    fn prepare(
        &self,
        token: &BearerToken,
        method: Method,
        path: &str,
        key: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<RequestBuilder, Error> {
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
        Ok(request)
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response, Error> {
        let response = request.send().await.map_err(|e| Error::Transport {
            kind: send_failure_kind(&e),
        })?;
        validate_response_headers(response.headers())
            .map_err(|_| protocol(response.status().as_u16(), Failure::HeaderBounds))?;
        Ok(response)
    }

    async fn answer<T: DeserializeOwned>(&self, response: Response) -> Result<T, Error> {
        let status = response.status();
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

/// A `{reason}` body within the runtime's bound: 1 to 256 bytes, no control
/// characters. Refused before sending.
fn reason_body(reason: &str) -> Result<Vec<u8>, Error> {
    if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
        return Err(Error::invalid_request("the reason is invalid"));
    }
    request_bytes(&json!({ "reason": reason }))
}

fn protocol(status: u16, failure: Failure) -> Error {
    Error::Protocol { status, failure }
}

/// Classify one admission attempt for the same-key retry, with the shared
/// rule. `status` and `retry_after` describe the answer, when one arrived.
fn keyed_attempt<T>(
    result: Result<T, Error>,
    status: Option<StatusCode>,
    retry_after: RetryAfter,
) -> KeyedMutationAttempt<T, Error> {
    classify_keyed_attempt(
        result,
        status,
        retry_after,
        Error::is_outcome_unknown,
        Error::resend_may_settle,
    )
}
