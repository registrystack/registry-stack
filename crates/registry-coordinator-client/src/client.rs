// SPDX-License-Identifier: Apache-2.0
use std::fmt;

use registry_platform_canonical_json::parse_json_strict;
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, classify_keyed_attempt, read_failure_kind, retry_keyed_mutation,
    send_failure_kind, KeyedMutationAttempt, OutboundOptions, RetryAfter, ServiceBaseUrl,
};
use registry_platform_httputil::{read_bounded, validate_response_headers};
use reqwest::{
    header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Method, RequestBuilder, Response, StatusCode,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;

use crate::{
    BearerToken, CoordinatorClientConfig, CoordinatorClientError as Error,
    CoordinatorProtocolFailure as Failure, RetryScheduled, RunInspection, RunList, RunListQuery,
    RunStatus, StartRunRequest, Uuid, WorkflowContract,
};

const MAXIMUM_REQUEST_BYTES: usize = 65_536;
const MAXIMUM_PROBLEM_BYTES: u64 = 8192;
const MAXIMUM_LIST_LIMIT: u32 = 100;
const MAXIMUM_LIST_CURSOR_BYTES: usize = 4096;
const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
/// The problem type namespace the runtime pins: a problem's `type` is its
/// code under this base, with each `.` read as a path separator.
const PROBLEM_TYPE_BASE: &str = "https://id.registrystack.org/problems/registry-coordinator/";

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

    /// Admit `{workflow, workflowRevision, input}` under the caller's exact key. HTTP 200 confirms
    /// admission, not a completed workflow or delivery. The runtime answers
    /// the same run again for the same caller, workflow, key, revision and input, and
    /// refuses conflicting revision or input. Fresh starts must match the active revision.
    ///
    /// The caller chooses the key; the client never invents one. When the
    /// outcome is unknown, after a timeout or broken exchange or on a 5xx
    /// answer, the client resends the identical request under the same key,
    /// at most `CoordinatorClientConfig::with_max_mutation_retries` times (2
    /// by default; 0 disables it). An error for which
    /// `CoordinatorClientError::is_outcome_unknown` is true may still have
    /// admitted a run: recover with the same identity, key, workflow, revision and
    /// input even after activation changes, never a new key.
    pub async fn start(
        &self,
        token: &BearerToken,
        key: &str,
        request: &StartRunRequest,
    ) -> Result<CoordinatorComplete<RunStatus>, Error> {
        if request.workflow.is_empty()
            || request.workflow.len() > 64
            || !request
                .workflow
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(Error::invalid_request("the workflow identifier is invalid"));
        }
        if key.is_empty() || key.len() > 256 || !key.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(Error::invalid_request("the admission key is invalid"));
        }
        if !valid_revision(&request.workflow_revision) {
            return Err(Error::invalid_request("the workflow revision is invalid"));
        }
        let body = request_bytes(request)?;
        let prepared = self.prepare(token, Method::POST, "v1/runs", Some(key), Some(body))?;
        let prepared = &prepared;
        let workflow = request.workflow.as_str();
        let revision = request.workflow_revision.as_str();
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
                if value.workflow == workflow && value.workflow_revision == revision {
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

    /// Discover the active revision and resolved input/outcome contracts under
    /// current start authority. This performs one bounded read and starts no run.
    pub async fn workflow(
        &self,
        token: &BearerToken,
        workflow: &str,
    ) -> Result<CoordinatorComplete<WorkflowContract>, Error> {
        if !valid_workflow(workflow) {
            return Err(Error::invalid_request("the workflow identifier is invalid"));
        }
        let value: WorkflowContract = self
            .exchange(
                token,
                Method::GET,
                &format!("v1/workflows/{workflow}"),
                None,
                None,
            )
            .await?;
        if value.workflow != workflow
            || !valid_revision(&value.workflow_revision)
            || value.outcomes.is_empty()
            || value.outcomes.len() > 64
        {
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

    /// The first page of runs the caller may read, newest admission first.
    /// `limit` is 1 to 100 and is checked before sending.
    pub async fn list(
        &self,
        token: &BearerToken,
        limit: u32,
    ) -> Result<CoordinatorComplete<RunList>, Error> {
        self.list_page(token, &RunListQuery::new(limit)).await
    }

    /// One stable page of caller-visible runs under an optional state or
    /// attention filter. Pass `next_cursor` back unchanged with the same
    /// filters and caller.
    pub async fn list_page(
        &self,
        token: &BearerToken,
        query: &RunListQuery,
    ) -> Result<CoordinatorComplete<RunList>, Error> {
        if !(1..=MAXIMUM_LIST_LIMIT).contains(&query.limit)
            || query
                .cursor
                .as_deref()
                .is_some_and(|cursor| !valid_cursor(cursor))
        {
            return Err(Error::invalid_request("the run list query is invalid"));
        }
        let mut parameters = vec![("limit", query.limit.to_string())];
        if let Some(cursor) = &query.cursor {
            parameters.push(("cursor", cursor.clone()));
        }
        if let Some(state) = query.state {
            parameters.push(("state", state.as_str().to_owned()));
        }
        if let Some(attention) = query.attention {
            parameters.push(("attention", attention.to_string()));
        }
        let request = self
            .prepare(token, Method::GET, "v1/runs", None, None)?
            .query(&parameters);
        let value: RunList = self.answer(self.send(request).await?).await?;
        if value.runs.len() > query.limit as usize
            || value.runs.iter().any(|run| {
                query.state.is_some_and(|state| run.state != state.as_str())
                    || query.attention.is_some_and(|attention| {
                        attention != matches!(run.state.as_str(), "attention" | "failed")
                    })
            })
            || value.runs.windows(2).any(|pair| {
                (pair[0].admitted_at, pair[0].run_id) <= (pair[1].admitted_at, pair[1].run_id)
            })
            || value.next_cursor.as_deref().is_some_and(|cursor| {
                !valid_cursor(cursor)
                    || value.runs.len() != query.limit as usize
                    || query.cursor.as_deref() == Some(cursor)
            })
        {
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
            .header(ACCEPT, JSON_MEDIA_TYPE);
        if let Some(key) = key {
            request = request.header("idempotency-key", key);
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, JSON_MEDIA_TYPE).body(body);
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
        if status != StatusCode::OK {
            return Err(self.problem(response).await);
        }
        if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
            return Err(protocol(status.as_u16(), Failure::MediaType));
        }
        let bytes = read_bounded(response, self.max_response_bytes)
            .await
            .map_err(|e| Error::Transport {
                kind: read_failure_kind(&e),
            })?;
        let value =
            parse_json_strict(&bytes).map_err(|_| protocol(status.as_u16(), Failure::Body))?;
        serde_json::from_value(value).map_err(|_| protocol(status.as_u16(), Failure::Body))
    }

    /// A refusal is a product problem only when the answer is an exact
    /// RFC 9457 document under the problem media type whose status equals the
    /// answer's, whose `traceId` equals the answer's `traceparent` trace, and
    /// whose `type` is its well-formed code under the runtime's namespace.
    /// Anything else is the edge or a defect talking: a protocol failure.
    ///
    /// The client has no copy of the runtime's vocabulary, so it checks the
    /// code's grammar, not its membership, and carries the code as the
    /// runtime spelled it. The title and detail are read and discarded.
    async fn problem(&self, response: Response) -> Error {
        let status = response.status();
        if !status.is_client_error() && !status.is_server_error() {
            return protocol(status.as_u16(), Failure::Status);
        }
        if !exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
            return protocol(status.as_u16(), Failure::MediaType);
        }
        let trace = response_trace_id(response.headers()).ok();
        let bound = self.max_response_bytes.min(MAXIMUM_PROBLEM_BYTES);
        let bytes = match read_bounded(response, bound).await {
            Ok(bytes) => bytes,
            Err(error) => {
                return Error::Transport {
                    kind: read_failure_kind(&error),
                }
            }
        };
        if parse_json_strict(&bytes).is_err() {
            return protocol(status.as_u16(), Failure::Problem);
        }
        let Ok(document) = ProblemDocument::parse_exact(&bytes, MAXIMUM_PROBLEM_BYTES as usize)
        else {
            return protocol(status.as_u16(), Failure::Problem);
        };
        if document.status != status.as_u16()
            || trace.as_ref().map(|trace| trace.as_str()) != Some(document.trace_id.as_str())
            || !well_formed_code(&document.code)
            || document.type_uri
                != format!("{PROBLEM_TYPE_BASE}{}", document.code.replace('.', "/"))
        {
            return protocol(status.as_u16(), Failure::Problem);
        }
        Error::Problem {
            status: status.as_u16(),
            code: document.code,
        }
    }
}

/// The runtime's code grammar, `family.reason`: two lowercase kebab-case
/// words joined by one dot.
fn well_formed_code(code: &str) -> bool {
    let word = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
            && !part.starts_with('-')
            && !part.ends_with('-')
    };
    code.len() <= 128
        && code
            .split_once('.')
            .is_some_and(|(family, reason)| word(family) && word(reason))
}

fn exact_media_type(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None) if value.as_bytes() == expected.as_bytes()
    )
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= MAXIMUM_LIST_CURSOR_BYTES
        && !cursor.chars().any(char::is_control)
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

fn valid_workflow(workflow: &str) -> bool {
    !workflow.is_empty()
        && workflow.len() <= 64
        && workflow
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn valid_revision(revision: &str) -> bool {
    revision.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    })
}
