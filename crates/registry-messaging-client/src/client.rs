// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use registry_messaging_core::{
    type_uri, MessageView, ProblemCode, HEALTH_PATH, MESSAGE_PATH, READY_PATH,
};
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, BearerToken, OutboundOptions,
    ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, url::append_path_segments, validate_response_headers,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Response, StatusCode, Url};

use crate::{MessagingClientConfig, MessagingClientError, MessagingProtocolFailure};

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;

/// One completed call: the answered value and the response's validated trace
/// identifier, so a caller correlates the answer with its own trace context
/// without re-reading headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessagingComplete<T> {
    pub value: T,
    pub trace_id: String,
}

pub struct MessagingClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    max_response_bytes: u64,
}

impl fmt::Debug for MessagingClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessagingClient")
            .field("base_url", &"<validated service URL>")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl MessagingClient {
    pub fn new(config: MessagingClientConfig) -> Result<Self, MessagingClientError> {
        let base_url = config.validate()?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| MessagingClientError::configuration("the HTTP client could not be built"))?;
        Ok(Self {
            http,
            base_url,
            max_response_bytes: config.max_response_bytes,
        })
    }

    /// Whether the process answers at all. Liveness says nothing about the
    /// store; use `ready` for that.
    pub async fn health(&self) -> Result<MessagingComplete<()>, MessagingClientError> {
        self.get_empty(HEALTH_PATH).await
    }

    /// Whether the runtime can serve: its store is reachable and carries
    /// exactly the schema this runtime expects. A runtime that is not ready
    /// answers the typed `ProblemCode::ServiceUnavailable`.
    pub async fn ready(&self) -> Result<MessagingComplete<()>, MessagingClientError> {
        self.get_empty(READY_PATH).await
    }

    /// One message as the caller may see it: its derived status, the
    /// dispatch state and delivery report that status is derived from, and
    /// its attempt summaries. A message the caller may not see answers the
    /// typed `ProblemCode::MessageNotVisible`, exactly as one that does not
    /// exist.
    ///
    /// `message_id` is the identifier the runtime answered on acceptance,
    /// in its lowercase hyphenated form; any other value is refused before
    /// a request is sent.
    pub async fn message(
        &self,
        token: &BearerToken,
        message_id: &str,
    ) -> Result<MessagingComplete<MessageView>, MessagingClientError> {
        if !is_message_id(message_id) {
            return Err(MessagingClientError::invalid_request(
                "the message identifier is not a lowercase hyphenated UUID",
            ));
        }
        let path = MESSAGE_PATH.replace("{message_id}", message_id);
        let request = self
            .http
            .get(self.url_from_constant(&path)?)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE);
        self.get_view(request).await
    }

    fn url_from_constant(&self, path: &str) -> Result<Url, MessagingClientError> {
        let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        append_path_segments(self.base_url.as_url(), &segments)
            .map_err(|_| MessagingClientError::configuration("the service base URL is not usable"))
    }

    async fn get_empty(&self, path: &str) -> Result<MessagingComplete<()>, MessagingClientError> {
        let url = self.url_from_constant(path)?;
        let response = self.send(self.http.get(url)).await?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(self.problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        let body =
            read_bounded(response, 1)
                .await
                .map_err(|error| MessagingClientError::Transport {
                    kind: read_failure_kind(&error),
                })?;
        if !body.is_empty() {
            return Err(protocol(
                status,
                MessagingProtocolFailure::Body,
                Some(trace_id),
            ));
        }
        Ok(MessagingComplete {
            value: (),
            trace_id,
        })
    }

    async fn get_view(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<MessagingComplete<MessageView>, MessagingClientError> {
        let response = self.send(request).await?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(self.problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
            return Err(protocol(
                status,
                MessagingProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let body = read_bounded(response, self.max_response_bytes)
            .await
            .map_err(|error| MessagingClientError::Transport {
                kind: read_failure_kind(&error),
            })?;
        let value = serde_json::from_slice(&body).map_err(|_| {
            protocol(
                status,
                MessagingProtocolFailure::Body,
                Some(trace_id.clone()),
            )
        })?;
        Ok(MessagingComplete { value, trace_id })
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Response, MessagingClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| MessagingClientError::Transport {
                kind: send_failure_kind(&error),
            })?;
        validate_response_headers(response.headers()).map_err(|_| {
            protocol(
                response.status(),
                MessagingProtocolFailure::HeaderBounds,
                None,
            )
        })?;
        Ok(response)
    }

    async fn problem_or_status(&self, response: Response) -> MessagingClientError {
        let status = response.status();
        let trace = response_trace(status, response.headers()).ok();
        if !exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
            return protocol(status, MessagingProtocolFailure::Status, trace);
        }
        let body = match read_bounded(response, MAXIMUM_PROBLEM_BYTES).await {
            Ok(value) => value,
            Err(error) => {
                return MessagingClientError::Transport {
                    kind: read_failure_kind(&error),
                }
            }
        };
        let document = match ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES as usize) {
            Ok(value) => value,
            Err(_) => return protocol(status, MessagingProtocolFailure::Problem, trace),
        };
        domain_problem(status, trace.as_deref(), &document)
    }
}

/// Decide between a typed product problem and a protocol failure.
///
/// A product problem requires every one of these to hold: the document's
/// status equals the response status, the code is in the closed vocabulary
/// and pins that same status, the response trace header matches the
/// document's trace identifier, and the type URI equals the pinned
/// definition. Any mismatch, and any code outside the closed vocabulary, is
/// the edge talking: a protocol failure, never a product problem.
///
/// The title and the remediation detail are deliberately not compared: the
/// caller reads its own pinned copies through `code.title()` and
/// `code.detail()`, so an editorial change on the deployment never turns a
/// refusal the code already named into an unrecoverable protocol failure.
pub(crate) fn domain_problem(
    status: StatusCode,
    header_trace: Option<&str>,
    document: &ProblemDocument,
) -> MessagingClientError {
    let trace_id = header_trace.map(str::to_owned);
    let Some(code) = ProblemCode::from_code(&document.code) else {
        return protocol(status, MessagingProtocolFailure::Problem, trace_id);
    };
    if document.status != status.as_u16()
        || code.http_status() != status.as_u16()
        || header_trace != Some(document.trace_id.as_str())
        || document.type_uri != type_uri(code.code())
    {
        return protocol(status, MessagingProtocolFailure::Problem, trace_id);
    }
    MessagingClientError::Problem {
        status: status.as_u16(),
        code,
        trace_id,
    }
}

/// Whether `value` is a UUID in the lowercase hyphenated form the runtime
/// answers message identifiers in.
fn is_message_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn response_trace(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<String, MessagingClientError> {
    response_trace_id(headers)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| protocol(status, MessagingProtocolFailure::TraceContext, None))
}

fn exact_media_type(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None) if value.as_bytes() == expected.as_bytes()
    )
}

fn protocol(
    status: StatusCode,
    failure: MessagingProtocolFailure,
    trace_id: Option<String>,
) -> MessagingClientError {
    MessagingClientError::Protocol {
        status: status.as_u16(),
        failure,
        trace_id,
    }
}
