// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use registry_messaging_core::{
    type_uri, valid_identifier, valid_template_version, MessageReceipt, MessageView, ProblemCode,
    SubmitMessageRequest, TemplatePreview, TemplatePreviewRequest, HEALTH_PATH,
    IDEMPOTENCY_KEY_HEADER, MAXIMUM_IDEMPOTENCY_KEY_BYTES, MESSAGES_PATH, MESSAGE_CANCEL_PATH,
    MESSAGE_PATH, READY_PATH, TEMPLATE_PREVIEW_PATH,
};
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, BearerToken, OutboundOptions,
    ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, retry_after_seconds, url::append_path_segments, validate_response_headers,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Response, StatusCode, Url};
use serde::de::DeserializeOwned;

use crate::{MessagingClientConfig, MessagingClientError, MessagingProtocolFailure};

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;

/// Longest `Retry-After` wait, in whole seconds, this client reports on a
/// 429 refusal. A daily limit clears as the profile's oldest counted
/// acceptance leaves its 24-hour window, so one day is the longest wait the
/// runtime can honestly ask for. A longer value, or one outside the
/// delta-seconds grammar, is reported as no wait; the refusal stays typed.
pub const MAXIMUM_RETRY_AFTER_SECONDS: u64 = 24 * 60 * 60;

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

    /// Submit one message under `idempotency_key`. The runtime answers the
    /// receipt of the accepted message; the same key and request answer the
    /// stored receipt again, and the same key with a different request
    /// answers the typed `ProblemCode::IdempotencyKeyReused`.
    ///
    /// The caller chooses the key and retries with it: the client never
    /// invents one and never retries. A key that is empty, longer than
    /// `MAXIMUM_IDEMPOTENCY_KEY_BYTES`, or carries a byte outside visible
    /// ASCII is refused before a request is sent. A templated submission's
    /// identifier and version must also follow the package naming grammar.
    pub async fn submit(
        &self,
        token: &BearerToken,
        idempotency_key: &str,
        request: &SubmitMessageRequest,
    ) -> Result<MessagingComplete<MessageReceipt>, MessagingClientError> {
        if !is_idempotency_key(idempotency_key) {
            return Err(MessagingClientError::invalid_request(
                "the idempotency key is not 1 to 128 visible ASCII characters",
            ));
        }
        if let Some(template) = &request.template {
            if !valid_identifier(&template.id) {
                return Err(MessagingClientError::invalid_request(
                    "the template identifier is not a package identifier",
                ));
            }
            if !valid_template_version(&template.version) {
                return Err(MessagingClientError::invalid_request(
                    "the template version is not a package version label",
                ));
            }
        }
        let body = serde_json::to_vec(request).map_err(|_| {
            MessagingClientError::invalid_request("the submission could not be encoded")
        })?;
        let request = self
            .http
            .post(self.url_from_constant(MESSAGES_PATH)?)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
            .body(body);
        self.json_answer(request, StatusCode::ACCEPTED).await
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
        self.json_answer(request, StatusCode::OK).await
    }

    /// Withdraw one message that has not been dispatched, and answer its
    /// view as the cancellation left it. A message the caller may not see
    /// answers the typed `ProblemCode::MessageNotVisible`; one whose dispatch
    /// already started answers `ProblemCode::MessageDispatchStarted`, and one
    /// already final answers `ProblemCode::MessageTerminal`. The client never
    /// retries a cancellation that lost either race.
    ///
    /// `message_id` is checked exactly as `message` checks it, before a
    /// request is sent.
    pub async fn cancel(
        &self,
        token: &BearerToken,
        message_id: &str,
    ) -> Result<MessagingComplete<MessageView>, MessagingClientError> {
        if !is_message_id(message_id) {
            return Err(MessagingClientError::invalid_request(
                "the message identifier is not a lowercase hyphenated UUID",
            ));
        }
        let path = MESSAGE_CANCEL_PATH.replace("{message_id}", message_id);
        let request = self
            .http
            .post(self.url_from_constant(&path)?)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE);
        self.json_answer(request, StatusCode::OK).await
    }

    /// Render one template version for `request.locale` and
    /// `request.data` without sending anything. A version the active
    /// package does not ship answers the typed
    /// `ProblemCode::TemplateNotFound`; data the template's schema refuses,
    /// a locale it does not carry, and a render the runtime stopped answer
    /// `ProblemCode::TemplateDataInvalid`,
    /// `ProblemCode::TemplateLocaleUnavailable`, and
    /// `ProblemCode::TemplateRenderRefused`.
    ///
    /// `template_id` must be a package identifier and `version` a package
    /// version label; any other value is refused before a request is sent.
    pub async fn preview(
        &self,
        token: &BearerToken,
        template_id: &str,
        version: &str,
        request: &TemplatePreviewRequest,
    ) -> Result<MessagingComplete<TemplatePreview>, MessagingClientError> {
        if !valid_identifier(template_id) {
            return Err(MessagingClientError::invalid_request(
                "the template identifier is not a package identifier",
            ));
        }
        if !valid_template_version(version) {
            return Err(MessagingClientError::invalid_request(
                "the template version is not a package version label",
            ));
        }
        let body = serde_json::to_vec(request).map_err(|_| {
            MessagingClientError::invalid_request("the preview request could not be encoded")
        })?;
        let path = TEMPLATE_PREVIEW_PATH
            .replace("{template_id}", template_id)
            .replace("{version}", version);
        let request = self
            .http
            .post(self.url_from_constant(&path)?)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .body(body);
        self.json_answer(request, StatusCode::OK).await
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

    async fn json_answer<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        expected: StatusCode,
    ) -> Result<MessagingComplete<T>, MessagingClientError> {
        let response = self.send(request).await?;
        let status = response.status();
        if status != expected {
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
        let retry_after = (status == StatusCode::TOO_MANY_REQUESTS)
            .then(|| retry_after_seconds(response.headers(), MAXIMUM_RETRY_AFTER_SECONDS))
            .flatten();
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
        domain_problem(status, trace.as_deref(), &document, retry_after)
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
///
/// `retry_after` is the bounded `Retry-After` wait read from a 429 answer;
/// it rides on the typed problem only, never on a protocol failure.
pub(crate) fn domain_problem(
    status: StatusCode,
    header_trace: Option<&str>,
    document: &ProblemDocument,
    retry_after: Option<u64>,
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
        retry_after_seconds: retry_after.filter(|_| status == StatusCode::TOO_MANY_REQUESTS),
    }
}

/// Whether `value` is an idempotency key the runtime accepts: 1 to
/// `MAXIMUM_IDEMPOTENCY_KEY_BYTES` bytes of visible ASCII.
fn is_idempotency_key(value: &str) -> bool {
    (1..=MAXIMUM_IDEMPOTENCY_KEY_BYTES).contains(&value.len())
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
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
