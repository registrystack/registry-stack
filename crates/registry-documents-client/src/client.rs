// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::time::Duration;

use registry_documents_core::{type_uri, ProblemCode, HEALTH_PATH};
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, OutboundOptions, ServiceBaseUrl,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
    MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
};
use registry_platform_httputil::{
    read_bounded, url::append_path_segments, validate_response_headers, BoundedReadError,
};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Response, StatusCode};
use url::Url;

use crate::{DocumentsClientError, DocumentsProtocolFailure};

const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;

/// Where the Document Store lives and the bounds every exchange with it is
/// held to. Nothing here is checked until `DocumentsClient::new`, which
/// refuses an unusable configuration before any client exists.
#[derive(Clone)]
pub struct DocumentsClientConfig {
    base_url: Url,
    request_timeout: Duration,
    connect_timeout: Duration,
    user_agent: Option<String>,
    trusted_root_certificates: Option<Vec<u8>>,
}

impl DocumentsClientConfig {
    #[must_use]
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
        }
    }

    #[must_use]
    pub fn with_request_timeout(mut self, value: Duration) -> Self {
        self.request_timeout = value;
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, value: Duration) -> Self {
        self.connect_timeout = value;
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, value: impl Into<String>) -> Self {
        self.user_agent = Some(value.into());
        self
    }

    #[must_use]
    pub fn with_trusted_root_certificates(mut self, value: Vec<u8>) -> Self {
        self.trusted_root_certificates = Some(value);
        self
    }

    fn validate(&self) -> Result<ServiceBaseUrl, DocumentsClientError> {
        let base_url = ServiceBaseUrl::new(self.base_url.clone()).map_err(|_| {
            DocumentsClientError::configuration("the service base URL is not usable")
        })?;
        if self.request_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(DocumentsClientError::configuration(
                "client timeouts must be greater than zero",
            ));
        }
        if self
            .trusted_root_certificates
            .as_ref()
            .is_some_and(|value| value.len() > MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES)
        {
            return Err(DocumentsClientError::configuration(
                "the trusted root certificate bundle exceeds the accepted bound",
            ));
        }
        Ok(base_url)
    }
}

impl fmt::Debug for DocumentsClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocumentsClientConfig")
            .field("base_url", &"<validated service URL>")
            .field("request_timeout", &self.request_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("user_agent_present", &self.user_agent.is_some())
            .field(
                "trusted_root_certificates_present",
                &self.trusted_root_certificates.is_some(),
            )
            .finish()
    }
}

/// One completed call: the answered value and the response's validated
/// trace identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentsComplete<T> {
    pub value: T,
    pub trace_id: String,
}

pub struct DocumentsClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
}

impl fmt::Debug for DocumentsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocumentsClient")
            .field("base_url", &"<validated service URL>")
            .finish_non_exhaustive()
    }
}

impl DocumentsClient {
    pub fn new(config: DocumentsClientConfig) -> Result<Self, DocumentsClientError> {
        let base_url = config.validate()?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| DocumentsClientError::configuration("the HTTP client could not be built"))?;
        Ok(Self { http, base_url })
    }

    /// Whether the process answers at all.
    pub async fn health(&self) -> Result<DocumentsComplete<()>, DocumentsClientError> {
        let segments = HEALTH_PATH
            .trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        let url = append_path_segments(self.base_url.as_url(), &segments).map_err(|_| {
            DocumentsClientError::configuration("the service base URL is not usable")
        })?;
        let response =
            self.http
                .get(url)
                .send()
                .await
                .map_err(|error| DocumentsClientError::Transport {
                    kind: send_failure_kind(&error),
                })?;
        let status = response.status();
        validate_response_headers(response.headers())
            .map_err(|_| protocol(status, DocumentsProtocolFailure::HeaderBounds, None))?;
        if status != StatusCode::OK {
            return Err(problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        // The health answer has no body, so any byte is a protocol failure
        // rather than a response the caller's bound was too small for.
        match read_bounded(response, 0).await {
            Ok(_) => {}
            Err(
                BoundedReadError::ContentLengthExceeded { .. }
                | BoundedReadError::BodyTooLarge { .. },
            ) => {
                return Err(protocol(
                    status,
                    DocumentsProtocolFailure::Body,
                    Some(trace_id),
                ));
            }
            Err(error) => {
                return Err(DocumentsClientError::Transport {
                    kind: read_failure_kind(&error),
                })
            }
        }
        Ok(DocumentsComplete {
            value: (),
            trace_id,
        })
    }
}

async fn problem_or_status(response: Response) -> DocumentsClientError {
    let status = response.status();
    let trace = response_trace(status, response.headers()).ok();
    if !exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
        return protocol(status, DocumentsProtocolFailure::Status, trace);
    }
    let body = match read_bounded(response, MAXIMUM_PROBLEM_BYTES).await {
        Ok(value) => value,
        Err(error) => {
            return DocumentsClientError::Transport {
                kind: read_failure_kind(&error),
            }
        }
    };
    let Ok(document) = ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES as usize) else {
        return protocol(status, DocumentsProtocolFailure::Problem, trace);
    };
    domain_problem(status, trace, &document)
}

/// Decide between a typed product problem and a protocol failure. A product
/// problem requires the document's status to equal the response status, its
/// code to be in the closed vocabulary and pin that same status, the
/// response trace to match the document's, and the type URI to equal the
/// pinned definition. The title and detail are not compared: the caller
/// reads its own pinned copies.
fn domain_problem(
    status: StatusCode,
    header_trace: Option<String>,
    document: &ProblemDocument,
) -> DocumentsClientError {
    let Some(code) = ProblemCode::from_code(&document.code) else {
        return protocol(status, DocumentsProtocolFailure::Problem, header_trace);
    };
    if document.status != status.as_u16()
        || code.http_status() != status.as_u16()
        || header_trace.as_deref() != Some(document.trace_id.as_str())
        || document.type_uri != type_uri(code.code())
    {
        return protocol(status, DocumentsProtocolFailure::Problem, header_trace);
    }
    DocumentsClientError::Problem {
        status: status.as_u16(),
        code,
        trace_id: header_trace,
    }
}

fn response_trace(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<String, DocumentsClientError> {
    response_trace_id(headers)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| protocol(status, DocumentsProtocolFailure::TraceContext, None))
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
    failure: DocumentsProtocolFailure,
    trace_id: Option<String>,
) -> DocumentsClientError {
    DocumentsClientError::Protocol {
        status: status.as_u16(),
        failure,
        trace_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_withholds_url_and_certificate_material() {
        let config = DocumentsClientConfig::new(
            Url::parse("https://secret.example.invalid/private").expect("fixture URL"),
        )
        .with_user_agent("secret-agent")
        .with_trusted_root_certificates(b"secret-certificate".to_vec());
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret.example"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret-agent"));
        assert!(!debug.contains("secret-certificate"));
    }

    #[test]
    fn configuration_bounds_are_enforced_before_any_client_exists() {
        let url = Url::parse("https://documents.example.invalid/").expect("fixture URL");
        for config in [
            DocumentsClientConfig::new(url.clone()).with_request_timeout(Duration::ZERO),
            DocumentsClientConfig::new(url.clone()).with_connect_timeout(Duration::ZERO),
            DocumentsClientConfig::new(url.clone()).with_trusted_root_certificates(vec![
                0;
                MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES
                    + 1
            ]),
            DocumentsClientConfig::new(
                Url::parse("https://user:pass@documents.example.invalid/").expect("fixture URL"),
            ),
        ] {
            assert!(
                matches!(
                    config.validate(),
                    Err(DocumentsClientError::Configuration { .. })
                ),
                "{config:?}"
            );
        }
        assert!(DocumentsClientConfig::new(url).validate().is_ok());
    }
}
