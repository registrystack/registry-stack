// SPDX-License-Identifier: Apache-2.0
//! Error types for the Registry Notary client.

use crate::options::RetryAfter;
use crate::responses::ReadinessChecks;

use std::time::Duration;

use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;

/// Errors raised while constructing a client or preparing a request.
#[derive(Debug, thiserror::Error)]
pub enum NotaryClientBuildError {
    /// The base URL could not be parsed.
    #[error("invalid base URL")]
    Url(String),
    /// The base URL is not HTTPS. Debug and `test-support` builds allow HTTP
    /// loopback for local tests.
    #[error("base URL must use https unless test-support HTTP loopback is enabled")]
    InsecureBaseUrl,
    /// More than one auth mode was configured.
    #[error("multiple authentication modes configured")]
    MultipleAuthModes,
    /// The purpose in [`crate::RequestOptions`] conflicts with the request body.
    #[error("request purpose conflicts with request body purpose")]
    PurposeConflict,
    /// The request body failed to serialize before sending.
    #[error("request body could not be serialized")]
    RequestSerialization,
    /// An idempotency key was supplied on a route that ignores it.
    #[error("idempotency key is not supported for this route")]
    UnsupportedIdempotencyKey,
}

/// RFC 9457 Problem Details emitted by Registry Notary.
///
/// The server may include sensitive details such as subject identifiers or
/// source-field names in `detail`. `Debug`, `Display`, and portable errors do
/// not render that field.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProblemDetails {
    /// Problem type URI, deserialized from the JSON `type` field.
    #[serde(rename = "type")]
    pub problem_type: Option<String>,
    /// Human-readable title.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Sensitive detail. Do not log this directly.
    pub detail: String,
    /// Stable machine-readable code.
    pub code: String,
    /// Server request/correlation id, when included in the problem body.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Readiness status for `GET /ready` failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_status: Option<String>,
    /// Typed readiness checks for `GET /ready` failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<ReadinessChecks>,
}

impl std::fmt::Debug for ProblemDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProblemDetails")
            .field("problem_type", &self.problem_type)
            .field("title", &self.title)
            .field("status", &self.status)
            .field("detail", &"<redacted>")
            .field("code", &self.code)
            .field("request_id", &self.request_id)
            .field("readiness_status", &self.readiness_status)
            .finish()
    }
}

impl std::fmt::Display for ProblemDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.title, self.code)
    }
}

/// OpenID4VCI error envelope.
///
/// `error_description` can include holder or credential details and is redacted
/// from incidental formatting.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Oid4vciError {
    /// OAuth/OID4VCI error code.
    pub error: String,
    /// Optional sensitive description.
    #[serde(default)]
    pub error_description: Option<String>,
}

impl std::fmt::Debug for Oid4vciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oid4vciError")
            .field("error", &self.error)
            .field(
                "error_description",
                &self.error_description.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl std::fmt::Display for Oid4vciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.error)
    }
}

/// Language-binding-safe error family.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortableErrorKind {
    /// Registry Notary Problem Details.
    Problem,
    /// OpenID4VCI error envelope.
    Oid4vci,
    /// Response body could not be decoded.
    Decode,
    /// Response body exceeded the client limit.
    BodyTooLarge,
    /// Transport failure before a response was decoded.
    Transport,
    /// Client build or request preparation failure.
    Build,
}

/// Redacted error envelope intended for Python, Node, and FFI boundaries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PortableClientError {
    /// Broad error family.
    pub kind: PortableErrorKind,
    /// HTTP status when a response was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Stable problem or client error code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Safe title suitable for application logs.
    pub title: String,
    /// Whether retry may be useful if the route also allows retry.
    pub retryable: bool,
    /// Server request id, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Errors returned by client operations.
///
/// `Display` is intentionally opaque for decode/body failures and redacts
/// sensitive problem or OID4VCI detail. Use [`Self::request_id`],
/// [`Self::status`], and [`Self::problem_code`] for safe logging.
#[derive(Debug, thiserror::Error)]
pub enum NotaryClientError {
    /// Build or request-preparation failure.
    #[error(transparent)]
    Build(#[from] NotaryClientBuildError),
    /// Request transport failed.
    #[error("transport error")]
    Transport(#[source] reqwest::Error),
    /// Registry Notary returned Problem Details.
    #[error("registry notary problem: {problem}")]
    Problem {
        status: reqwest::StatusCode,
        problem: Box<ProblemDetails>,
        request_id: Option<String>,
        retry_after: Option<RetryAfter>,
    },
    /// OpenID4VCI endpoint returned an OID4VCI error envelope.
    #[error("openid4vci error: {error}")]
    Oid4vci {
        status: reqwest::StatusCode,
        error: Oid4vciError,
        request_id: Option<String>,
        retry_after: Option<RetryAfter>,
    },
    /// Response body could not be decoded.
    #[error("failed to decode response body")]
    Decode {
        status: reqwest::StatusCode,
        request_id: Option<String>,
    },
    /// Response body exceeded the configured route limit.
    #[error("response body exceeded configured size limit")]
    BodyTooLarge { request_id: Option<String> },
}

impl NotaryClientError {
    /// HTTP status associated with the error, when available.
    #[must_use]
    pub fn status(&self) -> Option<reqwest::StatusCode> {
        match self {
            Self::Problem { status, .. } | Self::Oid4vci { status, .. } => Some(*status),
            Self::Decode { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Stable server or OID4VCI problem code, when available.
    #[must_use]
    pub fn problem_code(&self) -> Option<&str> {
        match self {
            Self::Problem { problem, .. } => Some(problem.code.as_str()),
            Self::Oid4vci { error, .. } => Some(error.error.as_str()),
            _ => None,
        }
    }

    /// Server request id captured before decoding the response body.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Problem { request_id, .. }
            | Self::Oid4vci { request_id, .. }
            | Self::Decode { request_id, .. }
            | Self::BodyTooLarge { request_id } => request_id.as_deref(),
            _ => None,
        }
    }

    /// Parsed `Retry-After` header, when the server provided one.
    #[must_use]
    pub fn retry_after(&self) -> Option<&RetryAfter> {
        match self {
            Self::Problem { retry_after, .. } | Self::Oid4vci { retry_after, .. } => {
                retry_after.as_ref()
            }
            _ => None,
        }
    }

    /// Whether the error class is retryable in principle.
    ///
    /// Route-specific retry rules still apply.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.status().map(|status| status.as_u16()), Some(429 | 503))
            || matches!(self, Self::Transport(_))
    }

    /// Convert to a redacted portable envelope for bindings or FFI.
    #[must_use]
    pub fn portable(&self) -> PortableClientError {
        match self {
            Self::Problem {
                status,
                problem,
                request_id,
                ..
            } => PortableClientError {
                kind: PortableErrorKind::Problem,
                status: Some(status.as_u16()),
                code: Some(problem.code.clone()),
                title: problem.title.clone(),
                retryable: self.is_retryable(),
                request_id: request_id.clone(),
            },
            Self::Oid4vci {
                status,
                error,
                request_id,
                ..
            } => PortableClientError {
                kind: PortableErrorKind::Oid4vci,
                status: Some(status.as_u16()),
                code: Some(error.error.clone()),
                title: "OpenID4VCI error".to_string(),
                retryable: self.is_retryable(),
                request_id: request_id.clone(),
            },
            Self::Decode { status, request_id } => PortableClientError {
                kind: PortableErrorKind::Decode,
                status: Some(status.as_u16()),
                code: Some("decode.failed".to_string()),
                title: "Failed to decode response body".to_string(),
                retryable: false,
                request_id: request_id.clone(),
            },
            Self::BodyTooLarge { request_id } => PortableClientError {
                kind: PortableErrorKind::BodyTooLarge,
                status: None,
                code: Some("body.too_large".to_string()),
                title: "Response body exceeded configured size limit".to_string(),
                retryable: false,
                request_id: request_id.clone(),
            },
            Self::Transport(_) => PortableClientError {
                kind: PortableErrorKind::Transport,
                status: None,
                code: Some("transport.failed".to_string()),
                title: "Transport error".to_string(),
                retryable: true,
                request_id: None,
            },
            Self::Build(error) => PortableClientError {
                kind: PortableErrorKind::Build,
                status: None,
                code: Some(
                    match error {
                        NotaryClientBuildError::Url(_) => "build.invalid_url",
                        NotaryClientBuildError::InsecureBaseUrl => "build.insecure_base_url",
                        NotaryClientBuildError::MultipleAuthModes => "build.multiple_auth_modes",
                        NotaryClientBuildError::PurposeConflict => "request.purpose_conflict",
                        NotaryClientBuildError::RequestSerialization => {
                            "request.serialization_failed"
                        }
                        NotaryClientBuildError::UnsupportedIdempotencyKey => {
                            "request.unsupported_idempotency_key"
                        }
                    }
                    .to_string(),
                ),
                title: error.to_string(),
                retryable: false,
                request_id: None,
            },
        }
    }
}

pub(crate) fn parse_retry_after(raw: Option<&str>, date_raw: Option<&str>) -> Option<RetryAfter> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(RetryAfter::Delta(Duration::from_secs(seconds)));
    }
    if let (Some(retry_at), Some(server_at)) = (
        parse_http_date(raw),
        date_raw.and_then(|value| parse_http_date(value.trim())),
    ) {
        let delta = retry_at - server_at;
        if delta <= time::Duration::ZERO {
            return Some(RetryAfter::Delta(Duration::ZERO));
        }
        return Some(RetryAfter::Delta(Duration::new(
            delta.whole_seconds() as u64,
            delta.subsec_nanoseconds() as u32,
        )));
    }
    Some(RetryAfter::HttpDate(raw.to_string()))
}

fn parse_http_date(raw: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(raw, &Rfc2822).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_http_date_uses_server_date_for_delta() {
        let retry_after = parse_retry_after(
            Some("Wed, 31 Dec 2099 00:00:02 GMT"),
            Some("Wed, 31 Dec 2099 00:00:00 GMT"),
        );

        assert_eq!(retry_after, Some(RetryAfter::Delta(Duration::from_secs(2))));
    }

    #[test]
    fn retry_after_http_date_without_valid_date_preserves_raw_value() {
        let retry_after = parse_retry_after(Some("Wed, 31 Dec 2099 00:00:02 GMT"), None);

        assert_eq!(
            retry_after,
            Some(RetryAfter::HttpDate(
                "Wed, 31 Dec 2099 00:00:02 GMT".to_string()
            ))
        );
    }
}
