// SPDX-License-Identifier: Apache-2.0
//! Error types for the Registry Notary client.

use crate::options::RetryAfter;

#[derive(Debug, thiserror::Error)]
pub enum NotaryClientBuildError {
    #[error("invalid base URL")]
    Url(String),
    #[error("base URL must use https unless test-support HTTP loopback is enabled")]
    InsecureBaseUrl,
    #[error("multiple authentication modes configured")]
    MultipleAuthModes,
    #[error("request purpose conflicts with request body purpose")]
    PurposeConflict,
    #[error("request body could not be serialized")]
    RequestSerialization,
    #[error("idempotency key is not supported for this route")]
    UnsupportedIdempotencyKey,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: Option<String>,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
}

impl std::fmt::Debug for ProblemDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProblemDetails")
            .field("problem_type", &self.problem_type)
            .field("title", &self.title)
            .field("status", &self.status)
            .field("detail", &"<redacted>")
            .field("code", &self.code)
            .finish()
    }
}

impl std::fmt::Display for ProblemDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.title, self.code)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Oid4vciError {
    pub error: String,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortableErrorKind {
    Problem,
    Oid4vci,
    Decode,
    BodyTooLarge,
    Transport,
    Build,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PortableClientError {
    pub kind: PortableErrorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub title: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum NotaryClientError {
    #[error(transparent)]
    Build(#[from] NotaryClientBuildError),
    #[error("transport error")]
    Transport(#[source] reqwest::Error),
    #[error("registry notary problem: {problem}")]
    Problem {
        status: reqwest::StatusCode,
        problem: Box<ProblemDetails>,
        request_id: Option<String>,
        retry_after: Option<RetryAfter>,
    },
    #[error("openid4vci error: {error}")]
    Oid4vci {
        status: reqwest::StatusCode,
        error: Oid4vciError,
        request_id: Option<String>,
        retry_after: Option<RetryAfter>,
    },
    #[error("failed to decode response body")]
    Decode {
        status: reqwest::StatusCode,
        request_id: Option<String>,
    },
    #[error("response body exceeded configured size limit")]
    BodyTooLarge { request_id: Option<String> },
}

impl NotaryClientError {
    #[must_use]
    pub fn status(&self) -> Option<reqwest::StatusCode> {
        match self {
            Self::Problem { status, .. } | Self::Oid4vci { status, .. } => Some(*status),
            Self::Decode { status, .. } => Some(*status),
            _ => None,
        }
    }

    #[must_use]
    pub fn problem_code(&self) -> Option<&str> {
        match self {
            Self::Problem { problem, .. } => Some(problem.code.as_str()),
            Self::Oid4vci { error, .. } => Some(error.error.as_str()),
            _ => None,
        }
    }

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

    #[must_use]
    pub fn retry_after(&self) -> Option<&RetryAfter> {
        match self {
            Self::Problem { retry_after, .. } | Self::Oid4vci { retry_after, .. } => {
                retry_after.as_ref()
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.status().map(|status| status.as_u16()), Some(429 | 503))
            || matches!(self, Self::Transport(_))
    }

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

pub(crate) fn parse_retry_after(raw: Option<&str>) -> Option<RetryAfter> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(RetryAfter::Delta(std::time::Duration::from_secs(seconds)));
    }
    Some(RetryAfter::HttpDate(raw.to_string()))
}
