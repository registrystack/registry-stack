use registry_platform_httputil::client::TransportKind;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReviewProtocolFailure {
    HeaderBounds,
    TraceContext,
    MediaType,
    Body,
    Problem,
    Status,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReviewClientError {
    #[error("review client configuration is invalid: {reason}")]
    Configuration { reason: &'static str },
    #[error("review client request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("review exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error("review service refused the request (HTTP {status})")]
    Problem {
        status: u16,
        trace_id: Option<String>,
    },
    #[error("review service returned an invalid response")]
    Protocol {
        status: u16,
        failure: ReviewProtocolFailure,
        trace_id: Option<String>,
    },
}

impl ReviewClientError {
    pub(crate) fn configuration(reason: &'static str) -> Self {
        Self::Configuration { reason }
    }

    pub(crate) fn invalid_request(reason: &'static str) -> Self {
        Self::InvalidRequest { reason }
    }
}
