use registry_platform_httpsec::TraceId;
use registry_platform_httputil::client::TokenError;
use registry_relay_http_contract::ProblemCode;
use thiserror::Error;

pub use registry_platform_httputil::client::TransportKind;

/// A closed reason why a response could not be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolFailure {
    HeaderBounds,
    TraceContext,
    MediaType,
    Body,
    Problem,
    EntityTag,
    NotModifiedBody,
    Status,
}

impl std::fmt::Display for ProtocolFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::HeaderBounds => "response headers exceeded the accepted bounds",
            Self::TraceContext => "response trace context was not canonical",
            Self::MediaType => "response media type was not the requested type",
            Self::Body => "response body did not match the expected shape",
            Self::Problem => "problem response did not match the registered Relay problem",
            Self::EntityTag => "response entity tag was not a strong SHA-256 tag",
            Self::NotModifiedBody => "not-modified response carried a body",
            Self::Status => "response status was not valid for this operation",
        })
    }
}

/// Coarse, value-free failures from a Relay exchange.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayClientError {
    #[error("the Relay client cannot be used as configured: {reason}")]
    Configuration { reason: &'static str },
    #[error("the Relay request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error("the Relay exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error("Relay refused or failed the request: status {status}, code {code}")]
    Problem {
        status: u16,
        code: ProblemCode,
        trace_id: TraceId,
        retry_after_seconds: Option<u64>,
    },
    #[error("the Relay response did not satisfy its wire contract: status {status}, {failure}")]
    Protocol {
        status: u16,
        failure: ProtocolFailure,
        trace_id: Option<TraceId>,
    },
}

impl RelayClientError {
    pub(crate) const fn configuration(reason: &'static str) -> Self {
        Self::Configuration { reason }
    }

    pub(crate) const fn transport(kind: TransportKind) -> Self {
        Self::Transport { kind }
    }

    pub(crate) const fn invalid_request(reason: &'static str) -> Self {
        Self::InvalidRequest { reason }
    }

    pub(crate) fn protocol(
        status: u16,
        failure: ProtocolFailure,
        trace_id: Option<TraceId>,
    ) -> Self {
        Self::Protocol {
            status,
            failure,
            trace_id,
        }
    }

    #[must_use]
    pub fn trace_id(&self) -> Option<&TraceId> {
        match self {
            Self::Problem { trace_id, .. } => Some(trace_id),
            Self::Protocol { trace_id, .. } => trace_id.as_ref(),
            _ => None,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Configuration { .. } => "configuration",
            Self::InvalidRequest { .. } => "invalid_request",
            Self::Token(_) => "token",
            Self::Transport { .. } => "transport",
            Self::Problem { .. } => "problem",
            Self::Protocol { .. } => "protocol",
        }
    }

    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Problem { status, .. } | Self::Protocol { status, .. } => Some(*status),
            _ => None,
        }
    }

    #[must_use]
    pub fn problem_code(&self) -> Option<ProblemCode> {
        match self {
            Self::Problem { code, .. } => Some(*code),
            _ => None,
        }
    }

    #[must_use]
    pub fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::Problem {
                retry_after_seconds,
                ..
            } => *retry_after_seconds,
            _ => None,
        }
    }
}
