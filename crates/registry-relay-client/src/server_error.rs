use registry_platform_httpsec::TraceId;
use registry_platform_httputil::client::TokenError;
use thiserror::Error;

pub use registry_platform_httputil::client::TransportKind;

/// One closed Registry Server Problem code accepted by the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryServerProblemCode {
    AuthenticationRefused,
    IdempotencyConflict,
    LookupUnresolved,
    MutationConflict,
    PreconditionFailed,
    PreconditionRequired,
    QueryCursorInvalid,
    QueryInvalid,
    RequestInvalid,
    RequestTimeout,
    ResourceNotFound,
    RuntimeNotReady,
    ServiceUnavailable,
    SourceUnavailable,
    UnsupportedMediaType,
}

impl RegistryServerProblemCode {
    pub const ALL: [Self; 15] = [
        Self::AuthenticationRefused,
        Self::IdempotencyConflict,
        Self::LookupUnresolved,
        Self::MutationConflict,
        Self::PreconditionFailed,
        Self::PreconditionRequired,
        Self::QueryCursorInvalid,
        Self::QueryInvalid,
        Self::RequestInvalid,
        Self::RequestTimeout,
        Self::ResourceNotFound,
        Self::RuntimeNotReady,
        Self::ServiceUnavailable,
        Self::SourceUnavailable,
        Self::UnsupportedMediaType,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => "authentication.refused",
            Self::IdempotencyConflict => "idempotency.conflict",
            Self::LookupUnresolved => "lookup.unresolved",
            Self::MutationConflict => "mutation.conflict",
            Self::PreconditionFailed => "precondition.failed",
            Self::PreconditionRequired => "precondition.required",
            Self::QueryCursorInvalid => "query.cursor_invalid",
            Self::QueryInvalid => "query.invalid",
            Self::RequestInvalid => "request.invalid",
            Self::RequestTimeout => "request.timeout",
            Self::ResourceNotFound => "resource.not_found",
            Self::RuntimeNotReady => "runtime.not_ready",
            Self::ServiceUnavailable => "service.unavailable",
            Self::SourceUnavailable => "source.unavailable",
            Self::UnsupportedMediaType => "unsupported.media_type",
        }
    }

    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::QueryCursorInvalid | Self::QueryInvalid | Self::RequestInvalid => 400,
            Self::AuthenticationRefused => 401,
            Self::LookupUnresolved | Self::ResourceNotFound => 404,
            Self::IdempotencyConflict | Self::MutationConflict => 409,
            Self::PreconditionFailed => 412,
            Self::UnsupportedMediaType => 415,
            Self::PreconditionRequired => 428,
            Self::RuntimeNotReady | Self::ServiceUnavailable | Self::SourceUnavailable => 503,
            Self::RequestTimeout => 504,
        }
    }

    pub(crate) const fn title(self) -> &'static str {
        match self.status() {
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            409 => "Conflict",
            412 => "Precondition Failed",
            415 => "Unsupported Media Type",
            428 => "Precondition Required",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Request failed",
        }
    }

    pub(crate) const fn detail(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => "The bearer credential is missing or refused.",
            Self::IdempotencyConflict => "The idempotency key is bound to another request.",
            Self::LookupUnresolved => "The lookup did not resolve exactly one record.",
            Self::MutationConflict => "The mutation conflicts with current state.",
            Self::PreconditionFailed => "The mutation precondition failed.",
            Self::PreconditionRequired => "The mutation precondition is required.",
            Self::QueryCursorInvalid => "The query cursor is invalid.",
            Self::QueryInvalid => "The query request is invalid.",
            Self::RequestInvalid => "The request is invalid.",
            Self::RequestTimeout => "The request timed out.",
            Self::ResourceNotFound => "The requested resource was not found.",
            Self::RuntimeNotReady => "Registry runtime is not ready.",
            Self::ServiceUnavailable => "The Registry mutation service is unavailable.",
            Self::SourceUnavailable => "The Registry data service is unavailable.",
            Self::UnsupportedMediaType => "The request media type is not supported.",
        }
    }

    pub(crate) fn type_uri(self) -> String {
        format!("urn:registry-server:problem:{}", self.code())
    }
}

impl std::fmt::Display for RegistryServerProblemCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

/// A closed, value-free reason why a Registry Server response was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryServerProtocolFailure {
    HeaderBounds,
    TraceContext,
    MediaType,
    Body,
    Problem,
    EntityTag,
    ProfileLink,
    Location,
    CachePolicy,
    Status,
}

impl std::fmt::Display for RegistryServerProtocolFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::HeaderBounds => "response headers exceeded the accepted bounds",
            Self::TraceContext => "response trace context was not canonical",
            Self::MediaType => "response media type was not the requested type",
            Self::Body => "response body did not match the expected shape",
            Self::Problem => "problem response did not match a registered Registry Server problem",
            Self::EntityTag => "response entity tag was not a strong Registry Server tag",
            Self::ProfileLink => {
                "response profile links did not match the Registry Record contract"
            }
            Self::Location => "response location did not match the mutation result",
            Self::CachePolicy => "response cache policy did not match the operation contract",
            Self::Status => "response status was not valid for this operation",
        })
    }
}

/// Coarse failures from one Registry Server exchange.
///
/// Values controlled by the caller or service are deliberately absent from
/// every variant and from `Debug`/`Display` output.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryServerClientError {
    #[error("the Registry Server client cannot be used as configured: {reason}")]
    Configuration { reason: &'static str },
    #[error("the Registry Server request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error("the Registry Server exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error("Registry Server refused or failed the request: status {status}, code {code}")]
    Problem {
        status: u16,
        code: RegistryServerProblemCode,
        trace_id: TraceId,
    },
    #[error("the Registry Server response did not satisfy its wire contract: status {status}, {failure}")]
    Protocol {
        status: u16,
        failure: RegistryServerProtocolFailure,
        trace_id: Option<TraceId>,
    },
}

impl RegistryServerClientError {
    pub(crate) const fn configuration(reason: &'static str) -> Self {
        Self::Configuration { reason }
    }

    pub(crate) const fn invalid_request(reason: &'static str) -> Self {
        Self::InvalidRequest { reason }
    }

    pub(crate) const fn transport(kind: TransportKind) -> Self {
        Self::Transport { kind }
    }

    pub(crate) fn protocol(
        status: u16,
        failure: RegistryServerProtocolFailure,
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
    pub fn problem_code(&self) -> Option<RegistryServerProblemCode> {
        match self {
            Self::Problem { code, .. } => Some(*code),
            _ => None,
        }
    }
}
