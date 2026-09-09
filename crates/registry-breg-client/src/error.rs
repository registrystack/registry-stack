use registry_platform_httpsec::TraceId;
use registry_platform_httputil::client::TokenError;
use thiserror::Error;

pub use registry_platform_httputil::client::TransportKind;

/// One closed kind of change-request plan refusal named by Base Registry Engine.
///
/// The kind is the whole reason the service discloses: it never carries planner
/// script text, request values, or target data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BRegPlanRefusal {
    Source,
    Entrypoint,
    Execution,
    Result,
    Ceiling,
    Disposition,
    Resource,
}

impl BRegPlanRefusal {
    /// Every refusal kind a submission may be refused for.
    pub const ALL: [Self; 7] = [
        Self::Source,
        Self::Entrypoint,
        Self::Execution,
        Self::Result,
        Self::Ceiling,
        Self::Disposition,
        Self::Resource,
    ];

    /// Returns the exact term Base Registry Engine names this refusal by.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Source => "change_request.planner.source",
            Self::Entrypoint => "change_request.planner.entrypoint",
            Self::Execution => "change_request.planner.execution",
            Self::Result => "change_request.planner.result",
            Self::Ceiling => "change_request.planner.ceiling",
            Self::Disposition => "change_request.planner.disposition",
            Self::Resource => "change_request.planner.resource",
        }
    }

    pub(crate) const fn detail(self) -> &'static str {
        match self {
            Self::Source => {
                "The change-request planner refused the submission: change_request.planner.source."
            }
            Self::Entrypoint => {
                "The change-request planner refused the submission: change_request.planner.entrypoint."
            }
            Self::Execution => {
                "The change-request planner refused the submission: change_request.planner.execution."
            }
            Self::Result => {
                "The change-request planner refused the submission: change_request.planner.result."
            }
            Self::Ceiling => {
                "The change-request planner refused the submission: change_request.planner.ceiling."
            }
            Self::Disposition => {
                "The change-request planner refused the submission: change_request.planner.disposition."
            }
            Self::Resource => {
                "The change-request planner refused the submission: change_request.planner.resource."
            }
        }
    }
}

impl std::fmt::Display for BRegPlanRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.kind())
    }
}

/// One package-declared reason an immediate-action handler refused a call.
///
/// Every other Base Registry Engine refusal names a closed vocabulary this
/// crate can enumerate. A refusal catalogue is declared by the package instead,
/// so the code is carried as the bounded string the published Problem schema
/// admits: 1 through 128 characters, none of them a control character. The
/// value is service-supplied text, so it is read through `as_str` rather than
/// rendered into the error message.
#[derive(Clone, PartialEq, Eq)]
pub struct BRegRefusalCode(String);

impl BRegRefusalCode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        (!value.is_empty() && value.chars().count() <= 128 && !value.chars().any(char::is_control))
            .then(|| Self(value.to_owned()))
    }

    /// Borrow the declared refusal code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for BRegRefusalCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BRegRefusalCode(<undisclosed>)")
    }
}

/// One closed Base Registry Engine Problem code accepted by the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BRegProblemCode {
    ActionEvidenceFailed,
    ActionHandlerFailed,
    ActionRefused,
    AuthenticationRefused,
    IdempotencyConflict,
    LookupUnresolved,
    MutationConflict,
    PreconditionFailed,
    PreconditionRequired,
    QueryCursorInvalid,
    QueryInvalid,
    RequestInvalid,
    RequestPlanRefused(BRegPlanRefusal),
    RequestTimeout,
    ResourceNotFound,
    RuntimeNotReady,
    ServiceUnavailable,
    SourceUnavailable,
    UnsupportedMediaType,
}

impl BRegProblemCode {
    pub const ALL: [Self; 25] = [
        Self::ActionEvidenceFailed,
        Self::ActionHandlerFailed,
        Self::ActionRefused,
        Self::AuthenticationRefused,
        Self::IdempotencyConflict,
        Self::LookupUnresolved,
        Self::MutationConflict,
        Self::PreconditionFailed,
        Self::PreconditionRequired,
        Self::QueryCursorInvalid,
        Self::QueryInvalid,
        Self::RequestInvalid,
        Self::RequestPlanRefused(BRegPlanRefusal::Source),
        Self::RequestPlanRefused(BRegPlanRefusal::Entrypoint),
        Self::RequestPlanRefused(BRegPlanRefusal::Execution),
        Self::RequestPlanRefused(BRegPlanRefusal::Result),
        Self::RequestPlanRefused(BRegPlanRefusal::Ceiling),
        Self::RequestPlanRefused(BRegPlanRefusal::Disposition),
        Self::RequestPlanRefused(BRegPlanRefusal::Resource),
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
            Self::ActionEvidenceFailed => "action.evidence_failed",
            Self::ActionHandlerFailed => "action.handler_failed",
            Self::ActionRefused => "action.refused",
            Self::AuthenticationRefused => "authentication.refused",
            Self::IdempotencyConflict => "idempotency.conflict",
            Self::LookupUnresolved => "lookup.unresolved",
            Self::MutationConflict => "mutation.conflict",
            Self::PreconditionFailed => "precondition.failed",
            Self::PreconditionRequired => "precondition.required",
            Self::QueryCursorInvalid => "query.cursor_invalid",
            Self::QueryInvalid => "query.invalid",
            Self::RequestInvalid => "request.invalid",
            Self::RequestPlanRefused(_) => "request.plan_refused",
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
            Self::QueryCursorInvalid
            | Self::QueryInvalid
            | Self::RequestInvalid
            | Self::RequestPlanRefused(_) => 400,
            Self::ActionEvidenceFailed => 503,
            Self::ActionHandlerFailed => 500,
            Self::AuthenticationRefused => 401,
            Self::LookupUnresolved | Self::ResourceNotFound => 404,
            Self::IdempotencyConflict | Self::MutationConflict => 409,
            Self::PreconditionFailed => 412,
            Self::UnsupportedMediaType => 415,
            Self::ActionRefused => 422,
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
            422 => "Unprocessable Entity",
            428 => "Precondition Required",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Request failed",
        }
    }

    pub(crate) const fn detail(self) -> &'static str {
        match self {
            Self::ActionEvidenceFailed => "The declared Evidence dependency could not be accepted.",
            Self::ActionHandlerFailed => "The action handler could not produce an accepted result.",
            // The published sentence for the code. A refusal carries its
            // package-declared label on the wire, which `accepts_detail` reads.
            Self::ActionRefused => "The action was refused by a declared business rule.",
            Self::AuthenticationRefused => "The bearer credential is missing or refused.",
            Self::IdempotencyConflict => "The idempotency key is bound to another request.",
            Self::LookupUnresolved => "The lookup did not resolve exactly one record.",
            Self::MutationConflict => "The mutation conflicts with current state.",
            Self::PreconditionFailed => "The mutation precondition failed.",
            Self::PreconditionRequired => "The mutation precondition is required.",
            Self::QueryCursorInvalid => "The query cursor is invalid.",
            Self::QueryInvalid => "The query request is invalid.",
            Self::RequestInvalid => "The request is invalid.",
            Self::RequestPlanRefused(refusal) => refusal.detail(),
            Self::RequestTimeout => "The request timed out.",
            Self::ResourceNotFound => "The requested resource was not found.",
            Self::RuntimeNotReady => "Registry runtime is not ready.",
            Self::ServiceUnavailable => "The Registry mutation service is unavailable.",
            Self::SourceUnavailable => "The Registry data service is unavailable.",
            Self::UnsupportedMediaType => "The request media type is not supported.",
        }
    }

    /// Closed alternate text for the field-pattern form of mutation conflict.
    /// It remains the same typed conflict for existing client consumers.
    /// An immediate-action refusal is the one code whose detail is declared by
    /// the package, so it is accepted against the schema bound instead.
    pub(crate) fn accepts_detail(self, detail: &str) -> bool {
        detail == self.detail()
            || (self == Self::MutationConflict
                && detail == "The field does not conform to its declared storage pattern.")
            || (self == Self::ActionRefused && bounded_refusal_label(detail))
    }

    /// The type URI the service names for this code, resolved the same way the
    /// service builds it: each dot in the code separates a path segment under
    /// the shared Registry Stack product prefix.
    pub(crate) fn type_uri(self) -> String {
        format!(
            "https://id.registrystack.org/problems/registry-breg/{}",
            self.code().replace('.', "/")
        )
    }
}

impl std::fmt::Display for BRegProblemCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

/// The published Problem schema bounds a refusal label at 256 characters. The
/// label is declared by the package, so the client holds it to that bound and
/// to the control-character exclusion every public member shares.
fn bounded_refusal_label(detail: &str) -> bool {
    !detail.is_empty() && detail.chars().count() <= 256 && !detail.chars().any(char::is_control)
}

/// A closed, value-free reason why a Base Registry Engine response was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BRegProtocolFailure {
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

impl std::fmt::Display for BRegProtocolFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::HeaderBounds => "response headers exceeded the accepted bounds",
            Self::TraceContext => "response trace context was not canonical",
            Self::MediaType => "response media type was not the requested type",
            Self::Body => "response body did not match the expected shape",
            Self::Problem => {
                "problem response did not match a registered Base Registry Engine problem"
            }
            Self::EntityTag => "response entity tag was not a strong Base Registry Engine tag",
            Self::ProfileLink => {
                "response profile links did not match the Registry Record contract"
            }
            Self::Location => "response location did not match the mutation result",
            Self::CachePolicy => "response cache policy did not match the operation contract",
            Self::Status => "response status was not valid for this operation",
        })
    }
}

/// Coarse failures from one Base Registry Engine exchange.
///
/// Values controlled by the caller or service are deliberately absent from
/// every variant and from `Debug`/`Display` output. The one exception is the
/// declared refusal code an immediate action is refused by, which is the whole
/// machine-readable outcome of that refusal: it is carried bounded, and it is
/// read through `refusal_code` rather than rendered.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum BaseRegistryClientError {
    #[error("the Base Registry Engine client cannot be used as configured: {reason}")]
    Configuration { reason: &'static str },
    #[error("the Base Registry Engine request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error("the Base Registry Engine exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error("Base Registry Engine refused or failed the request: status {status}, code {code}")]
    Problem {
        status: u16,
        code: BRegProblemCode,
        trace_id: TraceId,
        refusal_code: Option<BRegRefusalCode>,
    },
    #[error("the Base Registry Engine response did not satisfy its wire contract: status {status}, {failure}")]
    Protocol {
        status: u16,
        failure: BRegProtocolFailure,
        trace_id: Option<TraceId>,
    },
}

impl BaseRegistryClientError {
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
        failure: BRegProtocolFailure,
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
            Self::Problem {
                code: BRegProblemCode::ResourceNotFound,
                ..
            } => "not_found",
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
    pub fn problem_code(&self) -> Option<BRegProblemCode> {
        match self {
            Self::Problem { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// The declared reason an immediate-action handler refused the call, set
    /// only for `BRegProblemCode::ActionRefused`.
    #[must_use]
    pub fn refusal_code(&self) -> Option<&BRegRefusalCode> {
        match self {
            Self::Problem { refusal_code, .. } => refusal_code.as_ref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BRegPlanRefusal, BRegProblemCode};
    use super::{BaseRegistryClientError, TraceId};

    #[test]
    fn every_planner_refusal_detail_resolves_to_its_kind() {
        for refusal in BRegPlanRefusal::ALL {
            let resolved: Vec<_> = BRegProblemCode::ALL
                .into_iter()
                .filter(|code| code.detail() == refusal.detail())
                .collect();
            assert_eq!(resolved, vec![BRegProblemCode::RequestPlanRefused(refusal)]);
            assert!(refusal.detail().ends_with(&format!("{}.", refusal.kind())));
        }
    }

    #[test]
    fn a_refused_plan_carries_one_code_under_one_status() {
        for refusal in BRegPlanRefusal::ALL {
            let code = BRegProblemCode::RequestPlanRefused(refusal);
            assert_eq!(code.code(), "request.plan_refused");
            assert_eq!(code.status(), 400);
            assert_eq!(code.title(), "Bad Request");
            assert_eq!(
                code.type_uri(),
                "https://id.registrystack.org/problems/registry-breg/request/plan_refused"
            );
        }
    }

    /// The client resolves a problem type the same way the service builds it,
    /// on the shared Registry Stack identifier host, with each dot in the code
    /// read as a path separator. A type the client cannot rebuild is a problem
    /// it refuses to map.
    #[test]
    fn every_problem_type_resolves_on_the_shared_identifier_host() {
        for code in BRegProblemCode::ALL {
            assert_eq!(
                code.type_uri(),
                format!(
                    "https://id.registrystack.org/problems/registry-breg/{}",
                    code.code().replace('.', "/")
                ),
                "{code}"
            );
        }
    }

    #[test]
    fn every_registered_problem_carries_its_own_detail() {
        for code in BRegProblemCode::ALL {
            let sharing = BRegProblemCode::ALL
                .into_iter()
                .filter(|candidate| candidate.detail() == code.detail())
                .count();
            assert_eq!(sharing, 1, "{code} shares its detail with another problem");
        }
    }

    #[test]
    fn field_pattern_detail_is_a_closed_mutation_conflict_variant() {
        let detail = "The field does not conform to its declared storage pattern.";
        // An immediate-action refusal carries a package-declared label, so it
        // accepts any bounded detail and is told apart by its code instead.
        let matches = BRegProblemCode::ALL
            .into_iter()
            .filter(|code| *code != BRegProblemCode::ActionRefused && code.accepts_detail(detail))
            .collect::<Vec<_>>();
        assert_eq!(matches, vec![BRegProblemCode::MutationConflict]);
        assert!(BRegProblemCode::MutationConflict
            .accepts_detail(BRegProblemCode::MutationConflict.detail()));
        assert!(!BRegProblemCode::MutationConflict.accepts_detail("response-authored-canary"));
    }

    // app-developer-22: a missing record answered with `kind: "problem"` and
    // `status: 404` forces every caller to write a two-field test for the most
    // common failure in any CRUD application. `ResourceNotFound` is the one
    // problem code naming that exact case, so it alone is promoted to its own
    // kind. `LookupUnresolved` is deliberately excluded: it also carries status
    // 404, but it means a lookup matched zero or more than one record, not that
    // a known resource is absent, and folding it into `not_found` would mislead
    // a caller who could instead disambiguate.
    #[test]
    fn only_a_missing_resource_reports_kind_not_found() {
        let trace_id = TraceId::parse("0123456789abcdef0123456789abcdef")
            .expect("a canonical trace identifier");
        for code in BRegProblemCode::ALL {
            let error = BaseRegistryClientError::Problem {
                status: code.status(),
                code,
                trace_id: trace_id.clone(),
                refusal_code: None,
            };
            let expected = if code == BRegProblemCode::ResourceNotFound {
                "not_found"
            } else {
                "problem"
            };
            assert_eq!(error.kind(), expected, "{code} reported an unexpected kind");
        }
    }
}
