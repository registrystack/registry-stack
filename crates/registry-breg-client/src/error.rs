use registry_platform_httpsec::TraceId;
use registry_platform_httputil::client::TokenError;
use thiserror::Error;

use crate::{BRegMetadataError, BRegMetadataErrorKind};

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

/// One bounded machine-readable Problem detail code.
///
/// Immediate actions use package-declared refusal codes. Statistical release
/// refusals and withdrawals use closed engine vocabularies validated by the
/// decoder. The value is service-supplied text, so callers read it through
/// `as_str` rather than rendering it in an error message.
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

/// One validated location named by a Base Registry Engine Problem.
///
/// The service supplies this value from a closed product grammar. The client
/// validates that grammar and the shared 256-character bound before retaining
/// the location. Read it explicitly through [`Self::as_str`]; it is not
/// rendered into an error message or debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct BRegProblemFieldPath(String);

impl BRegProblemFieldPath {
    pub(crate) fn from_validated(value: &str) -> Self {
        Self(value.to_owned())
    }

    /// Borrow the validated problem location.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for BRegProblemFieldPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BRegProblemFieldPath(<undisclosed>)")
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
    IdempotencyExpired,
    IngestionChunkMismatch,
    IngestionProfileMismatch,
    IngestionReceiptErased,
    IngestionRunBlocked,
    IngestionRunNotOpen,
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
    RuntimeFieldEncryptionUnavailable,
    RuntimeNotReady,
    ServiceUnavailable,
    SourceUnavailable,
    StatisticalDatasetDomainViolation,
    StatisticalDatasetReleaseRefused,
    StatisticalDatasetVersionConflict,
    StatisticalDatasetVersionWithdrawn,
    UnsupportedMediaType,
}

impl BRegProblemCode {
    pub const ALL: [Self; 36] = [
        Self::ActionEvidenceFailed,
        Self::ActionHandlerFailed,
        Self::ActionRefused,
        Self::AuthenticationRefused,
        Self::IdempotencyConflict,
        Self::IdempotencyExpired,
        Self::IngestionChunkMismatch,
        Self::IngestionProfileMismatch,
        Self::IngestionReceiptErased,
        Self::IngestionRunBlocked,
        Self::IngestionRunNotOpen,
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
        Self::RuntimeFieldEncryptionUnavailable,
        Self::RuntimeNotReady,
        Self::ServiceUnavailable,
        Self::SourceUnavailable,
        Self::StatisticalDatasetDomainViolation,
        Self::StatisticalDatasetReleaseRefused,
        Self::StatisticalDatasetVersionConflict,
        Self::StatisticalDatasetVersionWithdrawn,
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
            Self::IdempotencyExpired => "idempotency.expired",
            Self::IngestionChunkMismatch => "ingestion.chunk_mismatch",
            Self::IngestionProfileMismatch => "ingestion.profile_mismatch",
            Self::IngestionReceiptErased => "ingestion.receipt_erased",
            Self::IngestionRunBlocked => "ingestion.run_blocked",
            Self::IngestionRunNotOpen => "ingestion.run_not_open",
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
            Self::RuntimeFieldEncryptionUnavailable => "runtime.field_encryption.unavailable",
            Self::RuntimeNotReady => "runtime.not_ready",
            Self::ServiceUnavailable => "service.unavailable",
            Self::SourceUnavailable => "source.unavailable",
            Self::StatisticalDatasetDomainViolation => "statistical_dataset.domain_violation",
            Self::StatisticalDatasetReleaseRefused => "statistical_dataset.release_refused",
            Self::StatisticalDatasetVersionConflict => "statistical_dataset.version_conflict",
            Self::StatisticalDatasetVersionWithdrawn => "statistical_dataset.version_withdrawn",
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
            Self::IngestionProfileMismatch => 403,
            Self::IdempotencyConflict
            | Self::IngestionChunkMismatch
            | Self::IngestionRunBlocked
            | Self::IngestionRunNotOpen
            | Self::MutationConflict
            | Self::StatisticalDatasetVersionConflict => 409,
            Self::IdempotencyExpired
            | Self::IngestionReceiptErased
            | Self::StatisticalDatasetVersionWithdrawn => 410,
            Self::PreconditionFailed => 412,
            Self::UnsupportedMediaType => 415,
            Self::ActionRefused | Self::StatisticalDatasetReleaseRefused => 422,
            Self::PreconditionRequired => 428,
            Self::StatisticalDatasetDomainViolation => 500,
            Self::RuntimeFieldEncryptionUnavailable
            | Self::RuntimeNotReady
            | Self::ServiceUnavailable
            | Self::SourceUnavailable => 503,
            Self::RequestTimeout => 504,
        }
    }

    /// Whether the engine returns this 5xx code only with the attempt rolled
    /// back, for a failure a resend meets again unless the registry's package
    /// or records change: a handler that could not produce an accepted
    /// result, or a statistic outside its declared dimension domain.
    const fn fails_before_commit(self) -> bool {
        matches!(
            self,
            Self::ActionHandlerFailed | Self::StatisticalDatasetDomainViolation
        )
    }

    pub(crate) const fn title(self) -> &'static str {
        match self.status() {
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            409 => "Conflict",
            410 => "Gone",
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

    /// The sentence the service answers this code under. It is the catalogue's
    /// own published sentence, so a caller can state what a matching problem
    /// said without keeping a second copy of the catalogue.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::ActionEvidenceFailed => "The declared Evidence dependency could not be accepted.",
            Self::ActionHandlerFailed => "The action handler could not produce an accepted result.",
            // The published sentence for the code. A refusal carries its
            // package-declared label on the wire, which `accepts_detail` reads.
            Self::ActionRefused => "The action was refused by a declared business rule.",
            Self::AuthenticationRefused => "The bearer credential is missing or refused.",
            Self::IdempotencyConflict => "The idempotency key is bound to another request.",
            Self::IdempotencyExpired => {
                "The held response of the idempotency key expired; the key stays spent."
            }
            Self::IngestionChunkMismatch => "The chunk does not match the expected next chunk.",
            Self::IngestionProfileMismatch => {
                "The selected access profile does not match the run's bound profile."
            }
            Self::IngestionReceiptErased => "The stored receipt of the chunk was erased.",
            Self::IngestionRunBlocked => "The ingestion run is blocked and refuses further chunks.",
            Self::IngestionRunNotOpen => "The ingestion run is not open for this transition.",
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
            Self::RuntimeFieldEncryptionUnavailable => {
                "The Registry field-encryption service is unavailable."
            }
            Self::RuntimeNotReady => "Registry runtime is not ready.",
            Self::ServiceUnavailable => "The Registry mutation service is unavailable.",
            Self::SourceUnavailable => "The Registry data service is unavailable.",
            Self::StatisticalDatasetDomainViolation => {
                "A statistical dataset contains a code outside its declared domain."
            }
            Self::StatisticalDatasetReleaseRefused => {
                "The statistical dataset release operation is not eligible."
            }
            Self::StatisticalDatasetVersionConflict => {
                "The statistical dataset computation was superseded or its package changed."
            }
            Self::StatisticalDatasetVersionWithdrawn => {
                "The statistical dataset version was withdrawn."
            }
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
    RepresentationDigest,
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
            Self::RepresentationDigest => {
                "response representation digest did not match the response bytes"
            }
            Self::Status => "response status was not valid for this operation",
        })
    }
}

/// Coarse failures from one Base Registry Engine exchange.
///
/// Values controlled by the caller or service are deliberately absent from
/// every variant and from `Debug`/`Display` output. The bounded declared
/// detail code and validated problem field path are retained because they are
/// machine-readable outcomes. Callers read immediate-action and statistical
/// detail codes through `refusal_code` or `reason_code`, and paths through
/// `field_path`; none are rendered.
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
        field_path: Option<BRegProblemFieldPath>,
        refusal_code: Option<BRegRefusalCode>,
    },
    #[error("the Base Registry Engine response did not satisfy its wire contract: status {status}, {failure}")]
    Protocol {
        status: u16,
        failure: BRegProtocolFailure,
        trace_id: Option<TraceId>,
        /// The specific runtime metadata decode failure, when `failure` is
        /// `BRegProtocolFailure::Body` and the response was Registry Metadata.
        /// `None` for every other body-shape refusal; never rendered by
        /// `Display`, so a caller must read it explicitly for diagnostics.
        metadata: Option<BRegMetadataErrorKind>,
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
            metadata: None,
        }
    }

    /// Build the `Protocol`/`Body` refusal for a runtime metadata document
    /// that failed to decode, keeping the specific kind for diagnostics
    /// instead of discarding it.
    pub(crate) fn protocol_metadata(
        status: u16,
        trace_id: Option<TraceId>,
        error: BRegMetadataError,
    ) -> Self {
        Self::Protocol {
            status,
            failure: BRegProtocolFailure::Body,
            trace_id,
            metadata: Some(error.kind()),
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

    /// The specific runtime metadata decode failure carried by this error,
    /// when it came from a Registry Metadata document that did not decode.
    /// `None` for every other error, including every other protocol failure.
    #[must_use]
    pub fn metadata_error_kind(&self) -> Option<BRegMetadataErrorKind> {
        match self {
            Self::Protocol { metadata, .. } => *metadata,
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

    /// The declared reason an immediate action or statistical release was refused.
    #[must_use]
    pub fn refusal_code(&self) -> Option<&BRegRefusalCode> {
        match self {
            Self::Problem {
                code:
                    BRegProblemCode::ActionRefused | BRegProblemCode::StatisticalDatasetReleaseRefused,
                refusal_code,
                ..
            } => refusal_code.as_ref(),
            _ => None,
        }
    }

    /// The closed withdrawal reason carried by a withdrawn statistical version.
    #[must_use]
    pub fn reason_code(&self) -> Option<&str> {
        match self {
            Self::Problem {
                code: BRegProblemCode::StatisticalDatasetVersionWithdrawn,
                refusal_code: Some(reason_code),
                ..
            } => Some(reason_code.as_str()),
            _ => None,
        }
    }

    /// The validated location named by the accepted Problem, when present.
    #[must_use]
    pub fn field_path(&self) -> Option<&BRegProblemFieldPath> {
        match self {
            Self::Problem { field_path, .. } => field_path.as_ref(),
            _ => None,
        }
    }

    /// Whether the request may have taken effect although this error was
    /// returned.
    ///
    /// True for a timeout or broken exchange after the request was sent, an
    /// oversized or unparseable answer, and a 5xx answer: a 5xx may follow a
    /// commit. False for a configuration or request defect, a credential the
    /// token provider could not supply, a connection that was never
    /// established, every typed 4xx refusal, and the two typed 5xx failures
    /// the engine returns only with the attempt rolled back,
    /// `action.handler_failed` and `statistical_dataset.domain_violation`.
    /// When it is true, the safe recovery for an idempotency-keyed mutation is
    /// the same request under the same key, which the engine either replays or
    /// executes once; a new key could apply the mutation twice.
    ///
    /// It is false for `410 idempotency.expired` too, but there an earlier
    /// attempt under the key committed and only its held response is gone:
    /// read the resource before choosing a new key.
    ///
    /// A protocol failure, such as a 3xx answer or an answer that cannot be
    /// parsed or does not meet the contract, counts as unknown conservatively,
    /// as an oversized answer does: the request may have been processed before
    /// the answer went wrong. The client resends such an answer only when it
    /// came with a 5xx status, because any other answer would be replayed
    /// unchanged. It never resends after a 4xx status line, even when the rest
    /// of that answer could not be read and the error is therefore unknown.
    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        match self {
            Self::Configuration { .. } | Self::InvalidRequest { .. } | Self::Token(_) => false,
            Self::Transport { kind } => !matches!(kind, TransportKind::Connect),
            Self::Problem { status, code, .. } => *status >= 500 && !code.fails_before_commit(),
            Self::Protocol { .. } => true,
        }
    }

    /// Whether resending the identical request under the same key may settle
    /// an unknown outcome. An oversized or unparseable non-5xx answer would be
    /// replayed unchanged, so it is not resent. A transport failure carries no
    /// status, so the shared classifier, which sees the answer's status line,
    /// still refuses to resend a timeout or broken exchange after a 4xx one.
    pub(crate) fn resend_may_settle(&self) -> bool {
        match self {
            Self::Transport { kind } => {
                matches!(kind, TransportKind::Timeout | TransportKind::Exchange)
            }
            Self::Problem { status, code, .. } => *status >= 500 && !code.fails_before_commit(),
            Self::Protocol { status, .. } => *status >= 500,
            Self::Configuration { .. } | Self::InvalidRequest { .. } | Self::Token(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BRegPlanRefusal, BRegProblemCode, BRegProtocolFailure, TokenError, TransportKind};
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

    #[test]
    fn ingestion_problem_codes_carry_their_wire_names_and_statuses() {
        let expected: [(BRegProblemCode, &str, u16, &str); 5] = [
            (
                BRegProblemCode::IngestionProfileMismatch,
                "ingestion.profile_mismatch",
                403,
                "Forbidden",
            ),
            (
                BRegProblemCode::IngestionRunNotOpen,
                "ingestion.run_not_open",
                409,
                "Conflict",
            ),
            (
                BRegProblemCode::IngestionRunBlocked,
                "ingestion.run_blocked",
                409,
                "Conflict",
            ),
            (
                BRegProblemCode::IngestionChunkMismatch,
                "ingestion.chunk_mismatch",
                409,
                "Conflict",
            ),
            (
                BRegProblemCode::IngestionReceiptErased,
                "ingestion.receipt_erased",
                410,
                "Gone",
            ),
        ];
        for (code, wire_name, status, title) in expected {
            assert_eq!(code.code(), wire_name);
            assert_eq!(code.status(), status);
            assert_eq!(code.title(), title);
            assert!(
                BRegProblemCode::ALL.contains(&code),
                "{code} is not registered"
            );
        }
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
                field_path: None,
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

    fn problem(code: BRegProblemCode) -> BaseRegistryClientError {
        BaseRegistryClientError::Problem {
            status: code.status(),
            code,
            trace_id: TraceId::parse("0123456789abcdef0123456789abcdef")
                .expect("a canonical trace identifier"),
            field_path: None,
            refusal_code: None,
        }
    }

    #[test]
    fn the_unknown_outcome_predicate_separates_maybe_committed_from_refused() {
        let unknown = [
            BaseRegistryClientError::transport(TransportKind::Timeout),
            BaseRegistryClientError::transport(TransportKind::Exchange),
            BaseRegistryClientError::transport(TransportKind::ResponseTooLarge),
            BaseRegistryClientError::protocol(502, BRegProtocolFailure::Problem, None),
            BaseRegistryClientError::protocol(201, BRegProtocolFailure::Body, None),
            BaseRegistryClientError::protocol(200, BRegProtocolFailure::TraceContext, None),
        ];
        for error in &unknown {
            assert!(error.is_outcome_unknown(), "{error:?}");
        }
        let settled = [
            BaseRegistryClientError::configuration("fixture reason"),
            BaseRegistryClientError::invalid_request("fixture reason"),
            BaseRegistryClientError::Token(TokenError::Unavailable),
            BaseRegistryClientError::transport(TransportKind::Connect),
        ];
        for error in &settled {
            assert!(!error.is_outcome_unknown(), "{error:?}");
        }
        // Every 4xx code is a deterministic refusal, and so are the two 5xx
        // codes the engine returns only with the attempt rolled back; every
        // other 5xx code may follow a commit.
        let rolled_back = [
            BRegProblemCode::ActionHandlerFailed,
            BRegProblemCode::StatisticalDatasetDomainViolation,
        ];
        for code in BRegProblemCode::ALL {
            assert_eq!(
                problem(code).is_outcome_unknown(),
                code.status() >= 500 && !rolled_back.contains(&code),
                "{code}"
            );
        }
        for code in [
            BRegProblemCode::AuthenticationRefused,
            BRegProblemCode::IdempotencyConflict,
            BRegProblemCode::IdempotencyExpired,
            BRegProblemCode::StatisticalDatasetVersionWithdrawn,
            BRegProblemCode::ActionRefused,
            BRegProblemCode::ActionHandlerFailed,
            BRegProblemCode::StatisticalDatasetDomainViolation,
        ] {
            assert!(!problem(code).is_outcome_unknown(), "{code}");
        }
        for code in [
            BRegProblemCode::ActionEvidenceFailed,
            BRegProblemCode::ServiceUnavailable,
            BRegProblemCode::RequestTimeout,
        ] {
            assert!(problem(code).is_outcome_unknown(), "{code}");
        }
    }

    #[test]
    fn only_a_timeout_a_broken_exchange_or_a_5xx_is_resent() {
        let resent = [
            BaseRegistryClientError::transport(TransportKind::Timeout),
            BaseRegistryClientError::transport(TransportKind::Exchange),
            problem(BRegProblemCode::ServiceUnavailable),
            problem(BRegProblemCode::ActionEvidenceFailed),
            BaseRegistryClientError::protocol(500, BRegProtocolFailure::Problem, None),
        ];
        for error in &resent {
            assert!(error.resend_may_settle(), "{error:?}");
        }
        let kept = [
            BaseRegistryClientError::transport(TransportKind::Connect),
            BaseRegistryClientError::transport(TransportKind::ResponseTooLarge),
            BaseRegistryClientError::protocol(201, BRegProtocolFailure::Body, None),
            problem(BRegProblemCode::IdempotencyConflict),
            problem(BRegProblemCode::IdempotencyExpired),
            problem(BRegProblemCode::ActionHandlerFailed),
            problem(BRegProblemCode::StatisticalDatasetDomainViolation),
            BaseRegistryClientError::Token(TokenError::Unavailable),
            BaseRegistryClientError::invalid_request("fixture reason"),
        ];
        for error in &kept {
            assert!(!error.resend_may_settle(), "{error:?}");
        }
    }
}
