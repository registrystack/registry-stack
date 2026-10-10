use std::fmt;

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

/// Whether a failed mutation can be safely corrected without first
/// reconciling the original idempotency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReviewMutationErrorClass {
    Deterministic,
    Ambiguous,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ReviewProblemCode(String);

impl ReviewProblemCode {
    pub(crate) fn validated(value: String) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReviewProblemCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ReviewProblemCode")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ReviewProblemCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReviewValidationReason {
    KindNotAllowed,
    ReferenceInvalid,
    ObjectRequired,
    MaximumBytesExceeded,
    MaximumDepthExceeded,
    SchemaMismatch,
    OutcomeNotDeclared,
    ReasonRequired,
    TextInvalid,
    ResultNotDeclared,
    ResultRequired,
    FieldNotDeclared,
    ConstraintInvalid,
    ConstraintViolated,
}

impl ReviewValidationReason {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "kind-not-allowed" => Self::KindNotAllowed,
            "reference-invalid" => Self::ReferenceInvalid,
            "object-required" => Self::ObjectRequired,
            "maximum-bytes-exceeded" => Self::MaximumBytesExceeded,
            "maximum-depth-exceeded" => Self::MaximumDepthExceeded,
            "schema-mismatch" => Self::SchemaMismatch,
            "outcome-not-declared" => Self::OutcomeNotDeclared,
            "reason-required" => Self::ReasonRequired,
            "text-invalid" => Self::TextInvalid,
            "result-not-declared" => Self::ResultNotDeclared,
            "result-required" => Self::ResultRequired,
            "field-not-declared" => Self::FieldNotDeclared,
            "constraint-invalid" => Self::ConstraintInvalid,
            "constraint-violated" => Self::ConstraintViolated,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewValidationError {
    pub path: String,
    pub reason: ReviewValidationReason,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReviewProblem {
    pub code: ReviewProblemCode,
    pub title: String,
    pub detail: String,
    pub trace_id: String,
    pub validation: Option<ReviewValidationError>,
}

impl fmt::Debug for ReviewProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewProblem")
            .field("code", &self.code)
            .field("title", &"<validated problem text>")
            .field("detail", &"<validated problem text>")
            .field("trace_id", &self.trace_id)
            .field("validation", &self.validation)
            .finish()
    }
}

impl fmt::Display for ReviewProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
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
    #[error("review service refused the request (HTTP {status}, problem {problem})")]
    Problem {
        status: u16,
        problem: Box<ReviewProblem>,
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

    /// Classify a create or cancellation failure without guessing whether the
    /// service committed a mutation before the failure became observable.
    #[must_use]
    pub fn mutation_class(&self) -> ReviewMutationErrorClass {
        match self {
            Self::Configuration { .. } | Self::InvalidRequest { .. } => {
                ReviewMutationErrorClass::Deterministic
            }
            Self::Problem { status, .. } if *status < 500 => {
                ReviewMutationErrorClass::Deterministic
            }
            Self::Transport { .. } | Self::Problem { .. } | Self::Protocol { .. } => {
                ReviewMutationErrorClass::Ambiguous
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReviewValidationReason;

    /// The client reads the validation reason header in the spelling the
    /// Casework runtime writes; the previous spelling is an unknown word.
    #[test]
    fn every_validation_reason_is_read_in_kebab_case_only() {
        let reasons = [
            ("kind-not-allowed", ReviewValidationReason::KindNotAllowed),
            (
                "reference-invalid",
                ReviewValidationReason::ReferenceInvalid,
            ),
            ("object-required", ReviewValidationReason::ObjectRequired),
            (
                "maximum-bytes-exceeded",
                ReviewValidationReason::MaximumBytesExceeded,
            ),
            (
                "maximum-depth-exceeded",
                ReviewValidationReason::MaximumDepthExceeded,
            ),
            ("schema-mismatch", ReviewValidationReason::SchemaMismatch),
            (
                "outcome-not-declared",
                ReviewValidationReason::OutcomeNotDeclared,
            ),
            ("reason-required", ReviewValidationReason::ReasonRequired),
            ("text-invalid", ReviewValidationReason::TextInvalid),
            (
                "result-not-declared",
                ReviewValidationReason::ResultNotDeclared,
            ),
            ("result-required", ReviewValidationReason::ResultRequired),
            (
                "field-not-declared",
                ReviewValidationReason::FieldNotDeclared,
            ),
            (
                "constraint-invalid",
                ReviewValidationReason::ConstraintInvalid,
            ),
            (
                "constraint-violated",
                ReviewValidationReason::ConstraintViolated,
            ),
        ];
        for (word, reason) in reasons {
            assert_eq!(ReviewValidationReason::parse(word), Some(reason), "{word}");
            assert_eq!(
                ReviewValidationReason::parse(&word.replace('-', "_")),
                None,
                "{word}"
            );
        }
    }
}
