// SPDX-License-Identifier: Apache-2.0

//! The problem codes that refuse a caller's authority.
//!
//! Kept apart from the request path so the vocabulary classification names
//! every problem code on purpose: the OpenAPI generator reads the request
//! path for the codes it produces, and a classification there would count
//! every code as produced.

use registry_scheduling_core::ProblemCode;

/// The problem codes that refuse a caller's authority. A refusal is built
/// with the check it failed (`ServiceError::Refused`), never from the bare
/// code, so the operator's counter and log line can name the check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalCode {
    AuthenticationRefused,
    DevelopmentAssertion,
    GrantLifetimeTooLong,
    OperationNotAuthorized,
    ProfileNotAuthorized,
}

impl RefusalCode {
    /// The problem this refusal answers with.
    #[must_use]
    pub const fn problem(self) -> ProblemCode {
        match self {
            Self::AuthenticationRefused => ProblemCode::AuthenticationRefused,
            Self::DevelopmentAssertion => ProblemCode::PlatformTaskGrantDevelopmentAssertion,
            Self::GrantLifetimeTooLong => ProblemCode::GrantLifetimeTooLong,
            Self::OperationNotAuthorized => ProblemCode::OperationNotAuthorized,
            Self::ProfileNotAuthorized => ProblemCode::ProfileNotAuthorized,
        }
    }

    /// Sort a problem into a refusal or a plain answer. The match names every
    /// code, so a code added to the vocabulary does not compile until it is
    /// sorted here. The vocabulary test in `http.rs` pins the refusal set.
    #[must_use]
    #[deny(clippy::wildcard_enum_match_arm)]
    pub const fn of(problem: ProblemCode) -> Option<Self> {
        match problem {
            ProblemCode::AuthenticationRefused => Some(Self::AuthenticationRefused),
            ProblemCode::PlatformTaskGrantDevelopmentAssertion => Some(Self::DevelopmentAssertion),
            ProblemCode::GrantLifetimeTooLong => Some(Self::GrantLifetimeTooLong),
            ProblemCode::OperationNotAuthorized => Some(Self::OperationNotAuthorized),
            ProblemCode::ProfileNotAuthorized => Some(Self::ProfileNotAuthorized),
            ProblemCode::BookingDuplicateActive
            | ProblemCode::CancellationCutoffPassed
            | ProblemCode::CapabilityUnmatched
            | ProblemCode::CapacityExhausted
            | ProblemCode::CursorExpired
            | ProblemCode::CursorInvalid
            | ProblemCode::EligibilityUnavailable
            | ProblemCode::HoldExpired
            | ProblemCode::HoldReleased
            | ProblemCode::HookUnavailable
            | ProblemCode::HorizonOutside
            | ProblemCode::IdempotencyExpired
            | ProblemCode::IdempotencyKeyReused
            | ProblemCode::LocationClosed
            | ProblemCode::PartyCapacityInadequate
            | ProblemCode::PolicyChanged
            | ProblemCode::PreconditionFailed
            | ProblemCode::PreconditionRequired
            | ProblemCode::PrerequisiteMissing
            | ProblemCode::ReceiptUnresolved
            | ProblemCode::RequestBodyTooLarge
            | ProblemCode::RequestInvalid
            | ProblemCode::RequestMethodNotAllowed
            | ProblemCode::RequestNotFound
            | ProblemCode::RequestUnprocessable
            | ProblemCode::RequestUnsupportedMediaType
            | ProblemCode::ResourceUnavailable
            | ProblemCode::RevisionMismatch
            | ProblemCode::ScheduleUnpublished
            | ProblemCode::ServiceUnavailable => None,
        }
    }
}
