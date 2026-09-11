use registry_casework_core::HostedValidationError;
use registry_casework_core::{
    ABSENCE_COVER_CYCLE_PROBLEM, ABSENCE_INVALID_PERIOD_PROBLEM, ABSENCE_OVERLAP_PROBLEM,
    ABSENCE_SELF_COVER_PROBLEM, AUTHENTICATION_REFUSED_PROBLEM,
    CLOCK_RECOMPUTE_PREVIEW_EXPIRED_PROBLEM, CURSOR_EXPIRED_PROBLEM, CURSOR_INVALID_PROBLEM,
    IDEMPOTENCY_EXPIRED_PROBLEM, IDEMPOTENCY_KEY_REUSED_PROBLEM, OPERATION_NOT_AUTHORIZED_PROBLEM,
    PRECONDITION_FAILED_PROBLEM, PRECONDITION_REQUIRED_PROBLEM, PROFILE_NOT_AUTHORIZED_PROBLEM,
    PROFILE_NOT_HUMAN_PROBLEM, REQUEST_BODY_TOO_LARGE_PROBLEM, REQUEST_INVALID_PROBLEM,
    REQUEST_METHOD_NOT_ALLOWED_PROBLEM, REQUEST_NOT_FOUND_PROBLEM, REQUEST_UNPROCESSABLE_PROBLEM,
    REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM, RUNTIME_FAILURE_PROBLEM, SERVICE_UNAVAILABLE_PROBLEM,
    SOURCE_BAD_GATEWAY_PROBLEM, SOURCE_NOT_FOUND_PROBLEM, SOURCE_SIGNATURE_INVALID_PROBLEM,
    WORK_ITEM_ALREADY_CLAIMED_PROBLEM, WORK_ITEM_NOT_HOLDER_PROBLEM, WORK_ITEM_NOT_OFFERED_PROBLEM,
    WORK_ITEM_NOT_VISIBLE_PROBLEM, WORK_ITEM_PROPOSAL_CHANGED_PROBLEM,
    WORK_ITEM_RECOVERY_PENDING_PROBLEM, WORK_ITEM_SOURCE_UNAVAILABLE_PROBLEM,
    WORK_ITEM_SUPERSEDED_PROBLEM,
};
use registry_platform_httputil::client::TransportKind;
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaseworkProtocolFailure {
    HeaderBounds,
    TraceContext,
    MediaType,
    Body,
    Problem,
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaseworkProblemCode {
    AbsenceCoverCycle,
    AbsenceInvalidPeriod,
    AbsenceOverlap,
    AbsenceSelfCover,
    AuthenticationRefused,
    ClockRecomputePreviewExpired,
    CursorExpired,
    CursorInvalid,
    IdempotencyExpired,
    IdempotencyKeyReused,
    OperationNotAuthorized,
    PreconditionFailed,
    PreconditionRequired,
    ProfileNotAuthorized,
    ProfileNotHuman,
    RequestBodyTooLarge,
    RequestInvalid,
    RequestMethodNotAllowed,
    RequestNotFound,
    RequestUnprocessable,
    RequestUnsupportedMediaType,
    RuntimeFailure,
    ServiceUnavailable,
    SourceBadGateway,
    SourceNotFound,
    SourceSignatureInvalid,
    WorkItemAlreadyClaimed,
    WorkItemNotHolder,
    WorkItemNotOffered,
    WorkItemNotVisible,
    WorkItemProposalChanged,
    WorkItemRecoveryPending,
    WorkItemSourceUnavailable,
    WorkItemSuperseded,
    /// An unrecognized problem code from a newer Casework service.
    Unknown(String),
}

impl CaseworkProblemCode {
    /// Every code this client recognizes, in code-string order.
    ///
    /// `Unknown` is absent: it carries whatever a newer Casework service
    /// answered, so it names no registered code.
    pub const ALL: [Self; 34] = [
        Self::AbsenceCoverCycle,
        Self::AbsenceInvalidPeriod,
        Self::AbsenceOverlap,
        Self::AbsenceSelfCover,
        Self::AuthenticationRefused,
        Self::ClockRecomputePreviewExpired,
        Self::CursorExpired,
        Self::CursorInvalid,
        Self::IdempotencyExpired,
        Self::IdempotencyKeyReused,
        Self::OperationNotAuthorized,
        Self::PreconditionFailed,
        Self::PreconditionRequired,
        Self::ProfileNotAuthorized,
        Self::ProfileNotHuman,
        Self::RequestBodyTooLarge,
        Self::RequestInvalid,
        Self::RequestMethodNotAllowed,
        Self::RequestNotFound,
        Self::RequestUnprocessable,
        Self::RequestUnsupportedMediaType,
        Self::RuntimeFailure,
        Self::ServiceUnavailable,
        Self::SourceBadGateway,
        Self::SourceNotFound,
        Self::SourceSignatureInvalid,
        Self::WorkItemAlreadyClaimed,
        Self::WorkItemNotHolder,
        Self::WorkItemNotOffered,
        Self::WorkItemNotVisible,
        Self::WorkItemProposalChanged,
        Self::WorkItemRecoveryPending,
        Self::WorkItemSourceUnavailable,
        Self::WorkItemSuperseded,
    ];

    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::AbsenceCoverCycle => ABSENCE_COVER_CYCLE_PROBLEM,
            Self::AbsenceInvalidPeriod => ABSENCE_INVALID_PERIOD_PROBLEM,
            Self::AbsenceOverlap => ABSENCE_OVERLAP_PROBLEM,
            Self::AbsenceSelfCover => ABSENCE_SELF_COVER_PROBLEM,
            Self::AuthenticationRefused => AUTHENTICATION_REFUSED_PROBLEM,
            Self::ClockRecomputePreviewExpired => CLOCK_RECOMPUTE_PREVIEW_EXPIRED_PROBLEM,
            Self::CursorExpired => CURSOR_EXPIRED_PROBLEM,
            Self::CursorInvalid => CURSOR_INVALID_PROBLEM,
            Self::IdempotencyExpired => IDEMPOTENCY_EXPIRED_PROBLEM,
            Self::IdempotencyKeyReused => IDEMPOTENCY_KEY_REUSED_PROBLEM,
            Self::OperationNotAuthorized => OPERATION_NOT_AUTHORIZED_PROBLEM,
            Self::PreconditionFailed => PRECONDITION_FAILED_PROBLEM,
            Self::PreconditionRequired => PRECONDITION_REQUIRED_PROBLEM,
            Self::ProfileNotAuthorized => PROFILE_NOT_AUTHORIZED_PROBLEM,
            Self::ProfileNotHuman => PROFILE_NOT_HUMAN_PROBLEM,
            Self::RequestBodyTooLarge => REQUEST_BODY_TOO_LARGE_PROBLEM,
            Self::RequestInvalid => REQUEST_INVALID_PROBLEM,
            Self::RequestMethodNotAllowed => REQUEST_METHOD_NOT_ALLOWED_PROBLEM,
            Self::RequestNotFound => REQUEST_NOT_FOUND_PROBLEM,
            Self::RequestUnprocessable => REQUEST_UNPROCESSABLE_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::RuntimeFailure => RUNTIME_FAILURE_PROBLEM,
            Self::ServiceUnavailable => SERVICE_UNAVAILABLE_PROBLEM,
            Self::SourceBadGateway => SOURCE_BAD_GATEWAY_PROBLEM,
            Self::SourceNotFound => SOURCE_NOT_FOUND_PROBLEM,
            Self::SourceSignatureInvalid => SOURCE_SIGNATURE_INVALID_PROBLEM,
            Self::WorkItemAlreadyClaimed => WORK_ITEM_ALREADY_CLAIMED_PROBLEM,
            Self::WorkItemNotHolder => WORK_ITEM_NOT_HOLDER_PROBLEM,
            Self::WorkItemNotOffered => WORK_ITEM_NOT_OFFERED_PROBLEM,
            Self::WorkItemNotVisible => WORK_ITEM_NOT_VISIBLE_PROBLEM,
            Self::WorkItemProposalChanged => WORK_ITEM_PROPOSAL_CHANGED_PROBLEM,
            Self::WorkItemRecoveryPending => WORK_ITEM_RECOVERY_PENDING_PROBLEM,
            Self::WorkItemSourceUnavailable => WORK_ITEM_SOURCE_UNAVAILABLE_PROBLEM,
            Self::WorkItemSuperseded => WORK_ITEM_SUPERSEDED_PROBLEM,
            Self::Unknown(code) => code,
        }
    }

    pub(crate) fn parse(value: &str) -> Self {
        match value {
            ABSENCE_COVER_CYCLE_PROBLEM => Self::AbsenceCoverCycle,
            ABSENCE_INVALID_PERIOD_PROBLEM => Self::AbsenceInvalidPeriod,
            ABSENCE_OVERLAP_PROBLEM => Self::AbsenceOverlap,
            ABSENCE_SELF_COVER_PROBLEM => Self::AbsenceSelfCover,
            AUTHENTICATION_REFUSED_PROBLEM => Self::AuthenticationRefused,
            CLOCK_RECOMPUTE_PREVIEW_EXPIRED_PROBLEM => Self::ClockRecomputePreviewExpired,
            CURSOR_EXPIRED_PROBLEM => Self::CursorExpired,
            CURSOR_INVALID_PROBLEM => Self::CursorInvalid,
            IDEMPOTENCY_EXPIRED_PROBLEM => Self::IdempotencyExpired,
            IDEMPOTENCY_KEY_REUSED_PROBLEM => Self::IdempotencyKeyReused,
            OPERATION_NOT_AUTHORIZED_PROBLEM => Self::OperationNotAuthorized,
            PRECONDITION_FAILED_PROBLEM => Self::PreconditionFailed,
            PRECONDITION_REQUIRED_PROBLEM => Self::PreconditionRequired,
            PROFILE_NOT_AUTHORIZED_PROBLEM => Self::ProfileNotAuthorized,
            PROFILE_NOT_HUMAN_PROBLEM => Self::ProfileNotHuman,
            REQUEST_BODY_TOO_LARGE_PROBLEM => Self::RequestBodyTooLarge,
            REQUEST_INVALID_PROBLEM => Self::RequestInvalid,
            REQUEST_METHOD_NOT_ALLOWED_PROBLEM => Self::RequestMethodNotAllowed,
            REQUEST_NOT_FOUND_PROBLEM => Self::RequestNotFound,
            REQUEST_UNPROCESSABLE_PROBLEM => Self::RequestUnprocessable,
            REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM => Self::RequestUnsupportedMediaType,
            RUNTIME_FAILURE_PROBLEM => Self::RuntimeFailure,
            SERVICE_UNAVAILABLE_PROBLEM => Self::ServiceUnavailable,
            SOURCE_BAD_GATEWAY_PROBLEM => Self::SourceBadGateway,
            SOURCE_NOT_FOUND_PROBLEM => Self::SourceNotFound,
            SOURCE_SIGNATURE_INVALID_PROBLEM => Self::SourceSignatureInvalid,
            WORK_ITEM_ALREADY_CLAIMED_PROBLEM => Self::WorkItemAlreadyClaimed,
            WORK_ITEM_NOT_HOLDER_PROBLEM => Self::WorkItemNotHolder,
            WORK_ITEM_NOT_OFFERED_PROBLEM => Self::WorkItemNotOffered,
            WORK_ITEM_NOT_VISIBLE_PROBLEM => Self::WorkItemNotVisible,
            WORK_ITEM_PROPOSAL_CHANGED_PROBLEM => Self::WorkItemProposalChanged,
            WORK_ITEM_RECOVERY_PENDING_PROBLEM => Self::WorkItemRecoveryPending,
            WORK_ITEM_SOURCE_UNAVAILABLE_PROBLEM => Self::WorkItemSourceUnavailable,
            WORK_ITEM_SUPERSEDED_PROBLEM => Self::WorkItemSuperseded,
            _ => Self::Unknown(value.to_owned()),
        }
    }

    /// The one status Casework answers this code under, or `None` for a code
    /// this client does not recognize.
    #[must_use]
    pub fn expected_status(&self) -> Option<u16> {
        Some(match self {
            Self::AbsenceCoverCycle
            | Self::AbsenceInvalidPeriod
            | Self::AbsenceOverlap
            | Self::AbsenceSelfCover => 422,
            Self::AuthenticationRefused => 401,
            Self::ClockRecomputePreviewExpired | Self::CursorExpired => 410,
            Self::CursorInvalid => 400,
            Self::IdempotencyExpired => 410,
            Self::ProfileNotAuthorized | Self::ProfileNotHuman | Self::OperationNotAuthorized => {
                403
            }
            Self::RequestInvalid | Self::SourceSignatureInvalid => 400,
            Self::RequestNotFound | Self::SourceNotFound | Self::WorkItemNotVisible => 404,
            Self::RequestMethodNotAllowed => 405,
            Self::IdempotencyKeyReused
            | Self::WorkItemAlreadyClaimed
            | Self::WorkItemNotHolder
            | Self::WorkItemNotOffered
            | Self::WorkItemProposalChanged
            | Self::WorkItemRecoveryPending
            | Self::WorkItemSuperseded => 409,
            Self::PreconditionFailed => 412,
            Self::RequestBodyTooLarge => 413,
            Self::RequestUnsupportedMediaType => 415,
            Self::RequestUnprocessable => 422,
            Self::PreconditionRequired => 428,
            Self::SourceBadGateway => 502,
            Self::RuntimeFailure => 500,
            Self::ServiceUnavailable | Self::WorkItemSourceUnavailable => 503,
            Self::Unknown(_) => return None,
        })
    }

    pub(crate) fn expected_text(&self) -> Option<(&'static str, &'static str)> {
        Some(match self {
            Self::AbsenceCoverCycle => (
                "Absence cover cycle",
                "Choose cover assignments that do not return to an earlier person during a shared period.",
            ),
            Self::AbsenceInvalidPeriod => ("Invalid absence period", "Set until later than from."),
            Self::AbsenceOverlap => (
                "Absence period overlaps",
                "Adjust the period so this person has no overlapping absence.",
            ),
            Self::AbsenceSelfCover => (
                "Absence self-cover not allowed",
                "Choose a different staff member as cover.",
            ),
            Self::AuthenticationRefused => (
                "Authentication refused",
                "The bearer credential is missing, invalid, or expired. Sign in again.",
            ),
            Self::ClockRecomputePreviewExpired => (
                "Clock recompute preview expired",
                "Create a new recompute preview and review it before applying.",
            ),
            Self::CursorExpired => (
                "Cursor expired",
                "This cursor has expired. Start again without a cursor and deduplicate entries by eventId.",
            ),
            Self::CursorInvalid => ("Cursor invalid", "The cursor is invalid for this request."),
            Self::IdempotencyExpired => (
                "Idempotency window expired",
                "The stored response for this idempotency key has expired. Reconcile the original operation before choosing a new key.",
            ),
            Self::IdempotencyKeyReused => (
                "Idempotency key reused",
                "This idempotency key was used for a different request.",
            ),
            Self::OperationNotAuthorized => (
                "Operation not authorized",
                "Your current Casework authority does not allow this operation.",
            ),
            Self::PreconditionFailed => (
                "Precondition failed",
                "The item or directory changed since you loaded it. Reload and try again.",
            ),
            Self::PreconditionRequired => (
                "Precondition required",
                "This mutation requires the revision that you loaded.",
            ),
            Self::ProfileNotAuthorized => (
                "Profile not authorized",
                "The selected Casework profile does not authorize this request.",
            ),
            Self::ProfileNotHuman => (
                "Human session required",
                "This action is reserved for a human session.",
            ),
            Self::RequestBodyTooLarge => (
                "Request body too large",
                "The request body exceeds the one MiB limit.",
            ),
            Self::RequestInvalid => ("Invalid request", "The Casework request is invalid."),
            Self::RequestMethodNotAllowed => (
                "Method not allowed",
                "This route does not accept that HTTP method.",
            ),
            Self::RequestNotFound => (
                "Route not found",
                "The requested Casework route does not exist.",
            ),
            Self::RequestUnprocessable => (
                "Request could not be processed",
                "The request body does not match the Casework contract.",
            ),
            Self::RequestUnsupportedMediaType => (
                "Unsupported media type",
                "Send a JSON request body with Content-Type application/json.",
            ),
            Self::RuntimeFailure => (
                "Casework runtime failure",
                "Casework could not complete the request.",
            ),
            Self::ServiceUnavailable => (
                "Casework service unavailable",
                "Casework storage is unavailable. Try again after the service recovers.",
            ),
            Self::SourceBadGateway => (
                "Invalid source response",
                "The source returned a response that does not match its registered contract.",
            ),
            Self::SourceNotFound => (
                "Source not found",
                "The requested source is not registered.",
            ),
            Self::SourceSignatureInvalid => (
                "Source signature invalid",
                "The event's signature did not verify.",
            ),
            Self::WorkItemAlreadyClaimed => (
                "Work item already claimed",
                "Someone else claimed this item a moment ago.",
            ),
            Self::WorkItemNotHolder => (
                "Work item held by another person",
                "You do not hold this item. Claim it first, or ask a supervisor.",
            ),
            Self::WorkItemNotOffered => (
                "Work item action not offered",
                "The registry did not offer this action to you. Refresh to check again.",
            ),
            Self::WorkItemNotVisible => (
                "Work item not visible",
                "The registry did not show you this request, so Casework cannot show you the item.",
            ),
            Self::WorkItemProposalChanged => (
                "Work item proposal changed",
                "The proposal changed since you read it. Your private draft is retained.",
            ),
            Self::WorkItemRecoveryPending => (
                "Work item recovery pending",
                "We could not confirm the result of your last action. Recover the original attempt; do not decide again.",
            ),
            Self::WorkItemSourceUnavailable => (
                "Work item source unavailable",
                "The registry is not answering. We cannot confirm the current item or its actions. Your private draft is retained.",
            ),
            Self::WorkItemSuperseded => (
                "Work item superseded",
                "A revised proposal replaced this item. Open the current one.",
            ),
            Self::Unknown(_) => return None,
        })
    }
}

impl fmt::Display for CaseworkProblemCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(_) => formatter.write_str("unknown"),
            known => formatter.write_str(known.code()),
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaseworkClientError {
    #[error("Registry Casework client configuration is invalid: {reason}")]
    Configuration { reason: &'static str },
    #[error("Registry Casework client request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("Registry Casework exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error("Registry Casework refused the request (HTTP {status}, problem {code})")]
    Problem {
        status: u16,
        code: CaseworkProblemCode,
        /// Curated human detail for a recognized, exactly validated problem.
        detail: Option<String>,
        trace_id: Option<String>,
        original_attempt_id: Option<uuid::Uuid>,
        validation: Option<HostedValidationError>,
    },
    #[error("Registry Casework returned an invalid response")]
    Protocol {
        status: u16,
        failure: CaseworkProtocolFailure,
        trace_id: Option<String>,
    },
}

impl CaseworkClientError {
    pub(crate) fn configuration(reason: &'static str) -> Self {
        Self::Configuration { reason }
    }

    pub(crate) fn invalid_request(reason: &'static str) -> Self {
        Self::InvalidRequest { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absence_validation_problems_have_exact_safe_contracts() {
        for (value, expected, title, detail) in [
            (
                "absence.cover-cycle",
                CaseworkProblemCode::AbsenceCoverCycle,
                "Absence cover cycle",
                "Choose cover assignments that do not return to an earlier person during a shared period.",
            ),
            (
                "absence.invalid-period",
                CaseworkProblemCode::AbsenceInvalidPeriod,
                "Invalid absence period",
                "Set until later than from.",
            ),
            (
                "absence.overlap",
                CaseworkProblemCode::AbsenceOverlap,
                "Absence period overlaps",
                "Adjust the period so this person has no overlapping absence.",
            ),
            (
                "absence.self-cover",
                CaseworkProblemCode::AbsenceSelfCover,
                "Absence self-cover not allowed",
                "Choose a different staff member as cover.",
            ),
        ] {
            let code = CaseworkProblemCode::parse(value);
            assert_eq!(code, expected);
            assert_eq!(code.expected_status(), Some(422));
            assert_eq!(code.expected_text(), Some((title, detail)));
        }
    }

    #[test]
    fn expired_clock_preview_has_actionable_recovery() {
        let code = CaseworkProblemCode::parse("clock.recompute-preview-expired");
        assert_eq!(code, CaseworkProblemCode::ClockRecomputePreviewExpired);
        assert_eq!(code.expected_status(), Some(410));
        assert_eq!(
            code.expected_text(),
            Some((
                "Clock recompute preview expired",
                "Create a new recompute preview and review it before applying."
            ))
        );
    }

    #[test]
    fn idempotency_expiry_has_an_exact_recoverable_contract() {
        let code = CaseworkProblemCode::parse("idempotency.expired");
        assert_eq!(code, CaseworkProblemCode::IdempotencyExpired);
        assert_eq!(code.expected_status(), Some(410));
        assert_eq!(
            code.expected_text(),
            Some((
                "Idempotency window expired",
                "The stored response for this idempotency key has expired. Reconcile the original operation before choosing a new key."
            ))
        );
    }
}
