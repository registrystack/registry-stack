use registry_casework_core::{ReviewValidationError, ReviewValidationReason};
use registry_casework_core::{
    ABSENCE_COVER_CYCLE_PROBLEM, ABSENCE_INVALID_PERIOD_PROBLEM, ABSENCE_OVERLAP_PROBLEM,
    ABSENCE_SELF_COVER_PROBLEM, AUTHENTICATION_REFUSED_PROBLEM,
    CLOCK_RECOMPUTE_PREVIEW_EXPIRED_PROBLEM, CURSOR_EXPIRED_PROBLEM, CURSOR_INVALID_PROBLEM,
    IDEMPOTENCY_EXPIRED_PROBLEM, IDEMPOTENCY_KEY_REUSED_PROBLEM, OPERATION_NOT_AUTHORIZED_PROBLEM,
    PRECONDITION_FAILED_PROBLEM, PRECONDITION_REQUIRED_PROBLEM, PROFILE_NOT_AUTHORIZED_PROBLEM,
    PROFILE_NOT_HUMAN_PROBLEM, REQUEST_BODY_TOO_LARGE_PROBLEM, REQUEST_INVALID_PROBLEM,
    REQUEST_METHOD_NOT_ALLOWED_PROBLEM, REQUEST_NOT_FOUND_PROBLEM,
    REQUEST_REASON_UNSUPPORTED_PROBLEM, REQUEST_SOURCE_REJECTED_PROBLEM,
    REQUEST_UNPROCESSABLE_PROBLEM, REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM, RUNTIME_FAILURE_PROBLEM,
    SERVICE_UNAVAILABLE_PROBLEM, SOURCE_BAD_GATEWAY_PROBLEM, SOURCE_NOT_FOUND_PROBLEM,
    SOURCE_PROFILE_NOT_APPLICABLE_PROBLEM, SOURCE_PROFILE_REQUIRED_PROBLEM,
    SOURCE_RECORD_MISSING_PROBLEM, SOURCE_REVIEWER_NOT_AUTHORIZED_PROBLEM,
    SOURCE_SIGNATURE_INVALID_PROBLEM, WORK_ITEM_ALREADY_CLAIMED_PROBLEM,
    WORK_ITEM_NOT_HOLDER_PROBLEM, WORK_ITEM_NOT_OFFERED_PROBLEM, WORK_ITEM_NOT_VISIBLE_PROBLEM,
    WORK_ITEM_PROPOSAL_CHANGED_PROBLEM, WORK_ITEM_RECOVERY_PENDING_PROBLEM,
    WORK_ITEM_SOURCE_UNAVAILABLE_PROBLEM, WORK_ITEM_SUPERSEDED_PROBLEM,
};
use registry_platform_httputil::client::TransportKind;
use std::fmt;
use thiserror::Error;

const REVIEW_INITIATOR_EXCLUDED_PROBLEM: &str = "review.initiator-excluded";
const REVIEW_INITIATOR_REQUIRED_PROBLEM: &str = "review.initiator-required";
const REVIEW_RESULT_EXPIRED_PROBLEM: &str = "review.result-expired";
const REVIEW_SUBMISSION_CONFLICT_PROBLEM: &str = "review.submission-conflict";
const REVIEW_TASK_NOT_HELD_PROBLEM: &str = "review.task-not-held";

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
    RequestReasonUnsupported,
    RequestSourceRejected,
    RequestUnprocessable,
    RequestUnsupportedMediaType,
    ReviewInitiatorExcluded,
    ReviewInitiatorRequired,
    ReviewResultExpired,
    ReviewSubmissionConflict,
    ReviewTaskNotHeld,
    RuntimeFailure,
    ServiceUnavailable,
    SourceProfileNotApplicable,
    SourceProfileRequired,
    SourceBadGateway,
    SourceNotFound,
    SourceRecordMissing,
    SourceReviewerNotAuthorized,
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
    pub const ALL: [Self; 45] = [
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
        Self::RequestReasonUnsupported,
        Self::RequestSourceRejected,
        Self::RequestUnprocessable,
        Self::RequestUnsupportedMediaType,
        Self::ReviewInitiatorExcluded,
        Self::ReviewInitiatorRequired,
        Self::ReviewResultExpired,
        Self::ReviewSubmissionConflict,
        Self::ReviewTaskNotHeld,
        Self::RuntimeFailure,
        Self::ServiceUnavailable,
        Self::SourceProfileNotApplicable,
        Self::SourceProfileRequired,
        Self::SourceBadGateway,
        Self::SourceNotFound,
        Self::SourceRecordMissing,
        Self::SourceReviewerNotAuthorized,
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
            Self::RequestReasonUnsupported => REQUEST_REASON_UNSUPPORTED_PROBLEM,
            Self::RequestSourceRejected => REQUEST_SOURCE_REJECTED_PROBLEM,
            Self::RequestUnprocessable => REQUEST_UNPROCESSABLE_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::ReviewResultExpired => REVIEW_RESULT_EXPIRED_PROBLEM,
            Self::ReviewInitiatorExcluded => REVIEW_INITIATOR_EXCLUDED_PROBLEM,
            Self::ReviewInitiatorRequired => REVIEW_INITIATOR_REQUIRED_PROBLEM,
            Self::ReviewSubmissionConflict => REVIEW_SUBMISSION_CONFLICT_PROBLEM,
            Self::ReviewTaskNotHeld => REVIEW_TASK_NOT_HELD_PROBLEM,
            Self::RuntimeFailure => RUNTIME_FAILURE_PROBLEM,
            Self::ServiceUnavailable => SERVICE_UNAVAILABLE_PROBLEM,
            Self::SourceProfileNotApplicable => SOURCE_PROFILE_NOT_APPLICABLE_PROBLEM,
            Self::SourceProfileRequired => SOURCE_PROFILE_REQUIRED_PROBLEM,
            Self::SourceBadGateway => SOURCE_BAD_GATEWAY_PROBLEM,
            Self::SourceNotFound => SOURCE_NOT_FOUND_PROBLEM,
            Self::SourceRecordMissing => SOURCE_RECORD_MISSING_PROBLEM,
            Self::SourceReviewerNotAuthorized => SOURCE_REVIEWER_NOT_AUTHORIZED_PROBLEM,
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
            REQUEST_REASON_UNSUPPORTED_PROBLEM => Self::RequestReasonUnsupported,
            REQUEST_SOURCE_REJECTED_PROBLEM => Self::RequestSourceRejected,
            REQUEST_UNPROCESSABLE_PROBLEM => Self::RequestUnprocessable,
            REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM => Self::RequestUnsupportedMediaType,
            REVIEW_RESULT_EXPIRED_PROBLEM => Self::ReviewResultExpired,
            REVIEW_INITIATOR_EXCLUDED_PROBLEM => Self::ReviewInitiatorExcluded,
            REVIEW_INITIATOR_REQUIRED_PROBLEM => Self::ReviewInitiatorRequired,
            REVIEW_SUBMISSION_CONFLICT_PROBLEM => Self::ReviewSubmissionConflict,
            REVIEW_TASK_NOT_HELD_PROBLEM => Self::ReviewTaskNotHeld,
            RUNTIME_FAILURE_PROBLEM => Self::RuntimeFailure,
            SERVICE_UNAVAILABLE_PROBLEM => Self::ServiceUnavailable,
            SOURCE_PROFILE_NOT_APPLICABLE_PROBLEM => Self::SourceProfileNotApplicable,
            SOURCE_PROFILE_REQUIRED_PROBLEM => Self::SourceProfileRequired,
            SOURCE_BAD_GATEWAY_PROBLEM => Self::SourceBadGateway,
            SOURCE_NOT_FOUND_PROBLEM => Self::SourceNotFound,
            SOURCE_RECORD_MISSING_PROBLEM => Self::SourceRecordMissing,
            SOURCE_REVIEWER_NOT_AUTHORIZED_PROBLEM => Self::SourceReviewerNotAuthorized,
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
            Self::ClockRecomputePreviewExpired
            | Self::CursorExpired
            | Self::ReviewResultExpired => 410,
            Self::CursorInvalid => 400,
            Self::IdempotencyExpired => 410,
            Self::ProfileNotAuthorized
            | Self::ProfileNotHuman
            | Self::OperationNotAuthorized
            | Self::ReviewInitiatorExcluded => 403,
            Self::RequestInvalid
            | Self::SourceProfileNotApplicable
            | Self::SourceProfileRequired
            | Self::SourceSignatureInvalid => 400,
            Self::RequestNotFound
            | Self::SourceNotFound
            | Self::SourceRecordMissing
            | Self::WorkItemNotVisible => 404,
            Self::RequestMethodNotAllowed => 405,
            Self::IdempotencyKeyReused
            | Self::WorkItemAlreadyClaimed
            | Self::WorkItemNotHolder
            | Self::WorkItemNotOffered
            | Self::WorkItemProposalChanged
            | Self::WorkItemRecoveryPending
            | Self::ReviewSubmissionConflict
            | Self::ReviewTaskNotHeld
            | Self::WorkItemSuperseded => 409,
            Self::PreconditionFailed => 412,
            Self::RequestBodyTooLarge => 413,
            Self::RequestUnsupportedMediaType => 415,
            Self::RequestReasonUnsupported
            | Self::RequestSourceRejected
            | Self::RequestUnprocessable
            | Self::ReviewInitiatorRequired => 422,
            Self::PreconditionRequired => 428,
            Self::SourceBadGateway => 502,
            Self::SourceReviewerNotAuthorized => 403,
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
            Self::RequestReasonUnsupported => (
                "Reason not supported",
                "The reason field is not supported for approve or apply on this source. Omit it and try again.",
            ),
            Self::RequestSourceRejected => (
                "Source rejected request",
                "The source refused the request body. Fix the request before trying again.",
            ),
            Self::RequestUnprocessable => (
                "Request could not be processed",
                "The request body does not match the Casework contract.",
            ),
            Self::RequestUnsupportedMediaType => (
                "Unsupported media type",
                "Send a JSON request body with Content-Type application/json.",
            ),
            Self::ReviewInitiatorExcluded => (
                "Review initiator excluded",
                "You submitted this request, and this review stage excludes the person who submitted it. Another reviewer must take it.",
            ),
            Self::ReviewInitiatorRequired => (
                "Review initiator required",
                "This review kind excludes the person who submitted the request, so the request must name its initiator.",
            ),
            Self::ReviewResultExpired => (
                "Review result expired",
                "The retained review result is no longer available. Reconcile through the producer's retained source correlation.",
            ),
            Self::ReviewSubmissionConflict => (
                "Review submission conflict",
                "The same producer, source subject, version, and policy were already submitted with different canonical content.",
            ),
            Self::ReviewTaskNotHeld => (
                "Review task not held",
                "Claim the review task before deciding it, and decide only while the claim remains current.",
            ),
            Self::RuntimeFailure => (
                "Casework runtime failure",
                "Casework could not complete the request.",
            ),
            Self::ServiceUnavailable => (
                "Casework service unavailable",
                "Casework storage is unavailable. Try again after the service recovers.",
            ),
            Self::SourceProfileNotApplicable => (
                "Source profile not applicable",
                "Omit the Registry-Source-Profile header for this request.",
            ),
            Self::SourceProfileRequired => (
                "Source profile required",
                "Send the Registry-Source-Profile header to select the source profile for this request.",
            ),
            Self::SourceBadGateway => (
                "Invalid source response",
                "The source returned a response that does not match its registered contract.",
            ),
            Self::SourceNotFound => (
                "Source not found",
                "The requested source is not registered.",
            ),
            Self::SourceRecordMissing => (
                "Source record missing",
                "The bound source record is no longer at the registered location.",
            ),
            Self::SourceReviewerNotAuthorized => (
                "Source reviewer not authorized",
                "The source refused the reviewer binding. Check the selected source profile and credential.",
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
        validation: Option<ReviewValidationError>,
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

    /// Classify a mutation failure for exact-key recovery decisions.
    #[must_use]
    pub fn mutation_class(&self) -> registry_review_client::ReviewMutationErrorClass {
        use registry_review_client::ReviewMutationErrorClass::{Ambiguous, Deterministic};

        match self {
            Self::Configuration { .. } | Self::InvalidRequest { .. } => Deterministic,
            Self::Problem { status, .. } if *status < 500 => Deterministic,
            Self::Transport { .. } | Self::Problem { .. } | Self::Protocol { .. } => Ambiguous,
        }
    }

    pub(crate) fn from_review(error: registry_review_client::ReviewClientError) -> Self {
        use registry_review_client::{ReviewClientError, ReviewProtocolFailure};

        match error {
            ReviewClientError::Configuration { reason } => Self::Configuration { reason },
            ReviewClientError::InvalidRequest { reason } => Self::InvalidRequest { reason },
            ReviewClientError::Transport { kind } => Self::Transport { kind },
            ReviewClientError::Protocol {
                status,
                failure,
                trace_id,
            } => Self::Protocol {
                status,
                failure: match failure {
                    ReviewProtocolFailure::HeaderBounds => CaseworkProtocolFailure::HeaderBounds,
                    ReviewProtocolFailure::TraceContext => CaseworkProtocolFailure::TraceContext,
                    ReviewProtocolFailure::MediaType => CaseworkProtocolFailure::MediaType,
                    ReviewProtocolFailure::Body => CaseworkProtocolFailure::Body,
                    ReviewProtocolFailure::Problem => CaseworkProtocolFailure::Problem,
                    ReviewProtocolFailure::Status => CaseworkProtocolFailure::Status,
                    _ => CaseworkProtocolFailure::Status,
                },
                trace_id,
            },
            ReviewClientError::Problem { status, problem } => {
                let registry_review_client::ReviewProblem {
                    code,
                    title,
                    detail,
                    trace_id,
                    validation,
                } = *problem;
                let code = CaseworkProblemCode::parse(code.as_str());
                let expected_text = code.expected_text();
                if code
                    .expected_status()
                    .is_some_and(|expected| expected != status)
                    || expected_text
                        .is_some_and(|expected| expected != (title.as_str(), detail.as_str()))
                {
                    return Self::Protocol {
                        status,
                        failure: CaseworkProtocolFailure::Problem,
                        trace_id: Some(trace_id),
                    };
                }
                let validation = match validation {
                    None => None,
                    Some(validation) => {
                        let reason = match validation.reason {
                        registry_review_client::ReviewValidationReason::KindNotAllowed => {
                            ReviewValidationReason::KindNotAllowed
                        }
                        registry_review_client::ReviewValidationReason::ReferenceInvalid => {
                            ReviewValidationReason::ReferenceInvalid
                        }
                        registry_review_client::ReviewValidationReason::ObjectRequired => {
                            ReviewValidationReason::ObjectRequired
                        }
                        registry_review_client::ReviewValidationReason::MaximumBytesExceeded => {
                            ReviewValidationReason::MaximumBytesExceeded
                        }
                        registry_review_client::ReviewValidationReason::MaximumDepthExceeded => {
                            ReviewValidationReason::MaximumDepthExceeded
                        }
                        registry_review_client::ReviewValidationReason::SchemaMismatch => {
                            ReviewValidationReason::SchemaMismatch
                        }
                        registry_review_client::ReviewValidationReason::OutcomeNotDeclared => {
                            ReviewValidationReason::OutcomeNotDeclared
                        }
                        registry_review_client::ReviewValidationReason::ReasonRequired => {
                            ReviewValidationReason::ReasonRequired
                        }
                        registry_review_client::ReviewValidationReason::TextInvalid => {
                            ReviewValidationReason::TextInvalid
                        }
                        registry_review_client::ReviewValidationReason::ResultNotDeclared => {
                            ReviewValidationReason::ResultNotDeclared
                        }
                        registry_review_client::ReviewValidationReason::ResultRequired => {
                            ReviewValidationReason::ResultRequired
                        }
                        registry_review_client::ReviewValidationReason::FieldNotDeclared => {
                            ReviewValidationReason::FieldNotDeclared
                        }
                        registry_review_client::ReviewValidationReason::ConstraintInvalid => {
                            ReviewValidationReason::ConstraintInvalid
                        }
                        registry_review_client::ReviewValidationReason::ConstraintViolated => {
                            ReviewValidationReason::ConstraintViolated
                        }
                            _ => {
                                return Self::Protocol {
                                    status,
                                    failure: CaseworkProtocolFailure::Problem,
                                    trace_id: Some(trace_id),
                                }
                            }
                        };
                        Some(ReviewValidationError {
                            path: validation.path,
                            reason,
                        })
                    }
                };
                Self::Problem {
                    status,
                    code,
                    detail: expected_text.map(|(_, detail)| detail.to_owned()),
                    trace_id: Some(trace_id),
                    original_attempt_id: None,
                    validation,
                }
            }
            _ => Self::Protocol {
                status: 0,
                failure: CaseworkProtocolFailure::Status,
                trace_id: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_failures_distinguish_refusal_from_ambiguous_outcome() {
        let refusal = CaseworkClientError::Problem {
            status: 409,
            code: CaseworkProblemCode::ReviewSubmissionConflict,
            detail: None,
            trace_id: None,
            original_attempt_id: None,
            validation: None,
        };
        assert_eq!(
            refusal.mutation_class(),
            registry_review_client::ReviewMutationErrorClass::Deterministic
        );

        let invalid_response = CaseworkClientError::Protocol {
            status: 503,
            failure: CaseworkProtocolFailure::Status,
            trace_id: None,
        };
        assert_eq!(
            invalid_response.mutation_class(),
            registry_review_client::ReviewMutationErrorClass::Ambiguous
        );
    }

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

    #[test]
    fn review_lifecycle_problems_have_exact_recovery_contracts() {
        for (value, expected, status, title, detail) in [
            (
                "review.initiator-excluded",
                CaseworkProblemCode::ReviewInitiatorExcluded,
                403,
                "Review initiator excluded",
                "You submitted this request, and this review stage excludes the person who submitted it. Another reviewer must take it.",
            ),
            (
                "review.initiator-required",
                CaseworkProblemCode::ReviewInitiatorRequired,
                422,
                "Review initiator required",
                "This review kind excludes the person who submitted the request, so the request must name its initiator.",
            ),
            (
                "review.result-expired",
                CaseworkProblemCode::ReviewResultExpired,
                410,
                "Review result expired",
                "The retained review result is no longer available. Reconcile through the producer's retained source correlation.",
            ),
            (
                "review.submission-conflict",
                CaseworkProblemCode::ReviewSubmissionConflict,
                409,
                "Review submission conflict",
                "The same producer, source subject, version, and policy were already submitted with different canonical content.",
            ),
            (
                "review.task-not-held",
                CaseworkProblemCode::ReviewTaskNotHeld,
                409,
                "Review task not held",
                "Claim the review task before deciding it, and decide only while the claim remains current.",
            ),
        ] {
            let code = CaseworkProblemCode::parse(value);
            assert_eq!(code, expected);
            assert_eq!(code.expected_status(), Some(status));
            assert_eq!(code.expected_text(), Some((title, detail)));
        }
    }

    #[test]
    fn source_profile_header_problems_have_exact_recovery_contracts() {
        for (value, expected, title, detail) in [
            (
                "source-profile.not-applicable",
                CaseworkProblemCode::SourceProfileNotApplicable,
                "Source profile not applicable",
                "Omit the Registry-Source-Profile header for this request.",
            ),
            (
                "source-profile.required",
                CaseworkProblemCode::SourceProfileRequired,
                "Source profile required",
                "Send the Registry-Source-Profile header to select the source profile for this request.",
            ),
        ] {
            let code = CaseworkProblemCode::parse(value);
            assert_eq!(code, expected);
            assert_eq!(code.expected_status(), Some(400));
            assert_eq!(code.expected_text(), Some((title, detail)));
        }
    }

    #[test]
    fn source_refusal_problems_have_exact_safe_contracts() {
        for (value, expected, status, title, detail) in [
            (
                "request.source-rejected",
                CaseworkProblemCode::RequestSourceRejected,
                422,
                "Source rejected request",
                "The source refused the request body. Fix the request before trying again.",
            ),
            (
                "source.record-missing",
                CaseworkProblemCode::SourceRecordMissing,
                404,
                "Source record missing",
                "The bound source record is no longer at the registered location.",
            ),
            (
                "source.reviewer-not-authorized",
                CaseworkProblemCode::SourceReviewerNotAuthorized,
                403,
                "Source reviewer not authorized",
                "The source refused the reviewer binding. Check the selected source profile and credential.",
            ),
        ] {
            let code = CaseworkProblemCode::parse(value);
            assert_eq!(code, expected);
            assert_eq!(code.expected_status(), Some(status));
            assert_eq!(code.expected_text(), Some((title, detail)));
        }
    }
}
