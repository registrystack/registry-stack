// SPDX-License-Identifier: Apache-2.0

//! Closed public problem vocabulary for Registry Casework.

use axum::http::StatusCode;
use registry_casework_core::{
    ABSENCE_COVER_CYCLE_PROBLEM, ABSENCE_INVALID_PERIOD_PROBLEM, ABSENCE_OVERLAP_PROBLEM,
    ABSENCE_SELF_COVER_PROBLEM, AUTHENTICATION_REFUSED_PROBLEM, CASEWORK_PROBLEM_TYPE_BASE,
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

/// Resolve a Casework problem code under its registered product prefix.
#[must_use]
pub fn type_uri(code: &str) -> String {
    format!("{CASEWORK_PROBLEM_TYPE_BASE}{}", code.replace('.', "/"))
}

/// One problem the Casework runtime can emit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProblemCode {
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
}

impl ProblemCode {
    /// Every registered code in code-string order.
    pub const ALL: &'static [Self] = &[
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
    pub const fn code(self) -> &'static str {
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
        }
    }

    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::AbsenceCoverCycle
            | Self::AbsenceInvalidPeriod
            | Self::AbsenceOverlap
            | Self::AbsenceSelfCover => StatusCode::UNPROCESSABLE_ENTITY,
            Self::AuthenticationRefused => StatusCode::UNAUTHORIZED,
            Self::ClockRecomputePreviewExpired => StatusCode::GONE,
            Self::CursorExpired => StatusCode::GONE,
            Self::CursorInvalid => StatusCode::BAD_REQUEST,
            Self::IdempotencyExpired => StatusCode::GONE,
            Self::ProfileNotAuthorized | Self::ProfileNotHuman | Self::OperationNotAuthorized => {
                StatusCode::FORBIDDEN
            }
            Self::RequestInvalid | Self::SourceSignatureInvalid => StatusCode::BAD_REQUEST,
            Self::RequestNotFound | Self::SourceNotFound | Self::WorkItemNotVisible => {
                StatusCode::NOT_FOUND
            }
            Self::RequestMethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::IdempotencyKeyReused
            | Self::WorkItemAlreadyClaimed
            | Self::WorkItemNotHolder
            | Self::WorkItemNotOffered
            | Self::WorkItemProposalChanged
            | Self::WorkItemRecoveryPending
            | Self::WorkItemSuperseded => StatusCode::CONFLICT,
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::RequestBodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RequestUnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::RequestUnprocessable => StatusCode::UNPROCESSABLE_ENTITY,
            Self::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::SourceBadGateway => StatusCode::BAD_GATEWAY,
            Self::RuntimeFailure => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable | Self::WorkItemSourceUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AbsenceCoverCycle => "Absence cover cycle",
            Self::AbsenceInvalidPeriod => "Invalid absence period",
            Self::AbsenceOverlap => "Absence period overlaps",
            Self::AbsenceSelfCover => "Absence self-cover not allowed",
            Self::AuthenticationRefused => "Authentication refused",
            Self::ClockRecomputePreviewExpired => "Clock recompute preview expired",
            Self::CursorExpired => "Cursor expired",
            Self::CursorInvalid => "Cursor invalid",
            Self::IdempotencyExpired => "Idempotency window expired",
            Self::IdempotencyKeyReused => "Idempotency key reused",
            Self::OperationNotAuthorized => "Operation not authorized",
            Self::PreconditionFailed => "Precondition failed",
            Self::PreconditionRequired => "Precondition required",
            Self::ProfileNotAuthorized => "Profile not authorized",
            Self::ProfileNotHuman => "Human session required",
            Self::RequestBodyTooLarge => "Request body too large",
            Self::RequestInvalid => "Invalid request",
            Self::RequestMethodNotAllowed => "Method not allowed",
            Self::RequestNotFound => "Route not found",
            Self::RequestUnprocessable => "Request could not be processed",
            Self::RequestUnsupportedMediaType => "Unsupported media type",
            Self::RuntimeFailure => "Casework runtime failure",
            Self::ServiceUnavailable => "Casework service unavailable",
            Self::SourceBadGateway => "Invalid source response",
            Self::SourceNotFound => "Source not found",
            Self::SourceSignatureInvalid => "Source signature invalid",
            Self::WorkItemAlreadyClaimed => "Work item already claimed",
            Self::WorkItemNotHolder => "Work item held by another person",
            Self::WorkItemNotOffered => "Work item action not offered",
            Self::WorkItemNotVisible => "Work item not visible",
            Self::WorkItemProposalChanged => "Work item proposal changed",
            Self::WorkItemRecoveryPending => "Work item recovery pending",
            Self::WorkItemSourceUnavailable => "Work item source unavailable",
            Self::WorkItemSuperseded => "Work item superseded",
        }
    }

    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::AbsenceCoverCycle => {
                "Choose cover assignments that do not return to an earlier person during a shared period."
            }
            Self::AbsenceInvalidPeriod => "Set until later than from.",
            Self::AbsenceOverlap => "Adjust the period so this person has no overlapping absence.",
            Self::AbsenceSelfCover => "Choose a different staff member as cover.",
            Self::AuthenticationRefused => {
                "The bearer credential is missing, invalid, or expired. Sign in again."
            }
            Self::ClockRecomputePreviewExpired => {
                "Create a new recompute preview and review it before applying."
            }
            Self::CursorExpired => {
                "This cursor has expired. Start again without a cursor and deduplicate entries by eventId."
            }
            Self::CursorInvalid => "The cursor is invalid for this request.",
            Self::IdempotencyExpired => {
                "The stored response for this idempotency key has expired. Reconcile the original operation before choosing a new key."
            }
            Self::IdempotencyKeyReused => "This idempotency key was used for a different request.",
            Self::OperationNotAuthorized => {
                "Your current Casework authority does not allow this operation."
            }
            Self::PreconditionFailed => {
                "The item or directory changed since you loaded it. Reload and try again."
            }
            Self::PreconditionRequired => "This mutation requires the revision that you loaded.",
            Self::ProfileNotAuthorized => {
                "The selected Casework profile does not authorize this request."
            }
            Self::ProfileNotHuman => "This action is reserved for a human session.",
            Self::RequestBodyTooLarge => "The request body exceeds the one MiB limit.",
            Self::RequestInvalid => "The Casework request is invalid.",
            Self::RequestMethodNotAllowed => "This route does not accept that HTTP method.",
            Self::RequestNotFound => "The requested Casework route does not exist.",
            Self::RequestUnprocessable => "The request body does not match the Casework contract.",
            Self::RequestUnsupportedMediaType => {
                "Send a JSON request body with Content-Type application/json."
            }
            Self::RuntimeFailure => "Casework could not complete the request.",
            Self::ServiceUnavailable => {
                "Casework storage is unavailable. Try again after the service recovers."
            }
            Self::SourceBadGateway => {
                "The source returned a response that does not match its registered contract."
            }
            Self::SourceNotFound => "The requested source is not registered.",
            Self::SourceSignatureInvalid => "The event's signature did not verify.",
            Self::WorkItemAlreadyClaimed => "Someone else claimed this item a moment ago.",
            Self::WorkItemNotHolder => {
                "You do not hold this item. Claim it first, or ask a supervisor."
            }
            Self::WorkItemNotOffered => {
                "The registry did not offer this action to you. Refresh to check again."
            }
            Self::WorkItemNotVisible => {
                "The registry did not show you this request, so Casework cannot show you the item."
            }
            Self::WorkItemProposalChanged => {
                "The proposal changed since you read it. Your private draft is retained."
            }
            Self::WorkItemRecoveryPending => {
                "We could not confirm the result of your last action. Recover the original attempt; do not decide again."
            }
            Self::WorkItemSourceUnavailable => {
                "The registry is not answering. We cannot confirm the current item or its actions. Your private draft is retained."
            }
            Self::WorkItemSuperseded => {
                "A revised proposal replaced this item. Open the current one."
            }
        }
    }

    #[must_use]
    pub fn type_uri(self) -> String {
        type_uri(self.code())
    }
}

impl std::fmt::Display for ProblemCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Rust-owned HTTP operation and reachable-problem contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationContract {
    pub method: &'static str,
    pub path: &'static str,
    pub success_statuses: &'static [u16],
    pub extracts_path: bool,
    pub extracts_query: bool,
    pub accepts_json: bool,
    pub problems: &'static [ProblemCode],
}

const AUTHENTICATION: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
];
const HOSTED_READ: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::RuntimeFailure,
];
const HOSTED_PAGE: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::CursorExpired,
    ProblemCode::CursorInvalid,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::RuntimeFailure,
];
const HOSTED_ITEM_PAGE: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::CursorExpired,
    ProblemCode::CursorInvalid,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::RuntimeFailure,
];
const HOSTED_CREATE: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::IdempotencyExpired,
    ProblemCode::ServiceUnavailable,
    ProblemCode::RuntimeFailure,
];
const HOSTED_MUTATION: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::IdempotencyExpired,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemAlreadyClaimed,
    ProblemCode::WorkItemNotHolder,
    ProblemCode::WorkItemNotOffered,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::RuntimeFailure,
];
const ITEM_READ: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const SOURCE_ITEM_PAGE: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::CursorExpired,
    ProblemCode::CursorInvalid,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const CLAIM: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::IdempotencyExpired,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemAlreadyClaimed,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const RELEASE: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::IdempotencyExpired,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotHolder,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const DRAFT_MUTATION: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotHolder,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const DECISION: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemNotHolder,
    ProblemCode::WorkItemNotOffered,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemProposalChanged,
    ProblemCode::WorkItemRecoveryPending,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::WorkItemSuperseded,
    ProblemCode::RuntimeFailure,
];
const RECOVERY: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemRecoveryPending,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const HOLDINGS: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const DIRECTORY: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::RuntimeFailure,
];
const DIRECTORY_PAGE: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::CursorExpired,
    ProblemCode::CursorInvalid,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::RuntimeFailure,
];
const ABSENCE_CREATE: &[ProblemCode] = &[
    ProblemCode::AbsenceCoverCycle,
    ProblemCode::AbsenceInvalidPeriod,
    ProblemCode::AbsenceOverlap,
    ProblemCode::AbsenceSelfCover,
    ProblemCode::AuthenticationRefused,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::ServiceUnavailable,
    ProblemCode::RuntimeFailure,
];
const ABSENCE_UPDATE: &[ProblemCode] = &[
    ProblemCode::AbsenceCoverCycle,
    ProblemCode::AbsenceInvalidPeriod,
    ProblemCode::AbsenceOverlap,
    ProblemCode::AbsenceSelfCover,
    ProblemCode::AuthenticationRefused,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::RuntimeFailure,
];
const ABSENCE_DELETE: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::RuntimeFailure,
];
const ASSIGNMENT_MUTATION: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemRecoveryPending,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const CASELOAD_PREVIEW: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::CursorExpired,
    ProblemCode::CursorInvalid,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const CASELOAD_APPLY: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const CLOCK_ITEM_READ: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::WorkItemProposalChanged,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];
const HOLIDAY_CREATE: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::PreconditionFailed,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::ServiceUnavailable,
    ProblemCode::RuntimeFailure,
];
const HOLIDAY_READ: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::RuntimeFailure,
];
const CLOCK_RECOMPUTE_PREVIEW: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::RuntimeFailure,
];
const CLOCK_RECOMPUTE_APPLY: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ClockRecomputePreviewExpired,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::PreconditionFailed,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::ServiceUnavailable,
    ProblemCode::WorkItemNotVisible,
    ProblemCode::RuntimeFailure,
];
const BOOTSTRAP: &[ProblemCode] = &[
    ProblemCode::AuthenticationRefused,
    ProblemCode::ProfileNotAuthorized,
    ProblemCode::ProfileNotHuman,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestUnprocessable,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::PreconditionFailed,
    ProblemCode::PreconditionRequired,
    ProblemCode::IdempotencyKeyReused,
    ProblemCode::ServiceUnavailable,
    ProblemCode::RuntimeFailure,
];
const SOURCE_EVENT: &[ProblemCode] = &[
    ProblemCode::RequestInvalid,
    ProblemCode::ServiceUnavailable,
    ProblemCode::SourceBadGateway,
    ProblemCode::SourceNotFound,
    ProblemCode::SourceSignatureInvalid,
    ProblemCode::WorkItemSourceUnavailable,
    ProblemCode::RuntimeFailure,
];

/// Framework problems can occur outside a successful operation dispatch.
pub const FRAMEWORK_PROBLEMS: &[ProblemCode] = &[
    ProblemCode::RequestBodyTooLarge,
    ProblemCode::RequestMethodNotAllowed,
    ProblemCode::RequestNotFound,
];

/// Every implemented operation, in path then method order.
pub const OPERATION_CONTRACTS: &[OperationContract] = &[
    OperationContract {
        method: "POST",
        path: "/events/sources/{source_id}",
        success_statuses: &[202],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: SOURCE_EVENT,
    },
    OperationContract {
        method: "GET",
        path: "/health",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: false,
        accepts_json: false,
        problems: &[],
    },
    OperationContract {
        method: "GET",
        path: "/ready",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: false,
        accepts_json: false,
        problems: &[ProblemCode::ServiceUnavailable],
    },
    OperationContract {
        method: "GET",
        path: "/v1/casework",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: false,
        accepts_json: false,
        problems: AUTHENTICATION,
    },
    OperationContract {
        method: "GET",
        path: "/v1/directory",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: false,
        accepts_json: false,
        problems: DIRECTORY,
    },
    OperationContract {
        method: "GET",
        path: "/v1/directory/targets",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: true,
        accepts_json: false,
        problems: DIRECTORY_PAGE,
    },
    OperationContract {
        method: "GET",
        path: "/v1/directory/absences",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: true,
        accepts_json: false,
        problems: DIRECTORY_PAGE,
    },
    OperationContract {
        method: "POST",
        path: "/v1/directory/absences",
        success_statuses: &[201],
        extracts_path: false,
        extracts_query: false,
        accepts_json: true,
        problems: ABSENCE_CREATE,
    },
    OperationContract {
        method: "DELETE",
        path: "/v1/directory/absences/{absence_id}",
        success_statuses: &[204],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: ABSENCE_DELETE,
    },
    OperationContract {
        method: "PUT",
        path: "/v1/directory/absences/{absence_id}",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: ABSENCE_UPDATE,
    },
    OperationContract {
        method: "POST",
        path: "/v1/directory/bootstrap",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: false,
        accepts_json: true,
        problems: BOOTSTRAP,
    },
    OperationContract {
        method: "POST",
        path: "/v1/directory/caseload/apply",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: false,
        accepts_json: true,
        problems: CASELOAD_APPLY,
    },
    OperationContract {
        method: "POST",
        path: "/v1/directory/caseload/preview",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: true,
        accepts_json: true,
        problems: CASELOAD_PREVIEW,
    },
    OperationContract {
        method: "POST",
        path: "/v1/directory/clocks/recompute/apply",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: false,
        accepts_json: true,
        problems: CLOCK_RECOMPUTE_APPLY,
    },
    OperationContract {
        method: "POST",
        path: "/v1/directory/clocks/recompute/preview",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: false,
        accepts_json: true,
        problems: CLOCK_RECOMPUTE_PREVIEW,
    },
    OperationContract {
        method: "POST",
        path: "/v1/directory/holidays",
        success_statuses: &[201],
        extracts_path: false,
        extracts_query: false,
        accepts_json: true,
        problems: HOLIDAY_CREATE,
    },
    OperationContract {
        method: "GET",
        path: "/v1/directory/holidays/{id}/revisions/{revision}",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: HOLIDAY_READ,
    },
    OperationContract {
        method: "PUT",
        path: "/v1/directory/teams/{team_id}",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: BOOTSTRAP,
    },
    OperationContract {
        method: "GET",
        path: "/v1/holdings",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: true,
        accepts_json: false,
        problems: HOLDINGS,
    },
    OperationContract {
        method: "POST",
        path: "/v1/hosted-items",
        success_statuses: &[201],
        extracts_path: false,
        extracts_query: false,
        accepts_json: true,
        problems: HOSTED_CREATE,
    },
    OperationContract {
        method: "GET",
        path: "/v1/hosted-items/terminal",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: true,
        accepts_json: false,
        problems: HOSTED_PAGE,
    },
    OperationContract {
        method: "GET",
        path: "/v1/hosted-items/{item_id}",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: HOSTED_READ,
    },
    OperationContract {
        method: "GET",
        path: "/v1/hosted-accountability/{event_id}",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: HOSTED_READ,
    },
    OperationContract {
        method: "POST",
        path: "/v1/hosted-items/{item_id}/cancel",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: HOSTED_MUTATION,
    },
    OperationContract {
        method: "POST",
        path: "/v1/hosted-items/{item_id}/notes",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: HOSTED_MUTATION,
    },
    OperationContract {
        method: "GET",
        path: "/v1/hosted-items/{item_id}/notes",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: true,
        accepts_json: false,
        problems: HOSTED_ITEM_PAGE,
    },
    OperationContract {
        method: "GET",
        path: "/v1/work-items",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: true,
        accepts_json: false,
        problems: ITEM_READ,
    },
    OperationContract {
        method: "GET",
        path: "/v1/work-items/next",
        success_statuses: &[200],
        extracts_path: false,
        extracts_query: true,
        accepts_json: false,
        problems: ITEM_READ,
    },
    OperationContract {
        method: "GET",
        path: "/v1/work-items/{item_id}",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: ITEM_READ,
    },
    OperationContract {
        method: "POST",
        path: "/v1/work-items/{item_id}/assign",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: ASSIGNMENT_MUTATION,
    },
    OperationContract {
        method: "POST",
        path: "/v1/work-items/{item_id}/attempts/recover",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: RECOVERY,
    },
    OperationContract {
        method: "POST",
        path: "/v1/work-items/{item_id}/attempts/{attempt_id}/recover",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: RECOVERY,
    },
    OperationContract {
        method: "POST",
        path: "/v1/work-items/{item_id}/claim",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: CLAIM,
    },
    OperationContract {
        method: "GET",
        path: "/v1/work-items/{item_id}/clocks",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: CLOCK_ITEM_READ,
    },
    OperationContract {
        method: "POST",
        path: "/v1/work-items/{item_id}/decisions",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: DECISION,
    },
    OperationContract {
        method: "POST",
        path: "/v1/work-items/{item_id}/delegate",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: ASSIGNMENT_MUTATION,
    },
    OperationContract {
        method: "POST",
        path: "/v1/work-items/{item_id}/hosted-decisions",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: HOSTED_MUTATION,
    },
    OperationContract {
        method: "DELETE",
        path: "/v1/work-items/{item_id}/draft",
        success_statuses: &[204],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: DRAFT_MUTATION,
    },
    OperationContract {
        method: "GET",
        path: "/v1/work-items/{item_id}/draft",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: ITEM_READ,
    },
    OperationContract {
        method: "PUT",
        path: "/v1/work-items/{item_id}/draft",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: true,
        problems: DRAFT_MUTATION,
    },
    OperationContract {
        method: "GET",
        path: "/v1/work-items/{item_id}/history",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: true,
        accepts_json: false,
        problems: SOURCE_ITEM_PAGE,
    },
    OperationContract {
        method: "GET",
        path: "/v1/work-items/{item_id}/hosted-history",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: true,
        accepts_json: false,
        problems: HOSTED_ITEM_PAGE,
    },
    OperationContract {
        method: "POST",
        path: "/v1/work-items/{item_id}/release",
        success_statuses: &[200],
        extracts_path: true,
        extracts_query: false,
        accepts_json: false,
        problems: RELEASE,
    },
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn every_problem_has_a_unique_namespaced_code_and_segmented_uri() {
        let codes = ProblemCode::ALL
            .iter()
            .map(|problem| problem.code())
            .collect::<Vec<_>>();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(codes, sorted);
        for problem in ProblemCode::ALL {
            assert!(problem.code().contains('.'), "{problem}");
            let path = problem
                .type_uri()
                .strip_prefix(CASEWORK_PROBLEM_TYPE_BASE)
                .expect("problem uses the Casework prefix")
                .to_owned();
            assert_eq!(path, problem.code().replace('.', "/"), "{problem}");
            assert!(!problem.title().is_empty(), "{problem}");
            assert!(!problem.detail().is_empty(), "{problem}");
        }
    }

    #[test]
    fn operation_contract_covers_every_problem_and_framework_rejection() {
        let mut operations = BTreeSet::new();
        let mut covered = FRAMEWORK_PROBLEMS.iter().copied().collect::<BTreeSet<_>>();
        for operation in OPERATION_CONTRACTS {
            assert!(
                operations.insert((operation.path, operation.method)),
                "duplicate {} {}",
                operation.method,
                operation.path
            );
            assert!(!operation.success_statuses.is_empty());
            if operation.extracts_path || operation.extracts_query {
                assert!(operation.problems.contains(&ProblemCode::RequestInvalid));
            }
            if operation.accepts_json {
                assert!(operation
                    .problems
                    .contains(&ProblemCode::RequestUnsupportedMediaType));
                assert!(operation
                    .problems
                    .contains(&ProblemCode::RequestUnprocessable));
            }
            covered.extend(operation.problems.iter().copied());
        }
        assert_eq!(
            covered,
            ProblemCode::ALL.iter().copied().collect::<BTreeSet<_>>()
        );
        let next = OPERATION_CONTRACTS
            .iter()
            .find(|operation| operation.method == "GET" && operation.path == "/v1/work-items/next")
            .expect("next-item operation");
        assert_eq!(next.success_statuses, &[200]);
    }
}
