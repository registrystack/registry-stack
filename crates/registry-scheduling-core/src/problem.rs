// SPDX-License-Identifier: Apache-2.0

//! The closed problem vocabulary of Registry Scheduling.
//!
//! The vocabulary is closed on purpose: a caller can enumerate every problem
//! this product can ever return, and a problem code outside this list is a
//! defect, not a compatibility event. `authorization.refused` is deliberately
//! absent everywhere in this file: it is an audit reason family used by other
//! Registry Stack products to describe why a decision was recorded, and audit
//! reasons and problem codes must not be conflated. The authorization refusals
//! callers see here are `authentication.refused`, `operation.not-authorized`,
//! and `profile.not-authorized`.
//!
//! The `request.*` family carries the request-edge rejections (a route that
//! does not exist, a method the route refuses, a body too large or not JSON)
//! under this product's own prefix, exactly as Casework does: no shared
//! platform problem prefix exists in the Registry Stack catalog.

use crate::naming::SCHEDULING_PROBLEM_TYPE_BASE;

pub const AUTHENTICATION_REFUSED_PROBLEM: &str = "authentication.refused";
pub const BOOKING_DUPLICATE_ACTIVE_PROBLEM: &str = "booking.duplicate-active";
pub const CANCELLATION_CUTOFF_PASSED_PROBLEM: &str = "cancellation.cutoff-passed";
pub const CAPABILITY_UNMATCHED_PROBLEM: &str = "capability.unmatched";
pub const CAPACITY_EXHAUSTED_PROBLEM: &str = "capacity.exhausted";
pub const CURSOR_EXPIRED_PROBLEM: &str = "cursor.expired";
pub const CURSOR_INVALID_PROBLEM: &str = "cursor.invalid";
pub const ELIGIBILITY_UNAVAILABLE_PROBLEM: &str = "eligibility.unavailable";
pub const HOLD_EXPIRED_PROBLEM: &str = "hold.expired";
pub const HOLD_RELEASED_PROBLEM: &str = "hold.released";
pub const HORIZON_OUTSIDE_PROBLEM: &str = "horizon.outside";
pub const HOOK_UNAVAILABLE_PROBLEM: &str = "hook.unavailable";
pub const IDEMPOTENCY_EXPIRED_PROBLEM: &str = "idempotency.expired";
pub const IDEMPOTENCY_KEY_REUSED_PROBLEM: &str = "idempotency.key-reused";
pub const LOCATION_CLOSED_PROBLEM: &str = "location.closed";
pub const OPERATION_NOT_AUTHORIZED_PROBLEM: &str = "operation.not-authorized";
pub const PARTY_CAPACITY_INADEQUATE_PROBLEM: &str = "party.capacity-inadequate";
pub const POLICY_CHANGED_PROBLEM: &str = "policy.changed";
pub const PRECONDITION_FAILED_PROBLEM: &str = "precondition.failed";
pub const PRECONDITION_REQUIRED_PROBLEM: &str = "precondition.required";
pub const PREREQUISITE_MISSING_PROBLEM: &str = "prerequisite.missing";
pub const PROFILE_NOT_AUTHORIZED_PROBLEM: &str = "profile.not-authorized";
pub const REQUEST_BODY_TOO_LARGE_PROBLEM: &str = "request.body-too-large";
pub const REQUEST_INVALID_PROBLEM: &str = "request.invalid";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const RESOURCE_UNAVAILABLE_PROBLEM: &str = "resource.unavailable";
pub const REVISION_MISMATCH_PROBLEM: &str = "revision.mismatch";
pub const SCHEDULE_UNPUBLISHED_PROBLEM: &str = "schedule.unpublished";
pub const SERVICE_UNAVAILABLE_PROBLEM: &str = "service.unavailable";

/// Every problem code Registry Scheduling can return, in code-string order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProblemCode {
    AuthenticationRefused,
    BookingDuplicateActive,
    CancellationCutoffPassed,
    CapabilityUnmatched,
    CapacityExhausted,
    CursorExpired,
    CursorInvalid,
    EligibilityUnavailable,
    HoldExpired,
    HoldReleased,
    HookUnavailable,
    HorizonOutside,
    IdempotencyExpired,
    IdempotencyKeyReused,
    LocationClosed,
    OperationNotAuthorized,
    PartyCapacityInadequate,
    PolicyChanged,
    PreconditionFailed,
    PreconditionRequired,
    PrerequisiteMissing,
    ProfileNotAuthorized,
    RequestBodyTooLarge,
    RequestInvalid,
    RequestMethodNotAllowed,
    RequestNotFound,
    RequestUnprocessable,
    RequestUnsupportedMediaType,
    ResourceUnavailable,
    RevisionMismatch,
    ScheduleUnpublished,
    ServiceUnavailable,
}

impl ProblemCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AuthenticationRefused,
        Self::BookingDuplicateActive,
        Self::CancellationCutoffPassed,
        Self::CapabilityUnmatched,
        Self::CapacityExhausted,
        Self::CursorExpired,
        Self::CursorInvalid,
        Self::EligibilityUnavailable,
        Self::HoldExpired,
        Self::HoldReleased,
        Self::HookUnavailable,
        Self::HorizonOutside,
        Self::IdempotencyExpired,
        Self::IdempotencyKeyReused,
        Self::LocationClosed,
        Self::OperationNotAuthorized,
        Self::PartyCapacityInadequate,
        Self::PolicyChanged,
        Self::PreconditionFailed,
        Self::PreconditionRequired,
        Self::PrerequisiteMissing,
        Self::ProfileNotAuthorized,
        Self::RequestBodyTooLarge,
        Self::RequestInvalid,
        Self::RequestMethodNotAllowed,
        Self::RequestNotFound,
        Self::RequestUnprocessable,
        Self::RequestUnsupportedMediaType,
        Self::ResourceUnavailable,
        Self::RevisionMismatch,
        Self::ScheduleUnpublished,
        Self::ServiceUnavailable,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => AUTHENTICATION_REFUSED_PROBLEM,
            Self::BookingDuplicateActive => BOOKING_DUPLICATE_ACTIVE_PROBLEM,
            Self::CancellationCutoffPassed => CANCELLATION_CUTOFF_PASSED_PROBLEM,
            Self::CapabilityUnmatched => CAPABILITY_UNMATCHED_PROBLEM,
            Self::CapacityExhausted => CAPACITY_EXHAUSTED_PROBLEM,
            Self::CursorExpired => CURSOR_EXPIRED_PROBLEM,
            Self::CursorInvalid => CURSOR_INVALID_PROBLEM,
            Self::EligibilityUnavailable => ELIGIBILITY_UNAVAILABLE_PROBLEM,
            Self::HoldExpired => HOLD_EXPIRED_PROBLEM,
            Self::HoldReleased => HOLD_RELEASED_PROBLEM,
            Self::HorizonOutside => HORIZON_OUTSIDE_PROBLEM,
            Self::HookUnavailable => HOOK_UNAVAILABLE_PROBLEM,
            Self::IdempotencyExpired => IDEMPOTENCY_EXPIRED_PROBLEM,
            Self::IdempotencyKeyReused => IDEMPOTENCY_KEY_REUSED_PROBLEM,
            Self::LocationClosed => LOCATION_CLOSED_PROBLEM,
            Self::OperationNotAuthorized => OPERATION_NOT_AUTHORIZED_PROBLEM,
            Self::PartyCapacityInadequate => PARTY_CAPACITY_INADEQUATE_PROBLEM,
            Self::PolicyChanged => POLICY_CHANGED_PROBLEM,
            Self::PreconditionFailed => PRECONDITION_FAILED_PROBLEM,
            Self::PreconditionRequired => PRECONDITION_REQUIRED_PROBLEM,
            Self::PrerequisiteMissing => PREREQUISITE_MISSING_PROBLEM,
            Self::ProfileNotAuthorized => PROFILE_NOT_AUTHORIZED_PROBLEM,
            Self::RequestBodyTooLarge => REQUEST_BODY_TOO_LARGE_PROBLEM,
            Self::RequestInvalid => REQUEST_INVALID_PROBLEM,
            Self::RequestMethodNotAllowed => REQUEST_METHOD_NOT_ALLOWED_PROBLEM,
            Self::RequestNotFound => REQUEST_NOT_FOUND_PROBLEM,
            Self::RequestUnprocessable => REQUEST_UNPROCESSABLE_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::ResourceUnavailable => RESOURCE_UNAVAILABLE_PROBLEM,
            Self::RevisionMismatch => REVISION_MISMATCH_PROBLEM,
            Self::ScheduleUnpublished => SCHEDULE_UNPUBLISHED_PROBLEM,
            Self::ServiceUnavailable => SERVICE_UNAVAILABLE_PROBLEM,
        }
    }

    /// Resolve a code string back to its variant, or `None` for any string
    /// outside the closed vocabulary.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code() == code)
    }

    /// Whether this code is disclosed only through the separately authorized
    /// explain path, never as the public projection of a refusal. A replay
    /// expectation compares the public projection, so a detailed-only code can
    /// never match one and is refused before any case runs.
    #[must_use]
    pub const fn is_detailed_only(self) -> bool {
        matches!(self, Self::ResourceUnavailable)
    }

    /// The HTTP status this problem answers with. The map lives here, beside
    /// the vocabulary it belongs to, so the runtime emits and every client
    /// validates one pinned status per code rather than each re-deriving its
    /// own.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::CursorInvalid | Self::RequestInvalid => 400,
            Self::AuthenticationRefused => 401,
            Self::OperationNotAuthorized | Self::ProfileNotAuthorized => 403,
            Self::RequestNotFound => 404,
            Self::RequestMethodNotAllowed => 405,
            Self::RequestBodyTooLarge => 413,
            Self::RequestUnsupportedMediaType => 415,
            Self::BookingDuplicateActive
            | Self::CancellationCutoffPassed
            | Self::CapacityExhausted
            | Self::HoldReleased
            | Self::IdempotencyKeyReused
            | Self::LocationClosed
            | Self::ResourceUnavailable => 409,
            Self::CursorExpired | Self::HoldExpired | Self::IdempotencyExpired => 410,
            Self::PolicyChanged | Self::PreconditionFailed | Self::RevisionMismatch => 412,
            Self::CapabilityUnmatched
            | Self::HorizonOutside
            | Self::PartyCapacityInadequate
            | Self::PrerequisiteMissing
            | Self::RequestUnprocessable
            | Self::ScheduleUnpublished => 422,
            Self::PreconditionRequired => 428,
            Self::EligibilityUnavailable | Self::HookUnavailable | Self::ServiceUnavailable => 503,
        }
    }

    /// The fixed, value-free problem title. Titles and details carry no
    /// identifiers, so a problem body never discloses another person's
    /// booking, a private staff reason, or restricted eligibility
    /// information.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => "Authentication refused",
            Self::BookingDuplicateActive => "Duplicate active booking",
            Self::CancellationCutoffPassed => "Cancellation cutoff passed",
            Self::CapabilityUnmatched => "Capability unmatched",
            Self::CapacityExhausted => "Capacity exhausted",
            Self::CursorExpired => "Cursor expired",
            Self::CursorInvalid => "Cursor invalid",
            Self::EligibilityUnavailable => "Eligibility unavailable",
            Self::HoldExpired => "Hold expired",
            Self::HoldReleased => "Hold released",
            Self::HookUnavailable => "Hook unavailable",
            Self::HorizonOutside => "Start outside the booking horizon",
            Self::IdempotencyExpired => "Idempotency window expired",
            Self::IdempotencyKeyReused => "Idempotency key reused",
            Self::LocationClosed => "Location closed",
            Self::OperationNotAuthorized => "Operation not authorized",
            Self::PartyCapacityInadequate => "Party capacity inadequate",
            Self::PolicyChanged => "Policy changed",
            Self::PreconditionFailed => "Precondition failed",
            Self::PreconditionRequired => "Precondition required",
            Self::PrerequisiteMissing => "Prerequisite missing",
            Self::ProfileNotAuthorized => "Profile not authorized",
            Self::RequestBodyTooLarge => "Payload too large",
            Self::RequestInvalid => "Request invalid",
            Self::RequestMethodNotAllowed => "Method not allowed",
            Self::RequestNotFound => "Route not found",
            Self::RequestUnprocessable => "Request unprocessable",
            Self::RequestUnsupportedMediaType => "Unsupported media type",
            Self::ResourceUnavailable => "Resource unavailable",
            Self::RevisionMismatch => "Revision mismatch",
            Self::ScheduleUnpublished => "Schedule unpublished",
            Self::ServiceUnavailable => "Scheduling service unavailable",
        }
    }

    /// The fixed remediation sentence, value-free like the title.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::AuthenticationRefused => {
                "The bearer credential is missing, invalid, or expired. Sign in again."
            }
            Self::BookingDuplicateActive => {
                "An active booking already holds this party's duplicate key. Cancel or complete it before booking again."
            }
            Self::CancellationCutoffPassed => {
                "The cancellation cutoff for this appointment has passed, so it can no longer be cancelled."
            }
            Self::CapabilityUnmatched => {
                "The party or backing supply does not carry every capability this offering requires."
            }
            Self::CapacityExhausted => {
                "The supply is fully committed for the requested interval. Choose another time."
            }
            Self::CursorExpired => {
                "This cursor has expired. Start again without a cursor and deduplicate entries by id."
            }
            Self::CursorInvalid => "The cursor is invalid for this request.",
            Self::EligibilityUnavailable => {
                "A required eligibility check could not run. Retry; do not treat this as permission."
            }
            Self::HoldExpired => {
                "The hold expired before confirmation. Its capacity is bookable again; start a new request."
            }
            Self::HoldReleased => {
                "The claim is not an active hold. It may already be confirmed or released."
            }
            Self::HookUnavailable => {
                "A required lifecycle hook could not run, so the request was refused rather than half-applied."
            }
            Self::HorizonOutside => {
                "The requested start is earlier than the lead time allows or further ahead than the horizon allows."
            }
            Self::IdempotencyExpired => {
                "The stored response for this idempotency key has expired. Reconcile the original operation before choosing a new key."
            }
            Self::IdempotencyKeyReused => {
                "This idempotency key was used for a different request."
            }
            Self::LocationClosed => {
                "A closure covers the requested start. Choose a start outside the closure."
            }
            Self::OperationNotAuthorized => {
                "Your current Scheduling authority does not allow this operation."
            }
            Self::PartyCapacityInadequate => {
                "The party is larger than this offering can ever serve, or its size falls outside the published units."
            }
            Self::PolicyChanged => {
                "The policy revision changed before the request committed. Reload the catalogue and try again with the current revision."
            }
            Self::PreconditionFailed => {
                "The appointment changed since you loaded it. Reload and try again."
            }
            Self::PreconditionRequired => {
                "This mutation requires the revision you loaded, or the duplicate key this offering keys on."
            }
            Self::PrerequisiteMissing => {
                "The party is missing a prerequisite this offering requires."
            }
            Self::ProfileNotAuthorized => {
                "The selected Scheduling profile does not authorize this request."
            }
            Self::RequestBodyTooLarge => "The request body exceeds the accepted size.",
            Self::RequestInvalid => "The request could not be read as a Scheduling request.",
            Self::RequestMethodNotAllowed => "The route exists but not for this method.",
            Self::RequestNotFound => "The requested route does not exist.",
            Self::RequestUnprocessable => "The request body could not be processed.",
            Self::RequestUnsupportedMediaType => "The request body is not JSON.",
            Self::ResourceUnavailable => {
                "Every capable member is unavailable for this interval."
            }
            Self::RevisionMismatch => {
                "The window revision changed before the request committed. Reload the catalogue and try again."
            }
            Self::ScheduleUnpublished => {
                "No published schedule serves that start. Choose a start on the published grid."
            }
            Self::ServiceUnavailable => {
                "Scheduling storage is unavailable. Try again after the service recovers."
            }
        }
    }
}

/// Expand a dotted problem code into its full problem type URI.
#[must_use]
pub fn type_uri(code: &str) -> String {
    format!("{}{}", SCHEDULING_PROBLEM_TYPE_BASE, code.replace('.', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::SCHEDULING_PROBLEM_TYPE_BASE;

    #[test]
    fn the_vocabulary_is_complete_and_closed() {
        assert_eq!(ProblemCode::ALL.len(), 32);
        for code in ProblemCode::ALL {
            assert_eq!(ProblemCode::from_code(code.code()), Some(*code));
        }
        assert_eq!(ProblemCode::from_code("authorization.refused"), None);
        assert_eq!(ProblemCode::from_code("capacity.unexhausted"), None);
        assert_eq!(ProblemCode::from_code(""), None);
    }

    /// Exactly one code is detailed-only. A second would mean the public and
    /// detailed projections diverge in more than the one place the disclosure
    /// contract describes, so this count is a decision point, not a tally.
    #[test]
    fn exactly_one_code_is_detailed_only() {
        let detailed: Vec<ProblemCode> = ProblemCode::ALL
            .iter()
            .copied()
            .filter(|code| code.is_detailed_only())
            .collect();
        assert_eq!(detailed, vec![ProblemCode::ResourceUnavailable]);
    }

    #[test]
    fn codes_are_listed_in_code_string_order() {
        let codes: Vec<&str> = ProblemCode::ALL.iter().map(|code| code.code()).collect();
        let mut sorted = codes.clone();
        sorted.sort();
        assert_eq!(codes, sorted);
    }

    #[test]
    fn type_uris_expand_dots_into_path_segments() {
        assert_eq!(
            type_uri(CAPACITY_EXHAUSTED_PROBLEM),
            format!("{SCHEDULING_PROBLEM_TYPE_BASE}capacity/exhausted")
        );
        assert_eq!(
            type_uri(IDEMPOTENCY_KEY_REUSED_PROBLEM),
            format!("{SCHEDULING_PROBLEM_TYPE_BASE}idempotency/key-reused")
        );
    }

    /// Every code carries one pinned status from the statuses this product
    /// answers with, a non-empty title, and a non-empty value-free detail.
    /// The request-edge family carries the transport statuses (404, 405,
    /// 413, 415) under this product's own prefix, exactly as Casework does.
    #[test]
    fn every_code_pins_a_status_title_and_detail() {
        let statuses = [
            400, 401, 403, 404, 405, 409, 410, 412, 413, 415, 422, 428, 503,
        ];
        for code in ProblemCode::ALL {
            assert!(
                statuses.contains(&code.http_status()),
                "{}: {}",
                code.code(),
                code.http_status()
            );
            assert!(!code.title().is_empty(), "{}", code.code());
            assert!(!code.detail().is_empty(), "{}", code.code());
        }
    }

    /// The request-edge family is Casework's, pinned one status per code, so
    /// the runtime's edge and every client agree on what a rejected request
    /// looks like.
    #[test]
    fn the_request_edge_family_pins_casework_s_statuses() {
        assert_eq!(ProblemCode::RequestInvalid.http_status(), 400);
        assert_eq!(ProblemCode::RequestNotFound.http_status(), 404);
        assert_eq!(ProblemCode::RequestMethodNotAllowed.http_status(), 405);
        assert_eq!(ProblemCode::RequestBodyTooLarge.http_status(), 413);
        assert_eq!(ProblemCode::RequestUnsupportedMediaType.http_status(), 415);
        assert_eq!(ProblemCode::RequestUnprocessable.http_status(), 422);
        for code in [
            ProblemCode::RequestInvalid,
            ProblemCode::RequestNotFound,
            ProblemCode::RequestMethodNotAllowed,
            ProblemCode::RequestBodyTooLarge,
            ProblemCode::RequestUnsupportedMediaType,
            ProblemCode::RequestUnprocessable,
        ] {
            assert!(code.code().starts_with("request."), "{}", code.code());
        }
    }

    /// The statuses the acceptance scenarios reason about: a recoverable
    /// capacity conflict, a hold that can no longer be confirmed, the two
    /// idempotency answers, and the two precondition answers.
    #[test]
    fn the_pinned_statuses_match_the_acceptance_reasoning() {
        assert_eq!(ProblemCode::CapacityExhausted.http_status(), 409);
        assert_eq!(ProblemCode::HoldExpired.http_status(), 410);
        assert_eq!(ProblemCode::IdempotencyExpired.http_status(), 410);
        assert_eq!(ProblemCode::IdempotencyKeyReused.http_status(), 409);
        assert_eq!(ProblemCode::PreconditionFailed.http_status(), 412);
        assert_eq!(ProblemCode::PreconditionRequired.http_status(), 428);
        // The detailed-only code shares its public projection's status: the
        // explain path names the reason, never a different outcome.
        assert_eq!(
            ProblemCode::ResourceUnavailable.http_status(),
            ProblemCode::CapacityExhausted.http_status()
        );
    }
}
