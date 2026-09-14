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
        assert_eq!(ProblemCode::ALL.len(), 26);
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
}
