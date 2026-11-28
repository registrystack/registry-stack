// SPDX-License-Identifier: Apache-2.0
//! Source-free Proposal lifecycle catalogue for author inspection.
//! Runtime controllers independently enforce caller authority and commit preconditions.

use crate::proposal_workflow::ProposalState;
use serde::Serialize;

/// One state machine reported by `bregctl explain lifecycle`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleDescription {
    pub id: &'static str,
    pub label: &'static str,
    pub states: Vec<LifecycleState>,
    pub transitions: Vec<LifecycleTransition>,
    pub enforcement: Vec<EnforcementLayer>,
}

/// One state in a `LifecycleDescription`. Structural fields are derived from
/// the transitions, and `turns` comes from the pure runtime turn rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleState {
    pub id: &'static str,
    pub turns: Vec<LifecycleTurn>,
    pub statuses: Vec<LifecycleStatus>,
    pub initial: bool,
    pub terminal: bool,
    pub unreachable: bool,
    pub incoming_transitions: usize,
    pub outgoing_transitions: usize,
}

/// One possible answer to whose move a Proposal in this state waits on.
/// This is workflow guidance only; caller authority remains an independent
/// runtime decision represented by `LifecycleDescription::enforcement`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleTurn {
    pub turn: &'static str,
    pub condition: &'static str,
}

/// One served status and the condition under which the shared rule selects it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleStatus {
    pub status: &'static str,
    pub condition: &'static str,
}

/// How far the current submission's review has gone. Runtime code derives this
/// only from BReg's retained submission and result rows; no authority is asked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, feature = "runtime"))]
pub(crate) enum ProposalReviewProgress {
    /// The submission's Action requires no review.
    NotRequired,
    /// The review authority holds the request, or BReg is still delivering it.
    Pending,
    /// Delivery or result lookup failed and Retry may resume it.
    Retrying,
    /// The review submission failed for good; only a later submission can be reviewed.
    Failed,
    Approved,
    /// An approval whose availability window has passed.
    ApprovalExpired,
    Rejected,
    ChangesRequested,
    /// An `answered` result, which has no meaning for a Proposal.
    Answered,
    /// A withdrawn round, or a Casework `cancelled` or `superseded` result.
    Ended,
}

/// The application facts that can change a submitted Proposal's turn after its
/// Review has approved it or when no Review is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, feature = "runtime"))]
pub(crate) enum ProposalApplicationProgress {
    Manual,
    BlockedRetry,
    BlockedOther,
    Other,
}

/// Inputs to the pure Proposal turn rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, feature = "runtime"))]
pub(crate) struct ProposalTurnContext {
    pub(crate) submission_blocked: bool,
    pub(crate) review: ProposalReviewProgress,
    pub(crate) ask_open: bool,
    pub(crate) application: ProposalApplicationProgress,
}

// Each vocabulary is declared once: runtime values and served schemas use it.
macro_rules! proposal_wire_values {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
        pub enum $name {
            $(#[serde(rename = $wire)] $variant),+
        }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
        }
    };
}

proposal_wire_values!(ProposalAvailabilityReason {
    PendingReview => "pending-review",
    ReviewRejected => "review-rejected",
    ReviewChangesRequested => "review-changes-requested",
    ReviewEnded => "review-ended",
    StaleRevision => "stale-revision",
    PackageChanged => "package-changed",
    DependencyOutage => "dependency-outage",
    InvalidInput => "invalid-input",
    AlreadyApplied => "already-applied",
    LimitReached => "limit-reached",
    ApplicationPending => "application-pending",
    AttachmentRequired => "attachment-required",
    AttachmentPending => "attachment-pending",
});

proposal_wire_values!(ProposalLinkRecovery {
    Refresh => "refresh",
    Revise => "revise",
    Retry => "retry",
    Rebase => "rebase",
    CorrectInput => "correct-input",
    ReceiptOnly => "receipt-only",
});

/// The reason and recovery pairs that Proposal links may serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalLinkRefusal {
    PendingReview,
    ReviewRejected,
    Rejected,
    ChangesRequested,
    ReviewEnded,
    WrongState,
    TargetChanged,
    PackageChanged,
    DependencyOutage,
    InvalidInput,
    ReviseInput,
    AlreadyApplied,
    LimitReached,
    ApplicationPending,
    AttachmentRequired,
    AttachmentPending,
}

impl ProposalLinkRefusal {
    pub const ALL: &'static [Self] = &[
        Self::PendingReview,
        Self::ReviewRejected,
        Self::Rejected,
        Self::ChangesRequested,
        Self::ReviewEnded,
        Self::WrongState,
        Self::TargetChanged,
        Self::PackageChanged,
        Self::DependencyOutage,
        Self::InvalidInput,
        Self::ReviseInput,
        Self::AlreadyApplied,
        Self::LimitReached,
        Self::ApplicationPending,
        Self::AttachmentRequired,
        Self::AttachmentPending,
    ];

    pub const fn pair(self) -> (ProposalAvailabilityReason, ProposalLinkRecovery) {
        use ProposalAvailabilityReason as Reason;
        use ProposalLinkRecovery as Recovery;
        match self {
            Self::PendingReview => (Reason::PendingReview, Recovery::Refresh),
            Self::ReviewRejected => (Reason::ReviewRejected, Recovery::Revise),
            Self::Rejected => (Reason::ReviewRejected, Recovery::ReceiptOnly),
            Self::ChangesRequested => (Reason::ReviewChangesRequested, Recovery::Revise),
            Self::ReviewEnded => (Reason::ReviewEnded, Recovery::Revise),
            Self::WrongState => (Reason::StaleRevision, Recovery::ReceiptOnly),
            Self::TargetChanged => (Reason::StaleRevision, Recovery::Rebase),
            Self::PackageChanged => (Reason::PackageChanged, Recovery::Rebase),
            Self::DependencyOutage => (Reason::DependencyOutage, Recovery::Retry),
            Self::InvalidInput => (Reason::InvalidInput, Recovery::CorrectInput),
            Self::ReviseInput => (Reason::InvalidInput, Recovery::Revise),
            Self::AlreadyApplied => (Reason::AlreadyApplied, Recovery::ReceiptOnly),
            Self::LimitReached => (Reason::LimitReached, Recovery::ReceiptOnly),
            Self::ApplicationPending => (Reason::ApplicationPending, Recovery::Refresh),
            Self::AttachmentRequired => (Reason::AttachmentRequired, Recovery::CorrectInput),
            Self::AttachmentPending => (Reason::AttachmentPending, Recovery::Refresh),
        }
    }
}

/// A link's complete availability. Private fields prevent JSON assembly from
/// bypassing the closed reason and recovery vocabulary.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalAvailability {
    available: bool,
    observed_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<ProposalAvailabilityReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery: Option<ProposalLinkRecovery>,
}

impl ProposalAvailability {
    pub fn new(observed_revision: u64, refusal: Option<ProposalLinkRefusal>) -> Self {
        let pair = refusal.map(ProposalLinkRefusal::pair);
        Self {
            available: pair.is_none(),
            observed_revision,
            reason: pair.map(|pair| pair.0),
            recovery: pair.map(|pair| pair.1),
        }
    }
}

/// The current applicant-facing stage, derived together with the turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProposalStatus {
    Draft,
    AwaitingParty,
    InReview,
    Approved,
    Processing,
    Applied,
    Rejected,
    Cancelled,
}

impl ProposalStatus {
    pub(crate) const ALL: [Self; 8] = [
        Self::Draft,
        Self::AwaitingParty,
        Self::InReview,
        Self::Approved,
        Self::Processing,
        Self::Applied,
        Self::Rejected,
        Self::Cancelled,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::AwaitingParty => "awaiting-party",
            Self::InReview => "in-review",
            Self::Approved => "approved",
            Self::Processing => "processing",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProposalTurn {
    Party,
    Official,
    Nobody,
}

impl ProposalTurn {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Party => "party",
            Self::Official => "official",
            Self::Nobody => "nobody",
        }
    }
}

#[derive(Clone, Copy)]
enum TurnCondition {
    Always,
    SubmittedParty,
    SubmittedOfficial,
    SubmittedNobody,
}

impl TurnCondition {
    const fn description(self) -> &'static str {
        match self {
            Self::Always => "Always while the Proposal is in this state.",
            Self::SubmittedParty => {
                "The submission package is blocked; Review is pending or retrying with an open ask; Review ended without a usable approval; or, after approval or when Review is not required, application is not manual and is blocked without recovery retry."
            }
            Self::SubmittedOfficial => {
                "The submission package is not blocked, and either Review is pending or being retried without an open ask, or, after approval or when Review is not required, application is manual or is blocked with recovery retry."
            }
            Self::SubmittedNobody => {
                "The submission package is not blocked, Review is approved or not required, and application is neither manual nor blocked, including queued, running, or unreported application status."
            }
        }
    }

    #[cfg(any(test, feature = "runtime"))]
    fn matches(self, context: ProposalTurnContext) -> bool {
        match self {
            Self::Always => true,
            Self::SubmittedParty => submitted_turn(context) == ProposalTurn::Party,
            Self::SubmittedOfficial => submitted_turn(context) == ProposalTurn::Official,
            Self::SubmittedNobody => submitted_turn(context) == ProposalTurn::Nobody,
        }
    }
}

#[cfg(any(test, feature = "runtime"))]
fn submitted_turn(context: ProposalTurnContext) -> ProposalTurn {
    if context.submission_blocked {
        return ProposalTurn::Party;
    }
    match context.review {
        ProposalReviewProgress::Pending | ProposalReviewProgress::Retrying => {
            if context.ask_open {
                ProposalTurn::Party
            } else {
                ProposalTurn::Official
            }
        }
        ProposalReviewProgress::Failed
        | ProposalReviewProgress::ApprovalExpired
        | ProposalReviewProgress::Rejected
        | ProposalReviewProgress::ChangesRequested
        | ProposalReviewProgress::Answered
        | ProposalReviewProgress::Ended => ProposalTurn::Party,
        ProposalReviewProgress::NotRequired | ProposalReviewProgress::Approved => {
            match context.application {
                ProposalApplicationProgress::Manual | ProposalApplicationProgress::BlockedRetry => {
                    ProposalTurn::Official
                }
                ProposalApplicationProgress::BlockedOther => ProposalTurn::Party,
                ProposalApplicationProgress::Other => ProposalTurn::Nobody,
            }
        }
    }
}

#[derive(Clone, Copy)]
struct TurnRule {
    turn: ProposalTurn,
    condition: TurnCondition,
}

const DRAFT_TURN_RULES: &[TurnRule] = &[TurnRule {
    turn: ProposalTurn::Party,
    condition: TurnCondition::Always,
}];
const SUBMITTED_TURN_RULES: &[TurnRule] = &[
    // Package blocking precedes Review and application progress in the runtime.
    TurnRule {
        turn: ProposalTurn::Party,
        condition: TurnCondition::SubmittedParty,
    },
    TurnRule {
        turn: ProposalTurn::Official,
        condition: TurnCondition::SubmittedOfficial,
    },
    TurnRule {
        turn: ProposalTurn::Nobody,
        condition: TurnCondition::SubmittedNobody,
    },
];
const TERMINAL_TURN_RULES: &[TurnRule] = &[TurnRule {
    turn: ProposalTurn::Nobody,
    condition: TurnCondition::Always,
}];

fn proposal_state_id(state: ProposalState) -> &'static str {
    match state {
        ProposalState::Draft => "draft",
        ProposalState::Submitted => "submitted",
        ProposalState::Cancelled => "cancelled",
        ProposalState::Applied => "applied",
        ProposalState::Rejected => "rejected",
    }
}

fn proposal_turn_rules(state: ProposalState) -> &'static [TurnRule] {
    match state {
        ProposalState::Draft => DRAFT_TURN_RULES,
        ProposalState::Submitted => SUBMITTED_TURN_RULES,
        ProposalState::Cancelled | ProposalState::Applied | ProposalState::Rejected => {
            TERMINAL_TURN_RULES
        }
    }
}

/// Whose move a Proposal waits on. The exhaustive state match above means a
/// new Proposal state cannot compile without an explicit turn rule.
#[cfg(any(test, feature = "runtime"))]
pub(crate) fn proposal_turn(state: ProposalState, context: ProposalTurnContext) -> ProposalTurn {
    proposal_status_and_turn(state, context).1
}

/// One rule owns both answers, including blocked submissions and open asks.
#[cfg(any(test, feature = "runtime"))]
pub(crate) fn proposal_status_and_turn(
    state: ProposalState,
    context: ProposalTurnContext,
) -> (ProposalStatus, ProposalTurn) {
    let turn = proposal_turn_rules(state)
        .iter()
        .find(|rule| rule.condition.matches(context))
        .expect("every Proposal state and context has a turn")
        .turn;
    let status = proposal_status_rules(state)
        .iter()
        .find(|(_, condition)| condition.matches(context, turn))
        .expect("every Proposal state and context has a status")
        .0;
    (status, turn)
}

#[derive(Clone, Copy)]
enum StatusCondition {
    Always,
    Party,
    ReviewPending,
    ReviewApproved,
    ReviewNotRequired,
}

impl StatusCondition {
    const fn description(self) -> &'static str {
        match self {
            Self::Always => "Always while the Proposal is in this state.",
            Self::Party => TurnCondition::SubmittedParty.description(),
            Self::ReviewPending => "The submission package is not blocked, Review is pending or retrying, and no ask is open.",
            Self::ReviewApproved => "Review is approved and neither the submission package nor application needs action by the party.",
            Self::ReviewNotRequired => "Review is not required and neither the submission package nor application needs action by the party.",
        }
    }

    #[cfg(any(test, feature = "runtime"))]
    fn matches(self, context: ProposalTurnContext, turn: ProposalTurn) -> bool {
        match self {
            Self::Always => true,
            Self::Party => turn == ProposalTurn::Party,
            Self::ReviewPending => matches!(
                context.review,
                ProposalReviewProgress::Pending | ProposalReviewProgress::Retrying
            ),
            Self::ReviewApproved => context.review == ProposalReviewProgress::Approved,
            Self::ReviewNotRequired => context.review == ProposalReviewProgress::NotRequired,
        }
    }
}

fn proposal_status_rules(state: ProposalState) -> &'static [(ProposalStatus, StatusCondition)] {
    use ProposalStatus as Status;
    use StatusCondition as Condition;
    match state {
        ProposalState::Draft => &[(Status::Draft, Condition::Always)],
        ProposalState::Cancelled => &[(Status::Cancelled, Condition::Always)],
        ProposalState::Applied => &[(Status::Applied, Condition::Always)],
        ProposalState::Rejected => &[(Status::Rejected, Condition::Always)],
        ProposalState::Submitted => &[
            (Status::AwaitingParty, Condition::Party),
            (Status::InReview, Condition::ReviewPending),
            (Status::Approved, Condition::ReviewApproved),
            (Status::Processing, Condition::ReviewNotRequired),
        ],
    }
}

fn lifecycle_statuses(state: ProposalState) -> Vec<LifecycleStatus> {
    proposal_status_rules(state)
        .iter()
        .map(|&(status, condition)| LifecycleStatus {
            status: status.as_str(),
            condition: condition.description(),
        })
        .collect()
}

fn lifecycle_turns(state: ProposalState) -> Vec<LifecycleTurn> {
    proposal_turn_rules(state)
        .iter()
        .map(|rule| LifecycleTurn {
            turn: rule.turn.as_str(),
            condition: rule.condition.description(),
        })
        .collect()
}

/// One edge in a `LifecycleDescription`, in declaration order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleTransition {
    pub from: &'static str,
    pub event: &'static str,
    pub to: &'static str,
    /// What the workflow method itself checks before it moves the state. Nothing the
    /// runtime checks around the call appears here; that is `enforcement`.
    pub guard: &'static str,
    /// Availability reasons for which this event is the documented recovery.
    pub recovery_reasons: &'static [&'static str],
}

/// One place the runtime can refuse an event, in execution order within
/// `LifecycleDescription::enforcement`. `events` names every event the layer runs for;
/// an event absent from the list passes the layer without being checked there.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnforcementLayer {
    pub id: &'static str,
    pub description: &'static str,
    pub events: &'static [&'static str],
}

/// Builds a `LifecycleDescription`, deriving each state's `initial`, `terminal`,
/// `unreachable`, transition counts, and turns from the transitions and pure
/// Proposal rules instead of accepting separate hand-written input that could drift.
fn build_lifecycle(
    id: &'static str,
    label: &'static str,
    initial_state_id: &'static str,
    states: &[ProposalState],
    transitions: Vec<LifecycleTransition>,
    enforcement: Vec<EnforcementLayer>,
) -> LifecycleDescription {
    let states = states
        .iter()
        .map(|&state| {
            let state_id = proposal_state_id(state);
            let incoming_transitions = transitions.iter().filter(|t| t.to == state_id).count();
            let outgoing_transitions = transitions.iter().filter(|t| t.from == state_id).count();
            let initial = state_id == initial_state_id;
            LifecycleState {
                id: state_id,
                turns: lifecycle_turns(state),
                statuses: lifecycle_statuses(state),
                initial,
                terminal: outgoing_transitions == 0,
                unreachable: incoming_transitions == 0 && !initial,
                incoming_transitions,
                outgoing_transitions,
            }
        })
        .collect();
    LifecycleDescription {
        id,
        label,
        states,
        transitions,
        enforcement,
    }
}

const EVERY_EVENT: &[&str] = &[
    "edit", "submit", "revise", "rebase", "retry", "cancel", "apply",
];

/// The Proposal controller checks these boundaries independently of state transitions.
fn proposal_enforcement() -> Vec<EnforcementLayer> {
    vec![
        EnforcementLayer {
            id: "caller-authority",
            events: EVERY_EVENT,
            description: "The selected access profile must explicitly authorize the Proposal operation. Verified caller claims, task grants, ownership restrictions, target boundaries, and disclosure remain independent checks.",
        },
        EnforcementLayer {
            id: "optimistic-concurrency",
            events: EVERY_EVENT,
            description: "A promoted transition carries the current Proposal revision and caller-bound If-Match condition. A stale condition requires rediscovery; availability is a hint and does not authorize execution.",
        },
        EnforcementLayer {
            id: "exact-receipt-recovery",
            events: EVERY_EVENT,
            description: "A retained authorized receipt can recover an uncertain outcome only for the original method, path, body, condition, and idempotency key. Recovery does not generate a different attempt or reacquire external guards for a committed application.",
        },
        EnforcementLayer {
            id: "plan-preparation",
            events: &["submit"],
            description: "Submission validates the typed Action input and runs the shared bounded plan evaluator. Function execution and external Evidence acquisition hold no database transaction or row lock. The controller rechecks the observed revision before freezing the submission.",
        },
        EnforcementLayer {
            id: "explicit-contract-rebase",
            events: &["rebase"],
            description: "Rebase explicitly selects the active Action definition and requires both the current Rebase grant and active Start authority. An incompatible activation never silently changes a frozen submission.",
        },
        EnforcementLayer {
            id: "submission-status",
            events: &["revise", "rebase"],
            description: "Revise and Rebase of a submitted Proposal require awaiting-party or in-review status from the shared status and turn rule. Approval and review-free processing preserve the current submission until Apply or Cancel, unless a recovery returns the turn to the party. Rebase of a draft is unchanged.",
        },
        EnforcementLayer {
            id: "application-authorization",
            events: &["apply"],
            description: "Application revalidates the frozen Action revision, submission version, effect digest, current caller or restricted executor authority, and any required current approval and Evidence. Manual and automatic execution use the same application boundary.",
        },
        EnforcementLayer {
            id: "atomic-commit",
            events: &["apply"],
            description: "The writer locks authorized current targets, enforces commit guards and PostgreSQL row policies, then commits the ordered effects, Record history, and exact application receipt atomically. A failed precondition produces no partial Record mutation.",
        },
        EnforcementLayer {
            id: "review-authority-result",
            events: &["reject"],
            description: "No caller operation rejects a Proposal. Only a verified result from the configured review authority for the exact current, not withdrawn submission does, in the same transaction that records the result and its lifecycle event.",
        },
    ]
}

/// Descriptive projection of the current first-class Proposal state machine.
pub fn proposal_lifecycle() -> LifecycleDescription {
    build_lifecycle(
        "proposal",
        "Proposal lifecycle",
        "draft",
        &[
            ProposalState::Draft,
            ProposalState::Submitted,
            ProposalState::Cancelled,
            ProposalState::Applied,
            ProposalState::Rejected,
        ],
        vec![
            LifecycleTransition {
                from: "draft",
                event: "edit",
                to: "draft",
                guard: "The Proposal is draft; replace validated Action input and advance its lifecycle revision.",
                recovery_reasons: &[],
            },
            LifecycleTransition {
                from: "draft",
                event: "submit",
                to: "submitted",
                guard: "The Proposal is draft and this submission version has not been frozen; accept the prepared plan and freeze its digest.",
                recovery_reasons: &[],
            },
            LifecycleTransition {
                from: "draft",
                event: "rebase",
                to: "draft",
                guard: "The Proposal is draft; explicitly bind the active Action definition and preserve the current submission version.",
                recovery_reasons: &[],
            },
            LifecycleTransition {
                from: "draft",
                event: "cancel",
                to: "cancelled",
                guard: "The Proposal is draft or submitted; cancel without applying its effects.",
                recovery_reasons: &[],
            },
            LifecycleTransition {
                from: "submitted",
                event: "revise",
                to: "draft",
                guard: "The Proposal is submitted; open a new draft submission version without modifying the frozen prior submission.",
                recovery_reasons: &[],
            },
            LifecycleTransition {
                from: "submitted",
                event: "rebase",
                to: "draft",
                guard: "The Proposal is submitted; open a new draft version explicitly bound to the active Action definition.",
                recovery_reasons: &[],
            },
            LifecycleTransition {
                from: "submitted",
                event: "retry",
                to: "submitted",
                guard: "The Proposal remains submitted; schedule another eligible review or application attempt without changing the frozen plan.",
                recovery_reasons: &["dependency-outage", "lease-expired"],
            },
            LifecycleTransition {
                from: "submitted",
                event: "cancel",
                to: "cancelled",
                guard: "The Proposal is draft or submitted; cancel without applying its effects.",
                recovery_reasons: &[],
            },
            LifecycleTransition {
                from: "submitted",
                event: "apply",
                to: "applied",
                guard: "The submission version, displayed digest, frozen Action contract, authorized targets, commit guards, and required approval match the application attempt.",
                recovery_reasons: &[],
            },
            LifecycleTransition {
                from: "submitted",
                event: "reject",
                to: "rejected",
                guard: "The configured review authority returned a rejected result for the exact current submission. A rejection is terminal; a changes-requested result leaves the Proposal submitted and revisable.",
                recovery_reasons: &[],
            },
        ],
        proposal_enforcement(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposal_workflow::{
        EntityId, ProposalKey, ProposalState, ProposalWorkflow, RecordId, StateRevision,
        TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
    };

    #[test]
    fn proposal_status_and_turn_follow_the_exhaustive_lifecycle_table() {
        use ProposalApplicationProgress as A;
        use ProposalReviewProgress as R;
        use ProposalState as S;
        let mut rows = [0usize; 23];
        for state in [
            S::Draft,
            S::Cancelled,
            S::Applied,
            S::Rejected,
            S::Submitted,
        ] {
            for blocked in [false, true] {
                for review in [
                    R::NotRequired,
                    R::Pending,
                    R::Retrying,
                    R::Failed,
                    R::Approved,
                    R::ApprovalExpired,
                    R::Rejected,
                    R::ChangesRequested,
                    R::Answered,
                    R::Ended,
                ] {
                    for ask_open in [false, true] {
                        for application in [A::Manual, A::BlockedRetry, A::BlockedOther, A::Other] {
                            let expected = match state {
                                S::Draft => (0, "draft", "party"),
                                S::Cancelled => (1, "cancelled", "nobody"),
                                S::Applied => (2, "applied", "nobody"),
                                S::Rejected => (3, "rejected", "nobody"),
                                S::Submitted if blocked => (4, "awaiting-party", "party"),
                                S::Submitted => match review {
                                    R::Pending if ask_open => (5, "awaiting-party", "party"),
                                    R::Retrying if ask_open => (6, "awaiting-party", "party"),
                                    R::Pending => (7, "in-review", "official"),
                                    R::Retrying => (8, "in-review", "official"),
                                    R::Failed => (9, "awaiting-party", "party"),
                                    R::ApprovalExpired => (10, "awaiting-party", "party"),
                                    R::Rejected => (11, "awaiting-party", "party"),
                                    R::ChangesRequested => (12, "awaiting-party", "party"),
                                    R::Answered => (13, "awaiting-party", "party"),
                                    R::Ended => (14, "awaiting-party", "party"),
                                    R::Approved => match application {
                                        A::Manual => (15, "approved", "official"),
                                        A::BlockedRetry => (16, "approved", "official"),
                                        A::BlockedOther => (17, "awaiting-party", "party"),
                                        A::Other => (18, "approved", "nobody"),
                                    },
                                    R::NotRequired => match application {
                                        A::Manual => (19, "processing", "official"),
                                        A::BlockedRetry => (20, "processing", "official"),
                                        A::BlockedOther => (21, "awaiting-party", "party"),
                                        A::Other => (22, "processing", "nobody"),
                                    },
                                },
                            };
                            let context = ProposalTurnContext {
                                submission_blocked: blocked,
                                review,
                                ask_open,
                                application,
                            };
                            let (status, turn) = proposal_status_and_turn(state, context);
                            rows[expected.0] += 1;
                            assert_eq!(
                                (status.as_str(), turn.as_str()),
                                (expected.1, expected.2),
                                "{state:?} {context:?}"
                            );
                            assert_eq!(proposal_turn(state, context), turn);
                            assert_eq!(
                                turn.as_str() == "party",
                                matches!(status.as_str(), "draft" | "awaiting-party")
                            );
                            for terminal in ["applied", "rejected", "cancelled"] {
                                assert_eq!(
                                    status.as_str() == terminal,
                                    proposal_state_id(state) == terminal
                                );
                            }
                            if status.as_str() == "approved" {
                                assert_eq!(review, R::Approved);
                            }
                            if status.as_str() == "in-review" {
                                assert_eq!(turn.as_str(), "official");
                            }
                            if matches!(status.as_str(), "approved" | "processing") {
                                assert!(matches!(turn.as_str(), "official" | "nobody"));
                            }
                        }
                    }
                }
            }
        }
        assert!(
            rows.into_iter().all(|count| count > 0),
            "all 23 rows are exercised"
        );
    }

    #[test]
    fn retry_names_the_runtime_recovery_reasons() {
        let lifecycle = proposal_lifecycle();
        let retry = lifecycle
            .transitions
            .iter()
            .find(|transition| transition.event == "retry")
            .expect("retry transition exists");
        assert_eq!(
            retry.recovery_reasons,
            ["dependency-outage", "lease-expired"]
        );
        assert!(lifecycle
            .transitions
            .iter()
            .filter(|transition| transition.event != "retry")
            .all(|transition| transition.recovery_reasons.is_empty()));
    }

    fn context() -> TrustedTransitionContext {
        TrustedTransitionContext::from_verified_context(
            TrustedActorRef::from_verified_context("author").unwrap(),
            TrustedTimestamp::from_server_clock("2026-10-14T00:00:00Z").unwrap(),
        )
    }
    fn draft() -> ProposalWorkflow {
        ProposalWorkflow::new_draft(
            ProposalKey::new(
                EntityId::new("correct-address").unwrap(),
                RecordId::new("proposal-1").unwrap(),
            ),
            TrustedActorRef::from_verified_context("author").unwrap(),
            StateRevision::new(1).unwrap(),
        )
    }

    fn turn(
        state: ProposalState,
        submission_blocked: bool,
        review: ProposalReviewProgress,
        application: ProposalApplicationProgress,
    ) -> &'static str {
        proposal_turn(
            state,
            ProposalTurnContext {
                submission_blocked,
                review,
                ask_open: false,
                application,
            },
        )
        .as_str()
    }

    #[test]
    fn catalogue_covers_every_current_proposal_state() {
        let states = [
            ProposalState::Draft,
            ProposalState::Submitted,
            ProposalState::Cancelled,
            ProposalState::Applied,
            ProposalState::Rejected,
        ]
        .map(proposal_state_id);
        let lifecycle = proposal_lifecycle();
        assert_eq!(
            lifecycle
                .states
                .iter()
                .map(|state| state.id)
                .collect::<Vec<_>>(),
            states
        );
        assert!(lifecycle.states.iter().all(|state| !state.unreachable));
        assert_eq!(
            lifecycle
                .states
                .iter()
                .filter(|state| state.terminal)
                .map(|state| state.id)
                .collect::<Vec<_>>(),
            ["cancelled", "applied", "rejected"]
        );
    }

    #[test]
    fn turn_rule_covers_every_submitted_review_and_application_branch() {
        assert_eq!(
            turn(
                ProposalState::Submitted,
                true,
                ProposalReviewProgress::Pending,
                ProposalApplicationProgress::Manual,
            ),
            "party",
            "package blocking precedes Review and application progress"
        );
        for review in [
            ProposalReviewProgress::Pending,
            ProposalReviewProgress::Retrying,
        ] {
            assert_eq!(
                turn(
                    ProposalState::Submitted,
                    false,
                    review,
                    ProposalApplicationProgress::Other,
                ),
                "official"
            );
        }
        for review in [
            ProposalReviewProgress::Failed,
            ProposalReviewProgress::ApprovalExpired,
            ProposalReviewProgress::Rejected,
            ProposalReviewProgress::ChangesRequested,
            ProposalReviewProgress::Answered,
            ProposalReviewProgress::Ended,
        ] {
            assert_eq!(
                turn(
                    ProposalState::Submitted,
                    false,
                    review,
                    ProposalApplicationProgress::BlockedRetry,
                ),
                "party",
                "Review ending precedes application progress"
            );
        }
        for review in [
            ProposalReviewProgress::NotRequired,
            ProposalReviewProgress::Approved,
        ] {
            for application in [
                ProposalApplicationProgress::Manual,
                ProposalApplicationProgress::BlockedRetry,
            ] {
                assert_eq!(
                    turn(ProposalState::Submitted, false, review, application),
                    "official"
                );
            }
            assert_eq!(
                turn(
                    ProposalState::Submitted,
                    false,
                    review,
                    ProposalApplicationProgress::BlockedOther,
                ),
                "party"
            );
            assert_eq!(
                turn(
                    ProposalState::Submitted,
                    false,
                    review,
                    ProposalApplicationProgress::Other,
                ),
                "nobody"
            );
        }
    }

    #[test]
    fn draft_and_terminal_turns_ignore_submitted_progress() {
        let context = (
            true,
            ProposalReviewProgress::Pending,
            ProposalApplicationProgress::Manual,
        );
        assert_eq!(
            turn(ProposalState::Draft, context.0, context.1, context.2),
            "party"
        );
        for state in [
            ProposalState::Cancelled,
            ProposalState::Applied,
            ProposalState::Rejected,
        ] {
            assert_eq!(turn(state, context.0, context.1, context.2), "nobody");
        }
    }

    #[test]
    fn lifecycle_lists_exactly_the_turns_the_pure_rule_can_return() {
        let lifecycle = proposal_lifecycle();
        let states = [
            ProposalState::Draft,
            ProposalState::Submitted,
            ProposalState::Cancelled,
            ProposalState::Applied,
            ProposalState::Rejected,
        ];
        let reviews = [
            ProposalReviewProgress::NotRequired,
            ProposalReviewProgress::Pending,
            ProposalReviewProgress::Retrying,
            ProposalReviewProgress::Failed,
            ProposalReviewProgress::Approved,
            ProposalReviewProgress::ApprovalExpired,
            ProposalReviewProgress::Rejected,
            ProposalReviewProgress::ChangesRequested,
            ProposalReviewProgress::Answered,
            ProposalReviewProgress::Ended,
        ];
        let applications = [
            ProposalApplicationProgress::Manual,
            ProposalApplicationProgress::BlockedRetry,
            ProposalApplicationProgress::BlockedOther,
            ProposalApplicationProgress::Other,
        ];
        for state in states {
            let described = lifecycle
                .states
                .iter()
                .find(|item| item.id == proposal_state_id(state))
                .unwrap()
                .turns
                .iter()
                .map(|turn| turn.turn)
                .collect::<Vec<_>>();
            let mut observed = Vec::new();
            for blocked in [false, true] {
                for review in reviews {
                    for application in applications {
                        let actual = turn(state, blocked, review, application);
                        assert!(
                            described.contains(&actual),
                            "{} omits runtime turn {actual}",
                            proposal_state_id(state)
                        );
                        if !observed.contains(&actual) {
                            observed.push(actual);
                        }
                    }
                }
            }
            for declared in described {
                assert!(
                    observed.contains(&declared),
                    "{} declares unreachable turn {declared}",
                    proposal_state_id(state)
                );
            }
        }
    }
    #[test]
    fn draft_edges_match_workflow_state_checks() {
        assert_eq!(
            draft()
                .edit_draft(context())
                .unwrap()
                .into_workflow()
                .state(),
            ProposalState::Draft
        );
        assert_eq!(
            draft().rebase(context()).unwrap().into_workflow().state(),
            ProposalState::Draft
        );
        let cancelled = draft().cancel(context()).unwrap().into_workflow();
        assert_eq!(cancelled.state(), ProposalState::Cancelled);
        assert!(cancelled.cancel(context()).is_err());
        assert!(draft().retry(context()).is_err());
        assert!(draft().revise(context()).is_err());
        assert!(draft().reject(context()).is_err());
    }
    #[test]
    fn transition_counts_and_enforcement_events_are_derived_from_the_catalogue() {
        let lifecycle = proposal_lifecycle();
        assert_eq!(lifecycle.transitions.len(), 10);
        for state in &lifecycle.states {
            assert_eq!(
                state.incoming_transitions,
                lifecycle
                    .transitions
                    .iter()
                    .filter(|edge| edge.to == state.id)
                    .count()
            );
            assert_eq!(
                state.outgoing_transitions,
                lifecycle
                    .transitions
                    .iter()
                    .filter(|edge| edge.from == state.id)
                    .count()
            );
        }
        assert!(lifecycle
            .enforcement
            .iter()
            .flat_map(|layer| layer.events)
            .all(|event| lifecycle
                .transitions
                .iter()
                .any(|edge| edge.event == *event)));
    }
}
