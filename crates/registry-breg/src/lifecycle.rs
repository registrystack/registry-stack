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
    pub(crate) application: ProposalApplicationProgress,
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
                "The submission package is blocked; Review ended without a usable approval; or, after approval or when Review is not required, application is not manual and is blocked without recovery retry."
            }
            Self::SubmittedOfficial => {
                "The submission package is not blocked, and either Review is pending or being retried, or, after approval or when Review is not required, application is manual or is blocked with recovery retry."
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
            ProposalTurn::Official
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
    proposal_turn_rules(state)
        .iter()
        .find(|rule| rule.condition.matches(context))
        .expect("every Proposal state and context has a turn")
        .turn
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
