// SPDX-License-Identifier: Apache-2.0
//! Source-free Proposal lifecycle catalogue for author inspection.
//! Runtime controllers independently enforce caller authority and commit preconditions.

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

/// One state in a `LifecycleDescription`. Every field but `id` is derived from
/// `transitions` and the declared initial state; none of them is authored per state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleState {
    pub id: &'static str,
    pub initial: bool,
    pub terminal: bool,
    pub unreachable: bool,
    pub incoming_transitions: usize,
    pub outgoing_transitions: usize,
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
/// `unreachable`, and transition counts from `transitions` and `initial_state_id` instead
/// of accepting them as separate hand-written input that could drift from the edges.
fn build_lifecycle(
    id: &'static str,
    label: &'static str,
    initial_state_id: &'static str,
    state_ids: &[&'static str],
    transitions: Vec<LifecycleTransition>,
    enforcement: Vec<EnforcementLayer>,
) -> LifecycleDescription {
    let states = state_ids
        .iter()
        .map(|&state_id| {
            let incoming_transitions = transitions.iter().filter(|t| t.to == state_id).count();
            let outgoing_transitions = transitions.iter().filter(|t| t.from == state_id).count();
            let initial = state_id == initial_state_id;
            LifecycleState {
                id: state_id,
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
    ]
}

/// Descriptive projection of the current first-class Proposal state machine.
pub fn proposal_lifecycle() -> LifecycleDescription {
    build_lifecycle(
        "proposal",
        "Proposal lifecycle",
        "draft",
        &["draft", "submitted", "cancelled", "applied"],
        vec![
            LifecycleTransition {
                from: "draft",
                event: "edit",
                to: "draft",
                guard: "The Proposal is draft; replace validated Action input and advance its lifecycle revision.",
            },
            LifecycleTransition {
                from: "draft",
                event: "submit",
                to: "submitted",
                guard: "The Proposal is draft and this submission version has not been frozen; accept the prepared plan and freeze its digest.",
            },
            LifecycleTransition {
                from: "draft",
                event: "rebase",
                to: "draft",
                guard: "The Proposal is draft; explicitly bind the active Action definition and preserve the current submission version.",
            },
            LifecycleTransition {
                from: "draft",
                event: "cancel",
                to: "cancelled",
                guard: "The Proposal is draft or submitted; cancel without applying its effects.",
            },
            LifecycleTransition {
                from: "submitted",
                event: "revise",
                to: "draft",
                guard: "The Proposal is submitted; open a new draft submission version without modifying the frozen prior submission.",
            },
            LifecycleTransition {
                from: "submitted",
                event: "rebase",
                to: "draft",
                guard: "The Proposal is submitted; open a new draft version explicitly bound to the active Action definition.",
            },
            LifecycleTransition {
                from: "submitted",
                event: "retry",
                to: "submitted",
                guard: "The Proposal remains submitted; schedule another eligible review or application attempt without changing the frozen plan.",
            },
            LifecycleTransition {
                from: "submitted",
                event: "cancel",
                to: "cancelled",
                guard: "The Proposal is draft or submitted; cancel without applying its effects.",
            },
            LifecycleTransition {
                from: "submitted",
                event: "apply",
                to: "applied",
                guard: "The submission version, displayed digest, frozen Action contract, authorized targets, commit guards, and required approval match the application attempt.",
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

    #[test]
    fn catalogue_covers_every_current_proposal_state() {
        fn name(state: ProposalState) -> &'static str {
            match state {
                ProposalState::Draft => "draft",
                ProposalState::Submitted => "submitted",
                ProposalState::Cancelled => "cancelled",
                ProposalState::Applied => "applied",
            }
        }
        let states = [
            ProposalState::Draft,
            ProposalState::Submitted,
            ProposalState::Cancelled,
            ProposalState::Applied,
        ]
        .map(name);
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
            ["cancelled", "applied"]
        );
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
    }
    #[test]
    fn transition_counts_and_enforcement_events_are_derived_from_the_catalogue() {
        let lifecycle = proposal_lifecycle();
        assert_eq!(lifecycle.transitions.len(), 9);
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
        assert!(
            lifecycle
                .enforcement
                .iter()
                .flat_map(|layer| layer.events)
                .all(|event| lifecycle
                    .transitions
                    .iter()
                    .any(|edge| edge.event == *event))
        );
    }
}
