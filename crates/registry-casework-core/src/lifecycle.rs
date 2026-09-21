//! Data descriptions of Casework's two state machines: the occurrence
//! lifecycle every work item moves through, and the review request lifecycle
//! a review settles into. Both are exposed as plain data so a caller (for
//! example an `explain` endpoint) can render or diff them without embedding
//! lifecycle knowledge of its own.

use registry_review_protocol::ReviewRequestLifecycle;
use serde::Serialize;

use crate::{transition, OccurrenceEvent, OccurrenceState};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleDescription {
    pub id: &'static str,
    pub label: &'static str,
    pub states: Vec<LifecycleState>,
    pub transitions: Vec<LifecycleTransition>,
}

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleTransition {
    pub from: &'static str,
    pub event: &'static str,
    pub to: &'static str,
    pub guard: &'static str,
}

/// Build a lifecycle description from a declared state and transition list.
/// Every derived field on a state is computed from the transitions and the
/// declared initial state, never hand-written, so the two cannot drift apart.
fn describe(
    id: &'static str,
    label: &'static str,
    initial_state_id: &'static str,
    state_ids: &[&'static str],
    transitions: Vec<LifecycleTransition>,
) -> LifecycleDescription {
    let states = state_ids
        .iter()
        .map(|&state_id| {
            let incoming_transitions = transitions
                .iter()
                .filter(|transition| transition.to == state_id)
                .count();
            let outgoing_transitions = transitions
                .iter()
                .filter(|transition| transition.from == state_id)
                .count();
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
    }
}

/// The storage spelling of an occurrence state, matched exhaustively so a new
/// `OccurrenceState` variant fails to compile here until it is given one.
fn occurrence_state_id(state: OccurrenceState) -> &'static str {
    match state {
        OccurrenceState::Open => "open",
        OccurrenceState::Claimed => "claimed",
        OccurrenceState::WaitingApplicant => "waiting_applicant",
        OccurrenceState::WaitingApplication => "waiting_application",
        OccurrenceState::Synchronizing => "synchronizing",
        OccurrenceState::Completed => "completed",
        OccurrenceState::Superseded => "superseded",
        OccurrenceState::Cancelled => "cancelled",
    }
}

/// The storage spelling of an occurrence event, matched exhaustively so a new
/// `OccurrenceEvent` variant fails to compile here until it is given one.
fn occurrence_event_id(event: OccurrenceEvent) -> &'static str {
    match event {
        OccurrenceEvent::Claim => "claim",
        OccurrenceEvent::Release => "release",
        OccurrenceEvent::AttemptReserved => "attempt_reserved",
        OccurrenceEvent::AttemptUncertain => "attempt_uncertain",
        OccurrenceEvent::AttemptCompleted => "attempt_completed",
        OccurrenceEvent::AttemptRefused => "attempt_refused",
        OccurrenceEvent::ObserveOpen => "observe_open",
        OccurrenceEvent::ObserveWaitingApplicant => "observe_waiting_applicant",
        OccurrenceEvent::ObserveWaitingApplication => "observe_waiting_application",
        OccurrenceEvent::Complete => "complete",
        OccurrenceEvent::Supersede => "supersede",
        OccurrenceEvent::Cancel => "cancel",
    }
}

/// Every occurrence edge shares this guard: the reducer itself is unguarded,
/// and legality is enforced one layer up, by storage, before an event fires.
const OCCURRENCE_GUARD: &str = "The occurrence reducer is total over (state, event); the store enforces holding, queue authority, revision, and attempt-state preconditions before any event is raised.";

/// Describe the occurrence lifecycle by generating its transition table from
/// the real reducer: every `(state, event)` pair is tried against
/// [`transition`], and every `Ok` result becomes an edge. The table cannot
/// drift from the reducer because it is produced by calling it.
pub fn occurrence_lifecycle() -> LifecycleDescription {
    let state_ids: Vec<&'static str> = OccurrenceState::ALL
        .into_iter()
        .map(occurrence_state_id)
        .collect();
    let mut transitions = Vec::new();
    for state in OccurrenceState::ALL {
        for event in OccurrenceEvent::ALL {
            if let Ok(next) = transition(state, event) {
                transitions.push(LifecycleTransition {
                    from: occurrence_state_id(state),
                    event: occurrence_event_id(event),
                    to: occurrence_state_id(next),
                    guard: OCCURRENCE_GUARD,
                });
            }
        }
    }
    describe(
        "occurrence",
        "Casework occurrence lifecycle",
        "open",
        &state_ids,
        transitions,
    )
}

/// The storage spelling of a review request lifecycle state, matched
/// exhaustively so a new `ReviewRequestLifecycle` variant fails to compile
/// here until it is given one.
fn review_lifecycle_state_id(state: ReviewRequestLifecycle) -> &'static str {
    match state {
        ReviewRequestLifecycle::Reviewing => "reviewing",
        ReviewRequestLifecycle::Approved => "approved",
        ReviewRequestLifecycle::Rejected => "rejected",
        ReviewRequestLifecycle::ChangesRequested => "changes_requested",
        ReviewRequestLifecycle::Answered => "answered",
        ReviewRequestLifecycle::Cancelled => "cancelled",
        ReviewRequestLifecycle::Superseded => "superseded",
    }
}

const REVIEW_EVENT: &str = "settle";

/// Describe the review request lifecycle: seven states, and six edges that
/// all leave `reviewing` on the same `settle` event. Which terminal state a
/// given review actually reaches is decided by `record_review_decision`
/// against the adopter's configured review policy (quorum, stage
/// advancement, deciding profiles, initiator and previous-stage-reviewer
/// exclusions). That decision is policy-dependent and deliberately not
/// enumerated here; this function only describes the shape all policies
/// settle within.
pub fn review_lifecycle() -> LifecycleDescription {
    let state_ids: Vec<&'static str> = [
        ReviewRequestLifecycle::Reviewing,
        ReviewRequestLifecycle::Approved,
        ReviewRequestLifecycle::Rejected,
        ReviewRequestLifecycle::ChangesRequested,
        ReviewRequestLifecycle::Answered,
        ReviewRequestLifecycle::Cancelled,
        ReviewRequestLifecycle::Superseded,
    ]
    .into_iter()
    .map(review_lifecycle_state_id)
    .collect();
    let reviewing = review_lifecycle_state_id(ReviewRequestLifecycle::Reviewing);
    let transitions = vec![
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Approved),
            guard: "Settlement only applies to a request still in reviewing; approval carries no outcome and no result.",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Rejected),
            guard: "Settlement only applies to a request still in reviewing; rejection must carry an outcome.",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::ChangesRequested),
            guard: "Settlement only applies to a request still in reviewing; changes-requested must carry an outcome.",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Answered),
            guard: "Settlement only applies to a request still in reviewing; an answer must carry an outcome.",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Cancelled),
            guard: "Settlement only applies to a request still in reviewing; cancellation carries no outcome and no result.",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Superseded),
            guard: "Settlement only applies to a request still in reviewing; supersession carries no outcome and no result.",
        },
    ];
    describe(
        "review_request",
        "Casework review request lifecycle",
        reviewing,
        &state_ids,
        transitions,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn occurrence_state_by_id(id: &str) -> OccurrenceState {
        OccurrenceState::ALL
            .into_iter()
            .find(|&state| occurrence_state_id(state) == id)
            .unwrap_or_else(|| panic!("unknown occurrence state id: {id}"))
    }

    fn occurrence_event_by_id(id: &str) -> OccurrenceEvent {
        OccurrenceEvent::ALL
            .into_iter()
            .find(|&event| occurrence_event_id(event) == id)
            .unwrap_or_else(|| panic!("unknown occurrence event id: {id}"))
    }

    #[test]
    fn occurrence_table_has_36_edges_and_8_states_and_every_edge_round_trips() {
        let description = occurrence_lifecycle();
        assert_eq!(description.states.len(), 8);
        assert_eq!(description.transitions.len(), 36);
        for edge in &description.transitions {
            let from = occurrence_state_by_id(edge.from);
            let event = occurrence_event_by_id(edge.event);
            let to = occurrence_state_by_id(edge.to);
            assert_eq!(transition(from, event), Ok(to));
        }
    }

    #[test]
    fn every_rejected_occurrence_pair_is_absent_from_the_table() {
        let description = occurrence_lifecycle();
        for state in OccurrenceState::ALL {
            for event in OccurrenceEvent::ALL {
                let present = description.transitions.iter().any(|edge| {
                    edge.from == occurrence_state_id(state)
                        && edge.event == occurrence_event_id(event)
                });
                assert_eq!(
                    present,
                    transition(state, event).is_ok(),
                    "{state:?} + {event:?}"
                );
            }
        }
    }

    #[test]
    fn six_occurrence_edges_are_self_transitions() {
        let expected = [
            (
                OccurrenceState::Synchronizing,
                OccurrenceEvent::AttemptUncertain,
            ),
            (
                OccurrenceState::Synchronizing,
                OccurrenceEvent::AttemptCompleted,
            ),
            (OccurrenceState::Claimed, OccurrenceEvent::ObserveOpen),
            (OccurrenceState::Open, OccurrenceEvent::ObserveOpen),
            (
                OccurrenceState::WaitingApplicant,
                OccurrenceEvent::ObserveWaitingApplicant,
            ),
            (
                OccurrenceState::WaitingApplication,
                OccurrenceEvent::ObserveWaitingApplication,
            ),
        ];
        for (state, event) in expected {
            assert_eq!(transition(state, event), Ok(state));
        }

        let description = occurrence_lifecycle();
        let self_transitions: BTreeSet<(&str, &str)> = description
            .transitions
            .iter()
            .filter(|edge| edge.from == edge.to)
            .map(|edge| (edge.from, edge.event))
            .collect();
        let expected_ids: BTreeSet<(&str, &str)> = expected
            .into_iter()
            .map(|(state, event)| (occurrence_state_id(state), occurrence_event_id(event)))
            .collect();
        assert_eq!(self_transitions.len(), 6);
        assert_eq!(self_transitions, expected_ids);
    }

    #[test]
    fn completed_superseded_and_cancelled_are_terminal_and_nothing_is_unreachable() {
        let description = occurrence_lifecycle();
        for id in ["completed", "superseded", "cancelled"] {
            let state = description
                .states
                .iter()
                .find(|state| state.id == id)
                .unwrap_or_else(|| panic!("missing occurrence state {id}"));
            assert!(state.terminal, "{id} should be terminal");
        }
        assert!(
            description.states.iter().all(|state| !state.unreachable),
            "no occurrence state should be unreachable"
        );
    }

    #[test]
    fn review_table_has_7_states_and_6_edges_all_from_reviewing_on_settle() {
        let description = review_lifecycle();
        assert_eq!(description.states.len(), 7);
        assert_eq!(description.transitions.len(), 6);
        for edge in &description.transitions {
            assert_eq!(edge.from, "reviewing");
            assert_eq!(edge.event, "settle");
        }
        for id in [
            "approved",
            "rejected",
            "changes_requested",
            "answered",
            "cancelled",
            "superseded",
        ] {
            let state = description
                .states
                .iter()
                .find(|state| state.id == id)
                .unwrap_or_else(|| panic!("missing review state {id}"));
            assert!(state.terminal, "{id} should be terminal");
        }
        assert!(
            description.states.iter().all(|state| !state.unreachable),
            "no review state should be unreachable"
        );
    }

    #[test]
    fn every_review_request_lifecycle_variant_appears_in_the_review_table() {
        let description = review_lifecycle();
        let ids: BTreeSet<&str> = description.states.iter().map(|state| state.id).collect();
        for variant in [
            ReviewRequestLifecycle::Reviewing,
            ReviewRequestLifecycle::Approved,
            ReviewRequestLifecycle::Rejected,
            ReviewRequestLifecycle::ChangesRequested,
            ReviewRequestLifecycle::Answered,
            ReviewRequestLifecycle::Cancelled,
            ReviewRequestLifecycle::Superseded,
        ] {
            assert!(ids.contains(review_lifecycle_state_id(variant)));
        }
    }
}
