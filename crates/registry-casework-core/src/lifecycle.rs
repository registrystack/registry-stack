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
/// declared initial states, never hand-written, so the two cannot drift apart.
///
/// A machine may have more than one initial state. `initial` means a record
/// can be created directly in that state, not that it is the only way in, so
/// a state that is both constructible and reachable by transition reports
/// `initial: true` and a non-zero `incomingTransitions`.
fn describe(
    id: &'static str,
    label: &'static str,
    initial_state_ids: &[&'static str],
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
            let initial = initial_state_ids.contains(&state_id);
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

/// What the store actually checks before each occurrence event is raised.
/// The reducer itself is unguarded and total over `(state, event)`; legality
/// is enforced one layer up, and it is enforced differently per event, so
/// these sentences are selected by event rather than shared across the table.
/// An authoritative observation is the case that matters most: it carries no
/// actor at all, so attaching the claim path's holder and queue-authority
/// checks to it would describe a check that never runs.
fn occurrence_guard(event: OccurrenceEvent) -> &'static str {
    match event {
        OccurrenceEvent::Claim => "Raised by a staff actor with authority over the item's queue, on an item that is unheld and still active, at the caller's expected revision, and only while no attempt is live.",
        OccurrenceEvent::Release => "Raised on two paths that check different things. A human release requires staff authority over the queue or supervisor authority, the item held and still active, the caller's expected revision, and no live attempt. The clock-driven reassignment path carries no actor and checks none of those: it requires the item active and not synchronizing, no live attempt, the source occurrence still current against a fresh read, a served target queue, and an unclaimed clock effect.",
        OccurrenceEvent::AttemptReserved => "Raised by the item's current holder with staff authority over its queue, at the caller's expected revision and against an action binding that still matches, and only while no other attempt is live.",
        OccurrenceEvent::AttemptUncertain => "Raised by the actor recorded on the attempt itself, fenced by that attempt's execution token. The item's holder and queue authority are not re-checked here.",
        OccurrenceEvent::AttemptCompleted => "Raised on two mutually exclusive paths. The executing path is raised by the actor recorded on the attempt, fenced by that attempt's execution token, and requires a receipt naming a positive source revision. The operator path settles an uncertain attempt whose lease has already expired: it carries no actor, is fenced by no token, and clears the receipt rather than requiring one. Neither path re-checks the item's holder or queue authority.",
        OccurrenceEvent::AttemptRefused => "Raised on two mutually exclusive paths: by the attempt's own actor under a still-live lease, or by an operator settling an uncertain attempt whose lease has already expired. Neither re-checks the item's holder or queue authority.",
        OccurrenceEvent::ObserveOpen
        | OccurrenceEvent::ObserveWaitingApplicant
        | OccurrenceEvent::ObserveWaitingApplication
        | OccurrenceEvent::Complete
        | OccurrenceEvent::Supersede
        | OccurrenceEvent::Cancel => "Raised by an authoritative observation of the source, which carries no actor and is checked against no queue authority: it requires the source binding generation to match, the observed revision to be monotonic against the revision already applied, and no attempt to be live.",
    }
}

/// The states in which the store can create an occurrence record outright.
/// The first authoritative observation for an unseen occurrence is inserted
/// with the state it reports, so a record can begin in any of these without
/// ever passing through `open`.
const OCCURRENCE_INITIAL_STATES: &[&str] = &["open", "waiting_applicant", "waiting_application"];

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
                    guard: occurrence_guard(event),
                });
            }
        }
    }
    describe(
        "occurrence",
        "Casework occurrence lifecycle",
        OCCURRENCE_INITIAL_STATES,
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

const REVIEW_SETTLE_EVENT: &str = "settle";
const REVIEW_RECORD_EVENT: &str = "record_decision";
const REVIEW_ADVANCE_EVENT: &str = "advance_stage";

/// What `record_review_decision` checks before it looks at the decision at
/// all. Every edge it raises carries these, so the sentence is written once
/// and concatenated onto each of the six rather than drifting six ways.
macro_rules! review_decision_gate {
    () => {
        "Raised on a task on the active stage that the reviewer holds, under a deciding profile that both the stage and the task allow, on a request still in reviewing and not already settled, with no earlier decision on that task, no earlier decision by the same reviewer in this stage, and the stage's initiator and previous-stage-reviewer exclusions satisfied."
    };
}

/// Describe the review request lifecycle: seven states and eight edges, all
/// leaving `reviewing`.
///
/// Six of the eight are raised by a reviewer's decision, and only four of
/// those settle the request. Which of `approved`, `rejected`,
/// `changes_requested`, or `answered` a given review reaches is decided by
/// `record_review_decision` against the adopter's configured review policy
/// (quorum, stage advancement, deciding profiles, initiator and
/// previous-stage-reviewer exclusions). That decision is policy-dependent and
/// deliberately not enumerated here.
///
/// The other two decision edges return to `reviewing`, and omitting them
/// would report that every decision settles the request. An approval that
/// leaves the active stage short of its quorum is recorded and moves no
/// stage; an approval that meets the quorum while a later stage exists closes
/// the active stage's tasks and opens the next stage's.
///
/// The last two are not decisions at all and must not be described as if they
/// were. `cancelled` is the requester withdrawing their own request, and
/// `superseded` is applied automatically to a prior reviewing request when a
/// replacement is created for the same subject and policy. Neither path
/// consults a stage, a quorum, or an exclusion.
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
            event: REVIEW_RECORD_EVENT,
            to: reviewing,
            guard: concat!(
                review_decision_gate!(),
                " An approval that leaves the stage's approvals short of the stage's required approvals is recorded against the task and moves no stage."
            ),
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_ADVANCE_EVENT,
            to: reviewing,
            guard: concat!(
                review_decision_gate!(),
                " An approval that meets the active stage's required approvals while a later stage exists closes that stage's remaining tasks, undecided or unclaimed alike, and opens the next stage's."
            ),
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Approved),
            guard: concat!(
                review_decision_gate!(),
                " On an approval-purpose policy, the approval that meets the last stage's required approvals settles the request as approved; approval carries no outcome and no result."
            ),
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Rejected),
            guard: concat!(
                review_decision_gate!(),
                " On an approval-purpose policy, a rejection settles the request on its own without reaching any quorum, and must carry an outcome the policy declares, with a result when that outcome requires one."
            ),
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::ChangesRequested),
            guard: concat!(
                review_decision_gate!(),
                " On an approval-purpose policy, a changes-requested decision settles the request on its own without reaching any quorum, and must carry an outcome the policy declares, with a result when that outcome requires one."
            ),
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Answered),
            guard: concat!(
                review_decision_gate!(),
                " On an answer-purpose policy, an answer settles the request on its own without reaching any quorum, and must carry an outcome the policy declares, with a result when that outcome requires one."
            ),
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Cancelled),
            guard: "Settlement only applies to a request still in reviewing; cancellation is the requester withdrawing their own request, is raised by no reviewer and through no task, consults no stage, quorum, or exclusion, and carries no outcome and no result.",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Superseded),
            guard: "Settlement only applies to a request still in reviewing; supersession is applied automatically when a replacement request is created for the same subject and policy, is raised by no reviewer and through no task, consults no stage, quorum, or exclusion, and carries no outcome and no result.",
        },
    ];
    describe(
        "review_request",
        "Casework review request lifecycle",
        &[reviewing],
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

    /// A record is created in whatever state the first authoritative
    /// observation reports, not always in `open`: the store inserts
    /// `state_name(observation.state)` directly for an occurrence it has not
    /// seen before. Reporting `open` as the only initial state would tell a
    /// reader that `waiting_applicant` is reachable only by transition, which
    /// is not how a record in that state actually comes to exist.
    #[test]
    fn every_directly_constructible_occurrence_state_is_reported_initial() {
        let description = occurrence_lifecycle();
        let initial: BTreeSet<&str> = description
            .states
            .iter()
            .filter(|state| state.initial)
            .map(|state| state.id)
            .collect();
        assert_eq!(
            initial,
            BTreeSet::from(["open", "waiting_applicant", "waiting_application"])
        );
    }

    /// The guard is the only place the report says what the runtime checks
    /// before an edge fires, so one shared sentence across every edge would
    /// be wrong wherever the checks differ. An authoritative observation in
    /// particular carries no actor at all, so it must not claim the holder
    /// and queue-authority checks a claim makes.
    #[test]
    fn occurrence_guards_are_selected_by_event_not_shared_by_every_edge() {
        let description = occurrence_lifecycle();
        let guards: BTreeSet<&str> = description
            .transitions
            .iter()
            .map(|edge| edge.guard)
            .collect();
        assert!(
            guards.len() > 1,
            "one guard across every edge cannot be accurate: {guards:#?}"
        );

        for edge in &description.transitions {
            let observation = edge.event.starts_with("observe_")
                || matches!(edge.event, "complete" | "supersede" | "cancel");
            if observation {
                for claimed in ["staff authority", "supervisor authority", "current holder"] {
                    assert!(
                        !edge.guard.contains(claimed),
                        "{} claims {claimed:?}, which the observation path never checks: {}",
                        edge.event,
                        edge.guard
                    );
                }
                assert!(
                    edge.guard.contains("carries no actor"),
                    "{} should say it carries no actor: {}",
                    edge.event,
                    edge.guard
                );
            }
        }

        let claim = description
            .transitions
            .iter()
            .find(|edge| edge.event == "claim")
            .expect("the table has a claim edge");
        assert!(
            claim.guard.contains("authority over the item's queue"),
            "claim does check queue authority: {}",
            claim.guard
        );
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
    fn review_table_has_7_states_and_8_edges_all_leaving_reviewing() {
        let description = review_lifecycle();
        assert_eq!(description.states.len(), 7);
        assert_eq!(description.transitions.len(), 8);
        for edge in &description.transitions {
            assert_eq!(edge.from, "reviewing");
        }
        assert_eq!(
            description
                .transitions
                .iter()
                .filter(|edge| edge.event == "settle")
                .count(),
            6
        );
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

    /// `record_review_decision` has three outcomes, not one. An approval that
    /// leaves the active stage short of its quorum is recorded, and an
    /// approval that meets it while a later stage exists advances the stage.
    /// Both leave the request in `reviewing`, so a table of settle edges alone
    /// would report that every decision settles the request.
    #[test]
    fn review_table_reports_the_two_decision_steps_that_do_not_settle() {
        let description = review_lifecycle();
        let staying: Vec<&LifecycleTransition> = description
            .transitions
            .iter()
            .filter(|edge| edge.to == "reviewing")
            .collect();
        let events: Vec<&str> = staying.iter().map(|edge| edge.event).collect();
        assert_eq!(events, vec!["record_decision", "advance_stage"]);
        assert!(
            staying[0].guard.contains("short of the stage's required"),
            "{:?}",
            staying[0]
        );
        assert!(
            staying[1].guard.contains("a later stage exists"),
            "{:?}",
            staying[1]
        );
        for edge in staying {
            assert!(!edge.guard.contains("settles"), "{edge:?}");
        }

        let reviewing = description
            .states
            .iter()
            .find(|state| state.id == "reviewing")
            .expect("reviewing state");
        assert_eq!(reviewing.incoming_transitions, 2);
        assert_eq!(reviewing.outgoing_transitions, 8);
        assert!(reviewing.initial);
        assert!(!reviewing.terminal);
        assert!(!reviewing.unreachable);
    }

    /// `settle_uncertain_attempt` emits `AttemptCompleted` from an operator
    /// decision on an expired lease: no original actor, no execution token,
    /// and it clears the receipt. A guard describing only the executor path
    /// would report a fence and a receipt that path does not have.
    #[test]
    fn attempt_completed_describes_the_operator_path_as_well_as_the_executor() {
        let description = occurrence_lifecycle();
        let completed: Vec<&LifecycleTransition> = description
            .transitions
            .iter()
            .filter(|edge| edge.event == "attempt_completed")
            .collect();
        assert!(!completed.is_empty());
        for edge in &completed {
            assert!(edge.guard.contains("two"), "{edge:?}");
            assert!(edge.guard.contains("operator"), "{edge:?}");
            assert!(edge.guard.contains("expired"), "{edge:?}");
        }
        let uncertain = description
            .transitions
            .iter()
            .find(|edge| edge.event == "attempt_uncertain")
            .expect("an attempt_uncertain edge");
        assert_ne!(uncertain.guard, completed[0].guard);
        assert!(!uncertain.guard.contains("operator"), "{uncertain:?}");
    }

    /// `check_task_holder` refuses `ReviewerTaskState::Open` outright. Calling
    /// the reviewer "the holder of an open task" stated the opposite of the
    /// task state the engine requires.
    #[test]
    fn review_decision_edges_require_a_held_task_not_an_open_one() {
        for edge in review_lifecycle()
            .transitions
            .iter()
            .filter(|edge| edge.event != "settle" || edge.to != "cancelled")
        {
            assert!(!edge.guard.contains("open task"), "{edge:?}");
        }
        let recorded = review_lifecycle()
            .transitions
            .into_iter()
            .find(|edge| edge.event == "record_decision")
            .expect("a record_decision edge");
        assert!(
            recorded
                .guard
                .contains("a task on the active stage that the reviewer holds"),
            "{recorded:?}"
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
