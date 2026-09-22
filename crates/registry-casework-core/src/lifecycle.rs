//! Data descriptions of Casework's two state machines: the occurrence
//! lifecycle every work item moves through, and the review request lifecycle
//! a review settles into. Both are exposed as plain data so a caller (for
//! example an `explain` endpoint) can render or diff them without embedding
//! lifecycle knowledge of its own.
//!
//! Each edge's `guard` states only what the state machine itself checks: for
//! an occurrence, that the `(state, event)` pair is in the reducer's table; for
//! a review request, the quorum arithmetic `record_review_decision` runs after
//! it has accepted a decision. Everything the runtime checks around that, from
//! the caller's token to the row lock the write is made under, is reported once
//! per machine in `enforcement`, in execution order, with the events each layer
//! covers. A layer is a named place the runtime can refuse, not an enumeration
//! of every check made there: the exact predicates live in the runtime crate
//! and change without notice.

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
    pub enforcement: Vec<EnforcementLayer>,
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
    /// What the state machine itself checks before it moves the state. Nothing
    /// the runtime checks around it appears here; that is `enforcement`.
    pub guard: &'static str,
}

/// One place the runtime can refuse an event, in execution order within
/// `LifecycleDescription::enforcement`. `events` names every event the layer
/// runs for; an event absent from the list passes the layer without being
/// checked there. Where an event is raised on more than one path and the layer
/// gates only some of them, the description says which. One list can report one
/// order, so where a layer's position is not the one a particular event meets,
/// that layer's description names the event and where it really runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnforcementLayer {
    pub id: &'static str,
    pub description: &'static str,
    pub events: &'static [&'static str],
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
    enforcement: Vec<EnforcementLayer>,
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
        enforcement,
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

/// What the reducer itself checks: that the `(state, event)` pair is in its
/// fixed table. It is a pure function that sees no actor, revision, attempt,
/// holder, queue, binding, or source, so the guard names the state the
/// occurrence must already be in and nothing else. The runtime's checks around
/// the call are `occurrence_enforcement`.
fn occurrence_guard(event: OccurrenceEvent) -> &'static str {
    match event {
        OccurrenceEvent::Claim => "the occurrence is open",
        OccurrenceEvent::Release | OccurrenceEvent::AttemptReserved => {
            "the occurrence is claimed"
        }
        OccurrenceEvent::AttemptUncertain
        | OccurrenceEvent::AttemptCompleted
        | OccurrenceEvent::AttemptRefused => "the occurrence is synchronizing",
        OccurrenceEvent::ObserveOpen => {
            "the occurrence is in any active state; a claimed occurrence keeps its holding through an open readback"
        }
        OccurrenceEvent::ObserveWaitingApplicant
        | OccurrenceEvent::ObserveWaitingApplication
        | OccurrenceEvent::Complete
        | OccurrenceEvent::Supersede
        | OccurrenceEvent::Cancel => "the occurrence is in any active state",
    }
}

/// The events a caller raises over HTTP. The other six are raised by an
/// authoritative observation of the source, which carries no caller.
const CALLER_EVENTS: &[&str] = &[
    "claim",
    "release",
    "attempt_reserved",
    "attempt_uncertain",
    "attempt_completed",
    "attempt_refused",
];

/// Every occurrence event, in `OccurrenceEvent::ALL` order.
const EVERY_OCCURRENCE_EVENT: &[&str] = &[
    "claim",
    "release",
    "attempt_reserved",
    "attempt_uncertain",
    "attempt_completed",
    "attempt_refused",
    "observe_open",
    "observe_waiting_applicant",
    "observe_waiting_application",
    "complete",
    "supersede",
    "cancel",
];

/// The layers the runtime runs around an occurrence transition, in the order a
/// caller-authenticated request meets them. Two paths do not start at the
/// first layer: reconciliation enters at the source-binding layer, and so does
/// the clock-driven release. The event lists are the runtime's own gating, not
/// a choice this module makes: neither recover route carries an If-Match and
/// neither attempt settlement compares the item revision, so the revision layer
/// stops at reservation; the operator path that settles an uncertain attempt
/// carries no caller at all. The order is the one every event meets except the
/// reservation, which reaches the reducer before its key check and the attempt
/// fence rather than after them; the reducer layer names that exception rather
/// than the list being split into a per-event order.
fn occurrence_enforcement() -> Vec<EnforcementLayer> {
    vec![
        EnforcementLayer {
            id: "caller_authentication",
            description: "The bearer token, the selected Casework profile, and its scopes verify; a token that impersonates or carries a registry grant is refused for any non-Requester profile, and the session must be a verified human. Gates the human paths only: the clock-driven release, the operator settlement of an uncertain attempt, and every observation carry no caller.",
            events: CALLER_EVENTS,
        },
        EnforcementLayer {
            id: "caller_revision_precondition",
            description: "The If-Match header is present and well formed before any row is read, and inside the transaction the locked item row still carries the revision, source binding, and activity the caller saw. Only the header check happens at this position. The comparison against the locked row runs much later: on the claim and release paths it follows both the idempotency admission and the holder-state refusals below, so an exact retry of an operation that already succeeded is answered from its record rather than refused for the revision having moved since; on the reservation path it follows the holder and queue checks and precedes the reducer. Neither recover route carries an If-Match, and no attempt settlement compares the item revision.",
            events: &["claim", "release", "attempt_reserved"],
        },
        EnforcementLayer {
            id: "erased_item_idempotency_preflight",
            description: "Before the source is re-read, a retry naming an item that has already been erased is answered from the retained idempotency record alone: a recorded request hash differing from this one is refused as a conflict, and a record whose response has been retained away is refused as expired. A reservation is stricter: any recorded hash matching this one is refused as expired, because an erased item can no longer be reserved even where the stored response survives. It runs only against an erased item and only for a caller who currently serves that item's queue in the role the operation needs, so a live item passes it and reaches the source and queue layers below.",
            events: &["claim", "release", "attempt_reserved"],
        },
        EnforcementLayer {
            id: "source_authorization",
            description: "The caller can see the item's queue, and the source, re-read as this caller, still discloses the subject under the binding the item holds. A binding the source has moved refuses the action; a subject the source no longer discloses is reported as absent. Those hold on every caller event named here, the recovery settlements included, because one shared caller read enforces them for every entry point. The further check that the source still offers the operation being attempted is narrower, and holds only on the reservation, the one path that chooses an operation. A recovery re-executes the operation its attempt already prepared and never re-tests it against the set the source offers now; standing in its place is the saved preparation itself, matched on the recorded binding and idempotency key and executed under a single-flight lease. The operator settlement of an uncertain attempt raises two of these events with no caller and reads no source, so that path passes this layer without being checked here.",
            events: CALLER_EVENTS,
        },
        EnforcementLayer {
            id: "queue_and_holder_authority",
            description: "The actor is a staff member of a team serving the item's queue; a supervisor serving that queue may release another person's holding but may not claim or reserve. A claim refuses an item already held. A release refuses an item nobody holds, and refuses a staff member who is not the recorded holder, but the supervisor above may release whoever holds it. A reservation refuses anyone but the recorded holder. On the claim and release paths this layer straddles the idempotency admission below: the queue membership check runs before that admission and the holder-state refusals after it, so an exact retry of a claim that already succeeded is answered from its record rather than refused for the item now being held. A reservation sits on neither side of that split, being admitted by no record at all, and meets the holder check before the queue check.",
            events: &["claim", "release", "attempt_reserved"],
        },
        EnforcementLayer {
            id: "idempotency_admission",
            description: "With the item row locked, a retried claim or release is answered from its recorded idempotency record: a recorded request hash differing from this one is refused as a conflict, and a retry whose stored response retention has erased, including the item itself, is refused as expired. Against an already erased item the preflight layer above has answered this before the source was read. A reservation is admitted by its own key check below instead, and no attempt settlement reaches an idempotency record on any path.",
            events: &["claim", "release"],
        },
        EnforcementLayer {
            id: "source_binding_currency",
            description: "An observation is applied only when it is the newest authoritative reading of the subject under the current binding generation: a stale generation is refused, an older revision is dropped, and an unchanged revision and etag reconciles clocks only. A source may never assert the claimed or synchronizing state. A clock effect additionally requires the subject, the observation, and its own recorded generation, revision, and etag to all be current.",
            events: &[
                "observe_open",
                "observe_waiting_applicant",
                "observe_waiting_application",
                "complete",
                "supersede",
                "cancel",
                "release",
            ],
        },
        EnforcementLayer {
            id: "reservation_key_admission",
            description: "A retried reservation is admitted by its own key lookup rather than by the idempotency record above, and that lookup straddles the layers between. It reads the attempt row recorded for this item and key before the source is re-read, comparing the actor, the caller's casework profile, and the request hash the row carries, but its outcome is taken only after the source layer above has run: a difference in any of those is refused as a conflict, an item erased since is refused as expired, and an exact match returns the stored attempt with whatever receipt it holds. A retried reservation is therefore answered from its record, and returns before the holder, operation-offered, and fence checks below are reached. Only where that lookup found no row does the reservation itself lock the row and compare the actor, both profiles, the displayed binding, the recovery evidence, and the operation field by field, refusing a difference as a conflict and an exact match as a still-pending attempt. That locked compare reads no request hash, and is reachable only by a concurrent caller who inserted under the same key in between, so it decides a race and never an ordinary retry.",
            events: &["attempt_reserved"],
        },
        EnforcementLayer {
            id: "attempt_fence",
            description: "No occurrence changes while a pending or uncertain attempt is live on the item: a claim, release, or reservation is refused, a clock effect is deferred, and an observation is requeued. An attempt settlement is fenced by the execution token recorded on the attempt; a refusal by the executor also requires its lease to be live, recovery requires it to have expired, and the operator settlement of an uncertain attempt requires an expired lease and then issues a fresh token that fences the original executor out.",
            events: EVERY_OCCURRENCE_EVENT,
        },
        EnforcementLayer {
            id: "lifecycle_transition",
            description: "The edge's own guard, run by the reducer: the (state, event) pair is in the fixed table. In practice this refuses every event against a completed, superseded, or cancelled occurrence and every caller event raised from the wrong active state. The position reported here is where every event but one reaches it. The reservation is the exception: its reducer runs before the key check and the attempt fence above, so a reservation against a state the table refuses is refused before either of them.",
            events: EVERY_OCCURRENCE_EVENT,
        },
        EnforcementLayer {
            id: "persist_serialization",
            description: "Every write runs in a transaction that already holds a row lock on the item, and on the subject or clock occurrence where one is involved, so a concurrent writer is serialized behind this one rather than filtered at write time; the clock path claims its effect once only. The first authoritative observation of an unseen occurrence is the exception: it inserts the item, so there is no item row to lock and the subject lock is the whole of its serialization. There is no row-level security and no persist-time state filter on this machine.",
            events: EVERY_OCCURRENCE_EVENT,
        },
    ]
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
        occurrence_enforcement(),
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

const EVERY_REVIEW_EVENT: &[&str] = &[
    REVIEW_RECORD_EVENT,
    REVIEW_ADVANCE_EVENT,
    REVIEW_SETTLE_EVENT,
];

/// The layers the runtime runs around a review request transition, in the
/// order a decision meets them. `settle` is one event with six targets, and
/// only four of them are raised by a decision: `cancelled` is the producer
/// withdrawing its request and `superseded` is the producer replacing it, and
/// both reach the persist filter directly. A layer that runs only on the
/// decision path therefore says so in its description rather than pretending
/// a reviewer check gates a requester's cancellation.
fn review_enforcement() -> Vec<EnforcementLayer> {
    macro_rules! decision_path_only {
        ($text:literal) => {
            concat!($text, " Gates the decision path only: record_decision, advance_stage, and the settle to approved, rejected, changes_requested, or answered, not cancelled or superseded.")
        };
    }
    vec![
        EnforcementLayer {
            id: "caller_authentication",
            description: "The bearer token, the selected Casework profile, and its scopes verify. A reviewer profile additionally refuses a token that impersonates or carries a registry grant and any session that is not a verified human; a Requester producer profile is exempt from both.",
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "producer_or_reviewer_admission",
            description: "The caller's role and profile are admitted for the path: a decision requires a human staff member or supervisor, while cancellation and creation require a Requester whose profile, issuer, and subject match a declared review producer covering the request's kind and source namespace. A source-profile header is refused outright on the creation and cancellation routes, and on a decision it is refused or required according to the policy's context strategy.",
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "review_source_preflight",
            description: decision_path_only!("Where the review kind takes its context from a source, the subject re-read as the deciding caller must still be the subject, binding version, and integrity digest pinned on the request, its disclosure must pass the policy's display rules, and the authoritative occurrence must still be reviewable: active or completed, never synchronizing. A record whose result has been erased or has expired is refused as well."),
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "producer_submission_idempotency",
            description: "A producer submitting a new review is admitted here, before any request row is locked. An advisory lock over the producer, the subject, and the review kind serializes that producer's concurrent submissions, and the submission's own idempotency record answers a retry under it: a recorded request hash differing from this one is refused as a conflict, and a record whose response has been retained away is refused as expired. The producer's priors that this submission supersedes are selected and locked only after that, so the settlements a supersession raises reach the request lock below having already passed this admission, not the one under the lock. The recovery route is admitted from its idempotency record too, and takes no lock at all.",
            events: &["settle"],
        },
        EnforcementLayer {
            id: "request_lock_and_lifecycle",
            description: "On the decision, stage, and cancellation routes the review request row is locked before anything is decided, and an event against a request not still in reviewing is refused; a repeated cancellation returns the terminal result already recorded rather than settling twice. Only the lock is taken at this position: it precedes both layers below, while the reviewing check itself runs after them, so a retry recorded while the request was still reviewing is replayed from its record rather than refused for having settled since. Cancellation also refuses a subject that is not the one the caller named, at that later position. A supersession reaches this lock through the producer's submission above, which selects only that producer's own reviewing requests.",
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "reviewer_queue_authority",
            description: decision_path_only!("The reviewer's role is neither Administrator nor Requester, their profile appears in at least one stage's deciding profiles, and they are a staff or supervisor member of a team serving a task this request holds at one of those stages; the task, queue-service, and membership rows are locked together so a concurrent membership change cannot race the decision. That half runs under the request lock and before the idempotency admission below, so a retry whose recorded response is still stored is refused for lost authority rather than replayed. The other half runs later, after the task revision below: the queue the locked task actually carries is re-checked against this reviewer's membership, so a task moved to a queue they do not serve is refused even though the first half passed."),
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "request_idempotency_admission",
            description: "With the request row locked and the reviewer admitted above, a retry on the decision, stage, or cancellation route is answered from its recorded idempotency record before any revision, holder, or decision check runs: a recorded request hash differing from this one is refused as a conflict, and a record whose response has been retained away is refused as expired. A settlement raised by a producer's submission or by the recover route was admitted by the producer submission layer above instead, without this lock.",
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "task_revision_and_holder",
            description: decision_path_only!("Three checks at three positions, not one. The If-Match header is mandatory, and its syntax is settled by the HTTP layer before the decision call is entered at all: a missing or empty value is refused as precondition-required, and an unquoted, non-numeric, or non-positive one as an invalid request, each ahead of the source preflight, the request lock, the reviewer authority, and the idempotency admission above. A caller malformed here and unauthorized below is therefore told only that the header was malformed. The value that parse produced is compared against the locked task row's revision much later, immediately after that admission, and a decision on a task another operation has advanced is refused there as a revision conflict. The holder check runs later still, after the queue re-check above has confirmed the queue the locked task actually carries: an unheld task, a task held by someone else, and a task already decided are each refused."),
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "decision_eligibility",
            description: decision_path_only!("Everything the engine checks before it counts the decision as a vote: the policy verifies, the request is not already settled, the stage, request, and task identities agree, the deciding profile is listed by both the stage and the task, neither this task nor this reviewer has already decided in the stage, the initiator and previous-stage-reviewer exclusions hold, and the decision kind is one the stage's purpose allows, with its outcome validated against the policy."),
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "stage_quorum_progression",
            description: decision_path_only!("The edge's own guard, run by the engine once it has accepted the decision: a non-approving decision settles the request at once, and an approval is counted against the stage's required approvals to decide whether the request stays in the stage, advances, or settles as approved."),
            events: EVERY_REVIEW_EVENT,
        },
        EnforcementLayer {
            id: "settlement_persist_filter",
            description: "The terminal write updates the request row only where its lifecycle is still reviewing, closes every open or claimed task on the request, and applies the settled status's clock effects. Every caller reaches it holding the row lock and having compared the lifecycle above, so the filter is a backstop rather than the check that refuses.",
            events: &[REVIEW_SETTLE_EVENT],
        },
    ]
}

/// Describe the review request lifecycle: seven states and eight edges, all
/// leaving `reviewing`.
///
/// Six of the eight are raised by a reviewer's decision, and only four of
/// those settle the request. Which of `approved`, `rejected`,
/// `changes_requested`, or `answered` a given review reaches is decided by
/// `record_review_decision` against the adopter's configured review policy.
/// The guards state the arithmetic that engine runs once it has accepted a
/// decision, and nothing it checks before accepting one; that is
/// `review_enforcement`.
///
/// The other two decision edges return to `reviewing`, and omitting them
/// would report that every decision settles the request. An approval that
/// leaves the active stage short of its required approvals is recorded and
/// moves no stage; an approval that meets them while a later stage remains
/// advances the stage.
///
/// The last two are not decisions at all and must not be described as if they
/// were. `cancelled` is the producer withdrawing its own request, and
/// `superseded` is applied automatically to a prior reviewing request when the
/// same admitted producer creates a replacement for the same subject and
/// policy. Neither path consults a reviewer, a stage, or a quorum.
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
            guard: "an approval that leaves the active stage's approvals short of the stage's required approvals; it is recorded against the task and moves no stage",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_ADVANCE_EVENT,
            to: reviewing,
            guard: "the approval that meets the active stage's required approvals while a later stage remains; the next stage becomes the active one",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Approved),
            guard: "the approval that meets the required approvals of the last stage",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Rejected),
            guard: "a rejection, which as a non-approving decision settles the request at once regardless of quorum",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::ChangesRequested),
            guard: "a changes-requested decision, which as a non-approving decision settles the request at once regardless of quorum",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Answered),
            guard: "an answer, which as a non-approving decision settles the request at once regardless of quorum",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Cancelled),
            guard: "the producer withdrew its own request; no reviewer, stage, or quorum is consulted",
        },
        LifecycleTransition {
            from: reviewing,
            event: REVIEW_SETTLE_EVENT,
            to: review_lifecycle_state_id(ReviewRequestLifecycle::Superseded),
            guard: "the same admitted producer, matched on its id, issuer and subject, created a replacement request for the same subject, type, and policy, so a request one producer creates never supersedes another producer's; no reviewer, stage, or quorum is consulted",
        },
    ];
    describe(
        "review_request",
        "Casework review request lifecycle",
        &[reviewing],
        &state_ids,
        transitions,
        review_enforcement(),
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

    fn layer<'a>(description: &'a LifecycleDescription, id: &str) -> &'a EnforcementLayer {
        description
            .enforcement
            .iter()
            .find(|layer| layer.id == id)
            .unwrap_or_else(|| panic!("{} has no {id} layer", description.id))
    }

    fn declared_events(description: &LifecycleDescription) -> BTreeSet<&'static str> {
        description
            .transitions
            .iter()
            .map(|edge| edge.event)
            .collect()
    }

    /// The reducer is a pure function of `(state, event)` that sees no actor,
    /// revision, attempt, holder, queue, or source, so a guard may state only
    /// which state the occurrence must already be in. Everything else the
    /// runtime checks is a reported layer, and a guard that restated one
    /// would put a caller-only check on the observation path that carries no
    /// caller.
    #[test]
    fn occurrence_guards_state_the_reducer_condition_and_restate_no_layer() {
        let description = occurrence_lifecycle();
        for edge in &description.transitions {
            assert!(!edge.guard.is_empty(), "{edge:?}");
            for phrase in [
                "actor",
                "authority",
                "holder",
                "revision",
                "If-Match",
                "attempt is live",
                "execution token",
                "lease",
                "operator",
                "clock",
                "source binding",
                "queue",
            ] {
                assert!(
                    !edge.guard.contains(phrase),
                    "{edge:?} restates an enforcement layer: {phrase:?}"
                );
            }
        }
        let by_event = |event: &str| -> BTreeSet<&str> {
            description
                .transitions
                .iter()
                .filter(|edge| edge.event == event)
                .map(|edge| edge.guard)
                .collect()
        };
        assert_eq!(
            by_event("claim"),
            BTreeSet::from(["the occurrence is open"])
        );
        assert_eq!(
            by_event("attempt_completed"),
            BTreeSet::from(["the occurrence is synchronizing"])
        );
        assert_eq!(
            by_event("observe_open"),
            BTreeSet::from([
                "the occurrence is in any active state; a claimed occurrence keeps its holding through an open readback",
            ])
        );
    }

    /// The layers are reported in the order a caller-authenticated request
    /// meets them, with the reducer placed where it sits among them, and
    /// each names at least one event the table raises and no event it does
    /// not.
    #[test]
    fn occurrence_enforcement_layers_are_ordered_and_name_declared_events() {
        let description = occurrence_lifecycle();
        let ids: Vec<&str> = description
            .enforcement
            .iter()
            .map(|layer| layer.id)
            .collect();
        assert_eq!(
            ids,
            vec![
                "caller_authentication",
                "caller_revision_precondition",
                "erased_item_idempotency_preflight",
                "source_authorization",
                "queue_and_holder_authority",
                "idempotency_admission",
                "source_binding_currency",
                "reservation_key_admission",
                "attempt_fence",
                "lifecycle_transition",
                "persist_serialization",
            ]
        );
        let events = declared_events(&description);
        for layer in &description.enforcement {
            assert!(!layer.events.is_empty(), "{layer:?}");
            assert!(!layer.description.is_empty(), "{layer:?}");
            for event in layer.events {
                assert!(
                    events.contains(event),
                    "{layer:?} names an undeclared event"
                );
            }
        }
    }

    /// Which events a layer covers is what the runtime does, not a choice
    /// this module makes. The six observation events and the clock-driven
    /// release carry no caller, so no caller layer may list them; neither
    /// recover route carries an If-Match and neither settlement compares the
    /// item revision, so the revision layer stops at reservation; and only
    /// the attempt fence, the reducer, and the row locks run for everything.
    #[test]
    fn occurrence_layers_cover_exactly_the_events_the_runtime_gates() {
        let description = occurrence_lifecycle();
        let caller_events = [
            "claim",
            "release",
            "attempt_reserved",
            "attempt_uncertain",
            "attempt_completed",
            "attempt_refused",
        ];
        let observation_events = [
            "observe_open",
            "observe_waiting_applicant",
            "observe_waiting_application",
            "complete",
            "supersede",
            "cancel",
        ];
        assert_eq!(
            layer(&description, "caller_authentication").events,
            caller_events
        );
        assert_eq!(
            layer(&description, "caller_revision_precondition").events,
            ["claim", "release", "attempt_reserved"]
        );
        assert_eq!(
            layer(&description, "erased_item_idempotency_preflight").events,
            ["claim", "release", "attempt_reserved"]
        );
        assert_eq!(
            layer(&description, "source_authorization").events,
            caller_events
        );
        assert_eq!(
            layer(&description, "queue_and_holder_authority").events,
            ["claim", "release", "attempt_reserved"]
        );
        assert_eq!(
            layer(&description, "idempotency_admission").events,
            ["claim", "release"]
        );
        assert_eq!(
            layer(&description, "reservation_key_admission").events,
            ["attempt_reserved"]
        );
        let mut currency = observation_events.to_vec();
        currency.push("release");
        assert_eq!(
            layer(&description, "source_binding_currency").events,
            currency
        );
        let every: Vec<&str> = OccurrenceEvent::ALL
            .into_iter()
            .map(occurrence_event_id)
            .collect();
        for id in [
            "attempt_fence",
            "lifecycle_transition",
            "persist_serialization",
        ] {
            assert_eq!(layer(&description, id).events, every, "{id}");
        }
        for event in observation_events {
            for id in [
                "caller_authentication",
                "caller_revision_precondition",
                "erased_item_idempotency_preflight",
                "source_authorization",
                "queue_and_holder_authority",
                "idempotency_admission",
                "reservation_key_admission",
            ] {
                assert!(
                    !layer(&description, id).events.contains(&event),
                    "{id} lists {event}, which carries no caller"
                );
            }
        }
    }

    /// Two events reach the reducer on a path with no caller at all: the
    /// clock reassigns a claimed item, and an operator settles an uncertain
    /// attempt whose lease has expired. The layers that gate the human path
    /// say so, or a reader would take the caller checks as covering every
    /// raise of the event.
    #[test]
    fn layers_name_the_caller_free_paths_they_do_not_gate() {
        let description = occurrence_lifecycle();
        let authentication = layer(&description, "caller_authentication").description;
        assert!(authentication.contains("clock"), "{authentication}");
        assert!(authentication.contains("operator"), "{authentication}");
        let revision = layer(&description, "caller_revision_precondition").description;
        assert!(revision.contains("recover"), "{revision}");
        let fence = layer(&description, "attempt_fence").description;
        assert!(fence.contains("execution token"), "{fence}");
        assert!(fence.contains("lease"), "{fence}");
        // The operator settlement reaches this layer's events without a caller
        // and without a source read, so the layer has to say so rather than
        // report a source check that path never runs.
        let source = layer(&description, "source_authorization").description;
        assert!(source.contains("operator"), "{source}");
    }

    /// One ordered list per machine can report one order, and the reservation
    /// is the single occurrence event whose reducer does not run where this
    /// list puts it: `reserve_attempt_for_execution` calls the reducer before
    /// its key check and before the attempt fence, while claim, release, the
    /// six observations, and the clock-driven release all reach the fence
    /// first. The list keeps the majority order and the layer that moves has
    /// to name the event it moves for, or the report states an order that is
    /// wrong for one event and says nothing about it.
    #[test]
    fn the_reducer_layer_names_the_one_event_that_reaches_it_early() {
        let description = occurrence_lifecycle();
        let index = |id: &str| {
            description
                .enforcement
                .iter()
                .position(|layer| layer.id == id)
                .unwrap_or_else(|| panic!("enforcement layer {id} declared"))
        };
        assert!(index("attempt_fence") < index("lifecycle_transition"));
        assert!(index("reservation_key_admission") < index("attempt_fence"));
        let reducer = layer(&description, "lifecycle_transition").description;
        assert!(reducer.contains("reservation"), "{reducer}");
        assert!(reducer.contains("attempt fence"), "{reducer}");
    }

    /// The reservation is admitted by a field-by-field comparison of its own
    /// attempt row, not by the idempotency record the other caller events use,
    /// and an exact match there is refused rather than replayed. Reporting it
    /// under the idempotency layer would promise a replay the runtime never
    /// performs, so the two are separate layers and the idempotency layer must
    /// not list the event it no longer gates.
    #[test]
    fn the_reservation_key_lookup_answers_a_retry_from_its_record() {
        let description = occurrence_lifecycle();
        let idempotency = layer(&description, "idempotency_admission");
        assert!(
            !idempotency.events.contains(&"attempt_reserved"),
            "{idempotency:?}"
        );
        let reservation = layer(&description, "reservation_key_admission").description;
        assert!(
            reservation.contains("answered from its record"),
            "a retried reservation is answered, not refused: {reservation}"
        );
        assert!(
            reservation.contains("request hash"),
            "the hash the early lookup compares stopped being reported: {reservation}"
        );
        assert!(
            reservation.contains("never an ordinary retry"),
            "the locked compare decides a race alone: {reservation}"
        );
    }

    #[test]
    fn the_operation_offered_check_is_scoped_to_the_reservation() {
        let description = occurrence_lifecycle();
        let source = layer(&description, "source_authorization").description;
        assert!(
            source.contains("holds only on the reservation"),
            "the operation check is not run on recovery and must say so: {source}"
        );
        assert!(
            source.contains("never re-tests it"),
            "recovery re-executes a prepared operation without re-testing it: {source}"
        );
        assert!(
            source.contains("recovery settlements included"),
            "disclosure and binding currency do hold on recovery: {source}"
        );
    }

    #[test]
    fn the_decision_layer_puts_the_header_syntax_before_the_call() {
        let description = review_lifecycle();
        let revision = layer(&description, "task_revision_and_holder").description;
        assert!(
            revision.contains("before the decision call is entered at all"),
            "the header syntax is settled outside the service call: {revision}"
        );
        assert!(
            revision.contains("told only that the header was malformed"),
            "the header refusal wins over every check below it: {revision}"
        );
        assert!(
            revision.contains("later still"),
            "the holder check is not adjacent to the revision compare: {revision}"
        );
    }

    /// The first authoritative observation of an unseen occurrence inserts the
    /// item row, so there is no item row to lock and the subject lock is the
    /// whole of the serialization. A layer claiming every write already holds
    /// an item lock would report a guarantee that path does not have.
    #[test]
    fn the_persist_layer_names_the_write_that_holds_no_item_lock() {
        let description = occurrence_lifecycle();
        let persist = layer(&description, "persist_serialization").description;
        assert!(persist.contains("no item row"), "{persist}");
        assert!(persist.contains("subject"), "{persist}");
    }

    /// A producer's submission is admitted before any review request row is
    /// locked: an advisory lock and the submission's own idempotency record
    /// answer a retry, and the priors it supersedes are selected and locked
    /// only afterwards. The lock-first layers below are correct for the
    /// decision and cancellation routes and wrong for this one, so this
    /// admission is reported as its own layer in front of them.
    #[test]
    fn the_producer_submission_is_admitted_before_the_request_lock() {
        let description = review_lifecycle();
        let index = |id: &str| {
            description
                .enforcement
                .iter()
                .position(|layer| layer.id == id)
                .unwrap_or_else(|| panic!("enforcement layer {id} declared"))
        };
        assert!(index("producer_submission_idempotency") < index("request_lock_and_lifecycle"));
        assert!(index("request_lock_and_lifecycle") < index("reviewer_queue_authority"));
        assert!(index("reviewer_queue_authority") < index("request_idempotency_admission"));
        assert_eq!(
            layer(&description, "producer_submission_idempotency").events,
            ["settle"]
        );
        let admission = layer(&description, "request_idempotency_admission").description;
        assert!(admission.contains("recover"), "{admission}");
    }

    /// A supervisor serving the queue may release another person's holding, so
    /// the layer that grants that exception must not also state a blanket
    /// recorded-holder rule that would take it back.
    #[test]
    fn the_holder_layer_keeps_the_supervisor_release_exception() {
        let description = occurrence_lifecycle();
        let holder = layer(&description, "queue_and_holder_authority").description;
        assert!(holder.contains("supervisor"), "{holder}");
        assert!(
            !holder.contains("a release or reservation refuses anyone but the recorded holder"),
            "the blanket rule contradicts the supervisor exception: {holder}"
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
            staying[1].guard.contains("a later stage remains"),
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

    /// `record_review_decision` decides four things and nothing else: a
    /// non-approving decision settles at once, an approval short of the
    /// stage's required approvals is recorded, an approval meeting them on
    /// the last stage settles as approved, and one meeting them earlier
    /// advances the stage. Cancellation and supersession never reach it. A
    /// guard may say only that; the task, holder, revision, queue, source,
    /// and eligibility checks are reported layers.
    #[test]
    fn review_guards_state_the_machine_condition_and_restate_no_layer() {
        let description = review_lifecycle();
        for edge in &description.transitions {
            assert!(!edge.guard.is_empty(), "{edge:?}");
            for phrase in [
                "If-Match",
                "revision",
                "holds",
                "held",
                "deciding profile",
                "exclusion",
                "re-reads",
                "source access",
                "queue",
                "already settled",
                "still in reviewing",
            ] {
                assert!(
                    !edge.guard.contains(phrase),
                    "{edge:?} restates an enforcement layer: {phrase:?}"
                );
            }
        }
        let guard = |to: &str, event: &str| -> &'static str {
            description
                .transitions
                .iter()
                .find(|edge| edge.to == to && edge.event == event)
                .unwrap_or_else(|| panic!("no {event} edge to {to}"))
                .guard
        };
        assert!(guard("reviewing", "record_decision").contains("approval"));
        assert!(guard("reviewing", "advance_stage").contains("later stage remains"));
        assert!(guard("approved", "settle").contains("last stage"));
        for to in ["rejected", "changes_requested", "answered"] {
            let guard = guard(to, "settle");
            assert!(guard.contains("regardless of quorum"), "{to}: {guard}");
        }
        for to in ["cancelled", "superseded"] {
            let guard = guard(to, "settle");
            assert!(
                guard.contains("no reviewer, stage, or quorum"),
                "{to}: {guard}"
            );
        }
    }

    /// Two admitted producers may hold requests for the same subject and
    /// policy at once, so supersession that reads as unscoped is wrong.
    #[test]
    fn supersession_is_scoped_to_the_same_producer() {
        let guard = review_lifecycle()
            .transitions
            .into_iter()
            .find(|edge| edge.to == "superseded")
            .expect("superseded edge")
            .guard;
        assert!(guard.contains("the same admitted producer"), "{guard}");
        assert!(guard.contains("id, issuer and subject"), "{guard}");
    }

    /// The layers are reported in the order a decision meets them, with the
    /// quorum arithmetic placed where it sits among them, and each names at
    /// least one event the table raises and no event it does not.
    #[test]
    fn review_enforcement_layers_are_ordered_and_name_declared_events() {
        let description = review_lifecycle();
        let ids: Vec<&str> = description
            .enforcement
            .iter()
            .map(|layer| layer.id)
            .collect();
        assert_eq!(
            ids,
            vec![
                "caller_authentication",
                "producer_or_reviewer_admission",
                "review_source_preflight",
                "producer_submission_idempotency",
                "request_lock_and_lifecycle",
                "reviewer_queue_authority",
                "request_idempotency_admission",
                "task_revision_and_holder",
                "decision_eligibility",
                "stage_quorum_progression",
                "settlement_persist_filter",
            ]
        );
        let events = declared_events(&description);
        for layer in &description.enforcement {
            assert!(!layer.events.is_empty(), "{layer:?}");
            assert!(!layer.description.is_empty(), "{layer:?}");
            for event in layer.events {
                assert!(
                    events.contains(event),
                    "{layer:?} names an undeclared event"
                );
            }
        }
    }

    /// The If-Match header is checked before any row is read, but the revision
    /// it carries is compared against the locked row only after the idempotency
    /// admission. Reporting both at the header's position would promise that an
    /// exact retry is refused as a revision conflict, when the record answers it
    /// first.
    #[test]
    fn the_revision_layer_separates_the_header_check_from_the_locked_comparison() {
        let description = occurrence_lifecycle();
        let revision = layer(&description, "caller_revision_precondition").description;
        assert!(
            revision.contains("Only the header check happens at this position"),
            "the two halves stopped being distinguished: {revision}"
        );
        assert!(
            revision.contains("follows both the idempotency admission"),
            "the locked comparison must say what it runs after: {revision}"
        );
    }

    /// Queue membership is checked before the idempotency admission and the
    /// holder-state refusals after it, so the layer that carries both sits at
    /// one position while half its refusals happen at another. Left unsaid, the
    /// report would promise that an exact retry of a successful claim is
    /// refused for the item being held, when the record answers it first.
    #[test]
    fn the_queue_and_holder_layer_names_the_admission_it_straddles() {
        let description = occurrence_lifecycle();
        let authority = layer(&description, "queue_and_holder_authority").description;
        assert!(
            authority.contains("straddles the idempotency admission below"),
            "the straddle stopped being reported: {authority}"
        );
        assert!(
            authority.contains("holder check before the queue check"),
            "the reservation meets the two halves in the other order and must say so: {authority}"
        );
    }

    /// Reviewer authority is consulted under the request lock and before the
    /// idempotency record, so a retry by a reviewer who has since lost their
    /// membership is refused rather than replayed. A report that placed the
    /// admission after the record would promise the opposite.
    #[test]
    fn the_reviewer_authority_is_consulted_before_the_recorded_response() {
        let description = review_lifecycle();
        let index = |id: &str| {
            description
                .enforcement
                .iter()
                .position(|layer| layer.id == id)
                .unwrap_or_else(|| panic!("enforcement layer {id} declared"))
        };
        assert!(index("reviewer_queue_authority") < index("request_idempotency_admission"));
        let authority = layer(&description, "reviewer_queue_authority").description;
        assert!(
            authority.contains("before the idempotency admission below"),
            "the authority layer stopped naming where it sits: {authority}"
        );
        assert!(
            authority.contains("The other half runs later"),
            "the authority layer straddles the record and must say so: {authority}"
        );
        assert!(
            layer(&description, "request_lock_and_lifecycle")
                .description
                .contains("Only the lock is taken at this position"),
            "the lock layer stopped naming that its reviewing check runs later"
        );
    }

    /// `settle` is one event with six targets, two of which (cancelled and
    /// superseded) are raised by no decision. A layer that lists `settle` and
    /// runs only on the decision path therefore has to say which settlements
    /// it gates, or the report claims a reviewer check on a requester
    /// cancellation.
    #[test]
    fn decision_only_layers_say_which_settlements_they_gate() {
        let description = review_lifecycle();
        let every = ["record_decision", "advance_stage", "settle"];
        for id in [
            "caller_authentication",
            "producer_or_reviewer_admission",
            "request_lock_and_lifecycle",
        ] {
            assert_eq!(layer(&description, id).events, every, "{id}");
        }
        for id in [
            "review_source_preflight",
            "reviewer_queue_authority",
            "task_revision_and_holder",
            "decision_eligibility",
            "stage_quorum_progression",
        ] {
            let layer = layer(&description, id);
            assert_eq!(layer.events, every, "{id}");
            assert!(
                layer.description.contains("not cancelled or superseded"),
                "{id} runs only on the decision path and must say so: {}",
                layer.description
            );
        }
        assert_eq!(
            layer(&description, "settlement_persist_filter").events,
            ["settle"]
        );
    }
}
