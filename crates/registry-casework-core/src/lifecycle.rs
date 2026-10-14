//! Source-neutral review lifecycle metadata.
use registry_review_protocol::ReviewRequestLifecycle;
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(extend("additionalProperties" = false)))]
#[serde(rename_all = "camelCase")]
pub struct LifecycleDescription {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: &'static str,
    pub label: &'static str,
    pub states: Vec<LifecycleState>,
    pub transitions: Vec<LifecycleTransition>,
    pub enforcement: Vec<EnforcementLayer>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(extend("additionalProperties" = false)))]
#[serde(rename_all = "camelCase")]
pub struct LifecycleState {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: &'static str,
    pub initial: bool,
    pub terminal: bool,
    pub unreachable: bool,
    pub incoming_transitions: usize,
    pub outgoing_transitions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(extend("additionalProperties" = false)))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(extend("additionalProperties" = false)))]
#[serde(rename_all = "camelCase")]
pub struct EnforcementLayer {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
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
/// lifecycle variant fails to compile here until it is given one.
fn review_lifecycle_state_id(state: ReviewRequestLifecycle) -> &'static str {
    match state {
        ReviewRequestLifecycle::Reviewing => "reviewing",
        ReviewRequestLifecycle::Approved => "approved",
        ReviewRequestLifecycle::Rejected => "rejected",
        ReviewRequestLifecycle::ChangesRequested => "changes-requested",
        ReviewRequestLifecycle::Answered => "answered",
        ReviewRequestLifecycle::Cancelled => "cancelled",
        ReviewRequestLifecycle::Superseded => "superseded",
    }
}

const REVIEW_SETTLE_EVENT: &str = "settle";
const REVIEW_RECORD_EVENT: &str = "record-decision";
const REVIEW_ADVANCE_EVENT: &str = "advance-stage";

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
    vec![
        EnforcementLayer {id:"caller-authentication",description:"Authenticate the exact caller and Casework profile. Reviewers must be humans with the governed review scopes; producer authority never supplies reviewer authority.",events:EVERY_REVIEW_EVENT},
        EnforcementLayer {id:"producer-or-reviewer-admission",description:"Producer admission binds exact profile, issuer, subject, source namespace, and expected PolicyBinding. Human admission checks Directory membership, queue service, exclusions, and current task authority.",events:EVERY_REVIEW_EVENT},
        EnforcementLayer {id:"review-context",description:"Submitted context uses the admitted schema-valid snapshot. Current-source visibility uses only the exact human's credential; decision and service rechecks bind the exact subject and producer contract to the named purpose.",events:EVERY_REVIEW_EVENT},
        EnforcementLayer {id:"transaction",description:"Revision and idempotency fences, task ownership, and the pinned policy are checked before recording a decision. One terminal winner stores the result, receipt, and result-feed event atomically.",events:EVERY_REVIEW_EVENT},
        EnforcementLayer {id:"threshold",description:"The reducer counts independent reviewers within a stage, enforces initiator and prior-stage exclusions, advances ordered stages on quorum, and settles a configured negative outcome immediately.",events:EVERY_REVIEW_EVENT},
    ]
}

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
        "review-request",
        "Casework review request lifecycle",
        &[reviewing],
        &state_ids,
        transitions,
        review_enforcement(),
    )
}
