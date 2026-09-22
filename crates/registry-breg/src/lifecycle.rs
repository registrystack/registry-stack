// SPDX-License-Identifier: Apache-2.0
//! Describes the BReg change-request lifecycle as data, for `bregctl explain lifecycle`.
//!
//! The lifecycle enforced by `RequestWorkflow` (see `request_workflow.rs`) is procedural
//! code: state checks scattered across `submit`, `revise`, `rebase`, `cancel`, and `apply`.
//! This module restates that same lifecycle as a `LifecycleDescription` value so a CLI
//! command can report it without reimplementing the workflow. `terminal`, `unreachable`,
//! and the transition counts on each state are computed from the declared transition list,
//! never hand-written, so the report cannot drift from the table it is built from.
//!
//! Each edge's `guard` states only what the workflow method itself checks. Everything
//! the runtime checks around that call, from route admission to the row policy at
//! persist, is reported once per layer in `enforcement`, in execution order, with the
//! events each layer covers. A layer is a named place the runtime can refuse, not an
//! enumeration of every check made there: a reader learns that a request-ownership
//! layer runs before the transition for four of the five events, not the exact
//! predicate, which lives in `mutation/request.rs` and changes without notice.

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

const EVERY_EVENT: &[&str] = &["submit", "revise", "rebase", "cancel", "apply"];

/// The layers `execute_request_action` and `execute_request_action_transaction` run
/// around a workflow transition, in the order they run. The event lists are the
/// runtime's own gating: `admit_submitter_targets` is called for Submit and Revise
/// (rebase is Revise with a flag), `action_requires_request_owner` is false only for
/// Apply, and the receipt and task-status preflight runs only for Apply. The three
/// apply-only layers before the transition are the steps `apply_approved_request` runs
/// in that order before it calls `RequestWorkflow::apply`: `authorize_targets`,
/// `lock_and_verify_application_preconditions`, and the `apply_request_target` loop.
/// No other action reaches them. The two submit-only layers are the halves of
/// `plan_submission_candidate` and its re-verification: the first runs before the
/// idempotency row is locked, the second immediately before the transition, and
/// reporting them as one layer would place the planning on whichever side of the lock
/// the single layer sat.
fn request_enforcement() -> Vec<EnforcementLayer> {
    vec![
        EnforcementLayer {
            id: "route_admission",
            description: "The action arrives on a POST route the caller's access profile lists, for an entity that declares change requests, with the route's operation matching the action and the requested response fields inside the profile's readable fields. Refused as an invalid request before any row is read.",
            events: EVERY_EVENT,
        },
        EnforcementLayer {
            id: "apply_preflight",
            description: "Before the transaction opens, a retained receipt for the same idempotent apply short-circuits to replay; otherwise the caller's task grant and the task grant frozen on the proposal are each confirmed current and live by the task-status check. Runs again on each retry of the transaction.",
            events: &["apply"],
        },
        EnforcementLayer {
            id: "submit_preparation",
            description: "Inside the transaction but before the idempotency row is locked, submit plans the submission once. It is skipped outright when an unlocked probe finds a receipt for this key, so a replay never re-plans. The request row is read under the same row policy the locked read below uses, a preview action ETag recomputed from that read must equal the caller's If-Match, the acting principal must be the recorded owner, and planning then requires the request to still be in draft at both the record revision and the workflow revision it read, admits the profile's submitter targets a first time, and refuses a plan whose intake, re-derived from the row, differs by a byte from the intake the planner ran on. Every one of those conditions is checked again after the lock, so a request that moved in between is refused rather than submitted on a stale plan.",
            events: &["submit"],
        },
        EnforcementLayer {
            id: "idempotency_replay",
            description: "Inside the transaction, the idempotency row for this action's key is locked and read before the request row and workflow are read under that lock. The stored binding covers the caller's If-Match, the target authority, and the canonical body, so a key already bound to a different request is refused as a conflict here, before those reads, and so is a key whose stored result was erased, because erasure is permanent and keeps the key reserved. Submit is the exception to the reading order: an unlocked probe for this key runs first, and where it finds no receipt the preparation layer above reads the row and plans the submission before this lock is taken. A binding that matches replays the stored response once row visibility and, where they apply, submitter targets have been re-checked. That replay returns without re-running the action ETag, request ownership, the in-transaction task grant check, the workflow transition, or the persist policy.",
            events: EVERY_EVENT,
        },
        EnforcementLayer {
            id: "row_visibility",
            description: "The request row is read under the row-level SELECT policy generated for this profile and operation, which admits only an active row whose request state the operation may see (draft, submitted, cancelled, and superseded; applied as well for apply) and only within the profile's request visibility. A row the policy hides is treated as absent.",
            events: EVERY_EVENT,
        },
        EnforcementLayer {
            id: "submitter_targets",
            description: "Where the profile declares submitter targets, the caller must still hold read authority over every existing record the request's effects name. Checked against the caller's current authorization, not the authorization held when the request was created.",
            events: &["submit", "revise", "rebase"],
        },
        EnforcementLayer {
            id: "action_etag",
            description: "The caller's If-Match, which is mandatory, must equal the action ETag recomputed from the record and workflow as locked, so an action prepared against a request that has since moved is refused as a failed precondition. For submit this is the second such comparison: the preparation layer above made the first, against an unlocked read, before it planned the submission.",
            events: EVERY_EVENT,
        },
        EnforcementLayer {
            id: "request_ownership",
            description: "The acting principal must be the owner recorded on the request. Apply is exempt: its authority is a task grant, and a different actor applies.",
            events: &["submit", "revise", "rebase", "cancel"],
        },
        EnforcementLayer {
            id: "task_grant",
            description: "Inside the transaction, apply re-verifies that the caller's grant is the one the preflight checked and that both it and the proposal's grant are still current. For every other action, a caller acting under a task grant has that grant's status checked here.",
            events: EVERY_EVENT,
        },
        EnforcementLayer {
            id: "submit_commit_preconditions",
            description: "Immediately before the transition, submit re-verifies the plan it made before the lock against the values read under it: the record revision and the workflow revision must still be the ones planning read, and the submission's attachments are validated. A plan made against a request that has moved since is refused here rather than submitted.",
            events: &["submit"],
        },
        EnforcementLayer {
            id: "apply_target_authorization",
            description: "Apply authorizes the proposal's frozen targets before it writes any of them: each target the effects name is checked against the target authority the caller presented, under this caller's current authorization rather than the authorization held when the proposal was frozen.",
            events: &["apply"],
        },
        EnforcementLayer {
            id: "apply_preconditions",
            description: "The frozen application preconditions are locked and verified against the records as they stand now, so a proposal whose observed targets have moved since it was approved is refused before any target row is written.",
            events: &["apply"],
        },
        EnforcementLayer {
            id: "apply_target_persistence",
            description: "Each of the proposal's effects writes its own target row under that target's row-level policy. These are the first writes apply makes, and a row the target's policy refuses stops the apply here, before the workflow transition runs.",
            events: &["apply"],
        },
        EnforcementLayer {
            id: "workflow_transition",
            description: "The edge's own guard, run by RequestWorkflow. A refused transition is reported by its workflow error.",
            events: EVERY_EVENT,
        },
        EnforcementLayer {
            id: "persist_policy",
            description: "The request row is then UPDATEd under the row-level UPDATE policy generated for this profile and operation, which admits only the source states the operation may leave (draft for submit; submitted for revise, rebase, and apply; draft or submitted for cancel, and for cancel only when the acting principal is the recorded owner). A transition the workflow accepted from any other state writes no row and is refused as a failed precondition. This is the first write for submit, revise, rebase, and cancel; apply has already written its target rows by this point.",
            events: EVERY_EVENT,
        },
    ]
}

/// Describes the request lifecycle enforced by `RequestWorkflow`: the states in
/// `RequestState` and the transitions its `submit`, `revise`, `rebase`, `cancel`, and
/// `apply` methods run.
///
/// `superseded` is in the table as a state and in no edge. Nothing writes it: no
/// transition targets it, `initialize_draft` stores `draft`, and `save` stores the state
/// a transition reached. `cancel`'s own check would accept it as a source, since it
/// refuses only `Applied` and `Cancelled`, but the UPDATE policy generated for cancel
/// admits only `draft` and `submitted` rows, so such a cancel would write nothing and be
/// refused at persist. An edge that cannot fire from a state that cannot exist is not a
/// transition the engine runs, so the state reports as unreachable and terminal rather
/// than carrying a dead edge.
pub fn request_lifecycle() -> LifecycleDescription {
    build_lifecycle(
        "request",
        "BReg change request lifecycle",
        "draft",
        &["draft", "submitted", "cancelled", "applied", "superseded"],
        vec![
            LifecycleTransition {
                from: "draft",
                event: "submit",
                to: "submitted",
                guard: "the request is in draft and its current version has not already been frozen into a proposal",
            },
            LifecycleTransition {
                from: "submitted",
                event: "revise",
                to: "draft",
                guard: "the request is submitted; opens the next draft version tagged as a content revision, not a rebase",
            },
            LifecycleTransition {
                from: "submitted",
                event: "rebase",
                to: "draft",
                guard: "the request is submitted; opens the next draft version tagged as a rebase onto updated context, not a revision",
            },
            LifecycleTransition {
                from: "draft",
                event: "cancel",
                to: "cancelled",
                guard: "the caller is the request owner and the request is not already applied or cancelled",
            },
            LifecycleTransition {
                from: "submitted",
                event: "cancel",
                to: "cancelled",
                guard: "the caller is the request owner and the request is not already applied or cancelled",
            },
            LifecycleTransition {
                from: "submitted",
                event: "apply",
                to: "applied",
                guard: "the request is submitted and unapplied, the named proposal version is its current version, the frozen proposal's digest verifies and matches the displayed digest, the contract fingerprint matches, review evidence matches the frozen review requirement, the observed targets match the frozen targets, the application links match the frozen effects, and any application reason is well-formed",
            },
        ],
        request_enforcement(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use std::collections::BTreeSet;

    fn declared_events(lifecycle: &LifecycleDescription) -> BTreeSet<&'static str> {
        lifecycle
            .transitions
            .iter()
            .map(|edge| edge.event)
            .collect()
    }

    fn layer<'a>(lifecycle: &'a LifecycleDescription, id: &str) -> &'a EnforcementLayer {
        lifecycle
            .enforcement
            .iter()
            .find(|layer| layer.id == id)
            .unwrap_or_else(|| panic!("enforcement layer {id} declared"))
    }

    /// A guard states what `RequestWorkflow` itself checks and nothing that
    /// runs around it. The runtime layers are reported once each in
    /// `enforcement`, in order, rather than transcribed onto every edge: the
    /// earlier report did transcribe them and six review rounds each found a
    /// layer it had left out, because a per-edge sentence can only ever be an
    /// incomplete copy of the stack. A guard that names a layer's check is
    /// that copy starting again.
    #[test]
    fn guards_state_the_workflow_condition_and_restate_no_layer() {
        for edge in &request_lifecycle().transitions {
            for phrase in [
                "If-Match",
                "ETag",
                "task grant",
                "policy",
                "submitterTargets",
                "before the transaction",
            ] {
                assert!(
                    !edge.guard.contains(phrase),
                    "{edge:?} restates an enforcement layer: {phrase:?}"
                );
            }
            assert!(!edge.guard.is_empty(), "{edge:?}");
        }
    }

    /// `RequestWorkflow::cancel` is the one transition that checks the actor
    /// itself (`context.actor != self.owner` is `NotOwner`), so only the
    /// cancel guards may name the owner; the owner check on submit, revise,
    /// and rebase belongs to the mutation layer and is a reported layer.
    #[test]
    fn only_cancel_guards_name_the_owner_the_workflow_checks() {
        for edge in &request_lifecycle().transitions {
            assert_eq!(
                edge.guard.contains("owner"),
                edge.event == "cancel",
                "{edge:?}"
            );
        }
    }

    /// The layers are reported in the order the runtime runs them, with the
    /// workflow transition placed where it sits among them, and each names
    /// at least one event the table raises and no event it does not.
    #[test]
    fn enforcement_layers_are_ordered_and_name_declared_events() {
        let lifecycle = request_lifecycle();
        let ids: Vec<&str> = lifecycle.enforcement.iter().map(|layer| layer.id).collect();
        assert_eq!(
            ids,
            vec![
                "route_admission",
                "apply_preflight",
                "submit_preparation",
                "idempotency_replay",
                "row_visibility",
                "submitter_targets",
                "action_etag",
                "request_ownership",
                "task_grant",
                "submit_commit_preconditions",
                "apply_target_authorization",
                "apply_preconditions",
                "apply_target_persistence",
                "workflow_transition",
                "persist_policy",
            ]
        );
        let events = declared_events(&lifecycle);
        for layer in &lifecycle.enforcement {
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

    /// Which events a selective layer covers is what the runtime does, not a
    /// choice this module makes: `admit_submitter_targets` runs for Submit
    /// and Revise, and rebase is Revise with a flag; `action_requires_request_owner`
    /// is false only for Apply; the receipt and task-status preflight runs
    /// only for Apply. Every other layer runs for every action.
    #[test]
    fn selective_layers_cover_exactly_the_events_the_runtime_gates() {
        let lifecycle = request_lifecycle();
        for id in [
            "apply_preflight",
            "apply_target_authorization",
            "apply_preconditions",
            "apply_target_persistence",
        ] {
            assert_eq!(layer(&lifecycle, id).events, ["apply"], "{id}");
        }
        for id in ["submit_preparation", "submit_commit_preconditions"] {
            assert_eq!(layer(&lifecycle, id).events, ["submit"], "{id}");
        }
        assert_eq!(
            layer(&lifecycle, "submitter_targets").events,
            ["submit", "revise", "rebase"]
        );
        assert_eq!(
            layer(&lifecycle, "request_ownership").events,
            ["submit", "revise", "rebase", "cancel"]
        );
        for id in [
            "route_admission",
            "idempotency_replay",
            "row_visibility",
            "action_etag",
            "task_grant",
            "workflow_transition",
            "persist_policy",
        ] {
            assert_eq!(
                layer(&lifecycle, id).events,
                ["submit", "revise", "rebase", "cancel", "apply"],
                "{id}"
            );
        }
    }

    /// Submit is the one action that does work before the idempotency row is
    /// locked: it reads the row, compares a preview ETag, and plans the
    /// submission, all under no lock. That is two reported places, one on each
    /// side of the lock, and the position of each is the fact worth pinning:
    /// a preparation layer reported after the lock would claim the plan was
    /// made against the locked read, and a re-verification layer reported
    /// before the transition would hide that the plan is checked again.
    /// The preview comparison belongs to the preparation layer alone; the
    /// ETag layer describes the locked comparison and must not reabsorb it.
    #[test]
    fn the_two_submit_layers_sit_on_either_side_of_the_lock() {
        let lifecycle = request_lifecycle();
        let index = |id: &str| {
            lifecycle
                .enforcement
                .iter()
                .position(|layer| layer.id == id)
                .unwrap_or_else(|| panic!("enforcement layer {id} declared"))
        };
        assert!(index("submit_preparation") < index("idempotency_replay"));
        assert!(index("submit_commit_preconditions") > index("task_grant"));
        assert!(index("submit_commit_preconditions") < index("workflow_transition"));
        assert!(
            !layer(&lifecycle, "action_etag")
                .description
                .contains("preview"),
            "the preview comparison belongs to submit_preparation"
        );
        assert!(
            layer(&lifecycle, "submit_preparation")
                .description
                .contains("preview"),
            "submit_preparation stopped naming the preview comparison"
        );
    }

    /// The replay layer's value is the list of layers it skips, so the layers it
    /// names must still be layers this report declares. A rename that leaves the
    /// prose behind would otherwise ship a skip-set naming nothing.
    #[test]
    fn the_replay_layer_names_layers_this_report_still_declares() {
        let lifecycle = request_lifecycle();
        let replay = layer(&lifecycle, "idempotency_replay").description;
        let ids: BTreeSet<&str> = lifecycle.enforcement.iter().map(|layer| layer.id).collect();
        let skipped = [
            ("action_etag", "the action ETag"),
            ("request_ownership", "request ownership"),
            ("task_grant", "the in-transaction task grant check"),
            ("workflow_transition", "the workflow transition"),
            ("persist_policy", "the persist policy"),
        ];
        let replay_index = lifecycle
            .enforcement
            .iter()
            .position(|layer| layer.id == "idempotency_replay")
            .expect("replay layer");
        for (id, prose) in skipped {
            assert!(ids.contains(id), "{id} is no longer declared");
            assert!(
                replay.contains(prose),
                "the replay layer stopped naming {id}"
            );
            let index = lifecycle
                .enforcement
                .iter()
                .position(|layer| layer.id == id)
                .expect("declared layer");
            // A skipped layer is reported after the replay, which is what makes
            // the skip an ordering fact rather than a claim.
            assert!(index > replay_index, "{id} is not after the replay layer");
        }
    }

    /// The persist layer is what makes `superseded` a dead source state: the
    /// UPDATE policy generated for cancel admits only draft and submitted
    /// rows, so a cancel the workflow accepted from `superseded` writes no
    /// row and is refused. The table declares no such edge, and this pins the
    /// policy the omission rests on.
    #[test]
    fn the_cancel_update_policy_admits_no_superseded_row() {
        use crate::contract::Operation;
        use crate::generated_ddl::{change_request_action_state_exists_expression, PolicyCommand};

        let cancel = change_request_action_state_exists_expression(
            Operation::CancelRequest,
            PolicyCommand::Update,
        );
        assert!(cancel.contains("'draft', 'submitted'"), "{cancel}");
        assert!(!cancel.contains("superseded"), "{cancel}");
    }

    use registry_platform_canonical_json::canonicalize_json;

    use crate::contract::Operation;
    use crate::model::{CompiledChangeRequestNoReview, CompiledChangeRequestNoReviewMode};
    use crate::request_workflow::{
        ApplicationId, ApplicationResultLink, ContractFingerprint, DraftStartReason, EffectId,
        EntityId, FieldId, FieldValue, FrozenPlannerKind, FrozenPlanningBinding,
        FrozenReviewRequirement, ObservedTarget, PackageFingerprint, PreparedApplication,
        PreparedEffect, PreparedFieldChange, PreparedProposal, PreparedTarget, ProposalVersion,
        RecordId, RecordRevision, RequestKey, RequestState, RequestWorkflow, StateRevision,
        TransitionEffect, TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
        WorkflowError,
    };

    const OWNER: &str = "submitter";

    fn entity(value: &str) -> EntityId {
        EntityId::new(value).expect("entity id")
    }

    fn record(value: &str) -> RecordId {
        RecordId::new(value).expect("record id")
    }

    fn revision(value: i64) -> RecordRevision {
        RecordRevision::new(value).expect("record revision")
    }

    fn context(actor: &str, timestamp: &str) -> TrustedTransitionContext {
        TrustedTransitionContext::from_verified_context(
            TrustedActorRef::from_verified_context(actor).expect("actor"),
            TrustedTimestamp::from_server_clock(timestamp).expect("timestamp"),
        )
    }

    fn draft_workflow() -> RequestWorkflow {
        RequestWorkflow::new_draft(
            RequestKey::new(entity("placement-correction-request"), record("request-1")),
            TrustedActorRef::from_verified_context(OWNER).expect("owner"),
            StateRevision::new(1).expect("state revision"),
        )
    }

    fn no_review() -> FrozenReviewRequirement {
        FrozenReviewRequirement::None(CompiledChangeRequestNoReview {
            mode: CompiledChangeRequestNoReviewMode::None,
        })
    }

    fn proposal() -> PreparedProposal {
        let effect = PreparedEffect::new(
            EffectId::new("patch-placement").expect("effect id"),
            Operation::Patch,
            PreparedTarget::existing(
                entity("asset-placement"),
                record("placement-1"),
                revision(3),
            ),
            vec![PreparedFieldChange::set(
                FieldId::new("site").expect("field id"),
                FieldValue::present(json!("site-a")),
                json!("site-b"),
            )
            .expect("field change")],
        )
        .expect("effect");
        let snapshot_bytes = canonicalize_json(
            &serde_json::to_value(std::slice::from_ref(&effect)).expect("effect serializes"),
        )
        .expect("effect canonicalizes")
        .len();
        PreparedProposal::new_with_binding(
            revision(7),
            ContractFingerprint::new("sha256:contract").expect("contract fingerprint"),
            PackageFingerprint::new("sha256:package").expect("package fingerprint"),
            no_review(),
            FrozenPlanningBinding::new(
                FrozenPlannerKind::Declarative,
                "registry.change-request-plan/v1",
                None,
            )
            .expect("planning binding"),
            vec![effect],
            snapshot_bytes,
        )
        .expect("proposal")
    }

    fn application() -> PreparedApplication {
        PreparedApplication::new(
            ApplicationId::new("application-1").expect("application id"),
            vec![ApplicationResultLink::new(
                entity("asset-placement"),
                record("placement-1"),
                revision(4),
            )],
        )
        .expect("application")
    }

    fn observed_targets() -> Vec<ObservedTarget> {
        vec![ObservedTarget::existing(
            entity("asset-placement"),
            record("placement-1"),
            revision(3),
        )]
    }

    fn submitted_workflow() -> RequestWorkflow {
        draft_workflow()
            .submit(context(OWNER, "2026-09-19T00:00:00Z"), proposal())
            .expect("submit")
            .into_workflow()
    }

    fn applied_workflow() -> RequestWorkflow {
        let submitted = submitted_workflow();
        let frozen = submitted.current_proposal().expect("frozen proposal");
        let digest = frozen.effect_digest().clone();
        let contract = frozen.contract_fingerprint().clone();
        submitted
            .apply(
                context("applier", "2026-09-19T00:02:00Z"),
                ProposalVersion::first(),
                &digest,
                &contract,
                None,
                observed_targets(),
                application(),
                None,
            )
            .expect("apply")
            .into_workflow()
    }

    // Edge 1: draft --submit--> submitted.
    #[test]
    fn submit_transitions_draft_to_submitted() {
        let result = draft_workflow()
            .submit(context(OWNER, "2026-09-19T00:00:00Z"), proposal())
            .expect("submit")
            .into_workflow();
        assert_eq!(result.state(), RequestState::Submitted);
    }

    // Edge 2: submitted --revise--> draft, tagged as a revision.
    #[test]
    fn revise_transitions_submitted_to_draft() {
        let transition = submitted_workflow()
            .revise(context(OWNER, "2026-09-19T00:03:00Z"))
            .expect("revise");
        assert!(matches!(
            transition.effect(),
            TransitionEffect::DraftVersionStarted {
                reason: DraftStartReason::Revision,
                ..
            }
        ));
        assert_eq!(transition.into_workflow().state(), RequestState::Draft);
    }

    // Edge 3: submitted --rebase--> draft, tagged as a rebase. Same from/to pair as
    // revise; the `DraftStartReason` on the emitted effect is what distinguishes them.
    #[test]
    fn rebase_transitions_submitted_to_draft() {
        let transition = submitted_workflow()
            .rebase(context(OWNER, "2026-09-19T00:03:00Z"))
            .expect("rebase");
        assert!(matches!(
            transition.effect(),
            TransitionEffect::DraftVersionStarted {
                reason: DraftStartReason::Rebase,
                ..
            }
        ));
        assert_eq!(transition.into_workflow().state(), RequestState::Draft);
    }

    // Edge 4: draft --cancel--> cancelled.
    #[test]
    fn cancel_transitions_draft_to_cancelled() {
        let result = draft_workflow()
            .cancel(context(OWNER, "2026-09-19T00:01:00Z"))
            .expect("cancel")
            .into_workflow();
        assert_eq!(result.state(), RequestState::Cancelled);
    }

    // Edge 5: submitted --cancel--> cancelled.
    #[test]
    fn cancel_transitions_submitted_to_cancelled() {
        let result = submitted_workflow()
            .cancel(context(OWNER, "2026-09-19T00:01:00Z"))
            .expect("cancel")
            .into_workflow();
        assert_eq!(result.state(), RequestState::Cancelled);
    }

    // Edge 6: submitted --apply--> applied.
    #[test]
    fn apply_transitions_submitted_to_applied() {
        assert_eq!(applied_workflow().state(), RequestState::Applied);
    }

    // `cancel`'s own check refuses exactly `Applied` and `Cancelled`, the two states the
    // table declares no `cancel` edge from. It would also accept `Superseded`, which the
    // table does not declare either: no transition produces a `Superseded` workflow, so
    // none can be constructed to call `cancel` on, and the persist layer refuses the write
    // regardless (see `the_cancel_update_policy_admits_no_superseded_row`).
    #[test]
    fn cancel_refuses_applied_and_cancelled_sources() {
        let applied = applied_workflow();
        assert_eq!(
            applied.cancel(context(OWNER, "2026-09-19T00:04:00Z")),
            Err(WorkflowError::InvalidTransition)
        );

        let cancelled = draft_workflow()
            .cancel(context(OWNER, "2026-09-19T00:01:00Z"))
            .expect("cancel")
            .into_workflow();
        assert_eq!(
            cancelled.cancel(context(OWNER, "2026-09-19T00:04:00Z")),
            Err(WorkflowError::InvalidTransition)
        );
    }

    // Matching exhaustively over `RequestState` means adding a variant without updating
    // this test fails to compile, forcing the table in `request_lifecycle` to be revisited.
    #[test]
    fn every_request_state_variant_is_declared_in_the_table() {
        fn storage_id(state: RequestState) -> &'static str {
            match state {
                RequestState::Draft => "draft",
                RequestState::Submitted => "submitted",
                RequestState::Cancelled => "cancelled",
                RequestState::Applied => "applied",
                RequestState::Superseded => "superseded",
            }
        }
        let declared: Vec<&str> = [
            RequestState::Draft,
            RequestState::Submitted,
            RequestState::Cancelled,
            RequestState::Applied,
            RequestState::Superseded,
        ]
        .into_iter()
        .map(storage_id)
        .collect();
        let table: Vec<&str> = request_lifecycle()
            .states
            .iter()
            .map(|state| state.id)
            .collect();
        assert_eq!(table, declared);
    }

    /// `superseded` is stored and matched but never written by any transition
    /// and never accepted as a source by the persist layer, so the table
    /// declares no edge touching it and it reports as both unreachable and
    /// terminal.
    #[test]
    fn superseded_is_unreachable_and_terminal_and_applied_and_cancelled_are_terminal() {
        let lifecycle = request_lifecycle();
        let state = |id: &str| {
            lifecycle
                .states
                .iter()
                .find(|state| state.id == id)
                .unwrap_or_else(|| panic!("state {id} declared"))
        };

        let superseded = state("superseded");
        assert!(superseded.unreachable);
        assert!(superseded.terminal);
        assert_eq!(superseded.incoming_transitions, 0);
        assert_eq!(superseded.outgoing_transitions, 0);
        assert_eq!(lifecycle.transitions.len(), 6);

        assert!(state("applied").terminal);
        assert!(state("cancelled").terminal);
    }

    #[test]
    fn submitted_and_draft_transition_counts_match_the_table() {
        let lifecycle = request_lifecycle();
        let state = |id: &str| {
            lifecycle
                .states
                .iter()
                .find(|state| state.id == id)
                .unwrap_or_else(|| panic!("state {id} declared"))
        };

        let submitted = state("submitted");
        assert_eq!(submitted.incoming_transitions, 1);
        assert_eq!(submitted.outgoing_transitions, 4);

        let draft = state("draft");
        assert_eq!(draft.incoming_transitions, 2);
        assert_eq!(draft.outgoing_transitions, 2);
    }
}
