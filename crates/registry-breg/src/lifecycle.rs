// SPDX-License-Identifier: Apache-2.0
//! Describes the BReg change-request lifecycle as data, for `bregctl explain lifecycle`.
//!
//! The lifecycle enforced by `RequestWorkflow` (see `request_workflow.rs`) is procedural
//! code: state checks scattered across `submit`, `revise`, `rebase`, `cancel`, and `apply`.
//! This module restates that same lifecycle as a `LifecycleDescription` value so a CLI
//! command can report it without reimplementing the workflow. `terminal`, `unreachable`,
//! and the transition counts on each state are computed from the declared transition list,
//! never hand-written, so the report cannot drift from the table it is built from.

use serde::Serialize;

/// One state machine reported by `bregctl explain lifecycle`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleDescription {
    pub id: &'static str,
    pub label: &'static str,
    pub states: Vec<LifecycleState>,
    pub transitions: Vec<LifecycleTransition>,
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
    pub guard: &'static str,
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
    }
}

/// Describes the request lifecycle enforced by `RequestWorkflow`: the states in
/// `RequestState` and the transitions its `submit`, `revise`, `rebase`, `cancel`, and
/// `apply` methods run.
///
/// `cancel` refuses only `Applied` and `Cancelled` source states (it checks
/// `matches!(self.state, RequestState::Applied | RequestState::Cancelled)`), so its guard
/// also accepts a request in `Superseded`. That gives this table a seventh edge,
/// `superseded` --cancel--> `cancelled`, declared here even though no transition targets
/// `Superseded` and nothing can ever reach it. The computed `unreachable` flag on the
/// `superseded` state reports that honestly instead of hiding it.
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
                guard: "the request is submitted and unapplied at the current version; digest, fingerprint, review evidence, targets and links verify",
            },
            LifecycleTransition {
                from: "superseded",
                event: "cancel",
                to: "cancelled",
                guard: "the caller is the request owner and the request is not already applied or cancelled",
            },
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    // Edge 7, `superseded` --cancel--> `cancelled`, cannot be exercised positively: no
    // transition ever produces a `Superseded` workflow, so one cannot be constructed to
    // call `cancel` on. Instead this proves `cancel`'s guard refuses exactly the two
    // states the table does NOT declare a `cancel` edge from (`Applied` and `Cancelled`),
    // which is the shape that makes `Superseded` the one remaining state `cancel` accepts.
    #[test]
    fn cancel_guard_refuses_only_applied_and_cancelled_sources() {
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

    #[test]
    fn superseded_is_unreachable_and_non_terminal_while_applied_and_cancelled_are_terminal() {
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
        assert!(!superseded.terminal);
        assert_eq!(superseded.incoming_transitions, 0);
        assert_eq!(superseded.outgoing_transitions, 1);

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
