// SPDX-License-Identifier: Apache-2.0

use super::*;

use registry_platform_hooks::{
    Causation, EnvelopeLimits, HandlerOutputLimits, HookEnvelope, HookMessage,
};

use crate::action_evidence::FrozenEvidenceEvaluation;
use crate::action_evidence_client::EvidenceSubjects;
use crate::action_evidence_contracts::CompiledEvidenceCapability;
use crate::action_handler::{evaluate_admitted_action_detailed, ActionHandlerOutcome};
use crate::action_outcome::{
    bound_document, decode_document, json_document, validate_proposed_outcome,
};
use crate::api::{ActionTargetConditionsInput, HeldReadResponse, ImmediateActionInput};

type ActionInputs = Map<String, Value>;

/// The budget one hook-proposal application runs under. The delivery-scoped
/// advisory lock keeps an expired-lease retry serialized even if finalization
/// does not complete inside the original lease.
const HOOK_PROPOSAL_APPLY_BUDGET: Duration = Duration::from_secs(5);

/// One accepted hook proposal the delivery worker settled, ready for the
/// same mutation path an action handler's outcome takes. Every field is
/// identity and the exact bytes the delivery row records.
pub(crate) struct HookChangeApplication<'a> {
    pub(crate) event_id: Uuid,
    pub(crate) compiled_delivery_id: &'a str,
    pub(crate) generation: i64,
    pub(crate) attempt: i16,
    pub(crate) lease_token: Uuid,
    pub(crate) package_revision: &'a str,
    pub(crate) envelope: &'a [u8],
    pub(crate) answer: &'a [u8],
    pub(crate) answer_digest: &'a [u8; 32],
}

/// What became of one hook proposal the mutation path was asked to apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HookChangeOutcome {
    /// The proposal applied; the revision the applied mutation produced.
    Applied(i64),
    /// Deterministically refused: retrying the same answer cannot apply it,
    /// and the delivery row still completes as delivered.
    Refused { code: &'static str, summary: String },
    /// The proposal can never be applied under this deployment; the delivery
    /// row dead-letters with this reason.
    DeadLettered { code: &'static str, summary: String },
}

/// The apply may or may not have committed. The caller fails closed: the
/// delivery row keeps its lease and expiry recovery retries, and the
/// idempotent replay of the same application resolves it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UncertainApply;

struct ActionEffectResult {
    effect_id: String,
    entity_id: String,
    record_id: String,
    record_uuid: Uuid,
    record_revision: i64,
    record_reference: String,
    operation: Operation,
}

struct HookChangeReceipt {
    answer_digest: Option<[u8; 32]>,
    resulting_revision: i64,
}

impl MutationTransaction {
    /// Acquire the session lock that serializes every classification for one
    /// hook delivery. The immediate-action transaction takes the same lock at
    /// transaction scope, so a recovery cannot observe the receipt until an
    /// in-flight application has committed or rolled back.
    ///
    /// The caller must release the lock before returning the pooled
    /// connection. If its future is cancelled while holding the lock, it must
    /// discard the connection so PostgreSQL closes the session and releases
    /// the lock.
    pub(crate) fn hook_change_key_reference(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
    ) -> Result<String, UncertainApply> {
        let idempotency_key = hook_change_idempotency_key(event_id, compiled_delivery_id);
        resolve_hook_key_reference(compiled_delivery_id, &idempotency_key)
            .map_err(|_| UncertainApply)
    }

    pub(crate) async fn acquire_hook_change_lock(
        &self,
        client: &Client,
        key_reference: &str,
    ) -> Result<(), UncertainApply> {
        // Match the transaction-side lock order: activation before the
        // delivery key. Hold activation stable through receipt lookup and
        // application, including the mutation's separate transactions.
        // This lock starts after the handler answers, never during egress.
        tokio::time::timeout(self.lock_timeout, async {
            client
                .query_one(
                    "SELECT pg_advisory_lock_shared($1)",
                    &[&self.lock_key.get()],
                )
                .await?;
            client
                .query_one(
                    "SELECT pg_advisory_lock(pg_catalog.hashtextextended($1, 0))",
                    &[&key_reference],
                )
                .await
        })
        .await
        .map_err(|_| UncertainApply)?
        .map_err(|_| UncertainApply)?;
        Ok(())
    }

    /// Acquire the delivery-scoped proposal lock on a transaction the caller
    /// already owns. The transaction-scoped form lets lease reaping serialize
    /// with an in-flight application without checking out a second pooled
    /// connection while its delivery row is locked.
    pub(crate) async fn acquire_hook_change_transaction_lock(
        &self,
        transaction: &Transaction<'_>,
        key_reference: &str,
    ) -> Result<(), UncertainApply> {
        tokio::time::timeout(
            self.lock_timeout,
            transaction.query_one(
                "SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))",
                &[&key_reference],
            ),
        )
        .await
        .map_err(|_| UncertainApply)?
        .map_err(|_| UncertainApply)?;
        Ok(())
    }

    /// Release a lock acquired by [`Self::acquire_hook_change_lock`].
    pub(crate) async fn release_hook_change_lock(
        &self,
        client: &Client,
        key_reference: &str,
    ) -> Result<(), UncertainApply> {
        let released = client
            .query_one(
                "SELECT pg_advisory_unlock(pg_catalog.hashtextextended($1, 0))",
                &[&key_reference],
            )
            .await
            .map_err(|_| UncertainApply)?
            .get::<_, bool>(0);
        let activation_released = client
            .query_one(
                "SELECT pg_advisory_unlock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| UncertainApply)?
            .get::<_, bool>(0);
        if released && activation_released {
            Ok(())
        } else {
            Err(UncertainApply)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_immediate_action(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: ImmediateActionInput<'_>,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        fault: FaultControl,
        deadline: tokio::time::Instant,
    ) -> Result<MutationOutcome, MutationError> {
        if !profile_is_keyed(self.audit.profile()) {
            return Err(MutationError::Unavailable);
        }
        let action = action_for_route(
            registry,
            input.action_id,
            input.route_id,
            ActionRouteKind::Invoke,
        )?;
        validate_action_claims(action, claims, Operation::Invoke)?;
        let normalized_input = validate_action_input(action, input.input)?;
        validate_precondition_set(action, &input.preconditions)?;
        let _attempt = self
            .begin_action_boundary_audit(claims, input.route_id, input.correlation)
            .await?;
        let request_digest =
            canonical_action_request_digest(action, &normalized_input, &input.preconditions)?;
        let binding = resolve_action_binding(
            self.audit.profile(),
            &self.idempotency,
            &ActionIdempotencyBinding {
                key: input.idempotency_key,
                context: claims,
                method: HttpMethod::Post,
                route: &action.route,
                package_revision: &self.expected.activation_id,
                action_contract_fingerprint: &action.definition_revision,
                target_authority,
                result_effects: claims.result_effects(),
                answer_digest: None,
                canonical_request_digest: request_digest,
            },
        )?;
        let reserved_creates = reserve_action_create_ids(action)?;
        let mut candidate = None;
        let application_id = Uuid::new_v4();
        let mut retryable_attempts = 0;
        let result = loop {
            let attempt = self
                .execute_immediate_action_after_attempt(
                    client,
                    registry,
                    action,
                    claims,
                    target_authority,
                    &normalized_input,
                    &input.preconditions,
                    &binding,
                    &reserved_creates,
                    application_id,
                    input.route_id,
                    input.correlation,
                    fault,
                    deadline,
                    &mut candidate,
                    None,
                    None,
                    None,
                )
                .await;
            if matches!(attempt, Err(MutationError::RetryableConflict))
                && retryable_attempts < 2
                && !fault.is_enabled()
            {
                retryable_attempts += 1;
                continue;
            }
            break attempt;
        };
        if failure_is_refusal(&result) && !fault.is_enabled() {
            self.record_action_boundary_audit(
                claims,
                input.route_id,
                input.correlation,
                PreIoAuditKind::Refusal,
            )
            .await?;
        }
        result.map_err(|error| match error {
            MutationError::RetryableConflict | MutationError::CommitUnresolved => {
                MutationError::Unavailable
            }
            other => other,
        })
    }

    /// Apply one settled hook proposal through the immediate-action path.
    ///
    /// The proposal runs the same validation, authorization, and mutation
    /// machinery an action handler's outcome runs: the proposed outcome is
    /// decoded and validated through [`validate_proposed_outcome`], the
    /// declared principal selects the action grant the proposal is applied
    /// under, and the mutation itself commits in this method's own fresh
    /// transactions, never inside the delivery worker's claim, material, or
    /// finalize transactions.
    ///
    /// The applied mutation's own events are children of the delivered
    /// event: the child causation is computed before any transaction opens,
    /// and a chain whose next hop would exceed the platform causation
    /// ceiling is refused here, before anything is enqueued, so the refusal
    /// is a dead letter the row keeps its payload for.
    ///
    /// Idempotency is the immediate-action receipt under a key derived from
    /// the hook delivery identity (event id and compiled delivery id,
    /// domain-separated). The key is stable across attempts, replay
    /// generations, and answer changes, so one delivery is one application;
    /// the digest of exactly the answer bytes rides in the binding reference
    /// instead, so a redelivered answer resolves through receipt recovery as
    /// a replay of the same application, while a changed answer after the
    /// commit surfaces as a stable dead-letter conflict.
    pub(crate) async fn apply_hook_change(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        application: &HookChangeApplication<'_>,
    ) -> Result<HookChangeOutcome, UncertainApply> {
        let idempotency_key =
            hook_change_idempotency_key(application.event_id, application.compiled_delivery_id);
        let receipt = self
            .hook_change_receipt(
                &***client,
                application.compiled_delivery_id,
                &idempotency_key,
            )
            .await?;
        if let Some(receipt) = &receipt {
            if let Some(answer_digest) = receipt.answer_digest {
                return if answer_digest == *application.answer_digest {
                    Ok(HookChangeOutcome::Applied(receipt.resulting_revision))
                } else {
                    conflicting_hook_answer()
                };
            }
        }
        if receipt.is_none()
            && !self
                .hook_change_still_owns_delivery(&***client, application)
                .await?
        {
            return Err(UncertainApply);
        }
        let outcome = self
            .apply_hook_change_inner(client, registry, application, &idempotency_key)
            .await;
        if receipt.is_some()
            && matches!(
                &outcome,
                Ok(HookChangeOutcome::Refused { .. } | HookChangeOutcome::DeadLettered { .. })
            )
        {
            return conflicting_hook_answer();
        }
        outcome
    }

    /// Confirm that the worker still owns the delivery lease before a new
    /// proposal mutation starts. Receipt replays do not need a live lease:
    /// they return an already committed result and cannot create new state.
    async fn hook_change_still_owns_delivery(
        &self,
        client: &(impl tokio_postgres::GenericClient + Sync),
        application: &HookChangeApplication<'_>,
    ) -> Result<bool, UncertainApply> {
        client
            .query_one(
                "SELECT EXISTS (
                     SELECT 1
                       FROM registry_internal.registry_webhook_delivery_state
                      WHERE event_id = $1
                        AND compiled_delivery_id = $2
                        AND generation = $3
                        AND attempt = $4
                        AND lease_token = $5
                        AND state = 'leased'
                 )",
                &[
                    &application.event_id,
                    &application.compiled_delivery_id,
                    &application.generation,
                    &application.attempt,
                    &application.lease_token,
                ],
            )
            .await
            .map_err(|_| UncertainApply)
            .map(|row| row.get(0))
    }

    /// Recover a proposal receipt when a later accepted answer proposes
    /// nothing. A receipt under the delivery-scoped key proves the earlier
    /// proposal committed, so the changed answer becomes the same stable
    /// conflict as a changed proposal instead of overwriting the row's
    /// disposition with `none`.
    pub(crate) async fn recover_hook_change_receipt(
        &self,
        client: &(impl tokio_postgres::GenericClient + Sync),
        event_id: Uuid,
        compiled_delivery_id: &str,
    ) -> Result<Option<HookChangeOutcome>, UncertainApply> {
        let idempotency_key = hook_change_idempotency_key(event_id, compiled_delivery_id);
        if self
            .hook_change_receipt(client, compiled_delivery_id, &idempotency_key)
            .await?
            .is_some()
        {
            conflicting_hook_answer().map(Some)
        } else {
            Ok(None)
        }
    }

    async fn hook_change_receipt(
        &self,
        client: &(impl tokio_postgres::GenericClient + Sync),
        compiled_delivery_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<HookChangeReceipt>, UncertainApply> {
        let key_reference = resolve_hook_key_reference(compiled_delivery_id, idempotency_key)
            .map_err(|_| UncertainApply)?;
        client
            .query_opt(
                "SELECT application.handler_answer_digest,
                        (SELECT result.target_record_revision
                           FROM registry_internal.registry_immediate_action_results AS result
                          WHERE result.key_reference = application.key_reference
                          ORDER BY result.effect_id COLLATE \"C\"
                          LIMIT 1)
                   FROM registry_internal.registry_immediate_action_applications AS application
                  WHERE application.key_reference = $1",
                &[&key_reference],
            )
            .await
            .map_err(|_| UncertainApply)?
            .map(|row| -> Result<HookChangeReceipt, UncertainApply> {
                let answer_digest = row
                    .get::<_, Option<Vec<u8>>>(0)
                    .map(|digest| digest.try_into().map_err(|_| UncertainApply))
                    .transpose()?;
                let resulting_revision = row
                    .get::<_, Option<i64>>(1)
                    .filter(|revision| *revision > 0)
                    .ok_or(UncertainApply)?;
                Ok(HookChangeReceipt {
                    answer_digest,
                    resulting_revision,
                })
            })
            .transpose()
    }

    async fn apply_hook_change_inner(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        application: &HookChangeApplication<'_>,
        idempotency_key: &str,
    ) -> Result<HookChangeOutcome, UncertainApply> {
        // The worker may have sent before activation and received its
        // answer afterward. Classify against the live ready activation,
        // held stable by the shared activation lock, not the worker's pin.
        // Receipt recovery already returned above; a failed state read is
        // uncertainty, never proof of a terminal package refusal.
        let active_activation_id: String = client
            .query_opt(
                "SELECT active_activation_id::text
                   FROM registry_internal.registry_state
                  WHERE singleton AND package_id = $1 AND database_id = $2
                    AND maintenance_status = 'ready'",
                &[&self.expected.package_id, &self.expected.database_id],
            )
            .await
            .map_err(|_| UncertainApply)?
            .ok_or(UncertainApply)?
            .try_get(0)
            .map_err(|_| UncertainApply)?;
        if application.package_revision != active_activation_id {
            return dead_lettered_proposal(
                "hook.proposal.package_unavailable",
                format!(
                    "The delivery was captured under activation {}, replaced by active activation {}. Derive a new change from a fresh event; this answer cannot be replayed.",
                    application.package_revision, active_activation_id,
                ),
            );
        }
        if application.package_revision != self.expected.activation_id {
            return Err(UncertainApply);
        }

        // The envelope the worker delivered, re-read from the exact stored
        // bytes so the chain position comes from what was delivered, not
        // from anything reconstructed.
        let Ok(envelope) =
            HookEnvelope::from_canonical_bytes(application.envelope, &EnvelopeLimits::default())
        else {
            return dead_lettered_proposal(
                "hook.proposal.envelope_refused",
                "The delivered envelope bytes could not be re-read as an envelope.",
            );
        };
        // Proposal lifecycle observers are permanently notification-only.
        // The delivered fixed contract also fences a forged compiled owner or
        // principal before any callback candidate can resolve an Action grant.
        if envelope.dataschema == crate::proposal_hooks::PROPOSAL_EVENT_SCHEMA
            || registry
                .event_deliveries()
                .deliveries
                .iter()
                .any(|delivery| {
                    delivery.id == application.compiled_delivery_id
                        && matches!(
                            delivery.owner,
                            crate::model::CompiledEventOwner::ProposalAction { .. }
                        )
                })
        {
            return dead_lettered_proposal(
                "hook.proposal.observer_only",
                "A Proposal lifecycle observer carries no callback application authority.",
            );
        }
        let Ok(message) =
            HookMessage::from_canonical_json(application.answer, &HandlerOutputLimits::default())
        else {
            return dead_lettered_proposal(
                "hook.proposal.answer_refused",
                "The settled answer bytes could not be re-read as a handler message.",
            );
        };
        let HookMessage::Proposal { document } = message else {
            return dead_lettered_proposal(
                "hook.proposal.answer_refused",
                "The settled answer does not carry a proposal.",
            );
        };

        // The proposal document: exact members, with the action, the input
        // values, the proposed outcome, and optional existing-target
        // preconditions.
        let Value::Object(members) = &document.0 else {
            return refused_proposal(
                "hook.proposal.document_refused",
                "Return the proposal document as a JSON object.",
            );
        };
        if members.keys().any(|key| {
            !matches!(
                key.as_str(),
                "action" | "input" | "outcome" | "preconditions"
            )
        }) {
            return refused_proposal(
                "hook.proposal.document_refused",
                "The proposal document may contain only action, input, outcome, and preconditions.",
            );
        }
        let Some(action_id) = members
            .get("action")
            .and_then(Value::as_str)
            .filter(|action_id| !action_id.is_empty())
        else {
            return refused_proposal(
                "hook.proposal.document_refused",
                "Name the proposed action as a non-empty string.",
            );
        };
        let Some(input_values) = members.get("input").and_then(Value::as_object) else {
            return refused_proposal(
                "hook.proposal.document_refused",
                "Carry the proposal input as a JSON object.",
            );
        };
        let input_values = input_values.clone();
        let Some(outcome_value) = members.get("outcome") else {
            return refused_proposal(
                "hook.proposal.document_refused",
                "Carry the proposed outcome under outcome.",
            );
        };
        let mut preconditions = BTreeMap::<String, String>::new();
        match members.get("preconditions") {
            None | Some(Value::Null) => {}
            Some(Value::Object(entries)) => {
                for (input_id, value) in entries {
                    let Some(record_id) = value.as_str().filter(|id| !id.is_empty()) else {
                        return refused_proposal(
                            "hook.proposal.document_refused",
                            "Carry each precondition as the target record id string.",
                        );
                    };
                    preconditions.insert(input_id.clone(), record_id.to_owned());
                }
            }
            Some(_) => {
                return refused_proposal(
                    "hook.proposal.document_refused",
                    "Carry the proposal preconditions as a JSON object.",
                );
            }
        }

        let Some(delivery) = registry
            .event_deliveries()
            .deliveries
            .iter()
            .find(|delivery| delivery.id == application.compiled_delivery_id)
        else {
            return dead_lettered_proposal(
                "hook.proposal.package_unavailable",
                "The compiled package declares no delivery under this binding.",
            );
        };

        // The principal a proposal from this hook is applied under. A hook
        // that declared none is a deployment defect a proposal exposes: the
        // proposal can never name an authority, so it dead-letters.
        let Some(principal) = delivery.principal.as_deref() else {
            return dead_lettered_proposal(
                "hook.proposal.no_principal",
                "The hook declares no principal, so its proposal names no authority to apply under.",
            );
        };

        let Some(action) = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == action_id)
        else {
            return refused_proposal(
                "hook.proposal.action_not_found",
                "The proposal names an action the compiled package does not declare.",
            );
        };
        let Some(handler) = action.handler.as_ref() else {
            return refused_proposal(
                "hook.proposal.action_without_handler",
                "The proposal names an action that declares no reviewed handler.",
            );
        };
        let Some(grant) = action
            .permissions
            .iter()
            .find(|grant| grant.profile_id == principal)
        else {
            return refused_proposal(
                "hook.proposal.unauthorized",
                "The declared principal holds no permission on the proposed action.",
            );
        };
        if !grant.operations.contains(&Operation::Invoke) {
            return refused_proposal(
                "hook.proposal.unauthorized",
                "The declared principal may not invoke the proposed action.",
            );
        }
        if grant.results.is_empty() {
            return refused_proposal(
                "hook.proposal.no_visible_results",
                "The declared principal's grant declares no result effects, so nothing could be recorded.",
            );
        }
        let Ok(claims) = ActionClaimContext::new(
            action.id.clone(),
            format!("hook:{principal}"),
            principal.to_owned(),
            None,
            grant.results.clone(),
        ) else {
            return refused_proposal(
                "hook.proposal.unauthorized",
                "The declared principal does not form a bounded authority context.",
            );
        };
        // A hook holds no claims, so a grant that row-boundaries its targets
        // can never be satisfied by this path and is refused outright.
        let mut target_authority = BTreeMap::<String, Vec<RowBoundaryContext>>::new();
        for target in grant.entity_target_locks() {
            if target.row_boundaries.is_empty() {
                target_authority.insert(target.entity_id.clone(), Vec::new());
            } else {
                return refused_proposal(
                    "hook.proposal.boundaries_unsatisfiable",
                    "The declared principal's grant carries row boundaries a hook holds no claims to satisfy.",
                );
            }
        }
        if validate_action_claims(action, &claims, Operation::Invoke).is_err() {
            return refused_proposal(
                "hook.proposal.unauthorized",
                "The declared principal's grant does not authorize this invocation.",
            );
        }
        let Ok(normalized_input) = validate_action_input(action, input_values) else {
            return refused_proposal(
                "hook.proposal.input_refused",
                "The proposal input does not satisfy the action's declared inputs.",
            );
        };
        if validate_precondition_set(action, &preconditions).is_err() {
            return refused_proposal(
                "hook.proposal.precondition_refused",
                "The proposal preconditions do not match the action's existing-target inputs.",
            );
        }

        // The proposed outcome runs the exact validation an action handler's
        // returned outcome runs, against the same declared write slots.
        let outcome_document = json_document(outcome_value.clone());
        if bound_document(&outcome_document, action.maximum_snapshot_bytes).is_err() {
            return refused_proposal(
                "hook.proposal.outcome_refused",
                "The proposed outcome exceeds the action's snapshot bound.",
            );
        }
        let proposed = match decode_document(outcome_document) {
            Ok(proposed) => proposed,
            Err(_) => {
                return refused_proposal(
                    "hook.proposal.outcome_refused",
                    "The proposed outcome is not a valid effects or refusal document.",
                );
            }
        };
        let outcome_effects = match validate_proposed_outcome(action, handler, proposed) {
            Ok(ActionHandlerOutcome::Effects(effects)) => effects,
            Ok(ActionHandlerOutcome::Refusal(refusal)) => {
                return refused_proposal(
                    "hook.proposal.handler_refusal",
                    format!(
                        "The proposed outcome refused the action with the declared refusal {}.",
                        refusal.code
                    ),
                );
            }
            Err(diagnostic) => {
                return refused_proposal("hook.proposal.outcome_refused", diagnostic.message);
            }
        };

        // The child causation is computed before any transaction opens, so a
        // refused chain never enqueues anything and the dead letter keeps
        // its payload.
        let causation = match envelope.causation.child(&envelope.id) {
            Ok(causation) => causation,
            Err(error) => {
                return dead_lettered_proposal(
                    "hook.causation.hop_beyond_ceiling",
                    error.to_string(),
                );
            }
        };

        let Ok(request_digest) =
            canonical_action_request_digest(action, &normalized_input, &preconditions)
        else {
            return refused_proposal(
                "hook.proposal.input_refused",
                "The proposal input could not be canonicalized for idempotency.",
            );
        };
        let binding = match resolve_hook_action_binding(
            self.audit.profile(),
            &self.idempotency,
            application.compiled_delivery_id,
            &ActionIdempotencyBinding {
                key: idempotency_key,
                context: &claims,
                method: HttpMethod::Post,
                route: &action.route,
                package_revision: &self.expected.activation_id,
                action_contract_fingerprint: &action.definition_revision,
                target_authority: &target_authority,
                result_effects: claims.result_effects(),
                answer_digest: Some(application.answer_digest),
                canonical_request_digest: request_digest,
            },
        ) {
            Ok(binding) => binding,
            Err(_) => {
                return dead_lettered_proposal(
                    "hook.proposal.binding_refused",
                    "The proposal's idempotency binding could not be resolved.",
                );
            }
        };
        let Ok(reserved_creates) = reserve_action_create_ids(action) else {
            return Err(UncertainApply);
        };
        let Some(route_id) = registry
            .actions()
            .routes
            .iter()
            .find(|route| route.action_id == action.id && route.kind == ActionRouteKind::Invoke)
            .map(|route| route.id.clone())
        else {
            return refused_proposal(
                "hook.proposal.action_not_found",
                "The proposed action declares no invoke route.",
            );
        };
        let application_id = Uuid::new_v4();
        let correlation = RequestCorrelation::breg_created();
        let _attempt = self
            .begin_action_boundary_audit(&claims, &route_id, &correlation)
            .await
            .map_err(|_| UncertainApply)?;

        let deadline = tokio::time::Instant::now() + HOOK_PROPOSAL_APPLY_BUDGET;
        let fault = FaultControl::Disabled;
        let mut candidate = Some(outcome_effects);
        let mut retryable_attempts = 0;
        let result = loop {
            let attempt = self
                .execute_immediate_action_after_attempt(
                    client,
                    registry,
                    action,
                    &claims,
                    &target_authority,
                    &normalized_input,
                    &preconditions,
                    &binding,
                    &reserved_creates,
                    application_id,
                    &route_id,
                    &correlation,
                    fault,
                    deadline,
                    &mut candidate,
                    None,
                    None,
                    Some(&causation),
                )
                .await;
            if matches!(attempt, Err(MutationError::RetryableConflict))
                && retryable_attempts < 2
                && !fault.is_enabled()
            {
                retryable_attempts += 1;
                continue;
            }
            break attempt;
        };
        if failure_is_refusal(&result) && !fault.is_enabled() {
            self.record_action_boundary_audit(
                &claims,
                &route_id,
                &correlation,
                PreIoAuditKind::Refusal,
            )
            .await
            .map_err(|_| UncertainApply)?;
        }
        match result {
            Ok(_) => {}
            Err(
                MutationError::ActionRefusal(_)
                | MutationError::ActionHandlerFailure(_)
                | MutationError::ActionEvidenceFailure { .. },
            ) => {
                return refused_proposal(
                    "hook.proposal.handler_refusal",
                    "The proposed outcome was refused by the action's handler contract.",
                );
            }
            Err(MutationError::IdempotencyConflict | MutationError::IdempotencyExpired) => {
                // The key is the delivery, so a conflict means this delivery
                // already settled a different answer: the first application
                // stands and the changed one can never apply. A delivery whose
                // receipt is past the horizon already applied, so it never
                // applies again either.
                return conflicting_hook_answer();
            }
            Err(MutationError::PreconditionFailed | MutationError::FieldGuardFailed { .. }) => {
                return refused_proposal(
                    "hook.proposal.precondition_failed",
                    "The proposed mutation found its target in an unexpected state.",
                );
            }
            Err(MutationError::InvalidRequest | MutationError::InvalidRequestAt(_)) => {
                return refused_proposal(
                    "hook.proposal.mutation_refused",
                    "The proposed mutation was refused by the mutation contract.",
                );
            }
            Err(_) => return Err(UncertainApply),
        }

        // The committed revision comes from the applied result records,
        // which hold every effect the mutation produced. The response the
        // grant returns is disclosure-filtered, so a grant whose result set
        // hides every applied effect would leave the row forever uncertain
        // if completion were derived from it.
        let resulting_revision = client
            .query_opt(
                "SELECT target_record_revision
                   FROM registry_internal.registry_immediate_action_results
                  WHERE key_reference = $1
                  ORDER BY effect_id COLLATE \"C\"
                  LIMIT 1",
                &[&binding.key_reference],
            )
            .await
            .map_err(|_| UncertainApply)?
            .map(|row| row.get::<_, i64>(0))
            .filter(|revision| *revision > 0)
            .ok_or(UncertainApply)?;
        Ok(HookChangeOutcome::Applied(resulting_revision))
    }

    pub(crate) async fn action_target_conditions(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: ActionTargetConditionsInput<'_>,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
    ) -> Result<HeldReadResponse, MutationError> {
        if !profile_is_keyed(self.audit.profile()) {
            return Err(MutationError::Unavailable);
        }
        let action = action_for_route(
            registry,
            input.action_id,
            input.route_id,
            ActionRouteKind::TargetConditions,
        )?;
        validate_action_claims(action, claims, Operation::Invoke)?;
        let refs = validate_condition_inputs(action, input.input)?;
        let _attempt = self
            .begin_action_boundary_audit(claims, input.route_id, input.correlation)
            .await?;
        let result = self
            .action_target_conditions_after_attempt(
                client,
                registry,
                action,
                claims,
                target_authority,
                &refs,
                input.route_id,
                input.correlation,
            )
            .await;
        if failure_is_refusal(&result) {
            self.record_action_boundary_audit(
                claims,
                input.route_id,
                input.correlation,
                PreIoAuditKind::Refusal,
            )
            .await?;
        }
        result.map_err(|error| match error {
            MutationError::CommitUnresolved => MutationError::Unavailable,
            other => other,
        })
    }

    /// Append the action's attempt and hold it until its terminal or refusal
    /// entry answers it.
    pub(crate) async fn begin_action_boundary_audit(
        &self,
        claims: &ActionClaimContext,
        operation_id: &str,
        correlation: &RequestCorrelation,
    ) -> Result<AuditRequest, MutationError> {
        Ok(begin_action_pre_io_audit(
            &self.audit,
            &self.expected,
            claims,
            PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method: HttpMethod::Post,
                operation_id,
                target_record: None,
                refusal_reason: None,
                correlation,
            },
        )
        .await?)
    }

    pub(crate) async fn record_action_boundary_audit(
        &self,
        claims: &ActionClaimContext,
        operation_id: &str,
        correlation: &RequestCorrelation,
        kind: PreIoAuditKind,
    ) -> Result<(), MutationError> {
        record_action_pre_io_audit(
            &self.audit,
            &self.expected,
            claims,
            PreIoAudit {
                kind,
                method: HttpMethod::Post,
                operation_id,
                target_record: None,
                refusal_reason: None,
                correlation,
            },
        )
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_immediate_action_after_attempt(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
        preconditions: &BTreeMap<String, String>,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        reserved_creates: &BTreeMap<String, Uuid>,
        application_id: Uuid,
        route_id: &str,
        correlation: &RequestCorrelation,
        fault: FaultControl,
        deadline: tokio::time::Instant,
        candidate: &mut Option<Vec<CompiledPlanEffect>>,
        frozen: Option<&FrozenEvidenceEvaluation>,
        commit_requests: Option<&[(CompiledEvidenceCapability, EvidenceSubjects)]>,
        causation: Option<&Causation>,
    ) -> Result<MutationOutcome, MutationError> {
        if tokio::time::Instant::now() >= deadline {
            return Err(MutationError::Unavailable);
        }
        let transaction = begin_action_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;

        transaction
            .set_statement_budget(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if let Some((outcome, entry)) = self
            .recover_action_receipt(
                transaction.transaction(),
                registry,
                action,
                claims,
                target_authority,
                binding,
                route_id,
                correlation,
            )
            .await?
        {
            check_current_action_grant(claims)?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::CommitUnresolved)?;
            self.audit
                .append(entry)
                .await
                .map_err(|_| MutationError::CommitUnresolved)?;
            check_current_action_grant(claims)?;
            return Ok(outcome);
        }
        if let Some(frozen) = frozen {
            validate_frozen_evidence(frozen)?;
            match &frozen.outcome {
                Ok(ActionHandlerOutcome::Effects(effects)) => *candidate = Some(effects.clone()),
                Ok(ActionHandlerOutcome::Refusal(refusal)) => {
                    let mut refusal = refusal.clone();
                    refusal.field = refusal.field.and_then(|id| {
                        action
                            .inputs
                            .iter()
                            .find(|input| input.id == id)
                            .map(|input| input.api_name.clone())
                    });
                    return Err(MutationError::ActionRefusal(refusal));
                }
                Err(error) => return Err(error.clone()),
            }
        }

        // Receipt recovery precedes computation. Once verified, retain this
        // candidate and the host-reserved identities across confirmed aborts.
        if candidate.is_none() {
            *candidate = Some(if action.handler.is_some() {
                // Keep receipt recovery and evaluation under the same key lock.
                // The blocking worker receives only owned compiled declarations
                // and bounded inputs, so cancellation cannot leave a worker
                // holding database authority or committing late effects.
                let compiled_action = action.clone();
                let handler_inputs = input_values.clone();
                let outcome = tokio::task::spawn_blocking(move || {
                    evaluate_admitted_action_detailed(
                        &compiled_action,
                        &handler_inputs,
                        deadline.into_std(),
                    )
                })
                .await
                .map_err(|_| MutationError::Unavailable)?
                .map_err(|diagnostic| {
                    // Locations are compiled identifiers and the cause is a
                    // static repair message. Never render Rhai errors, source,
                    // input values, or script-selected unknown identifiers.
                    tracing::error!(
                        action_id = %action.id,
                        slot_id = diagnostic.slot.as_deref(),
                        field_id = diagnostic.field.as_deref(),
                        handler_failure = diagnostic.kind.code(),
                        cause = diagnostic.message,
                        "action handler produced no effects"
                    );
                    MutationError::ActionHandlerFailure(diagnostic.kind)
                })?;
                match outcome {
                    ActionHandlerOutcome::Effects(effects) => effects,
                    ActionHandlerOutcome::Refusal(mut refusal) => {
                        refusal.field = refusal.field.and_then(|id| {
                            action
                                .inputs
                                .iter()
                                .find(|input| input.id == id)
                                .map(|input| input.api_name.clone())
                        });
                        return Err(MutationError::ActionRefusal(refusal));
                    }
                }
            } else {
                action.effects.clone()
            });
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(MutationError::Unavailable);
        }
        let effects = candidate.as_ref().ok_or(MutationError::Unavailable)?;
        let application_reference = action_application_reference(
            self.audit.profile(),
            &self.expected.activation_id,
            application_id,
        )?;

        let guard_failure = self
            .lock_existing_action_targets(
                transaction.transaction(),
                registry,
                action,
                claims,
                target_authority,
                input_values,
                application_id,
                preconditions,
            )
            .await?;

        if !action.commit_evidence.is_empty() {
            let frozen = frozen.ok_or(MutationError::PreconditionFailed)?;
            let expected = commit_requests.ok_or(MutationError::PreconditionFailed)?;
            let current = self
                .action_commit_evidence_requests(
                    transaction.transaction(),
                    registry,
                    action,
                    claims,
                    target_authority,
                    input_values,
                )
                .await?;
            if current != expected {
                return Err(MutationError::PreconditionFailed);
            }
            verify_action_commit_evidence(action, input_values, frozen)?;
        }

        self.verify_action_link_references(
            transaction.transaction(),
            registry,
            action,
            claims,
            target_authority,
            input_values,
        )
        .await?;

        let patch_bases = self
            .lock_action_patch_targets(
                transaction.transaction(),
                registry,
                action,
                claims,
                target_authority,
                input_values,
                preconditions,
                application_id,
            )
            .await?;
        // A failed field guard answers only after every other check passed, so
        // its distinct refusal never stands in for a stale or hidden target.
        if let Some(input) = guard_failure {
            check_current_action_grant(claims)?;
            return Err(MutationError::FieldGuardFailed { input });
        }
        let ordered = ordered_action_effects(effects)?;
        let groups = ordered_action_effect_groups(&ordered, &patch_bases, reserved_creates)?;
        let mut rows = BTreeMap::<String, CurrentRow>::new();
        let mut results = Vec::<ActionEffectResult>::new();
        for effects in groups {
            fault.fail_at(MutationFaultPoint::BeforeCurrentRow)?;
            let current = self
                .apply_action_effect_group(
                    transaction.transaction(),
                    registry,
                    action,
                    &effects,
                    claims,
                    target_authority,
                    input_values,
                    &patch_bases,
                    reserved_creates,
                    &rows,
                    application_id,
                )
                .await?;
            let effect = effects[0];
            let record_reference = record_reference(
                self.audit.profile(),
                &self.expected.activation_id,
                &current.record_id,
            )?;
            let snapshot = canonical_snapshot(&current.data)?;
            // The target journal describes the canonical entity operation.
            // The application reference and the stored receipt record which
            // action and effects produced it.
            let operation_id = format!(
                "records.{}.{}",
                effect.target.entity_id,
                mutation_kind(effect.operation)
            );
            fault.fail_at(MutationFaultPoint::BeforeRevision)?;
            insert_revision(
                transaction.transaction(),
                RevisionInsert {
                    entity_id: &effect.target.entity_id,
                    record_id: current.record_uuid,
                    record_reference: &record_reference,
                    record_revision: current.record_revision,
                    predecessor_revision: current.predecessor_revision,
                    lifecycle: &current.record_lifecycle,
                    package_revision: &self.expected.activation_id,
                    operation_id: &operation_id,
                    mutation_kind: mutation_kind(effect.operation),
                    principal_reference: &binding.principal_reference,
                    request_reference: &application_reference,
                    snapshot: &snapshot,
                },
            )
            .await?;
            let entity = registry
                .entities()
                .get(&effect.target.entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            fault.fail_at(MutationFaultPoint::BeforeOutbox)?;
            let deliveries = exact_entity_event_deliveries(registry, entity)?;
            let trigger = mutation_trigger(effect.operation);
            let data_schemas =
                event_data_schemas(registry.registry_id(), entity, trigger, &deliveries)?;
            let event_source = self.event_source();
            insert_configured_events(
                transaction.transaction(),
                entity,
                &deliveries,
                self.event_destinations.as_deref(),
                OutboxMutation {
                    trigger,
                    application_reference: Some(&application_reference),
                    entity_id: &entity.id,
                    record_id: &current.record_id,
                    record_reference: &record_reference,
                    record_revision: current.record_revision,
                    package_revision: &self.expected.activation_id,
                    package_digest: &self.expected.package_digest,
                    schema_fingerprint: &self.expected.schema_fingerprint,
                    before: current.before_data.as_ref(),
                    after: Some(&current.data),
                    payload_retention: self
                        .event_destinations
                        .as_deref()
                        .map_or(Duration::from_secs(7 * 24 * 60 * 60), |destinations| {
                            destinations.payload_retention()
                        }),
                    envelope: EnvelopeBinding {
                        source: &event_source,
                        data_schemas: &data_schemas,
                        causation,
                    },
                },
            )
            .await?;
            for effect in effects {
                results.push(ActionEffectResult {
                    effect_id: effect.id.clone(),
                    entity_id: effect.target.entity_id.clone(),
                    record_id: current.record_id.clone(),
                    record_uuid: current.record_uuid,
                    record_revision: current.record_revision,
                    record_reference: record_reference.clone(),
                    operation: effect.operation,
                });
                rows.insert(effect.id.clone(), current.clone());
            }
        }

        // Several effects may share one final record revision. Index each
        // distinct revision once, under the action transaction's one commit,
        // just as the single-record and batch mutation paths do.
        let distinct_revisions = results
            .iter()
            .map(|result| {
                (
                    (result.entity_id.as_str(), result.record_uuid),
                    result.record_revision,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let members = distinct_revisions
            .into_iter()
            .map(
                |((entity_id, record_id), record_revision)| RevisionCommitMember {
                    entity_id,
                    record_id,
                    record_revision,
                },
            )
            .collect::<Vec<_>>();
        allocate_revision_commit(
            transaction.transaction(),
            CommitAllocation {
                package_revision: &self.expected.activation_id,
                origin: CommitOrigin::Mutation {
                    actor_reference: &binding.principal_reference,
                    request_reference: &binding.request_reference,
                },
                change_context: None,
                members: &members,
            },
        )
        .await?;

        let held = action_held_response(action, claims, application_id, &results)?;
        let public_result_count = u16::try_from(
            results
                .iter()
                .filter(|result| claims.result_effect_allowed(action, &result.effect_id))
                .count(),
        )
        .map_err(|_| MutationError::Unavailable)?;
        fault.fail_at(MutationFaultPoint::BeforeTerminalAudit)?;
        let entry = action_terminal_entry(
            self.audit.profile(),
            TerminalAudit {
                grant: claims.grant_audit().cloned(),
                outcome: TerminalAuditOutcome::Committed,
                method: HttpMethod::Post,
                operation_id: route_id.to_owned(),
                entity_id: None,
                action_id: Some(action.id.clone()),
                package_revision: self.expected.activation_id.clone(),
                selected_access_profile: claims.access_profile().to_owned(),
                purpose_present: claims.purpose().is_some(),
                principal_reference: Some(binding.principal_reference.clone()),
                record_reference: None,
                record_revision: None,
                result_count: Some(usize::from(public_result_count)),
                field_set_reference: None,
                correlation: correlation.clone(),
            },
            &application_reference,
        )?;
        fault.fail_at(MutationFaultPoint::BeforeIdempotency)?;
        insert_result(
            transaction.transaction(),
            binding,
            &StoredResultMetadata::ImmediateAction {
                result_count: public_result_count,
            },
            &held,
        )
        .await?;
        insert_action_application(
            transaction.transaction(),
            binding,
            action,
            application_id,
            &self.expected.activation_id,
            &binding.principal_reference,
            public_result_count,
        )
        .await?;
        insert_action_result_links(transaction.transaction(), binding, action, &results).await?;
        if let Some(frozen) = frozen {
            insert_action_evidence(transaction.transaction(), application_id, frozen).await?;
        }
        fault.fail_at(MutationFaultPoint::BeforeCommit)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(MutationError::Unavailable);
        }
        if let Some(frozen) = frozen {
            validate_frozen_evidence(frozen)?;
            verify_action_commit_evidence(action, input_values, frozen)?;
        }

        check_current_action_grant(claims)?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::CommitUnresolved)?;
        self.audit
            .append(entry)
            .await
            .map_err(|_| MutationError::CommitUnresolved)?;
        check_current_action_grant(claims)?;
        fault.fail_at(MutationFaultPoint::AfterCommitBeforeResponseRelease)?;
        Ok(MutationOutcome {
            response: held,
            replayed: false,
        })
    }

    /// Recover a stored action answer. The caller commits the transaction,
    /// then appends the returned `response` entry before releasing the answer.
    #[allow(clippy::too_many_arguments)]
    async fn recover_action_receipt(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        binding: &crate::idempotency::ResolvedIdempotencyBinding,
        route_id: &str,
        correlation: &RequestCorrelation,
    ) -> Result<Option<(MutationOutcome, AuditEntry)>, MutationError> {
        if let Some(stored) = lock_and_load(transaction, binding).await? {
            let StoredResultMetadata::ImmediateAction { result_count } = stored.metadata else {
                return Err(MutationError::Unavailable);
            };
            self.authorize_stored_action_results(
                transaction,
                registry,
                action,
                claims,
                target_authority,
                &binding.key_reference,
            )
            .await?;
            let application_reference = stored_action_application_reference(
                transaction,
                self.audit.profile(),
                &binding.key_reference,
            )
            .await?;
            let entry = action_terminal_entry(
                self.audit.profile(),
                TerminalAudit {
                    grant: claims.grant_audit().cloned(),
                    outcome: TerminalAuditOutcome::Replayed,
                    method: HttpMethod::Post,
                    operation_id: route_id.to_owned(),
                    entity_id: None,
                    action_id: Some(action.id.clone()),
                    package_revision: self.expected.activation_id.clone(),
                    selected_access_profile: claims.access_profile().to_owned(),
                    purpose_present: claims.purpose().is_some(),
                    principal_reference: Some(binding.principal_reference.clone()),
                    record_reference: None,
                    record_revision: None,
                    result_count: Some(usize::from(result_count)),
                    field_set_reference: None,
                    correlation: correlation.clone(),
                },
                &application_reference,
            )?;
            return Ok(Some((
                MutationOutcome {
                    response: stored.response,
                    replayed: true,
                },
                entry,
            )));
        }

        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_action_effect_group(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        effects: &[&CompiledPlanEffect],
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
        patch_bases: &BTreeMap<String, CurrentRow>,
        reserved_creates: &BTreeMap<String, Uuid>,
        prior_results: &BTreeMap<String, CurrentRow>,
        application_id: Uuid,
    ) -> Result<CurrentRow, MutationError> {
        let effect = *effects.first().ok_or(MutationError::InvalidRequest)?;
        let entity = registry
            .entities()
            .get(&effect.target.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        if effects.iter().any(|candidate| {
            candidate.target.entity_id != effect.target.entity_id
                || candidate.operation != effect.operation
        }) {
            return Err(MutationError::InvalidRequest);
        }
        if entity
            .change_control
            .as_ref()
            .is_some_and(|control| control.required_for.contains(&effect.operation))
        {
            return Err(MutationError::InvalidRequest);
        }
        let (record_uuid, expected_revision, before) = match &effect.target.binding {
            CompiledPlanTargetBinding::Create => (
                *reserved_creates
                    .get(&effect.id)
                    .ok_or(MutationError::InvalidRequest)?,
                None,
                None,
            ),
            CompiledPlanTargetBinding::Existing { .. } => {
                let base = patch_bases
                    .get(&effect.id)
                    .ok_or(MutationError::PreconditionFailed)?;
                (base.record_uuid, Some(base.record_revision), Some(base))
            }
        };
        let target_context = action_target_group_context(
            registry,
            action,
            effects,
            claims,
            target_authority,
            record_uuid,
            expected_revision,
            false,
            Some(application_id),
            &self.expected.activation_id,
        )?;
        transaction
            .execute(
                "SELECT set_config('registry.immediate_action_target_context', $1, true)",
                &[&target_context.canonical_context()],
            )
            .await
            .map_err(map_database_error)?;
        let mut fields = Map::new();
        for effect in effects {
            let effect_fields = action_effect_document(
                action,
                entity,
                effect,
                input_values,
                prior_results,
                before,
            )?;
            for (field, value) in effect_fields {
                if fields.insert(field, value).is_some() {
                    return Err(MutationError::InvalidRequest);
                }
            }
        }
        match effect.operation {
            Operation::Create => target_context
                .authorize_rows(entity, None, &fields, record_uuid)
                .map_err(|_| MutationError::PreconditionFailed)?,
            Operation::Patch => {
                let before = before.ok_or(MutationError::PreconditionFailed)?;
                let mut preview = before.data.clone();
                for (field, value) in &fields {
                    preview.insert(field.clone(), value.clone());
                }
                target_context
                    .authorize_rows(entity, Some(&before.data), &preview, record_uuid)
                    .map_err(|_| MutationError::PreconditionFailed)?;
            }
            _ => return Err(MutationError::InvalidRequest),
        }
        let current = write_plan_row(
            transaction,
            entity,
            record_uuid,
            expected_revision,
            fields,
            before.map(|row| &row.data),
            self.field_encryption.as_deref(),
        )
        .await?;
        target_context
            .authorize_rows(
                entity,
                current.before_data.as_ref(),
                &current.data,
                current.record_uuid,
            )
            .map_err(|_| MutationError::PreconditionFailed)?;
        Ok(current)
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock_existing_action_targets(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
        application_id: Uuid,
        preconditions: &BTreeMap<String, String>,
    ) -> Result<Option<String>, MutationError> {
        enum Role<'a> {
            Patch(&'a CompiledPlanEffect),
            Link(&'a str),
        }

        // A row may be a patch target in one invocation and a link target in
        // another. Acquire the complete set in one order before either phase;
        // sorting each phase independently permits opposite-role deadlocks.
        let mut targets = BTreeMap::new();
        let mut guard_failure = None;
        for effect in &action.effects {
            if let CompiledPlanTargetBinding::Existing { input } = &effect.target.binding {
                let record_id = Uuid::parse_str(&input_record_id(input_values, input)?)
                    .map_err(|_| MutationError::InvalidRequest)?;
                targets
                    .entry((effect.target.entity_id.as_str(), record_id))
                    .or_insert(Role::Patch(effect));
            }
        }
        for target in &action.target_uses {
            if !(target.operation == Operation::Get
                || (target.operation == Operation::Invoke && target.fields.is_empty()))
            {
                continue;
            }
            if let crate::model::CompiledActionTargetUseSource::Input { input } = &target.source {
                let Some(record_id) = link_input_record_id(action, input_values, input)? else {
                    continue;
                };
                let record_id =
                    Uuid::parse_str(&record_id).map_err(|_| MutationError::InvalidRequest)?;
                targets
                    .entry((target.entity_id.as_str(), record_id))
                    .or_insert(Role::Link(input));
            }
        }
        for ((entity_id, record_id), role) in targets {
            let entity = registry
                .entities()
                .get(entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let (target_context, link_context) = match role {
                Role::Patch(effect) => (
                    action_target_context(
                        registry,
                        action,
                        effect,
                        claims,
                        target_authority,
                        record_id,
                        None,
                        true,
                        Some(application_id),
                        &self.expected.activation_id,
                    )?
                    .canonical_context()
                    .to_owned(),
                    String::new(),
                ),
                Role::Link(input) => (
                    String::new(),
                    action_link_context(
                        registry,
                        action,
                        input,
                        entity_id,
                        claims,
                        target_authority,
                        record_id,
                        &self.expected.activation_id,
                    )?
                    .canonical_context()
                    .to_owned(),
                ),
            };
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_target_context', $1, true),
                            set_config('registry.immediate_action_link_context', $2, true)",
                    &[&target_context, &link_context],
                )
                .await
                .map_err(map_database_error)?;
            let current =
                load_action_row(transaction, entity, &record_id.to_string(), true).await?;
            verify_action_requirements(
                entity,
                action,
                input_values,
                record_id,
                &current,
                self.audit.profile(),
                registry.registry_id(),
                preconditions,
                &mut guard_failure,
            )?;
        }
        transaction
            .execute(
                "SELECT set_config('registry.immediate_action_target_context', '', true),
                        set_config('registry.immediate_action_link_context', '', true)",
                &[],
            )
            .await
            .map_err(map_database_error)?;
        Ok(guard_failure)
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock_action_patch_targets(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
        preconditions: &BTreeMap<String, String>,
        application_id: Uuid,
    ) -> Result<BTreeMap<String, CurrentRow>, MutationError> {
        let mut patch_targets =
            BTreeMap::<(String, Uuid), Vec<(&str, &CompiledPlanEffect, String)>>::new();
        for effect in &action.effects {
            let CompiledPlanTargetBinding::Existing { input } = &effect.target.binding else {
                continue;
            };
            let record_id = input_record_id(input_values, input)?;
            let record_uuid =
                Uuid::parse_str(&record_id).map_err(|_| MutationError::InvalidRequest)?;
            patch_targets
                .entry((effect.target.entity_id.clone(), record_uuid))
                .or_default()
                .push((input, effect, record_id));
        }
        let mut bases = BTreeMap::new();
        for ((entity_id, record_uuid), mut target_effects) in patch_targets {
            target_effects.sort_by_key(|(_, effect, _)| &effect.id);
            let effects = target_effects
                .iter()
                .map(|(_, effect, _)| *effect)
                .collect::<Vec<_>>();
            let entity = registry
                .entities()
                .get(&entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let read_context = action_target_group_context(
                registry,
                action,
                &effects,
                claims,
                target_authority,
                record_uuid,
                None,
                true,
                Some(application_id),
                &self.expected.activation_id,
            )?;
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_target_context', $1, true)",
                    &[&read_context.canonical_context()],
                )
                .await
                .map_err(map_database_error)?;
            let current = load_action_row(transaction, entity, &target_effects[0].2, true).await?;
            for (input_id, effect, _) in &target_effects {
                let token = action_condition_token(
                    self.audit.profile(),
                    registry.registry_id(),
                    &action.id,
                    input_id,
                    &effect.target.entity_id,
                    &current.record_id,
                    current.record_revision,
                )?;
                let provided = preconditions
                    .get(*input_id)
                    .ok_or(MutationError::InvalidRequest)?;
                if provided.as_bytes().ct_eq(token.as_bytes()).unwrap_u8() != 1 {
                    return Err(MutationError::PreconditionFailed);
                }
            }
            let target_context = action_target_group_context(
                registry,
                action,
                &effects,
                claims,
                target_authority,
                current.record_uuid,
                Some(current.record_revision),
                false,
                None,
                &self.expected.activation_id,
            )?;
            target_context
                .authorize_rows(
                    entity,
                    Some(&current.data),
                    &current.data,
                    current.record_uuid,
                )
                .map_err(|_| MutationError::PreconditionFailed)?;
            for (_, effect, _) in target_effects {
                bases.insert(effect.id.clone(), current.clone());
            }
        }
        Ok(bases)
    }

    #[allow(clippy::too_many_arguments)]
    async fn action_target_conditions_after_attempt(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        refs: &BTreeMap<String, String>,
        route_id: &str,
        correlation: &RequestCorrelation,
    ) -> Result<HeldReadResponse, MutationError> {
        let transaction = begin_action_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        let mut conditions = serde_json::Map::new();
        for (input_id, record_id) in refs {
            let effect = action
                .effects
                .iter()
                .find(|effect| {
                    matches!(&effect.target.binding, CompiledPlanTargetBinding::Existing { input } if input == input_id)
                });
            let input = action
                .inputs
                .iter()
                .find(|input| input.id == *input_id)
                .ok_or(MutationError::InvalidRequest)?;
            let entity_id = if let Some(effect) = effect {
                &effect.target.entity_id
            } else if let FieldTypeSource::Reference { target, .. } = &input.field_type {
                target
            } else {
                return Err(MutationError::InvalidRequest);
            };
            let entity = registry
                .entities()
                .get(entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let record_uuid =
                Uuid::parse_str(record_id).map_err(|_| MutationError::InvalidRequest)?;
            let current = if let Some(effect) = effect {
                let target_context = action_target_context(
                    registry,
                    action,
                    effect,
                    claims,
                    target_authority,
                    record_uuid,
                    None,
                    false,
                    None,
                    &self.expected.activation_id,
                )?;
                transaction
                    .install_immediate_action_target_context(&target_context)
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                let current =
                    load_action_row(transaction.transaction(), entity, record_id, false).await?;
                target_context
                    .authorize_rows(
                        entity,
                        Some(&current.data),
                        &current.data,
                        current.record_uuid,
                    )
                    .map_err(|_| MutationError::PreconditionFailed)?;
                current
            } else {
                let link_context = action_link_context(
                    registry,
                    action,
                    input_id,
                    entity_id,
                    claims,
                    target_authority,
                    record_uuid,
                    &self.expected.activation_id,
                )?;
                transaction
                    .install_immediate_action_link_context(&link_context)
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                let current =
                    load_action_row(transaction.transaction(), entity, record_id, false).await?;
                link_context
                    .authorize_row(entity, &current.data, current.record_uuid)
                    .map_err(|_| MutationError::PreconditionFailed)?;
                current
            };
            conditions.insert(
                input.api_name.clone(),
                json!({
                    "ifMatch": action_condition_token(
                        self.audit.profile(),
                        registry.registry_id(),
                        &action.id,
                        input_id,
                        entity_id,
                        &current.record_id,
                        current.record_revision,
                    )?,
                }),
            );
        }
        let held = HeldReadResponse::from_json(&json!({ "preconditions": conditions }))
            .map_err(|_| MutationError::Unavailable)?;
        let entry = terminal_entry(
            self.audit.profile(),
            TerminalAudit {
                grant: claims.grant_audit().cloned(),
                outcome: TerminalAuditOutcome::Returned,
                method: HttpMethod::Post,
                operation_id: route_id.to_owned(),
                entity_id: None,
                action_id: Some(action.id.clone()),
                package_revision: self.expected.activation_id.clone(),
                selected_access_profile: claims.access_profile().to_owned(),
                purpose_present: claims.purpose().is_some(),
                principal_reference: None,
                record_reference: None,
                record_revision: None,
                result_count: Some(conditions.len()),
                field_set_reference: None,
                correlation: correlation.clone(),
            },
        )?;
        check_current_action_grant(claims)?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::CommitUnresolved)?;
        self.audit
            .append(entry)
            .await
            .map_err(|_| MutationError::CommitUnresolved)?;
        check_current_action_grant(claims)?;
        Ok(held)
    }

    async fn verify_action_link_references(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        input_values: &ActionInputs,
    ) -> Result<(), MutationError> {
        let mut refs = Vec::new();
        for target_use in &action.target_uses {
            if target_use.operation == Operation::Invoke
                && target_use.fields.is_empty()
                && !target_use.condition_required
            {
                if let crate::model::CompiledActionTargetUseSource::Input { input } =
                    &target_use.source
                {
                    let Some(record_id) = link_input_record_id(action, input_values, input)? else {
                        continue;
                    };
                    refs.push((target_use.entity_id.clone(), record_id, input, target_use));
                }
            }
        }
        refs.sort_by(|left, right| (&left.0, &left.1, left.2).cmp(&(&right.0, &right.1, right.2)));
        refs.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1 && left.2 == right.2);
        for (entity_id, record_id, input_id, target_use) in refs {
            let entity = registry
                .entities()
                .get(&entity_id)
                .ok_or(MutationError::InvalidRequest)?;
            let record_uuid =
                Uuid::parse_str(&record_id).map_err(|_| MutationError::InvalidRequest)?;
            let link_context = action_link_context(
                registry,
                action,
                input_id,
                &target_use.entity_id,
                claims,
                target_authority,
                record_uuid,
                &self.expected.activation_id,
            )?;
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_link_context', $1, true)",
                    &[&link_context.canonical_context()],
                )
                .await
                .map_err(map_database_error)?;
            let current = load_action_row(transaction, entity, &record_id, true).await?;
            link_context
                .authorize_row(entity, &current.data, current.record_uuid)
                .map_err(|_| MutationError::PreconditionFailed)?;
        }
        Ok(())
    }

    async fn authorize_stored_action_results(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        key_reference: &str,
    ) -> Result<(), MutationError> {
        if claims.result_effects().is_empty() {
            return Ok(());
        }
        let rows = transaction
            .query(
                "SELECT effect_id, target_entity_id, target_record_id, target_record_revision
                   FROM registry_internal.registry_immediate_action_results
                  WHERE key_reference = $1
                  ORDER BY effect_id COLLATE \"C\"",
                &[&key_reference],
            )
            .await
            .map_err(map_database_error)?;
        let mut targets = BTreeMap::<(String, Uuid), Vec<&CompiledPlanEffect>>::new();
        for row in &rows {
            let effect_id = row.get::<_, String>(0);
            let entity_id = row.get::<_, String>(1);
            let record_uuid = row.get::<_, Uuid>(2);
            let _revision = row.get::<_, i64>(3);
            if !claims.result_effect_allowed(action, &effect_id) {
                continue;
            }
            let effect = action
                .effects
                .iter()
                .find(|effect| effect.id == effect_id && effect.target.entity_id == entity_id)
                .ok_or(MutationError::Unavailable)?;
            targets
                .entry((entity_id, record_uuid))
                .or_default()
                .push(effect);
        }
        for ((entity_id, record_uuid), mut effects) in targets {
            effects.sort_by_key(|effect| &effect.id);
            let entity = registry
                .entities()
                .get(&entity_id)
                .ok_or(MutationError::Unavailable)?;
            let read_context = action_target_context(
                registry,
                action,
                effects[0],
                claims,
                target_authority,
                record_uuid,
                None,
                false,
                None,
                &self.expected.activation_id,
            )?;
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_target_context', $1, true)",
                    &[&read_context.canonical_context()],
                )
                .await
                .map_err(map_database_error)?;
            let current =
                load_action_row(transaction, entity, &record_uuid.to_string(), false).await?;
            for effect in effects {
                let target_context = action_target_context(
                    registry,
                    action,
                    effect,
                    claims,
                    target_authority,
                    record_uuid,
                    None,
                    false,
                    None,
                    &self.expected.activation_id,
                )?;
                target_context
                    .authorize_rows(
                        entity,
                        (effect.operation == Operation::Patch).then_some(&current.data),
                        &current.data,
                        current.record_uuid,
                    )
                    .map_err(|_| MutationError::PreconditionFailed)?;
            }
        }
        Ok(())
    }
}

fn action_for_route<'a>(
    registry: &'a CompiledRegistry,
    action_id: &str,
    route_id: &str,
    kind: ActionRouteKind,
) -> Result<&'a CompiledAction, MutationError> {
    let route = registry
        .actions()
        .routes
        .iter()
        .find(|route| route.id == route_id && route.action_id == action_id && route.kind == kind)
        .ok_or(MutationError::InvalidRequest)?;
    if route.method != HttpMethod::Post || route.operation != Operation::Invoke {
        return Err(MutationError::InvalidRequest);
    }
    registry
        .actions()
        .actions
        .iter()
        .find(|action| {
            action.id == action_id
                && matches!(
                    action.execution,
                    crate::model::CompiledActionExecution::Immediate
                )
                && match kind {
                    ActionRouteKind::Invoke => action.route == route.path,
                    ActionRouteKind::Availability => false,
                    ActionRouteKind::TargetConditions => {
                        action.condition_route.as_deref() == Some(route.path.as_str())
                    }
                }
        })
        .ok_or(MutationError::InvalidRequest)
}

fn refused_proposal(
    code: &'static str,
    summary: impl Into<String>,
) -> Result<HookChangeOutcome, UncertainApply> {
    Ok(HookChangeOutcome::Refused {
        code,
        summary: summary.into(),
    })
}

fn dead_lettered_proposal(
    code: &'static str,
    summary: impl Into<String>,
) -> Result<HookChangeOutcome, UncertainApply> {
    Ok(HookChangeOutcome::DeadLettered {
        code,
        summary: summary.into(),
    })
}

fn conflicting_hook_answer() -> Result<HookChangeOutcome, UncertainApply> {
    dead_lettered_proposal(
        "hook.proposal.answer_conflict",
        "This delivery already applied a different answer; the first application stands.",
    )
}

fn hook_change_idempotency_key(event_id: Uuid, compiled_delivery_id: &str) -> String {
    // The application identity is the hook delivery identity,
    // domain-separated. No attempt, generation, or answer component enters
    // the key; the answer digest belongs to the binding reference instead.
    let mut input = Vec::new();
    input.extend_from_slice(b"breg-hook-proposal-idempotency-v1");
    append_proposal_idempotency_component(&mut input, event_id.to_string().as_bytes());
    append_proposal_idempotency_component(&mut input, compiled_delivery_id.as_bytes());
    format!("sha256:{}", hex::encode(Sha256::digest(input)))
}

fn append_proposal_idempotency_component(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn check_current_action_grant(claims: &ActionClaimContext) -> Result<(), MutationError> {
    if claims
        .task_grant()
        .is_some_and(|binding| !binding.is_current())
    {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(())
}

fn validate_action_claims(
    action: &CompiledAction,
    claims: &ActionClaimContext,
    operation: Operation,
) -> Result<(), MutationError> {
    check_current_action_grant(claims)?;
    if claims.action_id() != action.id {
        return Err(MutationError::InvalidRequest);
    }
    let grant = action
        .permissions
        .iter()
        .find(|grant| grant.profile_id == claims.access_profile())
        .ok_or(MutationError::InvalidRequest)?;
    if !grant.operations.contains(&operation) {
        return Err(MutationError::InvalidRequest);
    }
    if !claims.result_effects().is_subset(&grant.results)
        || !claims.result_effects().is_subset(&action.result_effects)
    {
        return Err(MutationError::InvalidRequest);
    }
    Ok(())
}

trait ActionClaimExt {
    fn result_effect_allowed(&self, action: &CompiledAction, effect_id: &str) -> bool;
}

impl ActionClaimExt for ActionClaimContext {
    fn result_effect_allowed(&self, action: &CompiledAction, effect_id: &str) -> bool {
        action.result_effects.contains(effect_id) && self.result_effects().contains(effect_id)
    }
}

fn validate_action_input(
    action: &CompiledAction,
    input: Map<String, Value>,
) -> Result<ActionInputs, MutationError> {
    let expected = action
        .inputs
        .iter()
        .map(|input| input.id.as_str())
        .collect::<BTreeSet<_>>();
    if input.keys().any(|key| !expected.contains(key.as_str())) {
        return Err(MutationError::InvalidRequest);
    }
    let condition_inputs = existing_target_inputs(action);
    for source in &action.inputs {
        match input.get(&source.id) {
            None | Some(Value::Null)
                if source.required || condition_inputs.contains(&source.id) =>
            {
                return Err(MutationError::InvalidRequest);
            }
            Some(value) => {
                let valid = if action.handler.is_some() {
                    value.is_null()
                        || crate::action_handler::validate_input_value(value, &source.field_type)
                            .is_ok()
                } else {
                    validate_field_value(FieldValue::Json(value), &source.field_type)
                };
                if !valid {
                    return Err(MutationError::InvalidRequest);
                }
            }
            None => {}
        }
    }
    Ok(input)
}

fn validate_condition_inputs(
    action: &CompiledAction,
    input: Map<String, Value>,
) -> Result<BTreeMap<String, String>, MutationError> {
    let expected = existing_target_inputs(action);
    if input.len() != expected.len() || input.keys().any(|key| !expected.contains(key)) {
        return Err(MutationError::InvalidRequest);
    }
    let mut refs = BTreeMap::new();
    for input_id in expected {
        let record_id = input_record_id(&input, &input_id)?;
        refs.insert(input_id, record_id);
    }
    Ok(refs)
}

fn validate_precondition_set(
    action: &CompiledAction,
    preconditions: &BTreeMap<String, String>,
) -> Result<(), MutationError> {
    let expected = existing_target_inputs(action);
    if preconditions.len() != expected.len()
        || preconditions
            .keys()
            .any(|key| !expected.contains(key) || preconditions[key].is_empty())
    {
        return Err(MutationError::InvalidRequest);
    }
    Ok(())
}

fn existing_target_inputs(action: &CompiledAction) -> BTreeSet<String> {
    crate::plan::condition_inputs(action)
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn input_record_id(input_values: &ActionInputs, input_id: &str) -> Result<String, MutationError> {
    let value = input_values
        .get(input_id)
        .ok_or(MutationError::InvalidRequest)?;
    let id = value.as_str().ok_or(MutationError::InvalidRequest)?;
    if !valid_uuid(id) {
        return Err(MutationError::InvalidRequest);
    }
    Ok(id.to_owned())
}

fn link_input_record_id(
    action: &CompiledAction,
    input_values: &ActionInputs,
    input_id: &str,
) -> Result<Option<String>, MutationError> {
    let input = action
        .inputs
        .iter()
        .find(|input| input.id == input_id)
        .ok_or(MutationError::InvalidRequest)?;
    if input_values.get(input_id).is_none_or(Value::is_null) {
        return if input.required {
            Err(MutationError::InvalidRequest)
        } else {
            Ok(None)
        };
    }
    input_record_id(input_values, input_id).map(Some)
}

#[allow(clippy::too_many_arguments)]
fn action_link_context(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    input_id: &str,
    target_entity_id: &str,
    claims: &ActionClaimContext,
    target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
    record_id: Uuid,
    package_revision: &str,
) -> Result<ImmediateActionLinkContext, MutationError> {
    ImmediateActionLinkContext::for_input(
        registry,
        claims,
        target_authority
            .get(target_entity_id)
            .cloned()
            .ok_or(MutationError::InvalidRequest)?,
        ImmediateActionLinkBinding {
            action_id: action.id.clone(),
            contract_fingerprint: action.definition_revision.clone(),
            active_package_revision: package_revision.to_owned(),
            input_id: input_id.to_owned(),
            target_entity_id: target_entity_id.to_owned(),
            target_record_id: record_id,
        },
    )
    .map_err(|_| MutationError::InvalidRequest)
}

#[allow(clippy::too_many_arguments)]
fn action_target_context(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    effect: &CompiledPlanEffect,
    claims: &ActionClaimContext,
    target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
    record_id: Uuid,
    expected_revision: Option<i64>,
    lock_only: bool,
    application_id: Option<Uuid>,
    package_revision: &str,
) -> Result<ImmediateActionTargetContext, MutationError> {
    action_target_group_context(
        registry,
        action,
        &[effect],
        claims,
        target_authority,
        record_id,
        expected_revision,
        lock_only,
        application_id,
        package_revision,
    )
}

#[allow(clippy::too_many_arguments)]
fn action_target_group_context(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    effects: &[&CompiledPlanEffect],
    claims: &ActionClaimContext,
    target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
    record_id: Uuid,
    expected_revision: Option<i64>,
    lock_only: bool,
    application_id: Option<Uuid>,
    package_revision: &str,
) -> Result<ImmediateActionTargetContext, MutationError> {
    let effect = effects
        .first()
        .copied()
        .ok_or(MutationError::InvalidRequest)?;
    let effect_ids = effects
        .iter()
        .map(|effect| effect.id.clone())
        .collect::<BTreeSet<_>>();
    // PostgreSQL receives the compiled ceiling for these selected slots. The
    // candidate may mutate only a subset, which is checked independently.
    let declared_effects = effects
        .iter()
        .map(|effect| {
            let declared = action
                .effects
                .iter()
                .find(|declared| declared.id == effect.id)
                .ok_or(MutationError::InvalidRequest)?;
            if declared.operation != effect.operation || declared.target != effect.target {
                return Err(MutationError::InvalidRequest);
            }
            let ceiling = declared
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    CompiledPlanMutation::Set { field, .. }
                    | CompiledPlanMutation::Clear { field } => field,
                })
                .collect::<BTreeSet<_>>();
            if effect.mutations.iter().any(|mutation| {
                !ceiling.contains(match mutation {
                    CompiledPlanMutation::Set { field, .. }
                    | CompiledPlanMutation::Clear { field } => field,
                })
            }) {
                return Err(MutationError::InvalidRequest);
            }
            Ok(declared)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fields = declared_effects
        .iter()
        .flat_map(|effect| &effect.mutations)
        .map(|mutation| match mutation {
            CompiledPlanMutation::Set { field, .. } | CompiledPlanMutation::Clear { field } => {
                field.clone()
            }
        })
        .collect::<BTreeSet<_>>();
    ImmediateActionTargetContext::for_effect(
        registry,
        claims,
        target_authority
            .get(&effect.target.entity_id)
            .cloned()
            .ok_or(MutationError::InvalidRequest)?,
        ImmediateActionTargetBinding {
            action_id: action.id.clone(),
            contract_fingerprint: action.definition_revision.clone(),
            active_package_revision: package_revision.to_owned(),
            effect_ids,
            target_entity_id: effect.target.entity_id.clone(),
            target_record_id: record_id,
            operation: effect.operation,
            fields,
            expected_revision,
            lock_only,
            application_id,
        },
    )
    .map_err(|_| MutationError::InvalidRequest)
}

fn reserve_action_create_ids(
    action: &CompiledAction,
) -> Result<BTreeMap<String, Uuid>, MutationError> {
    let mut reserved = BTreeMap::new();
    for effect in &action.effects {
        if matches!(effect.target.binding, CompiledPlanTargetBinding::Create) {
            reserved.insert(effect.id.clone(), Uuid::new_v4());
        }
    }
    Ok(reserved)
}

fn ordered_action_effects(
    effects: &[CompiledPlanEffect],
) -> Result<Vec<&CompiledPlanEffect>, MutationError> {
    crate::plan::order_plan_effects(effects.to_vec()).map_err(|_| MutationError::InvalidRequest)?;
    Ok(effects.iter().collect())
}

fn ordered_action_effect_groups<'a>(
    ordered: &[&'a CompiledPlanEffect],
    patch_bases: &BTreeMap<String, CurrentRow>,
    reserved_creates: &BTreeMap<String, Uuid>,
) -> Result<Vec<Vec<&'a CompiledPlanEffect>>, MutationError> {
    let mut positions = BTreeMap::<(String, Uuid), usize>::new();
    let mut groups = Vec::<Vec<&CompiledPlanEffect>>::new();
    for effect in ordered {
        let key = action_effect_target_key(effect, patch_bases, reserved_creates)?;
        if let Some(position) = positions.get(&key).copied() {
            groups[position].push(*effect);
        } else {
            positions.insert(key, groups.len());
            groups.push(vec![*effect]);
        }
    }
    crate::plan::order_effect_groups(
        groups,
        |effect| effect.id.as_str(),
        |effect| &effect.depends_on,
    )
    .map_err(|_| MutationError::InvalidRequest)
}

fn action_effect_target_key(
    effect: &CompiledPlanEffect,
    patch_bases: &BTreeMap<String, CurrentRow>,
    reserved_creates: &BTreeMap<String, Uuid>,
) -> Result<(String, Uuid), MutationError> {
    let record_uuid = match &effect.target.binding {
        CompiledPlanTargetBinding::Create => *reserved_creates
            .get(&effect.id)
            .ok_or(MutationError::InvalidRequest)?,
        CompiledPlanTargetBinding::Existing { .. } => {
            patch_bases
                .get(&effect.id)
                .ok_or(MutationError::PreconditionFailed)?
                .record_uuid
        }
    };
    Ok((effect.target.entity_id.clone(), record_uuid))
}

fn action_effect_document(
    action: &CompiledAction,
    entity: &CompiledEntity,
    effect: &CompiledPlanEffect,
    input_values: &ActionInputs,
    prior_results: &BTreeMap<String, CurrentRow>,
    _before: Option<&CurrentRow>,
) -> Result<Map<String, Value>, MutationError> {
    let mut data = Map::new();
    for mutation in &effect.mutations {
        match mutation {
            CompiledPlanMutation::Set { field, value } => {
                let field_source = entity
                    .fields
                    .get(field)
                    .ok_or(MutationError::InvalidRequest)?;
                let value = match value {
                    CompiledPlanValue::Literal { value } => value.clone(),
                    CompiledPlanValue::FromInput { input } => match input_values.get(input) {
                        Some(value) => value.clone(),
                        // A fixed effect leaves out a field whose optional
                        // input is absent: a create stores the field's
                        // ordinary absent value and a patch leaves it
                        // unchanged. A handler's proposal is taken as written.
                        None if action.handler.is_none()
                            && !field_source.required
                            && action
                                .inputs
                                .iter()
                                .any(|source| source.id == *input && !source.required) =>
                        {
                            continue;
                        }
                        None => return Err(MutationError::InvalidRequest),
                    },
                    CompiledPlanValue::FromEffect {
                        effect,
                        target_entity_id,
                    } => {
                        let source = action
                            .effects
                            .iter()
                            .find(|candidate| candidate.id == *effect)
                            .ok_or(MutationError::InvalidRequest)?;
                        if target_entity_id != &source.target.entity_id {
                            return Err(MutationError::InvalidRequest);
                        }
                        let row = prior_results
                            .get(effect)
                            .ok_or(MutationError::InvalidRequest)?;
                        Value::String(row.record_id.clone())
                    }
                };
                if !validate_field_value(FieldValue::Json(&value), &field_source.field_type) {
                    return Err(MutationError::InvalidRequest);
                }
                data.insert(field.clone(), value);
            }
            CompiledPlanMutation::Clear { field } => {
                if entity.fields.get(field).is_none_or(|field| field.required) {
                    return Err(MutationError::InvalidRequest);
                }
                data.insert(field.clone(), Value::Null);
            }
        }
    }
    Ok(data)
}

fn action_held_response(
    action: &CompiledAction,
    claims: &ActionClaimContext,
    application_id: Uuid,
    results: &[ActionEffectResult],
) -> Result<HeldResponse, MutationError> {
    let allowed = claims.result_effects();
    let result_body = results
        .iter()
        .filter(|result| allowed.contains(&result.effect_id))
        .map(|result| {
            (
                result.effect_id.clone(),
                json!({
                    "recordType": result.entity_id,
                    "recordId": result.record_id,
                    "revision": result.record_revision,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    HeldResponse::from_json(
        200,
        &json!({
            "applicationId": application_id.to_string(),
            "action": action.id,
            "results": result_body,
        }),
        BTreeMap::from([(
            PermittedResponseHeader::ContentType,
            b"application/json".to_vec(),
        )]),
    )
    .map_err(MutationError::from)
}

#[allow(clippy::too_many_arguments)]
fn verify_action_requirements(
    entity: &CompiledEntity,
    action: &CompiledAction,
    inputs: &ActionInputs,
    record_id: Uuid,
    current: &CurrentRow,
    audit: &AuditProfile,
    registry_id: &str,
    preconditions: &BTreeMap<String, String>,
    guard_failure: &mut Option<String>,
) -> Result<(), MutationError> {
    for requirement in action
        .requires
        .iter()
        .filter(|requirement| requirement.entity_id == entity.id)
    {
        let required_id = Uuid::parse_str(&input_record_id(inputs, &requirement.input)?)
            .map_err(|_| MutationError::InvalidRequest)?;
        if required_id != record_id {
            continue;
        }
        if requirement.revision_unchanged {
            let expected = action_condition_token(
                audit,
                registry_id,
                &action.id,
                &requirement.input,
                &entity.id,
                &current.record_id,
                current.record_revision,
            )?;
            let provided = preconditions
                .get(&requirement.input)
                .ok_or(MutationError::InvalidRequest)?;
            if provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
                return Err(MutationError::PreconditionFailed);
            }
        } else {
            let field = entity
                .fields
                .get(&requirement.field)
                .ok_or(MutationError::InvalidRequest)?;
            if !crate::commit_guard::guard_matches(
                requirement,
                inputs,
                &current.data,
                &time::OffsetDateTime::now_utc().date().to_string(),
                matches!(field.field_type, FieldTypeSource::Timestamp),
            ) && guard_failure.is_none()
            {
                *guard_failure = Some(requirement.input.clone());
            }
        }
    }
    Ok(())
}

async fn load_action_row(
    transaction: &Transaction<'_>,
    entity: &CompiledEntity,
    id: &str,
    lock: bool,
) -> Result<CurrentRow, MutationError> {
    let sql = format!(
        "SELECT {} FROM registry_data.{} WHERE record_id = $1::text::uuid
         AND record_lifecycle = 'active'{}",
        returning_projection(entity),
        quote_identifier(&entity.physical_table),
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = transaction
        .query_opt(&sql, &[&id])
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    row_to_current(entity, &row)
}

fn action_condition_token(
    profile: &AuditProfile,
    registry_id: &str,
    action_id: &str,
    input_id: &str,
    entity_id: &str,
    record_id: &str,
    record_revision: i64,
) -> Result<String, MutationError> {
    let canonical = canonicalize_json(&json!({
        "version": 1,
        "registry": registry_id,
        "action": action_id,
        "input": input_id,
        "recordType": entity_id,
        "record": record_id,
        "revision": record_revision,
    }))
    .map_err(|_| MutationError::InvalidRequest)?;
    let canonical = std::str::from_utf8(&canonical).map_err(|_| MutationError::InvalidRequest)?;
    let digest = profile
        .key_hasher()
        .audit_reference_hash("breg-action-condition-token-v1", registry_id, canonical)
        .map_err(|_| MutationError::Unavailable)?;
    Ok(format!("\"breg-{digest}\""))
}

fn action_application_reference(
    profile: &AuditProfile,
    package_revision: &str,
    application_id: Uuid,
) -> Result<String, MutationError> {
    profile
        .key_hasher()
        .audit_reference_hash(
            "breg-immediate-action-application-v1",
            package_revision,
            &application_id.to_string(),
        )
        .map_err(|_| MutationError::Unavailable)
}

async fn stored_action_application_reference(
    transaction: &Transaction<'_>,
    profile: &AuditProfile,
    key_reference: &str,
) -> Result<String, MutationError> {
    let row = transaction
        .query_opt(
            "SELECT application_id, package_revision
               FROM registry_internal.registry_immediate_action_applications
              WHERE key_reference = $1",
            &[&key_reference],
        )
        .await
        .map_err(|_| MutationError::Unavailable)?
        .ok_or(MutationError::Unavailable)?;
    let application_id = row.get::<_, Uuid>(0);
    let package_revision = row.get::<_, String>(1);
    action_application_reference(profile, &package_revision, application_id)
}

async fn insert_action_application(
    transaction: &Transaction<'_>,
    binding: &crate::idempotency::ResolvedIdempotencyBinding,
    action: &CompiledAction,
    application_id: Uuid,
    package_revision: &str,
    principal_reference: &str,
    result_count: u16,
) -> Result<(), MutationError> {
    let handler_answer_digest = binding
        .handler_answer_digest
        .as_ref()
        .map(<[u8; 32]>::as_slice);
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_immediate_action_applications
                 (key_reference, binding_reference, application_id, action_id,
                  action_contract_fingerprint, package_revision, principal_reference,
                  result_count, handler_answer_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &binding.key_reference,
                &binding.binding_reference,
                &application_id,
                &action.id,
                &action.definition_revision,
                &package_revision,
                &principal_reference,
                &(i16::try_from(result_count).map_err(|_| MutationError::InvalidRequest)?),
                &handler_answer_digest,
            ],
        )
        .await
        .map_err(map_database_error)?;
    if changed != 1 {
        return Err(MutationError::Unavailable);
    }
    Ok(())
}

async fn insert_action_result_links(
    transaction: &Transaction<'_>,
    binding: &crate::idempotency::ResolvedIdempotencyBinding,
    action: &CompiledAction,
    results: &[ActionEffectResult],
) -> Result<(), MutationError> {
    for result in results {
        let changed = transaction
            .execute(
                "INSERT INTO registry_internal.registry_immediate_action_results
                     (key_reference, effect_id, action_id, target_entity_id, target_record_id,
                      target_record_reference, target_record_revision, mutation_kind)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &binding.key_reference,
                    &result.effect_id,
                    &action.id,
                    &result.entity_id,
                    &result.record_uuid,
                    &result.record_reference,
                    &result.record_revision,
                    &mutation_kind(result.operation),
                ],
            )
            .await
            .map_err(map_database_error)?;
        if changed != 1 {
            return Err(MutationError::Unavailable);
        }
    }
    Ok(())
}

fn canonical_action_request_digest(
    action: &CompiledAction,
    input_values: &ActionInputs,
    preconditions: &BTreeMap<String, String>,
) -> Result<[u8; 32], MutationError> {
    let canonical = canonicalize_json(&json!({
        "action": action.id,
        "route": action.route,
        "input": input_values,
        "preconditions": preconditions,
    }))
    .map_err(|_| MutationError::InvalidRequest)?;
    Ok(Sha256::digest(canonical).into())
}

// Admission state is created once, before protected external processing. It
// retains all identity and request bindings across confirmed SQL aborts.
pub(crate) struct PreparedEvidenceAction {
    pub(crate) action: CompiledAction,
    pub(crate) inputs: ActionInputs,
    pub(crate) commit_requests: Vec<(CompiledEvidenceCapability, EvidenceSubjects)>,
    preconditions: BTreeMap<String, String>,
    binding: crate::idempotency::ResolvedIdempotencyBinding,
    reserved_creates: BTreeMap<String, Uuid>,
    application_id: Uuid,
    /// The action's attempt, held across Evidence evaluation until the
    /// finalize terminal or refusal answers it. Dropping the admission
    /// before that answers the attempt as unfinished.
    attempt: Option<AuditRequest>,
}

impl MutationTransaction {
    /// Admit an Evidence action, recording its refusal when admission fails
    /// before the deadline. A successful admission carries the held attempt
    /// to [`Self::finalize_evidence_action`]; a recovered receipt answers it.
    #[allow(clippy::too_many_arguments)]
    async fn action_commit_evidence_requests(
        &self,
        transaction: &Transaction<'_>,
        registry: &CompiledRegistry,
        action: &CompiledAction,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        inputs: &ActionInputs,
    ) -> Result<Vec<(CompiledEvidenceCapability, EvidenceSubjects)>, MutationError> {
        let mut records = BTreeMap::new();
        for (input_id, fields) in crate::commit_evidence::target_fields(&action.commit_evidence) {
            let input = action
                .inputs
                .iter()
                .find(|input| input.id == input_id)
                .ok_or(MutationError::InvalidRequest)?;
            let FieldTypeSource::Reference { target, .. } = &input.field_type else {
                return Err(MutationError::InvalidRequest);
            };
            let record_id = input_record_id(inputs, &input_id)?;
            let uuid = Uuid::parse_str(&record_id).map_err(|_| MutationError::InvalidRequest)?;
            let entity = registry
                .entities()
                .get(target)
                .ok_or(MutationError::InvalidRequest)?;
            let context = action_link_context(
                registry,
                action,
                &input_id,
                target,
                claims,
                target_authority,
                uuid,
                &self.expected.activation_id,
            )?;
            transaction
                .execute(
                    "SELECT set_config('registry.immediate_action_target_context', '', true),
                        set_config('registry.immediate_action_link_context', $1, true)",
                    &[&context.canonical_context()],
                )
                .await
                .map_err(map_database_error)?;
            let current = load_action_row(transaction, entity, &record_id, false).await?;
            context
                .authorize_row(entity, &current.data, uuid)
                .map_err(|_| MutationError::PreconditionFailed)?;
            let values = fields
                .into_iter()
                .map(|field| {
                    current
                        .data
                        .get(&field)
                        .cloned()
                        .map(|value| (field, value))
                        .ok_or(MutationError::PreconditionFailed)
                })
                .collect::<Result<Map<_, _>, _>>()?;
            records.insert(input_id, values);
        }
        transaction
            .execute(
                "SELECT set_config('registry.immediate_action_link_context', '', true)",
                &[],
            )
            .await
            .map_err(map_database_error)?;
        crate::commit_evidence::requests(&action.commit_evidence, inputs, &records)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn preflight_evidence_action(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: ImmediateActionInput<'_>,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        deadline: tokio::time::Instant,
    ) -> Result<Result<PreparedEvidenceAction, MutationOutcome>, MutationError> {
        let route_id = input.route_id;
        let correlation = input.correlation;
        let mut attempt = None;
        let result = self
            .preflight_evidence_action_holding(
                client,
                registry,
                input,
                claims,
                target_authority,
                deadline,
                &mut attempt,
            )
            .await;
        if failure_is_refusal(&result) && tokio::time::Instant::now() < deadline {
            self.record_action_boundary_audit(
                claims,
                route_id,
                correlation,
                PreIoAuditKind::Refusal,
            )
            .await?;
        }
        let result = result.map_err(|error| match error {
            MutationError::CommitUnresolved => MutationError::Unavailable,
            other => other,
        })?;
        Ok(match result {
            Ok(mut prepared) => {
                prepared.attempt = attempt;
                Ok(prepared)
            }
            Err(receipt) => Err(receipt),
        })
    }

    /// Admission itself. The attempt it begins is left in `attempt`, so the
    /// caller answers it on every path.
    #[allow(clippy::too_many_arguments)]
    async fn preflight_evidence_action_holding(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        input: ImmediateActionInput<'_>,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        deadline: tokio::time::Instant,
        attempt: &mut Option<AuditRequest>,
    ) -> Result<Result<PreparedEvidenceAction, MutationOutcome>, MutationError> {
        if !profile_is_keyed(self.audit.profile()) {
            return Err(MutationError::Unavailable);
        }
        let action = action_for_route(
            registry,
            input.action_id,
            input.route_id,
            ActionRouteKind::Invoke,
        )?;
        validate_action_claims(action, claims, Operation::Invoke)?;
        let normalized = validate_action_input(action, input.input)?;
        validate_precondition_set(action, &input.preconditions)?;
        *attempt = Some(
            self.begin_action_boundary_audit(claims, input.route_id, input.correlation)
                .await?,
        );
        let binding = resolve_action_binding(
            self.audit.profile(),
            &self.idempotency,
            &ActionIdempotencyBinding {
                key: input.idempotency_key,
                context: claims,
                method: HttpMethod::Post,
                route: &action.route,
                package_revision: &self.expected.activation_id,
                action_contract_fingerprint: &action.definition_revision,
                target_authority,
                result_effects: claims.result_effects(),
                answer_digest: None,
                canonical_request_digest: canonical_action_request_digest(
                    action,
                    &normalized,
                    &input.preconditions,
                )?,
            },
        )?;
        let application_id = Uuid::new_v4();
        let transaction = begin_action_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        transaction
            .set_statement_budget(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await
            .map_err(|_| MutationError::Unavailable)?;
        if let Some((outcome, entry)) = self
            .recover_action_receipt(
                transaction.transaction(),
                registry,
                action,
                claims,
                target_authority,
                &binding,
                input.route_id,
                input.correlation,
            )
            .await?
        {
            check_current_action_grant(claims)?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::CommitUnresolved)?;
            self.audit
                .append(entry)
                .await
                .map_err(|_| MutationError::CommitUnresolved)?;
            check_current_action_grant(claims)?;
            return Ok(Err(outcome));
        }
        // This transaction proves current admission only. Its locks and entire
        // pooled connection are released before any Evidence request.
        let guard_failure = self
            .lock_existing_action_targets(
                transaction.transaction(),
                registry,
                action,
                claims,
                target_authority,
                &normalized,
                application_id,
                &input.preconditions,
            )
            .await?;
        self.verify_action_link_references(
            transaction.transaction(),
            registry,
            action,
            claims,
            target_authority,
            &normalized,
        )
        .await?;
        self.lock_action_patch_targets(
            transaction.transaction(),
            registry,
            action,
            claims,
            target_authority,
            &normalized,
            &input.preconditions,
            application_id,
        )
        .await?;
        let commit_requests = self
            .action_commit_evidence_requests(
                transaction.transaction(),
                registry,
                action,
                claims,
                target_authority,
                &normalized,
            )
            .await?;
        check_current_action_grant(claims)?;
        // As at commit, a failed field guard answers only after every other
        // admission check passed, and no Evidence is requested for it.
        if let Some(input) = guard_failure {
            return Err(MutationError::FieldGuardFailed { input });
        }
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        Ok(Ok(PreparedEvidenceAction {
            action: action.clone(),
            inputs: normalized,
            commit_requests,
            preconditions: input.preconditions,
            binding,
            reserved_creates: reserve_action_create_ids(action)?,
            application_id,
            attempt: None,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_evidence_action(
        &self,
        client: &mut Client,
        registry: &CompiledRegistry,
        prepared: &PreparedEvidenceAction,
        frozen: &FrozenEvidenceEvaluation,
        claims: &ActionClaimContext,
        target_authority: &BTreeMap<String, Vec<RowBoundaryContext>>,
        route_id: &str,
        correlation: &RequestCorrelation,
        fault: FaultControl,
        deadline: tokio::time::Instant,
    ) -> Result<MutationOutcome, MutationError> {
        validate_action_claims(&prepared.action, claims, Operation::Invoke)?;
        let mut candidate = None;
        let mut retries = 0;
        let result = loop {
            let result = self
                .execute_immediate_action_after_attempt(
                    client,
                    registry,
                    &prepared.action,
                    claims,
                    target_authority,
                    &prepared.inputs,
                    &prepared.preconditions,
                    &prepared.binding,
                    &prepared.reserved_creates,
                    prepared.application_id,
                    route_id,
                    correlation,
                    fault,
                    deadline,
                    &mut candidate,
                    Some(frozen),
                    Some(&prepared.commit_requests),
                    None,
                )
                .await;
            if matches!(result, Err(MutationError::RetryableConflict))
                && retries < 2
                && !fault.is_enabled()
            {
                retries += 1;
                continue;
            }
            break result;
        };
        if failure_is_refusal(&result)
            && !fault.is_enabled()
            && tokio::time::Instant::now() < deadline
        {
            self.record_action_boundary_audit(
                claims,
                route_id,
                correlation,
                PreIoAuditKind::Refusal,
            )
            .await?;
        }
        result.map_err(|error| match error {
            MutationError::RetryableConflict | MutationError::CommitUnresolved => {
                MutationError::Unavailable
            }
            other => other,
        })
    }
}

fn verify_action_commit_evidence(
    action: &CompiledAction,
    inputs: &ActionInputs,
    frozen: &FrozenEvidenceEvaluation,
) -> Result<(), MutationError> {
    let count = action.commit_evidence.len();
    if count > frozen.acquisitions.len() {
        return Err(MutationError::PreconditionFailed);
    }
    crate::commit_evidence::verify(
        &action.commit_evidence,
        inputs,
        |id| {
            action.inputs.iter().any(|input| {
                input.id == id && matches!(input.field_type, FieldTypeSource::Timestamp)
            })
        },
        &frozen.acquisitions[frozen.acquisitions.len() - count..],
    )
}

fn validate_frozen_evidence(frozen: &FrozenEvidenceEvaluation) -> Result<(), MutationError> {
    let now = chrono::Utc::now();
    for acquisition in &frozen.acquisitions {
        acquisition
            .validate_acceptance(now)
            .map_err(|_| MutationError::ActionEvidenceFailure {
                capability: Some(acquisition.capability_id().to_owned()),
            })?;
    }
    Ok(())
}

async fn insert_action_evidence(
    transaction: &Transaction<'_>,
    application_id: Uuid,
    frozen: &FrozenEvidenceEvaluation,
) -> Result<(), MutationError> {
    let mut bytes = 0usize;
    if frozen.acquisitions.len() > 2 {
        return Err(MutationError::Unavailable);
    }
    for (ordinal, acquisition) in frozen.acquisitions.iter().enumerate() {
        let retained = acquisition
            .retained_serialization()
            .map_err(MutationError::from)?;
        bytes = bytes
            .checked_add(
                crate::action_evidence_client::retained_jsonb_bytes(&retained)
                    .map_err(MutationError::from)?,
            )
            .ok_or(MutationError::Unavailable)?;
        if bytes > crate::action_evidence::MAXIMUM_RETAINED_EVIDENCE_BYTES {
            return Err(MutationError::Unavailable);
        }
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_action_evidence_uses
            (application_id, ordinal, retained, expires_at) VALUES ($1, $2, $3, $4)",
                &[
                    &application_id,
                    &(ordinal as i16),
                    &retained,
                    &acquisition.retention_expires_at(),
                ],
            )
            .await
            .map_err(map_database_error)?;
    }
    Ok(())
}

/// Erase only expired protected Evidence material with the migration role.
/// This covers both immediate Action and durable Proposal application uses.
/// Runtime roles have INSERT only; history erasure has a separate scope.
/// A future cutoff cannot erase material whose retention has not expired.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub(crate) async fn erase_expired_action_evidence(
    client: &tokio_postgres::Transaction<'_>,
    before: chrono::DateTime<chrono::Utc>,
) -> Result<u64, MutationError> {
    let action_uses = client
        .execute(
            "DELETE FROM registry_internal.registry_action_evidence_uses
        WHERE expires_at <= LEAST($1, CURRENT_TIMESTAMP)",
            &[&before],
        )
        .await
        .map_err(map_database_error)?;
    let proposal_uses = client
        .execute(
            "DELETE FROM registry_internal.registry_proposal_evidence_uses
        WHERE expires_at <= LEAST($1, CURRENT_TIMESTAMP)",
            &[&before],
        )
        .await
        .map_err(map_database_error)?;
    action_uses
        .checked_add(proposal_uses)
        .ok_or(MutationError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_action_binding_keeps_the_released_canonical_shape() {
        let profile = AuditProfile::unkeyed_dev_only();
        let result_effects = BTreeSet::from(["created".to_owned()]);
        let claims = ActionClaimContext::new(
            "register".to_owned(),
            "principal".to_owned(),
            "operator".to_owned(),
            None,
            result_effects.clone(),
        )
        .expect("action claims are valid");
        let target_authority = BTreeMap::new();
        let request_digest = [7_u8; 32];
        let policy = IdempotencyPolicy::default();
        let binding = resolve_action_binding(
            &profile,
            &policy,
            &ActionIdempotencyBinding {
                key: "ordinary-action-key",
                context: &claims,
                method: HttpMethod::Post,
                route: "/v1/actions/register",
                package_revision: "package-revision",
                action_contract_fingerprint: "sha256:contract",
                target_authority: &target_authority,
                result_effects: &result_effects,
                canonical_request_digest: request_digest,
                answer_digest: None,
            },
        )
        .expect("ordinary action binding resolves");

        let canonical_context =
            crate::idempotency::canonical_action_context(&profile, &claims, "package-revision")
                .expect("action context canonicalizes");
        let legacy = canonicalize_json(&json!({
            "context": canonical_context,
            "method": "POST",
            "route": "/v1/actions/register",
            "packageRevision": "package-revision",
            "actionContractFingerprint": "sha256:contract",
            "targetAuthority": Vec::<Value>::new(),
            "resultEffects": result_effects,
            "canonicalRequestDigest": hex::encode(request_digest),
        }))
        .expect("legacy binding canonicalizes");
        let legacy = std::str::from_utf8(&legacy).expect("canonical JSON is UTF-8");
        let expected = profile
            .key_hasher()
            .audit_reference_hash(
                "breg-action-idempotency-binding-v1",
                "package-revision",
                legacy,
            )
            .expect("legacy binding hashes");
        assert_eq!(
            binding.request_reference, expected,
            "an absent hook answer digest must not add a null member to released action receipts"
        );
        assert!(
            binding.binding_reference.starts_with("sha256:"),
            "the spent-key binding is independent of the audit hash key"
        );

        let answer_digest = [9_u8; 32];
        let hook_binding = resolve_action_binding(
            &profile,
            &policy,
            &ActionIdempotencyBinding {
                key: "ordinary-action-key",
                context: &claims,
                method: HttpMethod::Post,
                route: "/v1/actions/register",
                package_revision: "package-revision",
                action_contract_fingerprint: "sha256:contract",
                target_authority: &target_authority,
                result_effects: claims.result_effects(),
                canonical_request_digest: request_digest,
                answer_digest: Some(&answer_digest),
            },
        )
        .expect("hook action binding resolves");
        assert_ne!(
            hook_binding.request_reference, expected,
            "a hook answer digest still binds the exact accepted answer"
        );
        assert_ne!(
            hook_binding.binding_reference, binding.binding_reference,
            "a hook answer digest still binds the exact accepted answer"
        );
    }

    #[test]
    fn hook_receipts_do_not_share_the_caller_key_namespace() {
        let profile = AuditProfile::unkeyed_dev_only();
        let key = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let delivery = "compiled-delivery";
        let claims = ActionClaimContext::new(
            "register".to_owned(),
            delivery.to_owned(),
            "operator".to_owned(),
            None,
            BTreeSet::from(["created".to_owned()]),
        )
        .expect("action claims are valid");
        let target_authority = BTreeMap::new();
        let binding = ActionIdempotencyBinding {
            key,
            context: &claims,
            method: HttpMethod::Post,
            route: "/v1/actions/register",
            package_revision: "package-revision",
            action_contract_fingerprint: "sha256:contract",
            target_authority: &target_authority,
            result_effects: claims.result_effects(),
            canonical_request_digest: [7_u8; 32],
            answer_digest: None,
        };
        let policy = IdempotencyPolicy::default();

        let caller_reference = resolve_action_binding(&profile, &policy, &binding)
            .expect("caller key resolves")
            .key_reference;
        let hook_reference =
            resolve_hook_key_reference(delivery, key).expect("hook receipt key resolves");
        let hook_binding_reference =
            resolve_hook_action_binding(&profile, &policy, delivery, &binding)
                .expect("hook binding resolves")
                .key_reference;

        assert_eq!(hook_reference, hook_binding_reference);
        assert_ne!(
            caller_reference, hook_reference,
            "a caller whose subject equals a delivery id still cannot reach its key"
        );
    }

    #[test]
    fn fixed_optional_from_input_has_the_same_type_contract_at_admission_and_materialization() {
        let project = crate::contract::parse_project_yaml(include_bytes!(
            "../../tests/fixtures/fixed-optional-action-input.yaml"
        ))
        .unwrap();
        let registry = crate::compiler::compile_project(
            &project,
            &[],
            crate::compiler::CompileProfile::Authoring,
        )
        .unwrap();
        let action = &registry.actions().actions[0];
        let entity = &registry.entities()["entry"];
        let effect = &action.effects[0];
        assert!(action.handler.is_none());
        let value = Map::from_iter([("label".to_owned(), json!("A label"))]);
        assert_eq!(validate_action_input(action, value.clone()).unwrap(), value);
        assert_eq!(
            action_effect_document(action, entity, effect, &value, &BTreeMap::new(), None).unwrap(),
            value
        );

        let null = Map::from_iter([("label".to_owned(), Value::Null)]);
        assert!(matches!(
            action_effect_document(action, entity, effect, &null, &BTreeMap::new(), None),
            Err(MutationError::InvalidRequest)
        ));
        assert!(matches!(
            validate_action_input(action, null),
            Err(MutationError::InvalidRequest)
        ));
    }

    #[test]
    fn absent_optional_fixed_inputs_leave_their_fields_out_of_create_and_patch_documents() {
        let project = crate::contract::parse_project_yaml(include_bytes!(
            "../../tests/fixtures/absent-optional-action-inputs.yaml"
        ))
        .unwrap();
        let registry = crate::compiler::compile_project(
            &project,
            &[],
            crate::compiler::CompileProfile::Authoring,
        )
        .unwrap();
        let entity = &registry.entities()["entry"];
        let actions = &registry.actions().actions;
        let create = actions.iter().find(|a| a.id == "create-entry").unwrap();
        let update = actions.iter().find(|a| a.id == "update-entry").unwrap();

        let create_input = Map::from_iter([
            ("label".to_owned(), json!("A label")),
            ("jurisdiction".to_owned(), json!("zone-a")),
        ]);
        let create_input = validate_action_input(create, create_input).unwrap();
        assert_eq!(
            action_effect_document(
                create,
                entity,
                &create.effects[0],
                &create_input,
                &BTreeMap::new(),
                None
            )
            .unwrap(),
            Map::from_iter([
                ("jurisdiction".to_owned(), json!("zone-a")),
                ("label".to_owned(), json!("A label")),
            ]),
            "absent optional scalar and reference inputs take their fields' ordinary absent values on create"
        );

        let update_input = Map::from_iter([
            (
                "entry".to_owned(),
                json!("00000000-0000-4000-8000-000000000001"),
            ),
            ("status".to_owned(), json!("reviewed")),
        ]);
        let update_input = validate_action_input(update, update_input).unwrap();
        assert_eq!(
            action_effect_document(
                update,
                entity,
                &update.effects[0],
                &update_input,
                &BTreeMap::new(),
                None
            )
            .unwrap(),
            Map::from_iter([("status".to_owned(), json!("reviewed"))]),
            "an absent optional input leaves the field unchanged on patch"
        );

        let missing_required = Map::from_iter([(
            "entry".to_owned(),
            json!("00000000-0000-4000-8000-000000000001"),
        )]);
        assert!(matches!(
            validate_action_input(update, missing_required.clone()),
            Err(MutationError::InvalidRequest)
        ));
        assert!(
            matches!(
                action_effect_document(
                    update,
                    entity,
                    &update.effects[0],
                    &missing_required,
                    &BTreeMap::new(),
                    None
                ),
                Err(MutationError::InvalidRequest)
            ),
            "an absent required input still refuses the request"
        );
    }

    #[test]
    fn internal_action_admission_keeps_null_specific_to_functions() {
        let mut project = crate::contract::parse_project_yaml(include_bytes!(
            "../../../../products/breg/examples/facility/registry.yaml"
        ))
        .unwrap();
        project
            .actions
            .iter_mut()
            .find(|action| action.id == "correct-address")
            .unwrap()
            .inputs
            .iter_mut()
            .find(|input| input.id == "city")
            .unwrap()
            .required = false;
        let registry = crate::compiler::compile_project_with_assets(
            &project,
            &[],
            &[crate::contract::ModuleAssetSource {
                module: None,
                path: "plans/correct-address.rhai".into(),
                bytes: include_bytes!(
                    "../../../../products/breg/examples/facility/plans/correct-address.rhai"
                )
                .to_vec(),
            }],
            crate::compiler::CompileProfile::Authoring,
        )
        .unwrap();
        let mut action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == "correct-address")
            .unwrap()
            .clone();
        let input = json!({"facility":"00000000-0000-4000-8000-000000000001",
            "address-line":"1 Main Road","postal-code":"10200","city":null})
        .as_object()
        .unwrap()
        .clone();
        assert!(validate_action_input(&action, input.clone()).is_ok());
        action.handler = None;
        assert!(matches!(
            validate_action_input(&action, input),
            Err(MutationError::InvalidRequest)
        ));
    }

    #[test]
    fn aliased_patch_group_waits_for_every_selected_create_dependency() {
        let effect = |id: &str, operation, dependencies: &[&str]| CompiledPlanEffect {
            id: id.to_owned(),
            target: crate::model::CompiledPlanTarget {
                entity_id: "synthetic".to_owned(),
                binding: if operation == Operation::Create {
                    CompiledPlanTargetBinding::Create
                } else {
                    CompiledPlanTargetBinding::Existing {
                        input: "target".to_owned(),
                    }
                },
            },
            operation,
            mutations: vec![],
            depends_on: dependencies.iter().map(|id| (*id).to_owned()).collect(),
        };
        let first_patch = effect("first-patch", Operation::Patch, &[]);
        let create = effect("create", Operation::Create, &[]);
        let dependent_patch = effect("dependent-patch", Operation::Patch, &["create"]);
        let groups = crate::plan::order_effect_groups(
            vec![vec![&first_patch, &dependent_patch], vec![&create]],
            |effect| effect.id.as_str(),
            |effect| &effect.depends_on,
        )
        .unwrap();
        assert_eq!(groups[0][0].id, "create");
        assert_eq!(
            groups[1]
                .iter()
                .map(|effect| effect.id.as_str())
                .collect::<Vec<_>>(),
            ["first-patch", "dependent-patch"]
        );
    }
}
