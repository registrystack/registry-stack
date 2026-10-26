// SPDX-License-Identifier: Apache-2.0
//! One bounded step per tick, with leases and checkpoints owned by Dispatch.

use crate::{
    contracts::CompletionContract,
    definition::{CompletionKind, Step},
    metrics::StepAttempt,
    protocol::{AdapterSet, CallOutcome, CallRequest, CompletionObservation},
    store::{Detail, FrozenCommand, Job, Store, RETRY_MAXIMUM_DELAY, WAIT_READ_SPACING_SECONDS},
    CoordinatorError, Result,
};
use async_trait::async_trait;
use registry_platform_dispatch::postgres::{DispatchOutcome, DispatchTransport, LeasedJob};
use registry_platform_dispatch::{DispatchError, FailureCode, SendOutcome, Sent};
use serde_json::Value;
use std::{sync::Arc, time::Duration};

pub struct Worker {
    store: Arc<Store>,
    adapters: Arc<dyn AdapterSet>,
}
impl Worker {
    pub fn new(store: Arc<Store>, adapters: Arc<dyn AdapterSet>) -> Self {
        Self { store, adapters }
    }
    pub async fn tick(&self) -> Result<bool> {
        let result = self
            .store
            .dispatcher()?
            .dispatch_once(self)
            .await
            .map_err(|_| {
                CoordinatorError::new(
                    "worker-unavailable",
                    "the durable worker could not complete this tick",
                )
            })?;
        Ok(result != DispatchOutcome::Idle)
    }
}
fn accepted(detail: Detail) -> Sent<Detail> {
    Sent {
        outcome: SendOutcome::Accepted {
            receiver_reference: None,
        },
        detail,
    }
}
fn failed(code: &'static str, uncertain: bool) -> Sent<Detail> {
    Sent {
        outcome: if uncertain {
            SendOutcome::MaybeSent
        } else {
            SendOutcome::Permanent {
                code: FailureCode::new(code).expect("static bounded code"),
            }
        },
        detail: Detail::failure(code, uncertain),
    }
}
/// Only reviewed categories may become persisted operator diagnostics.
fn safe_code(code: &str, fallback: &'static str) -> &'static str {
    match code {
        "credential-unavailable" => "credential-unavailable",
        "credential-configuration" => "credential-configuration",
        "credential-refused" => "credential-refused",
        "product-forbidden" => "product-forbidden",
        "product-not-found" => "product-not-found",
        "product-refused" => "product-refused",
        "invalid-command" => "invalid-command",
        "invalid-response" => "invalid-response",
        "transport-unavailable" => "transport-unavailable",
        "transport-uncertain" => "transport-uncertain",
        "rate-limited" => "rate-limited",
        "operation-unbound" => "operation-unbound",
        "attempt-timeout" => "attempt-timeout",
        _ => crate::operations::failure_code(code).unwrap_or(fallback),
    }
}

fn advance(next: String, output: Option<Value>) -> Detail {
    Detail {
        next: Some(next),
        output,
        outcome: None,
        failure_code: None,
        failure_path: None,
        uncertain: false,
        recovery_hold: false,
        observation_pause_seconds: None,
        receipt_expired: false,
        completed_without_effect: false,
        recheck_seconds: None,
    }
}

fn call_result(
    result: CallOutcome,
    next: &str,
    on_declared_refusal: Option<&str>,
    uncertain: bool,
) -> Sent<Detail> {
    match result {
        CallOutcome::Success(value) => accepted(advance(next.to_owned(), Some(value))),
        CallOutcome::Retryable { code, retry_after } if !uncertain => Sent {
            outcome: SendOutcome::Transient { retry_after },
            detail: Detail::failure(safe_code(&code, "remote-retryable"), false),
        },
        CallOutcome::Retryable { code, .. } => failed(safe_code(&code, "remote-retryable"), true),
        // The retry is automatic, and the attempt stays uncertain so that an
        // expiry before a later attempt settles it holds the run.
        CallOutcome::UncertainRetryable { code, retry_after } => Sent {
            outcome: SendOutcome::Transient { retry_after },
            detail: Detail::failure(safe_code(&code, "remote-uncertain"), true),
        },
        CallOutcome::Refused { code } => failed(safe_code(&code, "remote-refused"), uncertain),
        CallOutcome::DeclaredRefusal(refusal) if !uncertain => {
            let Some(step) = on_declared_refusal else {
                return failed("product-refused", false);
            };
            let Ok(output) = serde_json::to_value(refusal) else {
                return failed("invalid-response", false);
            };
            let mut detail = advance(step.to_owned(), Some(output));
            detail.completed_without_effect = true;
            accepted(detail)
        }
        CallOutcome::DeclaredRefusal(_) => failed("product-refused", true),
        CallOutcome::Uncertain { code } => failed(safe_code(&code, "remote-uncertain"), true),
        CallOutcome::ReceiptExpired => {
            let mut sent = failed("receipt-expired", true);
            sent.detail.receipt_expired = true;
            sent
        }
    }
}

/// One authenticated observation. Business refusal is a typed terminal result;
/// unavailable or invalid evidence can never enter a success/refusal edge.
fn wait_result(
    contract: &CompletionContract,
    read: Option<CompletionObservation>,
    next: &str,
    on_timeout: Option<&str>,
    timed_out: bool,
    recheck_seconds: u32,
) -> Sent<Detail> {
    let pending = |code: Option<&'static str>, hint: Option<Duration>| {
        if hint.is_some_and(|delay| {
            delay
                > Duration::from_secs(u64::from(
                    crate::operations::MAXIMUM_OBSERVATION_INTERVAL_SECONDS,
                ))
        }) {
            return held("completion-unusable-retry-after");
        }
        let seconds = hint.map(|delay| {
            u32::try_from(
                delay
                    .as_secs()
                    .saturating_add(u64::from(delay.subsec_nanos() > 0)),
            )
            .unwrap_or(u32::MAX)
        });
        let pause = seconds
            .unwrap_or(recheck_seconds)
            .max(WAIT_READ_SPACING_SECONDS);
        accepted(Detail {
            recheck_seconds: Some(pause),
            observation_pause_seconds: seconds,
            failure_code: code,
            next: None,
            ..Detail::failure("observation-pending", false)
        })
    };
    match read {
        Some(CompletionObservation::Settled(value)) => {
            if contract.check(&value).is_ok() {
                accepted(advance(next.to_owned(), Some(value)))
            } else {
                held("completion-invalid-response")
            }
        }
        Some(CompletionObservation::Hold { code }) => {
            held(safe_code(&code, "completion-unavailable"))
        }
        _ if timed_out => match on_timeout {
            Some(step) => accepted(advance(step.to_owned(), None)),
            None => failed("wait-timed-out", false),
        },
        Some(CompletionObservation::Pending { retry_after }) => pending(None, retry_after),
        Some(CompletionObservation::Retryable { code, retry_after }) => pending(
            Some(safe_code(&code, "remote-retryable")),
            retry_after.or(Some(RETRY_MAXIMUM_DELAY)),
        ),
        None => pending(Some("attempt-timeout"), Some(RETRY_MAXIMUM_DELAY)),
    }
}

fn held(code: &'static str) -> Sent<Detail> {
    let mut result = failed(code, false);
    result.detail.recovery_hold = true;
    result
}

impl Worker {
    /// One step attempt, as Dispatch receives it.
    async fn attempt(
        &self,
        job: &LeasedJob<Job>,
    ) -> std::result::Result<Sent<Detail>, DispatchError> {
        let payload = match self.store.payload(job.key.id(), job.key.part(), &job.job) {
            Ok(value) => value,
            Err(_) => return Ok(failed("protected-state-invalid", job.job.uncertain)),
        };
        let definition = match self.store.definition(&payload.snapshot) {
            Ok(value) => value,
            Err(_) => return Ok(failed("snapshot-incompatible", job.job.uncertain)),
        };
        if job.job.binding_digest != self.adapters.binding_digest_for(&definition.workflow) {
            return Ok(failed("binding-conflict", job.job.uncertain));
        }
        let Some(step) = definition.workflow.steps.get(job.key.part()) else {
            return Ok(failed("step-invalid", job.job.uncertain));
        };
        let evaluate = || definition.evaluate(job.key.part(), &payload.input, &payload.outputs);
        match step {
            // Acceptance checkpoints the timer wake. Store checks the current
            // deadline atomically before advancing the workflow at commit.
            Step::WaitUntil { next, .. } => Ok(accepted(advance(next.clone(), None))),
            Step::WaitFor {
                wait_for,
                next,
                on_timeout,
                ..
            } => {
                if !self
                    .store
                    .before_io(job, false)
                    .await
                    .map_err(|_| DispatchError::Unavailable)?
                {
                    return Ok(failed("deadline-reached", false));
                }
                let completion = match definition.completion(wait_for) {
                    Ok(completion) => completion,
                    Err(_) => return Ok(held("protected-state-invalid")),
                };
                let completion_contract = match definition.completion_contract(wait_for) {
                    Ok(contract) => contract,
                    Err(_) => return Ok(held("protected-state-invalid")),
                };
                let (Some(Step::Call { call, .. }), Some(accepted_value)) = (
                    definition.workflow.steps.get(&wait_for.step),
                    payload.outputs.get(&wait_for.step),
                ) else {
                    return Ok(held("protected-state-invalid"));
                };
                let Some(command) = self
                    .store
                    .accepted_command(job, &wait_for.step)
                    .await
                    .map_err(|_| DispatchError::Unavailable)?
                else {
                    return Ok(held("protected-state-invalid"));
                };
                let request = command.request();
                if !command.matches_call(&definition, call) {
                    return Ok(held("protected-state-invalid"));
                }
                let recheck_seconds = self
                    .adapters
                    .observation_interval(&call.connection, completion);
                let permit = self
                    .store
                    .begin_observation(
                        job,
                        self.adapters
                            .minimum_observation_interval(&call.connection, completion),
                    )
                    .await
                    .map_err(|_| DispatchError::Unavailable)?;
                let timed_out = match permit {
                    Some(crate::store::ObservationPermit::Observe { timed_out }) => timed_out,
                    Some(crate::store::ObservationPermit::Pause { seconds }) => {
                        return Ok(accepted(Detail {
                            recheck_seconds: Some(seconds),
                            failure_code: None,
                            ..Detail::failure("observation-pending", false)
                        }));
                    }
                    Some(crate::store::ObservationPermit::TimedOut) => {
                        return Ok(wait_result(
                            completion_contract,
                            None,
                            next,
                            on_timeout.as_deref(),
                            true,
                            recheck_seconds,
                        ));
                    }
                    Some(crate::store::ObservationPermit::Exhausted) => {
                        return Ok(held("observation-budget-exhausted"))
                    }
                    None => return Ok(held("protected-state-invalid")),
                };
                let Some(budget) = job.remaining_budget(std::time::SystemTime::now()) else {
                    return Ok(wait_result(
                        completion_contract,
                        None,
                        next,
                        on_timeout.as_deref(),
                        timed_out,
                        recheck_seconds,
                    ));
                };
                let read = tokio::time::timeout(budget, async {
                    if matches!(completion.kind, CompletionKind::BoundedPoll { .. }) {
                        // The only repeated command is the immutable read frozen
                        // before the original accepted call. No mutation is allowed.
                        if request.operation != crate::protocol::Operation::ExternalGet {
                            return CompletionObservation::Hold {
                                code: "operation-unbound".into(),
                            };
                        }
                        match self.adapters.call(request).await {
                            CallOutcome::Success(response) => crate::completion::interpret_poll(
                                &definition,
                                request,
                                wait_for,
                                response,
                                false,
                            ),
                            outcome => CompletionObservation::from_failure(outcome),
                        }
                    } else {
                        self.adapters
                            .observe_completion(request, accepted_value, completion)
                            .await
                    }
                })
                .await
                .ok();
                Ok(wait_result(
                    completion_contract,
                    read,
                    next,
                    on_timeout.as_deref(),
                    timed_out,
                    recheck_seconds,
                ))
            }
            Step::Choose { cases, .. } => {
                let value = match evaluate() {
                    Ok(value) => value,
                    Err(_) => return Ok(failed("mapping-invalid", false)),
                };
                let Some(next) = value.as_str().and_then(|case| cases.get(case)) else {
                    return Ok(failed("choice-invalid", false));
                };
                Ok(accepted(advance(next.clone(), None)))
            }
            Step::Finish { finish, output } => {
                let value = match output {
                    Some(_) => match evaluate() {
                        Ok(value) => value,
                        Err(_) => return Ok(failed("mapping-invalid", false)),
                    },
                    None => Value::Null,
                };
                if definition.validate_outcome(finish, &value).is_err() {
                    return Ok(failed("outcome-invalid", false));
                }
                Ok(accepted(Detail {
                    next: None,
                    output: Some(value),
                    outcome: Some(finish.clone()),
                    failure_code: None,
                    failure_path: None,
                    uncertain: false,
                    recovery_hold: false,
                    observation_pause_seconds: None,
                    receipt_expired: false,
                    completed_without_effect: false,
                    recheck_seconds: None,
                }))
            }
            Step::Call {
                call,
                next,
                on_declared_refusal,
                ..
            } => {
                // A recovery race or stale queue state cannot turn unknown
                // non-repeatable work into a second remote effect.
                if job.job.uncertain && !call.operation.can_retry_after_unknown() {
                    let code = if call.operation.is_evaluation() {
                        "evaluation-uncertain"
                    } else {
                        "mutation-uncertain"
                    };
                    return Ok(failed(code, true));
                }
                let command = if let Some(command) = &payload.command {
                    command.clone()
                } else {
                    let value = match evaluate() {
                        Ok(value) => value,
                        Err(_) => return Ok(failed("mapping-invalid", job.job.uncertain)),
                    };
                    // The input is held to the contract the adapter decodes
                    // before anything is prepared, frozen or sent. Only the
                    // declared path is recorded, never the computed value.
                    let operation = definition.workflow.operation(call);
                    let Ok(contract) = definition.operation_contract(call) else {
                        return Ok(held("snapshot-incompatible"));
                    };
                    if let Err(violation) = contract.check_input(&value) {
                        let mut sent = failed("invalid-command", job.job.uncertain);
                        sent.detail.failure_path =
                            Some(violation.declared_path(&contract.input, &value));
                        return Ok(sent);
                    }
                    let request = CallRequest {
                        connection: call.connection.clone(),
                        operation: call.operation,
                        operation_contract: operation.action.clone(),
                        input: value,
                        idempotency_key: call.operation.requires_key().then(|| {
                            self.store
                                .command_key(&job.job.start_identity, job.key.part())
                        }),
                    };
                    let preparation = if request.operation.requires_preparation() {
                        // Preparation may read current metadata and target conditions,
                        // but must never dispatch a mutation or model evaluation.
                        // A crash here can prepare
                        // again because no external effect has been dispatched.
                        if !self
                            .store
                            .before_io(job, false)
                            .await
                            .map_err(|_| DispatchError::Unavailable)?
                        {
                            return Ok(failed("deadline-reached", job.job.uncertain));
                        }
                        let Some(budget) = job.remaining_budget(std::time::SystemTime::now())
                        else {
                            return Ok(failed("attempt-timeout", job.job.uncertain));
                        };
                        let value =
                            match tokio::time::timeout(budget, self.adapters.prepare(&request))
                                .await
                            {
                                Ok(Ok(Some(value))) => Some(value),
                                Ok(Ok(None)) => {
                                    return Ok(failed("preparation-invalid", job.job.uncertain))
                                }
                                Ok(Err(CallOutcome::Success(_))) => {
                                    return Ok(failed("preparation-invalid", job.job.uncertain));
                                }
                                Ok(Err(outcome)) => {
                                    return Ok(call_result(outcome, next, None, job.job.uncertain))
                                }
                                Err(_) => {
                                    return Ok(call_result(
                                        CallOutcome::Retryable {
                                            code: "attempt-timeout".into(),
                                            retry_after: None,
                                        },
                                        next,
                                        None,
                                        job.job.uncertain,
                                    ))
                                }
                            };
                        if value.as_ref().is_some_and(|bytes| {
                            bytes.len() > crate::operations::MAXIMUM_PREPARATION_BYTES
                        }) {
                            return Ok(failed("preparation-too-large", job.job.uncertain));
                        }
                        value
                    } else {
                        None
                    };
                    self.store
                        .freeze(job, FrozenCommand::new(request, preparation))
                        .await
                        .map_err(|_| DispatchError::Unavailable)?
                };
                let request = command.request();
                if !command.matches_call(&definition, call) {
                    return Ok(failed("protected-state-invalid", job.job.uncertain));
                }
                if !self
                    .store
                    .before_io(job, request.operation.has_dispatch_risk())
                    .await
                    .map_err(|_| DispatchError::Unavailable)?
                {
                    return Ok(failed("deadline-reached", job.job.uncertain));
                }
                let Some(budget) = job.remaining_budget(std::time::SystemTime::now()) else {
                    return Ok(failed(
                        "attempt-timeout",
                        request.operation.has_dispatch_risk() || job.job.uncertain,
                    ));
                };
                // Dispatch gives up after the policy's last attempt, so a
                // receiver's busy answer on that attempt is the workflow's to see.
                let final_attempt = job.attempt >= job.policy.maximum_attempts;
                let result = tokio::time::timeout(
                    budget,
                    self.adapters
                        .call_attempt(request, command.preparation(), final_attempt),
                )
                .await;
                let result = match result {
                    Ok(result) => result,
                    Err(_) if request.operation.has_dispatch_risk() => CallOutcome::Uncertain {
                        code: "attempt-timeout".to_owned(),
                    },
                    Err(_) => CallOutcome::Retryable {
                        code: "attempt-timeout".to_owned(),
                        retry_after: None,
                    },
                };
                // A command's provider response becomes its step result only
                // through the project's pinned interpretation Function.
                let result = match result {
                    CallOutcome::Success(response)
                        if request.operation == crate::protocol::Operation::ExternalCommand =>
                    {
                        crate::external_http::interpret_command(
                            &definition,
                            call,
                            &request.input,
                            response,
                            false,
                        )
                    }
                    result => result,
                };
                let contract = definition
                    .operation_contract(call)
                    .map_err(|_| DispatchError::Unavailable)?;
                let valid = match &result {
                    CallOutcome::Success(value) => contract.check_output(value).is_ok(),
                    CallOutcome::DeclaredRefusal(refusal) => serde_json::to_value(refusal)
                        .is_ok_and(|value| contract.check_refusal(&value).is_ok()),
                    _ => true,
                };
                if !valid {
                    return Ok(failed(
                        "invalid-response",
                        request.operation.has_dispatch_risk() || job.job.uncertain,
                    ));
                }
                Ok(call_result(
                    result,
                    next,
                    on_declared_refusal.as_deref(),
                    job.job.uncertain,
                ))
            }
        }
    }
}

/// What an attempt came to, by its closed class alone. A review read that
/// failed and left its wait open counts as transient.
fn attempt_class(result: &std::result::Result<Sent<Detail>, DispatchError>) -> StepAttempt {
    match result {
        Ok(sent) => match sent.outcome {
            SendOutcome::Accepted { .. } if sent.detail.failure_code.is_some() => {
                StepAttempt::Transient
            }
            SendOutcome::Accepted { .. } => StepAttempt::Accepted,
            SendOutcome::Transient { .. } => StepAttempt::Transient,
            SendOutcome::Permanent { .. } => StepAttempt::Permanent,
            SendOutcome::MaybeSent => StepAttempt::MaybeSent,
        },
        Err(_) => StepAttempt::Unavailable,
    }
}

#[async_trait]
impl DispatchTransport for Worker {
    type Job = Job;
    type Detail = Detail;
    async fn send(&self, job: &LeasedJob<Job>) -> std::result::Result<Sent<Detail>, DispatchError> {
        let result = self.attempt(job).await;
        self.store
            .metrics()
            .record_step_attempt(attempt_class(&result));
        result
    }
}

#[cfg(all(test, feature = "postgres-test"))]
#[path = "../tests/support/leased_wait_deadline.rs"]
mod leased_wait_deadline_tests;

#[cfg(test)]
mod tests {
    use super::{attempt_class, call_result, safe_code, wait_result};
    use crate::{
        contracts::CompletionContract,
        metrics::StepAttempt,
        protocol::{CallOutcome, CompletionObservation, DeclaredRefusal},
    };
    use registry_platform_dispatch::SendOutcome;
    use serde_json::{json, Value};
    use std::time::Duration;

    fn review() -> &'static CompletionContract {
        static CONTRACT: std::sync::OnceLock<CompletionContract> = std::sync::OnceLock::new();
        CONTRACT.get_or_init(|| {
            CompletionContract::new(crate::contracts::casework_completion_schema()).unwrap()
        })
    }

    fn result(status: &str) -> Value {
        let digest = |c: char| format!("sha256:{}", c.to_string().repeat(64));
        let mut result = json!({
            "resultId": "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
            "requestId": "1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d",
            "subject": {"source": "applications", "type": "application",
                "id": "c8e1f0a2-3b4c-4d5e-8f60-7a8b9c0d1e2f", "version": "1",
                "digest": digest('a')},
            "policy": {"id": "application-review", "version": "1", "digest": digest('b')},
            "submissionDigest": digest('c'),
            "status": status,
            "completedAt": "2026-10-11T10:00:00Z",
            "availableUntil": "2026-11-11T10:00:00Z",
        });
        if status == "rejected" {
            result["outcome"] = json!("not-eligible");
        }
        result
    }

    fn wait(
        read: Option<CompletionObservation>,
        on_timeout: Option<&str>,
        timed_out: bool,
    ) -> super::Sent<super::Detail> {
        wait_result(review(), read, "decide", on_timeout, timed_out, 900)
    }

    fn permanent(sent: &super::Sent<super::Detail>) -> Option<&'static str> {
        matches!(sent.outcome, SendOutcome::Permanent { .. })
            .then_some(sent.detail.failure_code)
            .flatten()
    }

    #[test]
    fn a_settled_result_advances_with_the_result_as_the_step_output() {
        for status in [
            "approved",
            "rejected",
            "changes-requested",
            "answered",
            "cancelled",
            "superseded",
        ] {
            for timed_out in [false, true] {
                let sent = wait(
                    Some(CompletionObservation::Settled(result(status))),
                    Some("withdraw"),
                    timed_out,
                );
                assert!(
                    matches!(sent.outcome, SendOutcome::Accepted { .. }),
                    "{status}"
                );
                assert_eq!(sent.detail.next.as_deref(), Some("decide"), "{status}");
                assert_eq!(sent.detail.output, Some(result(status)), "{status}");
                assert_eq!(sent.detail.recheck_seconds, None);
            }
        }
        let mut carried = result("approved");
        carried["unexpected"] = json!("value");
        let sent = wait(Some(CompletionObservation::Settled(carried)), None, false);
        assert_eq!(permanent(&sent), Some("completion-invalid-response"));
    }

    #[test]
    fn a_pending_result_keeps_waiting_until_the_timeout() {
        let sent = wait(
            Some(CompletionObservation::Pending { retry_after: None }),
            None,
            false,
        );
        assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
        assert_eq!(sent.detail.next, None);
        assert_eq!(sent.detail.output, None);
        assert_eq!(sent.detail.recheck_seconds, Some(900));
        let sent = wait(
            Some(CompletionObservation::Pending { retry_after: None }),
            Some("withdraw"),
            true,
        );
        assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
        assert_eq!(sent.detail.next.as_deref(), Some("withdraw"));
        assert_eq!(sent.detail.output, None);
        assert_eq!(sent.detail.recheck_seconds, None);
        assert_eq!(
            permanent(&wait(
                Some(CompletionObservation::Pending { retry_after: None }),
                None,
                true
            )),
            Some("wait-timed-out")
        );
    }

    #[test]
    fn an_unreadable_result_at_the_timeout_takes_the_timeout_route() {
        let busy = || {
            Some(CompletionObservation::from_failure(
                CallOutcome::Retryable {
                    code: "rate-limited".into(),
                    retry_after: None,
                },
            ))
        };
        for read in [busy(), None] {
            let sent = wait(read, Some("withdraw"), true);
            assert_eq!(sent.detail.next.as_deref(), Some("withdraw"));
        }
        for read in [busy(), None] {
            assert_eq!(permanent(&wait(read, None, true)), Some("wait-timed-out"));
        }
    }

    #[test]
    fn a_request_the_producer_no_longer_holds_fails_with_its_own_code() {
        for timed_out in [false, true] {
            assert_eq!(
                permanent(&wait(
                    Some(CompletionObservation::Hold {
                        code: "review-request-unknown".into()
                    }),
                    Some("withdraw"),
                    timed_out
                )),
                Some("review-request-unknown")
            );
            assert_eq!(
                permanent(&wait(
                    Some(CompletionObservation::Hold {
                        code: "review-result-expired".into()
                    }),
                    Some("withdraw"),
                    timed_out
                )),
                Some("review-result-expired")
            );
            assert_eq!(
                permanent(&wait(
                    Some(CompletionObservation::from_failure(CallOutcome::Refused {
                        code: "product-forbidden".into()
                    })),
                    Some("withdraw"),
                    timed_out
                )),
                Some("product-forbidden")
            );
        }
        for outcome in [
            CallOutcome::Success(Value::Null),
            CallOutcome::ReceiptExpired,
        ] {
            assert_eq!(
                permanent(&wait(
                    Some(CompletionObservation::from_failure(outcome)),
                    None,
                    false
                )),
                Some("invalid-response")
            );
        }
        assert_eq!(
            permanent(&wait(
                Some(CompletionObservation::from_failure(CallOutcome::Refused {
                    code: "Bearer synthetic-secret-canary".into()
                })),
                None,
                false
            )),
            Some("completion-unavailable")
        );
    }

    #[test]
    fn a_failed_read_before_the_timeout_keeps_waiting_at_its_hint_or_the_retry_ceiling() {
        for (hint, expected) in [
            (None, 300),
            (Some(Duration::from_secs(5)), 30),
            (Some(Duration::from_secs(120)), 120),
            (Some(Duration::from_secs(3600)), 3600),
        ] {
            let sent = wait(
                Some(CompletionObservation::from_failure(
                    CallOutcome::Retryable {
                        code: "rate-limited".into(),
                        retry_after: hint,
                    },
                )),
                None,
                false,
            );
            assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
            assert_eq!(sent.detail.next, None);
            assert_eq!(sent.detail.output, None);
            assert_eq!(sent.detail.recheck_seconds, Some(expected), "{hint:?}");
            assert_eq!(sent.detail.failure_code, Some("rate-limited"));
            assert_eq!(attempt_class(&Ok(sent)), StepAttempt::Transient);
        }
        let sent = wait(None, None, false);
        assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
        assert_eq!(sent.detail.recheck_seconds, Some(300));
        assert_eq!(sent.detail.failure_code, Some("attempt-timeout"));
        let sent = wait_result(review(), None, "decide", None, false, 120);
        assert_eq!(
            sent.detail.recheck_seconds,
            Some(300),
            "a failed transport retains its bounded retry pause"
        );
        assert_eq!(attempt_class(&Ok(sent)), StepAttempt::Transient);
        assert_eq!(
            attempt_class(&Ok(wait(
                Some(CompletionObservation::Pending { retry_after: None }),
                None,
                false
            ))),
            StepAttempt::Accepted
        );
    }

    #[test]
    fn a_product_pause_hint_reaches_the_retry_schedule_only_for_definite_retries() {
        let rate_limited = |retry_after| CallOutcome::Retryable {
            code: "rate-limited".into(),
            retry_after,
        };
        let hint = Some(Duration::from_secs(30));
        let sent = call_result(rate_limited(hint), "next", None, false);
        assert_eq!(sent.outcome, SendOutcome::Transient { retry_after: hint });
        assert_eq!(sent.detail.failure_code, Some("rate-limited"));
        assert_eq!(
            call_result(rate_limited(None), "next", None, false).outcome,
            SendOutcome::Transient { retry_after: None }
        );
        // An attempt after an unknown outcome stays held: a hint never turns
        // it into an automatic resend.
        assert_eq!(
            call_result(rate_limited(hint), "next", None, true).outcome,
            SendOutcome::MaybeSent
        );
    }

    #[test]
    fn a_busy_answer_that_may_follow_an_effect_retries_with_the_effect_unknown() {
        let unavailable = |code: &str, retry_after| CallOutcome::UncertainRetryable {
            code: code.into(),
            retry_after,
        };
        let hint = Some(Duration::from_secs(30));
        // The retry is scheduled like a definite one, and the attempt stays
        // uncertain, so an expiry before a later attempt settles it holds the
        // run instead of ending it.
        for prior_uncertainty in [false, true] {
            let sent = call_result(
                unavailable("external-unavailable", hint),
                "next",
                None,
                prior_uncertainty,
            );
            assert_eq!(sent.outcome, SendOutcome::Transient { retry_after: hint });
            assert_eq!(sent.detail.failure_code, Some("external-unavailable"));
            assert!(sent.detail.uncertain);
            assert_eq!(sent.detail.next, None);
            assert_eq!(sent.detail.output, None);
        }
        let sent = call_result(
            unavailable("Bearer synthetic-secret-canary", None),
            "next",
            None,
            false,
        );
        assert_eq!(sent.outcome, SendOutcome::Transient { retry_after: None });
        assert_eq!(sent.detail.failure_code, Some("remote-uncertain"));
    }

    #[test]
    fn an_unusable_completion_pause_is_held_instead_of_shortened() {
        let delay = Some(Duration::from_secs(
            u64::from(crate::operations::MAXIMUM_OBSERVATION_INTERVAL_SECONDS) + 1,
        ));
        for observation in [
            CompletionObservation::Pending { retry_after: delay },
            CompletionObservation::Retryable {
                code: "rate-limited".into(),
                retry_after: delay,
            },
        ] {
            let sent = wait(Some(observation), None, false);
            assert_eq!(permanent(&sent), Some("completion-unusable-retry-after"));
            assert_eq!(sent.detail.recheck_seconds, None);
            assert_eq!(sent.detail.output, None);
        }
    }

    #[test]
    fn declared_refusal_routes_only_with_opt_in_and_no_prior_uncertainty() {
        let refusal =
            || CallOutcome::DeclaredRefusal(DeclaredRefusal::new("label-not-eligible").unwrap());
        let routed = call_result(refusal(), "success", Some("not-eligible"), false);
        assert!(matches!(routed.outcome, SendOutcome::Accepted { .. }));
        assert_eq!(routed.detail.next.as_deref(), Some("not-eligible"));
        assert_eq!(
            routed.detail.output,
            Some(json!({"refusalCode":"label-not-eligible"}))
        );
        assert!(routed.detail.completed_without_effect);

        for prior_uncertainty in [false, true] {
            let refused = call_result(refusal(), "success", None, prior_uncertainty);
            assert_eq!(refused.detail.failure_code, Some("product-refused"));
            assert_eq!(refused.detail.next, None);
            assert_eq!(refused.detail.output, None);
            assert_eq!(
                refused.outcome,
                if prior_uncertainty {
                    SendOutcome::MaybeSent
                } else {
                    SendOutcome::Permanent {
                        code: registry_platform_dispatch::FailureCode::new("product-refused")
                            .unwrap(),
                    }
                }
            );
        }
        let held = call_result(refusal(), "success", Some("not-eligible"), true);
        assert_eq!(held.outcome, SendOutcome::MaybeSent);
        assert_eq!(held.detail.next, None);
        assert_eq!(held.detail.failure_code, Some("product-refused"));
        assert!(!held.detail.completed_without_effect);
    }

    #[test]
    fn operator_codes_preserve_reviewed_categories_and_scrub_runtime_text() {
        for code in [
            "review-result-expired",
            "action-contract-changed",
            "target-conditions-mismatch",
            "external-rate-limited",
        ] {
            assert_eq!(safe_code(code, "completion-unavailable"), code);
        }
        assert_eq!(
            safe_code("credential-refused", "remote-refused"),
            "credential-refused"
        );
        assert_eq!(
            safe_code("credential-configuration", "remote-refused"),
            "credential-configuration"
        );
        assert_eq!(
            safe_code("rate-limited", "remote-retryable"),
            "rate-limited"
        );
        assert_eq!(
            safe_code("Bearer synthetic-secret-canary", "remote-refused"),
            "remote-refused"
        );
        assert_eq!(
            safe_code("403-canary-secret", "remote-refused"),
            "remote-refused"
        );
    }
}
