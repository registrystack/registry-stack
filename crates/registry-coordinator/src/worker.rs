// SPDX-License-Identifier: Apache-2.0
//! One bounded step per tick, with leases and checkpoints owned by Dispatch.

use crate::{
    contracts::contract,
    definition::Step,
    metrics::StepAttempt,
    protocol::{AdapterSet, CallOutcome, CallRequest},
    store::{Detail, FrozenCommand, Job, Store},
    CoordinatorError, Result,
};
use async_trait::async_trait;
use registry_platform_dispatch::postgres::{DispatchOutcome, DispatchTransport, LeasedJob};
use registry_platform_dispatch::{DispatchError, FailureCode, SendOutcome, Sent};
use serde_json::Value;
use std::sync::Arc;

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
        receipt_expired: false,
    }
}

fn call_result(result: CallOutcome, next: &str, uncertain: bool) -> Sent<Detail> {
    match result {
        CallOutcome::Success(value) => accepted(advance(next.to_owned(), Some(value))),
        CallOutcome::Retryable { code, retry_after } if !uncertain => Sent {
            outcome: SendOutcome::Transient { retry_after },
            detail: Detail::failure(safe_code(&code, "remote-retryable"), false),
        },
        CallOutcome::Retryable { code, .. } => failed(safe_code(&code, "remote-retryable"), true),
        CallOutcome::Refused { code } => failed(safe_code(&code, "remote-refused"), uncertain),
        CallOutcome::Uncertain { code } => failed(safe_code(&code, "remote-uncertain"), true),
        CallOutcome::ReceiptExpired => {
            let mut sent = failed("receipt-expired", true);
            sent.detail.receipt_expired = true;
            sent
        }
    }
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
                    receipt_expired: false,
                }))
            }
            Step::Call { call, next, .. } => {
                // A recovery race or stale queue state cannot turn unknown
                // inference completion into a second provider evaluation.
                if job.job.uncertain && !call.operation.can_retry_after_unknown() {
                    return Ok(failed("evaluation-uncertain", true));
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
                    if let Err(violation) = contract(call.operation).check_input(&value) {
                        let mut sent = failed("invalid-command", job.job.uncertain);
                        sent.detail.failure_path = Some(violation.declared_path().to_owned());
                        return Ok(sent);
                    }
                    let request = CallRequest {
                        connection: call.connection.clone(),
                        operation: call.operation,
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
                                    return Ok(call_result(outcome, next, job.job.uncertain))
                                }
                                Err(_) => {
                                    return Ok(call_result(
                                        CallOutcome::Retryable {
                                            code: "attempt-timeout".into(),
                                            retry_after: None,
                                        },
                                        next,
                                        job.job.uncertain,
                                    ))
                                }
                            };
                        if value.as_ref().is_some_and(|bytes| bytes.len() > 65_536) {
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
                if request.operation != call.operation || request.connection != call.connection {
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
                Ok(call_result(result, next, job.job.uncertain))
            }
        }
    }
}

/// What an attempt came to, by its closed class alone.
fn attempt_class(result: &std::result::Result<Sent<Detail>, DispatchError>) -> StepAttempt {
    match result {
        Ok(sent) => match sent.outcome {
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
    use super::{call_result, safe_code};
    use crate::protocol::CallOutcome;
    use registry_platform_dispatch::SendOutcome;
    use std::time::Duration;

    #[test]
    fn a_product_pause_hint_reaches_the_retry_schedule_only_for_definite_retries() {
        let rate_limited = |retry_after| CallOutcome::Retryable {
            code: "rate-limited".into(),
            retry_after,
        };
        let hint = Some(Duration::from_secs(30));
        let sent = call_result(rate_limited(hint), "next", false);
        assert_eq!(sent.outcome, SendOutcome::Transient { retry_after: hint });
        assert_eq!(sent.detail.failure_code, Some("rate-limited"));
        assert_eq!(
            call_result(rate_limited(None), "next", false).outcome,
            SendOutcome::Transient { retry_after: None }
        );
        // An attempt after an unknown outcome stays held: a hint never turns
        // it into an automatic resend.
        assert_eq!(
            call_result(rate_limited(hint), "next", true).outcome,
            SendOutcome::MaybeSent
        );
    }

    #[test]
    fn operator_codes_preserve_reviewed_categories_and_scrub_runtime_text() {
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
