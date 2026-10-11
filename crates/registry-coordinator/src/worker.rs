// SPDX-License-Identifier: Apache-2.0
//! One bounded step per tick, with leases and checkpoints owned by Dispatch.

use crate::{
    contracts::{contract, event_contract},
    definition::{Step, WaitEvent},
    metrics::StepAttempt,
    protocol::{AdapterSet, CallOutcome, CallRequest, ReviewRead},
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
        receipt_expired: false,
        recheck_seconds: None,
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

/// What one read of a waiting step comes to. A settled result that keeps
/// the event's contract continues at `next` with the result as the step's
/// output, even when the timeout has passed. A wait that has reached its
/// timeout without a result continues at `on_timeout`, or fails. Otherwise
/// the wait goes on: an open review is read again after `recheck_seconds`,
/// and a read that could not answer after the product's pause, kept between
/// the read spacing and `recheck_seconds`, or without a pause after the
/// longest retry delay, bounded by `recheck_seconds`.
fn wait_result(
    event: &WaitEvent,
    read: Option<ReviewRead>,
    next: &str,
    on_timeout: Option<&str>,
    timed_out: bool,
    recheck_seconds: u32,
) -> Sent<Detail> {
    // A read that could not answer before the timeout leaves the wait open
    // like a pending one, so an outage shorter than the timeout spends no
    // attempt budget: the next read follows the product's pause, no sooner
    // than the read spacing and no later than the configured check interval.
    // Without a pause it waits the longest retry delay, so waiting runs do
    // not all read again as soon as the product recovers; a completion event
    // still brings the read forward.
    let unanswered = |code: &'static str, hint: Option<Duration>| {
        let seconds = |delay: Duration| u32::try_from(delay.as_secs()).unwrap_or(u32::MAX);
        let pause = hint.map_or(seconds(RETRY_MAXIMUM_DELAY), |hint| {
            seconds(hint).max(WAIT_READ_SPACING_SECONDS)
        });
        accepted(Detail {
            recheck_seconds: Some(pause.min(recheck_seconds)),
            ..Detail::failure(code, false)
        })
    };
    match read {
        Some(ReviewRead::Settled(value)) => {
            if event_contract(event).check(&value).is_ok() {
                accepted(advance(next.to_owned(), Some(value)))
            } else {
                failed("invalid-response", false)
            }
        }
        Some(ReviewRead::Unknown) => failed("review-request-unknown", false),
        Some(ReviewRead::Expired) => failed("review-result-expired", false),
        Some(ReviewRead::Failed(
            CallOutcome::Refused { code } | CallOutcome::Uncertain { code },
        )) => failed(safe_code(&code, "remote-refused"), false),
        Some(ReviewRead::Failed(CallOutcome::Success(_) | CallOutcome::ReceiptExpired)) => {
            failed("invalid-response", false)
        }
        _ if timed_out => match on_timeout {
            Some(step) => accepted(advance(step.to_owned(), None)),
            None => failed("wait-timed-out", false),
        },
        Some(ReviewRead::Pending) => accepted(Detail {
            next: None,
            output: None,
            outcome: None,
            failure_code: None,
            failure_path: None,
            uncertain: false,
            receipt_expired: false,
            recheck_seconds: Some(recheck_seconds),
        }),
        Some(ReviewRead::Failed(CallOutcome::Retryable { code, retry_after })) => {
            unanswered(safe_code(&code, "remote-retryable"), retry_after)
        }
        None => unanswered("attempt-timeout", None),
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
                let Some(timed_out) = self
                    .store
                    .wait_timed_out(job)
                    .await
                    .map_err(|_| DispatchError::Unavailable)?
                else {
                    return Ok(failed("protected-state-invalid", false));
                };
                let (Some(Step::Call { call, .. }), Some(accepted)) = (
                    definition.workflow.steps.get(wait_for.request()),
                    payload.outputs.get(wait_for.request()),
                ) else {
                    return Ok(failed("protected-state-invalid", false));
                };
                let recheck_seconds = self.adapters.result_check_seconds(&call.connection);
                let Some(budget) = job.remaining_budget(std::time::SystemTime::now()) else {
                    return Ok(wait_result(
                        wait_for,
                        None,
                        next,
                        on_timeout.as_deref(),
                        timed_out,
                        recheck_seconds,
                    ));
                };
                let read = tokio::time::timeout(
                    budget,
                    self.adapters.read_review_result(&call.connection, accepted),
                )
                .await
                .ok();
                Ok(wait_result(
                    wait_for,
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
                    receipt_expired: false,
                    recheck_seconds: None,
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
        definition::WaitEvent,
        metrics::StepAttempt,
        protocol::{CallOutcome, ReviewRead},
    };
    use registry_platform_dispatch::SendOutcome;
    use serde_json::{json, Value};
    use std::time::Duration;

    fn review() -> WaitEvent {
        WaitEvent::ReviewResult {
            request: "submit-review".into(),
        }
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
        read: Option<ReviewRead>,
        on_timeout: Option<&str>,
        timed_out: bool,
    ) -> super::Sent<super::Detail> {
        wait_result(&review(), read, "decide", on_timeout, timed_out, 900)
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
                    Some(ReviewRead::Settled(result(status))),
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
        let sent = wait(Some(ReviewRead::Settled(carried)), None, false);
        assert_eq!(permanent(&sent), Some("invalid-response"));
    }

    #[test]
    fn a_pending_result_keeps_waiting_until_the_timeout() {
        let sent = wait(Some(ReviewRead::Pending), None, false);
        assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
        assert_eq!(sent.detail.next, None);
        assert_eq!(sent.detail.output, None);
        assert_eq!(sent.detail.recheck_seconds, Some(900));
        let sent = wait(Some(ReviewRead::Pending), Some("withdraw"), true);
        assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
        assert_eq!(sent.detail.next.as_deref(), Some("withdraw"));
        assert_eq!(sent.detail.output, None);
        assert_eq!(sent.detail.recheck_seconds, None);
        assert_eq!(
            permanent(&wait(Some(ReviewRead::Pending), None, true)),
            Some("wait-timed-out")
        );
    }

    #[test]
    fn an_unreadable_result_at_the_timeout_takes_the_timeout_route() {
        let busy = || {
            Some(ReviewRead::Failed(CallOutcome::Retryable {
                code: "rate-limited".into(),
                retry_after: None,
            }))
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
                    Some(ReviewRead::Unknown),
                    Some("withdraw"),
                    timed_out
                )),
                Some("review-request-unknown")
            );
            assert_eq!(
                permanent(&wait(
                    Some(ReviewRead::Expired),
                    Some("withdraw"),
                    timed_out
                )),
                Some("review-result-expired")
            );
            assert_eq!(
                permanent(&wait(
                    Some(ReviewRead::Failed(CallOutcome::Refused {
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
                permanent(&wait(Some(ReviewRead::Failed(outcome)), None, false)),
                Some("invalid-response")
            );
        }
        assert_eq!(
            permanent(&wait(
                Some(ReviewRead::Failed(CallOutcome::Refused {
                    code: "Bearer synthetic-secret-canary".into()
                })),
                None,
                false
            )),
            Some("remote-refused")
        );
    }

    #[test]
    fn a_failed_read_before_the_timeout_keeps_waiting_at_its_hint_or_the_retry_ceiling() {
        for (hint, expected) in [
            (None, 300),
            (Some(Duration::from_secs(5)), 30),
            (Some(Duration::from_secs(120)), 120),
            (Some(Duration::from_secs(3600)), 900),
        ] {
            let sent = wait(
                Some(ReviewRead::Failed(CallOutcome::Retryable {
                    code: "rate-limited".into(),
                    retry_after: hint,
                })),
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
        let sent = wait_result(&review(), None, "decide", None, false, 120);
        assert_eq!(
            sent.detail.recheck_seconds,
            Some(120),
            "a shorter check interval bounds the wait without a hint"
        );
        assert_eq!(attempt_class(&Ok(sent)), StepAttempt::Transient);
        assert_eq!(
            attempt_class(&Ok(wait(Some(ReviewRead::Pending), None, false))),
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
