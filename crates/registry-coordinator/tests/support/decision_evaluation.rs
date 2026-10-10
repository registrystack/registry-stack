// SPDX-License-Identifier: Apache-2.0
//! Durable inference is not a repeatable read, even without a registry mutation.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const DECISION_WORKFLOW: &str = r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: synthetic-decision, version: '1'}
input: {type: object}
connections: {assessor: decision}
functionsFile: functions.rhai
deadlineSeconds: 3600
start: evaluate
steps:
  evaluate:
    type: call
    connection: assessor
    operation: evaluate-decision
    input: {function: decision_request, arguments: [{type: input}]}
    next: done
  done:
    type: finish
    outcome: assessed
    output: {function: decision_result, arguments: [{type: step, step: evaluate}]}
outcomes: {assessed: {type: object}}
"#;
const DECISION_FUNCTIONS: &str = r#"
fn decision_request(input) {
    #{ state: input, questions: #{ route: #{ type: "choice", instructions: "Assess supplied facts", criteria: #{ proceed: "Sufficient", review: "Needs review" } } } }
}
fn decision_result(result) { result }
"#;

async fn decision_harness() -> Harness {
    let mut h = harness().await;
    std::fs::write(h.project.path().join("workflow.yaml"), DECISION_WORKFLOW).unwrap();
    std::fs::write(h.project.path().join("functions.rhai"), DECISION_FUNCTIONS).unwrap();
    h.definition = Definition::load(h.project.path()).unwrap();
    h
}

struct DecisionFake {
    preparations: AtomicUsize,
    calls: Mutex<Vec<(CallRequest, Vec<u8>)>>,
    outcomes: Mutex<VecDeque<CallOutcome>>,
    entered: Notify,
    block: bool,
    release: Option<Semaphore>,
}
impl DecisionFake {
    fn new(outcomes: Vec<CallOutcome>, block: bool) -> Arc<Self> {
        Arc::new(Self {
            preparations: AtomicUsize::new(0),
            calls: Mutex::new(vec![]),
            outcomes: Mutex::new(outcomes.into()),
            entered: Notify::new(),
            block,
            release: None,
        })
    }
}
#[async_trait]
impl AdapterSet for DecisionFake {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }
    async fn prepare(&self, request: &CallRequest) -> Result<Option<Vec<u8>>, CallOutcome> {
        assert_eq!(request.operation, Operation::EvaluateDecision);
        assert!(request.idempotency_key.is_none());
        self.preparations.fetch_add(1, Ordering::SeqCst);
        Ok(Some(serde_json::to_vec(&request.input).unwrap()))
    }
    async fn call(&self, _: &CallRequest) -> CallOutcome {
        panic!("evaluation requires protected preparation")
    }
    async fn call_prepared(&self, request: &CallRequest, prepared: Option<&[u8]>) -> CallOutcome {
        let prepared = prepared.expect("exact frozen request");
        assert_eq!(
            serde_json::from_slice::<Value>(prepared).unwrap(),
            request.input
        );
        self.calls
            .lock()
            .unwrap()
            .push((request.clone(), prepared.to_vec()));
        self.entered.notify_one();
        if let Some(release) = &self.release {
            let permit = release.acquire().await.unwrap();
            permit.forget();
        }
        if self.block {
            std::future::pending::<()>().await;
        }
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .expect("declared synthetic outcome")
    }
}
fn decision_success() -> CallOutcome {
    CallOutcome::Success(
        json!({"answers":{"route":{"type":"choice","choice":"proceed"}},"returnedModel":"original-model"}),
    )
}

#[tokio::test]
async fn unknown_decision_completion_cannot_retry_reconcile_or_release_restore_hold() {
    let h = decision_harness().await;
    let run = h.admit().await;
    let fake = DecisionFake::new(
        vec![CallOutcome::Uncertain {
            code: "decision-uncertain".into(),
        }],
        false,
    );
    let worker = Worker::new(h.store.clone(), fake.clone());
    worker.tick().await.unwrap();
    let reopened = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
    let inspection = reopened.inspect(run, "binding-a").await.unwrap();
    assert_eq!(inspection.run.state, "attention");
    assert!(inspection.run.uncertain);
    assert_eq!(
        inspection.recovery.reason,
        Some(RetryBlockReason::EvaluationUncertain)
    );
    assert!(!inspection.recovery.retry_allowed);
    assert_eq!(
        reopened
            .retry_same(run, "binding-a")
            .await
            .unwrap_err()
            .code,
        "evaluation-uncertain"
    );
    let operator = actor("operator", true);
    assert_eq!(
        reopened
            .reconcile_owned(
                run,
                "binding-a",
                &operator,
                "original-result-lookup",
                fake.as_ref()
            )
            .await
            .unwrap_err()
            .code,
        "reconciliation-unavailable"
    );
    assert!(!Worker::new(reopened.clone(), fake.clone())
        .tick()
        .await
        .unwrap());
    reopened
        .set_restore_hold(&operator, "restored-decision")
        .await
        .unwrap();
    reopened
        .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
        .await
        .unwrap();
    assert_eq!(
        reopened
            .release_restore_hold(&operator, "complete-history-fenced")
            .await
            .unwrap_err()
            .code,
        "restore-unresolved"
    );
    assert_eq!(fake.calls.lock().unwrap().len(), 1);
    assert_eq!(fake.preparations.load(Ordering::SeqCst), 1);
    assert!(h.output_values(run).await.is_empty());
}

#[tokio::test]
async fn crashed_decision_dispatch_keeps_uncertainty_and_never_reissues_inference() {
    let h = decision_harness().await;
    let run = h.admit().await;
    let fake = DecisionFake::new(vec![], true);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let attempt = tokio::spawn(async move { worker.tick().await });
    fake.entered.notified().await;
    attempt.abort();
    assert!(attempt.await.unwrap_err().is_cancelled());
    h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE state='leased'").await;
    let reopened = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
    let worker = Worker::new(reopened.clone(), fake.clone());
    worker.tick().await.unwrap();
    let inspection = reopened.inspect(run, "binding-a").await.unwrap();
    assert_eq!(inspection.run.state, "attention");
    assert!(inspection.run.uncertain);
    assert_eq!(
        inspection.recovery.reason,
        Some(RetryBlockReason::EvaluationUncertain)
    );
    assert!(reopened.retry_same(run, "binding-a").await.is_err());
    assert!(!worker.tick().await.unwrap());
    assert_eq!(fake.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn known_non_dispatch_retry_reuses_exact_preparation_without_a_key() {
    let h = decision_harness().await;
    let run = h.admit().await;
    let fake = DecisionFake::new(
        vec![
            CallOutcome::Retryable {
                code: "decision-unavailable".into(),
            },
            decision_success(),
        ],
        false,
    );
    let worker = Worker::new(h.store.clone(), fake.clone());
    worker.tick().await.unwrap();
    assert!(!h.store.status(run).await.unwrap().uncertain);
    h.sql("UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE state='pending'").await;
    let reopened = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
    let worker = Worker::new(reopened.clone(), fake.clone());
    worker.tick().await.unwrap();
    worker.tick().await.unwrap();
    assert_eq!(reopened.status(run).await.unwrap().state, "finished");
    assert_eq!(fake.preparations.load(Ordering::SeqCst), 1);
    let calls = fake.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls[0].0.idempotency_key.is_none());
    assert_eq!(
        serde_json::to_value(&calls[0].0).unwrap(),
        serde_json::to_value(&calls[1].0).unwrap()
    );
    assert_eq!(calls[0].1, calls[1].1);
}

#[tokio::test]
async fn completed_decision_is_reused_after_restart_and_downstream_mapping_failure() {
    for broken_wait in [false, true] {
        let mut h = decision_harness().await;
        if broken_wait {
            std::fs::write(h.project.path().join("workflow.yaml"), DECISION_WORKFLOW.replace("next: done", "next: later").replace("  done:\n", "  later:\n    type: wait-until\n    waitUntil: {function: broken_wait, arguments: [{type: input}]}\n    next: done\n  done:\n")).unwrap();
            std::fs::write(
                h.project.path().join("functions.rhai"),
                format!("{DECISION_FUNCTIONS}\nfn broken_wait(input) {{ 42 }}"),
            )
            .unwrap();
            h.definition = Definition::load(h.project.path()).unwrap();
        }
        let run = h.admit().await;
        let fake = DecisionFake::new(vec![decision_success()], false);
        Worker::new(h.store.clone(), fake.clone())
            .tick()
            .await
            .unwrap();
        assert_eq!(
            h.output_values(run).await["evaluate"]["returnedModel"],
            "original-model"
        );
        let reopened = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
        let worker = Worker::new(reopened.clone(), fake.clone());
        if broken_wait {
            assert_settled_mapping_failure(&h, run, "evaluate").await;
            assert!(!worker.tick().await.unwrap());
        } else {
            worker.tick().await.unwrap();
            let result = reopened.status(run).await.unwrap();
            assert_eq!(result.state, "finished");
            assert_eq!(result.output.unwrap()["returnedModel"], "original-model");
        }
        assert!(!worker.tick().await.unwrap());
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
        assert_eq!(fake.preparations.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn decision_attempt_timeout_is_uncertain_and_cannot_retry() {
    let h = decision_harness().await;
    let run = h.admit().await;
    let fake = DecisionFake::new(vec![], true);
    Worker::new(h.store.clone(), fake.clone())
        .tick()
        .await
        .unwrap();
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert!(inspection.run.uncertain);
    assert_eq!(
        inspection.run.failure_code.as_deref(),
        Some("attempt-timeout")
    );
    assert_eq!(
        inspection.recovery.reason,
        Some(RetryBlockReason::EvaluationUncertain)
    );
    assert!(h.store.retry_same(run, "binding-a").await.is_err());
    assert_eq!(fake.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn restored_decision_before_dispatch_requires_explicit_safe_retry() {
    for prepared in [false, true] {
        let h = decision_harness().await;
        let run = h.admit().await;
        let fake = DecisionFake::new(
            if prepared {
                vec![
                    CallOutcome::Retryable {
                        code: "decision-unavailable".into(),
                    },
                    decision_success(),
                ]
            } else {
                vec![decision_success()]
            },
            false,
        );
        let worker = Worker::new(h.store.clone(), fake.clone());
        if prepared {
            worker.tick().await.unwrap();
        }
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "safe-decision-restored")
            .await
            .unwrap();
        h.store
            .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
            .await
            .unwrap();
        h.store
            .release_restore_hold(&operator, "complete-history-fenced")
            .await
            .unwrap();
        assert!(!worker.tick().await.unwrap());
        assert_eq!(fake.calls.lock().unwrap().len(), usize::from(prepared));
        let inspection = h.store.inspect(run, "binding-a").await.unwrap();
        assert_eq!(inspection.run.state, "failed");
        assert!(inspection.recovery.retry_allowed);
        h.store
            .retry_same_owned(run, "binding-a", &operator, "explicit-safe-retry")
            .await
            .unwrap();
        worker.tick().await.unwrap();
        worker.tick().await.unwrap();
        assert_eq!(h.store.status(run).await.unwrap().state, "finished");
        assert_eq!(fake.calls.lock().unwrap().len(), 1 + usize::from(prepared));
        assert_eq!(fake.preparations.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn cancelled_unknown_decision_requires_review_then_releases_only_its_restore_blocker() {
    let h = decision_harness().await;
    let original = input(Utc::now() - Duration::seconds(1));
    let run = h
        .store
        .admit(
            &h.definition,
            original.clone(),
            "synthetic-producer",
            "start",
            "binding-a",
        )
        .await
        .unwrap();
    let fake = DecisionFake::new(
        vec![CallOutcome::Uncertain {
            code: "decision-uncertain".into(),
        }],
        false,
    );
    let worker = Worker::new(h.store.clone(), fake.clone());
    worker.tick().await.unwrap();
    let operator = actor("operator", true);
    h.store
        .set_restore_hold(&operator, "restored-evaluation")
        .await
        .unwrap();
    h.store
        .cancel_owned(run, &operator, "abandon-evaluation-use")
        .await
        .unwrap();
    let cancelled = h.store.status(run).await.unwrap();
    assert!(cancelled.cancel_requested);
    assert!(cancelled.uncertain);
    assert_eq!(cancelled.state, "attention");
    assert_eq!(
        h.store
            .release_restore_hold(&operator, "cancel-alone")
            .await
            .unwrap_err()
            .code,
        "restore-unresolved"
    );
    h.store
        .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
        .await
        .unwrap();
    h.store
        .release_restore_hold(&operator, "reviewed-abandonment")
        .await
        .unwrap();
    h.store
        .release_admission_hold(&operator, "complete-admissions-fenced", true, true)
        .await
        .unwrap();
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert!(inspection.run.uncertain);
    assert!(inspection.run.cancel_requested);
    assert!(!inspection.run.restore_review_required);
    assert!(!inspection.recovery.retry_allowed);
    assert!(inspection
        .steps
        .iter()
        .any(|step| step.step == "evaluate" && step.command_prepared && step.uncertain));
    assert!(h.store.retry_same(run, "binding-a").await.is_err());
    assert!(h.store.retry_same(run, "binding-b").await.is_err());
    assert!(!worker.tick().await.unwrap());
    assert_eq!(
        h.store
            .admit(
                &h.definition,
                original,
                "synthetic-producer",
                "start",
                "binding-b"
            )
            .await
            .unwrap(),
        run
    );
    assert_eq!(
        h.store.status(run).await.unwrap().binding_digest,
        "binding-a"
    );
    assert_eq!(fake.calls.lock().unwrap().len(), 1);
    assert!(h.output_values(run).await.is_empty());
    assert_eq!(
        h.store
            .retain_terminal(Utc::now(), 100, &operator)
            .await
            .unwrap(),
        0
    );
    // A second restore requires a fresh review, even for abandoned evaluation.
    h.store
        .set_restore_hold(&operator, "second-restore")
        .await
        .unwrap();
    assert!(h.store.status(run).await.unwrap().restore_review_required);
    assert_eq!(
        h.store
            .release_restore_hold(&operator, "old-review")
            .await
            .unwrap_err()
            .code,
        "restore-unresolved"
    );
    h.store
        .complete_execution_recovery(&operator, "second-complete-history-fenced", true, true)
        .await
        .unwrap();
    h.store
        .release_restore_hold(&operator, "second-review")
        .await
        .unwrap();
    assert!(!worker.tick().await.unwrap());
    assert_eq!(fake.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cancelled_evaluation_active_lease_blocks_review_and_late_reply_cannot_advance() {
    for late_success in [false, true] {
        let h = decision_harness().await;
        let run = h.admit().await;
        let fake = Arc::new(DecisionFake {
            preparations: AtomicUsize::new(0),
            calls: Mutex::new(vec![]),
            outcomes: Mutex::new(vec![decision_success()].into()),
            entered: Notify::new(),
            block: false,
            release: Some(Semaphore::new(0)),
        });
        let worker = Worker::new(h.store.clone(), fake.clone());
        let attempt = tokio::spawn(async move { worker.tick().await });
        fake.entered.notified().await;
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "live-evaluation-restored")
            .await
            .unwrap();
        h.store
            .cancel_owned(run, &operator, "abandon-live-evaluation")
            .await
            .unwrap();
        h.store
            .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
            .await
            .unwrap();
        assert!(h.store.status(run).await.unwrap().restore_review_required);
        assert_eq!(
            h.store
                .release_restore_hold(&operator, "still-live")
                .await
                .unwrap_err()
                .code,
            "restore-unresolved"
        );
        if late_success {
            fake.release.as_ref().unwrap().add_permits(1);
            attempt.await.unwrap().unwrap();
            assert_eq!(h.store.status(run).await.unwrap().state, "attention");
        } else {
            attempt.abort();
            assert!(attempt.await.unwrap_err().is_cancelled());
            h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE state='leased'").await;
        }
        h.store
            .complete_execution_recovery(&operator, "settled-complete-history-fenced", true, true)
            .await
            .unwrap();
        h.store
            .release_restore_hold(&operator, "settled-reviewed-abandonment")
            .await
            .unwrap();
        assert!(!Worker::new(h.store.clone(), fake.clone())
            .tick()
            .await
            .unwrap());
        let status = h.store.status(run).await.unwrap();
        assert!(status.cancel_requested);
        assert_eq!(status.step, "evaluate");
        assert!(status.outcome.is_none());
        assert_eq!(status.uncertain, !late_success);
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn cancelled_unknown_mutation_still_blocks_restore_release() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Fake::new(vec![uncertain()]);
    let worker = Worker::new(h.store.clone(), fake);
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    let operator = actor("operator", true);
    h.store
        .set_restore_hold(&operator, "unknown-mutation-restored")
        .await
        .unwrap();
    h.store
        .cancel_owned(run, &operator, "stop-future-effects")
        .await
        .unwrap();
    h.store
        .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
        .await
        .unwrap();
    assert_eq!(
        h.store
            .release_restore_hold(&operator, "no-mutation-proof")
            .await
            .unwrap_err()
            .code,
        "restore-unresolved"
    );
    assert!(h.store.status(run).await.unwrap().uncertain);
    assert!(h.store.status(run).await.unwrap().restore_review_required);
}
