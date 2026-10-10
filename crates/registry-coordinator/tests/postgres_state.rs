// SPDX-License-Identifier: Apache-2.0
//! Isolated synthetic PostgreSQL proof. Missing database configuration fails.
#![cfg(feature = "postgres-test")]
use async_trait::async_trait;
use chrono::{Duration, Utc};
use registry_coordinator::{
    definition::Definition,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
    store::{RetryBlockReason, Store},
    worker::Worker,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::sync::{Notify, Semaphore};
use uuid::Uuid;

const FUNCTIONS: &str = r#"
fn timer(input) { input.at }
fn record(input) { #{ resource: "people", recordId: input.id } }
fn permission(record) { if record.allowed { "yes" } else { "no" } }
fn message(record) { #{ destination: record.contact, text: "Synthetic appointment reminder" } }
fn receipt(message) { #{ messageId: message.messageId } }
"#;
const WORKFLOW: &str = r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project:
  id: synthetic-reminder
  version: v1
input: {type: object}
connections: { source: breg, messages: messaging }
functionsFile: functions.rhai
deadlineSeconds: 3600
start: wait
steps:
  wait:
    type: wait-until
    waitUntil: {function: timer, arguments: [{type: input}]}
    next: read
  read:
    type: call
    connection: source
    operation: read-record
    input: {function: record, arguments: [{type: input}]}
    next: choose
  choose:
    type: choose
    choose: {function: permission, arguments: [{type: step, step: read}]}
    cases: {yes: message, no: withdrawn}
  message:
    type: call
    connection: messages
    operation: submit-message
    input: {function: message, arguments: [{type: step, step: read}]}
    next: done
  done:
    type: finish
    outcome: sent
    output: {function: receipt, arguments: [{type: step, step: message}]}
  withdrawn: {type: finish, outcome: withdrawn}
outcomes:
  sent:
    type: object
    properties: {messageId: {type: string}}
    required: [messageId]
    additionalProperties: false
  withdrawn: {type: 'null'}
"#;

struct Harness {
    url: String,
    namespace: String,
    store: Arc<Store>,
    definition: Definition,
    project: tempfile::TempDir,
}
async fn harness() -> Harness {
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").expect(
        "COORDINATOR_TEST_DATABASE_URL must name a disposable synthetic PostgreSQL 17+ database",
    );
    let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
    let store = Arc::new(
        Store::connect(&url, &namespace)
            .await
            .expect("local disposable connection"),
    );
    store.migrate().await.expect("isolated migration");
    let project = tempfile::tempdir().expect("project");
    std::fs::write(project.path().join("workflow.yaml"), WORKFLOW).expect("workflow");
    std::fs::write(project.path().join("functions.rhai"), FUNCTIONS).expect("functions");
    let definition = Definition::load(project.path()).expect("valid synthetic definition");
    Harness {
        url,
        namespace,
        store,
        definition,
        project,
    }
}
fn input(at: chrono::DateTime<Utc>) -> Value {
    json!({"at":at.to_rfc3339(), "id":"synthetic-contact-canary"})
}
impl Harness {
    async fn admit(&self) -> Uuid {
        self.store
            .admit(
                &self.definition,
                input(Utc::now() - Duration::seconds(1)),
                "synthetic-producer",
                "start",
                "binding-a",
            )
            .await
            .expect("admit")
    }
    async fn sql(&self, sql: &str) {
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .expect("test connection");
        tokio::spawn(async move {
            connection.await.expect("test connection finishes");
        });
        client
            .batch_execute(&sql.replace("{schema}", &self.namespace))
            .await
            .expect("synthetic test transition");
    }
}
impl Harness {
    async fn replace_protected<T: serde::Serialize>(&self, run: Uuid, purpose: &str, value: &T) {
        use base64::Engine as _;
        use registry_platform_crypto::sealed_value::{seal, Context};
        assert!(matches!(purpose, "snapshot" | "outputs"));
        let id = run.to_string();
        let envelope = seal(
            &[0x11; 32],
            &Context {
                domain: "registry-coordinator/state/v1",
                scope: &[&self.namespace, &id, purpose, ""],
                key_version: 1,
            },
            &serde_json::to_vec(value).unwrap(),
        )
        .unwrap();
        let value = json!({"sealedCoordinatorV1":base64::engine::general_purpose::STANDARD.encode(envelope)});
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        client
            .execute(
                &format!(
                    "UPDATE {}.runs SET {purpose}=$2 WHERE run_id=$1",
                    self.namespace
                ),
                &[&run, &value],
            )
            .await
            .unwrap();
    }
    async fn incompatible_snapshot(&self, run: Uuid) {
        let mut snapshot: Value =
            serde_json::from_str(&self.definition.snapshot().unwrap()).unwrap();
        snapshot["interpreterAbi"] = json!("unsupported-interpreter-abi");
        self.replace_protected(run, "snapshot", &snapshot.to_string())
            .await;
    }
}

struct Fake {
    outcomes: Mutex<VecDeque<CallOutcome>>,
    requests: Mutex<Vec<CallRequest>>,
    allowed: bool,
    entered: Notify,
    release: Option<Semaphore>,
}
impl Fake {
    fn new(outcomes: Vec<CallOutcome>) -> Arc<Self> {
        Arc::new(Self {
            outcomes: Mutex::new(outcomes.into()),
            requests: Mutex::new(vec![]),
            allowed: true,
            entered: Notify::new(),
            release: None,
        })
    }
}
#[async_trait]
impl AdapterSet for Fake {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }
    async fn call(&self, request: &CallRequest) -> CallOutcome {
        self.requests
            .lock()
            .expect("requests")
            .push(request.clone());
        if request.operation == Operation::ReadRecord {
            return CallOutcome::Success(
                json!({"allowed":self.allowed,"contact":"synthetic-destination-canary"}),
            );
        }
        if let Some(release) = &self.release {
            self.entered.notify_one();
            let permit = release.acquire().await.expect("release");
            permit.forget();
        }
        self.outcomes
            .lock()
            .expect("outcomes")
            .pop_front()
            .unwrap_or_else(|| {
                CallOutcome::Success(json!({"messageId":"synthetic-original-receipt"}))
            })
    }
}
async fn reach_message(worker: &Worker) {
    for _ in 0..3 {
        assert!(worker.tick().await.expect("graph progress"));
    }
}
fn uncertain() -> CallOutcome {
    CallOutcome::Uncertain {
        code: "safe-code".into(),
    }
}

struct PreparedFake {
    preparations: std::sync::atomic::AtomicUsize,
    calls: Mutex<Vec<(CallRequest, Vec<u8>)>>,
    refuse_preparation: bool,
}

#[async_trait]
impl AdapterSet for PreparedFake {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }

    async fn prepare(&self, request: &CallRequest) -> Result<Option<Vec<u8>>, CallOutcome> {
        if request.operation.is_read() {
            return Ok(None);
        }
        if self.refuse_preparation {
            return Err(CallOutcome::Refused {
                code: "product-forbidden".into(),
            });
        }
        let count = self
            .preparations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Some(
            format!("original-target-condition-canary-{count}").into_bytes(),
        ))
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        assert!(
            request.operation.is_read(),
            "mutations require persisted preparation"
        );
        CallOutcome::Success(json!({"allowed":true,"contact":"synthetic@example.invalid"}))
    }

    async fn call_prepared(&self, request: &CallRequest, bytes: Option<&[u8]>) -> CallOutcome {
        if request.operation.is_read() {
            return self.call(request).await;
        }
        let mut calls = self.calls.lock().unwrap();
        calls.push((request.clone(), bytes.expect("frozen bytes").to_vec()));
        if calls.len() == 1 {
            uncertain()
        } else {
            CallOutcome::Success(json!({"messageId":"original-action-receipt"}))
        }
    }
}

#[tokio::test]
async fn prepared_command_survives_restart_without_refreshing_conditions_or_key() {
    let mut h = harness().await;
    std::fs::write(
        h.project.path().join("workflow.yaml"),
        WORKFLOW
            .replace("messages: messaging", "messages: breg")
            .replace("operation: submit-message", "operation: invoke-breg-action"),
    )
    .unwrap();
    h.definition = Definition::load(h.project.path()).unwrap();
    let run = h.admit().await;
    let fake = Arc::new(PreparedFake {
        preparations: std::sync::atomic::AtomicUsize::new(0),
        calls: Mutex::new(Vec::new()),
        refuse_preparation: false,
    });
    let worker = Worker::new(h.store.clone(), fake.clone());
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    assert_eq!(h.store.status(run).await.unwrap().state, "attention");
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert_eq!(
        inspection.recovery.operation,
        Some(Operation::InvokeBregAction.identity())
    );
    assert!(!serde_json::to_string(&inspection)
        .unwrap()
        .contains("original-target-condition"));
    drop(worker);
    let reopened = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
    reopened.retry_same(run, "binding-a").await.unwrap();
    let worker = Worker::new(reopened.clone(), fake.clone());
    worker.tick().await.unwrap();
    worker.tick().await.unwrap();
    assert_eq!(reopened.status(run).await.unwrap().state, "finished");
    assert_eq!(
        fake.preparations.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let calls = fake.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        serde_json::to_value(&calls[0].0).unwrap(),
        serde_json::to_value(&calls[1].0).unwrap()
    );
    assert_eq!(calls[0].1, calls[1].1);
}

#[tokio::test]
async fn refused_preparation_never_dispatches_or_claims_an_uncertain_mutation() {
    let mut h = harness().await;
    std::fs::write(
        h.project.path().join("workflow.yaml"),
        WORKFLOW
            .replace("messages: messaging", "messages: breg")
            .replace("operation: submit-message", "operation: invoke-breg-action"),
    )
    .unwrap();
    h.definition = Definition::load(h.project.path()).unwrap();
    let run = h.admit().await;
    let fake = Arc::new(PreparedFake {
        preparations: std::sync::atomic::AtomicUsize::new(0),
        calls: Mutex::new(Vec::new()),
        refuse_preparation: true,
    });
    let worker = Worker::new(h.store.clone(), fake.clone());
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert_eq!(inspection.run.state, "failed");
    assert!(!inspection.run.uncertain);
    let step = inspection
        .steps
        .iter()
        .find(|step| step.step == "message")
        .unwrap();
    assert!(!step.command_prepared);
    assert!(fake.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn admission_is_atomic_deduplicates_equal_input_and_rejects_changed_input() {
    let h = harness().await;
    let value = input(Utc::now());
    let (a, b) = tokio::join!(
        h.store
            .admit(&h.definition, value.clone(), "producer", "key", "binding-a"),
        h.store
            .admit(&h.definition, value.clone(), "producer", "key", "binding-a")
    );
    let a = a.expect("first admission");
    assert_eq!(a, b.expect("concurrent duplicate"));
    let mut changed = value;
    changed["id"] = json!("another synthetic record");
    assert_eq!(
        h.store
            .admit(&h.definition, changed, "producer", "key", "binding-a")
            .await
            .expect_err("conflict")
            .code,
        "coordinator.command.start-conflict"
    );
}

#[tokio::test]
async fn timer_survives_store_restart_and_permission_is_read_after_wait() {
    let h = harness().await;
    let due = Utc::now() + Duration::minutes(1);
    let run = h
        .store
        .admit(&h.definition, input(due), "p", "k", "binding-a")
        .await
        .expect("timer admission");
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    assert!(!worker.tick().await.expect("timer not due"));
    assert!(fake.requests.lock().expect("requests").is_empty());
    let reopened = Store::connect(&h.url, &h.namespace).await.expect("restart");
    assert_eq!(
        reopened.status(run).await.expect("status").next_due_at,
        h.store.status(run).await.expect("status").next_due_at
    );
    h.sql("UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp()-interval '1 second'")
        .await;
    assert!(worker.tick().await.expect("wait finishes"));
    assert!(fake.requests.lock().expect("requests").is_empty());
    assert!(worker.tick().await.expect("source read"));
    assert_eq!(fake.requests.lock().expect("requests").len(), 1);
}

#[tokio::test]
async fn withdrawn_permission_produces_no_message() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Arc::new(Fake {
        allowed: false,
        outcomes: Mutex::new(VecDeque::new()),
        requests: Mutex::new(vec![]),
        entered: Notify::new(),
        release: None,
    });
    let worker = Worker::new(h.store.clone(), fake.clone());
    while worker.tick().await.expect("tick") {}
    assert_eq!(
        h.store
            .status(run)
            .await
            .expect("status")
            .outcome
            .as_deref(),
        Some("withdrawn")
    );
    assert!(fake
        .requests
        .lock()
        .expect("requests")
        .iter()
        .all(|r| r.operation == Operation::ReadRecord));
}

#[tokio::test]
async fn same_key_retry_uses_original_command_and_safe_status() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Fake::new(vec![
        uncertain(),
        CallOutcome::Success(json!({"messageId":"synthetic-original-receipt"})),
    ]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    reach_message(&worker).await;
    assert!(worker.tick().await.expect("ambiguous mutation"));
    let status = h.store.status(run).await.expect("status");
    assert_eq!(status.state, "attention");
    assert!(status.uncertain);
    let safe = serde_json::to_string(&status).expect("status JSON");
    for canary in [
        "synthetic-contact-canary",
        "synthetic-destination-canary",
        "Synthetic appointment reminder",
    ] {
        assert!(!safe.contains(canary));
    }
    // A source edit after the first submit must never rebuild the command.
    h.replace_protected(
        run,
        "outputs",
        &json!({"read":{"allowed":false,"contact":"changed-destination"}}),
    )
    .await;
    h.store
        .retry_same(run, "binding-a")
        .await
        .expect("same command replay");
    assert!(worker.tick().await.expect("original receipt recovered"));
    assert!(worker.tick().await.expect("finish"));
    assert_eq!(h.store.status(run).await.expect("status").state, "finished");
    assert_eq!(
        h.store.status(run).await.expect("status").output,
        Some(json!({"messageId":"synthetic-original-receipt"}))
    );
    let requests = fake.requests.lock().expect("requests");
    let messages = requests
        .iter()
        .filter(|r| r.operation == Operation::SubmitMessage)
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 2);
    assert_eq!(
        serde_json::to_value(messages[0]).unwrap(),
        serde_json::to_value(messages[1]).unwrap()
    );
    assert!(messages[0].idempotency_key.is_some());
}

#[tokio::test]
async fn later_refusal_and_receipt_expiry_keep_uncertainty_and_never_create_fresh_keys() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Fake::new(vec![
        uncertain(),
        CallOutcome::Refused {
            code: "403-canary-secret".into(),
        },
        CallOutcome::ReceiptExpired,
    ]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    reach_message(&worker).await;
    worker.tick().await.expect("uncertain");
    h.store.retry_same(run, "binding-a").await.expect("retry");
    worker.tick().await.expect("later refusal");
    let status = h.store.status(run).await.expect("status");
    assert_eq!(status.state, "attention");
    assert!(status.uncertain);
    assert!(!serde_json::to_string(&status)
        .unwrap()
        .contains("403-canary-secret"));
    h.store.retry_same(run, "binding-a").await.expect("retry");
    worker.tick().await.expect("expired receipt");
    assert_eq!(
        h.store
            .retry_same(run, "binding-a")
            .await
            .expect_err("expired receipts cannot replay")
            .code,
        "coordinator.command.receipt-expired"
    );
    let keys = fake
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.operation == Operation::SubmitMessage)
        .map(|r| r.idempotency_key.clone())
        .collect::<Vec<_>>();
    assert_eq!(keys.len(), 3);
    assert!(keys.iter().all(|k| k == &keys[0]));
    assert!(h.store.status(run).await.unwrap().uncertain);
}

#[tokio::test]
async fn deadline_stops_first_effect_and_same_key_mutation_retry() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    worker.tick().await.expect("expiry processing");
    assert!(fake.requests.lock().unwrap().is_empty());
    assert_eq!(h.store.status(run).await.unwrap().state, "expired");
    let other = harness().await;
    let run = other.admit().await;
    let fake = Fake::new(vec![uncertain()]);
    let worker = Worker::new(other.store.clone(), fake.clone());
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    other
        .sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    assert!(other.store.retry_same(run, "binding-a").await.is_err());
    assert!(other.store.status(run).await.unwrap().uncertain);
    assert_eq!(fake.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn immutable_versions_and_per_run_retry_bindings_are_preserved() {
    let h = harness().await;
    let run = h.admit().await;
    h.store
        .admit(
            &h.definition,
            input(Utc::now()),
            "other-producer",
            "other",
            "binding-b",
        )
        .await
        .unwrap();
    std::fs::write(
        h.project.path().join("functions.rhai"),
        format!("{FUNCTIONS}\n// changed exact source\n"),
    )
    .unwrap();
    let changed = Definition::load(h.project.path()).unwrap();
    assert_ne!(changed.digest, h.definition.digest);
    assert_eq!(
        h.store
            .admit(&changed, input(Utc::now()), "p", "another", "binding-a")
            .await
            .expect_err("definition conflict")
            .code,
        "coordinator.command.workflow-version-conflict"
    );
    assert_eq!(
        h.store
            .retry_same(run, "binding-b")
            .await
            .expect_err("original binding required")
            .code,
        "coordinator.command.binding-conflict"
    );
}

#[tokio::test]
async fn unrelated_admission_does_not_prevent_original_bound_replay() {
    let h = harness().await;
    let run = h.admit().await;
    let worker = Worker::new(
        h.store.clone(),
        Fake::new(vec![CallOutcome::Refused {
            code: "product-forbidden".into(),
        }]),
    );
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    h.store
        .admit(
            &h.definition,
            input(Utc::now()),
            "other-producer",
            "independent",
            "binding-b",
        )
        .await
        .unwrap();
    assert!(
        h.store
            .inspect(run, "binding-a")
            .await
            .unwrap()
            .recovery
            .retry_allowed
    );
    h.store.retry_same(run, "binding-a").await.unwrap();
    assert_eq!(
        h.store.retry_same(run, "binding-b").await.unwrap_err().code,
        "coordinator.command.binding-conflict"
    );
}

#[tokio::test]
async fn replay_does_not_deadlock_activation_or_lose_its_guard_on_caller_cancellation() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Fake::new(vec![CallOutcome::Refused {
        code: "product-forbidden".into(),
    }]);
    let worker = Worker::new(h.store.clone(), fake);
    reach_message(&worker).await;
    assert!(worker.tick().await.unwrap());
    assert_eq!(h.store.status(run).await.unwrap().state, "failed");

    let (mut client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let holder: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let tx = client.transaction().await.unwrap();
    tx.query_one(
        &format!(
            "SELECT id FROM {}.admission_lock WHERE id FOR UPDATE",
            h.namespace
        ),
        &[],
    )
    .await
    .unwrap();
    let retry = {
        let store = h.store.clone();
        tokio::spawn(async move { store.retry_same(run, "binding-a").await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let blocked: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE NOT granted AND $1=ANY(pg_blocking_pids(pid)))", &[&holder]).await.unwrap().get(0);
            if blocked { break; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await.expect("replay waits at the shared admission guard");
    // Apply takes the admission guard before updating control. Replay must
    // release its preliminary control read before waiting for this guard.
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tx.execute(
            &format!(
                "UPDATE {}.control SET admissions_hold=admissions_hold WHERE id",
                h.namespace
            ),
            &[],
        ),
    )
    .await
    .expect("activation is not blocked by replay's preliminary read")
    .unwrap();
    assert_eq!(h.store.status(run).await.unwrap().state, "failed");
    retry.abort();
    assert!(retry.await.unwrap_err().is_cancelled());
    tx.commit().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while h.store.status(run).await.unwrap().state != "running" {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Dispatch's owned replay commits despite caller cancellation");
    assert_eq!(
        h.store.retry_same(run, "binding-b").await.unwrap_err().code,
        "coordinator.command.binding-conflict"
    );
}

#[tokio::test]
async fn concurrent_workers_claim_once_and_stale_completion_cannot_advance() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Arc::new(Fake {
        allowed: true,
        outcomes: Mutex::new(VecDeque::new()),
        requests: Mutex::new(vec![]),
        entered: Notify::new(),
        release: Some(Semaphore::new(0)),
    });
    let worker = Arc::new(Worker::new(h.store.clone(), fake.clone()));
    reach_message(&worker).await;
    let sending = {
        let worker = worker.clone();
        tokio::spawn(async move { worker.tick().await })
    };
    fake.entered.notified().await;
    assert!(!worker
        .tick()
        .await
        .expect("second worker sees active lease"));
    h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE state='leased'").await;
    worker.tick().await.expect("recover expired lease");
    assert_eq!(h.store.status(run).await.unwrap().state, "attention");
    fake.release.as_ref().unwrap().add_permits(1);
    assert!(sending.await.unwrap().is_err());
    let status = h.store.status(run).await.unwrap();
    assert_eq!(status.state, "attention");
    assert_eq!(status.step, "message");
    assert!(status.uncertain);
    assert_eq!(
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.operation == Operation::SubmitMessage)
            .count(),
        1
    );
}

#[tokio::test]
async fn occupied_namespace_is_refused_without_touching_existing_tables() {
    let h = harness().await;
    h.sql("COMMENT ON SCHEMA {schema} IS 'unrelated synthetic owner'")
        .await;
    assert_eq!(
        h.store.migrate().await.expect_err("foreign namespace").code,
        "coordinator.command.namespace-occupied"
    );
    assert!(Store::connect(&h.url, "public").await.is_err());
}

#[tokio::test]
async fn over_budget_mapping_stops_before_the_next_mutation() {
    let h = harness().await;
    let source = FUNCTIONS.replace("fn message(record) { #{ destination: record.contact, text: \"Synthetic appointment reminder\" } }", "fn message(record) { loop { } }");
    std::fs::write(h.project.path().join("functions.rhai"), source).unwrap();
    let definition = Definition::load(h.project.path())
        .expect("bounded interpreter accepts valid function syntax");
    let run = h
        .store
        .admit(
            &definition,
            input(Utc::now() - Duration::seconds(1)),
            "p",
            "k",
            "binding-a",
        )
        .await
        .unwrap();
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    reach_message(&worker).await;
    worker.tick().await.expect("mapping refuses safely");
    let status = h.store.status(run).await.unwrap();
    assert_eq!(status.failure_code.as_deref(), Some("mapping-invalid"));
    assert!(!status.uncertain);
    assert!(fake
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r.operation == Operation::ReadRecord));
}

#[tokio::test]
async fn pure_steps_finalize_a_predeadline_receipt_but_never_start_a_late_mutation() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Arc::new(Fake {
        allowed: true,
        outcomes: Mutex::new(VecDeque::new()),
        requests: Mutex::new(vec![]),
        entered: Notify::new(),
        release: Some(Semaphore::new(0)),
    });
    let worker = Arc::new(Worker::new(h.store.clone(), fake.clone()));
    reach_message(&worker).await;
    let sending = {
        let worker = worker.clone();
        tokio::spawn(async move { worker.tick().await })
    };
    fake.entered.notified().await;
    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    fake.release.as_ref().unwrap().add_permits(1);
    assert!(sending.await.unwrap().expect("authorized attempt settles"));
    assert!(worker.tick().await.expect("pure finish after deadline"));
    let status = h.store.status(run).await.unwrap();
    assert_eq!(status.state, "finished");
    assert_eq!(
        status.output,
        Some(json!({"messageId":"synthetic-original-receipt"}))
    );
    assert_eq!(
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.operation == Operation::SubmitMessage)
            .count(),
        1
    );

    let other = harness().await;
    let run = other.admit().await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(other.store.clone(), fake.clone());
    worker.tick().await.unwrap(); // persisted timer
    worker.tick().await.unwrap(); // predeadline source read
    other
        .sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    assert!(worker.tick().await.expect("pure choice after deadline"));
    worker.tick().await.expect("late mutation expires");
    assert_eq!(other.store.status(run).await.unwrap().state, "expired");
    assert!(fake
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r.operation == Operation::ReadRecord));
}

#[tokio::test]
async fn immutable_versions_coexist_and_waiting_v1_uses_its_pinned_source() {
    let h = harness().await;
    // Keep v1 unclaimable while v2 completes, regardless of CI runner speed.
    // This test controls the persisted timer below; it does not test wall time.
    let v1_input = input(Utc::now() + Duration::minutes(30));
    let v1 = h
        .store
        .admit(&h.definition, v1_input, "p", "v1", "binding-a")
        .await
        .unwrap();
    let v1_due = h.store.status(v1).await.unwrap().next_due_at;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    assert!(!worker.tick().await.unwrap());
    std::fs::write(
        h.project.path().join("workflow.yaml"),
        WORKFLOW.replace("version: v1", "version: v2"),
    )
    .unwrap();
    std::fs::write(
        h.project.path().join("functions.rhai"),
        FUNCTIONS.replace("Synthetic appointment reminder", "V2 synthetic notice"),
    )
    .unwrap();
    let definition_v2 = Definition::load(h.project.path()).unwrap();
    let v2 = h
        .store
        .admit(
            &definition_v2,
            input(Utc::now() - Duration::seconds(1)),
            "p",
            "v2",
            "binding-a",
        )
        .await
        .unwrap();
    for _ in 0..5 {
        assert!(worker.tick().await.unwrap());
    }
    assert_eq!(h.store.status(v2).await.unwrap().state, "finished");
    assert_eq!(h.store.status(v2).await.unwrap().workflow_version, "v2");
    let listed = h.store.list_runs(100).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].run_id, v2);
    assert_eq!(listed[1].run_id, v1);
    let waiting = h.store.status(v1).await.unwrap();
    assert_eq!(waiting.next_due_at, v1_due);
    assert_eq!(waiting.workflow_version, "v1");
    assert_eq!(waiting.definition_digest, h.definition.digest);
    assert_eq!(waiting.state, "running");
    h.sql(&format!(
        "UPDATE {{schema}}.jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE run_id='{v1}' AND state='pending'"
    ))
    .await;
    for _ in 0..5 {
        assert!(worker.tick().await.unwrap());
    }
    assert_eq!(h.store.status(v1).await.unwrap().state, "finished");
    let requests = fake.requests.lock().unwrap();
    let texts = requests
        .iter()
        .filter(|r| r.operation == Operation::SubmitMessage)
        .map(|r| r.input["text"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        texts,
        vec!["V2 synthetic notice", "Synthetic appointment reminder"]
    );
}

#[tokio::test]
async fn a_start_key_returns_its_original_version_before_new_schema_validation() {
    let h = harness().await;
    let original = input(Utc::now() + Duration::minutes(1));
    let first = h
        .store
        .admit(&h.definition, original.clone(), "p", "stable", "binding-a")
        .await
        .unwrap();
    std::fs::write(
        h.project.path().join("workflow.yaml"),
        WORKFLOW.replace("version: v1", "version: v2").replace(
            "input: {type: object}",
            "input: {type: object, required: [v2Field]}",
        ),
    )
    .unwrap();
    let v2 = Definition::load(h.project.path()).unwrap();
    assert!(v2.validate_input(&original).is_err());
    let repeated = h
        .store
        .admit(&v2, original.clone(), "p", "stable", "binding-a")
        .await
        .unwrap();
    assert_eq!(first, repeated);
    let status = h.store.status(repeated).await.unwrap();
    assert_eq!(status.workflow_version, "v1");
    assert_eq!(status.definition_digest, h.definition.digest);
    assert_eq!(
        h.store
            .admit(&v2, original.clone(), "p", "new", "binding-a")
            .await
            .unwrap_err()
            .code,
        "coordinator.definition.input"
    );
    let mut changed = original.clone();
    changed["id"] = json!("changed");
    assert_eq!(
        h.store
            .admit(&v2, changed, "p", "stable", "binding-a")
            .await
            .unwrap_err()
            .code,
        "coordinator.command.start-conflict"
    );
    assert_eq!(
        h.store
            .admit(&v2, original, "p", "stable", "binding-b")
            .await
            .unwrap(),
        first
    );
}

#[tokio::test]
async fn same_version_mutation_is_refused_after_completion_and_on_a_duplicate_key() {
    let h = harness().await;
    let original = input(Utc::now() - Duration::seconds(1));
    let run = h
        .store
        .admit(&h.definition, original.clone(), "p", "stable", "binding-a")
        .await
        .unwrap();
    let worker = Worker::new(h.store.clone(), Fake::new(vec![]));
    for _ in 0..5 {
        worker.tick().await.unwrap();
    }
    assert_eq!(h.store.status(run).await.unwrap().state, "finished");
    std::fs::write(
        h.project.path().join("functions.rhai"),
        format!("{FUNCTIONS}\n// different exact artifact\n"),
    )
    .unwrap();
    let changed = Definition::load(h.project.path()).unwrap();
    for key in ["stable", "new"] {
        assert_eq!(
            h.store
                .admit(&changed, original.clone(), "p", key, "binding-a")
                .await
                .unwrap_err()
                .code,
            "coordinator.command.workflow-version-conflict"
        );
    }
}

#[tokio::test]
async fn bounded_listing_and_inspection_use_durable_dispatch_metadata() {
    let h = harness().await;
    let run = h.admit().await;
    assert_eq!(h.store.list_runs(1).await.unwrap().len(), 1);
    assert!(h.store.list_runs(0).await.is_err());
    assert!(h.store.list_runs(101).await.is_err());
    let prepared = h.store.inspect(run, "binding-a").await.unwrap();
    assert_eq!(prepared.steps.len(), 1);
    assert_eq!(prepared.steps[0].attempt, 0);
    assert!(!prepared.steps[0].command_prepared);
    assert_eq!(
        prepared.recovery.reason,
        Some(RetryBlockReason::NotRecoverable)
    );
    assert!(prepared.recovery.operation.is_none());
    let fake = Fake::new(vec![uncertain()]);
    let worker = Worker::new(h.store.clone(), fake);
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert!(inspection.recovery.retry_allowed);
    assert_eq!(
        inspection.recovery.operation,
        Some(Operation::SubmitMessage.identity())
    );
    let schema =
        registry_coordinator::http::openapi()["components"]["schemas"]["OperationIdentity"].clone();
    assert!(jsonschema::JSONSchema::compile(&schema)
        .unwrap()
        .is_valid(&serde_json::to_value(&inspection.recovery.operation).unwrap()));
    let message = inspection
        .steps
        .iter()
        .find(|s| s.step == "message")
        .unwrap();
    assert_eq!(message.state, "unknown");
    assert_eq!(message.generation, 1);
    assert_eq!(message.attempt, 1);
    assert!(message.command_prepared && message.uncertain);
    assert_eq!(message.failure_code.as_deref(), Some("remote-uncertain"));
    let safe = serde_json::to_string(&inspection).unwrap();
    for canary in [
        "synthetic-contact-canary",
        "synthetic-destination-canary",
        "Synthetic appointment reminder",
    ] {
        assert!(!safe.contains(canary));
    }
    assert_eq!(
        h.store
            .inspect(run, "binding-b")
            .await
            .unwrap()
            .recovery
            .reason,
        Some(RetryBlockReason::BindingChanged)
    );
    h.store.retry_same(run, "binding-a").await.unwrap();
    worker.tick().await.unwrap();
    worker.tick().await.unwrap();
    let completed = h.store.inspect(run, "binding-a").await.unwrap();
    assert_eq!(completed.run.state, "finished");
    assert!(completed.recovery.operation.is_none());
    let message = completed
        .steps
        .iter()
        .find(|s| s.step == "message")
        .unwrap();
    assert_eq!(message.generation, 2);
    assert_eq!(message.failure_code.as_deref(), Some("remote-uncertain"));
    assert_eq!(
        completed.recovery.reason,
        Some(RetryBlockReason::NotRecoverable)
    );
}

#[tokio::test]
async fn inspection_reports_read_capability_from_the_pinned_snapshot() {
    let h = harness().await;
    let run = h.admit().await;
    let worker = Worker::new(h.store.clone(), Fake::new(vec![]));
    assert!(worker.tick().await.unwrap());
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert_eq!(inspection.run.step, "read");
    assert_eq!(
        inspection.recovery.operation,
        Some(Operation::ReadRecord.identity())
    );
    assert!(!inspection.recovery.retry_allowed);
    assert_eq!(
        inspection.recovery.reason,
        Some(RetryBlockReason::NotRecoverable)
    );
}

#[tokio::test]
async fn inspection_refuses_recovery_after_deadline_receipt_expiry_and_unsupported_abi() {
    let h = harness().await;
    let run = h.admit().await;
    let fake = Fake::new(vec![uncertain()]);
    let worker = Worker::new(h.store.clone(), fake);
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert_eq!(inspection.run.state, "attention");
    assert!(inspection.run.uncertain);
    assert_eq!(
        inspection.recovery.reason,
        Some(RetryBlockReason::DeadlineReached)
    );
    assert!(!inspection.recovery.retry_allowed);
    assert_eq!(
        inspection.recovery.operation,
        Some(Operation::SubmitMessage.identity())
    );

    let other = harness().await;
    let run = other.admit().await;
    let worker = Worker::new(
        other.store.clone(),
        Fake::new(vec![CallOutcome::ReceiptExpired]),
    );
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    assert_eq!(
        other
            .store
            .inspect(run, "binding-a")
            .await
            .unwrap()
            .recovery
            .reason,
        Some(RetryBlockReason::ReceiptExpired)
    );

    let old = harness().await;
    let run = old.admit().await;
    let worker = Worker::new(old.store.clone(), Fake::new(vec![uncertain()]));
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    old.incompatible_snapshot(run).await;
    assert!(old
        .store
        .inspect(run, "binding-a")
        .await
        .unwrap()
        .recovery
        .operation
        .is_none());
    assert_eq!(
        old.store
            .inspect(run, "binding-a")
            .await
            .unwrap()
            .recovery
            .reason,
        Some(RetryBlockReason::SnapshotIncompatible)
    );
    assert_eq!(
        old.store
            .retry_same(run, "binding-a")
            .await
            .unwrap_err()
            .code,
        "coordinator.command.definition-incompatible"
    );
    assert_eq!(old.store.status(run).await.unwrap().state, "attention");

    let pending = harness().await;
    let run = pending.admit().await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(pending.store.clone(), fake.clone());
    pending.incompatible_snapshot(run).await;
    worker
        .tick()
        .await
        .expect("unsupported ABI refuses before source effects");
    let status = pending.store.status(run).await.unwrap();
    assert_eq!(
        status.failure_code.as_deref(),
        Some("snapshot-incompatible")
    );
    assert!(fake.requests.lock().unwrap().is_empty());
}

fn actor(subject: &str, operator: bool) -> registry_coordinator::store::Actor {
    registry_coordinator::store::Actor {
        issuer: "https://issuer.example.invalid".into(),
        subject: subject.into(),
        client_id: "pilot-producer".into(),
        operator,
    }
}

#[tokio::test]
async fn protected_rows_enforce_owner_and_authenticate_cross_run_swaps() {
    let h = harness().await;
    let owner = actor("institution-a", false);
    let other = actor("institution-b", false);
    let run = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now()),
            &owner,
            "private-start-key",
            "binding-a",
        )
        .await
        .unwrap();
    assert_eq!(
        h.store.status_owned(run, &other).await.unwrap_err().code,
        "coordinator.command.run-absent"
    );
    assert!(h
        .store
        .list_owned(10, &other, std::slice::from_ref(&h.definition.workflow.id))
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        h.store
            .cancel_owned(run, &other, "outside-owner")
            .await
            .unwrap_err()
            .code,
        "coordinator.command.run-absent"
    );
    let second = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now()),
            &other,
            "second",
            "binding-a",
        )
        .await
        .unwrap();
    let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let rows = client
        .query(
            &format!("SELECT row_to_json(r)::text FROM {}.runs r", h.namespace),
            &[],
        )
        .await
        .unwrap();
    for row in rows {
        let raw: String = row.get(0);
        for private in [
            "synthetic-contact-canary",
            "private-start-key",
            "institution-a",
            "issuer.example.invalid",
        ] {
            assert!(
                !raw.contains(private),
                "stored payload and identifiers must be protected"
            );
        }
    }
    client.execute(&format!("UPDATE {}.runs SET input=(SELECT input FROM {}.runs WHERE run_id=$2) WHERE run_id=$1",h.namespace,h.namespace),&[&run,&second]).await.unwrap();
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    for _ in 0..2 {
        worker.tick().await.unwrap();
    }
    assert_eq!(
        h.store
            .status_owned(run, &owner)
            .await
            .unwrap()
            .failure_code
            .as_deref(),
        Some("protected-state-invalid")
    );
    assert!(fake.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn terminal_retention_keeps_spent_start_keys_across_payload_rotation() {
    use registry_coordinator::{protected_state::StateKeys, store::StoreSecurity};
    use registry_platform_audit::{AuditProfile, AuditWriter};
    use std::collections::BTreeMap;
    let h = harness().await;
    let owner = actor("owner", false);
    let operator = actor("operator", true);
    let original = input(Utc::now());
    let run = h
        .store
        .admit_owned(
            &h.definition,
            original.clone(),
            &owner,
            "stable-key",
            "binding-a",
        )
        .await
        .unwrap();
    let rotated = Arc::new(
        Store::open(
            &h.url,
            &h.namespace,
            StoreSecurity {
                database_id: h.namespace.clone(),
                keys: StateKeys::new(
                    2,
                    BTreeMap::from([(1, [0x11; 32]), (2, [0x44; 32])]),
                    [0x22; 32],
                )
                .unwrap(),
                audit: AuditWriter::from_line_sink(Box::new(std::io::sink())),
                audit_profile: AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
                    vec![0x33; 32],
                ))
                .unwrap(),
            },
            None,
        )
        .await
        .unwrap(),
    );
    rotated.migrate().await.unwrap(); // explicit apply registers the new immutable payload key version
    let worker = Worker::new(rotated.clone(), Fake::new(vec![]));
    for _ in 0..5 {
        worker.tick().await.unwrap();
    }
    assert_eq!(
        rotated.status_owned(run, &owner).await.unwrap().state,
        "finished"
    );
    let before_retention = rotated.doctor().await.unwrap();
    assert_eq!(before_retention.terminal_payloads, 1);
    assert!(before_retention.oldest_terminal_payload_at.is_some());
    assert_eq!(
        rotated
            .retain_terminal(Utc::now(), 100, &operator)
            .await
            .unwrap(),
        1
    );
    let after_retention = rotated.doctor().await.unwrap();
    assert_eq!(after_retention.terminal_payloads, 0);
    assert!(after_retention.oldest_terminal_payload_at.is_none());
    assert!(rotated
        .status_owned(run, &owner)
        .await
        .unwrap()
        .output
        .is_none());
    assert_eq!(
        rotated
            .admit_owned(
                &h.definition,
                original.clone(),
                &owner,
                "stable-key",
                "binding-a"
            )
            .await
            .unwrap(),
        run
    );
    let mut changed = original;
    changed["id"] = json!("different-person");
    assert_eq!(
        rotated
            .admit_owned(&h.definition, changed, &owner, "stable-key", "binding-a")
            .await
            .unwrap_err()
            .code,
        "coordinator.command.start-conflict"
    );
    let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let row=client.query_one(&format!("SELECT snapshot IS NULL AND input IS NULL AND outputs IS NULL AND terminal_output IS NULL FROM {}.runs WHERE run_id=$1",h.namespace),&[&run]).await.unwrap();
    assert!(row.get::<_, bool>(0));
    let count: i64 = client
        .query_one(
            &format!(
                "SELECT count(*) FROM {}.jobs WHERE run_id=$1 AND command IS NOT NULL",
                h.namespace
            ),
            &[&run],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[tokio::test]
async fn cancellation_and_restore_holds_do_not_extend_effect_authority() {
    let h = harness().await;
    let owner = actor("owner", false);
    let operator = actor("operator", true);
    let run = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now() + Duration::hours(1)),
            &owner,
            "pending",
            "binding-a",
        )
        .await
        .unwrap();
    let status = h
        .store
        .cancel_owned(run, &owner, "source-withdrawn")
        .await
        .unwrap();
    assert_eq!(status.state, "cancelled");
    assert!(!status.uncertain);
    assert!(h
        .store
        .retry_same_owned(run, "binding-a", &owner, "do-not-restart")
        .await
        .is_err());
    h.store
        .set_restore_hold(&operator, "restored-backup")
        .await
        .unwrap();
    assert!(!Worker::new(h.store.clone(), Fake::new(vec![]))
        .tick()
        .await
        .unwrap());
    assert_eq!(
        h.store
            .admit_owned(
                &h.definition,
                input(Utc::now()),
                &owner,
                "missing-history",
                "binding-a"
            )
            .await
            .unwrap_err()
            .code,
        "coordinator.command.restore-admissions-held"
    );
    h.store
        .release_restore_hold(&operator, "fence-record")
        .await
        .unwrap();
    assert!(h.store.doctor().await.unwrap().admissions_hold);
    assert!(h
        .store
        .release_admission_hold(&operator, "incomplete-history", false, true)
        .await
        .is_err());
    assert!(h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now()),
            &owner,
            "missing-history",
            "binding-a"
        )
        .await
        .is_err());
    h.store
        .release_admission_hold(&operator, "complete-PITR-reviewed", true, true)
        .await
        .unwrap();
    assert!(!h.store.doctor().await.unwrap().admissions_hold);
}

#[tokio::test]
async fn audit_failure_prevents_admission_and_payload_release() {
    use registry_coordinator::{protected_state::StateKeys, store::StoreSecurity};
    use registry_platform_audit::{AuditProfile, AuditWriter};
    use std::collections::BTreeMap;
    struct Fails;
    impl std::io::Write for Fails {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected audit outage"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let h = harness().await;
    let owner = actor("owner", false);
    let run = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now()),
            &owner,
            "read",
            "binding-a",
        )
        .await
        .unwrap();
    let failing = Store::open(
        &h.url,
        &h.namespace,
        StoreSecurity {
            database_id: h.namespace.clone(),
            keys: StateKeys::new(1, BTreeMap::from([(1, [0x11; 32])]), [0x22; 32]).unwrap(),
            audit: AuditWriter::from_line_sink(Box::new(Fails)),
            audit_profile: AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
                vec![0x33; 32],
            ))
            .unwrap(),
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        failing.status_owned(run, &owner).await.unwrap_err().code,
        "coordinator.command.audit-unavailable"
    );
    assert_eq!(
        failing
            .admit_owned(
                &h.definition,
                input(Utc::now()),
                &owner,
                "never-admitted",
                "binding-a"
            )
            .await
            .unwrap_err()
            .code,
        "coordinator.command.audit-unavailable"
    );
    assert_eq!(
        h.store
            .list_owned(100, &owner, std::slice::from_ref(&h.definition.workflow.id))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn changing_admission_key_cannot_reopen_a_spent_identity() {
    use registry_coordinator::{protected_state::StateKeys, store::StoreSecurity};
    use registry_platform_audit::{AuditProfile, AuditWriter};
    use std::collections::BTreeMap;
    let h = harness().await;
    let owner = actor("owner", false);
    let original = input(Utc::now());
    let run = h
        .store
        .admit_owned(
            &h.definition,
            original.clone(),
            &owner,
            "spent-key",
            "binding-a",
        )
        .await
        .unwrap();
    let wrong = Store::open(
        &h.url,
        &h.namespace,
        StoreSecurity {
            database_id: h.namespace.clone(),
            keys: StateKeys::new(1, BTreeMap::from([(1, [0x11; 32])]), [0x99; 32]).unwrap(),
            audit: AuditWriter::from_line_sink(Box::new(std::io::sink())),
            audit_profile: AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
                vec![0x33; 32],
            ))
            .unwrap(),
        },
        None,
    )
    .await
    .unwrap();
    let wrong_payload = Store::open(
        &h.url,
        &h.namespace,
        StoreSecurity {
            database_id: h.namespace.clone(),
            keys: StateKeys::new(1, BTreeMap::from([(1, [0x55; 32])]), [0x22; 32]).unwrap(),
            audit: AuditWriter::from_line_sink(Box::new(std::io::sink())),
            audit_profile: AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
                vec![0x33; 32],
            ))
            .unwrap(),
        },
        None,
    )
    .await
    .unwrap();
    assert!(wrong_payload.doctor().await.is_err());
    assert!(wrong_payload
        .admit_owned(
            &h.definition,
            original.clone(),
            &owner,
            "spent-key",
            "binding-a"
        )
        .await
        .is_err());
    assert!(wrong.doctor().await.is_err());
    assert!(wrong
        .admit_owned(&h.definition, original, &owner, "spent-key", "binding-a")
        .await
        .is_err());
    assert_eq!(
        h.store
            .list_owned(100, &owner, std::slice::from_ref(&h.definition.workflow.id))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        h.store.status_owned(run, &owner).await.unwrap().state,
        "running"
    );
}

#[tokio::test]
async fn restore_before_command_freeze_cannot_be_cleared_by_cancellation_or_plain_release() {
    let h = harness().await;
    let owner = actor("owner", false);
    let operator = actor("operator", true);
    let run = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now() + Duration::minutes(2)),
            &owner,
            "older-backup",
            "binding-a",
        )
        .await
        .unwrap();
    h.store
        .set_restore_hold(&operator, "old-backup")
        .await
        .unwrap();
    let status = h
        .store
        .cancel_owned(run, &owner, "withdraw-local-work")
        .await
        .unwrap();
    assert_eq!(status.state, "attention");
    assert!(status.restore_review_required);
    assert_eq!(
        h.store
            .release_restore_hold(&operator, "fenced-only")
            .await
            .unwrap_err()
            .code,
        "coordinator.command.restore-unresolved"
    );
    assert!(h
        .store
        .complete_execution_recovery(&operator, "unproven-history", false, true)
        .await
        .is_err());
    h.store
        .complete_execution_recovery(&operator, "verified-complete-PITR", true, true)
        .await
        .unwrap();
    assert_eq!(
        h.store
            .cancel_owned(run, &owner, "withdraw-after-complete-history")
            .await
            .unwrap()
            .state,
        "cancelled"
    );
    h.store
        .release_restore_hold(&operator, "fenced-and-history-reviewed")
        .await
        .unwrap();
    assert!(h.store.doctor().await.unwrap().admissions_hold);
}

struct ReceiptObservation;
#[async_trait]
impl AdapterSet for ReceiptObservation {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }
    async fn call(&self, _: &CallRequest) -> CallOutcome {
        panic!("observation must not send a new command")
    }
    async fn reconcile(
        &self,
        request: &CallRequest,
        _: Option<&Value>,
    ) -> registry_coordinator::protocol::ReconciliationOutcome {
        assert_eq!(request.operation, Operation::SubmitMessage);
        assert!(request.idempotency_key.is_some());
        registry_coordinator::protocol::ReconciliationOutcome::Confirmed(
            json!({"messageId":"synthetic-original-receipt"}),
        )
    }
}

/// Recreate the leased mutation row from a backup made after command freezing.
/// The original worker has stopped, so recovery cannot depend on lease reaping.
async fn restored_leased_mutation() -> (Harness, Uuid, Arc<Fake>) {
    let h = harness().await;
    let run = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now() - Duration::seconds(1)),
            &actor("owner", false),
            "restored-leased-command",
            "binding-a",
        )
        .await
        .unwrap();
    let fake = Fake::new(vec![uncertain()]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    h.sql("UPDATE {schema}.jobs SET state='leased',lease_token=gen_random_uuid(),attempt_started_at=clock_timestamp(),lease_expires_at=clock_timestamp()+interval '30 minutes' WHERE step='message'").await;
    (h, run, fake)
}

struct OriginalReceiptObservation {
    original: CallRequest,
    calls: Mutex<usize>,
    entered: Notify,
    release: Option<Semaphore>,
}
impl OriginalReceiptObservation {
    fn new(fake: &Fake, blocked: bool) -> Arc<Self> {
        Arc::new(Self {
            original: fake
                .requests
                .lock()
                .unwrap()
                .iter()
                .find(|request| request.operation.is_mutating())
                .unwrap()
                .clone(),
            calls: Mutex::new(0),
            entered: Notify::new(),
            release: blocked.then(|| Semaphore::new(0)),
        })
    }
}
#[async_trait]
impl AdapterSet for OriginalReceiptObservation {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }
    async fn call(&self, _: &CallRequest) -> CallOutcome {
        panic!("receipt observation must not send a new command")
    }
    async fn reconcile(
        &self,
        request: &CallRequest,
        _: Option<&Value>,
    ) -> registry_coordinator::protocol::ReconciliationOutcome {
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::to_value(&self.original).unwrap(),
            "observe the exact original frozen command and idempotency identity"
        );
        *self.calls.lock().unwrap() += 1;
        if let Some(release) = &self.release {
            self.entered.notify_one();
            release.acquire().await.unwrap().forget();
        }
        registry_coordinator::protocol::ReconciliationOutcome::Confirmed(
            json!({"messageId":"synthetic-original-receipt"}),
        )
    }
}

#[tokio::test]
async fn expired_leased_original_receipt_settles_under_restore_hold_without_worker_polling() {
    for cancelled in [false, true] {
        let (h, run, fake) = restored_leased_mutation().await;
        h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE step='message'").await;
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "restored-expired-lease")
            .await
            .unwrap();
        if cancelled {
            h.store
                .cancel_owned(run, &operator, "withdraw-restored-command")
                .await
                .unwrap();
        }
        let receipt = OriginalReceiptObservation::new(&fake, false);
        let observed = h
            .store
            .reconcile_owned(
                run,
                "binding-a",
                &operator,
                "original-receipt",
                receipt.as_ref(),
            )
            .await
            .unwrap();
        assert_eq!(*receipt.calls.lock().unwrap(), 1);
        assert!(!observed.run.uncertain);
        assert!(!observed.run.restore_review_required);
        assert_eq!(
            observed.run.state,
            if cancelled {
                "cancelled-after-effect"
            } else {
                "running"
            }
        );
        assert_eq!(
            observed.run.step,
            if cancelled { "message" } else { "done" }
        );
        let settled = observed
            .steps
            .iter()
            .find(|step| step.step == "message")
            .unwrap();
        assert_eq!(settled.state, "delivered");
        assert!(settled.lease_expires_at.is_none());
        assert_eq!(
            fake.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.operation.is_mutating())
                .count(),
            1
        );
        let doctor = h.store.doctor().await.unwrap();
        assert!(doctor.restore_hold && doctor.admissions_hold);
    }
}

#[tokio::test]
async fn unexpired_leased_receipt_reconciliation_is_refused_before_observation() {
    let (h, run, fake) = restored_leased_mutation().await;
    let operator = actor("operator", true);
    h.store
        .set_restore_hold(&operator, "restored-live-lease")
        .await
        .unwrap();
    let receipt = OriginalReceiptObservation::new(&fake, false);
    let error = h
        .store
        .reconcile_owned(
            run,
            "binding-a",
            &operator,
            "original-receipt",
            receipt.as_ref(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, "coordinator.command.reconcile-refused");
    assert_eq!(*receipt.calls.lock().unwrap(), 0);
    // A malformed leased row with unknown expiry is not proven expired.
    h.sql("UPDATE {schema}.jobs SET lease_expires_at=NULL WHERE step='message'")
        .await;
    let error = h
        .store
        .reconcile_owned(
            run,
            "binding-a",
            &operator,
            "original-receipt",
            receipt.as_ref(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, "coordinator.command.reconcile-refused");
    assert_eq!(*receipt.calls.lock().unwrap(), 0);
    let status = h.store.status_owned(run, &operator).await.unwrap();
    assert_eq!(status.step, "message");
    assert!(status.uncertain && status.restore_review_required);
}

#[tokio::test]
async fn lease_renewal_during_original_receipt_observation_refuses_settlement() {
    for lease_expiry in ["clock_timestamp()+interval '30 minutes'", "NULL"] {
        let (h, run, fake) = restored_leased_mutation().await;
        h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE step='message'").await;
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "restore-receipt-race")
            .await
            .unwrap();
        let receipt = OriginalReceiptObservation::new(&fake, true);
        let observing = {
            let store = h.store.clone();
            let receipt = receipt.clone();
            let operator = operator.clone();
            tokio::spawn(async move {
                store
                    .reconcile_owned(
                        run,
                        "binding-a",
                        &operator,
                        "original-receipt",
                        receipt.as_ref(),
                    )
                    .await
            })
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receipt.entered.notified(),
        )
        .await
        .unwrap();
        h.sql(&format!(
            "UPDATE {{schema}}.jobs SET lease_expires_at={lease_expiry} WHERE step='message'"
        ))
        .await;
        receipt.release.as_ref().unwrap().add_permits(1);
        let error = observing.await.unwrap().unwrap_err();
        assert_eq!(error.code, "coordinator.command.reconcile-raced");
        assert_eq!(*receipt.calls.lock().unwrap(), 1);
        let status = h.store.status_owned(run, &operator).await.unwrap();
        assert_eq!(status.step, "message");
        assert!(status.uncertain && status.restore_review_required);
    }
}

#[tokio::test]
async fn terminal_retention_and_cancellation_share_the_job_then_run_lock_order() {
    let h = harness().await;
    let run = h.admit().await;
    let worker = Worker::new(h.store.clone(), Fake::new(vec![]));
    for _ in 0..5 {
        worker.tick().await.unwrap();
    }
    assert_eq!(h.store.status(run).await.unwrap().state, "finished");
    let (mut client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let holder: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let tx = client.transaction().await.unwrap();
    tx.query(
        &format!(
            "SELECT step FROM {}.jobs WHERE run_id=$1 ORDER BY step FOR UPDATE",
            h.namespace
        ),
        &[&run],
    )
    .await
    .unwrap();
    let retention = {
        let store = h.store.clone();
        tokio::spawn(async move {
            store
                .retain_terminal(Utc::now(), 100, &actor("operator", true))
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let blocked: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE NOT granted AND $1=ANY(pg_blocking_pids(pid)))", &[&holder]).await.unwrap().get(0);
            if blocked { break; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await.expect("retention waits for the job rows held by cancellation");
    // Cancellation and Dispatch take job locks before changing the run. A
    // concurrent retention must not already hold the run while awaiting jobs.
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tx.execute(
            &format!(
                "UPDATE {}.runs SET state=state WHERE run_id=$1",
                h.namespace
            ),
            &[&run],
        ),
    )
    .await
    .expect("run remains available to the job-lock owner")
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(retention.await.unwrap().unwrap(), 1);
    assert!(h.store.status(run).await.unwrap().output.is_none());
}
#[tokio::test]
async fn final_original_receipt_settles_restored_work_without_a_new_effect() {
    let h = harness().await;
    let owner = actor("owner", false);
    let operator = actor("operator", true);
    let run = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now()),
            &owner,
            "known-command-backup",
            "binding-a",
        )
        .await
        .unwrap();
    let fake = Fake::new(vec![uncertain()]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    reach_message(&worker).await;
    worker.tick().await.unwrap();
    h.store
        .set_restore_hold(&operator, "restore-known-command")
        .await
        .unwrap();
    assert!(h
        .store
        .release_restore_hold(&operator, "external-fence")
        .await
        .is_err());
    let observed = h
        .store
        .reconcile_owned(
            run,
            "binding-a",
            &operator,
            "original-receipt-observed",
            &ReceiptObservation,
        )
        .await
        .unwrap();
    assert!(!observed.run.restore_review_required);
    assert!(!observed.run.uncertain);
    h.store
        .release_restore_hold(&operator, "external-fence-and-final-receipt")
        .await
        .unwrap();
    worker.tick().await.unwrap();
    assert_eq!(
        h.store.status_owned(run, &owner).await.unwrap().state,
        "finished"
    );
    assert_eq!(
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.operation.is_mutating())
            .count(),
        1
    );
    assert!(h.store.doctor().await.unwrap().admissions_hold);
}

#[tokio::test]
async fn expired_settled_payloads_are_erased_but_live_uncertain_and_restored_work_stays() {
    for guard in [None, Some("uncertain"), Some("pending"), Some("restore")] {
        let h = harness().await;
        let owner = actor("owner", false);
        let original = input(Utc::now() - Duration::seconds(1));
        let run = h
            .store
            .admit_owned(
                &h.definition,
                original.clone(),
                &owner,
                "expired-key",
                "binding-a",
            )
            .await
            .unwrap();
        h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
            .await;
        let fake = Fake::new(vec![]);
        Worker::new(h.store.clone(), fake.clone())
            .tick()
            .await
            .unwrap();
        assert_eq!(
            h.store.status_owned(run, &owner).await.unwrap().state,
            "expired"
        );
        assert!(fake.requests.lock().unwrap().is_empty());
        match guard {
            Some("uncertain") => h.sql("UPDATE {schema}.jobs SET uncertain=true").await,
            Some("pending") => h.sql("UPDATE {schema}.jobs SET state='pending',next_attempt_at=clock_timestamp(),expired_at=NULL").await,
            Some("restore") => {
                h.sql("UPDATE {schema}.runs SET restore_review_required=true")
                    .await
            }
            None => {}
            _ => unreachable!(),
        }
        let expected = i64::from(guard.is_none());
        assert_eq!(h.store.doctor().await.unwrap().terminal_payloads, expected);
        assert_eq!(
            h.store
                .retain_terminal(Utc::now(), 100, &actor("operator", true))
                .await
                .unwrap(),
            expected as u64
        );
        let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        let row = client.query_one(&format!("SELECT snapshot IS NULL AND input IS NULL AND outputs IS NULL AND terminal_output IS NULL,payload_erased_at IS NOT NULL FROM {}.runs WHERE run_id=$1",h.namespace), &[&run]).await.unwrap();
        assert_eq!(row.get::<_, bool>(0), guard.is_none());
        assert_eq!(row.get::<_, bool>(1), guard.is_none());
        if guard.is_none() {
            let inspection = h
                .store
                .inspect_owned(run, "binding-a", &owner)
                .await
                .unwrap();
            assert!(serde_json::to_value(&inspection).unwrap()["recovery"]
                .get("operation")
                .is_none());
            assert_eq!(
                h.store
                    .admit_owned(&h.definition, original, &owner, "expired-key", "binding-a")
                    .await
                    .unwrap(),
                run,
                "erasure keeps the original spent start identity"
            );
            assert_eq!(
                h.store
                    .inspect_owned(run, "binding-a", &owner)
                    .await
                    .unwrap()
                    .recovery
                    .reason,
                Some(RetryBlockReason::PayloadErased)
            );
        }
    }
}

#[tokio::test]
async fn owned_and_operator_flow_policy_is_applied_before_the_list_limit() {
    let h = harness().await;
    let owner = actor("owner", false);
    let original = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now()),
            &owner,
            "allowed",
            "binding-a",
        )
        .await
        .unwrap();
    h.sql("UPDATE {schema}.runs SET admitted_at=clock_timestamp()-interval '1 hour'")
        .await;
    let foreign = h
        .store
        .admit_owned(
            &h.definition,
            input(Utc::now()),
            &actor("other", false),
            "foreign",
            "binding-a",
        )
        .await
        .unwrap();
    std::fs::write(
        h.project.path().join("workflow.yaml"),
        WORKFLOW.replace("id: synthetic-reminder", "id: another-workflow"),
    )
    .unwrap();
    let another = Definition::load(h.project.path()).unwrap();
    h.store
        .admit_owned(
            &another,
            input(Utc::now()),
            &owner,
            "disallowed",
            "binding-a",
        )
        .await
        .unwrap();
    let flows = vec![h.definition.workflow.id.clone()];
    let owned = h.store.list_owned(1, &owner, &flows).await.unwrap();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].run_id, original);
    let operator = actor("operator", true);
    let all_owners = h.store.list_owned(1, &operator, &flows).await.unwrap();
    assert_eq!(all_owners.len(), 1);
    assert_eq!(all_owners[0].run_id, foreign);
    assert!(h.store.list_owned(1, &owner, &[]).await.unwrap().is_empty());
    assert!(h
        .store
        .list_owned(1, &operator, &[])
        .await
        .unwrap()
        .is_empty());
    assert!(h
        .store
        .list_owned(1, &operator, &vec!["allowed".into(); 65])
        .await
        .is_err());
}

async fn invalid_following_wait(prior: &str, body: &str) -> Harness {
    let mut h = harness().await;
    let (start, steps) = match prior {
        "read" => ("read", "  read:\n    type: call\n    connection: source\n    operation: read-record\n    input: {function: record, arguments: [{type: input}]}\n    next: later\n"),
        "choose" => ("choose", "  choose:\n    type: choose\n    choose: {function: choose_input, arguments: [{type: input}]}\n    cases: {yes: later}\n"),
        "wait" => ("wait", "  wait:\n    type: wait-until\n    waitUntil: {function: timer, arguments: [{type: input}]}\n    next: later\n"),
        "message" => ("read", "  read:\n    type: call\n    connection: source\n    operation: read-record\n    input: {function: record, arguments: [{type: input}]}\n    next: message\n  message:\n    type: call\n    connection: messages\n    operation: submit-message\n    input: {function: message, arguments: [{type: step, step: read}]}\n    next: later\n"),
        _ => panic!("unknown test prior step"),
    };
    let workflow=format!("apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1\nkind: CoordinatorProject\nproject:\n  id: synthetic-reminder\n  version: v1\ninput: {{type: object}}\nconnections: {{source: breg, messages: messaging}}\nfunctionsFile: functions.rhai\ndeadlineSeconds: 3600\nstart: {start}\nsteps:\n{steps}  later:\n    type: wait-until\n    waitUntil: {{function: broken_wait, arguments: [{{type: input}}]}}\n    next: future-read\n  future-read:\n    type: call\n    connection: source\n    operation: read-record\n    input: {{function: record, arguments: [{{type: input}}]}}\n    next: done\n  done: {{type: finish, outcome: done}}\noutcomes: {{done: {{type: 'null'}}}}\n");
    std::fs::write(h.project.path().join("workflow.yaml"), workflow).unwrap();
    std::fs::write(
        h.project.path().join("functions.rhai"),
        format!(
            "{FUNCTIONS}\nfn choose_input(input) {{ \"yes\" }}\nfn broken_wait(input) {{ {body} }}"
        ),
    )
    .unwrap();
    h.definition = Definition::load(h.project.path()).unwrap();
    h
}

impl Harness {
    async fn output_values(&self, run: Uuid) -> std::collections::BTreeMap<String, Value> {
        use base64::Engine as _;
        use registry_platform_crypto::sealed_value::{open, Context};
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        let row = client
            .query_one(
                &format!(
                    "SELECT outputs FROM {}.runs WHERE run_id=$1",
                    self.namespace
                ),
                &[&run],
            )
            .await
            .unwrap();
        let sealed: Value = row.get(0);
        let envelope = base64::engine::general_purpose::STANDARD
            .decode(sealed["sealedCoordinatorV1"].as_str().unwrap())
            .unwrap();
        let id = run.to_string();
        let bytes = open(
            &[0x11; 32],
            &Context {
                domain: "registry-coordinator/state/v1",
                scope: &[&self.namespace, &id, "outputs", ""],
                key_version: 1,
            },
            &envelope,
        )
        .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}

async fn assert_settled_mapping_failure(h: &Harness, run: Uuid, step: &str) {
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert_eq!(inspection.run.state, "failed");
    assert_eq!(inspection.run.step, step);
    assert_eq!(
        inspection.run.failure_code.as_deref(),
        Some("mapping-invalid")
    );
    assert!(!inspection.run.uncertain);
    assert!(!inspection.recovery.retry_allowed);
    assert!(matches!(
        inspection.recovery.reason,
        Some(
            RetryBlockReason::NotRecoverable
                | RetryBlockReason::DeadlineReached
                | RetryBlockReason::RestoreHold
        )
    ));
    assert_eq!(
        inspection
            .steps
            .iter()
            .find(|row| row.step == step)
            .unwrap()
            .state,
        "delivered"
    );
    assert!(!inspection
        .steps
        .iter()
        .any(|row| row.step == "later" || row.step == "future-read"));
    assert!(h.store.retry_same(run, "binding-a").await.is_err());
    assert_eq!(h.store.doctor().await.unwrap().terminal_payloads, 1);
}

#[tokio::test]
async fn known_step_success_commits_when_following_wait_mapping_is_invalid() {
    for prior in ["read", "choose", "wait", "message"] {
        for body in [
            "throw \"synthetic mapping failure\"",
            "let n = 0; loop { n += 1; }",
            "42",
            "\"not-a-timestamp\"",
        ] {
            let h = invalid_following_wait(prior, body).await;
            let run = h.admit().await;
            let fake = Fake::new(vec![]);
            let worker = Worker::new(h.store.clone(), fake.clone());
            assert!(worker.tick().await.unwrap());
            if prior == "message" {
                assert!(worker.tick().await.unwrap());
            }
            assert_settled_mapping_failure(&h, run, prior).await;
            assert!(
                !worker.tick().await.unwrap(),
                "terminal mapping failure has no next job"
            );
            if prior == "read" || prior == "message" {
                let output = h.output_values(run).await;
                assert!(output.contains_key("read"));
                if prior == "message" {
                    assert_eq!(output["message"]["messageId"], "synthetic-original-receipt");
                }
            }
            assert_eq!(
                fake.requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|r| r.operation.is_mutating())
                    .count(),
                usize::from(prior == "message")
            );
            let operator = actor("operator", true);
            let cancelled = h
                .store
                .cancel_owned(run, &operator, "already-terminal-workflow")
                .await
                .unwrap();
            assert_eq!(cancelled.state, "failed");
            assert_eq!(cancelled.failure_code.as_deref(), Some("mapping-invalid"));
            h.store
                .set_restore_hold(&operator, "review-known-effect-failure")
                .await
                .unwrap();
            assert!(h
                .store
                .release_restore_hold(&operator, "not-yet-attested")
                .await
                .is_err());
            h.store
                .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
                .await
                .unwrap();
            h.store
                .release_restore_hold(&operator, "complete-history-fenced")
                .await
                .unwrap();
            assert_eq!(
                h.store
                    .retain_terminal(Utc::now(), 100, &operator)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(h.store.doctor().await.unwrap().terminal_payloads, 0);
            assert_eq!(
                h.store
                    .inspect(run, "binding-a")
                    .await
                    .unwrap()
                    .recovery
                    .reason,
                Some(RetryBlockReason::PayloadErased)
            );
        }
    }
}

#[tokio::test]
async fn original_receipt_commits_known_effect_despite_invalid_following_wait() {
    let h = invalid_following_wait("message", "\"not-a-timestamp\"").await;
    let run = h.admit().await;
    let fake = Fake::new(vec![uncertain()]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    assert!(worker.tick().await.unwrap());
    assert!(worker.tick().await.unwrap());
    assert!(
        h.store
            .inspect(run, "binding-a")
            .await
            .unwrap()
            .run
            .uncertain
    );
    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    let operator = actor("operator", true);
    h.store
        .set_restore_hold(&operator, "restore-original-effect")
        .await
        .unwrap();
    let receipt = OriginalReceiptObservation::new(&fake, false);
    h.store
        .reconcile_owned(
            run,
            "binding-a",
            &operator,
            "original-receipt",
            receipt.as_ref(),
        )
        .await
        .unwrap();
    assert_settled_mapping_failure(&h, run, "message").await;
    assert_eq!(*receipt.calls.lock().unwrap(), 1);
    assert_eq!(
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.operation.is_mutating())
            .count(),
        1
    );
    assert_eq!(
        h.output_values(run).await["message"]["messageId"],
        "synthetic-original-receipt"
    );
    assert!(
        !h.store
            .inspect(run, "binding-a")
            .await
            .unwrap()
            .run
            .restore_review_required
    );
    assert!(!worker.tick().await.unwrap());
    h.store
        .release_restore_hold(&operator, "original-receipt-verified")
        .await
        .unwrap();
    assert_eq!(
        h.store
            .retain_terminal(Utc::now(), 100, &operator)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn failed_dead_letter_remains_recoverable_and_ineligible_for_retention() {
    let h = invalid_following_wait("message", "42").await;
    let run = h.admit().await;
    let fake = Fake::new(vec![CallOutcome::Refused {
        code: "synthetic-refusal".into(),
    }]);
    let worker = Worker::new(h.store.clone(), fake);
    worker.tick().await.unwrap();
    worker.tick().await.unwrap();
    let operator = actor("operator", true);
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert_eq!(inspection.run.state, "failed");
    assert_eq!(
        inspection
            .steps
            .iter()
            .find(|row| row.step == "message")
            .unwrap()
            .state,
        "dead-lettered"
    );
    assert!(inspection.recovery.retry_allowed);
    assert_eq!(h.store.doctor().await.unwrap().terminal_payloads, 0);
    assert_eq!(
        h.store
            .retain_terminal(Utc::now(), 100, &operator)
            .await
            .unwrap(),
        0
    );
    h.store
        .set_restore_hold(&operator, "recover-refused-command")
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
    assert_eq!(
        h.store
            .retain_terminal(Utc::now(), 100, &operator)
            .await
            .unwrap(),
        0
    );
    h.store.retry_same(run, "binding-a").await.unwrap();
}

#[tokio::test]
async fn cancelled_original_receipt_does_not_evaluate_invalid_following_wait() {
    let h = invalid_following_wait("message", "throw \"synthetic failure\"").await;
    let run = h.admit().await;
    let fake = Fake::new(vec![uncertain()]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    worker.tick().await.unwrap();
    worker.tick().await.unwrap();
    let operator = actor("operator", true);
    h.store
        .cancel_owned(run, &operator, "withdraw-future-progression")
        .await
        .unwrap();
    let receipt = OriginalReceiptObservation::new(&fake, false);
    let inspection = h
        .store
        .reconcile_owned(
            run,
            "binding-a",
            &operator,
            "original-receipt",
            receipt.as_ref(),
        )
        .await
        .unwrap();
    assert_eq!(inspection.run.state, "cancelled-after-effect");
    assert_eq!(inspection.run.step, "message");
    assert!(inspection.run.failure_code.is_none());
    assert!(!inspection.run.uncertain);
    assert_eq!(
        inspection
            .steps
            .iter()
            .find(|s| s.step == "message")
            .unwrap()
            .state,
        "delivered"
    );
    assert_eq!(
        h.output_values(run).await["message"]["messageId"],
        "synthetic-original-receipt"
    );
    assert!(!worker.tick().await.unwrap());
    assert_eq!(
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.operation.is_mutating())
            .count(),
        1
    );
}

// Model a restored worker interrupted after claiming, before its pure mapping
// or read command is frozen. No product effect or receipt is fabricated.
async fn safe_restored_lease(kind: &str) -> (Harness, Uuid) {
    let mut h =
        invalid_following_wait(if kind == "finish" { "choose" } else { kind }, "input.at").await;
    if kind == "finish" {
        let path = h.project.path().join("workflow.yaml");
        let mut document: Value = registry_coordinator::authoring::parse_project(
            &path,
            std::fs::read_to_string(&path).unwrap(),
        )
        .unwrap()
        .1
        .to_json_value();
        document["start"] = json!("done");
        document["steps"] = json!({"done":{"type":"finish","outcome":"done"}});
        std::fs::write(&path, serde_norway::to_string(&document).unwrap()).unwrap();
        h.definition = Definition::load(h.project.path()).unwrap();
    }
    let run = h.admit().await;
    h.sql("UPDATE {schema}.jobs SET state='leased',attempt=1,next_attempt_at=NULL,attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second',lease_token=gen_random_uuid() WHERE state='pending'").await;
    (h, run)
}

#[tokio::test]
async fn attested_expired_safe_leases_settle_without_dispatch_and_keep_original_identity() {
    for kind in ["read", "wait", "choose", "finish"] {
        let (h, run) = safe_restored_lease(kind).await;
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "restored-safe-lease")
            .await
            .unwrap();
        for (history, fenced) in [(false, true), (true, false)] {
            assert_eq!(
                h.store
                    .complete_execution_recovery(&operator, "incomplete-review", history, fenced)
                    .await
                    .unwrap_err()
                    .code,
                "coordinator.command.restore-review-required"
            );
            assert_eq!(
                h.store
                    .inspect(run, "binding-a")
                    .await
                    .unwrap()
                    .steps
                    .last()
                    .unwrap()
                    .state,
                "leased"
            );
        }
        let before = restored_lease_identity(&h, run).await;
        h.store
            .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
            .await
            .unwrap();
        h.store
            .release_restore_hold(&operator, "complete-history-fenced")
            .await
            .unwrap();
        let inspection = h.store.inspect(run, "binding-a").await.unwrap();
        assert_eq!(
            inspection.steps.last().unwrap().state,
            "dead-lettered",
            "{kind}"
        );
        assert_eq!(
            inspection.run.failure_code.as_deref(),
            Some("restore-safe-lease-expired")
        );
        assert_eq!(restored_lease_identity(&h, run).await, before);
        assert!(inspection.recovery.retry_allowed);
        h.store.retry_same(run, "binding-a").await.unwrap();
        assert_eq!(
            h.store
                .inspect(run, "binding-a")
                .await
                .unwrap()
                .steps
                .last()
                .unwrap()
                .state,
            "pending"
        );
    }
}

async fn restored_lease_identity(h: &Harness, run: Uuid) -> Value {
    let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let row = client.query_one(&format!("SELECT jsonb_build_object('generation',j.generation,'attempt',j.attempt,'command',j.command,'startIdentity',r.start_identity,'deadline',r.deadline_at,'inputDigest',r.input_digest,'snapshot',r.snapshot,'input',r.input,'outputs',r.outputs) FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id AND r.step=j.step WHERE r.run_id=$1", h.namespace), &[&run]).await.unwrap();
    row.get(0)
}

async fn restored_current_job(h: &Harness, run: Uuid) -> Value {
    let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    client.query_one(&format!("SELECT to_jsonb(j) FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id AND r.step=j.step WHERE r.run_id=$1", h.namespace), &[&run]).await.unwrap().get(0)
}

#[tokio::test]
async fn control_lock_timeout_preserves_the_prepared_read_for_explicit_recovery() {
    let h = invalid_following_wait("read", "input.at").await;
    let run = h.admit().await;
    // Only the worker connection has this bound. The ordinary control SELECT
    // passes, while before_io's FOR SHARE waits for this fixture's row lock.
    let mut worker_url = url::Url::parse(&h.url).unwrap();
    worker_url
        .query_pairs_mut()
        .append_pair("options", "-clock_timeout=250ms");
    let store = Arc::new(
        Store::connect(worker_url.as_str(), &h.namespace)
            .await
            .unwrap(),
    );
    let fake = Fake::new(vec![]);
    let worker = Worker::new(store, fake.clone());
    let (mut blocker, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(
        &format!("SELECT id FROM {}.control WHERE id FOR UPDATE", h.namespace),
        &[],
    )
    .await
    .unwrap();
    let result = worker.tick().await;
    tx.rollback().await.unwrap();
    let job = restored_current_job(&h, run).await;
    assert!(
        result.is_err(),
        "a live control-check timeout must be unavailable, not permanent: state={}, failure={}",
        job["state"],
        job["failure_code"]
    );
    assert_eq!(
        result.unwrap_err().code,
        "coordinator.command.worker-unavailable"
    );
    assert_eq!(job["state"], "leased");
    assert_eq!(job["uncertain"], false);
    assert!(!job["command"].is_null());
    assert!(fake.requests.lock().unwrap().is_empty());
    assert!(h.store.status(run).await.unwrap().deadline_at > Utc::now());
    let identity = restored_lease_identity(&h, run).await;

    // Dispatch retains the lease on transport error. Its existing Hold policy
    // reaps the lapse as Unknown, without automatically claiming or sending.
    h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE state='leased'").await;
    assert!(!worker.tick().await.unwrap());
    assert_eq!(restored_current_job(&h, run).await["state"], "unknown");
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    assert!(fake.requests.lock().unwrap().is_empty());
    let operator = actor("operator", true);
    h.store
        .set_restore_hold(&operator, "control-check-outage")
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
    assert_eq!(
        restored_current_job(&h, run).await["state"],
        "dead-lettered"
    );
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    assert!(fake.requests.lock().unwrap().is_empty());
    h.store.retry_same(run, "binding-a").await.unwrap();
    let replay = restored_current_job(&h, run).await;
    assert_eq!(replay["state"], "pending");
    assert_eq!(replay["command"], job["command"]);
    assert_eq!(replay["uncertain"], false);
    assert!(worker.tick().await.unwrap());
    assert_eq!(fake.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn pre_io_control_refusals_and_deadlines_still_prevent_mutation_intent() {
    for guard in ["restore-hold", "activation-changed", "deadline"] {
        let h = invalid_following_wait("message", "input.at").await;
        let run = h.admit().await;
        let fake = Fake::new(vec![]);
        assert!(Worker::new(h.store.clone(), fake.clone())
            .tick()
            .await
            .unwrap());
        fake.requests.lock().unwrap().clear();
        let change = match guard {
            "restore-hold" => "UPDATE {schema}.control SET restore_hold=true WHERE id;",
            "activation-changed" => {
                h.sql("UPDATE {schema}.control SET active_package_digest='original-package' WHERE id")
                    .await;
                "UPDATE {schema}.control SET active_package_digest='changed-package' WHERE id;"
            }
            "deadline" => "UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=NEW.run_id;",
            _ => unreachable!(),
        };
        // Change the actual control/deadline after command freezing and before
        // before_io. Claim and preparation remain real Worker transactions.
        h.sql(&format!("CREATE FUNCTION {{schema}}.change_after_prepare() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN {change} RETURN NEW; END $$; CREATE TRIGGER change_after_prepare AFTER UPDATE OF command ON {{schema}}.jobs FOR EACH ROW WHEN (OLD.command IS NULL AND NEW.command IS NOT NULL) EXECUTE FUNCTION {{schema}}.change_after_prepare();")).await;
        let store = if guard == "activation-changed" {
            Arc::new(
                (*h.store)
                    .clone()
                    .with_package_digest("original-package".into()),
            )
        } else {
            h.store.clone()
        };
        let result = Worker::new(store, fake.clone()).tick().await;
        if guard == "activation-changed" {
            assert_eq!(
                result.unwrap_err().code,
                "coordinator.command.worker-unavailable"
            );
        } else {
            assert!(result.unwrap());
        }
        let job = restored_current_job(&h, run).await;
        assert_eq!(job["uncertain"], false, "{guard}");
        assert!(!job["command"].is_null(), "{guard}");
        assert!(fake.requests.lock().unwrap().is_empty(), "{guard}");
        if guard != "deadline" {
            assert!(h.store.status(run).await.unwrap().deadline_at > Utc::now());
        }
    }
}

struct PausedRecoveryRead {
    entered: Notify,
    release: Semaphore,
    requests: Mutex<Vec<CallRequest>>,
}
#[async_trait]
impl AdapterSet for PausedRecoveryRead {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }
    async fn call(&self, request: &CallRequest) -> CallOutcome {
        assert!(request.operation.is_read());
        self.requests.lock().unwrap().push(request.clone());
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
        CallOutcome::Success(json!({"allowed":false,"contact":"synthetic-read-only"}))
    }
}

#[tokio::test]
async fn restored_expired_read_fences_paused_completion_without_reclaiming_or_reexecuting() {
    for already_reaped in [false, true] {
        let h = invalid_following_wait("read", "input.at").await;
        let run = h.admit().await;
        let fake = Arc::new(PausedRecoveryRead {
            entered: Notify::new(),
            release: Semaphore::new(0),
            requests: Mutex::new(vec![]),
        });
        let worker = Arc::new(Worker::new(h.store.clone(), fake.clone()));
        let sending = tokio::spawn({
            let worker = worker.clone();
            async move { worker.tick().await }
        });
        fake.entered.notified().await;
        h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE state='leased'").await;
        if already_reaped {
            assert!(
                !worker.tick().await.unwrap(),
                "actual Dispatch lapse reaps without a new claim"
            );
            assert_eq!(
                h.store
                    .inspect(run, "binding-a")
                    .await
                    .unwrap()
                    .steps
                    .last()
                    .unwrap()
                    .state,
                "unknown"
            );
            assert!(!h.store.status(run).await.unwrap().uncertain);
        }
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "paused-prior-worker")
            .await
            .unwrap();
        let identity = restored_lease_identity(&h, run).await;
        h.store
            .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
            .await
            .unwrap();
        h.store
            .release_restore_hold(&operator, "complete-history-fenced")
            .await
            .unwrap();
        assert!(
            !worker.tick().await.unwrap(),
            "settling a safe lease never enqueues work"
        );
        fake.release.add_permits(1);
        assert!(
            sending.await.unwrap().is_err(),
            "the old generation/token cannot complete"
        );
        assert_eq!(restored_lease_identity(&h, run).await, identity);
        assert_eq!(h.store.status(run).await.unwrap().step, "read");
        assert_eq!(fake.requests.lock().unwrap().len(), 1);
        assert!(h.output_values(run).await.is_empty());
    }
}

// Fault the real Worker at one durable boundary, never the adapter. A
// command-freeze fault proves pre-I/O; an intent fault leaves a prepared command
// which must remain protected even though uncertainty was not committed.
async fn interrupted_mutation(kind: &str, prepared: bool) -> (Harness, Uuid, Arc<Fake>) {
    let mut h = invalid_following_wait("message", "input.at").await;
    let path = h.project.path().join("workflow.yaml");
    let mut document: Value = registry_coordinator::authoring::parse_project(
        &path,
        std::fs::read_to_string(&path).unwrap(),
    )
    .unwrap()
    .1
    .to_json_value();
    document["start"] = json!("message");
    document["steps"].as_object_mut().unwrap().remove("read");
    document["steps"]["message"]["input"] =
        json!({"function":"pre_io_command","arguments":[{"type":"input"}]});
    if kind == "appointment" {
        document["connections"]["messages"] = json!("scheduling");
        document["steps"]["message"]["operation"] = json!("create-appointment");
    }
    std::fs::write(&path, serde_norway::to_string(&document).unwrap()).unwrap();
    let functions = h.project.path().join("functions.rhai");
    let body = std::fs::read_to_string(&functions).unwrap();
    std::fs::write(
        functions,
        format!("{body}\nfn pre_io_command(input) {{ #{{ synthetic: true }} }}"),
    )
    .unwrap();
    h.definition = Definition::load(h.project.path()).unwrap();
    let run = h.admit().await;
    let column = if prepared { "uncertain" } else { "command" };
    h.sql(&format!("CREATE FUNCTION {{schema}}.interrupt_pre_io() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic pre-I/O interruption'; END $$; CREATE TRIGGER interrupt_pre_io BEFORE UPDATE OF {column} ON {{schema}}.jobs FOR EACH ROW EXECUTE FUNCTION {{schema}}.interrupt_pre_io()" )).await;
    let fake = Fake::new(vec![]);
    assert!(Worker::new(h.store.clone(), fake.clone())
        .tick()
        .await
        .is_err());
    assert!(fake.requests.lock().unwrap().is_empty());
    h.sql(
        "DROP TRIGGER interrupt_pre_io ON {schema}.jobs; DROP FUNCTION {schema}.interrupt_pre_io()",
    )
    .await;
    let job = restored_current_job(&h, run).await;
    assert_eq!(job["state"], "leased");
    assert_eq!(job["uncertain"], false);
    assert_eq!(!job["command"].is_null(), prepared);
    h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE state='leased'").await;
    (h, run, fake)
}

#[tokio::test]
async fn attested_unprepared_mutations_remain_held_until_explicit_retry_or_cancel() {
    for kind in ["message", "appointment"] {
        for reaped in [false, true] {
            for deadline_passed in [false, true] {
                let (h, run, fake) = interrupted_mutation(kind, false).await;
                let worker = Worker::new(h.store.clone(), fake.clone());
                if reaped {
                    assert!(
                        !worker.tick().await.unwrap(),
                        "Dispatch lapse must not claim new work"
                    );
                    assert_eq!(restored_current_job(&h, run).await["state"], "unknown");
                }
                if deadline_passed {
                    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'").await;
                }
                let operator = actor("operator", true);
                h.store
                    .set_restore_hold(&operator, "unprepared-pre-io-restored")
                    .await
                    .unwrap();
                let identity = restored_lease_identity(&h, run).await;
                for (history, fenced) in [(false, true), (true, false)] {
                    assert_eq!(
                        h.store
                            .complete_execution_recovery(
                                &operator,
                                "missing-history-or-fence",
                                history,
                                fenced
                            )
                            .await
                            .unwrap_err()
                            .code,
                        "coordinator.command.restore-review-required"
                    );
                    assert_eq!(restored_lease_identity(&h, run).await, identity);
                    assert_eq!(
                        restored_current_job(&h, run).await["state"],
                        if reaped { "unknown" } else { "leased" }
                    );
                }
                h.store
                    .complete_execution_recovery(
                        &operator,
                        "complete-pre-io-history-fenced",
                        true,
                        true,
                    )
                    .await
                    .unwrap();
                h.store
                    .release_restore_hold(&operator, "complete-pre-io-history-fenced")
                    .await
                    .unwrap();
                assert_eq!(restored_lease_identity(&h, run).await, identity);
                assert_eq!(
                    restored_current_job(&h, run).await["state"],
                    "dead-lettered"
                );
                assert!(
                    !worker.tick().await.unwrap(),
                    "attestation never enqueues work"
                );
                assert!(fake.requests.lock().unwrap().is_empty());
                if deadline_passed {
                    assert!(h.store.retry_same(run, "binding-a").await.is_err());
                    h.store
                        .cancel_owned(run, &operator, "past-original-deadline")
                        .await
                        .unwrap();
                    assert_eq!(
                        h.store
                            .retain_terminal(Utc::now(), 100, &operator)
                            .await
                            .unwrap(),
                        1
                    );
                } else {
                    h.store.retry_same(run, "binding-a").await.unwrap();
                    assert_eq!(restored_current_job(&h, run).await["state"], "pending");
                    assert!(
                        fake.requests.lock().unwrap().is_empty(),
                        "retry requires a separate worker attempt"
                    );
                }
            }
        }
    }
}

async fn prepared_pending_mutation(kind: &str) -> (Harness, Uuid, Arc<Fake>, CallRequest) {
    let mut h = invalid_following_wait("message", "input.at").await;
    if kind == "appointment" {
        let path = h.project.path().join("workflow.yaml");
        let mut document: Value = registry_coordinator::authoring::parse_project(
            &path,
            std::fs::read_to_string(&path).unwrap(),
        )
        .unwrap()
        .1
        .to_json_value();
        document["connections"]["messages"] = json!("scheduling");
        document["steps"]["message"]["operation"] = json!("create-appointment");
        std::fs::write(&path, serde_norway::to_string(&document).unwrap()).unwrap();
        h.definition = Definition::load(h.project.path()).unwrap();
    }
    let run = h.admit().await;
    let fake = Fake::new(vec![CallOutcome::Retryable {
        code: "rate-limited".into(),
    }]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    assert!(worker.tick().await.unwrap(), "read the original input");
    assert!(
        worker.tick().await.unwrap(),
        "record a definite retryable response"
    );
    let original = fake.requests.lock().unwrap().last().unwrap().clone();
    assert!(original.operation.is_mutating());
    let job = restored_current_job(&h, run).await;
    assert_eq!(job["state"], "pending");
    assert_eq!(job["uncertain"], false);
    assert!(!job["command"].is_null());
    // Make the existing retry due without waiting on the scheduler's clock.
    h.sql("UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE state='pending'").await;
    fake.requests.lock().unwrap().clear();
    (h, run, fake, original)
}

#[tokio::test]
async fn restored_prepared_pending_mutations_require_explicit_retry_or_cancel() {
    for kind in ["message", "appointment"] {
        for cancel in [false, true] {
            let (h, run, fake, original) = prepared_pending_mutation(kind).await;
            let worker = Worker::new(h.store.clone(), fake.clone());
            let operator = actor("operator", true);
            h.store
                .set_restore_hold(&operator, "prepared-retry-restored")
                .await
                .unwrap();
            let identity = restored_lease_identity(&h, run).await;
            for (history, fenced) in [(false, true), (true, false)] {
                assert_eq!(
                    h.store
                        .complete_execution_recovery(
                            &operator,
                            "incomplete-recovery",
                            history,
                            fenced
                        )
                        .await
                        .unwrap_err()
                        .code,
                    "coordinator.command.restore-review-required"
                );
                assert_eq!(restored_lease_identity(&h, run).await, identity);
            }
            h.store
                .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
                .await
                .unwrap();
            h.store
                .release_restore_hold(&operator, "complete-history-fenced")
                .await
                .unwrap();
            assert!(!worker.tick().await.unwrap(), "restored prepared {kind} must not dispatch automatically after attestation and hold release");
            assert!(fake.requests.lock().unwrap().is_empty());
            assert_eq!(
                restored_current_job(&h, run).await["state"],
                "dead-lettered"
            );
            assert_eq!(restored_lease_identity(&h, run).await, identity);
            if cancel {
                assert_eq!(
                    h.store
                        .cancel_owned(run, &operator, "withdraw-original-command")
                        .await
                        .unwrap()
                        .state,
                    "cancelled"
                );
                assert!(!worker.tick().await.unwrap());
                assert!(fake.requests.lock().unwrap().is_empty());
                assert_eq!(
                    h.store
                        .retain_terminal(Utc::now(), 100, &operator)
                        .await
                        .unwrap(),
                    1
                );
            } else {
                h.store.retry_same(run, "binding-a").await.unwrap();
                assert!(
                    fake.requests.lock().unwrap().is_empty(),
                    "explicit retry only schedules the original command"
                );
                assert!(worker.tick().await.unwrap());
                let requests = fake.requests.lock().unwrap();
                assert_eq!(requests.len(), 1);
                assert_eq!(
                    serde_json::to_value(&requests[0]).unwrap(),
                    serde_json::to_value(&original).unwrap(),
                    "explicit retry must retain the exact original command and key"
                );
            }
        }
    }
}

// A real read can retain a prepared command after a retryable transport result.
struct RetryableRead(Arc<Fake>);
#[async_trait]
impl AdapterSet for RetryableRead {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }
    async fn call(&self, request: &CallRequest) -> CallOutcome {
        let retry = self.0.outcomes.lock().unwrap().pop_front();
        if let Some(outcome) = retry {
            self.0.requests.lock().unwrap().push(request.clone());
            outcome
        } else {
            self.0.call(request).await
        }
    }
}

#[path = "support/restore_pending.rs"]
mod restore_pending;

#[tokio::test]
async fn restored_prepared_pending_keeps_deadline_and_cancelled_retention() {
    for kind in ["message", "appointment"] {
        for cancelled_before in [false, true] {
            let (h, run, fake, _) = prepared_pending_mutation(kind).await;
            let operator = actor("operator", true);
            if !cancelled_before {
                h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
                    .await;
            }
            h.store
                .set_restore_hold(&operator, "prepared-pending-restored")
                .await
                .unwrap();
            if cancelled_before {
                h.store
                    .cancel_owned(run, &operator, "withdraw-before-review")
                    .await
                    .unwrap();
            }
            let identity = restored_lease_identity(&h, run).await;
            h.store
                .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
                .await
                .unwrap();
            h.store
                .release_restore_hold(&operator, "complete-history-fenced")
                .await
                .unwrap();
            assert_eq!(restored_lease_identity(&h, run).await, identity);
            assert_eq!(
                restored_current_job(&h, run).await["state"],
                "dead-lettered"
            );
            assert!(h.store.retry_same(run, "binding-a").await.is_err());
            assert!(!Worker::new(h.store.clone(), fake.clone())
                .tick()
                .await
                .unwrap());
            assert!(fake.requests.lock().unwrap().is_empty());
            h.store
                .cancel_owned(run, &operator, "withdraw-held-command")
                .await
                .unwrap();
            assert_eq!(
                h.store
                    .retain_terminal(Utc::now(), 100, &operator)
                    .await
                    .unwrap(),
                1
            );
        }
    }
}

#[tokio::test]
async fn active_retryable_mutation_requires_repeated_recovery_before_hold_release() {
    let h = invalid_following_wait("message", "input.at").await;
    let run = h.admit().await;
    let fake = Arc::new(Fake {
        outcomes: Mutex::new(
            vec![CallOutcome::Retryable {
                code: "rate-limited".into(),
            }]
            .into(),
        ),
        requests: Mutex::new(vec![]),
        allowed: true,
        entered: Notify::new(),
        release: Some(Semaphore::new(0)),
    });
    let worker = Arc::new(Worker::new(h.store.clone(), fake.clone()));
    assert!(worker.tick().await.unwrap());
    let sending = tokio::spawn({
        let worker = worker.clone();
        async move { worker.tick().await }
    });
    fake.entered.notified().await;
    let original = fake.requests.lock().unwrap().last().unwrap().clone();
    let operator = actor("operator", true);
    h.store
        .set_restore_hold(&operator, "active-retry-restored")
        .await
        .unwrap();
    let identity = restored_lease_identity(&h, run).await;
    // Pause the final review-clear statement after the job scan. The live
    // worker must be unable to change its lease to Pending inside this gap.
    let gate = i64::from(Uuid::new_v4().as_fields().0 & 0x7fff_ffff);
    let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    client
        .query_one("SELECT pg_advisory_lock($1)", &[&gate])
        .await
        .unwrap();
    h.sql(&format!("CREATE FUNCTION {{schema}}.pause_review_clear() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({gate}); RETURN NULL; END $$; CREATE TRIGGER pause_review_clear BEFORE UPDATE OF restore_review_required ON {{schema}}.runs FOR EACH STATEMENT EXECUTE FUNCTION {{schema}}.pause_review_clear()")).await;
    let recovering = tokio::spawn({
        let store = h.store.clone();
        let operator = operator.clone();
        async move {
            store
                .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
                .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked: bool = client.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND objid::bigint=$1)", &[&gate]).await.unwrap().get(0);
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("recovery reached review-clear barrier");
    fake.release.as_ref().unwrap().add_permits(1);
    let mut sending = sending;
    let blocked_completion =
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut sending).await;
    client
        .query_one("SELECT pg_advisory_unlock($1)", &[&gate])
        .await
        .unwrap();
    recovering.await.unwrap().unwrap();
    h.sql("DROP TRIGGER pause_review_clear ON {schema}.runs; DROP FUNCTION {schema}.pause_review_clear()").await;
    assert!(
        blocked_completion.is_err(),
        "live completion must wait for attested recovery's job lock"
    );

    assert!(
        h.store
            .inspect(run, "binding-a")
            .await
            .unwrap()
            .run
            .restore_review_required
    );
    assert_eq!(
        h.store
            .release_restore_hold(&operator, "complete-history-fenced")
            .await
            .unwrap_err()
            .code,
        "coordinator.command.restore-unresolved"
    );
    assert!(sending.await.unwrap().unwrap());
    let pending = restored_current_job(&h, run).await;
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["uncertain"], false);
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    assert!(
        h.store
            .inspect(run, "binding-a")
            .await
            .unwrap()
            .run
            .restore_review_required
    );
    assert_eq!(
        h.store
            .release_restore_hold(&operator, "complete-history-fenced")
            .await
            .unwrap_err()
            .code,
        "coordinator.command.restore-unresolved"
    );
    h.store
        .complete_execution_recovery(&operator, "retry-result-reviewed", true, true)
        .await
        .unwrap();
    h.store
        .release_restore_hold(&operator, "retry-result-reviewed")
        .await
        .unwrap();
    assert_eq!(
        restored_current_job(&h, run).await["state"],
        "dead-lettered"
    );
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    fake.requests.lock().unwrap().clear();
    assert!(!worker.tick().await.unwrap());
    assert!(fake.requests.lock().unwrap().is_empty());
    h.store.retry_same(run, "binding-a").await.unwrap();
    fake.release.as_ref().unwrap().add_permits(1);
    assert!(worker.tick().await.unwrap());
    let requests = fake.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        serde_json::to_value(&requests[0]).unwrap(),
        serde_json::to_value(original).unwrap()
    );
}

#[tokio::test]
async fn attested_recovery_preserves_active_mutating_unknown_and_uncertain_leases() {
    for kind in [
        "active-read",
        "unknown-expiry-read",
        "uncertain-read",
        "unknown-uncertain-read",
        "unknown-message",
        "receipt-expired-read",
        "unknown-receipt-expired-read",
        "message",
        "appointment",
    ] {
        let (h, run) = if matches!(kind, "message" | "appointment" | "unknown-message") {
            let (h, run, fake) = interrupted_mutation(
                if kind == "appointment" {
                    "appointment"
                } else {
                    "message"
                },
                true,
            )
            .await;
            assert!(fake.requests.lock().unwrap().is_empty());
            (h, run)
        } else {
            safe_restored_lease("read").await
        };
        match kind {
            "active-read"=>h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp(),lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE state='leased'").await,
            "unknown-expiry-read"=>h.sql("UPDATE {schema}.jobs SET lease_expires_at=NULL WHERE state='leased'").await,
            "uncertain-read"=>h.sql("UPDATE {schema}.jobs SET uncertain=true WHERE state='leased'").await,
            "unknown-uncertain-read"=>h.sql("UPDATE {schema}.jobs SET state='unknown',uncertain=true,attempt_started_at=NULL,lease_expires_at=NULL,lease_token=NULL WHERE state='leased'").await,
            "unknown-receipt-expired-read"=>h.sql("UPDATE {schema}.jobs SET state='unknown',receipt_expired=true,attempt_started_at=NULL,lease_expires_at=NULL,lease_token=NULL WHERE state='leased'").await,
            "unknown-message"=>h.sql("UPDATE {schema}.jobs SET state='unknown',attempt_started_at=NULL,lease_expires_at=NULL,lease_token=NULL WHERE state='leased'").await,
            "receipt-expired-read"=>h.sql("UPDATE {schema}.jobs SET receipt_expired=true WHERE state='leased'").await,
            _=>{},
        }
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "protected-restored-lease")
            .await
            .unwrap();
        let before = h.store.inspect(run, "binding-a").await.unwrap();
        let identity = restored_lease_identity(&h, run).await;
        let job_before = restored_current_job(&h, run).await;
        h.store
            .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
            .await
            .unwrap();
        assert_eq!(
            h.store
                .release_restore_hold(&operator, "complete-history-fenced")
                .await
                .unwrap_err()
                .code,
            "coordinator.command.restore-unresolved",
            "{kind}"
        );
        let after = h.store.inspect(run, "binding-a").await.unwrap();
        assert_eq!(
            after
                .steps
                .iter()
                .find(|step| step.step == after.run.step)
                .unwrap()
                .state,
            before
                .steps
                .iter()
                .find(|step| step.step == before.run.step)
                .unwrap()
                .state,
            "{kind}"
        );
        assert_eq!(after.run.uncertain, before.run.uncertain);
        let job_after = restored_current_job(&h, run).await;
        assert_eq!(job_after, job_before, "{kind}: no job fields may change");
        assert_eq!(restored_lease_identity(&h, run).await, identity);
        if kind == "active-read" {
            h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE state='leased'").await;
            h.store
                .complete_execution_recovery(&operator, "later-expired-read", true, true)
                .await
                .unwrap();
            h.store
                .release_restore_hold(&operator, "later-expired-read")
                .await
                .unwrap();
            assert_eq!(
                restored_current_job(&h, run).await["state"],
                "dead-lettered"
            );
            assert_eq!(restored_lease_identity(&h, run).await, identity);
        }
    }
}

#[tokio::test]
async fn expired_read_after_deadline_is_cancellable_and_retirable_without_replay() {
    for kind in ["read", "wait"] {
        for already_cancelled in [false, true] {
            let (h, run) = safe_restored_lease(kind).await;
            h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
                .await;
            let operator = actor("operator", true);
            if already_cancelled {
                h.store
                    .cancel_owned(run, &operator, "stop-old-read")
                    .await
                    .unwrap();
            }
            h.store
                .set_restore_hold(&operator, "expired-read-history")
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
            assert!(
                !h.store
                    .inspect(run, "binding-a")
                    .await
                    .unwrap()
                    .recovery
                    .retry_allowed
            );
            assert!(h.store.retry_same(run, "binding-a").await.is_err());
            let status = h
                .store
                .cancel_owned(run, &operator, "read-deadline-reached")
                .await
                .unwrap();
            assert_eq!(status.state, "cancelled");
            assert_eq!(
                h.store
                    .retain_terminal(Utc::now(), 100, &operator)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                h.store
                    .inspect(run, "binding-a")
                    .await
                    .unwrap()
                    .recovery
                    .reason,
                Some(RetryBlockReason::PayloadErased)
            );
        }
    }
}

#[tokio::test]
async fn incompatible_restored_lease_rolls_back_all_safe_transitions_and_review_clearance() {
    for corruption in ["snapshot", "command"] {
        let (h, first) = safe_restored_lease("read").await;
        let second = h
            .store
            .admit(
                &h.definition,
                input(Utc::now()),
                "synthetic-producer",
                "another-start",
                "binding-a",
            )
            .await
            .unwrap();
        h.sql("UPDATE {schema}.jobs SET state='leased',attempt=1,next_attempt_at=NULL,attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second',lease_token=gen_random_uuid() WHERE state='pending'").await;
        // UUID order makes a valid row transition before the corrupt row is
        // decoded, proving the whole attested transaction rolls back.
        let corrupt = std::cmp::max(first, second);
        if corruption == "snapshot" {
            h.incompatible_snapshot(corrupt).await;
        } else {
            h.sql(&format!(
                "UPDATE {{schema}}.jobs SET command='{{}}'::jsonb WHERE run_id='{corrupt}'"
            ))
            .await;
        }
        let operator = actor("operator", true);
        h.store
            .set_restore_hold(&operator, "corrupt-lease-history")
            .await
            .unwrap();
        assert_eq!(
            h.store
                .complete_execution_recovery(&operator, "complete-history-fenced", true, true)
                .await
                .unwrap_err()
                .code,
            "coordinator.command.restore-lease-incompatible"
        );
        for run in [first, second] {
            let status = h.store.status(run).await.unwrap();
            assert!(status.restore_review_required);
            let inspection = h.store.inspect(run, "binding-a").await.unwrap();
            assert_eq!(inspection.steps.last().unwrap().state, "leased");
        }
        assert!(h.store.doctor().await.unwrap().restore_hold);
    }
}

#[path = "support/store_revision.rs"]
mod store_revision;

#[path = "support/decision_evaluation.rs"]
mod decision_evaluation;
