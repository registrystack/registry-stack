// SPDX-License-Identifier: Apache-2.0
//! A lapsed read lease retries, while any step that may have caused an effect holds.
#![cfg(feature = "postgres-test")]

use async_trait::async_trait;
use registry_coordinator::{
    definition::Definition,
    protected_state::StateKeys,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
    store::{Store, StoreSecurity},
    worker::Worker,
};
use registry_platform_audit::{AuditProfile, AuditWriter};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{Notify, Semaphore};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

const READ_WORKFLOW: &str = r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: read-lease-recovery, version: v1}
operations:
  read:
    uses: breg.read-record/v1
    connection: source
workflow:
  input: {type: object, additionalProperties: false}
  deadlineSeconds: 3600
  start: read
  steps:
    read:
      type: call
      operation: read
      input:
        type: fields
        fields:
          collection: {type: literal, value: people}
          recordId: {type: literal, value: 00000000-0000-4000-8000-000000000001}
      next: done
    done:
      type: finish
      outcome: observed
      output: {type: step, step: read}
  outcomes:
    observed: {operationOutput: read}
"#;

const MUTATION_WORKFLOW: &str = r#"
apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: mutation-lease-recovery, version: v1}
operations:
  send:
    uses: messaging.submit-message/v1
    connection: notices
workflow:
  input: {type: object, additionalProperties: false}
  deadlineSeconds: 3600
  start: send
  steps:
    send:
      type: call
      operation: send
      input:
        type: literal
        value:
          senderProfile: reminders
          to: {email: synthetic@example.invalid}
          content: {text: Synthetic recovery proof}
      next: done
    done: {type: finish, outcome: sent}
  outcomes:
    sent: {type: 'null'}
"#;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn clear(&self) {
        self.0.lock().expect("capture lock").clear();
    }

    fn entries(&self) -> Vec<Value> {
        let bytes = self.0.lock().expect("capture lock");
        std::str::from_utf8(&bytes)
            .expect("UTF-8 audit")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON audit entry"))
            .collect()
    }
}

struct Harness {
    url: String,
    namespace: String,
    store: Arc<Store>,
    definition: Definition,
    capture: Capture,
}

impl Harness {
    async fn new(workflow: &str) -> Self {
        let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").expect(
            "COORDINATOR_TEST_DATABASE_URL must name a disposable synthetic PostgreSQL 17+ database",
        );
        let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
        let bootstrap = Store::connect(&url, &namespace)
            .await
            .expect("local disposable connection");
        bootstrap.migrate().await.expect("isolated migration");
        let capture = Capture::default();
        let store = Arc::new(
            Store::open(
                &url,
                &namespace,
                StoreSecurity {
                    database_id: namespace.clone(),
                    keys: StateKeys::new(1, BTreeMap::from([(1, [0x11; 32])]), [0x22; 32])
                        .expect("test keys"),
                    audit: AuditWriter::from_line_sink(Box::new(capture.clone())),
                    audit_profile: AuditProfile::production_from_secret_bytes(
                        zeroize::Zeroizing::new(vec![0x33; 32]),
                    )
                    .expect("audit profile"),
                },
                None,
            )
            .await
            .expect("open migrated store"),
        );
        let project = tempfile::tempdir().expect("project");
        std::fs::write(project.path().join("workflow.yaml"), workflow).expect("workflow");
        let definition = Definition::load(project.path()).expect("valid recovery workflow");
        Self {
            url,
            namespace,
            store,
            definition,
            capture,
        }
    }

    async fn admit(&self) -> Uuid {
        let run = self
            .store
            .admit(
                &self.definition,
                json!({}),
                "synthetic-producer",
                &Uuid::new_v4().to_string(),
                "binding-a",
            )
            .await
            .expect("admit");
        self.capture.clear();
        run
    }

    async fn client(&self) -> Client {
        let (client, connection) = tokio_postgres::connect(&self.url, NoTls)
            .await
            .expect("test connection");
        tokio::spawn(async move {
            connection.await.expect("test connection finishes");
        });
        client
    }

    async fn lapse(&self, run: Uuid) {
        self.client()
            .await
            .execute(
                &format!(
                    "UPDATE {}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND state='leased'",
                    self.namespace
                ),
                &[&run],
            )
            .await
            .expect("lapse lease");
    }

    async fn make_retry_due(&self, run: Uuid) {
        self.client()
            .await
            .execute(
                &format!(
                    "UPDATE {}.jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND state='pending'",
                    self.namespace
                ),
                &[&run],
            )
            .await
            .expect("make retry due");
    }

    async fn spend_attempts(&self, run: Uuid) {
        self.client()
            .await
            .execute(
                &format!(
                    "UPDATE {}.jobs SET attempt=10 WHERE run_id=$1 AND state='leased'",
                    self.namespace
                ),
                &[&run],
            )
            .await
            .expect("spend attempt budget");
    }

    async fn expire_run(&self, run: Uuid) {
        self.client()
            .await
            .execute(
                &format!(
                    "UPDATE {}.runs SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1",
                    self.namespace
                ),
                &[&run],
            )
            .await
            .expect("expire run");
    }

    async fn job(&self, run: Uuid, step: &str) -> (String, i16, i64) {
        let row = self
            .client()
            .await
            .query_one(
                &format!(
                    "SELECT state,attempt,generation FROM {}.jobs WHERE run_id=$1 AND step=$2",
                    self.namespace
                ),
                &[&run, &step],
            )
            .await
            .expect("job row");
        (row.get(0), row.get(1), row.get(2))
    }

    fn assert_lapse_audit(&self) {
        let entries: Vec<_> = self
            .capture
            .entries()
            .into_iter()
            .filter(|entry| entry["record"]["action"] == "lease-lapsed")
            .collect();
        assert_eq!(entries.len(), 2, "one request/response lapse audit pair");
        assert_eq!(entries[0]["phase"], "request");
        assert_eq!(entries[0]["record"]["outcome"], "intent");
        assert_eq!(entries[1]["phase"], "response");
        assert_eq!(entries[1]["record"]["outcome"], "committed");
        assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    }
}

struct BlockingAdapter {
    calls: AtomicUsize,
    entered: Notify,
    release: Semaphore,
    marker: &'static str,
}

impl BlockingAdapter {
    fn new(marker: &'static str) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Semaphore::new(0),
            marker,
        })
    }
}

struct ImmediateAdapter {
    calls: AtomicUsize,
    marker: &'static str,
}

impl ImmediateAdapter {
    fn new(marker: &'static str) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            marker,
        })
    }
}

fn response(operation: Operation, marker: &str) -> CallOutcome {
    if operation == Operation::ReadRecord {
        CallOutcome::Success(json!({
            "meta": {
                "registryIdentifier": "fixture",
                "datasetIdentifier": "people",
                "entityTypeIdentifier": "person"
            },
            "data": {
                "recordIdentifier": "00000000-0000-4000-8000-000000000001",
                "revisionIdentifier": marker,
                "domainData": {}
            }
        }))
    } else {
        CallOutcome::Success(json!({
            "id": "00000000-0000-4000-8000-000000000002",
            "status": "queued",
            "links": {
                "self": "/v1/messages/00000000-0000-4000-8000-000000000002",
                "cancel": "/v1/messages/00000000-0000-4000-8000-000000000002/cancel"
            }
        }))
    }
}

#[async_trait]
impl AdapterSet for BlockingAdapter {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        let permit = self.release.acquire().await.expect("release stalled call");
        permit.forget();
        response(request.operation, self.marker)
    }
}

#[async_trait]
impl AdapterSet for ImmediateAdapter {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        response(request.operation, self.marker)
    }
}

async fn stall_attempt(
    harness: &Harness,
    adapter: Arc<BlockingAdapter>,
) -> tokio::task::JoinHandle<registry_coordinator::Result<bool>> {
    let worker = Worker::new(harness.store.clone(), adapter.clone());
    let stalled = tokio::spawn(async move { worker.tick().await });
    tokio::time::timeout(Duration::from_secs(10), adapter.entered.notified())
        .await
        .expect("worker reaches adapter");
    stalled
}

#[tokio::test]
async fn lapsed_read_retries_and_fences_the_old_attempt() {
    let harness = Harness::new(READ_WORKFLOW).await;
    let run = harness.admit().await;
    let stale = BlockingAdapter::new("stale");
    let stalled = stall_attempt(&harness, stale.clone()).await;
    harness.lapse(run).await;

    let replacement = ImmediateAdapter::new("replacement");
    let worker = Worker::new(harness.store.clone(), replacement.clone());
    worker.tick().await.expect("recover lapsed read");
    assert_eq!(harness.job(run, "read").await.0, "pending");
    harness.assert_lapse_audit();

    harness.make_retry_due(run).await;
    assert!(worker.tick().await.expect("replacement read"));
    assert_eq!(replacement.calls.load(Ordering::SeqCst), 1);
    let after_replacement = harness.job(run, "read").await;
    assert_eq!(after_replacement.0, "delivered");
    assert_eq!(after_replacement.1, 2);

    stale.release.add_permits(1);
    assert!(stalled.await.expect("stalled worker task").is_err());
    assert_eq!(harness.job(run, "read").await, after_replacement);

    assert!(worker.tick().await.expect("finish replacement read"));
    let status = harness.store.status(run).await.expect("finished status");
    assert_eq!(status.state, "finished");
    assert_eq!(
        status.output.unwrap()["data"]["revisionIdentifier"],
        "replacement"
    );
    assert_eq!(stale.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lapsed_mutation_holds_unknown_for_operator_review() {
    let harness = Harness::new(MUTATION_WORKFLOW).await;
    let run = harness.admit().await;
    let stale = BlockingAdapter::new("stale");
    let stalled = stall_attempt(&harness, stale.clone()).await;
    harness.lapse(run).await;

    let worker = Worker::new(harness.store.clone(), ImmediateAdapter::new("replacement"));
    worker.tick().await.expect("recover lapsed mutation");
    assert_eq!(harness.job(run, "send").await.0, "unknown");
    let status = harness.store.status(run).await.expect("held status");
    assert_eq!(status.state, "attention");
    assert_eq!(status.failure_code.as_deref(), Some("lease-lapsed"));
    harness.assert_lapse_audit();

    stale.release.add_permits(1);
    assert!(stalled.await.expect("stalled worker task").is_err());
    assert_eq!(harness.job(run, "send").await.0, "unknown");
}

#[tokio::test]
async fn lapsed_read_holds_when_attempts_are_spent() {
    let harness = Harness::new(READ_WORKFLOW).await;
    let run = harness.admit().await;
    let stale = BlockingAdapter::new("stale");
    let stalled = stall_attempt(&harness, stale.clone()).await;
    harness.spend_attempts(run).await;
    harness.lapse(run).await;

    let worker = Worker::new(harness.store.clone(), ImmediateAdapter::new("replacement"));
    worker.tick().await.expect("recover exhausted read");
    assert_eq!(harness.job(run, "read").await.0, "unknown");
    assert_eq!(harness.store.status(run).await.unwrap().state, "attention");

    stale.release.add_permits(1);
    assert!(stalled.await.expect("stalled worker task").is_err());
}

#[tokio::test]
async fn lapsed_read_holds_after_its_deadline() {
    let harness = Harness::new(READ_WORKFLOW).await;
    let run = harness.admit().await;
    let stale = BlockingAdapter::new("stale");
    let stalled = stall_attempt(&harness, stale.clone()).await;
    harness.expire_run(run).await;
    harness.lapse(run).await;

    let worker = Worker::new(harness.store.clone(), ImmediateAdapter::new("replacement"));
    worker.tick().await.expect("recover expired read");
    assert_eq!(harness.job(run, "read").await.0, "unknown");
    assert_eq!(harness.store.status(run).await.unwrap().state, "attention");

    stale.release.add_permits(1);
    assert!(stalled.await.expect("stalled worker task").is_err());
}
