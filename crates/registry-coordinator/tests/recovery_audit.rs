// SPDX-License-Identifier: Apache-2.0
//! Recovery references remain correlatable without disclosing operator text.
#![cfg(feature = "postgres-test")]
use async_trait::async_trait;
use chrono::{Duration, Utc};
use registry_coordinator::{
    definition::Definition,
    protected_state::StateKeys,
    protocol::{AdapterSet, CallOutcome, CallRequest},
    store::{Actor, Store, StoreSecurity},
};
use registry_platform_audit::{AuditProfile, AuditWriter};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const REASON: &str = "investigation-sensitive-canary@example.invalid";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Capture {
    fn entries(&self) -> Vec<Value> {
        let bytes = self.0.lock().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains(REASON),
            "operator text must stay out of audit"
        );
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}
struct LimitedSink {
    capture: Capture,
    remaining: usize,
}
impl Write for LimitedSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("synthetic audit outage"));
        }
        self.remaining -= 1;
        self.capture.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct NoIo;
#[async_trait]
impl AdapterSet for NoIo {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }
    async fn call(&self, _: &CallRequest) -> CallOutcome {
        panic!("recovery audit must not dispatch a new command")
    }
}
fn actor(subject: &str, operator: bool) -> Actor {
    Actor {
        issuer: "https://issuer.example.invalid".into(),
        subject: subject.into(),
        client_id: "operator-client".into(),
        operator,
    }
}
fn profile() -> AuditProfile {
    AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(vec![0x33; 32])).unwrap()
}
struct Harness {
    url: String,
    namespace: String,
    store: Store,
    capture: Capture,
    run: Uuid,
}
impl Harness {
    async fn open(&self, sink: impl Write + Send + 'static) -> Store {
        Store::open(
            &self.url,
            &self.namespace,
            StoreSecurity {
                database_id: self.namespace.clone(),
                keys: StateKeys::new(1, BTreeMap::from([(1, [0x11; 32])]), [0x22; 32]).unwrap(),
                audit: AuditWriter::from_line_sink(Box::new(sink)),
                audit_profile: profile(),
            },
            None,
        )
        .await
        .unwrap()
    }
}
async fn harness() -> Harness {
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("COORDINATOR_TEST_DATABASE_URL must name disposable synthetic PostgreSQL");
    let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
    let bootstrap = Store::connect(&url, &namespace).await.unwrap();
    bootstrap.migrate().await.unwrap();
    let capture = Capture::default();
    let mut h = Harness {
        url,
        namespace,
        store: bootstrap,
        capture,
        run: Uuid::nil(),
    };
    h.store = h.open(h.capture.clone()).await;
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("workflow.yaml"),
        r#"apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: recovery-audit, version: v1}
input: {type: object}
connections: {}
functionsFile: functions.rhai
deadlineSeconds: 3600
start: wait
steps:
  wait:
    type: wait-until
    waitUntil: {function: timer, arguments: [{type: input}]}
    next: done
  done: {type: finish, outcome: done}
outcomes: {done: {type: 'null'}}
"#,
    )
    .unwrap();
    std::fs::write(
        project.path().join("functions.rhai"),
        "fn timer(input) { input.at }",
    )
    .unwrap();
    let definition = Definition::load(project.path()).unwrap();
    h.run = h
        .store
        .admit_owned(
            &definition,
            json!({"at":(Utc::now()+Duration::minutes(10)).to_rfc3339()}),
            &actor("owner", false),
            "original-key",
            "binding-a",
        )
        .await
        .unwrap();
    h.capture.clear();
    h
}
fn assert_pair(entries: &[Value], action: &str, reason_ref: &str, outcome: &str) {
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["schema"], "registry-coordinator/audit/v1");
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    assert_eq!(entries[0]["record"].as_object().unwrap().len(), 4);
    assert_eq!(entries[1]["record"].as_object().unwrap().len(), 2);
    assert_eq!(entries[0]["record"]["action"], action);
    assert_eq!(entries[1]["record"]["action"], action);
    assert_eq!(entries[0]["record"]["reasonRef"], reason_ref);
    assert!(entries[1]["record"].get("reasonRef").is_none());
    assert_eq!(entries[1]["record"]["outcome"], outcome);
}

#[tokio::test]
async fn every_recovery_action_audits_the_keyed_investigation_reference() {
    let h = harness().await;
    let owner = actor("owner", false);
    let operator = actor("operator", true);
    let original_deadline = h.store.status(h.run).await.unwrap().deadline_at;
    assert!(h
        .store
        .retry_same_owned(h.run, "binding-a", &owner, REASON)
        .await
        .is_err());
    assert!(h
        .store
        .reconcile_owned(h.run, "binding-a", &owner, REASON, &NoIo)
        .await
        .is_err());
    h.store.cancel_owned(h.run, &owner, REASON).await.unwrap();
    h.store.set_restore_hold(&operator, REASON).await.unwrap();
    h.store
        .complete_execution_recovery(&operator, REASON, true, true)
        .await
        .unwrap();
    h.store
        .release_restore_hold(&operator, REASON)
        .await
        .unwrap();
    h.store
        .release_admission_hold(&operator, REASON, true, true)
        .await
        .unwrap();
    assert_eq!(
        h.store.status(h.run).await.unwrap().deadline_at,
        original_deadline
    );
    let all_entries = h.capture.entries();
    assert_eq!(
        all_entries.len(),
        16,
        "seven operator pairs and one cancellation transition pair"
    );
    let entries: Vec<_> = all_entries
        .into_iter()
        .filter(|entry| entry["record"].get("stepRef").is_none())
        .collect();
    assert_eq!(entries.len(), 14);
    let reference = profile()
        .key_hasher()
        .audit_reference_hash("reason-v1", &h.namespace, REASON)
        .unwrap();
    for (pair, (action, outcome)) in entries.chunks_exact(2).zip([
        ("retry-same", "unknown"),
        ("reconcile", "unknown"),
        ("cancel", "accepted"),
        ("restore-hold", "accepted"),
        ("complete-execution-recovery", "accepted"),
        ("release-restore-hold", "accepted"),
        ("release-admission-hold", "accepted"),
    ]) {
        assert_pair(pair, action, &reference, outcome);
    }
    h.capture.clear();
    h.store
        .set_restore_hold(&operator, "another-investigation")
        .await
        .unwrap();
    assert_ne!(h.capture.entries()[0]["record"]["reasonRef"], reference);
    assert_ne!(
        profile()
            .key_hasher()
            .audit_reference_hash("reason-v1", "another-deployment", REASON)
            .unwrap(),
        reference
    );
    h.capture.clear();
    h.store.status_owned(h.run, &owner).await.unwrap();
    assert!(h.capture.entries()[0]["record"].get("reasonRef").is_none());
}

#[tokio::test]
async fn invalid_references_and_foreign_owners_cannot_authorize_recovery() {
    let h = harness().await;
    let owner = actor("owner", false);
    for invalid in ["", "control\ncanary", &"x".repeat(257)] {
        assert_eq!(
            h.store
                .cancel_owned(h.run, &owner, invalid)
                .await
                .unwrap_err()
                .code,
            "reason-invalid"
        );
    }
    assert!(h.capture.entries().is_empty());
    assert_eq!(
        h.store
            .set_restore_hold(&owner, REASON)
            .await
            .unwrap_err()
            .code,
        "access.denied"
    );
    assert!(h.capture.entries().is_empty());
    let foreign = actor("foreign", false);
    assert_eq!(
        h.store
            .cancel_owned(h.run, &foreign, REASON)
            .await
            .unwrap_err()
            .code,
        "run-absent"
    );
    let reference = profile()
        .key_hasher()
        .audit_reference_hash("reason-v1", &h.namespace, REASON)
        .unwrap();
    assert_pair(&h.capture.entries(), "cancel", &reference, "unknown");
    assert_eq!(h.store.status(h.run).await.unwrap().state, "running");
    assert!(!h.store.doctor().await.unwrap().restore_hold);
}

#[tokio::test]
async fn recovery_audit_failure_preserves_request_and_response_release_gates() {
    let h = harness().await;
    let owner = actor("owner", false);
    let operator = actor("operator", true);
    let failing = h
        .open(LimitedSink {
            capture: h.capture.clone(),
            remaining: 0,
        })
        .await;
    assert_eq!(
        failing
            .cancel_owned(h.run, &owner, REASON)
            .await
            .unwrap_err()
            .code,
        "audit-unavailable"
    );
    assert_eq!(
        failing
            .set_restore_hold(&operator, REASON)
            .await
            .unwrap_err()
            .code,
        "audit-unavailable"
    );
    assert!(h.capture.entries().is_empty());
    assert_eq!(h.store.status(h.run).await.unwrap().state, "running");
    assert!(!h.store.doctor().await.unwrap().restore_hold);
    let terminal_failing = h
        .open(LimitedSink {
            capture: h.capture.clone(),
            remaining: 3,
        })
        .await;
    assert_eq!(
        terminal_failing
            .cancel_owned(h.run, &owner, REASON)
            .await
            .unwrap_err()
            .code,
        "audit-response-unavailable"
    );
    let entries = h.capture.entries();
    assert_eq!(entries.len(), 3, "operator intent and completed cancellation transition remain, but operator terminal release fails");
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "request");
    assert_eq!(entries[2]["phase"], "response");
    assert!(entries[1]["record"].get("stepRef").is_some());
    assert_eq!(entries[1]["correlation"], entries[2]["correlation"]);
    assert_eq!(
        entries[0]["record"]["reasonRef"],
        profile()
            .key_hasher()
            .audit_reference_hash("reason-v1", &h.namespace, REASON)
            .unwrap()
    );
    assert_eq!(h.store.status(h.run).await.unwrap().state, "cancelled");
}
