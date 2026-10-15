// SPDX-License-Identifier: Apache-2.0
//! Disposable PostgreSQL proof of one Run, exact replay, immutable Review
//! results, current producer ownership, cancellation and payload expiry.
#![cfg(feature = "postgres-test")]
use async_trait::async_trait;
use registry_coordinator::{
    definition::Definition,
    protocol::{AdapterSet, CallOutcome, CallRequest},
    review_provider::{policy_binding, ReviewProducer},
    runtime::RuntimeConfig,
    store::{Actor, ReviewLookup, Store},
    worker::Worker,
};
use registry_review_protocol::{
    ContentDigest, ReviewCancelRequest, ReviewCancelResponse, ReviewContext, ReviewCreateRequest,
    ReviewRequestLifecycle, ReviewResult, ReviewResultStatus, SubjectBinding,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Default)]
struct AuditCapture(
    Arc<std::sync::Mutex<Vec<u8>>>,
    Arc<std::sync::Mutex<Option<usize>>>,
);
impl std::io::Write for AuditCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(remaining) = self.1.lock().unwrap().as_mut() {
            if *remaining == 0 {
                return Err(std::io::Error::other("synthetic audit outage"));
            }
            *remaining -= 1;
        }
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl AuditCapture {
    fn take(&self) -> Vec<serde_json::Value> {
        let bytes = std::mem::take(&mut *self.0.lock().unwrap());
        std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

struct Pure(String);
#[async_trait]
impl AdapterSet for Pure {
    fn binding_digest(&self) -> &str {
        &self.0
    }
    async fn call(&self, _: &CallRequest) -> CallOutcome {
        panic!("pure Review policy dispatches no product effect")
    }
}

struct Assessment(String, serde_json::Value);
#[async_trait]
impl AdapterSet for Assessment {
    fn binding_digest(&self) -> &str {
        &self.0
    }
    async fn call(&self, _: &CallRequest) -> CallOutcome {
        CallOutcome::Success(self.1.clone())
    }
}

struct Harness {
    store: Arc<Store>,
    definition: Definition,
    runtime: RuntimeConfig,
    actor: Actor,
    producer: ReviewProducer,
    binding: String,
    url: String,
    namespace: String,
}
impl Harness {
    async fn new(retention: u32) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("workflow.yaml"),
            serde_json::to_string(&review_project(retention)).unwrap(),
        )
        .unwrap();
        let definition = Definition::load(root.path()).unwrap();
        let runtime_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/coordinator/examples/delayed-follow-up/runtime.yaml");
        let runtime = RuntimeConfig::load(&runtime_path.canonicalize().unwrap()).unwrap();
        let binding = runtime.binding_digest_for(&definition.workflow).unwrap();
        let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").expect(
            "COORDINATOR_TEST_DATABASE_URL must name an owned disposable PostgreSQL database",
        );
        let namespace = format!("coordinator_review_{}", Uuid::new_v4().simple());
        let store = Arc::new(Store::connect(&url, &namespace).await.unwrap());
        store.migrate().await.unwrap();
        Self {
            store,
            definition,
            runtime,
            actor: Actor {
                issuer: "https://issuer.example".into(),
                subject: "breg-client".into(),
                client_id: "breg-client".into(),
                operator: false,
            },
            producer: ReviewProducer {
                id: "breg-producer".into(),
                source_namespace: "registry-id".into(),
                profile: "registry-review".into(),
                sources: vec!["registry-proposals".into()],
            },
            binding,
            url,
            namespace,
        }
    }
    fn request(&self) -> ReviewCreateRequest {
        ReviewCreateRequest {
            policy: policy_binding(&self.definition.workflow, &self.definition.digest)
                .unwrap()
                .unwrap()
                .into(),
            subject: SubjectBinding {
                source: "registry-proposals".into(),
                subject_type: "proposal".into(),
                id: Uuid::new_v4().to_string(),
                version: "3".into(),
                digest: ContentDigest::for_bytes(b"exact frozen Proposal effects"),
            },
            requester_reference: "synthetic-request".into(),
            initiator: None,
            context: ReviewContext::Submitted {
                snapshot: json!({"requestedChange":"bounded synthetic context"}),
            },
            result_constraints: None,
        }
    }
    async fn admit(
        &self,
        request: ReviewCreateRequest,
        key: &str,
    ) -> registry_review_protocol::ReviewRequestAccepted {
        self.store
            .admit_review_owned(
                &self.definition,
                request,
                &self.actor,
                &self.producer,
                key,
                &self.binding,
                &self.runtime,
            )
            .await
            .unwrap()
    }
    fn workflows(&self) -> Vec<String> {
        vec![self.definition.workflow.id.clone()]
    }
    fn worker(&self) -> Worker {
        Worker::new(self.store.clone(), Arc::new(Pure(self.binding.clone())))
    }
    async fn result(&self, id: Uuid) -> ReviewResult {
        match self
            .store
            .review_result_owned(id, &self.actor, &self.producer, &self.workflows())
            .await
            .unwrap()
        {
            ReviewLookup::Available(result) => *result,
            _ => panic!("expected available immutable Review result"),
        }
    }
    async fn sql(&self, sql: &str) {
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let task = tokio::spawn(async move { connection.await.unwrap() });
        client
            .batch_execute(&sql.replace("{schema}", &self.namespace))
            .await
            .unwrap();
        drop(client);
        task.await.unwrap();
    }
    async fn database_now(&self) -> chrono::DateTime<chrono::Utc> {
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let task = tokio::spawn(async move { connection.await.unwrap() });
        let now = client
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .unwrap()
            .get(0);
        drop(client);
        task.await.unwrap();
        now
    }
    async fn cleanup(&self) {
        self.sql("DROP SCHEMA {schema} CASCADE").await;
    }

    async fn capture_audit(&mut self) -> AuditCapture {
        use registry_coordinator::{protected_state::StateKeys, store::StoreSecurity};
        use registry_platform_audit::{AuditProfile, AuditWriter};
        let capture = AuditCapture::default();
        self.store = Arc::new(
            Store::open(
                &self.url,
                &self.namespace,
                StoreSecurity {
                    database_id: self.namespace.clone(),
                    keys: StateKeys::new(
                        1,
                        std::collections::BTreeMap::from([(1, [0x11; 32])]),
                        [0x22; 32],
                    )
                    .unwrap(),
                    audit: AuditWriter::from_line_sink(Box::new(capture.clone())),
                    audit_profile: AuditProfile::production_from_secret_bytes(
                        zeroize::Zeroizing::new(vec![0x33; 32]),
                    )
                    .unwrap(),
                },
                None,
            )
            .await
            .unwrap(),
        );
        capture
    }

    async fn cancel_expired_after_restart(
        &self,
        accepted: &registry_review_protocol::ReviewRequestAccepted,
    ) {
        let restarted = Store::connect(&self.url, &self.namespace).await.unwrap();
        let cancellation = ReviewCancelRequest {
            subject: accepted.subject.clone(),
            reason: "expired-custody-must-not-renew".into(),
        };
        let error = restarted
            .cancel_review_owned(
                accepted.request_id,
                &self.actor,
                &self.producer,
                &self.workflows(),
                "late-cancel",
                &cancellation,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "review-result-expired");
        assert!(matches!(
            restarted
                .review_result_owned(
                    accepted.request_id,
                    &self.actor,
                    &self.producer,
                    &self.workflows()
                )
                .await
                .unwrap(),
            ReviewLookup::Expired
        ));
    }
}

fn review_project(retention: u32) -> serde_json::Value {
    json!({"apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1","kind":"CoordinatorProject","project":{"id":"proposal-assessment","version":"1"},"workflow":{"input":{"type":"object"},"deadlineSeconds":600,"review":{"resultRetentionSeconds":retention,"outcomes":{"accepted":{"status":"approved","outcome":"accepted"}}},"start":"done","steps":{"done":{"type":"finish","outcome":"accepted"}},"outcomes":{"accepted":{"type":"null"}}}})
}

#[tokio::test]
async fn exact_admission_result_restart_feed_and_current_ownership_share_one_run() {
    let h = Harness::new(86400).await;
    let request = h.request();
    let accepted = h.admit(request.clone(), "review-key").await;
    assert_eq!(
        accepted.submission_digest,
        registry_review_protocol::submission_digest(
            &h.producer.id,
            &h.producer.source_namespace,
            &request
        )
        .unwrap()
    );
    assert_eq!(h.admit(request.clone(), "review-key").await, accepted);
    assert!(matches!(
        h.store
            .review_result_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
            .await
            .unwrap(),
        ReviewLookup::Pending
    ));
    let mut conflicting = request.clone();
    conflicting.subject.version = "4".into();
    assert_eq!(
        h.store
            .admit_review_owned(
                &h.definition,
                conflicting,
                &h.actor,
                &h.producer,
                "review-key",
                &h.binding,
                &h.runtime
            )
            .await
            .unwrap_err()
            .code,
        "start-conflict"
    );
    h.worker().tick().await.unwrap();
    let result = h.result(accepted.request_id).await;
    assert_eq!(result.status, ReviewResultStatus::Approved);
    assert_eq!(result.subject, accepted.subject);
    assert_eq!(result.policy, accepted.policy);
    assert_eq!(result.submission_digest, accepted.submission_digest);
    assert_eq!(result.outcome.as_deref(), Some("accepted"));
    assert!(result.result.is_none());
    let restarted = Store::connect(&h.url, &h.namespace).await.unwrap();
    let reread = restarted
        .review_result_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
        .await
        .unwrap();
    assert!(matches!(reread,ReviewLookup::Available(ref retained) if retained.as_ref()==&result));
    let page = restarted
        .review_results_owned(&h.actor, &h.producer, &h.workflows(), None, 20)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].result_id, result.result_id);
    assert_eq!(page.items[0].event_id, accepted.request_id);
    assert_eq!(result.result_id, accepted.request_id);
    let mut stranger = h.actor.clone();
    stranger.client_id = "other-client".into();
    let mut other_subject = h.actor.clone();
    other_subject.subject = "other-subject".into();
    for (actor, workflows, producer) in [
        (&stranger, h.workflows(), h.producer.clone()),
        (&other_subject, h.workflows(), h.producer.clone()),
        (
            &h.actor,
            vec!["another-workflow".into()],
            h.producer.clone(),
        ),
        (
            &h.actor,
            h.workflows(),
            ReviewProducer {
                sources: vec!["other-source".into()],
                ..h.producer.clone()
            },
        ),
    ] {
        assert_eq!(
            restarted
                .review_result_owned(accepted.request_id, actor, &producer, &workflows)
                .await
                .err()
                .unwrap()
                .code,
            "run-absent"
        );
        assert_eq!(
            restarted
                .review_request_owned(accepted.request_id, actor, &producer, &workflows)
                .await
                .unwrap_err()
                .code,
            "run-absent"
        );
        assert!(restarted
            .review_results_owned(actor, &producer, &workflows, None, 20)
            .await
            .unwrap()
            .items
            .is_empty());
        assert_eq!(
            restarted
                .cancel_review_owned(
                    accepted.request_id,
                    actor,
                    &producer,
                    &workflows,
                    "foreign-cancel",
                    &ReviewCancelRequest {
                        subject: accepted.subject.clone(),
                        reason: "foreign-subject-cannot-cancel".into(),
                    },
                )
                .await
                .unwrap_err()
                .code,
            "run-absent"
        );
    }
    h.cleanup().await;
}

#[tokio::test]
async fn malformed_cancellation_is_refused_without_spending_the_key_or_changing_the_result() {
    let h = Harness::new(86400).await;
    let accepted = h.admit(h.request(), "cancel-validation").await;
    for reason in ["".into(), " ".into(), "bad\nreason".into(), "x".repeat(257)] {
        let error = h
            .store
            .cancel_review_owned(
                accepted.request_id,
                &h.actor,
                &h.producer,
                &h.workflows(),
                "cancel-key",
                &ReviewCancelRequest {
                    subject: accepted.subject.clone(),
                    reason,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "request.invalid");
    }
    let cancellation = ReviewCancelRequest {
        subject: accepted.subject.clone(),
        reason: "cancellation-private-canary@example.invalid".into(),
    };
    for key in [String::new(), "x".repeat(257)] {
        assert_eq!(
            h.store
                .cancel_review_owned(
                    accepted.request_id,
                    &h.actor,
                    &h.producer,
                    &h.workflows(),
                    &key,
                    &cancellation,
                )
                .await
                .unwrap_err()
                .code,
            "start-key-invalid"
        );
    }
    assert!(matches!(
        h.store
            .review_result_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
            .await
            .unwrap(),
        ReviewLookup::Pending
    ));
    assert!(matches!(
        h.store
            .cancel_review_owned(
                accepted.request_id,
                &h.actor,
                &h.producer,
                &h.workflows(),
                "cancel-key",
                &cancellation,
            )
            .await
            .unwrap(),
        ReviewCancelResponse::Cancelled { result } if result.status == ReviewResultStatus::Cancelled
    ));
    assert_eq!(
        h.result(accepted.request_id).await.status,
        ReviewResultStatus::Cancelled
    );
    h.cleanup().await;
}

#[tokio::test]
async fn cancellation_and_finish_have_one_immutable_winner() {
    let h = Harness::new(86400).await;
    for index in 0..8 {
        let accepted = h.admit(h.request(), &format!("race-{index}")).await;
        let cancellation = ReviewCancelRequest {
            subject: accepted.subject.clone(),
            reason: "synthetic-withdrawal".into(),
        };
        let worker = h.worker();
        let workflows = h.workflows();
        let (cancelled, tick) = tokio::join!(
            h.store.cancel_review_owned(
                accepted.request_id,
                &h.actor,
                &h.producer,
                &workflows,
                "withdrawal-key",
                &cancellation
            ),
            worker.tick()
        );
        tick.unwrap();
        let expected = match cancelled.unwrap() {
            ReviewCancelResponse::Cancelled { result }
            | ReviewCancelResponse::AlreadyTerminal { result } => result,
        };
        assert_eq!(h.result(accepted.request_id).await, expected);
        assert!(matches!(
            expected.status,
            ReviewResultStatus::Approved | ReviewResultStatus::Cancelled
        ));
        assert!(
            matches!(h.store.cancel_review_owned(accepted.request_id,&h.actor,&h.producer,&workflows,"withdrawal-key",&cancellation).await.unwrap(),ReviewCancelResponse::AlreadyTerminal{result} if result==expected)
        );
    }
    h.cleanup().await;
}

#[tokio::test]
async fn result_expiry_erases_payload_but_preserves_spent_admission_identity() {
    let h = Harness::new(1).await;
    let request = h.request();
    let accepted = h.admit(request.clone(), "expiring").await;
    h.worker().tick().await.unwrap();
    let result = h.result(accepted.request_id).await;
    let operator = Actor {
        operator: true,
        ..h.actor.clone()
    };
    assert_eq!(
        h.store
            .retain_terminal(h.database_now().await, 100, &operator)
            .await
            .unwrap(),
        0
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    h.cancel_expired_after_restart(&accepted).await;
    assert!(matches!(
        h.store
            .review_result_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
            .await
            .unwrap(),
        ReviewLookup::Expired
    ));
    assert_eq!(
        h.store
            .retain_terminal(h.database_now().await, 100, &operator)
            .await
            .unwrap(),
        1
    );
    // Erasure keeps the spent key, not enough content to reconstruct an
    // acceptance from today's active policy. The old key cannot create work.
    let erased = h
        .store
        .admit_review_owned(
            &h.definition,
            request,
            &h.actor,
            &h.producer,
            "expiring",
            &h.binding,
            &h.runtime,
        )
        .await
        .unwrap_err();
    assert_eq!(erased.code, "payload-erased");
    h.sql("DO $$ BEGIN IF (SELECT count(*) FROM {schema}.runs) <> 1 THEN RAISE EXCEPTION 'erased admission was recreated'; END IF; END $$").await;
    h.cancel_expired_after_restart(&accepted).await;
    assert!(matches!(
        h.store
            .review_result_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
            .await
            .unwrap(),
        ReviewLookup::Expired
    ));
    assert!(result.available_until > result.completed_at);
    h.cleanup().await;
}

#[tokio::test]
async fn late_cancel_cannot_create_a_result_for_an_expired_unsettled_request() {
    let h = Harness::new(86400).await;
    let accepted = h.admit(h.request(), "unsettled-expiry").await;
    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    h.cancel_expired_after_restart(&accepted).await;
    h.worker().tick().await.unwrap();
    h.cancel_expired_after_restart(&accepted).await;
    h.cleanup().await;
}

#[tokio::test]
async fn restore_fences_cancellation_and_release_of_sealed_and_unsealed_results() {
    let h = Harness::new(86400).await;
    for sealed in [false, true] {
        let accepted = h
            .admit(
                h.request(),
                if sealed {
                    "sealed-restore"
                } else {
                    "unsealed-restore"
                },
            )
            .await;
        h.worker().tick().await.unwrap();
        if sealed {
            assert_eq!(
                h.result(accepted.request_id).await.status,
                ReviewResultStatus::Approved
            );
        }
        for global in [true, false] {
            h.sql(if global {
                "UPDATE {schema}.control SET restore_hold=true"
            } else {
                "UPDATE {schema}.runs SET restore_review_required=true"
            })
            .await;
            let restarted = Store::connect(&h.url, &h.namespace).await.unwrap();
            let status = restarted
                .review_request_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
                .await
                .unwrap();
            assert_eq!(status.lifecycle, ReviewRequestLifecycle::Reviewing);
            assert_eq!(status.updated_at, status.created_at);
            if !sealed {
                h.sql(&format!("DO $$ BEGIN IF EXISTS(SELECT 1 FROM {{schema}}.runs WHERE run_id='{id}'::uuid AND review_completed_at IS NOT NULL) THEN RAISE EXCEPTION 'held status materialized a result'; END IF; END $$", id=accepted.request_id)).await;
            }
            let cancellation = ReviewCancelRequest {
                subject: accepted.subject.clone(),
                reason: "restore-must-preserve-approved-outcome".into(),
            };
            assert_eq!(
                restarted
                    .cancel_review_owned(
                        accepted.request_id,
                        &h.actor,
                        &h.producer,
                        &h.workflows(),
                        "restore-cancel",
                        &cancellation
                    )
                    .await
                    .unwrap_err()
                    .code,
                "restore-hold"
            );
            assert!(matches!(
                restarted
                    .review_result_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
                    .await
                    .unwrap(),
                ReviewLookup::Pending
            ));
            assert!(restarted
                .review_results_owned(&h.actor, &h.producer, &h.workflows(), None, 20)
                .await
                .unwrap()
                .items
                .is_empty());
            h.sql("UPDATE {schema}.control SET restore_hold=false; UPDATE {schema}.runs SET restore_review_required=false").await;
        }
        assert_eq!(
            h.store
                .review_request_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
                .await
                .unwrap()
                .lifecycle,
            ReviewRequestLifecycle::Approved
        );
        assert_eq!(
            h.result(accepted.request_id).await.status,
            ReviewResultStatus::Approved
        );
    }
    h.cleanup().await;
}

#[tokio::test]
async fn revoked_sources_do_not_disclose_or_starve_the_authorized_result_feed() {
    let mut h = Harness::new(86400).await;
    h.producer.sources.push("other-proposals".into());
    let mut results = Vec::new();
    for (index, source) in ["registry-proposals", "other-proposals", "other-proposals"]
        .into_iter()
        .enumerate()
    {
        let mut request = h.request();
        request.subject.source = source.into();
        let accepted = h.admit(request, &format!("feed-source-{index}")).await;
        h.worker().tick().await.unwrap();
        results.push(h.result(accepted.request_id).await);
    }
    let page = h
        .store
        .review_results_owned(&h.actor, &h.producer, &h.workflows(), None, 1)
        .await
        .unwrap();
    assert_eq!(page.items[0].result_id, results[0].result_id);
    let removed_source_cursor = page.next_cursor.unwrap();
    let continued = h
        .store
        .review_results_owned(
            &h.actor,
            &h.producer,
            &h.workflows(),
            Some(removed_source_cursor),
            20,
        )
        .await
        .unwrap();
    assert_eq!(continued.items.len(), 2);

    let narrowed = ReviewProducer {
        sources: vec!["other-proposals".into()],
        ..h.producer.clone()
    };
    for cursor in [removed_source_cursor, Uuid::new_v4()] {
        assert_eq!(
            h.store
                .review_results_owned(&h.actor, &narrowed, &h.workflows(), Some(cursor), 20)
                .await
                .unwrap_err()
                .code,
            "request.invalid"
        );
    }
    assert_eq!(
        h.store
            .review_request_owned(results[0].request_id, &h.actor, &narrowed, &h.workflows())
            .await
            .unwrap_err()
            .code,
        "run-absent"
    );
    assert_eq!(
        h.store
            .review_result_owned(results[0].request_id, &h.actor, &narrowed, &h.workflows())
            .await
            .err()
            .unwrap()
            .code,
        "run-absent"
    );
    let page = h
        .store
        .review_results_owned(&h.actor, &narrowed, &h.workflows(), None, 1)
        .await
        .unwrap();
    assert_eq!(page.items[0].result_id, results[1].result_id);
    let continued = h
        .store
        .review_results_owned(&h.actor, &narrowed, &h.workflows(), page.next_cursor, 20)
        .await
        .unwrap();
    assert_eq!(continued.items.len(), 1);
    assert_eq!(continued.items[0].result_id, results[2].result_id);
    assert!(continued.next_cursor.is_none());
    h.cleanup().await;
}

#[tokio::test]
async fn unexpired_review_custody_does_not_starve_later_eligible_retention() {
    let h = Harness::new(86400).await;
    let accepted = h.admit(h.request(), "retained-review").await;
    h.worker().tick().await.unwrap();
    h.result(accepted.request_id).await;
    let ordinary = h
        .store
        .admit_owned(
            &h.definition,
            json!({}),
            &h.actor,
            "ordinary-retention",
            &h.binding,
        )
        .await
        .unwrap();
    h.worker().tick().await.unwrap();
    let operator = Actor {
        operator: true,
        ..h.actor.clone()
    };
    // Doctor reports erasable payloads, excluding the still available Review.
    assert_eq!(h.store.doctor().await.unwrap().terminal_payloads, 1);
    assert_eq!(
        h.store
            .retain_terminal(h.database_now().await, 1, &operator)
            .await
            .unwrap(),
        1
    );
    h.sql(&format!("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM {{schema}}.runs WHERE run_id='{ordinary}'::uuid AND payload_erased_at IS NOT NULL) THEN RAISE EXCEPTION 'eligible ordinary payload was starved'; END IF; END $$")).await;
    assert_eq!(h.store.doctor().await.unwrap().terminal_payloads, 0);
    assert_eq!(
        h.result(accepted.request_id).await.status,
        ReviewResultStatus::Approved
    );
    h.cleanup().await;
}

#[tokio::test]
async fn expired_unsealed_results_do_not_hide_a_later_available_feed_entry() {
    let h = Harness::new(1).await;
    for key in ["unsealed-old-one", "unsealed-old-two"] {
        h.admit(h.request(), key).await;
        h.worker().tick().await.unwrap();
    }
    // No result read has replaced either conservative admission-time bound.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let fresh = h.admit(h.request(), "fresh-third").await;
    h.worker().tick().await.unwrap();
    let page = h
        .store
        .review_results_owned(&h.actor, &h.producer, &h.workflows(), None, 1)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].request_id, fresh.request_id);
    assert!(page.next_cursor.is_none());
    h.cleanup().await;
}

#[tokio::test]
async fn ordinary_run_cancellation_is_discoverable_without_a_prior_review_read() {
    let h = Harness::new(86400).await;
    let accepted = h.admit(h.request(), "operator-cancel-feed").await;
    let operator = Actor {
        operator: true,
        ..h.actor.clone()
    };
    h.store
        .cancel_owned(
            accepted.request_id,
            &operator,
            "synthetic-operator-cancellation",
        )
        .await
        .unwrap();
    h.worker().tick().await.unwrap();
    let page = h
        .store
        .review_results_owned(&h.actor, &h.producer, &h.workflows(), None, 1)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].request_id, accepted.request_id);
    assert_eq!(
        h.result(accepted.request_id).await.status,
        ReviewResultStatus::Cancelled
    );
    h.cleanup().await;
}

#[tokio::test]
async fn ordinary_late_run_cancellation_cannot_renew_expired_review_custody() {
    let h = Harness::new(86400).await;
    let accepted = h.admit(h.request(), "late-operator-cancel").await;
    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    let operator = Actor {
        operator: true,
        ..h.actor.clone()
    };
    h.store
        .cancel_owned(accepted.request_id, &operator, "late-operator-cancellation")
        .await
        .unwrap();
    h.worker().tick().await.unwrap();
    assert!(h
        .store
        .review_results_owned(&h.actor, &h.producer, &h.workflows(), None, 1)
        .await
        .unwrap()
        .items
        .is_empty());
    h.cancel_expired_after_restart(&accepted).await;
    h.cleanup().await;
}

#[tokio::test]
async fn status_outcome_provider_refuses_structured_constraints_without_spending_the_key() {
    let h = Harness::new(86400).await;
    for (index, constraints) in [json!({}), json!({"answer":{"enum":["constraint-canary"]}})]
        .into_iter()
        .enumerate()
    {
        let request = h.request();
        let key = format!("unsupported-constraints-{index}");
        let mut constrained = request.clone();
        constrained.result_constraints = Some(constraints);
        let error = h
            .store
            .admit_review_owned(
                &h.definition,
                constrained,
                &h.actor,
                &h.producer,
                &key,
                &h.binding,
                &h.runtime,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "request.invalid");
        assert_eq!(error.field.as_deref(), Some("$.resultConstraints"));
        assert!(!error.to_string().contains("constraint-canary"));
        let accepted = h.admit(request.clone(), &key).await;
        assert_eq!(h.admit(request, &key).await, accepted);
    }
    h.cleanup().await;
}

#[tokio::test]
async fn result_expiry_uses_the_clock_after_its_row_lock_wait() {
    lock_wait_expiry(false).await;
}

#[tokio::test]
async fn cancellation_expiry_uses_the_clock_after_its_row_lock_wait() {
    lock_wait_expiry(true).await;
}

async fn lock_wait_expiry(cancellation: bool) {
    let h = Harness::new(1).await;
    let accepted = h.admit(h.request(), "lock-wait-expiry").await;
    h.worker().tick().await.unwrap();
    let result = h.result(accepted.request_id).await;
    let (mut blocker, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(async move { connection.await.unwrap() });
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(&format!("SELECT r.run_id FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id AND r.step=j.step WHERE r.run_id=$1 FOR UPDATE OF j,r",h.namespace), &[&accepted.request_id]).await.unwrap();
    let store = h.store.clone();
    let actor = h.actor.clone();
    let producer = h.producer.clone();
    let workflows = h.workflows();
    let lookup = tokio::spawn(async move {
        if cancellation {
            store
                .cancel_review_owned(
                    accepted.request_id,
                    &actor,
                    &producer,
                    &workflows,
                    "blocked-cancel",
                    &ReviewCancelRequest {
                        subject: accepted.subject,
                        reason: "Cancellation cannot renew expired custody after waiting".into(),
                    },
                )
                .await
                .err()
                .is_some_and(|error| error.code == "review-result-expired")
        } else {
            matches!(
                store
                    .review_result_owned(accepted.request_id, &actor, &producer, &workflows)
                    .await
                    .unwrap(),
                ReviewLookup::Expired
            )
        }
    });
    let (probe, probe_connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let probe_connection = tokio::spawn(async move { probe_connection.await.unwrap() });
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let waiting: bool = probe.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)", &[&format!("%{}.jobs j%",h.namespace)]).await.unwrap().get(0);
        if waiting {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "Review lookup did not reach the held row"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let blocked_at: chrono::DateTime<chrono::Utc> = probe
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        blocked_at < result.available_until,
        "the fixture must begin waiting before the fixed expiry"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    tx.commit().await.unwrap();
    let expired = lookup.await.unwrap();
    drop(probe);
    probe_connection.await.unwrap();
    drop(blocker);
    connection.await.unwrap();
    h.cleanup().await;
    assert!(
        expired,
        "waiting beyond the fixed availability must not release or renew the result"
    );
}

#[tokio::test]
async fn lookup_during_a_real_call_transition_keeps_the_authorized_review_visible() {
    let mut h = Harness::new(86400).await;
    let subject = serde_json::to_value(h.request().subject).unwrap();
    let contract = json!({"id":"urn:registry:breg:review-context:source:correct-name:assessment","revision":format!("sha256:{}","a".repeat(64)),"schemaDigest":format!("sha256:{}","b".repeat(64))});
    let project = json!({"apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1","kind":"CoordinatorProject","project":{"id":"proposal-assessment","version":"1"},"operations":{"assessment":{"uses":"breg.read-review-context/v1","connection":"applications"}},"workflow":{"input":{"type":"object"},"deadlineSeconds":600,"review":{"outcomes":{"accepted":{"status":"approved","outcome":"accepted"}}},"start":"assess","steps":{"assess":{"type":"call","operation":"assessment","input":{"type":"literal","value":{"actionId":"correct-name","subject":subject,"contract":contract}},"next":"route"},"route":{"type":"choose","choose":{"type":"literal","value":"automatic"},"cases":{"automatic":"done"}},"done":{"type":"finish","outcome":"accepted"}},"outcomes":{"accepted":{"type":"null"}}}});
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_vec(&project).unwrap(),
    )
    .unwrap();
    h.definition = Definition::load(root.path()).unwrap();
    h.binding = h
        .runtime
        .binding_digest_for(&h.definition.workflow)
        .unwrap();
    let accepted = h.admit(h.request(), "transition-lookup").await;
    let advisory = Uuid::new_v4().as_u128() as i64;
    h.sql(&format!("CREATE FUNCTION {{schema}}.pause_review_advance() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.step='assess' AND NEW.step='route' THEN PERFORM pg_advisory_xact_lock({advisory}); END IF; RETURN NEW; END $$; CREATE TRIGGER pause_review_advance BEFORE UPDATE OF step ON {{schema}}.runs FOR EACH ROW EXECUTE FUNCTION {{schema}}.pause_review_advance();")).await;
    let (blocker, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(async move { connection.await.unwrap() });
    blocker
        .query_one("SELECT pg_advisory_lock($1)", &[&advisory])
        .await
        .unwrap();
    let worker = Worker::new(
        h.store.clone(),
        Arc::new(Assessment(
            h.binding.clone(),
            json!({"subject":subject,"contract":contract,"reference":"assessment-reference","fields":{"active":true}}),
        )),
    );
    let advancing = tokio::spawn(async move { worker.tick().await });
    let (probe, probe_connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let probe_connection = tokio::spawn(async move { probe_connection.await.unwrap() });
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let waiting: bool = probe.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE $1)", &[&format!("%UPDATE {}.runs SET outputs=%",h.namespace)]).await.unwrap().get(0);
        if waiting {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "worker did not reach its genuine assessment transition"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let store = h.store.clone();
    let actor = h.actor.clone();
    let producer = h.producer.clone();
    let workflows = h.workflows();
    let lookup = tokio::spawn(async move {
        store
            .review_request_owned(accepted.request_id, &actor, &producer, &workflows)
            .await
    });
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let waiting: bool = probe.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)", &[&format!("%{}.jobs j%",h.namespace)]).await.unwrap().get(0);
        if waiting {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "lookup did not wait on the transitioning current job"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    blocker
        .query_one("SELECT pg_advisory_unlock($1)", &[&advisory])
        .await
        .unwrap();
    advancing.await.unwrap().unwrap();
    let observed = lookup.await.unwrap();
    drop(probe);
    probe_connection.await.unwrap();
    drop(blocker);
    connection.await.unwrap();
    let observed =
        observed.expect("an authorized Review cannot disappear while its current job advances");
    assert_eq!(observed.request_id, accepted.request_id);
    h.worker().tick().await.unwrap();
    h.worker().tick().await.unwrap();
    let result = h.result(accepted.request_id).await;
    assert_eq!(result.status, ReviewResultStatus::Approved);
    assert_eq!(result.subject, accepted.subject);
    let feed = h
        .store
        .review_results_owned(&h.actor, &h.producer, &h.workflows(), None, 1)
        .await
        .unwrap();
    assert_eq!(feed.items.len(), 1);
    assert_eq!(feed.items[0].result_id, result.result_id);
    h.cleanup().await;
}

#[tokio::test]
async fn feed_rechecks_a_restore_flag_changed_while_its_candidate_row_is_locked() {
    let h = Harness::new(86400).await;
    let accepted = h.admit(h.request(), "feed-restore-race").await;
    h.worker().tick().await.unwrap();
    h.result(accepted.request_id).await;
    let second = h.admit(h.request(), "feed-after-held-row").await;
    h.worker().tick().await.unwrap();
    h.result(second.request_id).await;
    let third = h.admit(h.request(), "feed-after-first-window").await;
    h.worker().tick().await.unwrap();
    h.result(third.request_id).await;
    let (mut blocker, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(async move { connection.await.unwrap() });
    let tx = blocker.transaction().await.unwrap();
    tx.query_one(&format!("SELECT r.run_id FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id AND r.step=j.step WHERE r.run_id=$1 FOR UPDATE OF j,r",h.namespace),&[&accepted.request_id]).await.unwrap();
    let store = h.store.clone();
    let actor = h.actor.clone();
    let producer = h.producer.clone();
    let workflows = h.workflows();
    let feed = tokio::spawn(async move {
        store
            .review_results_owned(&actor, &producer, &workflows, None, 1)
            .await
    });
    let (probe, probe_connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let probe_connection = tokio::spawn(async move { probe_connection.await.unwrap() });
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let waiting:bool=probe.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)",&[&format!("%{}.jobs j%",h.namespace)]).await.unwrap().get(0);
        if waiting {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "feed did not reach the protected candidate reload"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    tx.execute(
        &format!(
            "UPDATE {}.runs SET restore_review_required=true WHERE run_id=$1",
            h.namespace
        ),
        &[&accepted.request_id],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let page = feed.await.unwrap().unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].request_id, second.request_id);
    assert_eq!(page.next_cursor, Some(second.request_id));
    let continued = h
        .store
        .review_results_owned(&h.actor, &h.producer, &h.workflows(), page.next_cursor, 1)
        .await
        .unwrap();
    assert_eq!(continued.items.len(), 1);
    assert_eq!(continued.items[0].request_id, third.request_id);
    assert!(continued.next_cursor.is_none());
    drop(probe);
    probe_connection.await.unwrap();
    drop(blocker);
    connection.await.unwrap();
    h.cleanup().await;
}

#[tokio::test]
async fn cancellation_refuses_owned_malformed_input_and_conceals_foreign_and_expired_requests() {
    use registry_coordinator::{
        access::{Action, Authenticator, ClientPolicy},
        deployment,
        http::{self, HttpState},
        project,
    };
    use registry_platform_config::PackageConfig;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{
        access_token_typ_set, JwksFetcher, JwksFetcherConfig, TokenVerifierConfig,
    };
    use registry_platform_testing::{TestAuthorizationServerBuilder, TestClient};
    let issuer = TestAuthorizationServerBuilder::default()
        .client(TestClient::new("breg-client"))
        .client(TestClient::new("other-client"))
        .start()
        .await;
    let mut h = Harness::new(1).await;
    h.actor.issuer = issuer.issuer();
    let accepted = h.admit(h.request(), "router-erased").await;
    h.worker().tick().await.unwrap();
    h.result(accepted.request_id).await;
    let active = h.admit(h.request(), "router-active").await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        h.store
            .retain_terminal(
                h.database_now().await,
                100,
                &Actor {
                    operator: true,
                    ..h.actor.clone()
                }
            )
            .await
            .unwrap(),
        1
    );
    let root = tempfile::tempdir().unwrap();
    let authored = root.path().join("workflow");
    project::init(&authored, Some("router-workflow")).unwrap();
    let package = root.path().join("package");
    let digest = deployment::package(&authored, &package).unwrap();
    let template = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/single-flow-runtime.yaml")
        .canonicalize()
        .unwrap();
    let mut runtime = RuntimeConfig::load(&template).unwrap();
    runtime.deployment.as_mut().unwrap().packages = vec![PackageConfig {
        root: package,
        expected_digest: Some(digest),
    }];
    let workflows =
        Arc::new(deployment::load_workflows(runtime.deployment.as_ref().unwrap()).unwrap());
    let policy = ClientPolicy {
        review_producer: Some(h.producer.clone()),
        required_scopes: vec!["review:request".into()],
        workflows: h.workflows(),
        actions: vec![Action::ReviewRead, Action::ReviewCancel],
        operator: false,
    };
    let verifier = TokenVerifierConfig::access_token_profile(
        issuer.issuer(),
        vec!["urn:coordinator:review-test".into()],
        vec![jsonwebtoken::Algorithm::EdDSA],
        access_token_typ_set("at+jwt"),
    )
    .with_scope_claim("scope")
    .with_allowed_clients(vec!["breg-client".into(), "other-client".into()]);
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        issuer.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let authenticator = Arc::new(Authenticator::new(
        verifier,
        keys,
        [
            ("breg-client".into(), policy.clone()),
            ("other-client".into(), policy),
        ]
        .into(),
        false,
    ));
    let state = HttpState {
        store: h.store.clone(),
        runtime: Arc::new(h.runtime.clone()),
        workflows,
        authenticator,
        adapters: Arc::new(Pure(h.binding.clone())),
        recovery_only: false,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server =
        tokio::spawn(async move { axum::serve(listener, http::router(state)).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let empty_reason = serde_json::to_string(&ReviewCancelRequest {
        subject: active.subject.clone(),
        reason: String::new(),
    })
    .unwrap();
    for (caller, id, status, body) in [
        (
            "breg-client",
            accepted.request_id,
            410,
            "{malformed-private-canary",
        ),
        (
            "other-client",
            accepted.request_id,
            404,
            "{malformed-private-canary",
        ),
        (
            "breg-client",
            Uuid::new_v4(),
            404,
            "{malformed-private-canary",
        ),
        ("breg-client", active.request_id, 400, empty_reason.as_str()),
        (
            "other-client",
            active.request_id,
            404,
            empty_reason.as_str(),
        ),
        (
            "other-subject",
            active.request_id,
            404,
            empty_reason.as_str(),
        ),
        ("breg-client", Uuid::new_v4(), 404, empty_reason.as_str()),
    ] {
        let token = issuer.issue_access_token(
            if caller == "other-subject" {
                "breg-client"
            } else {
                caller
            },
            caller,
            "urn:coordinator:review-test",
            "review:request",
            chrono::Utc::now().timestamp() + 300,
        );
        let response = client
            .post(format!("{url}/v1/review-requests/{id}/cancel"))
            .bearer_auth(token)
            .header(
                registry_review_protocol::REVIEW_PROFILE_HEADER,
                &h.producer.profile,
            )
            .header("content-type", "application/json")
            .header("idempotency-key", "expired-router-key")
            .body(body.to_owned())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let problem: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            problem["code"],
            if status == 410 {
                "review.result-expired"
            } else if status == 400 {
                "request.invalid"
            } else {
                "run.not-visible"
            }
        );
        assert!(problem["type"]
            .as_str()
            .unwrap()
            .starts_with(registry_coordinator::problem::PROBLEM_TYPE_BASE));
        assert!(!problem.to_string().contains("malformed-private-canary"));
        assert!(!problem.to_string().contains(&active.subject.id));
    }
    assert!(matches!(
        h.store
            .review_result_owned(active.request_id, &h.actor, &h.producer, &h.workflows())
            .await
            .unwrap(),
        ReviewLookup::Pending
    ));
    let response = client
        .post(format!(
            "{url}/v1/review-requests/{}/cancel",
            active.request_id
        ))
        .bearer_auth(issuer.issue_access_token(
            "breg-client",
            "breg-client",
            "urn:coordinator:review-test",
            "review:request",
            chrono::Utc::now().timestamp() + 300,
        ))
        .header(
            registry_review_protocol::REVIEW_PROFILE_HEADER,
            &h.producer.profile,
        )
        .header("idempotency-key", "expired-router-key")
        .json(&ReviewCancelRequest {
            subject: active.subject.clone(),
            reason: "synthetic-valid-cancellation".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        matches!(response.json::<ReviewCancelResponse>().await.unwrap(), ReviewCancelResponse::Cancelled { result } if result.status == ReviewResultStatus::Cancelled && result.subject == active.subject)
    );
    for subject in ["breg-client", "other-subject"] {
        let token = issuer.issue_access_token(
            "breg-client",
            subject,
            "urn:coordinator:review-test",
            "review:request",
            chrono::Utc::now().timestamp() + 300,
        );
        for suffix in ["", "/result"] {
            let response = client
                .get(format!(
                    "{url}/v1/review-requests/{}{suffix}",
                    active.request_id
                ))
                .bearer_auth(&token)
                .header(
                    registry_review_protocol::REVIEW_PROFILE_HEADER,
                    &h.producer.profile,
                )
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if subject == "breg-client" { 200 } else { 404 }
            );
        }
        let page: registry_review_protocol::ReviewResultFeedPage = client
            .get(format!("{url}/v1/review-results"))
            .bearer_auth(&token)
            .header(
                registry_review_protocol::REVIEW_PROFILE_HEADER,
                &h.producer.profile,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(page.items.len(), usize::from(subject == "breg-client"));
    }
    let response = client
        .put(format!("{url}/v1/review-requests"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 405);
    let problem: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        problem["type"],
        format!(
            "{}request/method-not-allowed",
            registry_coordinator::problem::PROBLEM_TYPE_BASE
        )
    );
    let response = client
        .post(format!("{url}/v1/review-requests"))
        .header("content-length", "131073")
        .body("x".repeat(131073))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
    let problem: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        problem["type"],
        format!(
            "{}request/body-too-large",
            registry_coordinator::problem::PROBLEM_TYPE_BASE
        )
    );
    server.abort();
    let _ = server.await;
    h.cleanup().await;
}

fn revised_policy(definition: &Definition, version: &str) -> Definition {
    let mut snapshot: serde_json::Value =
        serde_json::from_str(&definition.snapshot().unwrap()).unwrap();
    snapshot["workflow"]["version"] = json!(version);
    Definition::from_snapshot(&serde_json::to_string(&snapshot).unwrap()).unwrap()
}

#[tokio::test]
async fn router_recovers_removed_policy_only_under_current_authority_and_exact_input() {
    use registry_coordinator::{
        access::{Action, Authenticator, ClientPolicy},
        deployment,
        http::{self, HttpState},
        project,
    };
    use registry_platform_config::PackageConfig;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{
        access_token_typ_set, JwksFetcher, JwksFetcherConfig, TokenVerifierConfig,
    };
    use registry_platform_testing::{TestAuthorizationServerBuilder, TestClient};
    let issuer = TestAuthorizationServerBuilder::default()
        .client(TestClient::new("breg-client"))
        .start()
        .await;
    let mut h = Harness::new(86400).await;
    h.actor.issuer = issuer.issuer();
    let audit = h.capture_audit().await;
    let mut request = h.request();
    request.policy = registry_review_protocol::PolicySelection::current(&h.definition.workflow.id);
    // Seed the acceptance as the previous process did before its response was lost.
    let accepted = h.admit(request.clone(), "removed-policy").await;
    assert_review_admission_audit(&audit.take(), "accepted");
    let root = tempfile::tempdir().unwrap();
    let authored = root.path().join("other-workflow");
    project::init(&authored, Some("other-workflow")).unwrap();
    let package = root.path().join("package");
    let digest = deployment::package(&authored, &package).unwrap();
    let template = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/single-flow-runtime.yaml")
        .canonicalize()
        .unwrap();
    let mut runtime = RuntimeConfig::load(&template).unwrap();
    runtime.deployment.as_mut().unwrap().packages = vec![PackageConfig {
        root: package,
        expected_digest: Some(digest),
    }];
    let workflows =
        Arc::new(deployment::load_workflows(runtime.deployment.as_ref().unwrap()).unwrap());
    assert!(workflows.get(&request.policy.id).is_none());
    let other_workflow = workflows.iter().next().unwrap().0.clone();
    let verifier = TokenVerifierConfig::access_token_profile(
        issuer.issuer(),
        vec!["urn:coordinator:review-test".into()],
        vec![jsonwebtoken::Algorithm::EdDSA],
        access_token_typ_set("at+jwt"),
    )
    .with_scope_claim("scope")
    .with_allowed_clients(vec!["breg-client".into()]);
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        issuer.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let token = issuer.issue_access_token(
        "breg-client",
        "breg-client",
        "urn:coordinator:review-test",
        "review:request",
        chrono::Utc::now().timestamp() + 300,
    );
    for mode in [
        "current",
        "workflow-revoked",
        "source-revoked",
        "profile-revoked",
        "action-revoked",
        "recovery-only",
        "subject-changed",
    ] {
        let mut policy = ClientPolicy {
            review_producer: Some(h.producer.clone()),
            required_scopes: vec!["review:request".into()],
            workflows: vec![request.policy.id.clone(), other_workflow.clone()],
            actions: vec![Action::ReviewCreate],
            operator: false,
        };
        match mode {
            "workflow-revoked" => policy.workflows = vec![other_workflow.clone()],
            "source-revoked" => {
                policy.review_producer.as_mut().unwrap().sources = vec!["other-source".into()]
            }
            "profile-revoked" => {
                policy.review_producer.as_mut().unwrap().profile = "other-profile".into()
            }
            "action-revoked" => policy.actions = vec![Action::ReviewRead],
            _ => {}
        }
        let state = HttpState {
            store: h.store.clone(),
            runtime: Arc::new(runtime.clone()),
            workflows: workflows.clone(),
            authenticator: Arc::new(Authenticator::new(
                verifier.clone(),
                keys.clone(),
                [("breg-client".into(), policy)].into(),
                false,
            )),
            adapters: Arc::new(Pure(h.binding.clone())),
            recovery_only: mode == "recovery-only",
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/v1/review-requests",
            listener.local_addr().unwrap()
        );
        let server =
            tokio::spawn(async move { axum::serve(listener, http::router(state)).await.unwrap() });
        let response = client
            .post(&url)
            .bearer_auth(if mode == "subject-changed" {
                issuer.issue_access_token(
                    "breg-client",
                    "other-subject",
                    "urn:coordinator:review-test",
                    "review:request",
                    chrono::Utc::now().timestamp() + 300,
                )
            } else {
                token.clone()
            })
            .header(
                registry_review_protocol::REVIEW_PROFILE_HEADER,
                &h.producer.profile,
            )
            .header("idempotency-key", "removed-policy")
            .json(&request)
            .send()
            .await
            .unwrap();
        if mode == "current" {
            assert_eq!(response.status(), 201);
            let recovered: registry_review_protocol::ReviewRequestAccepted =
                response.json().await.unwrap();
            assert_eq!(recovered, accepted);
            assert_review_admission_audit(&audit.take(), "accepted");
            let mut changed = request.clone();
            changed.requester_reference = "different-request".into();
            let mut fresh = request.clone();
            fresh.subject.id = Uuid::new_v4().to_string();
            let mut served = fresh.clone();
            served.policy = registry_review_protocol::PolicySelection::current(&other_workflow);
            for (input, key, status, code) in [
                (changed, "removed-policy", 409, "idempotency.key-reused"),
                (fresh, "fresh-removed-policy", 404, "workflow.not-served"),
                (served, "fresh-served-policy", 409, "deployment.refused"),
            ] {
                let response = client
                    .post(&url)
                    .bearer_auth(&token)
                    .header(
                        registry_review_protocol::REVIEW_PROFILE_HEADER,
                        &h.producer.profile,
                    )
                    .header("idempotency-key", key)
                    .json(&input)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), status, "{key}");
                let problem: serde_json::Value = response.json().await.unwrap();
                assert_eq!(problem["code"], code, "{key}");
                assert_review_admission_audit(&audit.take(), "unknown");
            }
        } else if mode == "subject-changed" {
            assert_eq!(response.status(), 404);
            let problem: serde_json::Value = response.json().await.unwrap();
            assert_eq!(problem["code"], "workflow.not-served");
            assert_review_admission_audit(&audit.take(), "unknown");
        } else {
            assert_eq!(
                response.status(),
                if mode == "recovery-only" { 409 } else { 403 },
                "{mode}"
            );
            let problem: serde_json::Value = response.json().await.unwrap();
            assert_eq!(
                problem["code"],
                if mode == "recovery-only" {
                    "admission.recovery-only"
                } else {
                    "operation.not-authorized"
                },
                "{mode}"
            );
        }
        server.abort();
        let _ = server.await;
        audit.take();
    }
    let (db, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(async move { connection.await.unwrap() });
    let count: i64 = db
        .query_one(&format!("SELECT count(*) FROM {}.runs", h.namespace), &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "recovery and refused work create no Run");
    drop(db);
    connection.await.unwrap();
    h.cleanup().await;
}

fn assert_review_admission_audit(entries: &[serde_json::Value], outcome: &str) {
    assert_eq!(entries.len(), 2, "one request/response pair per admission");
    assert_eq!(entries[0]["phase"], "request");
    assert_eq!(entries[1]["phase"], "response");
    assert_eq!(entries[0]["correlation"], entries[1]["correlation"]);
    for entry in entries {
        assert_eq!(entry["record"]["action"], "review-admit");
    }
    assert_eq!(entries[1]["record"]["outcome"], outcome);
}

#[tokio::test]
async fn router_fresh_admission_audits_once_and_audit_outages_gate_commit_and_release() {
    use registry_coordinator::{
        access::{Action, Authenticator, ClientPolicy},
        deployment,
        http::{self, HttpState},
    };
    use registry_platform_config::PackageConfig;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{
        access_token_typ_set, JwksFetcher, JwksFetcherConfig, TokenVerifierConfig,
    };
    use registry_platform_testing::{TestAuthorizationServerBuilder, TestClient};

    let mut h = Harness::new(86400).await;
    let admin_url = h.url.clone();
    let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(async move { connection.await.unwrap() });
    let role = format!("coord_review_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    admin
        .batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
        ))
        .await
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("workflow.yaml"),
        serde_json::to_string(&review_project(86400)).unwrap(),
    )
    .unwrap();
    let package = root.path().join("package");
    let digest = deployment::package(&project, &package).unwrap();
    let template = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/single-flow-runtime.yaml")
        .canonicalize()
        .unwrap();
    let mut runtime = RuntimeConfig::load(&template).unwrap();
    runtime.namespace = h.namespace.clone();
    let deployment = runtime.deployment.as_mut().unwrap();
    deployment.database_id = h.namespace.clone();
    deployment.runtime_role = role.clone();
    deployment.packages = vec![PackageConfig {
        root: package,
        expected_digest: Some(digest),
    }];
    let workflows = Arc::new(deployment::load_workflows(deployment).unwrap());
    deployment::apply(&h.store, &runtime, &workflows, &[])
        .await
        .unwrap();
    h.url = if let Ok(mut url) = url::Url::parse(&admin_url) {
        url.set_username(&role).unwrap();
        url.set_password(Some(&password)).unwrap();
        url.into()
    } else {
        format!("{admin_url} user={role} password={password}")
    };
    let issuer = TestAuthorizationServerBuilder::default()
        .client(TestClient::new("breg-client"))
        .start()
        .await;
    h.actor.issuer = issuer.issuer();
    let verifier = TokenVerifierConfig::access_token_profile(
        issuer.issuer(),
        vec!["urn:coordinator:review-test".into()],
        vec![jsonwebtoken::Algorithm::EdDSA],
        access_token_typ_set("at+jwt"),
    )
    .with_scope_claim("scope")
    .with_allowed_clients(vec!["breg-client".into()]);
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        issuer.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let authenticator = Arc::new(Authenticator::new(
        verifier,
        keys,
        [(
            "breg-client".into(),
            ClientPolicy {
                review_producer: Some(h.producer.clone()),
                required_scopes: vec!["review:request".into()],
                workflows: h.workflows(),
                actions: vec![Action::ReviewCreate],
                operator: false,
            },
        )]
        .into(),
        false,
    ));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let request = h.request();
    let mut lost_response = None;
    let mut first_response = None;
    for (subject, writes, key, status, count) in [
        ("breg-client", None, "fresh-success", 201, 1_i64),
        ("breg-client", Some(0), "request-audit-outage", 503, 1),
        ("breg-client", Some(1), "response-audit-outage", 503, 2),
        ("breg-client", None, "response-audit-outage", 201, 2),
        ("other-subject", None, "fresh-success", 201, 3),
    ] {
        let token = issuer.issue_access_token(
            "breg-client",
            subject,
            "urn:coordinator:review-test",
            "review:request",
            chrono::Utc::now().timestamp() + 300,
        );
        let audit = h.capture_audit().await;
        *audit.1.lock().unwrap() = writes;
        let state = HttpState {
            store: h.store.clone(),
            runtime: Arc::new(runtime.clone()),
            workflows: workflows.clone(),
            authenticator: authenticator.clone(),
            adapters: Arc::new(Pure(h.binding.clone())),
            recovery_only: false,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/v1/review-requests",
            listener.local_addr().unwrap()
        );
        let server =
            tokio::spawn(async move { axum::serve(listener, http::router(state)).await.unwrap() });
        let response = client
            .post(&url)
            .bearer_auth(&token)
            .header(
                registry_review_protocol::REVIEW_PROFILE_HEADER,
                &h.producer.profile,
            )
            .header("idempotency-key", key)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{key}");
        let body: serde_json::Value = response.json().await.unwrap();
        let entries = audit.take();
        if status == 201 {
            assert_review_admission_audit(&entries, "accepted");
            let accepted: registry_review_protocol::ReviewRequestAccepted =
                serde_json::from_value(body).unwrap();
            if key == "response-audit-outage" {
                assert_eq!(accepted.request_id, lost_response.unwrap());
            } else if subject == "breg-client" {
                first_response = Some(accepted.request_id);
            } else {
                assert_ne!(Some(accepted.request_id), first_response);
            }
        } else {
            assert_eq!(
                body["code"],
                if writes == Some(0) {
                    "service.unavailable"
                } else {
                    "audit.response-unavailable"
                }
            );
            assert!(body.get("requestId").is_none());
            assert_eq!(entries.len(), usize::from(writes == Some(1)));
            if writes == Some(1) {
                lost_response = Some(
                    admin
                        .query_one(
                            &format!(
                                "SELECT run_id FROM {}.runs ORDER BY admitted_at DESC LIMIT 1",
                                h.namespace
                            ),
                            &[],
                        )
                        .await
                        .unwrap()
                        .get::<_, Uuid>(0),
                );
            }
        }
        let actual: i64 = admin
            .query_one(&format!("SELECT count(*) FROM {}.runs", h.namespace), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(actual, count, "{key}");
        server.abort();
        let _ = server.await;
    }
    h.url = admin_url;
    h.cleanup().await;
    admin
        .batch_execute(&format!("DROP ROLE {role}"))
        .await
        .unwrap();
    drop(admin);
    connection.await.unwrap();
}

#[tokio::test]
async fn current_selection_recovers_original_acceptance_after_policy_change_and_restart() {
    use registry_review_protocol::PolicySelection;
    let h = Harness::new(86400).await;
    let mut request = h.request();
    request.policy = PolicySelection::current(&h.definition.workflow.id);
    let accepted = h.admit(request.clone(), "current-selection").await;
    let changed = revised_policy(&h.definition, "2");
    let restarted = Store::connect(&h.url, &h.namespace).await.unwrap();
    // The caller could have lost the first response. It still sends the original selector.
    let recovered = restarted
        .admit_review_owned(
            &changed,
            request.clone(),
            &h.actor,
            &h.producer,
            "current-selection",
            &h.binding,
            &h.runtime,
        )
        .await
        .unwrap();
    assert_eq!(recovered, accepted);
    assert_eq!(accepted.policy.version, "1");
    let view = restarted
        .review_request_owned(accepted.request_id, &h.actor, &h.producer, &h.workflows())
        .await
        .unwrap();
    assert_eq!(view.policy, accepted.policy);
    let mut repinned = request.clone();
    repinned.policy = accepted.policy.clone().into();
    assert_eq!(
        restarted
            .admit_review_owned(
                &changed,
                repinned.clone(),
                &h.actor,
                &h.producer,
                "current-selection",
                &h.binding,
                &h.runtime
            )
            .await
            .unwrap_err()
            .code,
        "start-conflict",
        "an accepted binding cannot replace the original selector in recovery"
    );
    assert_eq!(
        restarted
            .admit_review_owned(
                &changed,
                repinned,
                &h.actor,
                &h.producer,
                "strict-new-selection",
                &h.binding,
                &h.runtime
            )
            .await
            .unwrap_err()
            .code,
        "workflow-revision-mismatch"
    );
    let mut next_request = request.clone();
    next_request.subject.id = Uuid::new_v4().to_string();
    let next = restarted
        .admit_review_owned(
            &changed,
            next_request,
            &h.actor,
            &h.producer,
            "next-selection",
            &h.binding,
            &h.runtime,
        )
        .await
        .unwrap();
    assert_eq!(
        next.policy,
        policy_binding(&changed.workflow, &changed.digest)
            .unwrap()
            .unwrap()
    );
    let revoked = ReviewProducer {
        sources: vec!["different-source".into()],
        ..h.producer.clone()
    };
    assert_eq!(
        restarted
            .admit_review_owned(
                &changed,
                request.clone(),
                &h.actor,
                &revoked,
                "current-selection",
                &h.binding,
                &h.runtime
            )
            .await
            .unwrap_err()
            .code,
        "access.denied"
    );
    // Accepted work executes its retained definition even when future admissions select v2.
    while h.worker().tick().await.unwrap() {}
    let result = h.result(accepted.request_id).await;
    assert_eq!(result.policy, accepted.policy);
    assert_eq!(result.submission_digest, accepted.submission_digest);
    h.cleanup().await;
}

#[tokio::test]
async fn concurrent_current_selection_keeps_one_concrete_policy_and_run() {
    use registry_review_protocol::PolicySelection;
    let h = Harness::new(86400).await;
    let mut request = h.request();
    request.policy = PolicySelection::current(&h.definition.workflow.id);
    let changed = revised_policy(&h.definition, "2");
    let (first, second) = tokio::join!(
        h.store.admit_review_owned(
            &h.definition,
            request.clone(),
            &h.actor,
            &h.producer,
            "policy-race",
            &h.binding,
            &h.runtime
        ),
        h.store.admit_review_owned(
            &changed,
            request.clone(),
            &h.actor,
            &h.producer,
            "policy-race",
            &h.binding,
            &h.runtime
        ),
    );
    let first = first.unwrap();
    assert_eq!(first, second.unwrap());
    assert!(request.policy.matches(&first.policy));
    assert!(["1", "2"].contains(&first.policy.version.as_str()));
    let (db, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(async move { connection.await.unwrap() });
    let count: i64 = db
        .query_one(&format!("SELECT count(*) FROM {}.runs", h.namespace), &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    drop(db);
    connection.await.unwrap();
    h.worker().tick().await.unwrap();
    assert_eq!(h.result(first.request_id).await.policy, first.policy);
    h.cleanup().await;
}
