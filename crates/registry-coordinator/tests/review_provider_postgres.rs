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
    ReviewResult, ReviewResultStatus, SubjectBinding,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

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
        let project = json!({"apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1","kind":"CoordinatorProject","project":{"id":"proposal-assessment","version":"1"},"workflow":{"input":{"type":"object"},"deadlineSeconds":600,"review":{"resultRetentionSeconds":retention,"outcomes":{"accepted":{"status":"approved"}}},"start":"done","steps":{"done":{"type":"finish","outcome":"accepted"}},"outcomes":{"accepted":{"type":"null"}}}});
        std::fs::write(
            root.path().join("workflow.yaml"),
            serde_json::to_string(&project).unwrap(),
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
                .unwrap(),
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
    async fn cleanup(&self) {
        self.sql("DROP SCHEMA {schema} CASCADE").await;
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
    assert!(result.outcome.is_none() && result.result.is_none());
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
    let mut stranger = h.actor.clone();
    stranger.client_id = "other-client".into();
    for (actor, workflows, producer) in [
        (&stranger, h.workflows(), h.producer.clone()),
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
    }
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
            .retain_terminal(chrono::Utc::now(), 100, &operator)
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
            .retain_terminal(chrono::Utc::now(), 100, &operator)
            .await
            .unwrap(),
        1
    );
    assert_eq!(h.admit(request, "expiring").await, accepted);
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
            assert_eq!(
                h.result(accepted.request_id).await.status,
                ReviewResultStatus::Approved
            );
        }
    }
    h.cleanup().await;
}

#[tokio::test]
async fn revoked_sources_do_not_disclose_or_starve_the_authorized_result_feed() {
    let mut h = Harness::new(86400).await;
    h.producer.sources.push("source-b".into());
    let revoked = h.admit(h.request(), "source-a").await;
    h.worker().tick().await.unwrap();
    let mut request = h.request();
    request.subject.source = "source-b".into();
    let retained = h.admit(request, "source-b").await;
    h.worker().tick().await.unwrap();
    let narrowed = ReviewProducer {
        sources: vec!["source-b".into()],
        ..h.producer.clone()
    };
    let page = h
        .store
        .review_results_owned(&h.actor, &narrowed, &h.workflows(), None, 1)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].request_id, retained.request_id);
    assert!(page.next_cursor.is_none());
    assert_eq!(
        h.store
            .review_result_owned(revoked.request_id, &h.actor, &narrowed, &h.workflows())
            .await
            .err()
            .unwrap()
            .code,
        "run-absent"
    );
    // A previously issued cursor remains a valid continuation anchor after
    // its source is revoked, without disclosing that source's result again.
    let page = h
        .store
        .review_results_owned(
            &h.actor,
            &narrowed,
            &h.workflows(),
            Some(revoked.request_id),
            1,
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].request_id, retained.request_id);
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
            .retain_terminal(chrono::Utc::now(), 1, &operator)
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
    let project = json!({"apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1","kind":"CoordinatorProject","project":{"id":"proposal-assessment","version":"1"},"operations":{"assessment":{"uses":"breg.read-review-context/v1","connection":"applications"}},"workflow":{"input":{"type":"object"},"deadlineSeconds":600,"review":{"outcomes":{"accepted":{"status":"approved"}}},"start":"assess","steps":{"assess":{"type":"call","operation":"assessment","input":{"type":"literal","value":{"actionId":"correct-name","subject":subject,"contract":contract}},"next":"route"},"route":{"type":"choose","choose":{"type":"literal","value":"automatic"},"cases":{"automatic":"done"}},"done":{"type":"finish","outcome":"accepted"}},"outcomes":{"accepted":{"type":"null"}}}});
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
    assert!(feed.await.unwrap().unwrap().items.is_empty());
    drop(probe);
    probe_connection.await.unwrap();
    drop(blocker);
    connection.await.unwrap();
    h.cleanup().await;
}

#[tokio::test]
async fn erased_cancel_is_expired_on_the_real_router_without_parsing_foreign_bodies() {
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
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        h.store
            .retain_terminal(
                chrono::Utc::now(),
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
    for (caller, id, status) in [
        ("breg-client", accepted.request_id, 410),
        ("other-client", accepted.request_id, 404),
        ("breg-client", Uuid::new_v4(), 404),
    ] {
        let token = issuer.issue_access_token(
            caller,
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
            .body("{malformed-private-canary")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let problem: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            problem["code"],
            if status == 410 {
                "review.result-expired"
            } else {
                "run.not-visible"
            }
        );
        assert!(problem["type"]
            .as_str()
            .unwrap()
            .starts_with(registry_review_protocol::REVIEW_PROBLEM_TYPE_BASE));
        assert!(!problem.to_string().contains("malformed-private-canary"));
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
            registry_review_protocol::REVIEW_PROBLEM_TYPE_BASE
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
            registry_review_protocol::REVIEW_PROBLEM_TYPE_BASE
        )
    );
    server.abort();
    let _ = server.await;
    h.cleanup().await;
}
