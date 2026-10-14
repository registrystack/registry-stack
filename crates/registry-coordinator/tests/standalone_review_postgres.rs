// SPDX-License-Identifier: Apache-2.0
//! Canonical standalone review through the maintained HTTP client and real
//! Coordinator PostgreSQL. The substitute is source neutral and needs no BReg.
#![cfg(feature = "postgres-test")]
mod support;

use registry_casework_client::{submission_digest, ReviewCreateRequest};
use registry_coordinator::{
    adapters::{ConnectionConfig, HttpAdapters},
    definition::Definition,
    protocol::AdapterSet,
    store::{Actor, Store},
    worker::Worker,
};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const REQUEST: &str = "00000000-0000-4000-8000-0000000000a1";
const RESULT: &str = "00000000-0000-4000-8000-0000000000a2";
const PRIVATE: &str = "submitted-notice-private-canary";

fn input() -> Value {
    json!({"policy":{"id":"notice-review","version":"1","digest":format!("sha256:{}","b".repeat(64))},
        "subject":{"source":"notices","type":"notice","id":"notice-7","version":"3","digest":format!("sha256:{}","a".repeat(64))},
        "requesterReference":"notice-request-7","context":{"mode":"submitted","snapshot":{"summary":PRIVATE}}})
}
fn accepted() -> Value {
    let input: ReviewCreateRequest = serde_json::from_value(input()).unwrap();
    json!({"requestId":REQUEST,"subject":input.subject,"policy":input.policy,
        "submissionDigest":submission_digest("coordinator","notices",&input).unwrap()})
}
fn result(status: &str) -> Value {
    let accepted = accepted();
    let mut result = json!({"requestId":REQUEST,"resultId":RESULT,"subject":accepted["subject"],"policy":accepted["policy"],"submissionDigest":accepted["submissionDigest"],
        "status":status,"completedAt":"2026-10-14T00:00:00Z","availableUntil":"2026-11-14T00:00:00Z"});
    if status == "rejected" {
        result["outcome"] = json!("notice-not-approved");
    }
    result
}
fn answer(status: u16, value: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("traceparent", support::TRACE)
        .set_body_json(value)
}
struct Harness {
    _root: tempfile::TempDir,
    _token: MockServer,
    casework: MockServer,
    definition: Definition,
    adapters: Arc<HttpAdapters>,
    store: Arc<Store>,
    url: String,
    namespace: String,
}
impl Harness {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/coordinator/examples/standalone-review/workflow.yaml"),
            root.path().join("workflow.yaml"),
        )
        .unwrap();
        let definition = Definition::load(root.path()).unwrap();
        let token = MockServer::start().await;
        let casework = MockServer::start().await;
        let issuer = support::issuer().await;
        let mut config = support::config(root.path(), &issuer, &casework.uri(), &casework.uri());
        let mut authorization = config.connections["applications"]
            .authorization()
            .unwrap()
            .clone();
        authorization.token_endpoint = format!("{}/token", token.uri()).parse().unwrap();
        authorization.resource = "urn:example:casework".into();
        authorization.scopes = vec!["casework:review".into()];
        config.connections.clear();
        config.connections.insert(
            "review".into(),
            ConnectionConfig::CaseworkReviewProducer(
                registry_coordinator::runtime::CaseworkConnectionConfig {
                    base_url: casework.uri().parse().unwrap(),
                    authorization,
                    profile: "coordinator-producer".into(),
                    producer: "coordinator".into(),
                    completion: None,
                    result_check_seconds: None,
                },
            ),
        );
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"access_token":"fixture-token","token_type":"Bearer","expires_in":40,
            "issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}),
            ))
            .mount(&token)
            .await;
        let adapters = Arc::new(HttpAdapters::new(&config).unwrap());
        issuer.stop().await;
        let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("disposable PostgreSQL is required");
        let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
        let store = Arc::new(Store::connect(&url, &namespace).await.unwrap());
        store.migrate().await.unwrap();
        Self {
            _root: root,
            _token: token,
            casework,
            definition,
            adapters,
            store,
            url,
            namespace,
        }
    }
    fn binding(&self) -> String {
        self.adapters.binding_digest_for(&self.definition.workflow)
    }
    fn worker(&self) -> Worker {
        Worker::new(self.store.clone(), self.adapters.clone())
    }
    async fn submit_response(&self, value: Value) {
        Mock::given(method("POST"))
            .and(path("/v1/review-requests"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(header("registry-casework-profile", "coordinator-producer"))
            .and(body_json(input()))
            .respond_with(answer(201, value))
            .expect(1)
            .mount(&self.casework)
            .await;
    }
    async fn observation(&self, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(format!("/v1/review-requests/{REQUEST}/result")))
            .and(header("authorization", "Bearer fixture-token"))
            .and(header("registry-casework-profile", "coordinator-producer"))
            .respond_with(response)
            .mount(&self.casework)
            .await;
    }
    async fn start(&self) -> Uuid {
        self.store
            .admit(
                &self.definition,
                input(),
                "notice-producer",
                &Uuid::new_v4().to_string(),
                &self.binding(),
            )
            .await
            .unwrap()
    }
    async fn sql(&self, sql: &str) {
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        client
            .batch_execute(&sql.replace("{schema}", &self.namespace))
            .await
            .unwrap();
    }
    async fn drain(&self, worker: &Worker) {
        for _ in 0..8 {
            if !worker.tick().await.unwrap() {
                return;
            }
        }
        panic!("workflow did not quiesce");
    }
}

#[tokio::test]
async fn exact_standalone_results_survive_restart_without_breg_or_source_reads() {
    for status in ["approved", "rejected", "superseded"] {
        let h = Harness::new().await;
        h.submit_response(accepted()).await;
        h.observation(ResponseTemplate::new(202).insert_header("traceparent", support::TRACE))
            .await;
        let run = h.start().await;
        h.drain(&h.worker()).await;
        let inspection = h.store.inspect(run, &h.binding()).await.unwrap();
        assert_eq!(inspection.run.step, "await-result");
        assert_eq!(inspection.waits.len(), 1);
        assert_eq!(inspection.effects.len(), 1);
        assert_eq!(
            serde_json::to_value(&inspection.effects[0]).unwrap()["state"],
            "accepted"
        );
        assert!(!serde_json::to_string(&inspection)
            .unwrap()
            .contains(PRIVATE));
        h.casework.verify().await;
        h.casework.reset().await;
        h.observation(answer(200, result(status))).await;
        h.sql("UPDATE {schema}.completion_waits SET not_before=clock_timestamp()-interval '1 second'; UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp() WHERE state='pending'").await;
        let restarted = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
        h.drain(&Worker::new(restarted.clone(), h.adapters.clone()))
            .await;
        let finished = restarted.status(run).await.unwrap();
        assert_eq!(finished.state, "finished");
        assert_eq!(finished.outcome.as_deref(), Some("review-result"));
        assert_eq!(finished.output, Some(result(status)));
        assert_eq!(
            h.casework.received_requests().await.unwrap().len(),
            1,
            "only the exact retained result is read"
        );
    }
}

#[tokio::test]
async fn changed_policy_or_submission_acceptance_cannot_create_an_observation_wait() {
    for field in ["version", "digest", "submissionDigest"] {
        let h = Harness::new().await;
        let mut wrong = accepted();
        if field == "submissionDigest" {
            wrong[field] = json!(format!("sha256:{}", "e".repeat(64)));
        } else {
            wrong["policy"][field] = if field == "version" {
                json!("2")
            } else {
                json!(format!("sha256:{}", "d".repeat(64)))
            };
        }
        h.submit_response(wrong).await;
        h.observation(answer(200, result("approved"))).await;
        let run = h.start().await;
        h.drain(&h.worker()).await;
        let inspection = h.store.inspect(run, &h.binding()).await.unwrap();
        assert_eq!(inspection.run.state, "attention");
        assert!(inspection.run.uncertain);
        assert!(inspection.waits.is_empty());
        assert_eq!(
            serde_json::to_value(&inspection.effects[0]).unwrap()["state"],
            "unknown"
        );
        assert!(h
            .casework
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.method == "POST"));
    }
}

#[tokio::test]
async fn withdrawal_reports_already_terminal_races_under_its_own_current_authority() {
    for (stop, outcome, status) in [
        ("timeout", "cancelled", "cancelled"),
        ("cancel", "cancelled", "cancelled"),
        ("timeout", "already-terminal", "approved"),
        ("cancel", "already-terminal", "rejected"),
    ] {
        let h = Harness::new().await;
        h.submit_response(accepted()).await;
        h.observation(ResponseTemplate::new(202).insert_header("traceparent", support::TRACE))
            .await;
        let cancellation = json!({"outcome":outcome,"result":result(status)});
        Mock::given(method("POST"))
            .and(path(format!("/v1/review-requests/{REQUEST}/cancel")))
            .and(header("authorization", "Bearer fixture-token"))
            .and(header("registry-casework-profile", "coordinator-producer"))
            .respond_with(answer(200, cancellation.clone()))
            .expect(1)
            .mount(&h.casework)
            .await;
        let run = h.start().await;
        h.drain(&h.worker()).await;
        if stop == "timeout" {
            h.sql("UPDATE {schema}.completion_waits SET timeout_at=clock_timestamp()-interval '1 second'; UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp() WHERE state='pending'").await;
        } else {
            h.store
                .cancel_owned(
                    run,
                    &Actor {
                        issuer: "https://issuer.example.invalid".into(),
                        subject: "operator".into(),
                        client_id: "operator".into(),
                        operator: true,
                    },
                    "synthetic-withdrawal",
                )
                .await
                .unwrap();
        }
        h.drain(&h.worker()).await;
        let finished = h.store.status(run).await.unwrap();
        assert_eq!(finished.state, "finished");
        assert_eq!(
            finished.outcome.as_deref(),
            Some(if stop == "timeout" {
                "timeout-withdrawal-result"
            } else {
                "operator-withdrawal-result"
            })
        );
        assert_eq!(finished.output, Some(cancellation));
        let requests = h.casework.received_requests().await.unwrap();
        assert!(requests
            .iter()
            .all(|r| r.url.path().starts_with("/v1/review-requests")));
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.path().ends_with("/cancel"))
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn pending_and_unavailable_review_reads_preserve_the_product_retry_floor() {
    for (status, hint, expected_state) in [
        (202, "120", "running"),
        (429, "120", "running"),
        (503, "120", "running"),
        (202, "999999", "attention"),
        (503, "invalid", "attention"),
    ] {
        let h = Harness::new().await;
        h.submit_response(accepted()).await;
        h.observation(
            ResponseTemplate::new(status)
                .insert_header("traceparent", support::TRACE)
                .insert_header("retry-after", hint),
        )
        .await;
        let run = h.start().await;
        h.drain(&h.worker()).await;
        let inspection = h.store.inspect(run, &h.binding()).await.unwrap();
        assert_eq!(inspection.run.state, expected_state);
        assert_eq!(inspection.waits[0].observations, 1);
        if expected_state == "running" {
            assert!((inspection.waits[0].not_before - chrono::Utc::now()).num_seconds() >= 115);
        } else {
            assert_eq!(
                inspection.run.failure_code.as_deref(),
                Some("completion-unusable-retry-after")
            );
        }
        assert!(!inspection.run.uncertain);
    }
}
