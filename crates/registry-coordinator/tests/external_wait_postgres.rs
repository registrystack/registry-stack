// SPDX-License-Identifier: Apache-2.0
//! The maintained external-job project over real HTTP and durable PostgreSQL.
//! No BReg, Casework, or other Registry Stack service participates.
#![cfg(feature = "postgres-test")]

use std::sync::Arc;

use async_trait::async_trait;
use registry_coordinator::{
    definition::{CompletionDefinition, Definition},
    external_http::{ExternalHttpConfig, ExternalHttpConnection},
    protocol::{AdapterSet, CallOutcome, CallRequest, CompletionObservation, Operation},
    store::{Actor, Store},
    worker::Worker,
};
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::{matchers::{method, path, query_param}, Mock, MockServer, ResponseTemplate};

const JOB: &str = "synthetic-job-private-correlation";

struct ExternalAdapter(ExternalHttpConnection);

#[async_trait]
impl AdapterSet for ExternalAdapter {
    fn binding_digest(&self) -> &str { "external-fixture-binding" }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        assert_eq!(request.operation, Operation::ExternalGet);
        assert_eq!(request.connection, "jobs");
        self.0.get(&request.input, false).await
    }

    async fn observe_completion(&self, request: &CallRequest, _: &Value, _: &CompletionDefinition) -> CompletionObservation {
        match self.call(request).await {
            CallOutcome::Success(value) => CompletionObservation::Settled(value),
            CallOutcome::Retryable { code, retry_after } => CompletionObservation::Retryable { code, retry_after },
            CallOutcome::Refused { code } | CallOutcome::Uncertain { code } => CompletionObservation::Hold { code },
            _ => panic!("a read has no business-refusal channel"),
        }
    }
}

struct Harness {
    _project: tempfile::TempDir,
    definition: Definition,
    server: MockServer,
    url: String,
    namespace: String,
    store: Arc<Store>,
    adapters: Arc<ExternalAdapter>,
}

impl Harness {
    async fn new() -> Self {
        let project = tempfile::tempdir().unwrap();
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/coordinator/examples/external-job");
        for name in ["workflow.yaml", "functions.rhai"] {
            std::fs::copy(source.join(name), project.path().join(name)).unwrap();
        }
        let definition = Definition::load(project.path()).expect("maintained external-job compiles");
        let server = MockServer::start().await;
        let config: ExternalHttpConfig = serde_json::from_value(json!({
            "baseUrl":server.uri(), "paths":["jobs/status"], "queryParameters":["id"],
            "responseSchema":{"type":"object"}
        })).unwrap();
        let adapters = Arc::new(ExternalAdapter(ExternalHttpConnection::new(&config, None).unwrap()));
        let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").expect("disposable PostgreSQL is required");
        let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
        let store = Arc::new(Store::connect(&url, &namespace).await.unwrap());
        store.migrate().await.unwrap();
        Self { _project: project, definition, server, url, namespace, store, adapters }
    }

    async fn reply(&self, response: ResponseTemplate) {
        self.server.reset().await;
        Mock::given(method("GET")).and(path("/jobs/status")).and(query_param("id", JOB))
            .respond_with(response).mount(&self.server).await;
    }

    async fn state(&self, state: &str) {
        self.reply(ResponseTemplate::new(200).set_body_json(json!({"jobId":JOB,"state":state}))).await;
    }

    async fn start(&self) -> Uuid {
        self.store.admit(&self.definition, json!({"jobId":JOB}), "external-fixture-producer", &Uuid::new_v4().to_string(), self.adapters.binding_digest()).await.unwrap()
    }

    async fn sql(&self, sql: &str) {
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap(); });
        client.batch_execute(&sql.replace("{schema}", &self.namespace)).await.unwrap();
    }

    async fn advance(&self) {
        // Advance the synthetic database schedule, including its durable floor.
        self.sql("UPDATE {schema}.completion_waits SET not_before=clock_timestamp()-interval '1 second'; UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE state='pending'").await;
    }

    async fn drain(&self, worker: &Worker) {
        for _ in 0..8 { if !worker.tick().await.unwrap() { return; } }
        panic!("bounded workflow did not quiesce");
    }

    fn worker(&self) -> Worker { Worker::new(self.store.clone(), self.adapters.clone()) }

    async fn begin_wait(&self) -> Uuid {
        self.state("running").await;
        let run = self.start().await;
        self.drain(&self.worker()).await;
        let inspection = self.store.inspect(run, self.adapters.binding_digest()).await.unwrap();
        assert_eq!(inspection.run.step, "await-terminal");
        assert_eq!(inspection.waits.len(), 1);
        assert_eq!(inspection.waits[0].observations, 1);
        run
    }
}

#[tokio::test]
async fn frozen_external_read_survives_restart_and_inspects_its_bounded_wait() {
    let h = Harness::new().await;
    let run = h.begin_wait().await;
    let before = h.store.inspect(run, h.adapters.binding_digest()).await.unwrap();
    let wait = &before.waits[0];
    assert_eq!(wait.accepted_step, "read");
    assert_eq!(wait.completion, "terminal");
    assert_eq!(wait.minimum_interval_seconds, 30);
    assert_eq!(wait.observation_limit, 21);
    assert!(before.effects.is_empty(), "GET acceptance is not a mutation effect");
    assert!(!serde_json::to_string(&before).unwrap().contains(JOB));

    h.state("succeeded").await;
    let restarted = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
    let worker = Worker::new(restarted.clone(), h.adapters.clone());
    // Restart and unmatched signals cannot accelerate the persisted read floor.
    for _ in 0..10 { restarted.wake("jobs", Uuid::new_v4()).await.unwrap(); }
    assert!(!worker.tick().await.unwrap());
    assert!(h.server.received_requests().await.unwrap().is_empty());
    h.advance().await;
    h.drain(&worker).await;
    let after = restarted.inspect(run, h.adapters.binding_digest()).await.unwrap();
    assert_eq!(after.run.state, "finished");
    assert_eq!(after.run.outcome.as_deref(), Some("job-result"));
    assert_eq!(after.run.output, Some(json!({"state":"complete","result":{"jobId":JOB}})));
    assert!(after.waits.is_empty());
    let requests = h.server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.query_pairs().collect::<Vec<_>>(), [("id".into(),JOB.into())]);
}

#[tokio::test]
async fn external_terminal_refusal_is_a_typed_result_and_never_an_unknown_command() {
    let h = Harness::new().await;
    let run = h.begin_wait().await;
    h.state("failed").await;
    h.advance().await;
    h.drain(&h.worker()).await;
    let status = h.store.status(run).await.unwrap();
    assert_eq!(status.state, "finished");
    assert!(!status.uncertain);
    assert_eq!(status.output, Some(json!({"state":"refused","code":"external-job-failed"})));
}

#[tokio::test]
async fn wrong_correlation_malformed_oversized_and_redirected_reads_cannot_advance() {
    for response in [
        ResponseTemplate::new(200).set_body_json(json!({"jobId":"another-private-job","state":"succeeded"})),
        ResponseTemplate::new(200).set_body_string("malformed-private-canary"),
        ResponseTemplate::new(200).set_body_json(json!({"jobId":JOB,"state":"surprising-private-canary"})),
        ResponseTemplate::new(200).set_body_string("x".repeat(2 * 1024 * 1024)),
        ResponseTemplate::new(302).insert_header("location", "http://127.0.0.1:9/private-redirect-canary"),
    ] {
        let h = Harness::new().await;
        let run = h.begin_wait().await;
        h.reply(response).await;
        h.advance().await;
        h.drain(&h.worker()).await;
        let inspection = h.store.inspect(run, h.adapters.binding_digest()).await.unwrap();
        assert_eq!(inspection.run.state, "attention");
        assert_eq!(inspection.run.step, "await-terminal");
        assert!(!inspection.run.uncertain, "inability to read is not dispatch ambiguity");
        assert!(inspection.run.output.is_none());
        assert_eq!(inspection.waits[0].observations, 2);
        assert!(inspection.recovery.retry_allowed, "read-only recovery keeps its original correlation");
        let text = serde_json::to_string(&inspection).unwrap();
        for private in [JOB,"another-private-job","malformed-private-canary","surprising-private-canary","private-redirect-canary"] { assert!(!text.contains(private)); }
        assert_eq!(h.server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn outage_honors_retry_after_and_observation_budget_survives_retry() {
    let h = Harness::new().await;
    let run = h.begin_wait().await;
    h.reply(ResponseTemplate::new(503).insert_header("retry-after", "120")).await;
    h.advance().await;
    h.drain(&h.worker()).await;
    let inspection = h.store.inspect(run,h.adapters.binding_digest()).await.unwrap();
    assert_eq!(inspection.run.state,"running");
    assert_eq!(inspection.waits[0].observations,2);
    let spacing = inspection.waits[0].not_before - chrono::Utc::now();
    assert!(spacing.num_seconds() >= 115, "Retry-After is a durable floor");
    h.sql("UPDATE {schema}.completion_waits SET observations=21").await;
    h.advance().await;
    h.drain(&h.worker()).await;
    let exhausted=h.store.inspect(run,h.adapters.binding_digest()).await.unwrap();
    assert_eq!(exhausted.run.state,"attention");
    assert_eq!(exhausted.run.failure_code.as_deref(),Some("observation-budget-exhausted"));
    assert_eq!(h.server.received_requests().await.unwrap().len(),1);
    h.store.retry_same(run,h.adapters.binding_digest()).await.unwrap();
    h.drain(&h.worker()).await;
    assert_eq!(h.store.inspect(run,h.adapters.binding_digest()).await.unwrap().waits[0].observations,21);
    assert_eq!(h.server.received_requests().await.unwrap().len(),1,"retry cannot reset a spent budget");
}

#[tokio::test]
async fn timeout_cancellation_and_deadline_stop_polling_without_claiming_job_failure() {
    for stop in ["timeout","cancel","deadline"] {
        let h=Harness::new().await;
        let run=h.begin_wait().await;
        h.state("succeeded").await;
        match stop {
            "timeout" => h.sql("UPDATE {schema}.completion_waits SET timeout_at=clock_timestamp()-interval '1 second'; UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp() WHERE state='pending'").await,
            "deadline" => h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'").await,
            _ => { h.store.cancel_owned(run,&Actor { issuer:"https://issuer.example.invalid".into(),subject:"operator".into(),client_id:"operator-client".into(),operator:true },"synthetic-withdrawal").await.unwrap(); }
        }
        h.drain(&h.worker()).await;
        let status=h.store.inspect(run,h.adapters.binding_digest()).await.unwrap();
        assert!(status.waits.is_empty());
        match stop {
            "timeout" => { assert_eq!(status.run.state,"finished"); assert_eq!(status.run.outcome.as_deref(),Some("job-wait-expired")); },
            "deadline" => assert_eq!(status.run.state,"expired"),
            _ => assert_eq!(status.run.state,"cancelled"),
        }
        assert!(h.server.received_requests().await.unwrap().is_empty(),"stopping a wait is not a final job read");
    }
}
