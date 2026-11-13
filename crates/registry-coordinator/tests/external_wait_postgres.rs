// SPDX-License-Identifier: Apache-2.0
//! The maintained external-job project over real HTTP and durable PostgreSQL.
//! No BReg, Casework, or other Registry Stack service participates.
#![cfg(feature = "postgres-test")]

use std::{
    io::{BufRead, BufReader, Read},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use registry_coordinator::{
    definition::{CompletionDefinition, Definition},
    external_http::{ExternalHttpConfig, ExternalHttpConnection},
    protocol::{AdapterSet, CallOutcome, CallRequest, CompletionObservation, Operation},
    store::{Actor, Store},
    worker::Worker,
};
use registry_platform_httputil::client::StaticToken;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::{
    matchers::{body_json, header_exists, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

const JOB: &str = "synthetic-job-private-correlation";
const PYTHON_ACCEPTANCE_TOKEN: &str = "external-job-acceptance-token";

struct PythonService {
    child: Child,
    stderr_reader: Option<JoinHandle<String>>,
    reaped: bool,
    base_url: String,
}

impl PythonService {
    fn start(fault: &str) -> Self {
        let schema = format!("external_job_{}", Uuid::new_v4().simple());
        Self::start_in_schema(fault, &schema)
    }

    fn start_in_schema(fault: &str, schema: &str) -> Self {
        let python = std::env::var("EXTERNAL_JOB_PYTHON")
            .expect("EXTERNAL_JOB_PYTHON must name the installed-wheel Python interpreter");
        let database = std::env::var("EXTERNAL_JOB_TEST_DATABASE_URL")
            .expect("EXTERNAL_JOB_TEST_DATABASE_URL must name a separate disposable database");
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/coordinator/examples/external-job/tests/acceptance_server.py");
        let child = Command::new(python)
            .arg(script)
            .arg("--fault")
            .arg(fault)
            .arg("--schema")
            .arg(schema)
            .env("EXTERNAL_JOB_DATABASE_URL", database)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the installed-wheel Python acceptance host");
        let mut service = Self {
            child,
            stderr_reader: None,
            reaped: false,
            base_url: String::new(),
        };
        let mut stderr = service.child.stderr.take().unwrap();
        service.stderr_reader = Some(std::thread::spawn(move || {
            let mut output = String::new();
            stderr
                .read_to_string(&mut output)
                .expect("read Python acceptance stderr");
            output
        }));
        let stdout = service.child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut ready = String::new();
            let result = BufReader::new(stdout).read_line(&mut ready).map(|_| ready);
            let _ = sender.send(result);
        });
        let ready = receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("Python acceptance host did not become ready within 30 seconds")
            .expect("read the Python acceptance host readiness line");
        reader.join().expect("Python acceptance host reader exited");
        service.base_url = serde_json::from_str::<Value>(&ready)
            .expect("Python acceptance host emitted one JSON readiness line")["baseUrl"]
            .as_str()
            .expect("Python acceptance host emitted its loopback base URL")
            .to_owned();
        service
    }

    fn wait_for_exit(&mut self, expected_code: i32) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.child.try_wait().expect("read Python acceptance exit") {
                Some(status) => {
                    assert_eq!(status.code(), Some(expected_code));
                    self.reaped = true;
                    return;
                }
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                None => panic!("Python acceptance host did not exit within 10 seconds"),
            }
        }
    }

    fn take_stderr(&mut self) -> String {
        assert!(self.reaped, "reap the Python acceptance host first");
        self.stderr_reader
            .take()
            .expect("Python acceptance stderr is available")
            .join()
            .expect("Python acceptance stderr reader exited")
    }

    fn stop_and_take_stderr(&mut self) -> String {
        let _ = self.child.kill();
        self.child
            .wait()
            .expect("reap the Python acceptance host after the journey");
        self.reaped = true;
        self.take_stderr()
    }
}

impl Drop for PythonService {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            self.child
                .wait()
                .expect("reap the Python acceptance host after the journey");
            self.reaped = true;
        }
        if self.stderr_reader.is_some() {
            let stderr = self.take_stderr();
            assert!(
                stderr.is_empty(),
                "Python acceptance host wrote unexpected stderr"
            );
        }
    }
}

struct ExternalAdapter(ExternalHttpConnection);

#[async_trait]
impl AdapterSet for ExternalAdapter {
    fn binding_digest(&self) -> &str {
        "external-fixture-binding"
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        assert_eq!(request.connection, "jobs");
        match request.operation {
            Operation::ExternalGet => self.0.get(&request.input, false).await,
            Operation::ExternalCommand => {
                self.0
                    .command(
                        &request.input,
                        request
                            .idempotency_key
                            .as_deref()
                            .expect("the durable admission has a frozen command key"),
                        false,
                    )
                    .await
            }
            operation => panic!("unexpected external-job operation {operation:?}"),
        }
    }

    async fn call_attempt(
        &self,
        request: &CallRequest,
        prepared: Option<&[u8]>,
        final_attempt: bool,
    ) -> CallOutcome {
        assert!(prepared.is_none(), "external HTTP has no prepared evidence");
        if request.operation == Operation::ExternalCommand {
            return self
                .0
                .command(
                    &request.input,
                    request
                        .idempotency_key
                        .as_deref()
                        .expect("the durable admission has a frozen command key"),
                    final_attempt,
                )
                .await;
        }
        self.call(request).await
    }

    async fn observe_completion(
        &self,
        request: &CallRequest,
        _: &Value,
        _: &CompletionDefinition,
    ) -> CompletionObservation {
        match self.call(request).await {
            CallOutcome::Success(value) => CompletionObservation::Settled(value),
            CallOutcome::Retryable { code, retry_after } => {
                CompletionObservation::Retryable { code, retry_after }
            }
            CallOutcome::Refused { code } | CallOutcome::Uncertain { code } => {
                CompletionObservation::Hold { code }
            }
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
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/coordinator/examples/external-job");
        for name in ["workflow.yaml", "functions.rhai"] {
            std::fs::copy(source.join(name), project.path().join(name)).unwrap();
        }
        let definition =
            Definition::load(project.path()).expect("maintained external-job compiles");
        let server = MockServer::start().await;
        let config: ExternalHttpConfig = serde_json::from_value(json!({
            "baseUrl":server.uri(), "paths":["jobs/status"], "queryParameters":["id"],
            "commandPath":"jobs",
            "responseSchema":{"type":"object"}
        }))
        .unwrap();
        let adapters = Arc::new(ExternalAdapter(
            ExternalHttpConnection::new(&config, None).unwrap(),
        ));
        let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("disposable PostgreSQL is required");
        let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
        let store = Arc::new(Store::connect(&url, &namespace).await.unwrap());
        store.migrate().await.unwrap();
        Self {
            _project: project,
            definition,
            server,
            url,
            namespace,
            store,
            adapters,
        }
    }

    async fn reply(&self, response: ResponseTemplate) {
        self.server.reset().await;
        Mock::given(method("GET"))
            .and(path("/jobs/status"))
            .and(query_param("id", JOB))
            .respond_with(response)
            .mount(&self.server)
            .await;
    }

    async fn state(&self, state: &str) {
        self.reply(ResponseTemplate::new(200).set_body_json(json!({"jobId":JOB,"state":state})))
            .await;
    }

    async fn admitted(&self, state: &str) {
        self.server.reset().await;
        Mock::given(method("POST"))
            .and(path("/jobs"))
            .and(header_exists("idempotency-key"))
            .and(body_json(json!({"reference":"case-001"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"jobId":JOB})))
            .expect(1)
            .mount(&self.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jobs/status"))
            .and(query_param("id", JOB))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"jobId":JOB,"state":state})),
            )
            .mount(&self.server)
            .await;
    }

    async fn start(&self) -> Uuid {
        self.store
            .admit(
                &self.definition,
                json!({"reference":"case-001"}),
                "external-fixture-producer",
                &Uuid::new_v4().to_string(),
                self.adapters.binding_digest(),
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

    async fn advance(&self) {
        // Advance the synthetic database schedule, including its durable floor.
        self.sql("UPDATE {schema}.completion_waits SET not_before=clock_timestamp()-interval '1 second'; UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE state='pending'").await;
    }

    async fn drain(&self, worker: &Worker) {
        for _ in 0..8 {
            if !worker.tick().await.unwrap() {
                return;
            }
        }
        panic!("bounded workflow did not quiesce");
    }

    fn worker(&self) -> Worker {
        Worker::new(self.store.clone(), self.adapters.clone())
    }

    fn bind_python(&mut self, service: &PythonService) {
        let mut config: ExternalHttpConfig = serde_json::from_value(json!({
            "baseUrl":service.base_url,
            "paths":["jobs/status"],
            "queryParameters":["id"],
            "commandPath":"jobs",
            "responseSchema":{"type":"object"}
        }))
        .unwrap();
        config.authorization = Some(
            serde_json::from_value(json!({
                "tokenEndpoint":"http://127.0.0.1:9999/token",
                "clientId":"coordinator-external-job",
                "signingKeyRef":"secret:file/external-job-client-jwk",
                "resource":"urn:example:external-job",
                "scopes":["external-job:admit","external-job:observe"]
            }))
            .unwrap(),
        );
        self.adapters = Arc::new(ExternalAdapter(
            ExternalHttpConnection::new(
                &config,
                Some(Arc::new(StaticToken::new(PYTHON_ACCEPTANCE_TOKEN).unwrap())),
            )
            .unwrap(),
        ));
    }

    async fn begin_wait(&self) -> Uuid {
        self.admitted("running").await;
        let run = self.start().await;
        self.drain(&self.worker()).await;
        let inspection = self
            .store
            .inspect(run, self.adapters.binding_digest())
            .await
            .unwrap();
        assert_eq!(inspection.run.step, "await-terminal");
        assert_eq!(inspection.waits.len(), 1);
        assert_eq!(inspection.waits[0].observations, 1);
        assert_eq!(inspection.effects.len(), 1);
        assert_eq!(
            serde_json::to_value(&inspection.effects[0]).unwrap()["state"],
            "accepted"
        );
        run
    }
}

#[tokio::test]
#[ignore = "requires separate disposable Coordinator and external-job databases plus an installed-wheel Python interpreter"]
async fn installed_python_job_recovers_the_original_command_after_commit() {
    let service = PythonService::start("malformed-response-after-commit");
    let mut h = Harness::new().await;
    let mut config: ExternalHttpConfig = serde_json::from_value(json!({
        "baseUrl":service.base_url,
        "paths":["jobs/status"],
        "queryParameters":["id"],
        "commandPath":"jobs",
        "responseSchema":{"type":"object"}
    }))
    .unwrap();
    config.authorization = Some(
        serde_json::from_value(json!({
            "tokenEndpoint":"http://127.0.0.1:9999/token",
            "clientId":"coordinator-external-job",
            "signingKeyRef":"secret:file/external-job-client-jwk",
            "resource":"urn:example:external-job",
            "scopes":["external-job:admit","external-job:observe"]
        }))
        .unwrap(),
    );
    h.adapters = Arc::new(ExternalAdapter(
        ExternalHttpConnection::new(
            &config,
            Some(Arc::new(StaticToken::new(PYTHON_ACCEPTANCE_TOKEN).unwrap())),
        )
        .unwrap(),
    ));

    let run = h.start().await;
    h.drain(&h.worker()).await;
    let held = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(held.run.state, "attention");
    assert!(held.run.uncertain);
    assert_eq!(
        serde_json::to_value(&held.effects[0]).unwrap()["state"],
        "unknown"
    );
    assert!(held.recovery.retry_allowed);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let snapshot_url = format!("{}/test/snapshot", service.base_url);
    let first_snapshot: Value = client
        .get(&snapshot_url)
        .bearer_auth(PYTHON_ACCEPTANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first_snapshot["jobCount"], 1);
    assert_eq!(
        first_snapshot["jobs"][0]["request"],
        json!({"reference":"case-001"})
    );
    let job_id = first_snapshot["jobs"][0]["receipt"]["jobId"]
        .as_str()
        .expect("the application stored its committed receipt")
        .to_owned();

    h.store
        .retry_same(run, h.adapters.binding_digest())
        .await
        .unwrap();
    h.drain(&h.worker()).await;
    let recovered = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(recovered.run.step, "await-terminal");
    assert_eq!(recovered.effects.len(), 1);
    assert_eq!(recovered.waits.len(), 1);
    let recovered_snapshot: Value = client
        .get(&snapshot_url)
        .bearer_auth(PYTHON_ACCEPTANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        recovered_snapshot, first_snapshot,
        "retry-same reused the original command and application receipt"
    );

    for state in ["running", "succeeded"] {
        client
            .post(format!("{}/test/transition", service.base_url))
            .bearer_auth(PYTHON_ACCEPTANCE_TOKEN)
            .json(&json!({"jobId":job_id,"state":state}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
    h.advance().await;
    h.drain(&h.worker()).await;
    let terminal = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(terminal.run.state, "finished");
    assert_eq!(terminal.run.outcome.as_deref(), Some("job-result"));
    assert_eq!(
        terminal.run.output,
        Some(json!({"state":"complete","result":{"jobId":job_id}}))
    );
    assert!(terminal.waits.is_empty());
}

#[tokio::test]
#[ignore = "requires separate disposable Coordinator and external-job databases plus an installed-wheel Python interpreter"]
async fn installed_python_job_survives_process_death_after_commit_and_restart() {
    let schema = format!("external_job_{}", Uuid::new_v4().simple());
    let mut service = PythonService::start_in_schema("process-exit-after-commit", &schema);
    let mut h = Harness::new().await;
    h.bind_python(&service);

    let run = h.start().await;
    h.drain(&h.worker()).await;
    let held = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(held.run.state, "attention");
    assert!(held.run.uncertain);
    assert_eq!(
        serde_json::to_value(&held.effects[0]).unwrap()["state"],
        "unknown"
    );
    assert!(held.recovery.retry_allowed);
    assert_eq!(
        held.recovery.operation,
        Some(Operation::ExternalCommand.identity())
    );
    service.wait_for_exit(86);
    assert!(service.take_stderr().is_empty());
    drop(service);

    let service = PythonService::start_in_schema("none", &schema);
    h.bind_python(&service);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let snapshot_url = format!("{}/test/snapshot", service.base_url);
    let committed_snapshot: Value = client
        .get(&snapshot_url)
        .bearer_auth(PYTHON_ACCEPTANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(committed_snapshot["jobCount"], 1);
    let committed_job = &committed_snapshot["jobs"][0];
    assert_eq!(committed_job["request"], json!({"reference":"case-001"}));
    assert!(committed_job["key"]
        .as_str()
        .is_some_and(|key| !key.is_empty()));
    let job_id = committed_job["receipt"]["jobId"]
        .as_str()
        .expect("the restarted application read the committed receipt")
        .to_owned();

    h.store
        .retry_same(run, h.adapters.binding_digest())
        .await
        .unwrap();
    h.drain(&h.worker()).await;
    let recovered = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(recovered.run.step, "await-terminal");
    assert_eq!(recovered.effects.len(), 1);
    assert_eq!(recovered.waits.len(), 1);
    let recovered_snapshot: Value = client
        .get(&snapshot_url)
        .bearer_auth(PYTHON_ACCEPTANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        recovered_snapshot, committed_snapshot,
        "retry-same preserved the original application key, request and receipt"
    );

    for state in ["running", "succeeded"] {
        client
            .post(format!("{}/test/transition", service.base_url))
            .bearer_auth(PYTHON_ACCEPTANCE_TOKEN)
            .json(&json!({"jobId":job_id,"state":state}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
    h.advance().await;
    h.drain(&h.worker()).await;
    let terminal = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(terminal.run.state, "finished");
    assert_eq!(terminal.run.outcome.as_deref(), Some("job-result"));
    assert_eq!(
        terminal.run.output,
        Some(json!({"state":"complete","result":{"jobId":job_id}}))
    );
}

#[tokio::test]
#[ignore = "requires separate disposable Coordinator and external-job databases plus an installed-wheel Python interpreter"]
async fn installed_python_encoding_failure_keeps_the_committed_job_recoverable() {
    let mut service = PythonService::start("encoding-error-after-commit");
    let mut h = Harness::new().await;
    h.bind_python(&service);

    let run = h.start().await;
    h.drain(&h.worker()).await;
    let held = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(held.run.state, "attention");
    assert!(held.run.uncertain);
    assert_eq!(
        serde_json::to_value(&held.effects[0]).unwrap()["state"],
        "unknown"
    );
    assert!(held.recovery.retry_allowed);
    assert_eq!(
        held.recovery.operation,
        Some(Operation::ExternalCommand.identity())
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let snapshot_url = format!("{}/test/snapshot", service.base_url);
    let first_snapshot: Value = client
        .get(&snapshot_url)
        .bearer_auth(PYTHON_ACCEPTANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first_snapshot["jobCount"], 1);

    h.store
        .retry_same(run, h.adapters.binding_digest())
        .await
        .unwrap();
    h.drain(&h.worker()).await;
    let recovered = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(recovered.run.step, "await-terminal");
    assert_eq!(recovered.effects.len(), 1);
    assert_eq!(recovered.waits.len(), 1);
    let recovered_snapshot: Value = client
        .get(&snapshot_url)
        .bearer_auth(PYTHON_ACCEPTANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(recovered_snapshot, first_snapshot);
    let stderr = service.stop_and_take_stderr();
    assert!(stderr.contains("UnicodeError: synthetic response encoding failure"));
}

#[tokio::test]
async fn command_rate_limit_retries_without_claiming_an_unknown_effect() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/jobs"))
        .and(header_exists("idempotency-key"))
        .and(body_json(json!({"reference":"case-001"})))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .expect(1)
        .mount(&h.server)
        .await;

    let run = h.start().await;
    h.drain(&h.worker()).await;
    let rate_limited = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(rate_limited.run.state, "running");
    assert!(!rate_limited.run.uncertain);
    assert!(rate_limited.effects.is_empty());
    assert!(!rate_limited.recovery.retry_allowed);
    assert_eq!(
        rate_limited.recovery.operation,
        Some(Operation::ExternalCommand.identity())
    );
    let first_requests = h.server.received_requests().await.unwrap();
    assert_eq!(first_requests.len(), 1);
    let first_key = first_requests[0].headers["idempotency-key"]
        .to_str()
        .unwrap()
        .to_owned();

    // Replace the 429 responder before the scheduled retry, so this attempt
    // must reach a distinct accepted response.
    h.admitted("running").await;
    h.advance().await;
    h.drain(&h.worker()).await;
    let accepted = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(accepted.run.step, "await-terminal");
    assert!(!accepted.run.uncertain);
    assert_eq!(accepted.effects.len(), 1);
    assert_eq!(
        serde_json::to_value(&accepted.effects[0]).unwrap()["state"],
        "accepted"
    );
    let retried_requests = h.server.received_requests().await.unwrap();
    let retried_post = retried_requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .unwrap();
    assert_eq!(
        retried_post.headers["idempotency-key"].to_str().unwrap(),
        first_key
    );
}

#[tokio::test]
async fn declared_admission_refusal_takes_the_authored_no_effect_route() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/jobs"))
        .and(header_exists("idempotency-key"))
        .and(body_json(json!({"reference":"case-001"})))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({"reason":"invalid-job"})))
        .expect(1)
        .mount(&h.server)
        .await;

    let run = h.start().await;
    h.drain(&h.worker()).await;
    let inspection = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(inspection.run.state, "finished");
    assert_eq!(
        inspection.run.outcome.as_deref(),
        Some("job-admission-refused")
    );
    assert_eq!(
        inspection.run.output,
        Some(json!({"refusalCode":"invalid-job"}))
    );
    assert!(
        inspection.effects.is_empty(),
        "a refusal claims no admitted job"
    );
    assert!(inspection.waits.is_empty());
}

#[tokio::test]
async fn unusable_post_commit_response_is_unknown_and_same_command_recovers() {
    let h = Harness::new().await;
    Mock::given(method("POST"))
        .and(path("/jobs"))
        .and(header_exists("idempotency-key"))
        .respond_with(ResponseTemplate::new(201).set_body_string("not-json-after-admission"))
        .expect(1)
        .mount(&h.server)
        .await;
    let run = h.start().await;
    h.drain(&h.worker()).await;
    let held = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(held.run.state, "attention");
    assert!(held.run.uncertain);
    assert_eq!(
        serde_json::to_value(&held.effects[0]).unwrap()["state"],
        "unknown"
    );
    assert!(held.recovery.retry_allowed);
    let first = h.server.received_requests().await.unwrap();
    let key = first[0].headers["idempotency-key"]
        .to_str()
        .unwrap()
        .to_owned();

    h.admitted("running").await;
    h.store
        .retry_same(run, h.adapters.binding_digest())
        .await
        .unwrap();
    h.drain(&h.worker()).await;
    let recovered = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(recovered.run.step, "await-terminal");
    assert_eq!(recovered.waits.len(), 1);
    let requests = h.server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|request| request.method.as_str() == "POST")
        .unwrap();
    assert_eq!(post.headers["idempotency-key"].to_str().unwrap(), key);
}

#[tokio::test]
async fn frozen_external_read_survives_restart_and_inspects_its_bounded_wait() {
    let h = Harness::new().await;
    let run = h.begin_wait().await;
    let before = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    let wait = &before.waits[0];
    assert_eq!(wait.accepted_step, "read");
    assert_eq!(wait.completion, "terminal");
    assert_eq!(wait.minimum_interval_seconds, 30);
    assert_eq!(wait.observation_limit, 21);
    assert_eq!(
        before.effects.len(),
        1,
        "only durable admission is an effect"
    );
    assert!(!serde_json::to_string(&before).unwrap().contains(JOB));

    h.state("succeeded").await;
    let restarted = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
    let worker = Worker::new(restarted.clone(), h.adapters.clone());
    // Restart and unmatched signals cannot accelerate the persisted read floor.
    for _ in 0..10 {
        restarted.wake("jobs", Uuid::new_v4()).await.unwrap();
    }
    assert!(!worker.tick().await.unwrap());
    assert!(h.server.received_requests().await.unwrap().is_empty());
    h.advance().await;
    h.drain(&worker).await;
    let after = restarted
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(after.run.state, "finished");
    assert_eq!(after.run.outcome.as_deref(), Some("job-result"));
    assert_eq!(
        after.run.output,
        Some(json!({"state":"complete","result":{"jobId":JOB}}))
    );
    assert!(after.waits.is_empty());
    let requests = h.server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.query_pairs().collect::<Vec<_>>(),
        [("id".into(), JOB.into())]
    );
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
    assert_eq!(
        status.output,
        Some(json!({"state":"refused","code":"external-job-failed"}))
    );
}

#[tokio::test]
async fn wrong_correlation_malformed_oversized_and_redirected_reads_cannot_advance() {
    for response in [
        ResponseTemplate::new(200)
            .set_body_json(json!({"jobId":"another-private-job","state":"succeeded"})),
        ResponseTemplate::new(200).set_body_string("malformed-private-canary"),
        ResponseTemplate::new(200)
            .set_body_json(json!({"jobId":JOB,"state":"surprising-private-canary"})),
        ResponseTemplate::new(200).set_body_string("x".repeat(2 * 1024 * 1024)),
        ResponseTemplate::new(302)
            .insert_header("location", "http://127.0.0.1:9/private-redirect-canary"),
    ] {
        let h = Harness::new().await;
        let run = h.begin_wait().await;
        h.reply(response).await;
        h.advance().await;
        h.drain(&h.worker()).await;
        let inspection = h
            .store
            .inspect(run, h.adapters.binding_digest())
            .await
            .unwrap();
        assert_eq!(inspection.run.state, "attention");
        assert_eq!(inspection.run.step, "await-terminal");
        assert!(
            !inspection.run.uncertain,
            "inability to read is not dispatch ambiguity"
        );
        assert!(inspection.run.output.is_none());
        assert_eq!(inspection.waits[0].observations, 2);
        assert!(
            inspection.recovery.retry_allowed,
            "read-only recovery keeps its original correlation"
        );
        let text = serde_json::to_string(&inspection).unwrap();
        for private in [
            JOB,
            "another-private-job",
            "malformed-private-canary",
            "surprising-private-canary",
            "private-redirect-canary",
        ] {
            assert!(!text.contains(private));
        }
        assert_eq!(h.server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn outage_honors_retry_after_and_observation_budget_survives_retry() {
    let h = Harness::new().await;
    let run = h.begin_wait().await;
    h.reply(ResponseTemplate::new(503).insert_header("retry-after", "120"))
        .await;
    h.advance().await;
    h.drain(&h.worker()).await;
    let inspection = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(inspection.run.state, "running");
    assert_eq!(inspection.waits[0].observations, 2);
    let spacing = inspection.waits[0].not_before - chrono::Utc::now();
    assert!(
        spacing.num_seconds() >= 115,
        "Retry-After is a durable floor"
    );
    h.sql("UPDATE {schema}.completion_waits SET observations=21")
        .await;
    h.advance().await;
    h.drain(&h.worker()).await;
    let exhausted = h
        .store
        .inspect(run, h.adapters.binding_digest())
        .await
        .unwrap();
    assert_eq!(exhausted.run.state, "attention");
    assert_eq!(
        exhausted.run.failure_code.as_deref(),
        Some("observation-budget-exhausted")
    );
    assert_eq!(h.server.received_requests().await.unwrap().len(), 1);
    h.store
        .retry_same(run, h.adapters.binding_digest())
        .await
        .unwrap();
    h.drain(&h.worker()).await;
    assert_eq!(
        h.store
            .inspect(run, h.adapters.binding_digest())
            .await
            .unwrap()
            .waits[0]
            .observations,
        21
    );
    assert_eq!(
        h.server.received_requests().await.unwrap().len(),
        1,
        "retry cannot reset a spent budget"
    );
}

#[tokio::test]
async fn timeout_cancellation_and_deadline_stop_polling_without_claiming_job_failure() {
    for stop in ["timeout", "cancel", "deadline"] {
        let h = Harness::new().await;
        let run = h.begin_wait().await;
        h.state("succeeded").await;
        match stop {
            "timeout" => h.sql("UPDATE {schema}.completion_waits SET timeout_at=clock_timestamp()-interval '1 second'; UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp() WHERE state='pending'").await,
            "deadline" => h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'").await,
            _ => { h.store.cancel_owned(run,&Actor { issuer:"https://issuer.example.invalid".into(),subject:"operator".into(),client_id:"operator-client".into(),operator:true },"synthetic-withdrawal").await.unwrap(); }
        }
        h.drain(&h.worker()).await;
        let status = h
            .store
            .inspect(run, h.adapters.binding_digest())
            .await
            .unwrap();
        assert!(status.waits.is_empty());
        match stop {
            "timeout" => {
                assert_eq!(status.run.state, "finished");
                assert_eq!(status.run.outcome.as_deref(), Some("job-wait-expired"));
            }
            "deadline" => assert_eq!(status.run.state, "expired"),
            _ => assert_eq!(status.run.state, "cancelled"),
        }
        assert!(
            h.server.received_requests().await.unwrap().is_empty(),
            "stopping a wait is not a final job read"
        );
    }
}
