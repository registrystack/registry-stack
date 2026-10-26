// SPDX-License-Identifier: Apache-2.0
//! The bounded external command over real HTTP and durable PostgreSQL: the
//! request id is frozen before the first send, every ambiguous exchange holds
//! the run, and same-command recovery sends that id again. No Registry Stack
//! service participates.
#![cfg(feature = "postgres-test")]

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use registry_coordinator::{
    definition::Definition,
    external_http::{ExternalHttpConfig, ExternalHttpConnection},
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation},
    store::Store,
    worker::Worker,
};
use registry_platform_httputil::client::StaticToken;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
use uuid::Uuid;
use wiremock::{
    matchers::{body_json, header, header_exists, method, path},
    Mock, MockServer, ResponseTemplate,
};

const APPLICATION: &str = "application-body-canary";
const TOKEN: &str = "synthetic-command-token-canary";
const BINDING: &str = "external-command-binding";

/// The runtime's command adapter, recording each frozen request id it is
/// asked to send. It can stall once after the command is persisted, the
/// way a process dies before its request leaves.
struct CommandAdapter {
    connection: ExternalHttpConnection,
    keys: Arc<Mutex<Vec<String>>>,
    stall: AtomicBool,
    entered: Notify,
}

#[async_trait]
impl AdapterSet for CommandAdapter {
    fn binding_digest(&self) -> &str {
        BINDING
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        self.call_attempt(request, None, false).await
    }

    async fn call_attempt(
        &self,
        request: &CallRequest,
        prepared: Option<&[u8]>,
        final_attempt: bool,
    ) -> CallOutcome {
        assert_eq!(request.operation, Operation::ExternalCommand);
        assert_eq!(request.connection, "payments");
        assert!(prepared.is_none(), "a command has no prepared evidence");
        let key = request
            .idempotency_key
            .clone()
            .expect("a command carries its frozen request id");
        self.keys.lock().unwrap().push(key.clone());
        if self.stall.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        self.connection
            .command(&request.input, &key, final_attempt)
            .await
    }
}

struct Harness {
    _project: tempfile::TempDir,
    definition: Definition,
    url: String,
    namespace: String,
    store: Arc<Store>,
    keys: Arc<Mutex<Vec<String>>>,
}

impl Harness {
    async fn new() -> Self {
        let project = tempfile::tempdir().unwrap();
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/external-command");
        for name in ["workflow.yaml", "functions.rhai"] {
            std::fs::copy(source.join(name), project.path().join(name)).unwrap();
        }
        let definition = Definition::load(project.path()).expect("the command fixture compiles");
        let url = std::env::var("COORDINATOR_TEST_DATABASE_URL")
            .expect("disposable PostgreSQL is required");
        let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
        let store = Arc::new(Store::connect(&url, &namespace).await.unwrap());
        store.migrate().await.unwrap();
        Self {
            _project: project,
            definition,
            url,
            namespace,
            store,
            keys: Arc::default(),
        }
    }

    /// The operator's connection: the destination, command path and
    /// credential come only from here.
    fn adapter(&self, base: &str, stall: bool) -> Arc<CommandAdapter> {
        let mut config: ExternalHttpConfig = serde_json::from_value(json!({
            "baseUrl":base, "paths":["bills/status"], "commandPath":"bills",
            "responseSchema":{"type":"object"},
            "authorization":{
                "tokenEndpoint":"http://127.0.0.1:9999/token", "clientId":"bill-issuer",
                "signingKeyRef":"secret:file/bill-issuer",
                "resource":"https://payments.example.test", "scopes":["bills.create"]
            }
        }))
        .unwrap();
        config.attempt_timeout_milliseconds = 1_500.try_into().unwrap();
        let tokens = Arc::new(StaticToken::new(TOKEN).unwrap());
        Arc::new(CommandAdapter {
            connection: ExternalHttpConnection::new(&config, Some(tokens)).unwrap(),
            keys: self.keys.clone(),
            stall: AtomicBool::new(stall),
            entered: Notify::new(),
        })
    }

    async fn start(&self) -> Uuid {
        self.store
            .admit(
                &self.definition,
                json!({"applicationId":APPLICATION,"amount":2500}),
                "external-command-producer",
                &Uuid::new_v4().to_string(),
                BINDING,
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
        panic!("bounded workflow did not quiesce");
    }

    /// Inspection and status as an operator reads them, with no command
    /// body, request id or credential anywhere in either.
    async fn read(&self, run: Uuid) -> Value {
        let inspection =
            serde_json::to_value(self.store.inspect(run, BINDING).await.unwrap()).unwrap();
        let status = serde_json::to_string(&self.store.status(run).await.unwrap()).unwrap();
        let keys = self.keys.lock().unwrap().clone();
        assert!(!keys.is_empty(), "the adapter saw the frozen request id");
        for text in [inspection.to_string(), status] {
            assert!(!text.contains(APPLICATION));
            assert!(!text.contains(TOKEN));
            for key in &keys {
                assert!(!text.contains(key.as_str()));
            }
        }
        inspection
    }

    fn keys(&self) -> Vec<String> {
        self.keys.lock().unwrap().clone()
    }
}

fn worker(store: &Arc<Store>, adapters: &Arc<CommandAdapter>) -> Worker {
    Worker::new(store.clone(), adapters.clone())
}

#[tokio::test]
async fn an_accepted_command_continues_the_run_with_its_typed_result() {
    let h = Harness::new().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bills"))
        .and(header_exists("idempotency-key"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(body_json(json!({"reference":APPLICATION,"amount":2500})))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"billId":"bill-001"})))
        .expect(1)
        .mount(&server)
        .await;
    let adapters = h.adapter(&server.uri(), false);
    let run = h.start().await;
    h.drain(&worker(&h.store, &adapters)).await;

    let inspection = h.read(run).await;
    assert_eq!(inspection["run"]["state"], "finished");
    assert_eq!(inspection["run"]["outcome"], "billed");
    assert_eq!(inspection["run"]["output"], json!({"billId":"bill-001"}));
    assert_eq!(inspection["effects"][0]["state"], "accepted");
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].headers["idempotency-key"].to_str().unwrap(),
        h.keys()[0],
        "the provider receives the frozen request id"
    );
}

#[tokio::test]
async fn a_declared_refusal_takes_the_workflow_refusal_route() {
    let h = Harness::new().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bills"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({"reason":"account-closed"})))
        .expect(1)
        .mount(&server)
        .await;
    let adapters = h.adapter(&server.uri(), false);
    let run = h.start().await;
    h.drain(&worker(&h.store, &adapters)).await;

    let inspection = h.read(run).await;
    assert_eq!(inspection["run"]["state"], "finished");
    assert_eq!(inspection["run"]["outcome"], "not-billed");
    assert_eq!(
        inspection["run"]["output"],
        json!({"refusalCode":"account-closed"})
    );
    assert_eq!(
        inspection["effects"],
        json!([]),
        "a refusal claims no effect"
    );
}

#[tokio::test]
async fn an_unrecognised_answer_holds_the_run_for_same_command_recovery() {
    let h = Harness::new().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bills"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({})))
        .mount(&server)
        .await;
    let adapters = h.adapter(&server.uri(), false);
    let run = h.start().await;
    h.drain(&worker(&h.store, &adapters)).await;

    let inspection = h.read(run).await;
    assert_eq!(inspection["run"]["state"], "attention");
    assert_eq!(inspection["run"]["uncertain"], true);
    assert_eq!(inspection["run"]["failureCode"], "external-uncertain");
    assert_eq!(inspection["effects"][0]["state"], "unknown");
    assert_eq!(inspection["recovery"]["retryAllowed"], true);
}

#[tokio::test]
async fn a_busy_503_the_deadline_ends_holds_the_effect_as_unknown() {
    // (status, run state, uncertain): a 429 is a definite "not processed",
    // while a 503 may follow an effect, so only the 503 holds.
    for (status, state, uncertain) in [(503, "attention", true), (429, "expired", false)] {
        let h = Harness::new().await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bills"))
            .respond_with(ResponseTemplate::new(status).insert_header("retry-after", "120"))
            .expect(1)
            .mount(&server)
            .await;
        let adapters = h.adapter(&server.uri(), false);
        let run = h.start().await;
        // The retry the provider asks for would land after the run deadline.
        h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()+interval '30 seconds'")
            .await;
        h.drain(&worker(&h.store, &adapters)).await;

        let inspection = h.read(run).await;
        assert_eq!(inspection["run"]["state"], state, "{status}");
        assert_eq!(inspection["run"]["uncertain"], uncertain, "{status}");
        let code = if status == 503 {
            "external-unavailable"
        } else {
            "external-rate-limited"
        };
        assert_eq!(inspection["run"]["failureCode"], code, "{status}");
        let effects: Vec<&Value> = inspection["effects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|effect| &effect["state"])
            .collect();
        let expected = if uncertain { vec!["unknown"] } else { vec![] };
        assert_eq!(effects, expected, "{status}");
        server.verify().await;
    }
}

#[tokio::test]
async fn a_deadline_that_passes_before_a_busy_503_is_retried_holds_the_effect() {
    let h = Harness::new().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bills"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let adapters = h.adapter(&server.uri(), false);
    let run = h.start().await;
    let worker = worker(&h.store, &adapters);
    h.drain(&worker).await;
    assert_eq!(h.read(run).await["run"]["state"], "running");

    // The deadline passes while the automatic retry is still pending.
    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'; UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp() WHERE state='pending'")
        .await;
    h.drain(&worker).await;
    let inspection = h.read(run).await;
    assert_eq!(inspection["run"]["state"], "attention");
    assert_eq!(inspection["run"]["uncertain"], true);
    assert_eq!(inspection["run"]["failureCode"], "deadline-reached");
    assert_eq!(inspection["effects"][0]["state"], "unknown");
    server.verify().await;
}

#[tokio::test]
async fn a_busy_503_then_an_accepted_command_clears_the_unknown_effect() {
    let h = Harness::new().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/bills"))
        .respond_with(ResponseTemplate::new(503).insert_header("retry-after", "60"))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/bills"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"billId":"bill-001"})))
        .expect(1)
        .mount(&server)
        .await;
    let adapters = h.adapter(&server.uri(), false);
    let run = h.start().await;
    let worker = worker(&h.store, &adapters);
    h.drain(&worker).await;

    // The automatic retry is scheduled, and until it settles the command
    // the effect of the first attempt is reported as unknown.
    let retrying = h.read(run).await;
    assert_eq!(retrying["run"]["state"], "running");
    assert_eq!(retrying["run"]["uncertain"], true);
    assert_eq!(retrying["run"]["failureCode"], "external-unavailable");
    assert_eq!(retrying["effects"][0]["state"], "unknown");

    h.sql("UPDATE {schema}.jobs SET next_attempt_at=clock_timestamp() WHERE state='pending'")
        .await;
    h.drain(&worker).await;
    let finished = h.read(run).await;
    assert_eq!(finished["run"]["state"], "finished");
    assert_eq!(finished["run"]["outcome"], "billed");
    assert_eq!(finished["run"]["uncertain"], false);
    assert_eq!(finished["run"]["output"], json!({"billId":"bill-001"}));
    assert_eq!(finished["effects"][0]["state"], "accepted");
    let keys = h.keys();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1], "the retry sends the same request id");
    server.verify().await;
}

/// Reads one complete request, returning its head and body.
async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let read = socket.read(&mut chunk).await.unwrap();
        assert!(read > 0, "the client sends a complete request");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        assert!(buffer.len() < 65_536, "request headers stay bounded");
    };
    let head = String::from_utf8(buffer[..head_end].to_vec()).unwrap();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .expect("the command declares its length");
    while buffer.len() < head_end + length {
        let read = socket.read(&mut chunk).await.unwrap();
        assert!(read > 0, "the client sends the complete body");
        buffer.extend_from_slice(&chunk[..read]);
    }
    (head, buffer[head_end..head_end + length].to_vec())
}

fn request_id(head: &str) -> String {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("idempotency-key")
                .then(|| value.trim().to_owned())
        })
        .expect("every command carries its request id")
}

/// A deduplicating provider. It answers `answered` of the attempts it sees
/// (the first is committed and its acknowledgement lost when `lose_first`),
/// and records the request id and body of each.
async fn provider(
    attempts: usize,
    lose_first: bool,
) -> (String, tokio::task::JoinHandle<Vec<(String, Vec<u8>)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut seen = Vec::new();
        for attempt in 0..attempts {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut socket).await;
            assert!(head.starts_with("POST /bills HTTP/1.1\r\n"));
            seen.push((request_id(&head), body));
            if lose_first && attempt == 0 {
                drop(socket);
                continue;
            }
            let reply = br#"{"billId":"bill-001"}"#;
            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(reply).await.unwrap();
            socket.shutdown().await.unwrap();
        }
        seen
    });
    (format!("http://{address}"), server)
}

async fn provided(
    server: tokio::task::JoinHandle<Vec<(String, Vec<u8>)>>,
) -> Vec<(String, Vec<u8>)> {
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("the provider saw every expected attempt")
        .unwrap()
}

#[tokio::test]
async fn a_lost_acknowledgement_holds_and_retry_same_sends_the_same_command() {
    let h = Harness::new().await;
    let (base, server) = provider(2, true).await;
    let adapters = h.adapter(&base, false);
    let run = h.start().await;
    let worker = worker(&h.store, &adapters);
    h.drain(&worker).await;

    let held = h.read(run).await;
    assert_eq!(held["run"]["state"], "attention");
    assert_eq!(held["run"]["step"], "create");
    assert_eq!(held["run"]["uncertain"], true);
    assert_eq!(held["run"]["failureCode"], "transport-uncertain");
    assert_eq!(held["recovery"]["retryAllowed"], true);

    h.store.retry_same(run, BINDING).await.unwrap();
    h.drain(&worker).await;
    let finished = h.read(run).await;
    assert_eq!(finished["run"]["state"], "finished");
    assert_eq!(finished["run"]["outcome"], "billed");
    assert_eq!(finished["run"]["output"], json!({"billId":"bill-001"}));

    let seen = provided(server).await;
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], seen[1], "one logical command: same id, same bytes");
    let keys = h.keys();
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter().all(|key| key == &seen[0].0),
        "no new id is minted"
    );
}

#[tokio::test]
async fn a_timeout_holds_as_uncertain_and_never_claims_a_provider_failure() {
    let h = Harness::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let silent = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let adapters = h.adapter(&format!("http://{address}"), false);
    let run = h.start().await;
    h.drain(&worker(&h.store, &adapters)).await;

    let inspection = h.read(run).await;
    assert_eq!(inspection["run"]["state"], "attention");
    assert_eq!(inspection["run"]["uncertain"], true);
    assert_eq!(inspection["run"]["failureCode"], "attempt-timeout");
    assert_eq!(inspection["effects"][0]["state"], "unknown");
    silent.abort();
}

#[tokio::test]
async fn a_restart_between_persist_and_send_sends_the_prepared_command_once() {
    let h = Harness::new().await;
    let (base, server) = provider(1, false).await;
    let run = h.start().await;

    // The first process persists the command, then dies before sending it.
    let stalled = h.adapter(&base, true);
    let first = Arc::new(worker(&h.store, &stalled));
    let sending = {
        let first = first.clone();
        tokio::spawn(async move { first.tick().await })
    };
    stalled.entered.notified().await;
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    h.sql("UPDATE {schema}.jobs SET attempt_started_at=clock_timestamp()-interval '60 seconds',lease_expires_at=clock_timestamp()-interval '1 second' WHERE state='leased'").await;

    // A restarted process cannot know whether the command left, so it holds.
    let restarted = Arc::new(Store::connect(&h.url, &h.namespace).await.unwrap());
    let adapters = h.adapter(&base, false);
    let second = worker(&restarted, &adapters);
    h.drain(&second).await;
    let held = h.read(run).await;
    assert_eq!(held["run"]["state"], "attention");
    assert_eq!(held["run"]["uncertain"], true);
    assert_eq!(held["recovery"]["retryAllowed"], true);

    restarted.retry_same(run, BINDING).await.unwrap();
    h.drain(&second).await;
    let finished = h.read(run).await;
    assert_eq!(finished["run"]["state"], "finished");
    assert_eq!(finished["run"]["outcome"], "billed");

    let seen = provided(server).await;
    assert_eq!(seen.len(), 1, "the provider sees the command once");
    let keys = h.keys();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1], "the restart keeps the original id");
    assert_eq!(seen[0].0, keys[0]);
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[0].1).unwrap(),
        json!({"reference":APPLICATION,"amount":2500})
    );
}
