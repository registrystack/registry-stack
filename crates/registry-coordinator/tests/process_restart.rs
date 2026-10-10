// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]
mod support;

use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, Response, StatusCode},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use support::{config, issuer, messaging::Messaging, record, RECORD, TRACE};

#[derive(Clone)]
struct Source {
    value: Arc<Mutex<Value>>,
    reads: Arc<Mutex<usize>>,
}

async fn read(State(source): State<Source>) -> Response<Body> {
    *source.reads.lock().unwrap() += 1;
    Response::builder().status(200).header("content-type", "application/json").header("traceparent", TRACE)
        .header("etag", "\"breg-record-000000000001\"")
        .header("link", "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/application>; rel=\"describedby\"")
        .body(Body::from(source.value.lock().unwrap().to_string())).unwrap()
}

type CapturedSubmission = (String, Vec<u8>);

#[derive(Clone)]
struct Proxy {
    destination: String,
    lose_first: Arc<AtomicBool>,
    committed: Arc<tokio::sync::Notify>,
    requests: Arc<Mutex<Vec<CapturedSubmission>>>,
    accepted_receipt: Arc<Mutex<Option<Value>>>,
}

async fn submit(State(proxy): State<Proxy>, request: Request<Body>) -> Response<Body> {
    let mut headers = request.headers().clone();
    headers.remove("host");
    let key = headers["idempotency-key"].to_str().unwrap().to_owned();
    let body = to_bytes(request.into_body(), 65_536)
        .await
        .unwrap()
        .to_vec();
    proxy.requests.lock().unwrap().push((key, body.clone()));
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/v1/messages", proxy.destination))
        .headers(headers)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.unwrap();
    if proxy.lose_first.swap(false, Ordering::SeqCst) {
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "real Messaging committed before the induced interruption"
        );
        *proxy.accepted_receipt.lock().unwrap() = Some(serde_json::from_slice(&bytes).unwrap());
        proxy.committed.notify_one();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        return Response::builder().status(503).body(Body::empty()).unwrap();
    }
    let mut response = Response::builder()
        .status(status)
        .body(Body::from(bytes))
        .unwrap();
    *response.headers_mut() = headers;
    response
}

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, task)
}

struct Process(Child);
impl Process {
    fn worker(config: &Path) -> Self {
        Self(
            Command::new(env!("CARGO_BIN_EXE_coordinator-test-worker"))
                .arg("--runtime-config")
                .arg(config)
                .arg("worker")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn terminate(&mut self) {
        self.0.kill().unwrap();
        let status = self.0.wait().unwrap();
        assert!(
            !status.success(),
            "the worker really exited under interruption"
        );
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(config: &Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_coordinator-test-worker"))
        .args(["--format", "json", "--runtime-config"])
        .arg(config)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "local CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

async fn status_until(config: &Path, run: &str, state: &str) -> Value {
    let stop = Instant::now() + Duration::from_secs(50);
    loop {
        let status = cli(config, &["status", "--run", run]);
        if status["state"] == state {
            return status;
        }
        assert!(Instant::now() < stop, "run did not reach {state}: {status}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exited_workers_preserve_timer_and_recover_original_real_messaging_command() {
    std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("disposable coordinator database is required");
    let issuer = issuer().await;
    let messaging = Messaging::start(&issuer).await;
    let source = Source {
        value: Arc::new(Mutex::new(record(true, "before-due@example.invalid"))),
        reads: Arc::new(Mutex::new(0)),
    };
    let (breg, source_task) = serve(
        Router::new()
            .route(&format!("/v1/records/applications/{RECORD}"), get(read))
            .with_state(source.clone()),
    )
    .await;
    let proxy = Proxy {
        destination: messaging.base_url.clone(),
        lose_first: Arc::new(AtomicBool::new(true)),
        committed: Arc::new(tokio::sync::Notify::new()),
        requests: Arc::new(Mutex::new(Vec::new())),
        accepted_receipt: Arc::new(Mutex::new(None)),
    };
    let (notices, proxy_task) = serve(
        Router::new()
            .route("/v1/messages", post(submit))
            .with_state(proxy.clone()),
    )
    .await;
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let runtime = root.path().join("runtime.yaml");
    let config = config(root.path(), &issuer, &breg, &notices);
    support::write_runtime(&runtime, &config);
    let input = root.path().join("input.json");
    let due = (chrono::Utc::now() + chrono::Duration::seconds(3)).to_rfc3339();
    std::fs::write(
        &input,
        json!({"applicationId":RECORD, "sendAfter":due}).to_string(),
    )
    .unwrap();
    let key = root.path().join("start-key");
    std::fs::write(&key, "durable-start-key").unwrap();
    cli(&runtime, &["init-db"]);
    let project = root.path().join("workflow");
    let initialized = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", "init", "--directory"])
        .arg(&project)
        .output()
        .unwrap();
    assert!(
        initialized.status.success(),
        "the operator scaffold must initialize"
    );
    assert!(project.join("workflow.yaml").is_file());
    assert!(project.join("functions.rhai").is_file());
    assert!(project.join("runtime.yaml").is_file());
    let run = cli(
        &runtime,
        &[
            "start",
            "--project",
            project.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--producer",
            "case-service",
            "--key-file",
            key.to_str().unwrap(),
        ],
    )["runId"]
        .as_str()
        .unwrap()
        .to_owned();
    let initial = cli(&runtime, &["status", "--run", &run]);
    let mut before_due = Process::worker(&runtime);
    tokio::time::sleep(Duration::from_millis(300)).await;
    before_due.terminate();
    assert_eq!(*source.reads.lock().unwrap(), 0);
    let after_restart = cli(&runtime, &["status", "--run", &run]);
    assert_eq!(
        initial["nextDueAt"], after_restart["nextDueAt"],
        "restart cannot shift the admitted timer"
    );
    *source.value.lock().unwrap() = record(true, "current-at-due@example.invalid");
    let mut sending = Process::worker(&runtime);
    tokio::time::timeout(Duration::from_secs(15), proxy.committed.notified())
        .await
        .expect("real Messaging accepted the first submission");
    sending.terminate();
    assert_eq!(messaging.count().await, 1);
    *source.value.lock().unwrap() = record(true, "changed-after-uncertain@example.invalid");
    let mut restarted = Process::worker(&runtime);
    let held = status_until(&runtime, &run, "attention").await;
    assert_eq!(held["uncertain"], true);
    cli(&runtime, &["retry-same", "--run", &run]);
    let complete = status_until(&runtime, &run, "finished").await;
    assert_eq!(complete["outcome"], "message-accepted");
    assert!(complete["output"]["messageId"].as_str().is_some());
    assert_eq!(
        complete["output"]["messageId"],
        proxy.accepted_receipt.lock().unwrap().as_ref().unwrap()["id"],
        "terminal output names the original remotely committed receipt"
    );
    restarted.terminate();
    {
        let requests = proxy.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0], requests[1],
            "same body and key across actual process exits"
        );
        let original: Value = serde_json::from_slice(&requests[0].1).unwrap();
        assert_eq!(original["to"]["email"], "current-at-due@example.invalid");
    }
    assert_eq!(
        *source.reads.lock().unwrap(),
        1,
        "pending command recovery never rereads contact"
    );
    assert_eq!(messaging.count().await, 1);
    let rendered = complete.to_string();
    assert!(!rendered.contains("example.invalid"));
    source_task.abort();
    proxy_task.abort();
    messaging.stop().await;
    issuer.stop().await;
}
