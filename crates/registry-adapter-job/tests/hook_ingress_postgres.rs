// SPDX-License-Identifier: Apache-2.0

//! Real job-host proofs for the separate hook ingress. Hook-attribution cases
//! hold reconciliation sixty seconds away; the lost-hook case deliberately
//! uses a 250 millisecond interval to prove reconciliation.
#![cfg(all(feature = "job-hook", feature = "postgres-test"))]

use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use tokio_postgres::{Config as PgConfig, NoTls};

#[path = "support/fixture_receiver.rs"]
mod fixture_receiver;
#[path = "support/job_fixture.rs"]
mod job_fixture;

use fixture_receiver::{FixtureReceiver, Scripted};
use job_fixture::{reply_page_end, Edits, JobFixture, PAGE_SCRIPT};

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);
const HOOK_BODY_MARKER: &str = "hook-body-must-never-cross-the-trigger-boundary";

struct HoldingReceiver {
    url: String,
    requests: Arc<AtomicUsize>,
    arrived: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

impl HoldingReceiver {
    async fn start() -> Self {
        #[derive(Clone)]
        struct State {
            requests: Arc<AtomicUsize>,
            arrived: Arc<tokio::sync::Semaphore>,
            release: Arc<tokio::sync::Semaphore>,
        }

        async fn deliver(
            axum::extract::State(state): axum::extract::State<State>,
        ) -> axum::response::Json<Value> {
            state.requests.fetch_add(1, Ordering::SeqCst);
            state.arrived.add_permits(1);
            state
                .release
                .acquire()
                .await
                .expect("the release semaphore stays open")
                .forget();
            axum::response::Json(json!({
                "outcome": "acknowledged",
                "runId": "duplicate-running"
            }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the holding fixture binds");
        let address = listener.local_addr().expect("the holding fixture address");
        let requests = Arc::new(AtomicUsize::new(0));
        let arrived = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let state = State {
            requests: Arc::clone(&requests),
            arrived: Arc::clone(&arrived),
            release: Arc::clone(&release),
        };
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new()
                    .route("/deliver", axum::routing::post(deliver))
                    .with_state(state),
            )
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("the holding fixture serves");
        });
        Self {
            url: format!("http://{address}/deliver"),
            requests,
            arrived,
            release,
            _shutdown: shutdown,
        }
    }

    async fn wait_for_request(&self) {
        tokio::time::timeout(Duration::from_secs(20), self.arrived.acquire())
            .await
            .expect("the running pass reaches its held destination")
            .expect("the arrival semaphore stays open")
            .forget();
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn release(&self) {
        self.release.add_permits(1);
    }
}

struct ManagedChild {
    child: Option<Child>,
    hook_address: mpsc::Receiver<SocketAddr>,
    stderr_reader: Option<std::thread::JoinHandle<Vec<u8>>>,
}

impl ManagedChild {
    fn spawn(database_url: &str, fixture: &JobFixture, fixture_url: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_adapter-job"))
            .env("JOB_TEST_DB", database_url)
            .args([
                "pass",
                fixture.job.to_str().expect("a UTF-8 job path"),
                "--pack",
                fixture.pack.to_str().expect("a UTF-8 pack path"),
                "--runtime",
                fixture.runtime.to_str().expect("a UTF-8 runtime path"),
                "--fixture",
                "--fixture-url",
                fixture_url,
                "--loop",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the real adapter-job host");
        let stderr = child.stderr.take().expect("capture adapter-job stderr");
        let (address_tx, hook_address) = mpsc::sync_channel(1);
        let stderr_reader = std::thread::spawn(move || {
            use std::io::BufRead as _;

            let mut captured = Vec::new();
            for line in std::io::BufReader::new(stderr).lines() {
                let line = line.expect("read adapter-job stderr");
                if let Some(value) = line.strip_prefix("adapter.job.hook-listening address=") {
                    let address = value.parse().expect("the hook startup address is a socket");
                    let _ = address_tx.send(address);
                }
                captured.extend_from_slice(line.as_bytes());
                captured.push(b'\n');
            }
            captured
        });
        Self {
            child: Some(child),
            hook_address,
            stderr_reader: Some(stderr_reader),
        }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .expect("the child is present")
            .try_wait()
            .expect("poll the adapter-job child")
    }

    fn interrupt(&mut self) {
        let pid = self
            .child
            .as_ref()
            .expect("the child is present")
            .id()
            .to_string();
        let output = Command::new("kill")
            .args(["-INT", pid.as_str()])
            .output()
            .expect("send SIGINT to adapter-job");
        assert!(
            output.status.success(),
            "SIGINT failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn wait_for_exit(&mut self, deadline: Duration) {
        tokio::time::timeout(deadline, async {
            loop {
                if self.try_wait().is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("adapter-job exits within the host shutdown bound");
    }

    fn output(&mut self) -> Output {
        let mut output = self
            .child
            .take()
            .expect("the child is present")
            .wait_with_output()
            .expect("collect adapter-job output");
        output.stderr = self
            .stderr_reader
            .take()
            .expect("the stderr reader is present")
            .join()
            .expect("join the stderr reader");
        output
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = child.kill() {
                    eprintln!("failed to kill adapter-job hook test child: {error}");
                }
            }
            Err(error) => eprintln!("failed to poll adapter-job hook test child: {error}"),
        }
        if let Err(error) = child.wait() {
            eprintln!("failed to wait for adapter-job hook test child: {error}");
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

async fn connect(url: &str) -> tokio_postgres::Client {
    let mut config = PgConfig::from_str(url).expect("parse the PostgreSQL test URL");
    config.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let (client, connection) = config.connect(NoTls).await.expect("connect to PostgreSQL");
    tokio::spawn(async move {
        connection.await.expect("the test PostgreSQL connection");
    });
    client
}

async fn isolated_database_url() -> String {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let serial = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the test clock follows the Unix epoch")
        .as_nanos();
    let schema = format!("adapter_hook_{nanos}_{serial}");
    let admin = connect(&base).await;
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated hook-test schema");
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

fn configure_hook(fixture: &JobFixture, initial_delay_milliseconds: u64, burst: u64) {
    let authored = std::fs::read_to_string(&fixture.job).expect("read the fixture job");
    let with_hook = authored.replace(
        "    delayMilliseconds: 60000",
        &format!("    delayMilliseconds: 60000\n    initialDelayMilliseconds: {initial_delay_milliseconds}\n  - kind: hook\n    path: /hooks/kobo\n    binding: kobo"),
    );
    assert_ne!(with_hook, authored, "the fixture gains a hook trigger");
    std::fs::write(&fixture.job, with_hook).expect("write the hook job");

    let secret_root = fixture
        .runtime
        .parent()
        .expect("the fixture runtime has a directory")
        .join("hook-secrets");
    std::fs::create_dir(&secret_root).expect("create the hook secret root");
    std::fs::set_permissions(&secret_root, std::fs::Permissions::from_mode(0o700))
        .expect("confine the hook secret root");
    for (name, value) in [
        ("username", "kobo"),
        ("password", "synthetic-hook-password"),
    ] {
        let path = secret_root.join(name);
        std::fs::write(&path, value).expect("write a synthetic hook credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("confine the hook credential");
    }

    let mut runtime: Value =
        serde_json::from_slice(&std::fs::read(&fixture.runtime).expect("read the fixture runtime"))
            .expect("the fixture runtime is JSON");
    runtime["secretProviders"] = json!({
        "environment": {},
        "file": {"root": secret_root}
    });
    runtime["hookIngress"] = json!({
        "listener": {
            "bind": "127.0.0.1:0",
            "tlsTermination": "development-loopback"
        },
        "sources": {
            "kobo": {
                "usernameRef": "secret:file/username",
                "passwordRef": "secret:file/password",
                "requestsPerMinute": 60,
                "burst": burst
            }
        }
    });
    std::fs::write(
        &fixture.runtime,
        serde_json::to_vec_pretty(&runtime).expect("render the hook runtime"),
    )
    .expect("write the hook runtime");
}

async fn wait_for_listener(child: &mut ManagedChild) -> SocketAddr {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(status) = child.try_wait() {
                panic!("adapter-job exited before hook ingress bound: {status}");
            }
            if let Ok(address) = child.hook_address.try_recv() {
                assert!(address.ip().is_loopback());
                assert_ne!(address.port(), 0);
                assert!(TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok());
                return address;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the real hook listener reports its bound port within 20 seconds")
}

async fn wait_for_pass(database_url: &str, receiver: &FixtureReceiver) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if receiver.requests().len() == 1 {
                let client = connect(database_url).await;
                if client
                    .query_opt(
                        "SELECT last_pass_at FROM adapter_job_state WHERE job_id = $1",
                        &[&"case-daily"],
                    )
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|row| row.get::<_, Option<SystemTime>>(0).is_some())
                {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the hook-started pass persists within 20 seconds");
}

#[tokio::test]
async fn actual_cli_hook_starts_one_postgres_backed_pass_without_using_its_body() {
    let fixture =
        JobFixture::start(PAGE_SCRIPT, vec![(200, reply_page_end())], Edits::Ordered).await;
    configure_hook(&fixture, 60_000, 1);
    let database_url = isolated_database_url().await;
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge {
        run_id: Some("hook-run".to_string()),
    }])
    .await;
    let mut child = ManagedChild::spawn(&database_url, &fixture, &receiver.url);
    let address = wait_for_listener(&mut child).await;

    let forged = reqwest::Client::new()
        .post(format!("http://{address}/hooks/kobo"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode("kobo:forged-password")),
        )
        .send()
        .await
        .expect("send the forged hook");
    assert_eq!(forged.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(fixture.double.requests().is_empty());

    let authorization = format!("Basic {}", STANDARD.encode("kobo:synthetic-hook-password"));
    let response = reqwest::Client::new()
        .post(format!("http://{address}/hooks/kobo"))
        .header(reqwest::header::AUTHORIZATION, authorization)
        .body(HOOK_BODY_MARKER)
        .send()
        .await
        .expect("send the real authenticated hook");
    assert_eq!(response.status(), reqwest::StatusCode::ACCEPTED);
    assert_eq!(
        response.text().await.expect("the static hook response"),
        r#"{"status":"started"}"#
    );

    wait_for_pass(&database_url, &receiver).await;
    let deliveries = receiver.requests();
    assert_eq!(deliveries.len(), 1);
    assert!(!deliveries[0].body_text().contains(HOOK_BODY_MARKER));
    assert_eq!(fixture.double.requests().len(), 1);

    child.interrupt();
    let output = tokio::task::spawn_blocking(move || child.output())
        .await
        .expect("join output collection");
    assert!(
        output.status.success(),
        "adapter-job did not stop cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(HOOK_BODY_MARKER));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("adapter.job.hook-listening address=")
            .count(),
        1
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("hook-listening"));
}

#[tokio::test]
async fn partial_request_head_is_force_closed_on_real_cli_shutdown() {
    let fixture =
        JobFixture::start(PAGE_SCRIPT, vec![(200, reply_page_end())], Edits::Ordered).await;
    configure_hook(&fixture, 60_000, 1);
    let database_url = isolated_database_url().await;
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge {
        run_id: Some("unused-shutdown-run".to_string()),
    }])
    .await;
    let mut child = ManagedChild::spawn(&database_url, &fixture, &receiver.url);
    let address = wait_for_listener(&mut child).await;

    let mut partial = TcpStream::connect(address).expect("connect a partial-header client");
    partial
        .write_all(b"POST /hooks/kobo HTTP/1.1\r\nHost: loopback\r\nX-Stalled: ")
        .expect("write an intentionally incomplete request head");
    let barrier = reqwest::get(format!("http://{address}/accepted-after-partial"))
        .await
        .expect("the real accept loop continues past the partial connection");
    assert_eq!(barrier.status(), reqwest::StatusCode::NOT_FOUND);
    barrier
        .bytes()
        .await
        .expect("the accept-loop barrier response drains");

    child.interrupt();
    child.wait_for_exit(Duration::from_secs(15)).await;
    drop(partial);
    let output = tokio::task::spawn_blocking(move || child.output())
        .await
        .expect("join output collection");
    assert!(
        !output.status.success(),
        "the forced ingress shutdown reports its closed fault"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches("adapter.job.hook-shutdown-timeout").count(),
        1
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("hook-shutdown-timeout"));
}

#[tokio::test]
async fn duplicate_hook_joins_the_one_running_cli_pass() {
    let fixture =
        JobFixture::start(PAGE_SCRIPT, vec![(200, reply_page_end())], Edits::Ordered).await;
    configure_hook(&fixture, 60_000, 2);
    let database_url = isolated_database_url().await;
    let receiver = HoldingReceiver::start().await;
    let mut child = ManagedChild::spawn(&database_url, &fixture, &receiver.url);
    let address = wait_for_listener(&mut child).await;
    let authorization = format!("Basic {}", STANDARD.encode("kobo:synthetic-hook-password"));

    let started = reqwest::Client::new()
        .post(format!("http://{address}/hooks/kobo"))
        .header(reqwest::header::AUTHORIZATION, &authorization)
        .send()
        .await
        .expect("start the real hook pass");
    assert_eq!(started.status(), reqwest::StatusCode::ACCEPTED);
    assert_eq!(started.text().await.unwrap(), r#"{"status":"started"}"#);
    receiver.wait_for_request().await;
    assert!(
        child.try_wait().is_none(),
        "the pass remains observably running"
    );

    let joined = reqwest::Client::new()
        .post(format!("http://{address}/hooks/kobo"))
        .header(reqwest::header::AUTHORIZATION, authorization)
        .send()
        .await
        .expect("join the running real hook pass");
    assert_eq!(joined.status(), reqwest::StatusCode::ACCEPTED);
    assert_eq!(joined.text().await.unwrap(), r#"{"status":"joined"}"#);
    assert_eq!(fixture.double.requests().len(), 1);
    assert_eq!(receiver.request_count(), 1);

    receiver.release();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let client = connect(&database_url).await;
            if client
                .query_opt(
                    "SELECT last_pass_at FROM adapter_job_state WHERE job_id = $1",
                    &[&"case-daily"],
                )
                .await
                .ok()
                .flatten()
                .is_some_and(|row| row.get::<_, Option<SystemTime>>(0).is_some())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the released pass persists");
    child.interrupt();
    let output = tokio::task::spawn_blocking(move || child.output())
        .await
        .expect("join output collection");
    assert!(
        output.status.success(),
        "adapter-job did not stop cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn lost_hook_is_reconciled_by_the_real_cli_interval() {
    let fixture =
        JobFixture::start(PAGE_SCRIPT, vec![(200, reply_page_end())], Edits::Ordered).await;
    configure_hook(&fixture, 250, 1);
    let database_url = isolated_database_url().await;
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge {
        run_id: Some("interval-run".to_string()),
    }])
    .await;
    let mut child = ManagedChild::spawn(&database_url, &fixture, &receiver.url);
    let _address = wait_for_listener(&mut child).await;

    wait_for_pass(&database_url, &receiver).await;
    assert_eq!(fixture.double.requests().len(), 1);
    assert_eq!(receiver.requests().len(), 1);

    child.interrupt();
    let output = tokio::task::spawn_blocking(move || child.output())
        .await
        .expect("join output collection");
    assert!(
        output.status.success(),
        "adapter-job did not stop cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
