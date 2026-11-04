// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "postgres-test", feature = "native-test-support"))]

//! The direct BReg destination through the actual job pass and store,
//! against a real BReg runtime and PostgreSQL. The maintained native
//! runner supplies the product binaries and disposable database.

#[path = "support/job_fixture.rs"]
mod job_fixture;
#[cfg(feature = "job-postgres")]
#[path = "support/postgres_native_source.rs"]
mod postgres_native_source;

use std::future::Future;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::str::FromStr as _;
#[cfg(feature = "job-postgres")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter_connectors::breg::{BregConnector, BregConnectorConfig};
use registry_adapter_connectors::operation::{CommandKey, Observable, Operation, OutcomeCategory};
use registry_adapter_engine::job::compile_job;
use registry_adapter_job::destination::{DeliverableItem, HandOffOutcome, JobDestination};
use registry_adapter_job::direct_breg::DirectBregMappingRefused;
use registry_adapter_job::direct_breg::{DirectBregDestination, DirectBregOperation};
use registry_adapter_job::pass::{run_pass, PassOptions, StopReason};
#[cfg(feature = "job-postgres")]
use registry_adapter_job::postgres_source::activate_postgres_sources;
use registry_adapter_job::store::{self, ItemStatus};
use registry_platform_testing::TestAuthorizationServer;
use serde_json::json;
use tokio_postgres::{Config as PgConfig, NoTls};

const SUBJECT: &str = "adapter-job-native";

struct IsolatedStore {
    pool: Pool,
    url: String,
}

async fn isolated_store_binding() -> IsolatedStore {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let schema = format!("adapter_job_native_{}", uuid::Uuid::new_v4().simple());
    let (admin, connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect the adapter job test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("the adapter job test connection failed: {error}");
        }
    });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated adapter job schema");
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let mut scoped = PgConfig::from_str(&url).expect("parse the scoped adapter job URL");
    scoped.ssl_mode(tokio_postgres::config::SslMode::Disable);
    let manager = Manager::from_config(
        scoped,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        },
    );
    let pool = Pool::builder(manager)
        .max_size(2)
        .build()
        .expect("build the scoped adapter job pool");
    IsolatedStore { pool, url }
}

async fn isolated_store() -> Pool {
    let isolated = isolated_store_binding().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    store::migrate(&client)
        .await
        .expect("the job store migration applies");
    drop(client);
    isolated.pool
}

async fn proposal_connector(
    service: &registry_adapter_connectors::test_support::Breg,
    issuer: &TestAuthorizationServer,
) -> Arc<BregConnector> {
    Arc::new(
        BregConnector::connect(BregConnectorConfig::new(
            service.origin(),
            registry_adapter_connectors::test_support::token_provider(issuer, SUBJECT),
            "writer",
            "manual-item",
            "item",
            "items",
        ))
        .await
        .expect("the proposal connector resolves"),
    )
}

fn create_target(connector: &Arc<BregConnector>) -> String {
    let prepared = connector
        .record_create()
        .prepare(
            &json!({"data": {"owner": SUBJECT, "label": "Before"}}),
            CommandKey::new("adapter-job-native/target".to_string()).expect("a command key"),
        )
        .expect("the target prepares");
    let outcome = connector
        .record_create()
        .send(&prepared)
        .expect("the target sends");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    outcome.correlation.expect("the target identifier")
}

#[derive(Clone)]
struct LostSubmitState {
    destination: String,
    start_target: Arc<Mutex<Option<String>>>,
    started: Arc<Mutex<Vec<String>>>,
    start_command_keys: Arc<Mutex<Vec<String>>>,
    submit_command_keys: Arc<Mutex<Vec<String>>>,
    submitted: Arc<Mutex<Option<String>>>,
    drop_submit_answers: Arc<AtomicBool>,
    hold_submit_answer: bool,
    submit_accepted: Arc<tokio::sync::Notify>,
    release_submit_answer: Arc<tokio::sync::Notify>,
}

struct LostSubmitProxy {
    origin: String,
    state: LostSubmitState,
}

impl LostSubmitProxy {
    async fn start(destination: String) -> Self {
        Self::start_with_answer_mode(destination, false).await
    }

    async fn start_holding_submit_answer(destination: String) -> Self {
        Self::start_with_answer_mode(destination, true).await
    }

    async fn start_with_answer_mode(destination: String, hold_submit_answer: bool) -> Self {
        let state = LostSubmitState {
            destination,
            start_target: Arc::new(Mutex::new(None)),
            started: Arc::new(Mutex::new(Vec::new())),
            start_command_keys: Arc::new(Mutex::new(Vec::new())),
            submit_command_keys: Arc::new(Mutex::new(Vec::new())),
            submitted: Arc::new(Mutex::new(None)),
            drop_submit_answers: Arc::new(AtomicBool::new(true)),
            hold_submit_answer,
            submit_accepted: Arc::new(tokio::sync::Notify::new()),
            release_submit_answer: Arc::new(tokio::sync::Notify::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the BReg lost-answer proxy");
        let address = listener.local_addr().expect("the proxy address");
        let app = Router::new()
            .fallback(any(forward_breg))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve the BReg lost-answer proxy");
        });
        Self {
            origin: format!("http://{address}"),
            state,
        }
    }

    fn started_proposals(&self) -> Vec<String> {
        self.state
            .started
            .lock()
            .expect("the started Proposal lock")
            .clone()
    }

    fn proposal_id(&self) -> String {
        self.state
            .submitted
            .lock()
            .expect("the submitted Proposal lock")
            .clone()
            .expect("the proxy discarded one submitted Proposal answer")
    }

    fn start_command_keys(&self) -> Vec<String> {
        self.state
            .start_command_keys
            .lock()
            .expect("the Proposal start command-key lock")
            .clone()
    }

    fn submit_command_keys(&self) -> Vec<String> {
        self.state
            .submit_command_keys
            .lock()
            .expect("the Proposal submit command-key lock")
            .clone()
    }

    async fn wait_for_accepted_submit(&self) -> bool {
        tokio::time::timeout(
            Duration::from_secs(30),
            self.state.submit_accepted.notified(),
        )
        .await
        .is_ok()
    }

    fn allow_answers(&self) {
        self.state
            .drop_submit_answers
            .store(false, Ordering::SeqCst);
        self.state.release_submit_answer.notify_one();
    }
}

async fn forward_breg(
    State(proxy): State<LostSubmitState>,
    request: Request<Body>,
) -> Response<Body> {
    let (mut parts, body) = request.into_parts();
    parts.headers.remove(header::HOST);
    let command_key = parts
        .headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(body, 2 * 1024 * 1024)
        .await
        .expect("read the bounded BReg request");
    let target = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let answer = reqwest::Client::new()
        .request(
            parts.method.clone(),
            format!("{}{target}", proxy.destination),
        )
        .headers(parts.headers)
        .body(body)
        .send()
        .await
        .expect("forward to native BReg");
    let status = answer.status();
    let headers = answer.headers().clone();
    let body = answer
        .bytes()
        .await
        .expect("read the bounded native BReg answer");
    let document = serde_json::from_slice::<serde_json::Value>(&body).ok();
    let proposal = document
        .as_ref()
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str);
    if parts.method == axum::http::Method::POST && status.is_success() {
        let is_start = {
            let mut start_target = proxy
                .start_target
                .lock()
                .expect("the Proposal start target lock");
            match start_target.as_deref() {
                None => {
                    *start_target = Some(target.to_string());
                    true
                }
                Some(start_target) => start_target == target,
            }
        };
        if is_start {
            let id = proposal.expect("an accepted Proposal start answers its id");
            proxy
                .started
                .lock()
                .expect("the started Proposal lock")
                .push(id.to_string());
            proxy
                .start_command_keys
                .lock()
                .expect("the Proposal start command-key lock")
                .push(command_key.expect("an accepted Proposal start carries a command key"));
        } else {
            let id = proposal.expect("an accepted Proposal transition answers its id");
            proxy
                .submit_command_keys
                .lock()
                .expect("the Proposal submit command-key lock")
                .push(command_key.expect("an accepted Proposal submit carries a command key"));
            {
                let mut first = proxy.submitted.lock().expect("the submitted Proposal lock");
                if first.is_none() {
                    *first = Some(id.to_string());
                }
            }
            if proxy.drop_submit_answers.load(Ordering::SeqCst) {
                if proxy.hold_submit_answer {
                    proxy.submit_accepted.notify_one();
                    proxy.release_submit_answer.notified().await;
                } else {
                    return Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::empty())
                        .expect("the lost-answer response builds");
                }
            }
        }
    }
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        if let Some(name) = name {
            if name != header::CONTENT_LENGTH
                && name != header::TRANSFER_ENCODING
                && name != header::CONNECTION
            {
                response = response.header(name, value);
            }
        }
    }
    response
        .body(Body::from(body))
        .expect("the forwarded BReg response builds")
}

fn cli_pass_command(
    fixture: &job_fixture::JobFixture,
    store_url: &str,
    private_key: &str,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_adapter-job"));
    command
        .arg("pass")
        .arg(&fixture.job)
        .arg("--pack")
        .arg(&fixture.pack)
        .arg("--runtime")
        .arg(&fixture.runtime)
        .env("JOB_TEST_DB", store_url)
        .env("BREG_CLIENT_KEY", private_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

async fn run_cli_pass_with_key(
    fixture: &job_fixture::JobFixture,
    store_url: &str,
    private_key: &str,
) -> std::process::Output {
    let mut command = cli_pass_command(fixture, store_url, private_key);
    tokio::task::spawn_blocking(move || {
        command
            .output()
            .expect("run the configured adapter-job pass")
    })
    .await
    .expect("the configured adapter-job pass joins")
}

async fn run_cli_pass(fixture: &job_fixture::JobFixture, store_url: &str) -> std::process::Output {
    run_cli_pass_with_key(
        fixture,
        store_url,
        registry_platform_testing::fixtures::ED25519_PRIVATE_JWK,
    )
    .await
}

struct AdapterJobProcess(Option<Child>);

impl AdapterJobProcess {
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("the adapter-job child is owned")
    }

    fn take(&mut self) -> Child {
        self.0.take().expect("the adapter-job child is owned")
    }
}

impl Drop for AdapterJobProcess {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_cli_pass(
    fixture: &job_fixture::JobFixture,
    store_url: &str,
    private_key: &str,
) -> AdapterJobProcess {
    AdapterJobProcess(Some(
        cli_pass_command(fixture, store_url, private_key)
            .spawn()
            .expect("spawn the configured adapter-job pass"),
    ))
}

async fn wait_for_lease_expiry(pool: &Pool) {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let client = pool.get().await.expect("a pooled store client");
            let expired: bool = client
                .query_one(
                    "SELECT lease_expires IS NOT NULL AND lease_expires <= clock_timestamp() \
                     FROM adapter_job_state WHERE job_id = $1",
                    &[&"case-daily"],
                )
                .await
                .expect("the crashed lease expiry reads")
                .get(0);
            if expired {
                break;
            }
            drop(client);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the crashed pass lease expires inside its declared bound");
}

fn shorten_crash_fixture_lease(fixture: &job_fixture::JobFixture) {
    let job = std::fs::read_to_string(&fixture.job).expect("read the native crash fixture job");
    let shortened = job.replace(
        "\"pageDeadlineMilliseconds\": 60000",
        "\"pageDeadlineMilliseconds\": 10000",
    );
    assert_ne!(
        shortened, job,
        "the native fixture carries the expected page deadline"
    );
    std::fs::write(&fixture.job, shortened).expect("shorten the native crash fixture lease");
}

fn assert_cli_output_redacted(output: &std::process::Output, stage: &str) {
    let mut rendered = String::from_utf8_lossy(&output.stdout).into_owned();
    rendered.push_str(&String::from_utf8_lossy(&output.stderr));
    for forbidden in [
        "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw",
        "f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys",
        "045",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "the {stage} output stays credential- and value-free"
        );
    }
}

/// Deliberately discard the first accepted answer after BReg has taken
/// the effect. The store therefore remains pending, exactly the crash
/// window the next pass must recover without persisted attempt bytes.
struct LoseFirstAnswer {
    inner: Arc<dyn JobDestination>,
    accepted_reference: Mutex<Option<String>>,
}

impl JobDestination for LoseFirstAnswer {
    fn deliver<'a>(
        &'a self,
        job: &'a registry_adapter_core::JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        Box::pin(async move {
            let outcome = self.inner.deliver(job, item).await;
            let mut first = self
                .accepted_reference
                .lock()
                .expect("the accepted-reference lock");
            if first.is_none() {
                let HandOffOutcome::Acknowledged {
                    run_id: Some(run_id),
                } = outcome
                else {
                    panic!("the first native hand-off must submit one Proposal: {outcome:?}");
                };
                *first = Some(run_id);
                HandOffOutcome::StopPass {
                    code: "adapter.test.lost-destination-answer".to_string(),
                }
            } else {
                outcome
            }
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under the Adapter native connector runner"]
async fn a_lost_native_proposal_answer_recovers_the_same_proposal_through_the_job_store() {
    let issuer = registry_adapter_connectors::test_support::issuer(SUBJECT).await;
    let service = registry_adapter_connectors::test_support::Breg::start(&issuer).await;
    let connector = proposal_connector(&service, &issuer).await;
    let target = create_target(&connector);
    let fixture = job_fixture::JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(
            200,
            json!({
                "data": [{"id": "a", "answers": {"age": "045"}}],
                "nextCursor": "p2"
            }),
        )],
        job_fixture::Edits::Ordered,
    )
    .await;
    let program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles");
    let pool = isolated_store().await;
    let direct = DirectBregDestination::new(
        connector,
        move |item: &DeliverableItem| {
            let label = item
                .projected
                .get("answers.age")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            Ok::<_, DirectBregMappingRefused>(DirectBregOperation::Proposal {
                start_input: json!({"input": {"targetId": target, "label": label}}),
                submit_body: json!({}),
            })
        },
        [0x42; 32],
    );
    let destination = LoseFirstAnswer {
        inner: Arc::new(direct),
        accepted_reference: Mutex::new(None),
    };

    let first = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(
        first.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.test.lost-destination-answer".to_string()
        })
    );
    let client = pool.get().await.expect("a pooled client");
    let pending = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the pending row reads")
        .expect("the pending row exists");
    assert_eq!(pending.status, ItemStatus::Pending);
    assert_eq!(pending.sequence, 1);
    assert!(pending.run_id.is_none(), "the lost answer stored no result");
    drop(client);

    let second = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(second.stopped, None);
    assert_eq!(second.items_redelivered, 1);
    assert_eq!(second.items_acknowledged, 1);
    let original = destination
        .accepted_reference
        .lock()
        .expect("the accepted-reference lock")
        .clone()
        .expect("the first Proposal reference");
    let client = pool.get().await.expect("a pooled client");
    let recovered = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the recovered row reads")
        .expect("the recovered row exists");
    assert_eq!(recovered.status, ItemStatus::Acknowledged);
    assert_eq!(recovered.sequence, 1);
    assert_eq!(recovered.run_id.as_deref(), Some(original.as_str()));
    let payload_columns: i64 = client
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'adapter_job_items' \
             AND data_type IN ('json', 'jsonb')",
            &[],
        )
        .await
        .expect("the item table shape reads")
        .get(0);
    assert_eq!(
        payload_columns, 0,
        "the recovery stored no payload or attempt"
    );
    service.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under the Adapter native connector runner"]
async fn configured_cli_pass_recovers_the_same_native_proposal_without_payload_storage() {
    let issuer = registry_adapter_connectors::test_support::issuer(SUBJECT).await;
    let service = registry_adapter_connectors::test_support::Breg::start(&issuer).await;
    let connector = proposal_connector(&service, &issuer).await;
    let target = create_target(&connector);
    let proxy = LostSubmitProxy::start(service.origin()).await;
    let fixture = job_fixture::JobFixture::start_direct_breg(
        vec![(
            200,
            json!({
                "data": [{"id": "a", "answers": {"age": "045", "target": target}}],
                "nextCursor": "p2"
            }),
        )],
        &proxy.origin,
        &issuer.token_endpoint(),
    )
    .await;
    let store = isolated_store_binding().await;

    let first = run_cli_pass(&fixture, &store.url).await;
    assert!(
        !first.status.success(),
        "the lost submit answer stops the pass: stdout={}; stderr={}; starts={:?}; lost={:?}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
        proxy.started_proposals(),
        proxy
            .state
            .submitted
            .lock()
            .expect("the submitted Proposal lock")
            .clone()
    );
    let first_report: serde_json::Value =
        serde_json::from_slice(&first.stdout).unwrap_or_else(|error| {
            panic!(
                "the first pass report is JSON: {error}; status={}; stderr={}",
                first.status,
                String::from_utf8_lossy(&first.stderr)
            )
        });
    assert_eq!(
        first_report.pointer("/stopped/code"),
        Some(&json!(
            "destination-stop:adapter.job.breg-outcome-uncertain"
        ))
    );
    assert!(first.stderr.is_empty(), "the stopped pass stays value-free");
    let client = store.pool.get().await.expect("a pooled store client");
    let pending = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the pending row reads")
        .expect("the pending row exists");
    assert_eq!(pending.status, ItemStatus::Pending);
    assert!(pending.run_id.is_none(), "the lost answer stored no result");
    drop(client);

    proxy.allow_answers();
    let second = run_cli_pass(&fixture, &store.url).await;
    assert!(
        second.status.success(),
        "the repeated CLI pass recovers: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_report: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("the second pass report is JSON");
    assert_eq!(second_report["itemsRedelivered"], 1);
    assert_eq!(second_report["itemsAcknowledged"], 1);
    assert!(
        second.stderr.is_empty(),
        "the recovered pass stays value-free"
    );

    let proposal = proxy.proposal_id();
    assert_eq!(
        proxy.started_proposals(),
        vec![proposal.clone(), proposal.clone()],
        "both CLI passes recovered the same started Proposal"
    );
    let client = store.pool.get().await.expect("a pooled store client");
    let recovered = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the recovered row reads")
        .expect("the recovered row exists");
    assert_eq!(recovered.status, ItemStatus::Acknowledged);
    assert_eq!(recovered.sequence, 1);
    assert_eq!(recovered.run_id.as_deref(), Some(proposal.as_str()));
    let payload_columns: i64 = client
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'adapter_job_items' \
             AND data_type IN ('json', 'jsonb')",
            &[],
        )
        .await
        .expect("the item table shape reads")
        .get(0);
    assert_eq!(payload_columns, 0, "the CLI recovery stored no payload");
    drop(client);
    let state = connector
        .proposal_submit()
        .observe(&proposal)
        .expect("the recovered Proposal remains observable");
    assert_eq!(state.state, "submitted");
    service.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under the Adapter native connector runner"]
/// Proves process-start secret-reference reload, refusal of unregistered
/// replacement material, and recovery after restoring trusted material. The
/// fixture does not model valid-to-valid issuer rotation or old-key revocation.
async fn configured_cli_child_crash_reloads_credential_reference_and_recovers_the_same_proposal() {
    let issuer = registry_adapter_connectors::test_support::issuer(SUBJECT).await;
    let service = registry_adapter_connectors::test_support::Breg::start(&issuer).await;
    let connector = proposal_connector(&service, &issuer).await;
    let target = create_target(&connector);
    let proxy = LostSubmitProxy::start_holding_submit_answer(service.origin()).await;
    let fixture = job_fixture::JobFixture::start_direct_breg(
        vec![(
            200,
            json!({
                "data": [{"id": "a", "answers": {"age": "045", "target": target}}],
                "nextCursor": "p2"
            }),
        )],
        &proxy.origin,
        &issuer.token_endpoint(),
    )
    .await;
    // The source endpoint's declared attempt is ten seconds, so ten seconds is
    // the smallest valid page deadline. With the fixed operator-observation
    // margin, the crashed lease expires naturally in about seventy seconds.
    shorten_crash_fixture_lease(&fixture);
    let store = isolated_store_binding().await;

    let mut crashed = spawn_cli_pass(
        &fixture,
        &store.url,
        registry_platform_testing::fixtures::ED25519_PRIVATE_JWK,
    );
    if !proxy.wait_for_accepted_submit().await {
        let _ = crashed.child().kill();
        let status = crashed
            .child()
            .wait()
            .expect("collect the adapter-job child after the acceptance timeout");
        panic!(
            "the native BReg submit was not accepted before the crash bound; child status={status}"
        );
    }
    assert!(
        crashed
            .child()
            .try_wait()
            .expect("inspect the held adapter-job child")
            .is_none(),
        "the child is still running while its accepted answer is withheld"
    );
    crashed
        .child()
        .kill()
        .expect("kill the owned adapter-job child in the lost-answer window");
    let crashed = crashed.take();
    let crashed_output = tokio::task::spawn_blocking(move || {
        crashed
            .wait_with_output()
            .expect("collect the killed adapter-job child")
    })
    .await
    .expect("the killed adapter-job child joins");
    assert!(
        !crashed_output.status.success(),
        "the deliberately killed child cannot report success"
    );
    assert_cli_output_redacted(&crashed_output, "crashed child");
    proxy.allow_answers();

    let proposal = proxy.proposal_id();
    assert_eq!(
        proxy.started_proposals(),
        vec![proposal.clone()],
        "BReg accepted exactly one Proposal before the process crash"
    );
    let client = store.pool.get().await.expect("a pooled store client");
    let pending = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the crash-window row reads")
        .expect("the crash-window row exists");
    assert_eq!(pending.status, ItemStatus::Pending);
    assert_eq!(pending.sequence, 1);
    assert!(pending.run_id.is_none(), "the crash stored no answer");
    let state = store::read_state(&client, "case-daily")
        .await
        .expect("the crashed job state reads")
        .expect("the crashed job state exists");
    assert!(
        state.lease_expires.is_some(),
        "the killed process leaves its fenced lease to expire"
    );
    drop(client);

    let fenced = run_cli_pass(&fixture, &store.url).await;
    assert!(
        !fenced.status.success(),
        "the immediate restart cannot cross the crashed process's lease"
    );
    let fenced_report: serde_json::Value =
        serde_json::from_slice(&fenced.stdout).expect("the fenced pass report is JSON");
    assert_eq!(
        fenced_report.pointer("/stopped/reason"),
        Some(&json!("lease-held"))
    );
    assert_eq!(
        fenced_report.pointer("/stopped/code"),
        Some(&json!("lease-held"))
    );
    assert!(fenced.stderr.is_empty(), "lease fencing stays value-free");
    assert_cli_output_redacted(&fenced, "fenced restart");

    wait_for_lease_expiry(&store.pool).await;
    let refused = run_cli_pass_with_key(
        &fixture,
        &store.url,
        registry_platform_testing::fixtures::ED25519_ROTATED_PRIVATE_JWK,
    )
    .await;
    assert!(
        !refused.status.success(),
        "the unregistered synthetic key is refused after lease recovery"
    );
    assert_cli_output_redacted(&refused, "credential refusal");
    assert_eq!(
        refused.stdout, b"",
        "destination startup refusal emits no pass report"
    );
    assert_eq!(
        refused.stderr,
        b"adapter-job: adapter.job.breg-credential-refused: no bearer credential BReg accepts was obtained; check `destinations.breg-test` tokenEndpoint, clientId, privateKeyRef, scopes and resource, and that BReg trusts the issuer\n",
        "the unregistered key fails at the exact authenticated metadata boundary"
    );
    assert_eq!(
        proxy.started_proposals(),
        vec![proposal.clone()],
        "the refused credential reaches no new BReg effect"
    );
    let client = store.pool.get().await.expect("a pooled store client");
    let still_pending = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the refused-credential row reads")
        .expect("the refused-credential row exists");
    assert_eq!(still_pending.status, ItemStatus::Pending);
    assert_eq!(still_pending.sequence, 1);
    assert!(still_pending.run_id.is_none());
    drop(client);

    // The runtime binding still names secret:env/BREG_CLIENT_KEY. Restoring
    // the trusted material behind that same reference is observed only by the
    // new process; this is corrected-material recovery, not issuer rotation.
    let recovered = run_cli_pass_with_key(
        &fixture,
        &store.url,
        registry_platform_testing::fixtures::ED25519_PRIVATE_JWK,
    )
    .await;
    assert!(
        recovered.status.success(),
        "the restored trusted key recovers the pending item: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let recovered_report: serde_json::Value =
        serde_json::from_slice(&recovered.stdout).expect("the recovered pass report is JSON");
    assert_eq!(recovered_report["itemsRedelivered"], 1);
    assert_eq!(recovered_report["itemsAcknowledged"], 1);
    assert!(recovered.stderr.is_empty(), "recovery stays value-free");
    assert_cli_output_redacted(&recovered, "corrected credential material");

    assert_eq!(
        proxy.started_proposals(),
        vec![proposal.clone(), proposal.clone()],
        "restart recovers the same Proposal rather than duplicating the effect"
    );
    let start_keys = proxy.start_command_keys();
    let submit_keys = proxy.submit_command_keys();
    assert_eq!(start_keys.len(), 2);
    assert_eq!(
        submit_keys.len(),
        1,
        "fresh observation of the submitted Proposal avoids a duplicate submit request"
    );
    assert_eq!(start_keys[0], start_keys[1], "start retries use one key");
    assert_ne!(
        start_keys[0], submit_keys[0],
        "the two steps keep distinct keys"
    );

    let client = store.pool.get().await.expect("a pooled store client");
    let item = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the recovered crash row reads")
        .expect("the recovered crash row exists");
    assert_eq!(item.status, ItemStatus::Acknowledged);
    assert_eq!(item.sequence, 1);
    assert_eq!(item.run_id.as_deref(), Some(proposal.as_str()));
    let payload_columns: i64 = client
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'adapter_job_items' \
             AND data_type IN ('json', 'jsonb')",
            &[],
        )
        .await
        .expect("the recovered item table shape reads")
        .get(0);
    assert_eq!(payload_columns, 0, "crash recovery stored no payload");
    drop(client);
    let proposal_state = connector
        .proposal_submit()
        .observe(&proposal)
        .expect("the recovered Proposal remains observable");
    assert_eq!(proposal_state.state, "submitted");
    service.finish();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under the Adapter native connector runner"]
#[cfg(feature = "job-postgres")]
async fn postgres_source_reaches_native_breg_and_holds_a_revised_row() {
    let issuer = registry_adapter_connectors::test_support::issuer(SUBJECT).await;
    let service = registry_adapter_connectors::test_support::Breg::start(&issuer).await;
    let connector = proposal_connector(&service, &issuer).await;
    let target = create_target(&connector);
    let fixture = job_fixture::JobFixture::start_direct_breg(
        vec![(200, json!({"data": []}))],
        &service.origin(),
        &issuer.token_endpoint(),
    )
    .await;
    let source = postgres_native_source::PostgresNativeSource::install(
        &fixture.pack,
        &fixture.job,
        &fixture.runtime,
        true,
        &target,
    )
    .await;
    let mut program =
        compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the SQL job compiles");
    activate_postgres_sources(&mut program, &source.resolver())
        .expect("the production PostgreSQL source host activates");
    let pool = isolated_store().await;
    let mapping_calls = Arc::new(AtomicUsize::new(0));
    let observed_mapping_calls = Arc::clone(&mapping_calls);
    let expected_target = target.clone();
    let destination = DirectBregDestination::new(
        connector.clone(),
        move |item: &DeliverableItem| {
            observed_mapping_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                item.projected,
                json!({"id": "a", "label": "045", "target": expected_target})
            );
            Ok::<_, DirectBregMappingRefused>(DirectBregOperation::Proposal {
                start_input: json!({"input": {"targetId": expected_target, "label": "045"}}),
                submit_body: json!({}),
            })
        },
        [0x42; 32],
    );

    let first = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(first.stopped, None);
    assert_eq!(first.items_read, 1);
    assert_eq!(first.items_new, 1);
    assert_eq!(first.items_acknowledged, 1);
    let item_key = postgres_native_source::only_item_key(&pool).await;
    let client = pool.get().await.expect("a native item-store client");
    let admitted = store::inspect_item(&client, "case-daily", &item_key)
        .await
        .expect("read the SQL-backed native item")
        .expect("the SQL-backed native item exists");
    assert_eq!(admitted.status, ItemStatus::Acknowledged);
    assert_eq!(admitted.sequence, 1);
    let proposal = admitted.run_id.expect("native BReg returned a Proposal");
    drop(client);
    let proposal_state = connector
        .proposal_submit()
        .observe(&proposal)
        .expect("the SQL-backed native Proposal remains observable");
    assert_eq!(proposal_state.state, "submitted");

    let repeated = run_pass(&pool, &program, &destination, PassOptions::default()).await;
    assert_eq!(repeated.stopped, None);
    assert_eq!(repeated.items_skipped, 1);
    // One mapping freezes the operation identity before the send and one
    // builds the send; a skipped or held item is never mapped again.
    assert_eq!(mapping_calls.load(Ordering::SeqCst), 2);

    source.revise_label().await;
    let revised = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            rescan: true,
            ..PassOptions::default()
        },
    )
    .await;
    assert_eq!(revised.stopped, None);
    assert_eq!(revised.items_changed, 1);
    assert_eq!(revised.items_held, 1);
    assert_eq!(
        revised.holds_by_code.get("adapter.job.revised-item"),
        Some(&1)
    );
    assert_eq!(mapping_calls.load(Ordering::SeqCst), 2);
    let client = pool.get().await.expect("a native item-store client");
    let held = store::inspect_item(&client, "case-daily", &item_key)
        .await
        .expect("read the revised native item")
        .expect("the revised native item exists");
    assert_eq!(held.status, ItemStatus::Held);
    assert_eq!(held.sequence, 2);
    assert_eq!(held.run_id.as_deref(), Some(proposal.as_str()));
    drop(client);
    postgres_native_source::assert_no_payload_columns(&pool).await;
    service.finish();
}
