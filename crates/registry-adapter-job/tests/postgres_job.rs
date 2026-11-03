// SPDX-License-Identifier: Apache-2.0

//! The job host's PostgreSQL suite: the item table's no-payload
//! invariant, the lease, and every pass edge the seven steps carry
//! (`products/adapter/CONCEPT.md` section 17.2). Every test runs in its
//! own schema inside the database named by `ADAPTER_TEST_DATABASE_URL`;
//! a test binary that passes because its database URL is absent is not
//! database verification, so the variable is required: without it every
//! test in this file fails on the spot.
#![cfg(feature = "postgres-test")]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter_core::{AdapterJob, JobIdentity};
use registry_adapter_engine::job::compile_job;
use registry_adapter_job::destination::{
    DeliverableItem, HandOffOutcome, JobDestination, NullDestination,
};
use registry_adapter_job::pass::{run_pass, PassOptions, StopReason};
use registry_adapter_job::store::{self, ItemStatus};
use registry_adapter_job::trigger::{self, JobState};
use serde_json::{json, Value};
use tokio_postgres::{Config as PgConfig, NoTls};

#[path = "support/fixture_receiver.rs"]
mod fixture_receiver;
#[path = "support/job_fixture.rs"]
mod job_fixture;

use fixture_receiver::{FixtureReceiver, Scripted};
use job_fixture::{reply_page, reply_page_end, JobFixture};

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);

const SOURCE_SECRET_MARKER: &str = "never-projected";

/// One isolated schema, the pooled client that reaches it, and the
/// scoped URL the `adapter-job` binary connects with.
struct Isolated {
    pool: Pool,
    url: String,
}

async fn connect(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect the adapter job test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("the adapter job test connection failed: {error}");
        }
    });
    client
}

/// An isolated schema with the job store migrated.
async fn isolated() -> Isolated {
    let isolated = unmigrated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    store::migrate(&client)
        .await
        .expect("the job store migration applies");
    drop(client);
    isolated
}

/// An isolated schema no migration has touched.
async fn unmigrated() -> Isolated {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let serial = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the test clock is after the Unix epoch")
        .as_nanos();
    let schema = format!("adapter_job_{nanos}_{serial}");
    let admin = connect(&base).await;
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated adapter job schema");
    drop(admin);
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
    Isolated { pool, url }
}

/// Run the `adapter-job` binary against the isolated schema: the
/// fixture runtime config's store reads its URL from `JOB_TEST_DB`. The
/// run blocks on a worker thread, so the test runtime stays free to
/// serve the fixture's loopback double.
async fn run_job(url: &str, args: Vec<std::ffi::OsString>) -> std::process::Output {
    let url = url.to_string();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_adapter-job"))
            .env("JOB_TEST_DB", url)
            .args(args)
            .output()
            .expect("run adapter-job")
    })
    .await
    .expect("the adapter-job run joins")
}

/// Run the job binary with named ambient variables removed. Bootstrap
/// coverage uses this to prove that source and destination references are
/// parsed but not resolved by the store-only command.
async fn run_job_without_env(
    url: &str,
    args: Vec<std::ffi::OsString>,
    removed: &[&str],
) -> std::process::Output {
    let url = url.to_string();
    let removed = removed
        .iter()
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_adapter-job"));
        command.env("JOB_TEST_DB", url).args(args);
        for name in removed {
            command.env_remove(name);
        }
        command.output().expect("run adapter-job")
    })
    .await
    .expect("the adapter-job run joins")
}

/// A child whose failure path cannot leave the interval loop running.
/// Successful tests consume the child through `output`; every earlier
/// return or panic kills and waits for it here.
struct ManagedChild {
    child: Option<Child>,
}

impl ManagedChild {
    fn spawn(url: &str, args: Vec<std::ffi::OsString>) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_adapter-job"))
            .env("JOB_TEST_DB", url)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn adapter-job interval loop");
        Self { child: Some(child) }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .expect("the managed child is present")
            .try_wait()
            .expect("poll adapter-job interval loop")
    }

    fn interrupt(&mut self) {
        let pid = self
            .child
            .as_ref()
            .expect("the managed child is present")
            .id()
            .to_string();
        let signal = Command::new("kill")
            .args(["-INT", pid.as_str()])
            .output()
            .expect("send SIGINT to adapter-job interval loop");
        assert!(
            signal.status.success(),
            "sending SIGINT failed: {}",
            String::from_utf8_lossy(&signal.stderr)
        );
    }

    fn output(&mut self) -> Output {
        self.child
            .take()
            .expect("the managed child is present")
            .wait_with_output()
            .expect("collect adapter-job interval loop output")
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
                    eprintln!("failed to kill adapter-job test child: {error}");
                }
            }
            Err(error) => eprintln!("failed to poll adapter-job test child: {error}"),
        }
        if let Err(error) = child.wait() {
            eprintln!("failed to wait for adapter-job test child: {error}");
        }
    }
}

/// Wait generously for one pass to persist after `after`, while still
/// failing early if the real child exits. The assertions use persisted
/// scheduler state, not an in-process trigger simulation.
async fn wait_for_persisted_pass(
    child: &mut ManagedChild,
    pool: &Pool,
    after: Option<SystemTime>,
) -> SystemTime {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if let Some(status) = child.try_wait() {
                panic!("adapter-job exited before the expected pass persisted: {status}");
            }
            let persisted = state(pool, "case-daily").await.last_pass_at;
            if let Some(persisted) = persisted {
                if after.is_none_or(|prior| persisted > prior) {
                    return persisted;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("adapter-job persisted the scheduled pass within 45 seconds")
}

async fn wait_for_clean_exit(child: &mut ManagedChild) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if child.try_wait().is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("adapter-job exits promptly after SIGINT");
}

fn set_acceptance_interval(fixture: &JobFixture) {
    let authored = std::fs::read_to_string(&fixture.job).expect("read the fixture job");
    let scheduled = authored.replace(
        "    delayMilliseconds: 60000",
        "    delayMilliseconds: 3000\n    initialDelayMilliseconds: 1000",
    );
    assert_ne!(scheduled, authored, "the fixture interval was replaced");
    std::fs::write(&fixture.job, scheduled).expect("write the acceptance interval");
}

fn fixture_pass_args(fixture: &JobFixture, receiver: &FixtureReceiver) -> Vec<std::ffi::OsString> {
    let mut args = job_args("pass", fixture, &["--fixture"]);
    args.push("--fixture-url".into());
    args.push(receiver.url.clone().into());
    args
}

fn assert_value_free_output(label: &str, output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(SOURCE_SECRET_MARKER)
                && !text.contains("\"answers\"")
                && !text.contains("\"age\"")
                && !text.contains("\"045\""),
            "{label} exposed a source-only canary"
        );
    }
    assert!(
        output.stderr.is_empty(),
        "{label} wrote stderr after the output passed source-canary checks: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A destination whose answers the test scripts, and whose deliveries
/// the test inspects.
#[derive(Clone, Default)]
struct ScriptedDestination {
    outcomes: Arc<Mutex<VecDeque<HandOffOutcome>>>,
    delivered: Arc<Mutex<Vec<DeliverableItem>>>,
}

impl ScriptedDestination {
    fn script(outcomes: Vec<HandOffOutcome>) -> Self {
        Self {
            outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
            delivered: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn delivered(&self) -> Vec<DeliverableItem> {
        self.delivered
            .lock()
            .expect("the delivery record lock")
            .clone()
    }
}

impl JobDestination for ScriptedDestination {
    fn deliver<'a>(
        &'a self,
        _job: &'a JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        Box::pin(async move {
            self.delivered
                .lock()
                .expect("the delivery record lock")
                .push(item.clone());
            self.outcomes
                .lock()
                .expect("the script lock")
                .pop_front()
                .unwrap_or_else(|| panic!("the test scripted an answer for every delivery"))
        })
    }
}

#[derive(Clone)]
struct IdentifiedDestination {
    identity: [u8; 32],
    scripted: ScriptedDestination,
}

impl IdentifiedDestination {
    fn script(identity: [u8; 32], outcomes: Vec<HandOffOutcome>) -> Self {
        Self {
            identity,
            scripted: ScriptedDestination::script(outcomes),
        }
    }

    fn delivered(&self) -> Vec<DeliverableItem> {
        self.scripted.delivered()
    }
}

impl JobDestination for IdentifiedDestination {
    fn receiver_identity(&self, _job: &JobIdentity, _item: &DeliverableItem) -> Option<[u8; 32]> {
        Some(self.identity)
    }

    fn deliver<'a>(
        &'a self,
        job: &'a JobIdentity,
        item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        self.scripted.deliver(job, item)
    }
}

fn acknowledged(run_id: &str) -> HandOffOutcome {
    HandOffOutcome::Acknowledged {
        run_id: Some(run_id.to_string()),
    }
}

fn refused(code: &str) -> HandOffOutcome {
    HandOffOutcome::Refused {
        code: code.to_string(),
    }
}

fn held(code: &str, run_id: Option<&str>) -> HandOffOutcome {
    HandOffOutcome::Held {
        code: code.to_string(),
        run_id: run_id.map(str::to_string),
    }
}

/// The pass options of these tests, a refusal limit small enough to
/// reach inside a two-item page.
fn options(refusal_limit: u32) -> PassOptions {
    PassOptions {
        refusal_limit,
        ..PassOptions::default()
    }
}

/// The fixture of these tests: the two-item page over the loopback
/// double, and the isolated schema's pool.
async fn pass_fixture() -> (JobFixture, Pool) {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![
            (200, reply_page()),
            (200, reply_page()),
            (200, reply_page()),
        ],
        job_fixture::Edits::Ordered,
    )
    .await;
    let isolated = isolated().await;
    (fixture, isolated.pool)
}

async fn compile(fixture: &JobFixture) -> registry_adapter_engine::job::JobProgram {
    compile_job(&fixture.pack, &fixture.job, &fixture.runtime).expect("the job compiles")
}

async fn state(pool: &Pool, job_id: &str) -> store::JobStateRow {
    let client = pool.get().await.expect("a pooled client");
    store::read_state(&client, job_id)
        .await
        .expect("the state row reads")
        .unwrap_or_default()
}

async fn item(pool: &Pool, key: &str) -> Option<store::ItemRecord> {
    let client = pool.get().await.expect("a pooled client");
    store::inspect_item(&client, "case-daily", key)
        .await
        .expect("the item row reads")
}

/// The invariant the table's shape carries: no column can hold a JSON
/// item body, and the column set is exactly the identity-and-progress
/// set of `products/adapter/CONCEPT.md` section 17.2.
#[tokio::test]
async fn the_item_table_holds_no_column_that_can_carry_a_payload() {
    let isolated = isolated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    let rows = client
        .query(
            "SELECT column_name, data_type FROM information_schema.columns \
             WHERE table_name = 'adapter_job_items' AND table_schema = current_schema() \
             ORDER BY column_name",
            &[],
        )
        .await
        .expect("the information schema reads");
    let columns: Vec<(String, String)> = rows
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let expected: Vec<(String, String)> = [
        ("admitted_before", "boolean"),
        ("code", "text"),
        ("delivery_attempt", "bigint"),
        ("event_time", "timestamp with time zone"),
        ("first_seen", "timestamp with time zone"),
        ("item_key", "text"),
        ("job_id", "text"),
        ("last_digest", "text"),
        ("last_seen", "timestamp with time zone"),
        ("prior_run_id", "text"),
        ("receiver_identity", "bytea"),
        ("receiver_identity_known", "boolean"),
        ("run_id", "text"),
        ("sequence", "bigint"),
        ("status", "text"),
    ]
    .iter()
    .map(|(name, kind)| ((*name).to_string(), (*kind).to_string()))
    .collect();
    assert_eq!(
        columns, expected,
        "the item table carries exactly the identity-and-progress columns, no payload column at all"
    );
    for (name, kind) in &columns {
        assert!(
            kind != "json" && kind != "jsonb",
            "column {name} is {kind}, a type that can hold an item body"
        );
    }
    // The state row keeps the cursor as engine-owned resume state, and
    // nothing else JSON-shaped.
    let rows = client
        .query(
            "SELECT column_name, data_type FROM information_schema.columns \
             WHERE table_name = 'adapter_job_state' AND table_schema = current_schema() \
             AND data_type IN ('json', 'jsonb')",
            &[],
        )
        .await
        .expect("the information schema reads");
    let json_columns: Vec<String> = rows.into_iter().map(|row| row.get(0)).collect();
    assert_eq!(
        json_columns,
        vec!["position".to_string()],
        "the only JSON column is the engine's own opaque cursor, never an item payload"
    );
}

/// Step 1: the lease refuses a second pass until the first releases it,
/// and a released or expired lease grants again.
#[tokio::test]
async fn the_lease_refuses_a_second_pass_until_the_first_releases() {
    let isolated = isolated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row creates");
    assert!(
        store::take_lease(&client, "case-daily", Duration::from_secs(60))
            .await
            .expect("the first lease grants")
            .is_some(),
        "a fresh lease grants"
    );
    assert!(
        store::take_lease(&client, "case-daily", Duration::from_secs(60))
            .await
            .expect("the second lease answers")
            .is_none(),
        "a live lease refuses a second grant"
    );
    // An expired lease grants again.
    client
        .execute(
            "UPDATE adapter_job_state SET lease_expires = now() - interval '1 second' \
             WHERE job_id = $1",
            &[&"case-daily"],
        )
        .await
        .expect("the lease expires");
    let held = store::take_lease(&client, "case-daily", Duration::from_secs(60))
        .await
        .expect("the renewed lease answers")
        .expect("an expired lease grants again");
    // A completed pass releases its lease under its own epoch.
    store::complete_pass(
        &client,
        "case-daily",
        held.token,
        None,
        false,
        store::RescanProgress::None,
        SystemTime::now(),
    )
    .await
    .expect("the pass completes");
    assert!(
        store::take_lease(&client, "case-daily", Duration::from_secs(60))
            .await
            .expect("the released lease answers")
            .is_some(),
        "a released lease grants again"
    );
}

/// A pass whose lease another pass holds refuses whole: no page read,
/// no item staged, and the position untouched.
#[tokio::test]
async fn a_pass_whose_lease_is_held_refuses_whole() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    // Hold the lease the way a concurrent pass would.
    {
        let client = pool.get().await.expect("a pooled client");
        store::ensure_state(&client, "case-daily")
            .await
            .expect("the state row creates");
        store::take_lease(&client, "case-daily", Duration::from_secs(600))
            .await
            .expect("the lease grants");
    }
    let destination = NullDestination::new();
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(
        report.stopped,
        Some(StopReason::LeaseHeld),
        "the held lease refuses the pass"
    );
    assert_eq!(report.items_read, 0, "a refused pass reads no page");
    assert!(
        destination.recorded().is_empty(),
        "a refused pass delivers nothing"
    );
    let row = state(&pool, "case-daily").await;
    assert!(row.position.is_none(), "a refused pass leaves no position");
}

/// The happy path: new items stage, deliver, and settle with the
/// destination's references, and the page's cursor becomes the
/// position; a second pass over the same page skips every item.
#[tokio::test]
async fn a_pass_hands_off_new_items_and_the_next_pass_skips_them() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    let destination =
        ScriptedDestination::script(vec![acknowledged("run-a"), acknowledged("run-b")]);
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(report.stopped, None, "the pass settles its page");
    assert_eq!(report.items_read, 2);
    assert_eq!(report.items_new, 2);
    assert_eq!(report.items_acknowledged, 2);
    assert_eq!(report.items_refused, 0);
    let row = state(&pool, "case-daily").await;
    assert_eq!(
        row.position,
        Some(json!("p2")),
        "the page's next cursor is the saved position"
    );
    assert!(row.last_pass_stop.is_none(), "a settled pass names no stop");
    let first = item(&pool, "submissions/a")
        .await
        .expect("the first item row");
    assert_eq!(first.status, ItemStatus::Acknowledged);
    assert_eq!(first.run_id.as_deref(), Some("run-a"));
    assert_eq!(first.sequence, 1);
    assert!(
        first.admitted_before,
        "an acknowledged item counts as admitted"
    );
    // The second pass over the same page (the double repeats its last
    // reply) skips both settled items and delivers nothing.
    let second = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(second.items_read, 2);
    assert_eq!(second.items_skipped, 2, "both settled items skip");
    assert_eq!(second.items_new, 0);
    assert_eq!(destination.delivered().len(), 2, "no re-delivery happened");
}

/// The at-least-once hand-off: a row staged `pending` and abandoned, the
/// crash of the brief, is re-delivered by the next pass with identical
/// identity and bytes, and the sequence does not move.
#[tokio::test]
async fn a_crash_before_the_answer_replays_identical_bytes() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    // The crash: the row is staged, the delivery never happens.
    let client = pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    let items = registry_adapter_engine::job::run_job_page(&program, None)
        .await
        .expect("the page runs")
        .page;
    let first = &items.items[0];
    let digest =
        registry_adapter_job::projection::item_digest(&program.job.projection, &first.value);
    // A crashed holder leaves its lease to expire by time; a one-second
    // lease stands in for the crash, so the follow-up pass waits it out
    // instead of finding it held.
    let lease = store::take_lease(&client, "case-daily", Duration::from_secs(1))
        .await
        .expect("the lease answers")
        .expect("the lease grants");
    let staged = store::stage_item(
        &mut pool.get().await.expect("a pooled client"),
        "case-daily",
        &first.key,
        &digest,
        false,
        SystemTime::now(),
        lease.token,
        Duration::from_secs(1),
    )
    .await
    .expect("the row stages")
    .expect("a new item stages");
    assert_eq!(staged.sequence, 1);
    drop(client);
    let row = item(&pool, &first.key).await.expect("the staged row");
    assert_eq!(
        row.status,
        ItemStatus::Pending,
        "the crash left the row pending"
    );
    // The crashed lease expires by time; the next pass waits it out.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    // The next pass re-delivers the same identity and bytes.
    let destination =
        ScriptedDestination::script(vec![acknowledged("run-recovered"), acknowledged("run-b")]);
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(report.items_redelivered, 1, "the pending row re-delivers");
    assert_eq!(report.items_new, 1, "the page's other item is new");
    let delivered = destination.delivered();
    let replay = delivered
        .iter()
        .find(|item| item.key == first.key)
        .expect("the crashed hand-off replayed");
    assert_eq!(
        replay.sequence, 1,
        "the re-delivery carries the staged sequence"
    );
    assert_eq!(
        replay.digest, digest,
        "the re-delivery carries the staged digest"
    );
    assert_eq!(
        replay.projected,
        registry_adapter_job::projection::project(&program.job.projection, &first.value),
        "the re-delivery carries the same projected bytes"
    );
    let row = item(&pool, &first.key).await.expect("the settled row");
    assert_eq!(row.status, ItemStatus::Acknowledged);
    assert_eq!(row.run_id.as_deref(), Some("run-recovered"));
}

/// A maybe-admitted delivery cannot be redirected under the same event id.
/// Deployment drift stops before a second recipient call, leaves the position
/// unchanged, and restoring the frozen identity resumes the pending attempt.
#[tokio::test]
async fn a_pending_delivery_stops_on_receiver_drift_and_recovers_on_equality() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    let original = IdentifiedDestination::script(
        [0x11; 32],
        vec![HandOffOutcome::StopPass {
            code: "coordinator.event.outcome-uncertain".to_string(),
        }],
    );
    let first = run_pass(&pool, &program, &original, options(20)).await;
    assert_eq!(original.delivered().len(), 1);
    assert!(matches!(
        first.stopped,
        Some(StopReason::DestinationStop { .. })
    ));

    let changed = IdentifiedDestination::script([0x22; 32], vec![]);
    let drifted = run_pass(&pool, &program, &changed, options(20)).await;
    assert_eq!(
        drifted.stopped,
        Some(StopReason::DestinationStop {
            code: registry_adapter_job::pass::COORDINATOR_RECEIVER_CHANGED.to_string(),
        })
    );
    assert!(
        changed.delivered().is_empty(),
        "receiver drift stops before a second recipient call"
    );
    assert!(state(&pool, "case-daily").await.position.is_none());

    let restored = IdentifiedDestination::script(
        [0x11; 32],
        vec![acknowledged("run-recovered"), acknowledged("run-b")],
    );
    let recovered = run_pass(&pool, &program, &restored, options(20)).await;
    assert_eq!(recovered.items_redelivered, 1);
    let delivered = restored.delivered();
    assert_eq!(delivered[0].delivery_attempt, 2);
    assert_eq!(
        delivered[0].event_time,
        original.delivered()[0].event_time,
        "the sequence event time remains frozen across the stopped drift"
    );
}

/// The stop rule: a run of consecutive refusals with one code stops the
/// pass with the position unchanged, the rows refused with their code,
/// and status naming the code.
#[tokio::test]
async fn a_refusal_run_stops_the_pass_with_the_position_unchanged() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    let destination =
        ScriptedDestination::script(vec![refused("schema.required"), refused("schema.required")]);
    let report = run_pass(&pool, &program, &destination, options(2)).await;
    assert_eq!(
        report.stopped,
        Some(StopReason::RefusalLimit {
            code: "schema.required".to_string()
        }),
        "two consecutive refusals with one code reach the limit of two"
    );
    assert_eq!(report.items_acknowledged, 0);
    assert_eq!(report.items_refused, 2);
    assert_eq!(
        report.refusals_by_code.get("schema.required"),
        Some(&2),
        "the refusals count by their code"
    );
    let row = state(&pool, "case-daily").await;
    assert!(
        row.position.is_none(),
        "a refused-run pass saves no position"
    );
    assert_eq!(
        row.last_pass_stop.as_deref(),
        Some("refusal-limit:schema.required"),
        "status names the code the pass stopped on"
    );
    assert_eq!(
        row.error_streak, 1,
        "a stopped pass counts into the error streak"
    );
    let first = item(&pool, "submissions/a").await.expect("the first row");
    assert_eq!(first.status, ItemStatus::Refused);
    assert_eq!(first.code.as_deref(), Some("schema.required"));
}

/// A deployment-level answer stops the pass immediately with the
/// position unchanged; the item it stopped on stays pending, the item
/// before it keeps its acknowledgement.
#[tokio::test]
async fn a_deployment_stop_leaves_the_position_unchanged() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    let destination = ScriptedDestination::script(vec![
        acknowledged("run-a"),
        HandOffOutcome::StopPass {
            code: "deployment.held".to_string(),
        },
    ]);
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(
        report.stopped,
        Some(StopReason::DestinationStop {
            code: "deployment.held".to_string()
        })
    );
    assert_eq!(
        report.items_acknowledged, 1,
        "the answer before the stop kept"
    );
    let row = state(&pool, "case-daily").await;
    assert!(row.position.is_none(), "a stopped pass saves no position");
    assert_eq!(
        row.last_pass_stop.as_deref(),
        Some("destination-stop:deployment.held"),
        "status names the destination's own code"
    );
    let second = item(&pool, "submissions/b").await.expect("the second row");
    assert_eq!(
        second.status,
        ItemStatus::Pending,
        "the item the stop landed on stays pending for the next pass"
    );
}

/// An item-scoped hold is a settled answer, not a deployment stop and
/// not a refusal. It advances the page, preserves the destination
/// reference, skips on ordinary and rescan passes while unchanged, and
/// a later source edit reaches the destination as a revision rather
/// than another first registration.
#[tokio::test]
async fn a_held_item_settles_and_stays_held_until_the_source_changes() {
    let mut changed = reply_page();
    changed["data"][0]["answers"]["age"] = json!("046");
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![
            (200, reply_page()),
            (200, reply_page()),
            (200, changed.clone()),
            (200, changed),
        ],
        job_fixture::Edits::Rescan(60),
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    let destination = ScriptedDestination::script(vec![
        held("idempotency.key-reused", Some("proposal-a")),
        acknowledged("proposal-b"),
        held("adapter.job.revised-item", None),
    ]);

    let first = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(first.stopped, None, "a held item settles its page");
    assert_eq!(first.items_held, 1);
    assert_eq!(first.items_acknowledged, 1);
    assert_eq!(state(&pool, "case-daily").await.position, Some(json!("p2")));
    let held_row = item(&pool, "submissions/a").await.expect("the held row");
    assert_eq!(held_row.status, ItemStatus::Held);
    assert_eq!(held_row.code.as_deref(), Some("idempotency.key-reused"));
    assert_eq!(held_row.run_id.as_deref(), Some("proposal-a"));
    assert!(
        held_row.admitted_before,
        "a hold fences a later edit as possibly admitted"
    );

    let unchanged = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(unchanged.items_skipped, 2);
    assert_eq!(
        destination.delivered().len(),
        2,
        "an unchanged held row is not handed off again"
    );

    let revised = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(revised.items_changed, 1);
    assert_eq!(revised.items_held, 1);
    let deliveries = destination.delivered();
    let revision = deliveries.last().expect("the revision was handed off");
    assert_eq!(revision.key, "submissions/a");
    assert_eq!(revision.sequence, 2);
    assert!(revision.admitted_before);
    assert_eq!(revision.prior_run_id.as_deref(), Some("proposal-a"));
    let revised_row = item(&pool, "submissions/a")
        .await
        .expect("the revised held row");
    assert_eq!(revised_row.status, ItemStatus::Held);
    assert_eq!(
        revised_row.code.as_deref(),
        Some("adapter.job.revised-item")
    );
    assert_eq!(revised_row.prior_run_id.as_deref(), Some("proposal-a"));

    let still_held = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(still_held.items_skipped, 2);
    assert_eq!(destination.delivered().len(), 3);

    let client = pool.get().await.expect("a pooled client");
    let counts = store::item_counts(&client, "case-daily")
        .await
        .expect("status counts read");
    assert_eq!(counts.held, 1);
    assert_eq!(
        counts.holds_by_code.get("adapter.job.revised-item"),
        Some(&1)
    );
}

/// A source revert is still a change: A is accepted at sequence 1, B is
/// held as a revision at sequence 2, and byte-identical A is held as a
/// new revision at sequence 3. The original destination reference stays
/// beside both revisions, and unchanged ordinary and rescan passes do
/// not create another destination effect.
#[tokio::test]
async fn a_source_revert_advances_the_sequence_and_stays_held() {
    let original = reply_page();
    let mut changed = original.clone();
    changed["data"][0]["answers"]["age"] = json!("046");
    let empty = json!({"data": []});
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![
            (200, original.clone()),
            (200, changed),
            (200, empty.clone()),
            (200, original.clone()),
            (200, empty),
            (200, original.clone()),
            (200, original),
        ],
        job_fixture::Edits::Rescan(60),
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    let destination = ScriptedDestination::script(vec![
        acknowledged("proposal-a"),
        acknowledged("proposal-b"),
        held("adapter.job.revised-item", None),
        held("adapter.job.revised-item", None),
    ]);

    let accepted = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(accepted.items_new, 2);
    assert_eq!(accepted.items_acknowledged, 2);
    assert_eq!(accepted.items_changed, 0);
    assert_eq!(accepted.items_held, 0);
    assert_eq!(state(&pool, "case-daily").await.position, Some(json!("p2")));
    let accepted_row = item(&pool, "submissions/a")
        .await
        .expect("the accepted A row");
    let original_digest = accepted_row.last_digest.clone();
    assert_eq!(accepted_row.sequence, 1);
    assert_eq!(accepted_row.status, ItemStatus::Acknowledged);
    assert_eq!(accepted_row.run_id.as_deref(), Some("proposal-a"));
    assert_eq!(accepted_row.prior_run_id, None);
    let original_delivery = destination
        .delivered()
        .into_iter()
        .find(|delivery| delivery.key == "submissions/a")
        .expect("the original A delivery");
    assert_eq!(original_delivery.sequence, 1);
    assert_eq!(original_delivery.digest, original_digest);
    assert_eq!(original_delivery.prior_run_id, None);

    let revised = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(revised.items_new, 0);
    assert_eq!(revised.items_changed, 1);
    assert_eq!(revised.items_held, 1);
    assert_eq!(revised.items_skipped, 1);
    assert_eq!(state(&pool, "case-daily").await.position, Some(json!("p2")));
    let revised_delivery = destination
        .delivered()
        .last()
        .cloned()
        .expect("the B revision delivery");
    assert_eq!(revised_delivery.key, "submissions/a");
    assert_eq!(revised_delivery.sequence, 2);
    assert_ne!(revised_delivery.digest, original_digest);
    assert_eq!(revised_delivery.prior_run_id.as_deref(), Some("proposal-a"));
    assert!(revised_delivery.admitted_before);
    let revised_row = item(&pool, "submissions/a").await.expect("the held B row");
    assert_eq!(revised_row.last_digest, revised_delivery.digest);
    assert_eq!(revised_row.sequence, 2);
    assert_eq!(revised_row.status, ItemStatus::Held);
    assert_eq!(
        revised_row.code.as_deref(),
        Some("adapter.job.revised-item")
    );
    assert_eq!(revised_row.run_id, None);
    assert_eq!(revised_row.prior_run_id.as_deref(), Some("proposal-a"));

    let completed_revision_rescan = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(completed_revision_rescan.items_read, 0);
    let revision_state = state(&pool, "case-daily").await;
    assert_eq!(revision_state.position, None);
    assert!(!revision_state.rescan_active);

    let reverted = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(
        reverted.items_new, 0,
        "the reverted A is not registered anew"
    );
    assert_eq!(reverted.items_changed, 1);
    assert_eq!(reverted.items_held, 1);
    assert_eq!(reverted.items_skipped, 1);
    assert_eq!(state(&pool, "case-daily").await.position, Some(json!("p2")));
    let reverted_delivery = destination
        .delivered()
        .last()
        .cloned()
        .expect("the reverted A delivery");
    assert_eq!(reverted_delivery.key, "submissions/a");
    assert_eq!(reverted_delivery.sequence, 3);
    assert_eq!(reverted_delivery.digest, original_digest);
    assert_eq!(
        reverted_delivery.prior_run_id.as_deref(),
        Some("proposal-a")
    );
    assert!(reverted_delivery.admitted_before);
    let reverted_row = item(&pool, "submissions/a")
        .await
        .expect("the held reverted A row");
    assert_eq!(reverted_row.last_digest, original_digest);
    assert_eq!(reverted_row.sequence, 3);
    assert_eq!(reverted_row.status, ItemStatus::Held);
    assert_eq!(
        reverted_row.code.as_deref(),
        Some("adapter.job.revised-item")
    );
    assert_eq!(reverted_row.run_id, None);
    assert_eq!(reverted_row.prior_run_id.as_deref(), Some("proposal-a"));

    let completed_revert_rescan = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(completed_revert_rescan.items_read, 0);
    assert_eq!(state(&pool, "case-daily").await.position, None);

    let unchanged = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(unchanged.items_skipped, 2);
    assert_eq!(unchanged.items_changed, 0);
    assert_eq!(unchanged.items_held, 0);
    assert_eq!(destination.delivered().len(), 4);
    assert_eq!(state(&pool, "case-daily").await.position, Some(json!("p2")));

    let unchanged_rescan = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(unchanged_rescan.items_skipped, 2);
    assert_eq!(unchanged_rescan.items_changed, 0);
    assert_eq!(unchanged_rescan.items_held, 0);
    assert_eq!(destination.delivered().len(), 4);
    let final_state = state(&pool, "case-daily").await;
    assert_eq!(final_state.position, Some(json!("p2")));
    assert!(final_state.rescan_active);
    let final_row = item(&pool, "submissions/a")
        .await
        .expect("the unchanged held A row");
    assert_eq!(final_row.last_digest, original_digest);
    assert_eq!(final_row.sequence, 3);
    assert_eq!(final_row.status, ItemStatus::Held);
    assert_eq!(final_row.code.as_deref(), Some("adapter.job.revised-item"));
    assert_eq!(final_row.run_id, None);
    assert_eq!(final_row.prior_run_id.as_deref(), Some("proposal-a"));

    let client = pool.get().await.expect("a pooled client");
    let counts = store::item_counts(&client, "case-daily")
        .await
        .expect("status counts read");
    assert_eq!(counts.pending, 0);
    assert_eq!(counts.acknowledged, 1);
    assert_eq!(counts.refused, 0);
    assert_eq!(counts.held, 1);
    assert_eq!(
        counts.holds_by_code.get("adapter.job.revised-item"),
        Some(&1)
    );
}

/// A page fault stops the pass under its closed code with the position
/// unchanged.
#[tokio::test]
async fn a_page_fault_stops_under_its_page_code() {
    let fixture = JobFixture::start(
        job_fixture::EMPTY_KEY_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    let destination = NullDestination::new();
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(
        report.stopped,
        Some(StopReason::PageFault {
            code: "adapter.job.page-key".to_string(),
            record: None,
        }),
        "the empty-key page refuses under its own code"
    );
    assert_eq!(report.items_read, 0, "a refused page hands off no item");
    let row = state(&pool, "case-daily").await;
    assert!(row.position.is_none());
    assert_eq!(
        row.last_pass_stop.as_deref(),
        Some("page-fault:adapter.job.page-key"),
        "status names the page code"
    );
}

/// The rescan: a refused item retries only when the pass rescans from
/// the first page; unchanged items skip by digest in both passes; the
/// completed rescan stamps its own gate.
#[tokio::test]
async fn a_rescan_retries_the_refused_item_and_skips_the_unchanged_ones() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    // The first pass: the destination refuses the first item and takes
    // the second, and the page settles.
    let destination = ScriptedDestination::script(vec![
        refused("review.unavailable"),
        acknowledged("run-b"),
        acknowledged("run-a-retried"),
    ]);
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(report.stopped, None);
    assert_eq!(report.items_refused, 1);
    assert_eq!(report.items_acknowledged, 1);
    let row = state(&pool, "case-daily").await;
    assert_eq!(row.position, Some(json!("p2")));
    // A plain pass over the same page skips both: the refused item
    // retries only on a rescan.
    let plain = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(
        plain.items_skipped, 2,
        "a plain pass retries no refused item"
    );
    assert_eq!(plain.items_redelivered, 0);
    // The rescan runs from the first page, re-delivers the refused item
    // under the same identity, and skips the acknowledged one.
    let rescan_options = PassOptions {
        refusal_limit: 20,
        rescan: true,
        dry_run: false,
    };
    let rescan = run_pass(&pool, &program, &destination, rescan_options).await;
    assert_eq!(rescan.items_redelivered, 1, "the refused item retries");
    assert_eq!(rescan.items_skipped, 1, "the acknowledged item still skips");
    let delivered = destination.delivered();
    let retried = delivered
        .iter()
        .filter(|item| item.key == "submissions/a")
        .collect::<Vec<_>>();
    assert_eq!(retried.len(), 2, "the refused item was delivered twice");
    assert_eq!(
        retried[0].sequence, retried[1].sequence,
        "a re-delivery under the same digest does not move the sequence"
    );
    assert_eq!(retried[0].digest, retried[1].digest);
    assert_eq!(
        retried[0].projected, retried[1].projected,
        "identical bytes"
    );
    let first = item(&pool, "submissions/a").await.expect("the retried row");
    assert_eq!(first.status, ItemStatus::Acknowledged, "the retry settled");
    // The rescan traversal stays in progress: this page carried a next
    // cursor, so the marker holds and the gate stamps its time only at
    // the finite end, where the declared delay starts.
    let row = state(&pool, "case-daily").await;
    assert!(row.rescan_active, "the rescan traversal is in progress");
    assert!(
        row.last_rescan_at.is_none(),
        "the gate stamps at the finite end, not the traversal's first page"
    );
}

/// A rescan starts at the first page once, then follows the saved
/// cursor until the finite end instead of restarting page one on every
/// bounded pass.
#[tokio::test]
async fn an_active_rescan_continues_from_its_saved_cursor() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![
            (200, reply_page()),
            (
                200,
                json!({
                    "data": [{"id": "c"}],
                    "nextCursor": "p3"
                }),
            ),
            (200, json!({"data": [{"id": "d"}]})),
        ],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    let destination = ScriptedDestination::script(vec![
        acknowledged("run-a"),
        acknowledged("run-b"),
        acknowledged("run-c"),
        acknowledged("run-d"),
    ]);

    let first = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(first.items_read, 2);
    let row = state(&pool, "case-daily").await;
    assert_eq!(row.position, Some(json!("p2")));
    assert!(row.rescan_active, "the first page leaves the rescan active");

    let second = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(
        second.items_read, 1,
        "the continuation reads the second page"
    );
    let row = state(&pool, "case-daily").await;
    assert_eq!(row.position, Some(json!("p3")));
    assert!(
        row.rescan_active,
        "the second page leaves the rescan active"
    );

    let third = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(third.items_read, 1, "the continuation reads the final page");
    let requests = fixture.double.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].target, "/v1/submissions");
    assert_eq!(
        requests[1].target, "/v1/submissions?cursor=p2",
        "an explicit rescan option still resumes the active traversal"
    );
    assert_eq!(
        requests[2].target, "/v1/submissions?cursor=p3",
        "a plain pass also resumes the active traversal"
    );
    let row = state(&pool, "case-daily").await;
    assert!(row.position.is_none(), "the finite end clears the cursor");
    assert!(!row.rescan_active, "the finite end completes the rescan");
    assert!(
        row.last_rescan_at.is_some(),
        "completion stamps the rescan gate"
    );
}

/// An ongoing source holds its place at the tail: its empty page still
/// carries a cursor, so no finite end ever clears the position. A rescan
/// of such a source ends at the first empty page, where it has caught up
/// with the tail; the position stays at that cursor so the next ordinary
/// pass reads only what arrives after it.
#[tokio::test]
async fn a_rescan_of_an_ongoing_source_ends_when_it_reaches_the_tail() {
    let fixture = JobFixture::start_ongoing(
        job_fixture::PAGE_SCRIPT,
        vec![
            (200, reply_page()),
            (200, json!({"data": [], "nextCursor": "p2"})),
        ],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    let destination =
        ScriptedDestination::script(vec![acknowledged("run-a"), acknowledged("run-b")]);

    let first = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(first.stopped, None);
    assert_eq!(first.items_read, 2);
    let row = state(&pool, "case-daily").await;
    assert!(
        row.rescan_active,
        "a page with items leaves the rescan active"
    );

    let caught_up = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(caught_up.stopped, None);
    assert_eq!(caught_up.items_read, 0, "the tail page is empty");
    let row = state(&pool, "case-daily").await;
    assert_eq!(
        row.position,
        Some(json!("p2")),
        "the held tail cursor stays the position"
    );
    assert!(!row.rescan_active, "reaching the tail completes the rescan");
    assert!(
        row.last_rescan_at.is_some(),
        "completion stamps the rescan gate"
    );
}

/// A finite source ends only where its cursor clears: an empty page that
/// still carries a cursor is not the end, so the rescan stays active.
#[tokio::test]
async fn a_rescan_of_a_finite_source_continues_past_an_empty_page_with_a_cursor() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, json!({"data": [], "nextCursor": "p2"}))],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    let destination = ScriptedDestination::script(vec![]);

    let report = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(report.stopped, None);
    assert_eq!(report.items_read, 0);
    let row = state(&pool, "case-daily").await;
    assert_eq!(row.position, Some(json!("p2")));
    assert!(
        row.rescan_active,
        "a finite scan is not over while a cursor stands"
    );
    assert!(row.last_rescan_at.is_none());
}

/// An explicit rescan preview shows the first page even when a real
/// rescan is active, while its dry-run contract leaves that traversal's
/// saved cursor and marker untouched.
#[tokio::test]
async fn an_explicit_rescan_dry_run_restarts_without_moving_the_active_state() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    let destination =
        ScriptedDestination::script(vec![acknowledged("run-a"), acknowledged("run-b")]);
    let first = run_pass(
        &pool,
        &program,
        &destination,
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(first.items_read, 2);
    let before = state(&pool, "case-daily").await;
    assert_eq!(before.position, Some(json!("p2")));
    assert!(before.rescan_active);

    let preview = run_pass(
        &pool,
        &program,
        &NullDestination::new(),
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: true,
        },
    )
    .await;
    assert_eq!(preview.items_read, 2);
    let requests = fixture.double.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target, "/v1/submissions");
    assert_eq!(
        requests[1].target, "/v1/submissions",
        "the explicit rescan preview starts at the first page"
    );
    let after = state(&pool, "case-daily").await;
    assert_eq!(
        after.position, before.position,
        "the preview leaves the active traversal's cursor untouched"
    );
    assert_eq!(
        after.rescan_active, before.rescan_active,
        "the preview leaves the active traversal marker untouched"
    );

    let client = pool.get().await.expect("a pooled client");
    store::mark_rescan_due(&client, "case-daily")
        .await
        .expect("the operator rescan is marked due");
    drop(client);
    let marked = state(&pool, "case-daily").await;
    assert_eq!(
        marked.position,
        Some(json!("p2")),
        "marking the rescan preserves the prior traversal's cursor until the pass starts"
    );
    assert!(
        !marked.rescan_active,
        "the explicit operator action abandons the active traversal"
    );
    let restarted = run_pass(
        &pool,
        &program,
        &NullDestination::new(),
        PassOptions {
            refusal_limit: 20,
            rescan: true,
            dry_run: false,
        },
    )
    .await;
    assert_eq!(restarted.items_read, 2);
    let requests = fixture.double.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[2].target, "/v1/submissions",
        "the marked operator rescan restarts despite the saved p2 cursor"
    );
}

/// The dry run writes nothing: no lease, no rows, no position, while the
/// report says what a real pass would have done.
#[tokio::test]
async fn the_dry_run_writes_nothing_and_reports_the_hand_offs() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    let destination = NullDestination::new();
    let options = PassOptions {
        refusal_limit: 20,
        rescan: false,
        dry_run: true,
    };
    let report = run_pass(&pool, &program, &destination, options).await;
    assert_eq!(report.stopped, None);
    assert_eq!(report.items_read, 2);
    assert_eq!(report.items_new, 2);
    assert_eq!(
        report.items_acknowledged, 2,
        "the preview destination acknowledges"
    );
    assert!(
        destination.recorded().len() == 2,
        "the preview recorded both hand-offs"
    );
    assert!(
        item(&pool, "submissions/a").await.is_none(),
        "the preview wrote no row"
    );
    let row = state(&pool, "case-daily").await;
    assert!(row.position.is_none(), "the preview saved no position");
    assert!(row.last_pass_at.is_none(), "the preview stamped no pass");
}

/// A page that ends the scan clears the position, and an idle pass
/// counts into the schedule's idle streak, which multiplies the
/// interval trigger's delay once its threshold is met.
#[tokio::test]
async fn the_schedule_counts_idle_passes_and_backoff_follows_the_state() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page_end()), (200, json!({"data": []}))],
        job_fixture::Edits::Ordered,
    )
    .await;
    let pool = isolated().await.pool;
    let program = compile(&fixture).await;
    let destination =
        ScriptedDestination::script(vec![acknowledged("run-c"), acknowledged("run-x")]);
    // The first pass reads the one-item page and reaches the finite end:
    // the position clears.
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(report.items_read, 1);
    let row = state(&pool, "case-daily").await;
    assert_eq!(row.position, None, "a finite end clears the position");
    assert_eq!(row.idle_streak, 0, "a pass that read an item is not idle");
    // The second pass reads the empty page: an idle pass.
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(report.items_read, 0);
    let row = state(&pool, "case-daily").await;
    assert_eq!(row.idle_streak, 1, "an empty pass counts as idle");
    // The interval trigger reads that streak: below the threshold the
    // base delay holds, at it the multiplier applies.
    let job_with_backoff = job_with_trigger(json!({
        "kind": "interval",
        "delayMilliseconds": 60000,
        "backoffIdleThreshold": 1,
        "backoffMultiplier": 3
    }));
    let now = SystemTime::now();
    let base = trigger::next_due(
        &job_with_backoff,
        &trigger_state(&(state(&pool, "case-daily").await)),
        now,
        now,
    )
    .expect("an interval trigger has a schedule");
    assert!(
        base > Duration::ZERO,
        "the pass just ran; the delay has not passed"
    );
    // A job whose trigger carries no backoff reads the same state at the
    // base delay; read at the same instant, the multiplied schedule sits
    // exactly two base delays beyond it.
    let plain = trigger::next_due(
        &program.job,
        &trigger_state(&state(&pool, "case-daily").await),
        now,
        now,
    )
    .expect("an interval trigger has a schedule");
    assert_eq!(
        base - plain,
        Duration::from_secs(120),
        "the met idle threshold sits two base delays beyond the plain schedule"
    );
}

/// The state row's projection digest follows the job's, so a projection
/// edit is visible in status, and the items re-flag through their own
/// digests on the next pass.
#[tokio::test]
async fn a_projection_edit_shows_in_the_state_and_reflags_the_items() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    let destination = ScriptedDestination::script(vec![
        acknowledged("run-a"),
        acknowledged("run-b"),
        acknowledged("run-a2"),
        acknowledged("run-b2"),
    ]);
    let first = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(first.items_new, 2);
    let row = state(&pool, "case-daily").await;
    assert_eq!(
        row.projection_digest.as_deref(),
        Some(program.job.projection_digest().as_str()),
        "the state row carries the job's projection digest"
    );
    // The second pass over the same page skips both items by digest.
    let second = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(second.items_skipped, 2);
    // With the projection digest absent from the state row, the pass
    // re-syncs it; the items whose digests were computed under the old
    // projection re-flag as changed on their next comparison.
    {
        let client = pool.get().await.expect("a pooled client");
        client
            .execute(
                "UPDATE adapter_job_items SET last_digest = 'sha256:1111111111111111111111111111111111111111111111111111111111111111' \
                 WHERE job_id = $1",
                &[&"case-daily"],
            )
            .await
            .expect("the digests reset");
    }
    let third = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(
        third.items_changed, 2,
        "a digest that no longer matches re-flags the item as changed"
    );
    let first_row = item(&pool, "submissions/a").await.expect("the row");
    assert_eq!(
        first_row.sequence, 2,
        "a changed digest advances the change sequence"
    );
    assert!(
        first_row.admitted_before,
        "a changed digest over an acknowledged row admits before"
    );
    assert_eq!(
        first_row.prior_run_id.as_deref(),
        Some("run-a"),
        "the prior hand-off's reference moves beside the row"
    );
}

/// When successive changed digests have no new destination reference,
/// staging keeps the last accepted reference in persistent state so a
/// crash and re-delivery carry the same fallback.
#[tokio::test]
async fn changed_staging_preserves_the_last_accepted_reference_for_recovery() {
    let pool = isolated().await.pool;
    let mut client = pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    let ttl = Duration::from_secs(60);
    let lease = store::take_lease(&client, "case-daily", ttl)
        .await
        .expect("the lease answers")
        .expect("the lease grants");
    let now = SystemTime::now();

    store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        false,
        now,
        lease.token,
        ttl,
    )
    .await
    .expect("digest A stages")
    .expect("digest A is new");
    store::record_acknowledged(
        &mut client,
        "case-daily",
        "submissions/a",
        Some("run-a"),
        now,
        lease.token,
        ttl,
    )
    .await
    .expect("digest A is acknowledged");

    let staged_b = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        false,
        now,
        lease.token,
        ttl,
    )
    .await
    .expect("digest B stages")
    .expect("digest B changed");
    assert_eq!(staged_b.prior_run_id.as_deref(), Some("run-a"));
    store::record_refused(
        &mut client,
        "case-daily",
        "submissions/a",
        "review.unavailable",
        now,
        lease.token,
        ttl,
    )
    .await
    .expect("digest B is refused");

    let staged_c = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        false,
        now,
        lease.token,
        ttl,
    )
    .await
    .expect("digest C stages")
    .expect("digest C changed");
    assert_eq!(staged_c.prior_run_id.as_deref(), Some("run-a"));
    let pending = store::inspect_item(&client, "case-daily", "submissions/a")
        .await
        .expect("the pending row reads")
        .expect("the pending row exists");
    assert_eq!(
        pending.prior_run_id.as_deref(),
        Some("run-a"),
        "the staged fallback survives a crash"
    );

    let replay = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        false,
        now,
        lease.token,
        ttl,
    )
    .await
    .expect("digest C re-stages")
    .expect("pending digest C re-delivers");
    assert_eq!(
        replay.prior_run_id.as_deref(),
        Some("run-a"),
        "the crash retry carries the persisted fallback"
    );
}

#[tokio::test]
async fn receiver_identity_and_event_metadata_freeze_per_sequence() {
    let pool = isolated().await.pool;
    let mut client = pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    let ttl = Duration::from_secs(60);
    let lease = store::take_lease(&client, "case-daily", ttl)
        .await
        .expect("the lease answers")
        .expect("the lease grants");
    let first_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let retry_time = first_time + Duration::from_secs(30);
    let changed_time = retry_time + Duration::from_secs(30);
    let digest_a = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let digest_b = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let first = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        digest_a,
        false,
        first_time,
        lease.token,
        ttl,
    )
    .await
    .expect("the first sequence stages")
    .expect("the item is new");
    store::bind_delivery_identity(
        &mut client,
        "case-daily",
        "submissions/a",
        &[0x11; 32],
        &[0x31; 32],
        first.delivery_attempt,
        false,
        lease.token,
        ttl,
    )
    .await
    .expect("the first receiver binds");
    assert!(matches!(
        store::bind_delivery_identity(
            &mut client,
            "case-daily",
            "submissions/a",
            &[0x22; 32],
            &[0x31; 32],
            2,
            false,
            lease.token,
            ttl,
        )
        .await,
        Err(store::StoreError::ReceiverIdentityChanged)
    ));
    store::record_refused(
        &mut client,
        "case-daily",
        "submissions/a",
        "event.invalid",
        first_time,
        lease.token,
        ttl,
    )
    .await
    .expect("the no-effect refusal records");
    let retry = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        digest_a,
        true,
        retry_time,
        lease.token,
        ttl,
    )
    .await
    .expect("the refused row restages")
    .expect("the explicit rescan retries it");
    assert_eq!(retry.event_time, first_time);
    assert_eq!(retry.delivery_attempt, 2);
    store::bind_delivery_identity(
        &mut client,
        "case-daily",
        "submissions/a",
        &[0x22; 32],
        &[0x32; 32],
        retry.delivery_attempt,
        true,
        lease.token,
        ttl,
    )
    .await
    .expect("a reviewed no-effect refusal can rebind");

    let changed = store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        digest_b,
        false,
        changed_time,
        lease.token,
        ttl,
    )
    .await
    .expect("the changed digest stages")
    .expect("the digest is a new sequence");
    assert_eq!(changed.sequence, 2);
    assert_eq!(changed.event_time, changed_time);
    assert_eq!(changed.delivery_attempt, 1);
}

#[tokio::test]
async fn a_delivery_attempt_at_i64_max_stops_without_wrapping_or_mutating_the_row() {
    let pool = isolated().await.pool;
    let mut client = pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    let ttl = Duration::from_secs(60);
    let lease = store::take_lease(&client, "case-daily", ttl)
        .await
        .expect("the lease answers")
        .expect("the lease grants");
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        digest,
        false,
        now,
        lease.token,
        ttl,
    )
    .await
    .expect("the first delivery stages")
    .expect("the item is new");
    client
        .execute(
            "UPDATE adapter_job_items SET delivery_attempt = $3 \
             WHERE job_id = $1 AND item_key = $2",
            &[&"case-daily", &"submissions/a", &i64::MAX],
        )
        .await
        .expect("the boundary attempt installs");

    assert!(matches!(
        store::stage_item(
            &mut client,
            "case-daily",
            "submissions/a",
            digest,
            false,
            now + Duration::from_secs(1),
            lease.token,
            ttl,
        )
        .await,
        Err(store::StoreError::DeliveryAttemptExhausted)
    ));
    let row = client
        .query_one(
            "SELECT status, delivery_attempt FROM adapter_job_items \
             WHERE job_id = $1 AND item_key = $2",
            &[&"case-daily", &"submissions/a"],
        )
        .await
        .expect("the boundary row reads");
    assert_eq!(row.get::<_, &str>(0), "pending");
    assert_eq!(row.get::<_, i64>(1), i64::MAX);
}

#[tokio::test]
async fn file_item_identity_adopts_only_empty_state_and_fences_every_transition() {
    let pool = isolated().await.pool;
    let mut client = pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "file-daily")
        .await
        .expect("the state row exists");
    let ttl = Duration::from_secs(60);
    let lease = store::take_lease(&client, "file-daily", ttl)
        .await
        .expect("the lease answers")
        .expect("the lease grants");
    store::bind_item_identity(
        &mut client,
        "file-daily",
        Some(&[0x31; 32]),
        lease.token,
        ttl,
    )
    .await
    .expect("empty state adopts the row identity");
    store::bind_item_identity(
        &mut client,
        "file-daily",
        Some(&[0x31; 32]),
        lease.token,
        ttl,
    )
    .await
    .expect("the stable digest remains usable");
    for changed in [Some([0x32; 32]), None] {
        assert!(matches!(
            store::bind_item_identity(
                &mut client,
                "file-daily",
                changed.as_ref(),
                lease.token,
                ttl,
            )
            .await,
            Err(store::StoreError::ItemIdentityMigrationRequired)
        ));
    }

    store::ensure_state(&client, "http-daily")
        .await
        .expect("the non-row state exists");
    let raw_lease = store::take_lease(&client, "http-daily", ttl)
        .await
        .expect("the raw lease answers")
        .expect("the raw lease grants");
    store::bind_item_identity(&mut client, "http-daily", None, raw_lease.token, ttl)
        .await
        .expect("an ordinary non-row job needs no identity migration");

    store::ensure_state(&client, "legacy-file")
        .await
        .expect("the legacy state exists");
    client
        .execute(
            "INSERT INTO adapter_job_items \
             (job_id, item_key, last_digest, sequence, status, first_seen, last_seen, \
              event_time, delivery_attempt, receiver_identity_known) \
             VALUES ('legacy-file', 'row/a', \
             'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             1, 'acknowledged', now(), now(), now(), 1, true)",
            &[],
        )
        .await
        .expect("the legacy item inserts");
    let legacy_lease = store::take_lease(&client, "legacy-file", ttl)
        .await
        .expect("the legacy lease answers")
        .expect("the legacy lease grants");
    assert!(matches!(
        store::bind_item_identity(
            &mut client,
            "legacy-file",
            Some(&[0x41; 32]),
            legacy_lease.token,
            ttl,
        )
        .await,
        Err(store::StoreError::ItemIdentityMigrationRequired)
    ));
}

/// The interval trigger and the schedule read the state row the pass
/// wrote, the shape the loop mode sleeps on.
#[tokio::test]
async fn the_loop_schedule_reads_the_pass_state() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    let destination = NullDestination::new();
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(report.stopped, None);
    let row = state(&pool, "case-daily").await;
    let state = trigger_state(&row);
    let now = SystemTime::now();
    let due = trigger::next_due(&program.job, &state, now, now)
        .expect("the job declares an interval trigger");
    assert!(
        due > Duration::ZERO && due <= Duration::from_secs(60),
        "the next pass is due within the one-minute delay, in {due:?}"
    );
    // Greedy is not the schedule's: a greedy trigger restarts on the
    // report, and the schedule stays at the declared delay.
    assert!(
        !program.job.triggers[0].greedy,
        "the fixture trigger is not greedy"
    );
}

fn trigger_state(row: &store::JobStateRow) -> JobState {
    JobState {
        position: row.position.clone(),
        projection_digest: row.projection_digest.clone(),
        lease_expires: row.lease_expires,
        last_pass_at: row.last_pass_at,
        last_pass_stop: row.last_pass_stop.clone(),
        last_rescan_at: row.last_rescan_at,
        rescan_active: row.rescan_active,
        idle_streak: u32::try_from(row.idle_streak.max(0)).unwrap_or(u32::MAX),
        error_streak: u32::try_from(row.error_streak.max(0)).unwrap_or(u32::MAX),
    }
}

/// The fixture job with one trigger replaced: the schedule tests read
/// the same job with the trigger options each case names.
fn job_with_trigger(trigger: Value) -> AdapterJob {
    let mut job: AdapterJob = serde_json::from_value(serde_json::json!({
        "apiVersion": registry_adapter_core::ADAPTER_JOB_API_VERSION,
        "kind": registry_adapter_core::ADAPTER_JOB_KIND,
        "job": {"id": "case-daily", "version": "1"},
        "source": {
            "pack": {"id": "case-api-pack", "version": "1",
                "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"},
            "route": "submissions-page"
        },
        "destination": {
            "type": "signed-coordinator-event",
            "binding": "coordinator-test",
            "workflow": "case-ingestion",
            "trigger": "submitted",
            "source": "urn:registry-adapter:job:case-daily",
            "eventType": "org.example.case-submitted.v1",
            "dataSchema": "urn:example:schema:case-submitted:v1"
        },
        "projection": {"fields": ["id"]},
        "triggers": [trigger],
        "profile": {
            "pageDeadlineMilliseconds": 60000,
            "maximumResponseBytes": 65536,
            "maximumPageItems": 100,
            "maximumPageBytes": 65536,
            "maximumUpstreamCalls": 8,
            "read": {
                "maximumFileBytes": 1048576,
                "maximumRowBytes": 65536,
                "maximumFieldBytes": 65536,
                "maximumRowsPerPage": 100
            }
        }
    }))
    .expect("the schedule job parses");
    job.triggers = vec![serde_json::from_value(trigger).expect("the trigger parses")];
    job
}

/// The applied schema versions, in order.
async fn applied_versions(client: &impl deadpool_postgres::GenericClient) -> Vec<i64> {
    client
        .query(
            "SELECT version FROM adapter_job_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .expect("the migration table reads")
        .into_iter()
        .map(|row| row.get::<_, i64>(0))
        .collect()
}

/// Whether the isolated schema holds the named table.
async fn table_present(pool: &Pool, table: &str) -> bool {
    let client = pool.get().await.expect("a pooled client");
    client
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
        .await
        .expect("the catalog reads")
        .get(0)
}

/// Count rows in one of the fixed job-store tables named by the tests.
async fn table_rows(pool: &Pool, table: &str) -> i64 {
    assert!(
        matches!(
            table,
            "adapter_job_schema_migrations" | "adapter_job_state" | "adapter_job_items"
        ),
        "the test queries only a fixed job-store table"
    );
    let client = pool.get().await.expect("a pooled client");
    client
        .query_one(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .expect("the fixed job-store table reads")
        .get(0)
}

/// Install the first maintained store version exactly, so the command-level
/// upgrade test starts from a supported historical schema without copying its
/// SQL into the test.
async fn install_schema_100(pool: &Pool) {
    let client = pool.get().await.expect("a pooled client");
    client
        .batch_execute(
            "CREATE TABLE adapter_job_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await
        .expect("create the migration ledger");
    client
        .batch_execute(include_str!("../src/store/migrations/0100_job_items.sql"))
        .await
        .expect("apply maintained schema version 100");
    client
        .execute(
            "INSERT INTO adapter_job_schema_migrations(version, applied_at) VALUES (100, now())",
            &[],
        )
        .await
        .expect("record maintained schema version 100");
}

/// Install the last schema that predates receiver identity, for the migration
/// test proving an already-pending hand-off never silently binds a new target.
async fn install_schema_102(pool: &Pool) {
    install_schema_100(pool).await;
    let client = pool.get().await.expect("a pooled client");
    for (version, migration) in [
        (
            101_i64,
            include_str!("../src/store/migrations/0101_rescan_active.sql"),
        ),
        (
            102_i64,
            include_str!("../src/store/migrations/0102_held_items.sql"),
        ),
    ] {
        client
            .batch_execute(migration)
            .await
            .expect("the maintained historical migration applies");
        client
            .execute(
                "INSERT INTO adapter_job_schema_migrations(version, applied_at) VALUES ($1, now())",
                &[&version],
            )
            .await
            .expect("the historical schema version records");
    }
}

#[tokio::test]
async fn migration_keeps_a_legacy_pending_receiver_identity_unknown() {
    let isolated = unmigrated().await;
    install_schema_102(&isolated.pool).await;
    let mut client = isolated.pool.get().await.expect("a pooled client");
    let now = SystemTime::now();
    client
        .execute(
            "INSERT INTO adapter_job_items \
             (job_id, item_key, last_digest, sequence, status, first_seen, last_seen) \
             VALUES ('case-daily', 'submissions/a', \
             'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             1, 'pending', $1, $1)",
            &[&now],
        )
        .await
        .expect("the legacy pending row inserts");
    store::migrate(&client)
        .await
        .expect("schema 103 migrates the legacy row");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    let ttl = Duration::from_secs(60);
    let lease = store::take_lease(&client, "case-daily", ttl)
        .await
        .expect("the lease answers")
        .expect("the lease grants");
    assert!(matches!(
        store::bind_delivery_identity(
            &mut client,
            "case-daily",
            "submissions/a",
            &[0x11; 32],
            &[0x31; 32],
            2,
            false,
            lease.token,
            ttl,
        )
        .await,
        Err(store::StoreError::ReceiverIdentityUnknown)
    ));
}

/// A migration and its version row commit together: a failure after the
/// migration's own statements leaves neither, and the next run applies
/// the whole migration again.
#[tokio::test]
async fn a_failed_migration_records_no_version_and_retries_whole() {
    let isolated = unmigrated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    client
        .batch_execute(
            "CREATE TABLE adapter_job_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL);\
             CREATE FUNCTION refuse_101() RETURNS trigger LANGUAGE plpgsql AS $$\
             BEGIN IF NEW.version = 101 THEN RAISE EXCEPTION 'refused for the test'; END IF; \
             RETURN NEW; END $$;\
             CREATE TRIGGER refuse_101 BEFORE INSERT ON adapter_job_schema_migrations \
             FOR EACH ROW EXECUTE FUNCTION refuse_101();",
        )
        .await
        .expect("the refusing trigger installs");
    store::migrate(&client)
        .await
        .expect_err("the version insert of 101 refuses");
    assert_eq!(applied_versions(&client).await, vec![100]);
    let rescan_column: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'adapter_job_state' \
             AND column_name = 'rescan_active')",
            &[],
        )
        .await
        .expect("the catalog reads")
        .get(0);
    assert!(
        !rescan_column,
        "a migration whose version row failed leaves none of its statements"
    );
    client
        .batch_execute("DROP TRIGGER refuse_101 ON adapter_job_schema_migrations")
        .await
        .expect("the trigger drops");
    store::migrate(&client)
        .await
        .expect("the retried migration applies whole");
    assert_eq!(applied_versions(&client).await, vec![100, 101, 102, 103]);
}

/// The fixture's operator arguments for one command over the binary.
fn job_args(command: &str, fixture: &JobFixture, extra: &[&str]) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = vec![command.into(), fixture.job.clone().into()];
    if command != "status" {
        args.push("--pack".into());
        args.push(fixture.pack.clone().into());
    }
    args.push("--runtime".into());
    args.push(fixture.runtime.clone().into());
    args.extend(extra.iter().map(Into::into));
    args
}

/// The store bootstrap takes only the runtime artifact: no job, pack,
/// profile, project, source activation, or destination activation belongs to
/// this command.
fn init_store_args(fixture: &JobFixture) -> Vec<std::ffi::OsString> {
    vec![
        "init-store".into(),
        "--runtime".into(),
        fixture.runtime.clone().into(),
    ]
}

fn inspect_args(fixture: &JobFixture, key: &str) -> Vec<std::ffi::OsString> {
    vec![
        "inspect".into(),
        fixture.job.clone().into(),
        "--runtime".into(),
        fixture.runtime.clone().into(),
        "--key".into(),
        key.into(),
    ]
}

/// Add syntactically valid source and destination secret references to the
/// fixture runtime. The bootstrap test removes these variables from its child
/// process, while leaving the store reference available as `JOB_TEST_DB`.
fn add_unresolved_non_store_secrets(fixture: &JobFixture) {
    let mut runtime: Value =
        serde_json::from_slice(&std::fs::read(&fixture.runtime).expect("read the fixture runtime"))
            .expect("the fixture runtime is JSON");
    runtime["endpoints"][0]["credential"] = json!({
        "type": "basic",
        "usernameRef": "secret:env/JOB_UNRESOLVED_SOURCE_USERNAME",
        "passwordRef": "secret:env/JOB_UNRESOLVED_SOURCE_PASSWORD"
    });
    runtime["destinations"] = json!({
        "coordinator-test": {
            "type": "signed-coordinator-event",
            "baseUrl": "https://coordinator.example.invalid",
            "signingKeyRef": "secret:env/JOB_UNRESOLVED_DESTINATION_KEY",
            "attemptTimeoutMilliseconds": 3000
        }
    });
    std::fs::write(
        &fixture.runtime,
        serde_json::to_vec_pretty(&runtime).expect("render the fixture runtime"),
    )
    .expect("write the fixture runtime");
}

/// Store bootstrap is a complete command with only the runtime artifact. It
/// resolves the store reference, applies the maintained schema, and does not
/// resolve or act through source and destination bindings.
#[tokio::test]
async fn init_store_bootstraps_only_the_store_from_the_runtime_reference() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    add_unresolved_non_store_secrets(&fixture);
    let isolated = unmigrated().await;
    // The global output option affects only a dry-run pass; initialization
    // remains value-free just like status, inspect, and check.
    let mut arguments = init_store_args(&fixture);
    arguments.push("--show-values".into());
    let output = run_job_without_env(
        &isolated.url,
        arguments,
        &[
            "JOB_UNRESOLVED_SOURCE_USERNAME",
            "JOB_UNRESOLVED_SOURCE_PASSWORD",
            "JOB_UNRESOLVED_DESTINATION_KEY",
        ],
    )
    .await;
    assert!(
        output.status.success(),
        "init-store failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "store initialization logs no errors"
    );
    assert!(
        fixture.double.requests().is_empty(),
        "store initialization never reads the source endpoint"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("init-store prints JSON");
    assert_eq!(report["ok"], true);
    assert_eq!(report["schemaVersion"], 103);
    assert_eq!(
        report
            .as_object()
            .expect("init-store prints an object")
            .len(),
        2,
        "the bootstrap report carries no runtime, source, destination, or secret material"
    );

    let client = isolated.pool.get().await.expect("a pooled client");
    assert_eq!(applied_versions(&client).await, vec![100, 101, 102, 103]);
    drop(client);
    for table in [
        "adapter_job_schema_migrations",
        "adapter_job_state",
        "adapter_job_items",
    ] {
        assert!(table_present(&isolated.pool, table).await, "{table} exists");
    }
    assert_eq!(table_rows(&isolated.pool, "adapter_job_state").await, 0);
    assert_eq!(table_rows(&isolated.pool, "adapter_job_items").await, 0);
}

/// Bootstrap is safe to repeat and advances an older supported store through
/// the same embedded migration sequence used by an operational pass.
#[tokio::test]
async fn init_store_repeats_unchanged_and_advances_a_supported_schema() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let current = unmigrated().await;
    let first = run_job(&current.url, init_store_args(&fixture)).await;
    assert!(
        first.status.success(),
        "first init-store failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let client = current.pool.get().await.expect("a pooled client");
    let before = client
        .query(
            "SELECT version, applied_at FROM adapter_job_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .expect("read the first migration records")
        .into_iter()
        .map(|row| (row.get::<_, i64>(0), row.get::<_, SystemTime>(1)))
        .collect::<Vec<_>>();
    drop(client);
    let repeated = run_job(&current.url, init_store_args(&fixture)).await;
    assert!(
        repeated.status.success(),
        "repeated init-store failed: {}",
        String::from_utf8_lossy(&repeated.stderr)
    );
    let client = current.pool.get().await.expect("a pooled client");
    let after = client
        .query(
            "SELECT version, applied_at FROM adapter_job_schema_migrations ORDER BY version",
            &[],
        )
        .await
        .expect("read the repeated migration records")
        .into_iter()
        .map(|row| (row.get::<_, i64>(0), row.get::<_, SystemTime>(1)))
        .collect::<Vec<_>>();
    assert_eq!(after, before, "repeat records no migration twice");
    drop(client);

    let older = unmigrated().await;
    install_schema_100(&older.pool).await;
    let upgraded = run_job(&older.url, init_store_args(&fixture)).await;
    assert!(
        upgraded.status.success(),
        "supported schema upgrade failed: {}",
        String::from_utf8_lossy(&upgraded.stderr)
    );
    let client = older.pool.get().await.expect("a pooled client");
    assert_eq!(applied_versions(&client).await, vec![100, 101, 102, 103]);
    store::schema_current(&client)
        .await
        .expect("the upgraded schema is current");
    drop(client);
    assert_eq!(table_rows(&older.pool, "adapter_job_state").await, 0);
    assert_eq!(table_rows(&older.pool, "adapter_job_items").await, 0);
}

/// A future store belongs to the newer release. Bootstrap refuses it without
/// rewriting its migration ledger or creating job data.
#[tokio::test]
async fn init_store_refuses_a_future_schema_without_mutation() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let isolated = unmigrated().await;
    let initialized = run_job(&isolated.url, init_store_args(&fixture)).await;
    assert!(
        initialized.status.success(),
        "the current schema initializes"
    );
    let client = isolated.pool.get().await.expect("a pooled client");
    client
        .execute(
            "INSERT INTO adapter_job_schema_migrations(version, applied_at) VALUES (999, now())",
            &[],
        )
        .await
        .expect("record the future version");
    let before = applied_versions(&client).await;
    drop(client);

    let output = run_job(&isolated.url, init_store_args(&fixture)).await;
    assert!(!output.status.success(), "a future schema refuses");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("schema version 999") && stderr.contains("newer"),
        "the refusal names the incompatible future schema: {stderr}"
    );
    let client = isolated.pool.get().await.expect("a pooled client");
    assert_eq!(applied_versions(&client).await, before);
    drop(client);
    assert_eq!(table_rows(&isolated.pool, "adapter_job_state").await, 0);
    assert_eq!(table_rows(&isolated.pool, "adapter_job_items").await, 0);
}

/// After explicit bootstrap, all observational and preview commands work in
/// fresh processes without creating the absent job or item rows.
#[tokio::test]
async fn initialized_fresh_store_supports_status_inspect_and_dry_run_without_writes() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let isolated = unmigrated().await;
    let initialized = run_job(&isolated.url, init_store_args(&fixture)).await;
    assert!(
        initialized.status.success(),
        "init-store failed: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let status = run_job(&isolated.url, job_args("status", &fixture, &[])).await;
    assert!(
        status.status.success(),
        "fresh status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_report: Value = serde_json::from_slice(&status.stdout).expect("status prints JSON");
    assert_eq!(status_report["items"]["pending"], 0);
    assert_eq!(status_report["items"]["acknowledged"], 0);
    assert_eq!(status_report["items"]["refused"], 0);
    assert_eq!(status_report["items"]["held"], 0);
    assert_eq!(status_report["schedule"]["overdue"], false);

    let inspect = run_job(&isolated.url, inspect_args(&fixture, "submissions/missing")).await;
    assert!(
        inspect.status.success(),
        "fresh inspect failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_report: Value =
        serde_json::from_slice(&inspect.stdout).expect("inspect prints JSON");
    assert_eq!(inspect_report["found"], false);
    assert_eq!(inspect_report["key"], "submissions/missing");

    let preview = run_job(&isolated.url, job_args("pass", &fixture, &["--dry-run"])).await;
    assert!(
        preview.status.success(),
        "fresh dry run failed: {}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview_report: Value =
        serde_json::from_slice(&preview.stdout).expect("dry run prints JSON");
    assert_eq!(preview_report["dryRun"], true);
    assert_eq!(preview_report["itemsRead"], 2);
    assert_eq!(table_rows(&isolated.pool, "adapter_job_state").await, 0);
    assert_eq!(table_rows(&isolated.pool, "adapter_job_items").await, 0);
    let client = isolated.pool.get().await.expect("a pooled client");
    assert_eq!(applied_versions(&client).await, vec![100, 101, 102, 103]);
}

/// Status is a read: it reports a job with no state row and writes none.
#[tokio::test]
async fn status_reads_without_writing_the_state_row() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let isolated = isolated().await;
    let output = run_job(&isolated.url, job_args("status", &fixture, &[])).await;
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let client = isolated.pool.get().await.expect("a pooled client");
    assert!(
        store::read_state(&client, "case-daily")
            .await
            .expect("the state row reads")
            .is_none(),
        "status wrote no state row"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("status prints JSON");
    assert_eq!(
        report.pointer("/schedule/overdue"),
        Some(&json!(false)),
        "a never-run job is due now, not overdue"
    );
}

/// Once a job has run, status distinguishes an interval whose due time
/// passed from a fresh job whose first pass is merely due now.
#[tokio::test]
async fn status_reports_an_existing_late_job_overdue() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let isolated = isolated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    client
        .execute(
            "UPDATE adapter_job_state SET last_pass_at = now() - interval '2 minutes' \
             WHERE job_id = 'case-daily'",
            &[],
        )
        .await
        .expect("the job becomes late");
    drop(client);

    let output = run_job(&isolated.url, job_args("status", &fixture, &[])).await;
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("status prints JSON");
    assert_eq!(
        report.pointer("/schedule/overdue"),
        Some(&json!(true)),
        "the existing job is overdue after two minutes"
    );
}

/// Aggregate status names every hold without pretending it knows an
/// item's destination reference or offering an Adapter-side release.
#[tokio::test]
async fn status_explains_aggregate_holds_without_promising_release() {
    let fixture = JobFixture::start_direct_breg(
        vec![(200, reply_page())],
        "http://127.0.0.1:9",
        "http://127.0.0.1:9/token",
    )
    .await;
    let isolated = isolated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    for (key, code) in [
        ("submissions/a", "idempotency.expired"),
        ("submissions/b", "idempotency.expired"),
        ("submissions/c", "adapter.job.breg-receipt-horizon"),
        ("submissions/d", "adapter.job.rabbitmq-event-changed"),
    ] {
        client
            .execute(
                "INSERT INTO adapter_job_items \
                 (job_id, item_key, last_digest, sequence, status, code, run_id, prior_run_id, \
                  admitted_before, first_seen, last_seen, event_time, delivery_attempt, \
                  receiver_identity_known) \
                 VALUES ('case-daily', $1, $2, 1, 'held', $3, NULL, NULL, true, now(), now(), \
                         now(), 1, true)",
                &[&key, &format!("sha256:{}", "0".repeat(64)), &code],
            )
            .await
            .expect("the value-free held row inserts");
    }
    drop(client);

    let output = run_job(&isolated.url, job_args("status", &fixture, &[])).await;
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("status prints JSON");
    assert_eq!(report.pointer("/items/held"), Some(&json!(4)));
    assert_eq!(
        report.pointer("/holdsByCode/idempotency.expired"),
        Some(&json!(2))
    );
    assert_eq!(
        report.pointer("/holdsByCode/adapter.job.breg-receipt-horizon"),
        Some(&json!(1))
    );
    assert_eq!(
        report.pointer("/holdsByCode/adapter.job.rabbitmq-event-changed"),
        Some(&json!(1))
    );
    let guidance = report["holdGuidance"]
        .as_array()
        .expect("status prints aggregate hold guidance");
    assert_eq!(guidance.len(), 3);
    for (code, count, owner) in [
        ("idempotency.expired", 2, "breg"),
        ("adapter.job.breg-receipt-horizon", 1, "breg"),
        ("adapter.job.rabbitmq-event-changed", 1, "broker-operator"),
    ] {
        let item = guidance
            .iter()
            .find(|item| item["code"] == code)
            .unwrap_or_else(|| panic!("status explains {code}"));
        assert_eq!(item["count"], count);
        assert_eq!(item["actionOwner"], owner);
        assert_eq!(item["destinationReference"], Value::Null);
        let action = item["nextAction"]
            .as_str()
            .expect("the aggregate guidance names an action");
        assert!(action.contains("Use inspect on each held item"));
        assert!(!action.contains("referenced"));
        assert!(!action.contains("retry"));
        if code == "adapter.job.rabbitmq-event-changed" {
            assert!(action.contains("destination's own authority"));
            assert!(action.contains("broker operator"));
            assert!(action.contains("under approved broker policy"));
            assert!(action.contains("publisher/source operator"));
            assert!(action.contains("legitimate future work"));
            assert!(action.contains("Do not rekey uncertain or already accepted work"));
            assert!(action.contains("Publishing a new message ID alone does not clear"));
            assert!(action.contains("Adapter keeps the row held"));
            assert!(action.contains("does not acknowledge or release it"));
            assert!(action.contains("can block later messages at the queue head"));
            assert!(!action.contains("remains head-blocking"));
        } else {
            assert!(action.contains("under BReg's own authority"));
            assert!(action.contains("keeps held items held"));
            assert!(action.contains("unchanged rescans skip them"));
        }
    }
}

/// Inspect derives recovery ownership from the authored destination and
/// prints only the stored destination reference plus static guidance.
#[tokio::test]
async fn inspect_explains_direct_and_coordinator_holds_without_item_values() {
    let coordinator = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let direct = JobFixture::start_direct_breg(
        vec![(200, reply_page())],
        "http://127.0.0.1:9",
        "http://127.0.0.1:9/token",
    )
    .await;

    for (fixture, code, run_id, prior_run_id, owner, reference, authority) in [
        (
            &direct,
            "idempotency.expired",
            Some("proposal-a"),
            None,
            "breg",
            Some("proposal-a"),
            "BReg's own authority",
        ),
        (
            &direct,
            "adapter.job.breg-receipt-horizon",
            None,
            None,
            "breg",
            None,
            "BReg's own authority",
        ),
        (
            &coordinator,
            "adapter.job.revised-item",
            None,
            Some("run-a"),
            "coordinator",
            Some("run-a"),
            "Coordinator's own authority",
        ),
    ] {
        let isolated = isolated().await;
        let client = isolated.pool.get().await.expect("a pooled client");
        client
            .execute(
                "INSERT INTO adapter_job_items \
                 (job_id, item_key, last_digest, sequence, status, code, run_id, prior_run_id, \
                  admitted_before, first_seen, last_seen, event_time, delivery_attempt, \
                  receiver_identity_known) \
                 VALUES ('case-daily', 'submissions/a', $1, 2, 'held', $2, $3, $4, true, \
                         now(), now(), now(), 1, true)",
                &[
                    &format!("sha256:{}", "0".repeat(64)),
                    &code,
                    &run_id,
                    &prior_run_id,
                ],
            )
            .await
            .expect("the value-free held row inserts");
        drop(client);
        let output = run_job(
            &isolated.url,
            vec![
                "inspect".into(),
                fixture.job.clone().into(),
                "--runtime".into(),
                fixture.runtime.clone().into(),
                "--key".into(),
                "submissions/a".into(),
            ],
        )
        .await;
        assert!(
            output.status.success(),
            "inspect failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("inspect prints JSON");
        assert_eq!(report.pointer("/item/hold/code"), Some(&json!(code)));
        assert_eq!(
            report.pointer("/item/hold/destinationReference"),
            Some(&json!(reference))
        );
        assert_eq!(
            report.pointer("/item/hold/actionOwner"),
            Some(&json!(owner))
        );
        let action = report
            .pointer("/item/hold/nextAction")
            .and_then(Value::as_str)
            .filter(|action| !action.is_empty())
            .expect("inspect names an operator action");
        assert!(action.contains(authority));
        assert!(action.contains("keeps this item held"));
        assert!(action.contains("unchanged rescans skip it"));
        assert!(!action.contains("retry"));
        if reference.is_none() {
            assert!(action.contains("No destination reference is established"));
            assert!(action.contains("admission"));
            assert!(action.contains("idempotency records"));
        }
        let rendered = serde_json::to_string(&report).expect("the report renders");
        assert!(!rendered.contains("never-projected"));
        assert!(!rendered.contains("mark-accepted"));
    }
}

/// A dry run never migrates: an unmigrated store refuses it with the
/// migration named, and the store stays untouched.
#[tokio::test]
async fn a_dry_run_refuses_an_unmigrated_store_without_migrating_it() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let isolated = unmigrated().await;
    for command in ["pass", "rescan"] {
        let output = run_job(&isolated.url, job_args(command, &fixture, &["--dry-run"])).await;
        assert!(!output.status.success(), "{command} --dry-run refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("init-store"),
            "{command} --dry-run names the store bootstrap: {stderr}"
        );
    }
    assert!(
        !table_present(&isolated.pool, "adapter_job_schema_migrations").await,
        "the dry run created no migration table"
    );
    assert!(!table_present(&isolated.pool, "adapter_job_state").await);
}

/// Status and inspect remain reads on an uninitialized store. They refuse
/// with the explicit bootstrap recovery and create no migration or job table.
#[tokio::test]
async fn status_and_inspect_name_init_store_without_bootstrapping() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let isolated = unmigrated().await;
    for (command, args) in [
        ("status", job_args("status", &fixture, &[])),
        ("inspect", inspect_args(&fixture, "submissions/missing")),
    ] {
        let output = run_job(&isolated.url, args).await;
        assert!(!output.status.success(), "uninitialized {command} refuses");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("init-store"),
            "{command} names the store bootstrap: {stderr}"
        );
    }
    for table in [
        "adapter_job_schema_migrations",
        "adapter_job_state",
        "adapter_job_items",
    ] {
        assert!(
            !table_present(&isolated.pool, table).await,
            "{table} was not created by an observational command"
        );
    }
}

/// A dry run refuses a store behind this release's schema, and runs
/// over a current one.
#[tokio::test]
async fn a_dry_run_reads_only_a_store_at_this_release_schema() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let isolated = isolated().await;
    let output = run_job(&isolated.url, job_args("pass", &fixture, &["--dry-run"])).await;
    assert!(
        output.status.success(),
        "a dry run over a current store runs: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let client = isolated.pool.get().await.expect("a pooled client");
    client
        .batch_execute("DELETE FROM adapter_job_schema_migrations WHERE version = 103")
        .await
        .expect("the version row deletes");
    let output = run_job(&isolated.url, job_args("pass", &fixture, &["--dry-run"])).await;
    assert!(
        !output.status.success(),
        "a store behind the release refuses"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("init-store"),
        "the refusal names the store bootstrap: {stderr}"
    );
    assert_eq!(
        applied_versions(&client).await,
        vec![100, 101, 102],
        "the dry run applied nothing"
    );
}

/// An operator rescan never moves the traversal of a pass that holds
/// the lease.
#[tokio::test]
async fn a_rescan_refuses_while_a_pass_holds_the_lease() {
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page())],
        job_fixture::Edits::Rescan(3600),
    )
    .await;
    let isolated = isolated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    client
        .batch_execute(
            "UPDATE adapter_job_state SET rescan_active = true, last_rescan_at = now(), \
             position = '\"page-2\"'::jsonb WHERE job_id = 'case-daily'",
        )
        .await
        .expect("the traversal is in progress");
    store::take_lease(&client, "case-daily", Duration::from_secs(600))
        .await
        .expect("the lease writes")
        .expect("the lease grants");
    let before = state(&isolated.pool, "case-daily").await;
    let output = run_job(
        &isolated.url,
        job_args(
            "rescan",
            &fixture,
            &["--fixture", "--fixture-url", "http://127.0.0.1:9/"],
        ),
    )
    .await;
    assert!(!output.status.success(), "the rescan refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lease"),
        "the refusal names the lease: {stderr}"
    );
    let after = state(&isolated.pool, "case-daily").await;
    assert!(after.rescan_active, "the traversal stays active");
    assert_eq!(after.last_rescan_at, before.last_rescan_at);
    assert_eq!(after.position, before.position);
    assert_eq!(after.lease_expires, before.lease_expires);
}

/// Recording an answer for a row that is not there refuses, inside the
/// same transaction as the lease renewal.
#[tokio::test]
async fn recording_an_answer_for_a_missing_row_refuses() {
    let isolated = isolated().await;
    let mut client = isolated.pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    let leased = store::take_lease(&client, "case-daily", Duration::from_secs(600))
        .await
        .expect("the lease writes")
        .expect("the lease grants");
    let ttl = Duration::from_secs(600);
    store::record_acknowledged(
        &mut client,
        "case-daily",
        "submissions/missing",
        Some("run-1"),
        SystemTime::now(),
        leased.token,
        ttl,
    )
    .await
    .expect_err("an acknowledgement for a missing row refuses");
    store::record_refused(
        &mut client,
        "case-daily",
        "submissions/missing",
        "schema.required",
        SystemTime::now(),
        leased.token,
        ttl,
    )
    .await
    .expect_err("a refusal for a missing row refuses");
}

/// A lease a newer grant replaced fences every write: the old holder's
/// token refuses on stage, record, complete, and stop, and the new
/// holder's token writes.
#[tokio::test]
async fn a_stale_lease_epoch_refuses_every_fenced_write() {
    let isolated = isolated().await;
    let mut client = isolated.pool.get().await.expect("a pooled client");
    let ttl = Duration::from_secs(600);
    store::ensure_state(&client, "case-daily")
        .await
        .expect("the state row exists");
    let first = store::take_lease(&client, "case-daily", ttl)
        .await
        .expect("the lease writes")
        .expect("the first lease grants");
    client
        .batch_execute(
            "UPDATE adapter_job_state SET lease_expires = now() - interval '1 second' \
             WHERE job_id = 'case-daily'",
        )
        .await
        .expect("the first lease expires");
    let second = store::take_lease(&client, "case-daily", ttl)
        .await
        .expect("the lease writes")
        .expect("the second lease grants");
    assert_ne!(first.token, second.token);
    let digest = format!("sha256:{}", "a".repeat(64));
    store::stage_item(
        &mut client,
        "case-daily",
        "submissions/a",
        &digest,
        false,
        SystemTime::now(),
        second.token,
        ttl,
    )
    .await
    .expect("the current holder stages")
    .expect("a new item delivers");
    let stale = first.token;
    let lost = |result: Result<(), store::StoreError>, what: &str| match result {
        Err(store::StoreError::LeaseLost) => {}
        other => panic!("{what} under a stale epoch refuses as a lost lease: {other:?}"),
    };
    match store::stage_item(
        &mut client,
        "case-daily",
        "submissions/b",
        &digest,
        false,
        SystemTime::now(),
        stale,
        ttl,
    )
    .await
    {
        Err(store::StoreError::LeaseLost) => {}
        other => panic!("stage under a stale epoch refuses as a lost lease: {other:?}"),
    }
    lost(
        store::record_acknowledged(
            &mut client,
            "case-daily",
            "submissions/a",
            Some("run-1"),
            SystemTime::now(),
            stale,
            ttl,
        )
        .await,
        "record_acknowledged",
    );
    lost(
        store::record_refused(
            &mut client,
            "case-daily",
            "submissions/a",
            "schema.required",
            SystemTime::now(),
            stale,
            ttl,
        )
        .await,
        "record_refused",
    );
    lost(
        store::record_held(
            &mut client,
            "case-daily",
            "submissions/a",
            "idempotency.expired",
            None,
            SystemTime::now(),
            stale,
            ttl,
        )
        .await,
        "record_held",
    );
    lost(
        store::complete_pass(
            &client,
            "case-daily",
            stale,
            None,
            false,
            store::RescanProgress::None,
            SystemTime::now(),
        )
        .await,
        "complete_pass",
    );
    lost(
        store::stop_pass(
            &client,
            "case-daily",
            stale,
            "lease-held",
            SystemTime::now(),
        )
        .await,
        "stop_pass",
    );
    let row = item(&isolated.pool, "submissions/a")
        .await
        .expect("the staged row");
    assert_eq!(row.status, ItemStatus::Pending, "no stale write landed");
    store::record_acknowledged(
        &mut client,
        "case-daily",
        "submissions/a",
        Some("run-1"),
        SystemTime::now(),
        second.token,
        ttl,
    )
    .await
    .expect("the current holder records");
    store::complete_pass(
        &client,
        "case-daily",
        second.token,
        None,
        false,
        store::RescanProgress::None,
        SystemTime::now(),
    )
    .await
    .expect("the current holder completes");
}

/// Take the lease on a fresh state row, for the position tests.
async fn leased(client: &deadpool_postgres::Object) -> i64 {
    store::ensure_state(client, "case-daily")
        .await
        .expect("the state row exists");
    store::take_lease(client, "case-daily", Duration::from_secs(600))
        .await
        .expect("the lease writes")
        .expect("the lease grants")
        .token
}

/// The position bound is the engine's compact one: a cursor the engine
/// accepted saves even when PostgreSQL's jsonb text of it runs longer.
#[tokio::test]
async fn a_position_within_the_engine_bound_saves_whatever_its_jsonb_text_length() {
    let isolated = isolated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    let token = leased(&client).await;
    let members: serde_json::Map<String, Value> = (0..220)
        .map(|index| (format!("k{index:03}"), json!(0)))
        .collect();
    let position = Value::Object(members);
    let compact = serde_json::to_vec(&position).expect("renders").len();
    assert!(
        compact <= registry_adapter_core::MAXIMUM_NEXT_BYTES,
        "the cursor is within the engine bound: {compact}"
    );
    store::complete_pass(
        &client,
        "case-daily",
        token,
        Some(&position),
        false,
        store::RescanProgress::None,
        SystemTime::now(),
    )
    .await
    .expect("a cursor within the engine bound saves");
    assert_eq!(
        state(&isolated.pool, "case-daily").await.position,
        Some(position)
    );
}

/// A position over the engine bound refuses under its own error.
#[tokio::test]
async fn a_position_over_the_engine_bound_refuses() {
    let isolated = isolated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    let token = leased(&client).await;
    let position = json!("p".repeat(2100));
    match store::complete_pass(
        &client,
        "case-daily",
        token,
        Some(&position),
        false,
        store::RescanProgress::None,
        SystemTime::now(),
    )
    .await
    {
        Err(store::StoreError::PositionBound { .. }) => {}
        other => panic!("an over-bound cursor refuses under its own error: {other:?}"),
    }
    assert_eq!(state(&isolated.pool, "case-daily").await.position, None);
}

/// A destination that replaces the pass's lease while it answers, then
/// stops the pass: the stop can no longer be recorded.
struct LeaseStealer {
    pool: Pool,
}

impl JobDestination for LeaseStealer {
    fn deliver<'a>(
        &'a self,
        _job: &'a JobIdentity,
        _item: &'a DeliverableItem,
    ) -> Pin<Box<dyn Future<Output = HandOffOutcome> + Send + 'a>> {
        Box::pin(async move {
            let client = self.pool.get().await.expect("a pooled client");
            client
                .batch_execute(
                    "UPDATE adapter_job_state SET lease_epoch = lease_epoch + 1 \
                     WHERE job_id = 'case-daily'",
                )
                .await
                .expect("the lease is replaced");
            HandOffOutcome::StopPass {
                code: "auth.rejected".to_string(),
            }
        })
    }
}

/// A stop the store refuses to record is reported, never dropped.
#[tokio::test]
async fn a_stop_the_store_cannot_record_is_reported() {
    let (fixture, pool) = pass_fixture().await;
    let program = compile(&fixture).await;
    let destination = LeaseStealer { pool: pool.clone() };
    let report = run_pass(&pool, &program, &destination, options(20)).await;
    assert_eq!(
        report.stopped,
        Some(StopReason::DestinationStop {
            code: "auth.rejected".to_string()
        })
    );
    let failure = report
        .stop_record_failure
        .expect("the unrecorded stop is reported");
    assert!(
        failure.contains("lease"),
        "the failure names its cause: {failure}"
    );
}

/// A destination answer the item table cannot hold stops the pass under
/// the invalid-answer code, and the stop is recorded.
#[tokio::test]
async fn an_answer_code_over_its_bound_stops_under_the_invalid_answer_code() {
    for outcome in [
        refused(&"x".repeat(300)),
        refused(""),
        HandOffOutcome::StopPass {
            code: "y".repeat(300),
        },
        held(&"z".repeat(300), None),
        held("idempotency.expired", Some(&"r".repeat(300))),
        acknowledged(&"r".repeat(300)),
    ] {
        let (fixture, pool) = pass_fixture().await;
        let program = compile(&fixture).await;
        let destination = ScriptedDestination::script(vec![outcome.clone()]);
        let report = run_pass(&pool, &program, &destination, options(20)).await;
        let invalid = registry_adapter_job::destination::DESTINATION_ANSWER_INVALID;
        assert_eq!(
            report.stopped,
            Some(StopReason::DestinationStop {
                code: invalid.to_string()
            }),
            "{outcome:?} stops under the invalid-answer code"
        );
        assert_eq!(report.stop_record_failure, None);
        let row = state(&pool, "case-daily").await;
        assert_eq!(
            row.last_pass_stop.as_deref(),
            Some(format!("destination-stop:{invalid}").as_str())
        );
        assert_eq!(row.lease_expires, None, "the stop released the lease");
        assert_eq!(
            item(&pool, "submissions/a").await.map(|row| row.status),
            Some(ItemStatus::Pending),
            "the item stays pending for the next pass"
        );
    }
}

/// Status can warn on the last day of BReg's declared receipt horizon and
/// distinguish rows already past it, without reading or storing a payload.
#[tokio::test]
async fn pending_receipt_horizon_counts_are_bounded_and_value_free() {
    let isolated = isolated().await;
    let client = isolated.pool.get().await.expect("a pooled client");
    store::ensure_state(&client, "receipt-job")
        .await
        .expect("the state row exists");
    let now = UNIX_EPOCH + Duration::from_secs(20 * 86_400);
    for (key, age) in [
        ("near", 6 * 86_400 + 43_200),
        ("expired", 8 * 86_400),
        ("fresh", 2 * 86_400),
    ] {
        let first_seen = now - Duration::from_secs(age);
        client
            .execute(
                "INSERT INTO adapter_job_items \
                 (job_id, item_key, last_digest, sequence, status, first_seen, last_seen, \
                  event_time, delivery_attempt, receiver_identity_known) \
                 VALUES ('receipt-job', $1, $2, 1, 'pending', $3, $3, $3, 1, true)",
                &[&key, &format!("sha256:{}", "0".repeat(64)), &first_seen],
            )
            .await
            .expect("the pending row inserts");
    }
    let counts = store::receipt_horizon_counts(&client, "receipt-job", now, 7)
        .await
        .expect("the horizon counts read");
    assert_eq!(counts.nearing, 1);
    assert_eq!(counts.expired, 1);
}

/// The owned synthetic operator journey: the default command runs one page,
/// while `pass --loop` honours its initial and fixed delays from PostgreSQL
/// state, runs a second page, and accepts SIGINT while waiting without any
/// later source read or destination hand-off.
#[tokio::test]
async fn actual_cli_interval_loop_runs_two_persisted_passes_and_stops_cleanly() {
    // First hold the default: absent --loop, one child runs one bounded page
    // even though the source has another page available.
    let bounded_fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page()), (200, reply_page_end())],
        job_fixture::Edits::Ordered,
    )
    .await;
    let bounded_store = isolated().await;
    let bounded_receiver = FixtureReceiver::start(vec![
        Scripted::Acknowledge {
            run_id: Some("bounded-a".to_string()),
        },
        Scripted::Acknowledge {
            run_id: Some("bounded-b".to_string()),
        },
    ])
    .await;
    let bounded = run_job(
        &bounded_store.url,
        fixture_pass_args(&bounded_fixture, &bounded_receiver),
    )
    .await;
    assert_value_free_output("bounded pass", &bounded);
    assert!(bounded.status.success(), "the bounded pass failed");
    let bounded_report: Value =
        serde_json::from_slice(&bounded.stdout).expect("the bounded pass prints one JSON report");
    assert_eq!(bounded_report["itemsRead"], 2);
    assert_eq!(
        bounded_fixture.double.requests().len(),
        1,
        "the default pass reads exactly one page"
    );
    assert_eq!(bounded_receiver.requests().len(), 2);

    // Then run the actual long-lived operator command on a fresh store. Two
    // distinct pages make both scheduled passes externally observable.
    let fixture = JobFixture::start(
        job_fixture::PAGE_SCRIPT,
        vec![(200, reply_page()), (200, reply_page_end())],
        job_fixture::Edits::Ordered,
    )
    .await;
    set_acceptance_interval(&fixture);
    let isolated = isolated().await;
    let receiver = FixtureReceiver::start(vec![
        Scripted::Acknowledge {
            run_id: Some("loop-a".to_string()),
        },
        Scripted::Acknowledge {
            run_id: Some("loop-b".to_string()),
        },
        Scripted::Acknowledge {
            run_id: Some("loop-c".to_string()),
        },
    ])
    .await;
    let mut args = fixture_pass_args(&fixture, &receiver);
    args.push("--loop".into());
    let child_started = SystemTime::now();
    let mut child = ManagedChild::spawn(&isolated.url, args);

    let first = wait_for_persisted_pass(&mut child, &isolated.pool, None).await;
    assert!(
        first.duration_since(child_started).unwrap_or_default() >= Duration::from_secs(1),
        "the first pass cannot precede the declared one-second initial delay"
    );
    assert_eq!(fixture.double.requests().len(), 1);
    assert_eq!(receiver.requests().len(), 2);

    let second = wait_for_persisted_pass(&mut child, &isolated.pool, Some(first)).await;
    assert!(
        second.duration_since(first).unwrap_or_default() >= Duration::from_secs(3),
        "the second pass cannot precede the declared three-second fixed delay"
    );
    assert_eq!(fixture.double.requests().len(), 2);
    assert_eq!(receiver.requests().len(), 3);
    assert_eq!(state(&isolated.pool, "case-daily").await.position, None);

    // The persisted completion precedes the process returning to its wait.
    // Give that short control path room, then interrupt well inside the next
    // three-second delay. This avoids any startup or pass-duration upper bound.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(fixture.double.requests().len(), 2);
    assert_eq!(receiver.requests().len(), 3);
    child.interrupt();
    wait_for_clean_exit(&mut child).await;
    let loop_output = child.output();
    assert_value_free_output("interval loop", &loop_output);
    assert!(
        loop_output.status.success(),
        "SIGINT during the interval wait was not a clean exit"
    );

    let source_effects = fixture.double.requests().len();
    let destination_effects = receiver.requests().len();
    let persisted_after_exit = state(&isolated.pool, "case-daily").await.last_pass_at;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(fixture.double.requests().len(), source_effects);
    assert_eq!(receiver.requests().len(), destination_effects);
    assert_eq!(
        state(&isolated.pool, "case-daily").await.last_pass_at,
        persisted_after_exit,
        "the exited child creates no later persisted pass"
    );

    // Observational commands read the persisted outcome without source
    // fields, values, or the source-only secret marker.
    let status = run_job(&isolated.url, job_args("status", &fixture, &[])).await;
    assert!(status.status.success(), "status reads the loop's store");
    assert_value_free_output("status", &status);
    let status_report: Value =
        serde_json::from_slice(&status.stdout).expect("status prints one JSON report");
    assert_eq!(status_report["items"]["acknowledged"], 3);

    let inspect = run_job(&isolated.url, inspect_args(&fixture, "submissions/a")).await;
    assert!(inspect.status.success(), "inspect reads the loop's item");
    assert_value_free_output("inspect", &inspect);
    let inspect_report: Value =
        serde_json::from_slice(&inspect.stdout).expect("inspect prints one JSON report");
    assert_eq!(inspect_report["found"], true);
    assert_eq!(inspect_report["item"]["key"], "submissions/a");
    assert_eq!(inspect_report["item"]["status"], "acknowledged");
}
