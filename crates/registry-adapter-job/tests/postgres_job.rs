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
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter::engine::job::compile_job;
use registry_adapter_core::{AdapterJob, JobIdentity};
use registry_adapter_job::destination::{
    DeliverableItem, HandOffOutcome, JobDestination, NullDestination,
};
use registry_adapter_job::pass::{run_pass, PassOptions, StopReason};
use registry_adapter_job::store::{self, ItemStatus};
use registry_adapter_job::trigger::{self, JobState};
use serde_json::{json, Value};
use tokio_postgres::{Config as PgConfig, NoTls};

#[path = "support/job_fixture.rs"]
mod job_fixture;

use job_fixture::{reply_page, reply_page_end, JobFixture};

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);

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

async fn compile(fixture: &JobFixture) -> registry_adapter::engine::job::JobProgram {
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
        ("first_seen", "timestamp with time zone"),
        ("item_key", "text"),
        ("job_id", "text"),
        ("last_digest", "text"),
        ("last_seen", "timestamp with time zone"),
        ("prior_run_id", "text"),
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
    let items = registry_adapter::engine::job::run_job_page(&program, None)
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
            code: "adapter.job.page-key".to_string()
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
    assert_eq!(applied_versions(&client).await, vec![100, 101]);
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
            stderr.contains("without --dry-run"),
            "{command} --dry-run names the missing migration: {stderr}"
        );
    }
    assert!(
        !table_present(&isolated.pool, "adapter_job_schema_migrations").await,
        "the dry run created no migration table"
    );
    assert!(!table_present(&isolated.pool, "adapter_job_state").await);
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
        .batch_execute("DELETE FROM adapter_job_schema_migrations WHERE version = 101")
        .await
        .expect("the version row deletes");
    let output = run_job(&isolated.url, job_args("pass", &fixture, &["--dry-run"])).await;
    assert!(
        !output.status.success(),
        "a store behind the release refuses"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("without --dry-run"),
        "the refusal names the migration: {stderr}"
    );
    assert_eq!(
        applied_versions(&client).await,
        vec![100],
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
