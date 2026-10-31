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
use registry_adapter_job::pass::{run_pass, PassOptions, PassReport, StopReason};
use registry_adapter_job::store::{self, ItemStatus, StagedItem};
use registry_adapter_job::trigger::{self, Edits, JobState};
use serde_json::{json, Value};
use tokio_postgres::{Config as PgConfig, NoTls};

#[path = "support/job_fixture.rs"]
mod job_fixture;

use job_fixture::{reply_page, reply_page_end, JobFixture};

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);

/// One isolated schema and the pooled client that reaches it.
struct Isolated {
    pool: Pool,
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

async fn isolated() -> Isolated {
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
    let mut scoped = PgConfig::from_str(&format!(
        "{base}{separator}options=-csearch_path%3D{schema}"
    ))
    .expect("parse the scoped adapter job URL");
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
    let client = pool.get().await.expect("a pooled client");
    store::migrate(&client)
        .await
        .expect("the job store migration applies");
    drop(client);
    Isolated { pool }
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
        vec![(200, reply_page())],
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
/// set the concept's table names.
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
        false,
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
    let page = vec![(200, reply_page())];
    let _ = page;
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
        !row.last_rescan_at.is_some(),
        "the gate stamps at the finite end, not the traversal's first page"
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
    job.triggers =
        vec![
            serde_norway::from_str(&serde_json::to_string(&trigger).expect("a trigger renders"))
                .expect("the trigger parses"),
        ];
    job
}

/// One delivered item the assertions reuse.
#[allow(dead_code)]
fn delivered_of(destination: &ScriptedDestination, key: &str) -> Option<StagedItem> {
    destination
        .delivered()
        .into_iter()
        .find(|item| item.key == key)
        .map(|item| StagedItem {
            key: item.key,
            sequence: item.sequence,
            digest: item.digest,
            prior_run_id: item.prior_run_id,
            admitted_before: item.admitted_before,
            classification: registry_adapter_job::store::StagedClassification::New,
        })
}

/// Every pass report the assertions reuse.
#[allow(dead_code)]
fn stopped_of(report: &PassReport) -> Option<&StopReason> {
    report.stopped.as_ref()
}
