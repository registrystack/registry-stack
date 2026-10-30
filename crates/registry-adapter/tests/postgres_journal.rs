// SPDX-License-Identifier: Apache-2.0

//! The audit journal's PostgreSQL suite: the migration, the runtime-clock
//! stamp, and the retention index
//! (`products/adapter/CONCEPT.md` section 11). Every test runs in its own
//! schema inside the database named by `ADAPTER_TEST_DATABASE_URL`; a test
//! binary that passes because its database URL is absent is not database
//! verification, so the variable is required: without it every test in
//! this file fails on the spot.
#![cfg(feature = "postgres-test")]

use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deadpool_postgres::{GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod};
use registry_adapter::journal::{self, JournalError, JournalEvent};
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, Config as PgConfig, NoTls};

/// Slack for comparing a stamped `occurred_at` against the wall clock
/// around the append, generous for clock slew on a loaded test machine.
const STAMP_SLACK: Duration = Duration::from_secs(5);
/// One day, the retention horizon the deletes in this suite test against.
const DAY: Duration = Duration::from_secs(24 * 3600);

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);

/// One isolated schema and the pooled client that reaches it.
struct Isolated {
    pool: Pool,
}

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect the adapter journal test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("the adapter journal test connection failed: {error}");
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
    let schema = format!("adapter_journal_{nanos}_{serial}");
    // The schema exists before any pool connection resolves into it:
    // table creation follows search_path, and the scoped URL below points
    // every pool connection at this schema. The admin connection is not
    // needed once the schema exists; dropping it closes the connection
    // and leaves the committed schema behind.
    let admin = connect(&base).await;
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated adapter journal schema");
    drop(admin);
    let separator = if base.contains('?') { '&' } else { '?' };
    let mut scoped = PgConfig::from_str(&format!(
        "{base}{separator}options=-csearch_path%3D{schema}"
    ))
    .expect("parse the scoped adapter journal URL");
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
        .expect("build the adapter journal test pool");
    Isolated { pool }
}

impl Isolated {
    async fn client(&self) -> deadpool_postgres::Client {
        self.pool
            .get()
            .await
            .expect("a pooled adapter journal client")
    }
}

/// One value-free journal event for the tests to append.
fn event(event_kind: &'static str) -> JournalEvent {
    JournalEvent {
        event_kind,
        exchange_id: "4c5f7c44-9d2e-4f6a-8d21-6b0f5f4f10aa".to_owned(),
        operation: "listRecords".to_owned(),
        caller_ref: "profile:dhis2-reader".to_owned(),
        route_id: "dhis2-records".to_owned(),
        detail: None,
    }
}

/// Assert a journal error is the driver's check violation, naming the
/// constraint that refused the write.
fn expect_check_violation(error: JournalError, what: &'static str) {
    match error {
        JournalError::Query(pg_error) => assert_eq!(
            pg_error.code(),
            Some(&SqlState::CHECK_VIOLATION),
            "{what}: expected a check violation, got {pg_error}"
        ),
        other => panic!("{what}: expected a query error, got {other:?}"),
    }
}

#[tokio::test]
async fn the_migration_creates_the_journal_table_with_the_runtime_clock_column() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    journal::migrate(&client)
        .await
        .expect("the first migration run applies the journal baseline");
    journal::migrate(&client)
        .await
        .expect("a second migration run applies nothing twice");

    let column = client
        .query_one(
            "SELECT data_type, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name = 'adapter_journal_events' \
               AND column_name = 'occurred_at'",
            &[],
        )
        .await
        .expect("read the occurred_at column from the migrated schema");
    assert_eq!(
        column.get::<_, String>("data_type"),
        "timestamp with time zone",
        "occurred_at is a timestamptz"
    );
    assert_eq!(
        column.get::<_, String>("is_nullable"),
        "NO",
        "occurred_at is NOT NULL: every event carries its instant"
    );
    assert_eq!(
        column.get::<_, Option<String>>("column_default"),
        None,
        "occurred_at carries no database default: the runtime clock stamps the event, not the database"
    );

    let index = client
        .query_one(
            "SELECT indexdef FROM pg_indexes \
             WHERE schemaname = current_schema() \
               AND tablename = 'adapter_journal_events' \
               AND indexname = 'adapter_journal_events_occurrence_idx'",
            &[],
        )
        .await
        .expect("read the retention index from the migrated schema");
    assert!(
        index
            .get::<_, String>(0)
            .contains("(occurred_at, event_id)"),
        "the retention index must lead with occurred_at for the deletes and carry event_id for stable batches, got {}",
        index.get::<_, String>(0)
    );
}

#[tokio::test]
async fn append_stamps_occurred_at_from_the_runtime_clock() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    journal::migrate(&client)
        .await
        .expect("apply the journal baseline");

    let append_began = SystemTime::now();
    journal::append(&client, event("exchangeCreated"), SystemTime::now())
        .await
        .expect("append the first journal event");
    journal::append(&client, event("exchangeCompleted"), SystemTime::now())
        .await
        .expect("append the second journal event");
    let append_ended = SystemTime::now();

    let rows = client
        .query(
            "SELECT event_id::text, occurred_at FROM adapter_journal_events",
            &[],
        )
        .await
        .expect("read the appended journal rows");
    assert_eq!(rows.len(), 2);
    assert_ne!(
        rows[0].get::<_, String>(0),
        rows[1].get::<_, String>(0),
        "each event row carries its own generated event_id"
    );
    let earliest = append_began
        .checked_sub(STAMP_SLACK)
        .expect("the stamp window is after the Unix epoch");
    let latest = append_ended
        .checked_add(STAMP_SLACK)
        .expect("the stamp window is representable");
    for row in &rows {
        let occurred_at: SystemTime = row.get(1);
        assert!(
            occurred_at >= earliest && occurred_at <= latest,
            "occurred_at {occurred_at:?} must be the runtime clock's instant at the event, between {earliest:?} and {latest:?}",
        );
    }
}

#[tokio::test]
async fn occurred_at_has_no_database_default_to_fall_back_on() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    journal::migrate(&client)
        .await
        .expect("apply the journal baseline");
    let error = client
        .execute(
            "INSERT INTO adapter_journal_events \
             (event_kind, exchange_id, operation, caller_ref, route_id, detail) \
             VALUES ('exchangeCreated', 'e1', 'listRecords', 'caller', 'route', '{}'::jsonb)",
            &[],
        )
        .await
        .expect_err(
            "an insert without the runtime-clock stamp must fail: occurred_at has no default",
        );
    assert_eq!(
        error.code(),
        Some(&SqlState::NOT_NULL_VIOLATION),
        "a writer that skips the stamp is refused, not silently stamped by the database: {error}"
    );
}

#[tokio::test]
async fn retention_deletes_by_occurred_at_read_the_occurrence_index() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    journal::migrate(&client)
        .await
        .expect("apply the journal baseline");

    journal::append(&client, event("exchangeCreated"), SystemTime::now())
        .await
        .expect("append a current journal event");
    journal::append(&client, event("exchangeCompleted"), SystemTime::now())
        .await
        .expect("append a second current journal event");
    let backdated = SystemTime::now()
        .checked_sub(30 * DAY)
        .expect("the backdated stamp is after the Unix epoch");
    client
        .execute(
            "INSERT INTO adapter_journal_events \
             (event_kind, exchange_id, operation, caller_ref, route_id, occurred_at) \
             VALUES ('exchangeSent', 'e0', 'listRecords', 'caller', 'route', $1)",
            &[&backdated],
        )
        .await
        .expect("a backdated row exercises retention");
    let cutoff = SystemTime::now()
        .checked_sub(DAY)
        .expect("the retention cutoff is after the Unix epoch");

    // The index must serve the retention predicate: with sequential scans
    // priced out, the delete plan reads the occurrence index.
    let mut planner = isolated.client().await;
    let transaction = planner
        .transaction()
        .await
        .expect("open the plan-only transaction");
    transaction
        .batch_execute("SET LOCAL enable_seqscan = off")
        .await
        .expect("price out sequential scans for the plan check");
    let plan = transaction
        .query(
            "EXPLAIN (COSTS OFF) DELETE FROM adapter_journal_events WHERE occurred_at < $1",
            &[&cutoff],
        )
        .await
        .expect("explain the retention delete");
    let plan_text = plan
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        plan_text.contains("adapter_journal_events_occurrence_idx"),
        "the retention delete must read the occurrence index, got plan:\n{plan_text}"
    );
    transaction
        .rollback()
        .await
        .expect("close the plan-only transaction without writing");

    let deleted = client
        .execute(
            "DELETE FROM adapter_journal_events WHERE occurred_at < $1",
            &[&cutoff],
        )
        .await
        .expect("run the retention delete");
    assert_eq!(
        deleted, 1,
        "retention deletes exactly the rows older than the cutoff"
    );
    let remaining: i64 = client
        .query_one("SELECT count(*) FROM adapter_journal_events", &[])
        .await
        .expect("count the remaining journal rows")
        .get(0);
    assert_eq!(
        remaining, 2,
        "rows at or after the cutoff survive retention"
    );
}

#[tokio::test]
async fn journal_rows_refuse_updates_and_delete_only_whole_for_retention() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    journal::migrate(&client)
        .await
        .expect("apply the journal baseline");
    journal::append(&client, event("exchangeCreated"), SystemTime::now())
        .await
        .expect("append the journal event");

    let error = client
        .execute(
            "UPDATE adapter_journal_events SET operation = 'rewritten'",
            &[],
        )
        .await
        .expect_err("a journal row must refuse updates: rows are append-only");
    assert_eq!(
        error.code(),
        Some(&SqlState::CHECK_VIOLATION),
        "the append-only trigger refuses with a check violation: {error}"
    );
    let kept: i64 = client
        .query_one("SELECT count(*) FROM adapter_journal_events", &[])
        .await
        .expect("count the journal rows after the refused update")
        .get(0);
    assert_eq!(kept, 1, "the refused update leaves the row untouched");

    let horizon = SystemTime::now()
        .checked_add(DAY)
        .expect("the retention horizon is representable");
    let deleted = client
        .execute(
            "DELETE FROM adapter_journal_events WHERE occurred_at < $1",
            &[&horizon],
        )
        .await
        .expect("run the retention delete");
    assert_eq!(deleted, 1, "retention deletes the row whole");
}

#[tokio::test]
async fn the_journal_refuses_unknown_kinds_and_oversized_details() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    journal::migrate(&client)
        .await
        .expect("apply the journal baseline");

    let error = client
        .execute(
            "INSERT INTO adapter_journal_events \
             (event_kind, exchange_id, operation, caller_ref, route_id, occurred_at) \
             VALUES ('exchangeUnknown', 'e1', 'listRecords', 'caller', 'route', $1)",
            &[&SystemTime::now()],
        )
        .await
        .expect_err("the journal only holds the closed Camel event kinds");
    assert_eq!(
        error.code(),
        Some(&SqlState::CHECK_VIOLATION),
        "an unknown event kind is refused: {error}"
    );

    let oversized = format!("{{\"reason\": \"{}\"}}", "x".repeat(20000));
    let error = journal::append(
        &client,
        JournalEvent {
            detail: Some(oversized),
            ..event("exchangeSent")
        },
        SystemTime::now(),
    )
    .await
    .expect_err("a journal row's detail is bounded");
    expect_check_violation(error, "the oversized detail");
}

#[tokio::test]
async fn upgrading_a_version_100_journal_keeps_its_rows_and_accepts_refused_calls() {
    let isolated = isolated().await;
    let client = isolated.client().await;
    client
        .batch_execute(
            "CREATE TABLE adapter_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await
        .expect("create the migration ledger");
    client
        .batch_execute(include_str!("../src/journal/migrations/0100_journal.sql"))
        .await
        .expect("apply the first journal schema by hand");
    client
        .execute(
            "INSERT INTO adapter_schema_migrations (version, applied_at) VALUES (100, now())",
            &[],
        )
        .await
        .expect("record version 100");
    journal::append(&client, event("exchangeCreated"), SystemTime::now())
        .await
        .expect("a version 100 journal takes its own kinds");
    let error = journal::append(&client, event("callRefused"), SystemTime::now())
        .await
        .expect_err("version 100 does not know callRefused");
    expect_check_violation(error, "callRefused before the upgrade");

    journal::migrate(&client)
        .await
        .expect("the upgrade applies over existing rows");

    journal::append(&client, event("callRefused"), SystemTime::now())
        .await
        .expect("version 200 accepts callRefused");
    let rows = client
        .query(
            "SELECT event_kind FROM adapter_journal_events ORDER BY 1",
            &[],
        )
        .await
        .expect("read the journal");
    let kinds: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
    assert_eq!(kinds, ["callRefused", "exchangeCreated"]);
}
