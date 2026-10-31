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

#[tokio::test]
async fn readiness_requires_the_exact_migration_set_and_journal_table() {
    let database = isolated().await;
    let mut client = database.client().await;
    journal::migrate(&mut client)
        .await
        .expect("the journal migrates");
    assert!(journal::ready(&client)
        .await
        .expect("the ledger is readable"));

    client
        .execute(
            "DELETE FROM adapter_schema_migrations WHERE version = 100",
            &[],
        )
        .await
        .expect("simulate a missing baseline below the unchanged maximum");
    assert!(!journal::ready(&client)
        .await
        .expect("the ledger is readable"));
    client
        .execute("INSERT INTO adapter_schema_migrations(version, applied_at) VALUES (100, now()), (250, now())", &[])
        .await
        .expect("restore the baseline and add an unknown intermediate version");
    assert!(!journal::ready(&client)
        .await
        .expect("the ledger is readable"));
    client
        .execute(
            "DELETE FROM adapter_schema_migrations WHERE version = 250",
            &[],
        )
        .await
        .expect("restore the supported exact migration set");
    assert!(journal::ready(&client)
        .await
        .expect("the ledger is readable"));
    client
        .batch_execute("ALTER TABLE adapter_journal_events RENAME TO unavailable_journal_events")
        .await
        .expect("simulate a missing journal table");
    assert!(!journal::ready(&client)
        .await
        .expect("the ledger is still readable"));
}

#[tokio::test]
async fn an_interrupted_migration_commits_neither_its_schema_nor_its_ledger_row() {
    let database = isolated().await;
    let mut client = database.client().await;
    // A ledger that refuses the baseline's version row stands in for a
    // startup interrupted between a schema change and its ledger insert.
    client
        .batch_execute(
            "CREATE TABLE adapter_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL);\
             CREATE FUNCTION interrupt_the_ledger() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN RAISE EXCEPTION 'interrupted before the ledger row committed'; END; $$;\
             CREATE TRIGGER interrupt_the_ledger BEFORE INSERT ON adapter_schema_migrations \
             FOR EACH ROW EXECUTE FUNCTION interrupt_the_ledger();",
        )
        .await
        .expect("install the interrupting ledger");
    journal::migrate(&mut client)
        .await
        .expect_err("a ledger row that never commits fails the migration");
    let table: Option<String> = client
        .query_one("SELECT to_regclass('adapter_journal_events')::text", &[])
        .await
        .expect("look up the journal table")
        .get(0);
    assert_eq!(
        table, None,
        "a migration whose ledger row did not commit leaves no schema change behind"
    );

    client
        .batch_execute("DROP TRIGGER interrupt_the_ledger ON adapter_schema_migrations")
        .await
        .expect("end the interruption");
    journal::migrate(&mut client)
        .await
        .expect("the next startup applies the whole migration set");
    assert!(journal::ready(&client)
        .await
        .expect("the ledger is readable"));
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
    let mut client = isolated.client().await;
    journal::migrate(&mut client)
        .await
        .expect("the first migration run applies the journal baseline");
    journal::migrate(&mut client)
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
    let mut client = isolated.client().await;
    journal::migrate(&mut client)
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
    let mut client = isolated.client().await;
    journal::migrate(&mut client)
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
    let mut client = isolated.client().await;
    journal::migrate(&mut client)
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
async fn retention_deletes_expired_rows_in_bounded_oldest_first_batches() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
    journal::migrate(&mut client)
        .await
        .expect("apply the journal baseline");
    let batch = i64::from(journal::MAX_RETENTION_BATCH);
    let now = SystemTime::now();
    let expired_at = now
        .checked_sub(30 * DAY)
        .expect("the expired stamp is after the Unix epoch");
    let kept_at = now
        .checked_sub(DAY / 2)
        .expect("the kept stamp is after the Unix epoch");
    client
        .execute(
            "INSERT INTO adapter_journal_events \
             (event_kind, exchange_id, operation, caller_ref, route_id, occurred_at) \
             SELECT 'exchangeSent', 'e' || n, 'listRecords', 'caller', 'route', \
                    $1::timestamptz + n * interval '1 millisecond' \
             FROM generate_series(1, $2::bigint + 1) AS n",
            &[&expired_at, &batch],
        )
        .await
        .expect("seed one more expired row than a batch holds");
    journal::append(&client, event("exchangeCreated"), kept_at)
        .await
        .expect("append a row inside the retention window");
    let cutoff = now.checked_sub(DAY).expect("the cutoff is representable");

    let first = journal::delete_expired(&client, cutoff)
        .await
        .expect("the first retention batch runs");
    assert_eq!(
        first,
        u64::from(journal::MAX_RETENTION_BATCH),
        "one batch deletes at most its bound"
    );
    let survivor: String = client
        .query_one(
            "SELECT exchange_id FROM adapter_journal_events \
             WHERE occurred_at < $1",
            &[&cutoff],
        )
        .await
        .expect("exactly one expired row outlives the first batch")
        .get(0);
    assert_eq!(
        survivor,
        format!("e{}", batch + 1),
        "the batch deletes the oldest rows first"
    );

    let second = journal::delete_expired(&client, cutoff)
        .await
        .expect("the second retention batch runs");
    assert_eq!(second, 1, "the second batch drains the remainder");
    let third = journal::delete_expired(&client, cutoff)
        .await
        .expect("an empty retention batch runs");
    assert_eq!(third, 0, "nothing older than the cutoff remains");
    let kept: Vec<String> = client
        .query("SELECT event_kind FROM adapter_journal_events", &[])
        .await
        .expect("read the surviving rows")
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        kept,
        ["exchangeCreated"],
        "a row inside the retention window survives"
    );
}

#[tokio::test]
async fn the_runtime_role_needs_insert_select_and_delete_on_the_journal() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
    journal::migrate(&mut client)
        .await
        .expect("apply the journal baseline");
    let schema: String = client
        .query_one("SELECT current_schema()", &[])
        .await
        .expect("read the isolated schema")
        .get(0);
    let role = format!("{schema}_runtime");
    client
        .batch_execute(&format!(
            "CREATE ROLE {role} NOLOGIN; \
             GRANT USAGE ON SCHEMA {schema} TO {role}; \
             GRANT SELECT ON adapter_schema_migrations TO {role}; \
             GRANT INSERT, SELECT ON adapter_journal_events TO {role}; \
             SET ROLE {role}"
        ))
        .await
        .expect("act as a runtime role that may append but not delete");
    assert_eq!(
        journal::missing_runtime_privileges(&client)
            .await
            .expect("the privileges are readable"),
        ["DELETE"]
    );
    assert!(
        !journal::ready(&client)
            .await
            .expect("the ledger is readable"),
        "a role that cannot run retention is not ready"
    );

    client
        .batch_execute(&format!(
            "RESET ROLE; GRANT DELETE ON adapter_journal_events TO {role}; SET ROLE {role}"
        ))
        .await
        .expect("grant the runtime role retention deletes");
    assert!(journal::missing_runtime_privileges(&client)
        .await
        .expect("the privileges are readable")
        .is_empty());
    assert!(journal::ready(&client)
        .await
        .expect("the ledger is readable"));
    let now = SystemTime::now();
    journal::append(
        &client,
        event("exchangeCreated"),
        now.checked_sub(2 * DAY)
            .expect("the stamp is representable"),
    )
    .await
    .expect("INSERT lets the runtime role append");
    assert_eq!(
        journal::delete_expired(&client, now.checked_sub(DAY).expect("representable"))
            .await
            .expect("INSERT, SELECT and DELETE let the runtime role sweep"),
        1
    );
    client
        .batch_execute(&format!(
            "RESET ROLE; DROP OWNED BY {role}; DROP ROLE {role}"
        ))
        .await
        .expect("remove the test runtime role");
}

#[tokio::test]
async fn journal_rows_refuse_updates_and_delete_only_whole_for_retention() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
    journal::migrate(&mut client)
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
    let mut client = isolated.client().await;
    journal::migrate(&mut client)
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
async fn upgrading_a_version_100_journal_keeps_its_rows_and_accepts_new_event_kinds() {
    let isolated = isolated().await;
    let mut client = isolated.client().await;
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
    let error = journal::append(&client, event("breakerFallback"), SystemTime::now())
        .await
        .expect_err("version 100 does not know breakerFallback");
    expect_check_violation(error, "breakerFallback before the upgrade");
    let error = journal::append(&client, event("breakerRefused"), SystemTime::now())
        .await
        .expect_err("version 100 does not know breakerRefused");
    expect_check_violation(error, "breakerRefused before the upgrade");

    journal::migrate(&mut client)
        .await
        .expect("the upgrade applies over existing rows");

    journal::append(&client, event("callRefused"), SystemTime::now())
        .await
        .expect("version 200 accepts callRefused");
    // An open-breaker facade exchange emits this pair in order. The journal
    // must admit the whole lifecycle, not just the fallback that answers it.
    journal::append(&client, event("breakerRefused"), SystemTime::now())
        .await
        .expect("the current schema accepts breakerRefused");
    journal::append(&client, event("breakerFallback"), SystemTime::now())
        .await
        .expect("the current schema accepts breakerFallback");
    let rows = client
        .query(
            "SELECT event_kind FROM adapter_journal_events ORDER BY 1",
            &[],
        )
        .await
        .expect("read the journal");
    let kinds: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
    assert_eq!(
        kinds,
        [
            "breakerFallback",
            "breakerRefused",
            "callRefused",
            "exchangeCreated"
        ]
    );
}
