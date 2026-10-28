// SPDX-License-Identifier: Apache-2.0

//! Database-clock acceptance for Record timers over disposable PostgreSQL.
//!
//! Scratch-only until the accepted postgres-test clock bridge exists. The four
//! injected cases deliberately drift their disposable database catalog and are
//! not startup/readiness evidence. The final case uses unmodified PostgreSQL
//! `clock_timestamp()`.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::mutation::{MutationBody, MutationPlan, MutationRequest, MutationTransaction};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    install_record_timer_clock_fixture_for_test, managed_schema_fingerprint,
    set_record_timer_clock_for_test, ClaimContext, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RecordTimerWorker, RegistryLockKey, RegistryStateTestIdentity,
    RowBoundaryContext, RuntimePool,
};
use registry_breg::record_profile::RecordRepresentation;
use registry_platform_audit::AuditProfile;
use serde_json::{json, Map, Value};
use tokio::task::JoinHandle;
use tokio_postgres::Client;
use uuid::Uuid;

const PACKAGE_ID: &str = "record-timer-clock-registry";
const DATABASE_ID: &str = "record-timer-clock-database";
const INSTANCE_ID: &str = "record-timer-clock-instance";

async fn wait_for_timer_barrier(
    observed: &tokio::sync::Notify,
    worker: &mut JoinHandle<Result<usize, registry_breg::mutation::MutationError>>,
    phase: &str,
) {
    tokio::select! {
        _ = observed.notified() => {}
        result = worker => panic!("timer worker returned before {phase}: {result:?}"),
        () = tokio::time::sleep(Duration::from_secs(30)) => {
            panic!("timer worker did not reach {phase} within 30 seconds")
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_clock_freeze_repeat_and_forward_execute_once() {
    let frozen = instant("2037-04-05T10:11:12.123456Z");
    let due = frozen + chrono::Duration::seconds(10);
    let harness = ClockHarness::injected("clock-freeze-forward", 0x91, frozen).await;
    let record_id = harness
        .create_service(
            "clock-freeze-forward",
            &rfc3339(due),
            None,
            "freeze repeat forward",
        )
        .await;
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;
    let worker = harness.worker(Duration::from_secs(5));

    assert_eq!(worker.run_once().await.expect("frozen scan succeeds"), 0);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("repeated frozen scan succeeds"),
        0
    );
    let pending = generation_snapshot(&harness.database, occurrence_id).await;
    assert_eq!(pending.state, "pending");
    assert_eq!(pending.claim_epoch, 0);
    assert_eq!(pending.attempt_count, 0);
    assert_eq!(pending.due_at, due);
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );

    harness.set_clock(due).await;
    assert_eq!(worker.run_once().await.expect("exact-due scan succeeds"), 1);
    let completed = generation_snapshot(&harness.database, occurrence_id).await;
    assert_eq!(completed.state, "completed");
    assert_eq!(completed.executed_attempt_count, 1);
    assert_eq!(completed.attempt_count, 1);
    assert_eq!(completed.completed_at, Some(due));
    assert_eq!(completed.attempt_started_at, Some(due));
    assert_eq!(completed.attempt_finished_at, Some(due));
    let after = effect_counts(&harness.database, &harness.registry, &record_id).await;
    assert_eq!(after.revisions, before.revisions + 1);
    assert_eq!(after.outbox, before.outbox);
    assert_eq!(after.action_receipts, before.action_receipts + 1);

    harness.set_clock(due).await;
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("same-instant rescan succeeds"),
        0
    );
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        after,
        "a repeated database instant cannot refire a settled occurrence"
    );
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn injected_clock_backward_move_rechecks_due_after_claim() {
    let base = instant("2041-08-09T10:11:12.000000Z");
    let due = base + chrono::Duration::seconds(10);
    let harness = ClockHarness::injected("clock-backward", 0x92, base).await;
    let record_id = harness
        .create_service("clock-backward", &rfc3339(due), None, "backward jump")
        .await;
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    harness.set_clock(due + chrono::Duration::seconds(1)).await;
    let claimed = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let waiting = harness
        .worker(Duration::from_secs(30))
        .with_claim_barrier_for_test(Arc::clone(&claimed), Arc::clone(&release));
    let mut execution = tokio::spawn(async move { waiting.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;

    harness.set_clock(due - chrono::Duration::seconds(1)).await;
    release.notify_one();
    assert_eq!(
        execution
            .await
            .expect("backward-jump worker joins")
            .expect("backward-jump hold settles"),
        1
    );
    let held = generation_snapshot(&harness.database, occurrence_id).await;
    assert_eq!(held.state, "pending");
    assert_eq!(held.claim_epoch, 1);
    assert_eq!(held.executed_attempt_count, 0);
    assert_eq!(held.attempt_count, 0);
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before,
        "the final locked check uses the moved-back database instant"
    );

    harness.set_clock(due).await;
    assert_eq!(
        harness
            .worker(Duration::from_secs(5))
            .run_once()
            .await
            .expect("exact-due retry succeeds"),
        1
    );
    let completed = generation_snapshot(&harness.database, occurrence_id).await;
    assert_eq!(completed.state, "completed");
    assert_eq!(completed.claim_epoch, 2);
    assert_eq!(completed.executed_attempt_count, 1);
    assert_eq!(completed.attempt_count, 1);
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_clock_normalizes_offsets_precision_and_far_dates() {
    let now = instant("2400-03-02T00:00:00.000000Z");
    let harness = ClockHarness::injected("clock-offsets-far", 0x93, now).await;
    let first_text = "2400-02-29T12:34:56.123456+05:30";
    let second_text = "2399-12-31T23:59:59.654321-04:00";
    let first_due = instant(first_text);
    let second_due = instant(second_text);
    let first = harness
        .create_service("clock-offset-plus", first_text, None, "offset plus")
        .await;
    let second = harness
        .create_service("clock-offset-minus", second_text, None, "offset minus")
        .await;
    assert_eq!(stored_due(&harness.database, &first).await, first_due);
    assert_eq!(stored_due(&harness.database, &second).await, second_due);

    let worker = harness.worker(Duration::from_secs(5));
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("first past-due scan succeeds"),
        1
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("second past-due scan succeeds"),
        1
    );
    assert_eq!(worker.run_once().await.expect("past-due queue drains"), 0);
    assert_eq!(
        record_status(&harness.database, &harness.registry, &first).await,
        "active"
    );
    assert_eq!(
        record_status(&harness.database, &harness.registry, &second).await,
        "active"
    );
    assert_eq!(
        generation_snapshot(
            &harness.database,
            timer_occurrence(&harness.database, &first).await,
        )
        .await
        .attempt_count,
        1
    );
    assert_eq!(
        generation_snapshot(
            &harness.database,
            timer_occurrence(&harness.database, &second).await,
        )
        .await
        .attempt_count,
        1
    );
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_clock_uses_exclusive_window_end_and_retention_deadline() {
    let now = instant("2045-06-07T08:09:10.111111Z");
    let harness = ClockHarness::injected("clock-window-retention", 0x94, now).await;
    let inclusive = harness
        .create_service(
            "clock-inclusive-due",
            &rfc3339(now),
            Some(&rfc3339(now + chrono::Duration::seconds(1))),
            "inclusive due",
        )
        .await;
    let expired = harness
        .create_service(
            "clock-exclusive-window",
            &rfc3339(now - chrono::Duration::seconds(1)),
            Some(&rfc3339(now)),
            "exclusive window",
        )
        .await;
    let worker = harness.worker(Duration::from_secs(5));
    assert_eq!(worker.run_once().await.expect("first due lane succeeds"), 1);
    assert_eq!(
        worker.run_once().await.expect("second due lane succeeds"),
        1
    );
    assert_eq!(
        record_status(&harness.database, &harness.registry, &inclusive).await,
        "active"
    );
    let expired_occurrence = timer_occurrence(&harness.database, &expired).await;
    let missed = generation_snapshot(&harness.database, expired_occurrence).await;
    assert_eq!(missed.state, "missed");
    assert_eq!(missed.executed_attempt_count, 0);
    assert_eq!(missed.attempt_count, 0);
    assert_eq!(
        record_status(&harness.database, &harness.registry, &expired).await,
        "scheduled"
    );

    let inclusive_occurrence = timer_occurrence(&harness.database, &inclusive).await;
    let completed = generation_snapshot(&harness.database, inclusive_occurrence).await;
    let expiry = completed
        .detail_expires_at
        .expect("completed generation has a persisted detail expiry");
    assert_eq!(completed.completed_at, Some(now));
    harness
        .set_clock(expiry - chrono::Duration::microseconds(1))
        .await;
    assert_eq!(
        worker
            .prune_retention_once_for_test()
            .await
            .expect("pre-expiry retention scan succeeds"),
        0
    );
    assert_eq!(
        attempt_count(&harness.database, inclusive_occurrence).await,
        1
    );
    harness.set_clock(expiry).await;
    assert_eq!(
        worker
            .prune_retention_once_for_test()
            .await
            .expect("exact-expiry retention scan succeeds"),
        1
    );
    assert_eq!(
        attempt_count(&harness.database, inclusive_occurrence).await,
        0
    );
    assert_eq!(
        generation_snapshot(&harness.database, inclusive_occurrence)
            .await
            .state,
        "completed",
        "retention keeps the current settled marker and generation"
    );
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_clock_preflight_uses_fixture_time_inside_past_window() {
    let fixture_now = instant("2020-02-03T04:05:06.000000Z");
    let due = fixture_now - chrono::Duration::seconds(1);
    let end = fixture_now + chrono::Duration::seconds(1);
    let harness = ClockHarness::injected("clock-preflight-past-window", 0x96, fixture_now).await;
    let record_id = harness
        .create_service(
            "clock-preflight-past-window",
            &rfc3339(due),
            Some(&rfc3339(end)),
            "past window under injected clock",
        )
        .await;
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(5))
            .run_once()
            .await
            .expect("the fixture-clock preflight executes inside its window"),
        1
    );
    let completed = generation_snapshot(&harness.database, occurrence_id).await;
    assert_eq!(completed.state, "completed");
    assert_eq!(completed.executed_attempt_count, 1);
    assert_eq!(completed.attempt_count, 1);
    assert_eq!(
        record_status(&harness.database, &harness.registry, &record_id).await,
        "active"
    );
    harness.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_clock_lock_wait_rechecks_window_expiry() {
    let harness = ClockHarness::real("clock-real-lock-wait", 0x95).await;
    let now = database_real_now(&harness.database).await;
    let not_after = now + chrono::Duration::seconds(2);
    let record_id = harness
        .create_service(
            "clock-real-lock-wait",
            &rfc3339(now - chrono::Duration::seconds(1)),
            Some(&rfc3339(not_after)),
            "real clock lock wait",
        )
        .await;
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;
    let claimed = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let waiting = harness
        .worker(Duration::from_secs(10))
        .with_claim_barrier_for_test(Arc::clone(&claimed), Arc::clone(&release));
    let mut execution = tokio::spawn(async move { waiting.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;

    let (mut blocker, blocker_task) = harness.database.connect_admin().await;
    let blocker = blocker.transaction().await.expect("row blocker begins");
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("blocker PID is visible")
        .get(0);
    let entity = &harness.registry.entities()["service"];
    blocker
        .query_one(
            &format!(
                "SELECT record_id FROM registry_data.\"{}\" WHERE record_id=$1::text::uuid FOR UPDATE",
                entity.physical_table
            ),
            &[&record_id],
        )
        .await
        .expect("fixture holds the exact anchor row");
    release.notify_one();
    wait_for_exact_blocker(&harness.database, blocker_pid).await;
    wait_for_real_database_time(&harness.database, not_after).await;
    blocker
        .rollback()
        .await
        .expect("fixture releases the anchor row");
    blocker_task.abort();

    assert_eq!(
        execution
            .await
            .expect("real-clock worker joins")
            .expect("post-wait expiry settles normally"),
        1
    );
    let missed = generation_snapshot(&harness.database, occurrence_id).await;
    assert_eq!(missed.state, "missed");
    assert_eq!(missed.executed_attempt_count, 0);
    assert_eq!(missed.attempt_count, 0);
    assert_eq!(
        record_status(&harness.database, &harness.registry, &record_id).await,
        "scheduled"
    );
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    harness.cleanup().await;
}

struct ClockHarness {
    database: TestDatabase,
    migration: Client,
    migration_task: JoinHandle<()>,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    pool: RuntimePool,
    coordinator: MutationTransaction,
    claims: ClaimContext,
    lock_key: RegistryLockKey,
    injected: bool,
}

impl ClockHarness {
    async fn injected(label: &'static str, audit_seed: u8, initial: DateTime<Utc>) -> Self {
        Self::new(label, audit_seed, Some(initial)).await
    }

    async fn real(label: &'static str, audit_seed: u8) -> Self {
        Self::new(label, audit_seed, None).await
    }

    async fn new(label: &'static str, audit_seed: u8, injected: Option<DateTime<Utc>>) -> Self {
        let injected_enabled = injected.is_some();
        let database = TestDatabase::create(8).await;
        let (migration, migration_task) = database.connect_migration().await;
        let registry = Arc::new(compiled_registry());
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("migration installs the normal timer schema first");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                database_id: DATABASE_ID,
                label,
            },
        )
        .await
        .expect("migration initializes the active timer package");
        let catalog = ExpectedManagedCatalog::compiled(&registry);
        let normal_fingerprint =
            managed_schema_fingerprint(&migration, &database.runtime_role, &catalog)
                .await
                .expect("normal managed catalog fingerprint is readable");
        assert_eq!(normal_fingerprint, identity.schema_fingerprint);
        assert_normal_catalog_uses_only_real_clock(&migration).await;
        if let Some(initial) = injected {
            install_record_timer_clock_fixture_for_test(
                &migration,
                &database.runtime_role,
                initial,
            )
            .await
            .expect("postgres-test installs the database-scoped timer clock fixture");
            assert!(
                managed_schema_fingerprint(&migration, &database.runtime_role, &catalog)
                    .await
                    .is_err(),
                "clock-injected databases deliberately fail the managed-catalog check and are never readiness evidence"
            );
        }
        let pool = database
            .runtime_config
            .build_pool()
            .expect("bounded pool builds");
        let audit = database.audit(
            AuditProfile::production_from_secret_bytes(vec![audit_seed; 32].into())
                .expect("test owns a keyed audit profile"),
        );
        let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key is bounded");
        let coordinator = MutationTransaction::new(
            lock_key,
            Duration::from_secs(2),
            identity.clone(),
            INSTANCE_ID,
            audit,
        );
        let claims = ClaimContext::for_compiled(
            &registry,
            "service",
            Some("timer-clock-test-operator".to_owned()),
            "service-editor",
            Some("service-administration".to_owned()),
            vec![RowBoundaryContext::Equals {
                field: "jurisdiction".to_owned(),
                value: "zone-a".to_owned(),
            }],
        )
        .expect("ordinary mutation authority is compiler-bound");
        Self {
            database,
            migration,
            migration_task,
            registry,
            identity,
            pool,
            coordinator,
            claims,
            lock_key,
            injected: injected_enabled,
        }
    }

    fn worker(&self, lease_duration: Duration) -> RecordTimerWorker {
        let worker = RecordTimerWorker::new_for_test(
            self.pool.clone(),
            Arc::clone(&self.registry),
            self.coordinator.clone(),
            self.identity.clone(),
            self.lock_key,
            Duration::from_secs(2),
            lease_duration,
        );
        if self.injected {
            worker.with_database_clock_fixture_for_test()
        } else {
            worker
        }
    }

    async fn set_clock(&self, instant: DateTime<Utc>) {
        assert!(self.injected, "only an injected-clock harness has a setter");
        set_record_timer_clock_for_test(&self.migration, instant)
            .await
            .expect("fixture atomically changes the database-scoped instant");
    }

    async fn create_service(
        &self,
        idempotency_key: &str,
        due: &str,
        not_after: Option<&str>,
        note: &str,
    ) -> String {
        let plan = MutationPlan::from_compiled(&self.registry, "records.service.create")
            .expect("create route is compiled");
        let mut data = Map::from_iter([
            ("jurisdiction".to_owned(), json!("zone-a")),
            ("status".to_owned(), json!("scheduled")),
            ("activatesAt".to_owned(), json!(due)),
            ("note".to_owned(), json!(note)),
        ]);
        if let Some(not_after) = not_after {
            data.insert("activationWindowEnd".to_owned(), json!(not_after));
        }
        let mut client = self.pool.get_for_test().await.expect("runtime connection");
        let created = self
            .coordinator
            .execute(
                &mut client,
                MutationRequest {
                    plan: &plan,
                    idempotency_key,
                    claims: &self.claims,
                    record_id: None,
                    expected_etag: None,
                    body: MutationBody::Create(data),
                    response_fields: response_fields(),
                    representation: RecordRepresentation::Json,
                    correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
                },
            )
            .await
            .expect("ordinary create arms one timer occurrence");
        response_id(&created)
    }

    async fn cleanup(self) {
        drop(self.migration);
        self.migration_task.abort();
        self.database.cleanup().await;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectCounts {
    revisions: i64,
    outbox: i64,
    action_receipts: i64,
}

#[derive(Debug)]
struct GenerationSnapshot {
    state: String,
    claim_epoch: i64,
    executed_attempt_count: i32,
    due_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    detail_expires_at: Option<DateTime<Utc>>,
    attempt_started_at: Option<DateTime<Utc>>,
    attempt_finished_at: Option<DateTime<Utc>>,
    attempt_count: i64,
}

async fn assert_normal_catalog_uses_only_real_clock(migration: &Client) {
    let policies: String = migration
        .query_one(
            "SELECT coalesce(string_agg(
                 policyname || ':' || coalesce(qual,'') || ':' || coalesce(with_check,''),
                 E'\\n' ORDER BY policyname), '')
               FROM pg_catalog.pg_policies
              WHERE schemaname='registry_data'
                AND policyname LIKE 'record_timer_%'",
            &[],
        )
        .await
        .expect("normal timer policies are inspectable")
        .get(0);
    let functions: String = migration
        .query_one(
            "SELECT coalesce(string_agg(pg_catalog.pg_get_functiondef(proc.oid), E'\\n'
                                        ORDER BY proc.proname), '')
               FROM pg_catalog.pg_proc AS proc
               JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=proc.pronamespace
              WHERE namespace.nspname='registry_internal'
                AND proc.proname LIKE '%record_timer%'",
            &[],
        )
        .await
        .expect("normal timer functions are inspectable")
        .get(0);
    let corpus = format!("{policies}\n{functions}").to_ascii_lowercase();
    assert!(
        corpus.contains("clock_timestamp()"),
        "the normal installed timer catalog must use PostgreSQL's real clock"
    );
    for forbidden in ["test_clock", "fixture_clock", "clock_fixture"] {
        assert!(
            !corpus.contains(forbidden),
            "the normal catalog unexpectedly contains {forbidden}"
        );
    }
}

async fn generation_snapshot(database: &TestDatabase, occurrence_id: Uuid) -> GenerationSnapshot {
    let row = database
        .admin
        .query_one(
            "SELECT generation.state,generation.claim_epoch,
                    generation.executed_attempt_count,generation.due_at,
                    generation.completed_at,generation.detail_expires_at,
                    min(attempt.started_at),max(attempt.finished_at),count(attempt.attempt_number)
               FROM registry_internal.registry_record_timer_generations AS generation
               LEFT JOIN registry_internal.registry_record_timer_attempts AS attempt
                 ON attempt.occurrence_id=generation.occurrence_id
              WHERE generation.occurrence_id=$1
              GROUP BY generation.occurrence_id",
            &[&occurrence_id],
        )
        .await
        .expect("the exact generation is queryable");
    GenerationSnapshot {
        state: row.get(0),
        claim_epoch: row.get(1),
        executed_attempt_count: row.get(2),
        due_at: row.get(3),
        completed_at: row.get(4),
        detail_expires_at: row.get(5),
        attempt_started_at: row.get(6),
        attempt_finished_at: row.get(7),
        attempt_count: row.get(8),
    }
}

async fn timer_occurrence(database: &TestDatabase, record_id: &str) -> Uuid {
    database
        .admin
        .query_one(
            "SELECT occurrence_id
               FROM registry_internal.registry_record_timer_current
              WHERE record_type='service' AND record_id=$1::text::uuid
                AND timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("one current timer occurrence exists")
        .get(0)
}

async fn stored_due(database: &TestDatabase, record_id: &str) -> DateTime<Utc> {
    database
        .admin
        .query_one(
            "SELECT generation.due_at
               FROM registry_internal.registry_record_timer_current AS current
               JOIN registry_internal.registry_record_timer_generations AS generation
                 ON generation.occurrence_id=current.occurrence_id
              WHERE current.record_type='service' AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("stored due instant is queryable")
        .get(0)
}

async fn attempt_count(database: &TestDatabase, occurrence_id: Uuid) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_record_timer_attempts
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("attempt count is queryable")
        .get(0)
}

async fn effect_counts(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
    record_id: &str,
) -> EffectCounts {
    let table = &registry.entities()["service"].physical_table;
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
                    (SELECT count(*) FROM registry_internal.registry_revisions
                      WHERE entity_id='service' AND record_id=$1::text::uuid),
                    (SELECT count(*) FROM registry_internal.registry_outbox
                      WHERE entity_id='service' AND application_reference IS NOT NULL),
                    (SELECT count(*) FROM registry_internal.registry_idempotency
                      WHERE result_kind='immediate_action'),
                    (SELECT count(*) FROM registry_data.\"{table}\"
                      WHERE record_id=$1::text::uuid)"
            ),
            &[&record_id],
        )
        .await
        .expect("durable timer effects are queryable");
    assert_eq!(row.get::<_, i64>(3), 1);
    EffectCounts {
        revisions: row.get(0),
        outbox: row.get(1),
        action_receipts: row.get(2),
    }
}

async fn record_status(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
    record_id: &str,
) -> String {
    let entity = &registry.entities()["service"];
    let status = &entity.fields["status"].physical_name;
    database
        .admin
        .query_one(
            &format!(
                "SELECT \"{status}\" FROM registry_data.\"{}\"
                  WHERE record_id=$1::text::uuid",
                entity.physical_table
            ),
            &[&record_id],
        )
        .await
        .expect("record status is queryable")
        .get(0)
}

async fn database_real_now(database: &TestDatabase) -> DateTime<Utc> {
    database
        .admin
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .expect("real PostgreSQL clock is readable")
        .get(0)
}

async fn wait_for_real_database_time(database: &TestDatabase, instant: DateTime<Utc>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if database_real_now(database).await >= instant {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the bounded real database clock crosses the exact window end");
}

async fn wait_for_exact_blocker(database: &TestDatabase, blocker_pid: i32) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: i64 = database
                .admin
                .query_one(
                    "SELECT count(*)
                       FROM pg_catalog.pg_stat_activity AS activity
                      WHERE activity.datname=current_database()
                        AND activity.pid<>pg_backend_pid()
                        AND activity.wait_event_type='Lock'
                        AND $1=ANY(pg_catalog.pg_blocking_pids(activity.pid))",
                    &[&blocker_pid],
                )
                .await
                .expect("PostgreSQL blocker relation is inspectable")
                .get(0);
            if blocked == 1 {
                return;
            }
            assert_eq!(
                blocked, 0,
                "only the exact worker may wait on the fixture row lock"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the claimed worker reaches the exact PostgreSQL row lock");
}

fn response_fields() -> BTreeSet<String> {
    BTreeSet::from([
        "jurisdiction".to_owned(),
        "status".to_owned(),
        "activates-at".to_owned(),
        "activation-window-end".to_owned(),
        "activation-revision".to_owned(),
        "note".to_owned(),
    ])
}

fn response_id(outcome: &registry_breg::mutation::MutationOutcome) -> String {
    let body: Value =
        serde_json::from_slice(outcome.response().body()).expect("mutation response is JSON");
    body["data"]["recordIdentifier"]
        .as_str()
        .expect("response contains the record identifier")
        .to_owned()
}

fn instant(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap_or_else(|error| panic!("fixture timestamp {value} parses: {error}"))
        .with_timezone(&Utc)
}

fn rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{
            "id":PACKAGE_ID,
            "version":"1",
            "defaultLanguage":"en",
            "canonicalBaseIri":"https://timer-clock.example.test"
        },
        "datasets":[{"id":"services"}],
        "recordTypes":[{
            "id":"service",
            "primaryDataset":"services",
            "route":"services",
            "mutationMode":"mutable",
            "fields":[
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"status","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"activates-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"activation-window-end","type":"timestamp","classification":"internal"},
                {"id":"activation-revision","type":"uuid","classification":"internal"},
                {"id":"note","type":"string","required":true,"maximumLength":128,"classification":"internal"}
            ],
            "timers":[{
                "id":"activate",
                "at":"activates-at",
                "notAfter":"activation-window-end",
                "rearmOn":"activation-revision",
                "when":{"type":"fields","equals":{"status":"scheduled"}},
                "invoke":"activate-service",
                "input":{
                    "service":{"fromRecordId":true},
                    "planned-at":{"fromField":"activates-at"},
                    "operation-id":{"fromTimer":"occurrence-id"}
                }
            }]
        }],
        "timerGrants":[{"recordType":"service","timer":"activate"}],
        "actions":[{
            "id":"activate-service",
            "execution":{"mode":"immediate"},
            "inputs":[
                {"id":"service","type":"reference","target":"service","required":true,"classification":"internal"},
                {"id":"planned-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
            ],
            "plan":{"type":"fixed","effects":[{
                "id":"activated",
                "target":{"fromInput":"service"},
                "operation":"patch",
                "set":{"status":{"value":"active"}}
            }]}
        }],
        "accessProfiles":[{
            "id":"service-editor",
            "default":true,
            "principalClaim":"registry_principal",
            "requiredScopes":"unrestricted",
            "requiredPurposes":["service-administration"],
            "permissions":{"records":[{
                "recordType":"service",
                "operations":["create","get","patch"],
                "readableFields":[
                    "jurisdiction","status","activates-at",
                    "activation-window-end","activation-revision","note"
                ],
                "writableFields":[
                    "jurisdiction","status","activates-at",
                    "activation-window-end","activation-revision","note"
                ],
                "rowBoundaries":[{
                    "field":"jurisdiction",
                    "claim":"jurisdiction",
                    "operator":"equals"
                }]
            }]}
        }]
    });
    let bytes = serde_json::to_vec(&source).expect("clock fixture serializes");
    let project = parse_project_json(&bytes).expect("clock fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("clock fixture compiles to one bounded timer Action")
}
