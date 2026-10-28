// SPDX-License-Identifier: Apache-2.0

//! Bounded Record-timer diagnostic retention over real PostgreSQL.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::mutation::{MutationFaultPoint, MutationTransaction};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    prune_record_timer_retention_batch_for_test, ExpectedRegistryIdentity, RecordTimerWorker,
    RegistryLockKey, RegistryStateTestIdentity, RuntimePool,
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use tokio_postgres::error::SqlState;
use uuid::Uuid;

const PACKAGE_ID: &str = "record-timer-retention-registry";
const DATABASE_ID: &str = "record-timer-retention-database";

struct RetentionHarness {
    database: TestDatabase,
    pool: RuntimePool,
    registry: Arc<registry_breg::model::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
}

#[derive(Clone, Copy)]
struct SeedOptions<'a> {
    state: &'a str,
    current: bool,
    generation_expiry: Option<DateTime<Utc>>,
    attempt_expiries: &'a [Option<DateTime<Utc>>],
    executed_attempt_count: i32,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_prunes_expired_detail_without_reopening_or_losing_current_markers() {
    let harness = retention_harness().await;
    let now = database_now(&harness.database).await;
    let expired = now - chrono::Duration::seconds(1);
    let retained = now + chrono::Duration::days(1);

    let current_completed = seed_generation(
        &harness,
        SeedOptions {
            state: "completed",
            current: true,
            generation_expiry: Some(expired),
            attempt_expiries: &[Some(retained)],
            executed_attempt_count: 1,
        },
    )
    .await;
    let noncurrent_refused = seed_generation(
        &harness,
        SeedOptions {
            state: "refused",
            current: false,
            generation_expiry: Some(expired),
            attempt_expiries: &[Some(retained)],
            executed_attempt_count: 1,
        },
    )
    .await;
    let future_cancelled = seed_generation(
        &harness,
        SeedOptions {
            state: "cancelled",
            current: false,
            generation_expiry: Some(retained),
            attempt_expiries: &[Some(expired)],
            executed_attempt_count: 1,
        },
    )
    .await;
    let blocked = seed_generation(
        &harness,
        SeedOptions {
            state: "blocked",
            current: true,
            generation_expiry: None,
            attempt_expiries: &[Some(expired), Some(expired), Some(expired), Some(retained)],
            executed_attempt_count: 4,
        },
    )
    .await;
    let pending = seed_generation(
        &harness,
        SeedOptions {
            state: "pending",
            current: true,
            generation_expiry: None,
            attempt_expiries: &[None],
            executed_attempt_count: 0,
        },
    )
    .await;
    let leased = seed_generation(
        &harness,
        SeedOptions {
            state: "leased",
            current: true,
            generation_expiry: None,
            attempt_expiries: &[None],
            executed_attempt_count: 0,
        },
    )
    .await;

    let binding_count = timer_binding_count(&harness.database).await;
    let first = prune_record_timer_retention_batch_for_test(
        &harness.pool,
        &harness.identity,
        harness.lock_key,
        Duration::from_secs(2),
        5,
    )
    .await
    .expect("the first bounded retention batch succeeds");
    assert_eq!(
        first,
        (5, 1),
        "terminal deadlines, unfinished-attempt deadlines and generation cleanup use fair independent lanes"
    );

    assert_generation(&harness.database, current_completed, true, true).await;
    assert_eq!(attempt_count(&harness.database, current_completed).await, 0);
    assert_generation(&harness.database, noncurrent_refused, false, false).await;
    assert_generation(&harness.database, future_cancelled, true, false).await;
    assert_eq!(attempt_count(&harness.database, future_cancelled).await, 1);

    let blocked_row = harness
        .database
        .admin
        .query_one(
            "SELECT generation.state,generation.block_kind,generation.outcome_code,
                    generation.executed_attempt_count,current.occurrence_id IS NOT NULL
               FROM registry_internal.registry_record_timer_generations AS generation
               LEFT JOIN registry_internal.registry_record_timer_current AS current
                 ON current.occurrence_id=generation.occurrence_id
              WHERE generation.occurrence_id=$1",
            &[&blocked],
        )
        .await
        .expect("the blocked current generation is retained");
    assert_eq!(blocked_row.get::<_, &str>(0), "blocked");
    assert_eq!(blocked_row.get::<_, Option<&str>>(1), Some("technical"));
    assert_eq!(
        blocked_row.get::<_, Option<&str>>(2),
        Some("attempts-exhausted")
    );
    assert_eq!(blocked_row.get::<_, i32>(3), 4);
    assert!(blocked_row.get::<_, bool>(4));
    assert_eq!(attempt_count(&harness.database, blocked).await, 1);

    assert_generation(&harness.database, pending, true, true).await;
    assert_generation(&harness.database, leased, true, true).await;
    assert_eq!(attempt_count(&harness.database, pending).await, 1);
    assert_eq!(attempt_count(&harness.database, leased).await, 1);
    assert_eq!(timer_binding_count(&harness.database).await, binding_count);

    let stale_settlement = harness
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_generations
                SET state='completed'
              WHERE occurrence_id=$1",
            &[&noncurrent_refused],
        )
        .await
        .expect("the fixture can model one stale settlement update");
    assert_eq!(
        stale_settlement, 0,
        "pruned history cannot be reconstructed by a stale worker settlement"
    );

    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_lanes_are_bounded_skip_busy_rows_and_keep_delete_private() {
    let mut harness = retention_harness().await;
    let now = database_now(&harness.database).await;
    let oldest = seed_generation(
        &harness,
        SeedOptions {
            state: "missed",
            current: false,
            generation_expiry: Some(now - chrono::Duration::seconds(3)),
            attempt_expiries: &[],
            executed_attempt_count: 0,
        },
    )
    .await;
    let second = seed_generation(
        &harness,
        SeedOptions {
            state: "missed",
            current: false,
            generation_expiry: Some(now - chrono::Duration::seconds(2)),
            attempt_expiries: &[],
            executed_attempt_count: 0,
        },
    )
    .await;
    let third = seed_generation(
        &harness,
        SeedOptions {
            state: "missed",
            current: false,
            generation_expiry: Some(now - chrono::Duration::seconds(1)),
            attempt_expiries: &[],
            executed_attempt_count: 0,
        },
    )
    .await;
    let busy_attempt = seed_generation(
        &harness,
        SeedOptions {
            state: "blocked",
            current: true,
            generation_expiry: None,
            attempt_expiries: &[Some(now - chrono::Duration::seconds(2))],
            executed_attempt_count: 1,
        },
    )
    .await;
    let available_attempt = seed_generation(
        &harness,
        SeedOptions {
            state: "blocked",
            current: true,
            generation_expiry: None,
            attempt_expiries: &[Some(now - chrono::Duration::seconds(1))],
            executed_attempt_count: 1,
        },
    )
    .await;

    let runtime = harness
        .pool
        .get_for_test()
        .await
        .expect("the runtime role obtains a connection");
    let denied = runtime
        .execute(
            "DELETE FROM registry_internal.registry_record_timer_generations WHERE false",
            &[],
        )
        .await
        .expect_err("the runtime role never receives broad timer-ledger DELETE");
    assert_eq!(denied.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    let denied = runtime
        .execute(
            "DELETE FROM registry_internal.registry_record_timer_attempts WHERE false",
            &[],
        )
        .await
        .expect_err("the runtime role never receives broad timer-attempt DELETE");
    assert_eq!(denied.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    for invalid_limit in [0_i32, 1_001_i32] {
        let refused = runtime
            .query(
                "SELECT * FROM registry_internal.prune_record_timer_retention($1)",
                &[&invalid_limit],
            )
            .await
            .expect_err("the fixed definer function enforces its own row bound");
        assert_eq!(refused.code(), Some(&SqlState::INVALID_PARAMETER_VALUE));
    }
    drop(runtime);

    let pool = harness.pool.clone();
    let identity = harness.identity.clone();
    let lock_key = harness.lock_key;
    let locked = harness
        .database
        .admin
        .transaction()
        .await
        .expect("the fixture opens a competing ledger transaction");
    locked
        .query_one(
            "SELECT occurrence_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1
              FOR UPDATE",
            &[&oldest],
        )
        .await
        .expect("the oldest terminal generation is busy");
    locked
        .query_one(
            "SELECT occurrence_id
               FROM registry_internal.registry_record_timer_attempts
              WHERE occurrence_id=$1 AND attempt_number=1
              FOR UPDATE",
            &[&busy_attempt],
        )
        .await
        .expect("the oldest expired attempt is busy");

    let skipped = prune_record_timer_retention_batch_for_test(
        &pool,
        &identity,
        lock_key,
        Duration::from_secs(2),
        1,
    )
    .await
    .expect("the retention batch skips both busy oldest rows");
    assert_eq!(
        skipped,
        (1, 1),
        "attempt and generation lanes each remain within their private bound"
    );
    assert_eq!(attempt_count_via_pool(&pool, busy_attempt).await, 1);
    assert_eq!(attempt_count_via_pool(&pool, available_attempt).await, 0);
    assert_generation_via_pool(&pool, oldest, true).await;
    assert_generation_via_pool(&pool, second, false).await;
    assert_generation_via_pool(&pool, third, true).await;

    locked
        .rollback()
        .await
        .expect("the fixture releases the busy row");
    let oldest_removed = prune_record_timer_retention_batch_for_test(
        &pool,
        &identity,
        lock_key,
        Duration::from_secs(2),
        1,
    )
    .await
    .expect("the formerly busy rows are revisited");
    assert_eq!(oldest_removed, (1, 1));
    assert_eq!(attempt_count(&harness.database, busy_attempt).await, 0);
    assert_generation_via_pool(&pool, oldest, false).await;
    assert_generation_via_pool(&pool, third, true).await;

    assert!(
        prune_record_timer_retention_batch_for_test(
            &pool,
            &identity,
            lock_key,
            Duration::from_secs(2),
            0,
        )
        .await
        .is_err(),
        "zero is not an unbounded batch alias"
    );
    assert!(
        prune_record_timer_retention_batch_for_test(
            &pool,
            &identity,
            lock_key,
            Duration::from_secs(2),
            1_001,
        )
        .await
        .is_err(),
        "the private maximum cannot be raised by a caller"
    );

    let last = prune_record_timer_retention_batch_for_test(
        &pool,
        &identity,
        lock_key,
        Duration::from_secs(2),
        1,
    )
    .await
    .expect("the final bounded row is removed");
    assert_eq!(last, (0, 1));
    assert_generation_via_pool(&pool, third, false).await;

    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_retention_is_audited_only_for_real_work_and_uncertain_commit_stays_unfinished() {
    let harness = retention_harness().await;
    let now = database_now(&harness.database).await;
    let retained_current = seed_generation(
        &harness,
        SeedOptions {
            state: "completed",
            current: true,
            generation_expiry: Some(now - chrono::Duration::seconds(2)),
            attempt_expiries: &[],
            executed_attempt_count: 0,
        },
    )
    .await;
    assert_eq!(
        retention_worker(&harness, None)
            .prune_retention_once_for_test()
            .await
            .expect("a retained current terminal marker needs no pruning"),
        0
    );
    assert!(
        harness.database.audit_entries().is_empty(),
        "idle discovery emits no maintenance audit stream"
    );
    assert_generation(&harness.database, retained_current, true, true).await;

    let expired = seed_generation(
        &harness,
        SeedOptions {
            state: "missed",
            current: false,
            generation_expiry: Some(now - chrono::Duration::seconds(1)),
            attempt_expiries: &[],
            executed_attempt_count: 0,
        },
    )
    .await;
    harness
        .database
        .audit_capture()
        .fail_on("breg-record-timer-retention-audit/v1", "attempt");
    assert!(matches!(
        retention_worker(&harness, None)
            .prune_retention_once_for_test()
            .await,
        Err(registry_breg::mutation::MutationError::Unavailable)
    ));
    assert_eq!(harness.database.audit_capture().matched_refusal_count(), 1);
    assert_generation(&harness.database, expired, true, false).await;

    harness.database.audit_capture().restore();
    assert!(matches!(
        retention_worker(
            &harness,
            Some(MutationFaultPoint::AfterCommitBeforeResponseRelease),
        )
        .prune_retention_once_for_test()
        .await,
        Err(registry_breg::mutation::MutationError::CommitUnresolved)
    ));
    assert_generation(&harness.database, expired, false, false).await;
    let retention_entries = harness
        .database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["schema"] == "breg-record-timer-retention-audit/v1")
        .collect::<Vec<_>>();
    assert_eq!(retention_entries.len(), 2);
    assert_eq!(retention_entries[0]["record"]["phase"], "attempt");
    assert_eq!(retention_entries[1]["record"]["phase"], "terminal");
    assert_eq!(retention_entries[1]["record"]["outcome"], "unfinished");

    harness.database.cleanup().await;
}

fn retention_worker(
    harness: &RetentionHarness,
    fault: Option<MutationFaultPoint>,
) -> RecordTimerWorker {
    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        harness.identity.clone(),
        "record-timer-retention-instance",
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x6d; 32].into())
                .expect("the retention audit profile is valid"),
        ),
    );
    let worker = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        Arc::clone(&harness.registry),
        coordinator,
        harness.identity.clone(),
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    match fault {
        Some(fault) => worker.with_fault_for_test(fault),
        None => worker,
    }
}

async fn retention_harness() -> RetentionHarness {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("the retention fixture installs the real timer ledger");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-retention-package-1",
        },
    )
    .await
    .expect("the retention fixture activates one timer binding");
    drop(migration);
    migration_task.abort();
    let pool = database
        .runtime_config
        .build_pool()
        .expect("the bounded runtime pool builds");
    RetentionHarness {
        database,
        pool,
        registry,
        identity,
        lock_key: RegistryLockKey::derive(PACKAGE_ID).expect("the package lock key is bounded"),
    }
}

async fn seed_generation(harness: &RetentionHarness, options: SeedOptions<'_>) -> Uuid {
    let record_id = Uuid::new_v4();
    let occurrence_id = Uuid::new_v4();
    let terminal = matches!(
        options.state,
        "completed" | "refused" | "cancelled" | "superseded" | "missed"
    );
    let block_kind = (options.state == "blocked").then_some("technical");
    let outcome_code = match options.state {
        "completed" => Some("completed"),
        "refused" => Some("declared-refusal"),
        "cancelled" => Some("control-cleared"),
        "superseded" => Some("superseded"),
        "missed" => Some("execution-window-expired"),
        "blocked" => Some("attempts-exhausted"),
        _ => None,
    };
    let claim_owner = (options.state == "leased").then(Uuid::new_v4);
    let claim_token = (options.state == "leased").then(Uuid::new_v4);
    let receipt = (options.state == "completed").then(Uuid::new_v4);
    harness
        .database
        .admin
        .execute(
            "WITH binding AS (
                 SELECT * FROM registry_internal.registry_record_timer_bindings
                  WHERE record_type='service' AND timer_id='activate'
                    AND removed_activation_id IS NULL
             ), control AS (
                 SELECT * FROM registry_internal.registry_record_timer_control WHERE singleton
             ), registry AS (
                 SELECT * FROM registry_internal.registry_state WHERE singleton
             )
             INSERT INTO registry_internal.registry_record_timer_generations (
                 record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                 material_signature,due_at,definition_revision,action_revision,
                 system_grant_revision,gate_open,state,block_kind,outcome_code,
                 executed_attempt_count,retry_allowance,claim_owner_id,claim_epoch,
                 claim_token,claim_until,claimed_control_epoch,claimed_instance_epoch,
                 claimed_activation_id,created_activation_id,current_policy_activation_id,
                 executed_activation_id,receipt_correlation,completed_at,detail_expires_at
             )
             SELECT binding.record_type,$1,binding.timer_id,$2,binding.incarnation,
                    'sha256:'||repeat('d',64),clock_timestamp()-interval '1 hour',
                    binding.definition_revision,binding.action_revision,
                    binding.system_grant_revision,true,$3,$4,$5,$6,0,$7,
                    CASE WHEN $3='leased' THEN 1 ELSE 0 END,$8,
                    CASE WHEN $3='leased' THEN clock_timestamp()+interval '1 minute' END,
                    CASE WHEN $3='leased' THEN control.control_epoch END,
                    CASE WHEN $3='leased' THEN registry.epoch END,
                    CASE WHEN $3='leased' THEN registry.active_activation_id END,
                    binding.created_activation_id,binding.current_policy_activation_id,
                    CASE WHEN $9 THEN registry.active_activation_id END,$10,
                    CASE WHEN $9 THEN clock_timestamp()-interval '1 hour' END,$11
               FROM binding CROSS JOIN control CROSS JOIN registry",
            &[
                &record_id,
                &occurrence_id,
                &options.state,
                &block_kind,
                &outcome_code,
                &options.executed_attempt_count,
                &claim_owner,
                &claim_token,
                &terminal,
                &receipt,
                &options.generation_expiry,
            ],
        )
        .await
        .expect("the internal retention fixture inserts one generation");

    if options.current {
        harness
            .database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_record_timer_current (
                     record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                     material_signature
                 )
                 SELECT record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                        material_signature
                   FROM registry_internal.registry_record_timer_generations
                  WHERE occurrence_id=$1",
                &[&occurrence_id],
            )
            .await
            .expect("the internal retention fixture installs one current marker");
    }

    for (ordinal, expiry) in options.attempt_expiries.iter().enumerate() {
        let attempt_number = i32::try_from(ordinal + 1).expect("attempt fixture is bounded");
        let finished = expiry.is_some();
        let attempt_outcome = if finished && terminal {
            outcome_code
        } else {
            None
        };
        let technical_code = if finished && !terminal {
            Some("handler-failure")
        } else {
            None
        };
        harness
            .database
            .admin
            .execute(
                "INSERT INTO registry_internal.registry_record_timer_attempts (
                     occurrence_id,attempt_number,claim_owner_id,claim_epoch,
                     control_epoch,instance_epoch,activation_id,definition_revision,
                     action_revision,system_grant_revision,started_at,finished_at,
                     detail_expires_at,block_kind,outcome_code,technical_code,
                     receipt_correlation
                 )
                 SELECT generation.occurrence_id,$2,gen_random_uuid(),$2::integer::bigint,
                        control.control_epoch,registry.epoch,registry.active_activation_id,
                        generation.definition_revision,generation.action_revision,
                        generation.system_grant_revision,clock_timestamp()-interval '2 hours',
                        CASE WHEN $3 THEN clock_timestamp()-interval '1 hour' END,$4,
                        CASE WHEN $5::text IS NOT NULL THEN 'technical' END,$6,$5,
                        CASE WHEN $6='completed' THEN generation.receipt_correlation END
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_internal.registry_record_timer_control AS control
                     ON control.singleton
                   JOIN registry_internal.registry_state AS registry ON registry.singleton
                  WHERE generation.occurrence_id=$1",
                &[
                    &occurrence_id,
                    &attempt_number,
                    &finished,
                    expiry,
                    &technical_code,
                    &attempt_outcome,
                ],
            )
            .await
            .expect("the internal retention fixture inserts one attempt");
    }
    occurrence_id
}

async fn database_now(database: &TestDatabase) -> DateTime<Utc> {
    database
        .admin
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .expect("the fixture reads the authoritative database clock")
        .get(0)
}

async fn timer_binding_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_record_timer_bindings",
            &[],
        )
        .await
        .expect("the binding fence count is queryable")
        .get(0)
}

async fn attempt_count(database: &TestDatabase, occurrence_id: Uuid) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_record_timer_attempts
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the retained attempt count is queryable")
        .get(0)
}

async fn attempt_count_via_pool(pool: &RuntimePool, occurrence_id: Uuid) -> i64 {
    pool.get_for_test()
        .await
        .expect("the runtime connection is available")
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_record_timer_attempts
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the runtime can inspect the retained attempt count")
        .get(0)
}

async fn assert_generation(
    database: &TestDatabase,
    occurrence_id: Uuid,
    exists: bool,
    current: bool,
) {
    let row = database
        .admin
        .query_opt(
            "SELECT current.occurrence_id IS NOT NULL
               FROM registry_internal.registry_record_timer_generations AS generation
               LEFT JOIN registry_internal.registry_record_timer_current AS current
                 ON current.occurrence_id=generation.occurrence_id
              WHERE generation.occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the generation evidence is queryable");
    assert_eq!(row.is_some(), exists);
    if let Some(row) = row {
        assert_eq!(row.get::<_, bool>(0), current);
    }
}

async fn assert_generation_via_pool(pool: &RuntimePool, occurrence_id: Uuid, exists: bool) {
    let client = pool
        .get_for_test()
        .await
        .expect("the runtime connection is available");
    let present = client
        .query_opt(
            "SELECT occurrence_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the runtime can inspect timer retention state")
        .is_some();
    assert_eq!(present, exists);
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let source = timer_project_source();
    let bytes = serde_json::to_vec(&source).expect("the timer project serializes");
    let project = parse_project_json(&bytes).expect("the timer project parses strictly");
    compile_project(&project, &[], CompileProfile::Authoring).expect("the timer project compiles")
}

fn timer_project_source() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{"id":PACKAGE_ID,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://retention.example.test"},
        "datasets":[{"id":"services"}],
        "recordTypes":[{
            "id":"service","primaryDataset":"services","route":"services","mutationMode":"mutable",
            "fields":[
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"status","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"activates-at","type":"timestamp","required":true,"classification":"internal"}
            ],
            "timers":[{
                "id":"activate","at":"activates-at","invoke":"activate-service",
                "input":{"service":{"fromRecordId":true}}
            }]
        }],
        "timerGrants":[{"recordType":"service","timer":"activate"}],
        "actions":[{
            "id":"activate-service","execution":{"mode":"immediate"},
            "inputs":[{"id":"service","type":"reference","target":"service","required":true,"classification":"internal"}],
            "plan":{"type":"fixed","effects":[{
                "id":"activated","target":{"fromInput":"service"},"operation":"patch",
                "set":{"status":{"value":"active"}}
            }]}
        }],
        "accessProfiles":[{
            "id":"service-editor","default":true,"principalClaim":"registry_principal",
            "requiredScopes":"unrestricted","requiredPurposes":["service-administration"],
            "permissions":{"records":[{
                "recordType":"service","operations":["create","get","patch"],
                "readableFields":["jurisdiction","status","activates-at"],
                "writableFields":["jurisdiction","status","activates-at"],
                "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
        }]
    })
}
