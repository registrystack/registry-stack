// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

#[path = "postgres_record_timers/action_guard_regressions.rs"]
mod action_guard_regressions;

#[path = "postgres_record_timers/lifecycle_regressions.rs"]
mod lifecycle_regressions;

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chrono::{SecondsFormat, Utc};
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::field_encryption::{FieldEncryptionProvider, FieldEncryptionService};
use registry_breg::idempotency::PermittedResponseHeader;
use registry_breg::mutation::{
    MutationBody, MutationFaultPoint, MutationPlan, MutationRequest, MutationTransaction,
    PatchOperation,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    install_record_timer_clock_fixture_for_test, managed_schema_fingerprint,
    reconcile_compiled_runtime_acl_for_test, reconcile_record_timer_runtime_acl_for_test,
    record_timer_operator_detail_for_test, retained_record_timer_state_exists_for_test,
    set_record_timer_clock_for_test, strong_record_etag_for_test, test_activation_id,
    test_package_digest, timer_create_target_id_for_test, ClaimContext, DedicatedApplyConnection,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RecordTimerWorker, RegistryLockKey,
    RegistryStateTestIdentity, RowBoundaryContext, RuntimePool, SqlIdentifier,
};
use registry_breg::record_profile::RecordRepresentation;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{SecretProvider, SecretReference, SecretResolver};
use serde_json::{json, Map, Value};
use tokio::task::JoinHandle;

const PACKAGE_ID: &str = "record-timer-registry";
const DATABASE_ID: &str = "record-timer-database";
const INSTANCE_ID: &str = "record-timer-instance";
const TIMER_MAINTENANCE_AUDIT_SCHEMA: &str = "breg-record-timer-maintenance-audit/v1";

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn future_activation_is_not_early_is_atomic_and_survives_restart_and_concurrent_edit() {
    let database = TestDatabase::create(10).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    let initial = chrono::DateTime::parse_from_rfc3339("2040-02-03T04:05:06.000000Z")
        .expect("fixed timer instant parses")
        .with_timezone(&Utc);
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs the timer ledger with the compiled registry");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-package-1",
        },
    )
    .await
    .expect("migration initializes the active timer package");
    install_record_timer_clock_fixture_for_test(&migration, &database.runtime_role, initial)
        .await
        .expect("test installs the explicit database timer clock");

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x71; 32].into())
            .expect("test owns a keyed audit profile"),
    );
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key is bounded");
    let coordinator = MutationTransaction::new(
        lock_key,
        Duration::from_secs(2),
        identity.clone(),
        INSTANCE_ID,
        audit.clone(),
    );
    let claims = ClaimContext::for_compiled(
        &registry,
        "service",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.service.create")
        .expect("create route is compiled");
    let patch_plan = MutationPlan::from_compiled(&registry, "records.service.patch")
        .expect("patch route is compiled");
    let due = initial + chrono::Duration::seconds(2);
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let created = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-scheduled-service",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!(due.to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("created")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms one timer generation");
    let record_id = response_id(&created);
    let create_etag = response_etag(&created);
    assert_eq!(timer_state(&database, &record_id).await, "pending");
    let occurrence_id = timer_occurrence(&database, &record_id).await;
    let before_timer = effect_counts(&database, &registry, &record_id).await;

    let worker = RecordTimerWorker::new_for_test(
        pool.clone(),
        registry.clone(),
        coordinator.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .with_database_clock_fixture_for_test();
    assert_eq!(worker.run_once().await.expect("early scan succeeds"), 0);
    assert_eq!(
        record_values(&database, &registry, &record_id).await.0,
        "scheduled"
    );
    assert_eq!(
        effect_counts(&database, &registry, &record_id).await,
        before_timer
    );

    set_record_timer_clock_for_test(&migration, due)
        .await
        .expect("database timer clock reaches the exact due instant");
    drop(migration);
    migration_task.abort();
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let racing_worker = worker
        .clone()
        .with_claim_barrier_for_test(claimed.clone(), resume.clone());
    let mut execution = tokio::spawn(async move { racing_worker.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;

    let edited = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "edit-before-timer-lock",
                claims: &claims,
                record_id: Some(&record_id),
                expected_etag: Some(&create_etag),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/note".to_owned(),
                    value: json!("edited while claimed"),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary edit wins the record lock before timer execution");
    assert!(!edited.replayed());
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence_id);
    resume.notify_one();
    assert_eq!(
        execution
            .await
            .expect("worker task joins")
            .expect("due scan succeeds"),
        1
    );

    let (status, note, revision) = record_values(&database, &registry, &record_id).await;
    assert_eq!(status, "active");
    assert_eq!(note, "edited while claimed");
    assert_eq!(
        revision, 3,
        "create, concurrent edit, and activation each revise once"
    );
    assert_eq!(timer_state(&database, &record_id).await, "completed");
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence_id);
    let completed = effect_counts(&database, &registry, &record_id).await;
    assert_eq!(completed.revisions, before_timer.revisions + 2);
    assert_eq!(completed.outbox, before_timer.outbox + 1);
    assert_eq!(completed.action_receipts, before_timer.action_receipts + 1);

    drop(worker);
    let restarted = RecordTimerWorker::new_for_test(
        pool,
        registry.clone(),
        coordinator,
        identity,
        lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    assert_eq!(
        restarted.run_once().await.expect("restart scan succeeds"),
        0
    );
    assert_eq!(
        effect_counts(&database, &registry, &record_id).await,
        completed
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn material_rearm_retains_history_and_never_reuses_an_occurrence() {
    let database = TestDatabase::create(6).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs the timer ledger");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-material-history",
        },
    )
    .await
    .expect("migration initializes the active timer package");
    drop(migration);
    migration_task.abort();

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x76; 32].into())
            .expect("test owns a keyed audit profile"),
    );
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key is bounded");
    let coordinator = MutationTransaction::new(
        lock_key,
        Duration::from_secs(2),
        identity,
        INSTANCE_ID,
        audit,
    );
    let claims = ClaimContext::for_compiled(
        &registry,
        "service",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.service.create").unwrap();
    let patch_plan = MutationPlan::from_compiled(&registry, "records.service.patch").unwrap();
    let first_due = Utc::now() + chrono::Duration::hours(1);
    let second_due = first_due + chrono::Duration::hours(1);
    let first_due = first_due.to_rfc3339_opts(SecondsFormat::Micros, true);
    let second_due = second_due.to_rfc3339_opts(SecondsFormat::Micros, true);
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let created = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-material-history-service",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    ("activatesAt".to_owned(), json!(first_due)),
                    ("note".to_owned(), json!("material history")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms the first occurrence");
    let record_id = response_id(&created);
    let first_occurrence = timer_occurrence(&database, &record_id).await;

    let second = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "rearm-material-history-service-b",
                claims: &claims,
                record_id: Some(&record_id),
                expected_etag: Some(&response_etag(&created)),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/activatesAt".to_owned(),
                    value: json!(second_due),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("material change arms a successor occurrence");
    let second_occurrence = timer_occurrence(&database, &record_id).await;
    assert_ne!(second_occurrence, first_occurrence);

    coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "rearm-material-history-service-a",
                claims: &claims,
                record_id: Some(&record_id),
                expected_etag: Some(&response_etag(&second)),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/activatesAt".to_owned(),
                    value: json!(first_due),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("returning to the first material value creates a new occurrence");
    let third_occurrence = timer_occurrence(&database, &record_id).await;
    assert_ne!(third_occurrence, first_occurrence);
    assert_ne!(third_occurrence, second_occurrence);

    let history = database
        .admin
        .query_one(
            "SELECT count(*), count(DISTINCT occurrence_id),
                    count(*) FILTER (WHERE state='superseded'),
                    count(*) FILTER (WHERE state='pending')
               FROM registry_internal.registry_record_timer_generations
              WHERE record_type='service' AND record_id=$1::text::uuid AND timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("retained occurrence history is queryable");
    assert_eq!(history.get::<_, i64>(0), 3);
    assert_eq!(history.get::<_, i64>(1), 3);
    assert_eq!(history.get::<_, i64>(2), 2);
    assert_eq!(history.get::<_, i64>(3), 1);
    let current = database
        .admin
        .query_one(
            "SELECT occurrence_id,
                    (SELECT count(*)
                       FROM registry_internal.registry_record_timer_current
                      WHERE record_type='service' AND record_id=$1::text::uuid
                        AND timer_id='activate')
               FROM registry_internal.registry_record_timer_current
              WHERE record_type='service' AND record_id=$1::text::uuid AND timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("one current marker is queryable");
    assert_eq!(current.get::<_, uuid::Uuid>(0), third_occurrence);
    assert_eq!(current.get::<_, i64>(1), 1);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_system_context_without_a_live_claim_is_denied_by_rls() {
    let database = TestDatabase::create(6).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs timer RLS");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-package-forged-context",
        },
    )
    .await
    .expect("migration initializes the active package");
    drop(migration);
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x73; 32].into())
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
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.service.create").unwrap();
    let due = Utc::now() - chrono::Duration::seconds(1);
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let created = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-forged-context-service",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!(due.to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("forged context canary")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms a pending generation");
    let record_id = response_id(&created);
    let record_uuid = uuid::Uuid::parse_str(&record_id).unwrap();
    let timer = &registry.entities()["service"].timers["activate"];
    let occurrence = timer_occurrence(&database, &record_id).await;
    let revision: i64 = database
        .admin
        .query_one(
            &format!(
                "SELECT record_revision FROM registry_data.\"{}\" WHERE record_id=$1",
                registry.entities()["service"].physical_table
            ),
            &[&record_uuid],
        )
        .await
        .unwrap()
        .get(0);
    let instance_epoch: i64 = database
        .admin
        .query_one(
            "SELECT epoch FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let context = json!({
        "version":1,
        "actorKind":"system",
        "systemActor":"record-timer",
        "timerId":"activate",
        "occurrenceId":occurrence,
        "anchorRecordId":record_id,
        "claimToken":uuid::Uuid::new_v4(),
        "controlEpoch":1,
        "instanceEpoch":instance_epoch,
        "activationId":identity.activation_id,
        "systemGrantRevision":timer.system_grant.revision,
        "actionId":timer.invoke,
        "contractFingerprint":timer.action_revision,
        "activePackageRevision":identity.activation_id,
        "selectedAccessProfile":"system-record-timer",
        "principal":"urn:registrystack:breg:system:record-timer",
        "purpose":null,
        "effectIds":["activated"],
        "applicationId":uuid::Uuid::new_v4(),
        "targetEntityId":"service",
        "targetRecordId":record_id,
        "operation":"patch",
        "fields":["status"],
        "expectedRevision":revision,
        "lockOnly":false,
        "targetRowBoundaries":[]
    });
    let context = String::from_utf8(canonicalize_json(&context).unwrap()).unwrap();
    let transaction = client.transaction().await.unwrap();
    transaction
        .execute(
            "SELECT set_config('registry.principal',$1,true),
                    set_config('registry.access_profile',$2,true),
                    set_config('registry.active_package_revision',$3,true),
                    set_config('registry.immediate_action_target_context',$4,true)",
            &[
                &"urn:registrystack:breg:system:record-timer",
                &"system-record-timer",
                &identity.activation_id,
                &context,
            ],
        )
        .await
        .unwrap();
    let entity = &registry.entities()["service"];
    let changed = transaction
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"='active' WHERE record_id=$1",
                entity.physical_table, entity.fields["status"].physical_name
            ),
            &[&record_uuid],
        )
        .await
        .expect("forged context is evaluated without a database error");
    assert_eq!(
        changed, 0,
        "no live durable claim means no system write authority"
    );
    transaction.rollback().await.unwrap();
    assert_eq!(
        record_values(&database, &registry, &record_id).await.0,
        "scheduled"
    );
    assert_eq!(timer_state(&database, &record_id).await, "pending");
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_current
                SET record_id=$1
              WHERE record_type='service' AND record_id=$2 AND timer_id='activate'",
            &[&uuid::Uuid::new_v4(), &record_uuid],
        )
        .await
        .expect("fixture creates a mismatched current marker");
    let worker = RecordTimerWorker::new_for_test(
        pool,
        registry,
        coordinator,
        identity,
        lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("mismatched marker is a fail-closed non-claim"),
        0
    );
    let unchanged = database
        .admin
        .query_one(
            "SELECT state,claim_epoch FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence],
        )
        .await
        .expect("mismatched occurrence remains unclaimed");
    assert_eq!(unchanged.get::<_, String>(0), "pending");
    assert_eq!(unchanged.get::<_, i64>(1), 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_timer_patch_authority_is_bound_to_its_exact_anchor() {
    let harness =
        timer_outcome_harness(compiled_registry(), "record-timer-exact-patch-anchor", 0x6d).await;
    let anchor = create_outcome_service(
        &harness,
        "create-exact-patch-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let victim = create_outcome_service(
        &harness,
        "create-unbound-patch-victim",
        "held",
        Utc::now() + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let anchor_id = response_id(&anchor);
    let victim_id = response_id(&victim);
    let occurrence_id = timer_occurrence(&harness.database, &anchor_id).await;
    let worker = harness.worker(Duration::from_secs(10));
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let waiting = worker
        .clone()
        .with_claim_barrier_for_test(Arc::clone(&claimed), Arc::clone(&resume));
    let mut execution = tokio::spawn(async move { waiting.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;
    let claim = harness
        .database
        .admin
        .query_one(
            "SELECT claim_token,claim_owner_id,claim_epoch,claimed_control_epoch,
                    claimed_instance_epoch,claimed_activation_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the exact occurrence has one live claim");
    let entity = &harness.registry.entities()["service"];
    let anchor_uuid = uuid::Uuid::parse_str(&anchor_id).unwrap();
    let victim_uuid = uuid::Uuid::parse_str(&victim_id).unwrap();
    let revisions = harness
        .database
        .admin
        .query(
            &format!(
                "SELECT record_id,record_revision
                   FROM registry_data.\"{}\"
                  WHERE record_id=ANY($1::uuid[])",
                entity.physical_table
            ),
            &[&vec![anchor_uuid, victim_uuid]],
        )
        .await
        .expect("the anchor and victim revisions are queryable")
        .into_iter()
        .map(|row| (row.get::<_, uuid::Uuid>(0), row.get::<_, i64>(1)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let claim_token = claim.get::<_, uuid::Uuid>(0);
    let claim_owner_id = claim.get::<_, uuid::Uuid>(1);
    let claim_epoch = claim.get::<_, i64>(2);
    let control_epoch = claim.get::<_, i64>(3);
    let instance_epoch = claim.get::<_, i64>(4);
    let activation_id = claim.get::<_, uuid::Uuid>(5);

    for (target_id, expected_revision, expected_rows) in [
        (anchor_uuid, revisions[&anchor_uuid], 1_u64),
        (victim_uuid, revisions[&victim_uuid], 0_u64),
    ] {
        let context = timer_patch_context(
            &harness.registry,
            &harness.identity,
            occurrence_id,
            anchor_uuid,
            target_id,
            claim_token,
            claim_owner_id,
            claim_epoch,
            control_epoch,
            instance_epoch,
            activation_id,
            expected_revision,
        );
        let mut client = harness
            .pool
            .get_for_test()
            .await
            .expect("runtime connection");
        let transaction = client.transaction().await.unwrap();
        transaction
            .execute(
                "SELECT set_config('registry.principal',$1,true),
                        set_config('registry.access_profile',$2,true),
                        set_config('registry.active_package_revision',$3,true),
                        set_config('registry.immediate_action_target_context',$4,true)",
                &[
                    &"urn:registrystack:breg:system:record-timer",
                    &"system-record-timer",
                    &harness.identity.activation_id,
                    &context,
                ],
            )
            .await
            .unwrap();
        let changed = transaction
            .execute(
                &format!(
                    "UPDATE registry_data.\"{}\" SET \"{}\"='active' WHERE record_id=$1",
                    entity.physical_table, entity.fields["status"].physical_name
                ),
                &[&target_id],
            )
            .await
            .expect("the exact live-claim policy evaluates without a database error");
        assert_eq!(
            changed, expected_rows,
            "a live claim authorizes only its exact anchor Patch"
        );
        transaction.rollback().await.unwrap();
    }

    resume.notify_one();
    assert_eq!(
        execution
            .await
            .expect("worker task joins")
            .expect("the genuine timer execution succeeds"),
        1
    );
    assert_eq!(
        record_values(&harness.database, &harness.registry, &victim_id)
            .await
            .0,
        "held"
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_only_action_locks_its_exact_anchor_and_commits_once() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_create_only_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs timer and create-target policies");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-package-create-only",
        },
    )
    .await
    .expect("migration initializes the active package");
    drop(migration);
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x75; 32].into())
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
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.service.create").unwrap();
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let created = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-anchor-for-create-only-timer",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("create-only anchor canary")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms one due generation");
    let record_id = response_id(&created);
    let occurrence = timer_occurrence(&database, &record_id).await;
    let worker = RecordTimerWorker::new_for_test(
        pool.clone(),
        registry.clone(),
        coordinator,
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        Duration::from_secs(10),
    );
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let waiting_worker = worker
        .clone()
        .with_claim_barrier_for_test(claimed.clone(), resume.clone())
        .with_fault_for_test(MutationFaultPoint::BeforeCommit);
    let mut execution = tokio::spawn(async move { waiting_worker.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;
    let claim = database
        .admin
        .query_one(
            "SELECT claim_token,claim_owner_id,claim_epoch,claimed_control_epoch,
                    claimed_instance_epoch,claimed_activation_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence],
        )
        .await
        .expect("worker persisted one exact live claim");
    let timer = &registry.entities()["service"].timers["activate"];
    let target = &registry.entities()["activation-log"];
    let derived_target_id = timer_create_target_id_for_test(
        occurrence,
        &timer.action_revision,
        "activation-log",
        "activation-log",
    );
    let derived_context = timer_create_context(
        &identity,
        timer,
        occurrence,
        uuid::Uuid::parse_str(&record_id).unwrap(),
        derived_target_id,
        claim.get(0),
        claim.get(1),
        claim.get(2),
        claim.get(3),
        claim.get(4),
        claim.get(5),
    );
    let mut derived_client = pool.get_for_test().await.expect("runtime connection");
    let derived_insert = derived_client.transaction().await.unwrap();
    derived_insert
        .execute(
            "SELECT set_config('registry.principal',$1,true),
                    set_config('registry.access_profile',$2,true),
                    set_config('registry.active_package_revision',$3,true),
                    set_config('registry.immediate_action_target_context',$4,true)",
            &[
                &"urn:registrystack:breg:system:record-timer",
                &"system-record-timer",
                &identity.activation_id,
                &derived_context,
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        derived_insert
            .execute(
                &format!(
                    "INSERT INTO registry_data.\"{}\" (
                         record_id,record_revision,record_lifecycle,\"{}\",\"{}\",\"{}\"
                     ) VALUES ($1,1,'active',$2,$3,$4)",
                    target.physical_table,
                    target.fields["activation-number"].physical_name,
                    target.fields["planned-at"].physical_name,
                    target.fields["operation-id"].physical_name,
                ),
                &[&derived_target_id, &"ACT-9999", &Utc::now(), &occurrence],
            )
            .await
            .expect("the exact derived timer Create target is authorized"),
        1
    );
    derived_insert.rollback().await.unwrap();

    let random_target_id = uuid::Uuid::new_v4();
    let create_context = timer_create_context(
        &identity,
        timer,
        occurrence,
        uuid::Uuid::parse_str(&record_id).unwrap(),
        random_target_id,
        claim.get(0),
        claim.get(1),
        claim.get(2),
        claim.get(3),
        claim.get(4),
        claim.get(5),
    );
    let mut forged_create_client = pool.get_for_test().await.expect("runtime connection");
    let forged_create = forged_create_client.transaction().await.unwrap();
    forged_create
        .execute(
            "SELECT set_config('registry.principal',$1,true),
                    set_config('registry.access_profile',$2,true),
                    set_config('registry.active_package_revision',$3,true),
                    set_config('registry.immediate_action_target_context',$4,true)",
            &[
                &"urn:registrystack:breg:system:record-timer",
                &"system-record-timer",
                &identity.activation_id,
                &create_context,
            ],
        )
        .await
        .unwrap();
    let random_insert = forged_create
        .execute(
            &format!(
                "INSERT INTO registry_data.\"{}\" (
                     record_id,record_revision,record_lifecycle,\"{}\",\"{}\",\"{}\"
                 ) VALUES ($1,1,'active',$2,$3,$4)",
                target.physical_table,
                target.fields["activation-number"].physical_name,
                target.fields["planned-at"].physical_name,
                target.fields["operation-id"].physical_name,
            ),
            &[&random_target_id, &"ACT-9999", &Utc::now(), &occurrence],
        )
        .await;
    assert!(
        random_insert.is_err(),
        "a live claim must not create an arbitrary timer target identity"
    );
    forged_create.rollback().await.unwrap();

    let victim_id = uuid::Uuid::new_v4();
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.\"{}\" (
                     record_id,record_revision,record_lifecycle,active_package_revision,\"{}\",\"{}\",\"{}\"
                 ) VALUES ($1,1,'active',$2,$3,$4,$5)",
                target.physical_table,
                target.fields["activation-number"].physical_name,
                target.fields["planned-at"].physical_name,
                target.fields["operation-id"].physical_name,
            ),
            &[
                &victim_id,
                &identity.activation_id,
                &"ACT-9998",
                &Utc::now(),
                &uuid::Uuid::new_v4(),
            ],
        )
        .await
        .expect("administrator seeds an unrelated create-target victim");
    let victim_context = timer_create_context(
        &identity,
        timer,
        occurrence,
        uuid::Uuid::parse_str(&record_id).unwrap(),
        victim_id,
        claim.get(0),
        claim.get(1),
        claim.get(2),
        claim.get(3),
        claim.get(4),
        claim.get(5),
    );
    let mut forged_select_client = pool.get_for_test().await.expect("runtime connection");
    let forged_select = forged_select_client.transaction().await.unwrap();
    forged_select
        .execute(
            "SELECT set_config('registry.principal',$1,true),
                    set_config('registry.access_profile',$2,true),
                    set_config('registry.active_package_revision',$3,true),
                    set_config('registry.immediate_action_target_context',$4,true)",
            &[
                &"urn:registrystack:breg:system:record-timer",
                &"system-record-timer",
                &identity.activation_id,
                &victim_context,
            ],
        )
        .await
        .unwrap();
    assert!(
        forged_select
            .query_opt(
                &format!(
                    "SELECT record_id FROM registry_data.\"{}\" WHERE record_id=$1",
                    target.physical_table
                ),
                &[&victim_id],
            )
            .await
            .expect("the create-result SELECT policy evaluates")
            .is_none(),
        "a live claim must not reveal an arbitrary existing create target"
    );
    forged_select.rollback().await.unwrap();

    let read_fields = &timer
        .system_grant
        .targets
        .iter()
        .find(|target| {
            target.entity_id == "service"
                && target.operation == registry_breg::contract::Operation::Get
        })
        .expect("timer grant carries the exact anchor read ceiling")
        .read_fields;
    let context = json!({
        "version":1,
        "actorKind":"system",
        "systemActor":"record-timer",
        "timerId":timer.id,
        "occurrenceId":occurrence,
        "anchorRecordId":record_id,
        "claimToken":claim.get::<_, uuid::Uuid>(0),
        "claimOwnerId":claim.get::<_, uuid::Uuid>(1),
        "claimEpoch":claim.get::<_, i64>(2),
        "controlEpoch":claim.get::<_, i64>(3),
        "instanceEpoch":claim.get::<_, i64>(4),
        "activationId":claim.get::<_, uuid::Uuid>(5),
        "systemGrantRevision":timer.system_grant.revision,
        "actionId":timer.invoke,
        "contractFingerprint":timer.action_revision,
        "activePackageRevision":identity.activation_id,
        "selectedAccessProfile":"system-record-timer",
        "principal":"urn:registrystack:breg:system:record-timer",
        "purpose":null,
        "effectIds":[],
        "applicationId":occurrence,
        "targetEntityId":"service",
        "targetRecordId":record_id,
        "operation":"get",
        "fields":read_fields,
        "expectedRevision":null,
        "lockOnly":true,
        "targetRowBoundaries":[]
    });
    let context = String::from_utf8(canonicalize_json(&context).unwrap()).unwrap();
    let mut authority_client = pool.get_for_test().await.expect("runtime connection");
    let authority_transaction = authority_client.transaction().await.unwrap();
    authority_transaction
        .execute(
            "SELECT set_config('registry.principal',$1,true),
                    set_config('registry.access_profile',$2,true),
                    set_config('registry.active_package_revision',$3,true),
                    set_config('registry.immediate_action_target_context',$4,true)",
            &[
                &"urn:registrystack:breg:system:record-timer",
                &"system-record-timer",
                &identity.activation_id,
                &context,
            ],
        )
        .await
        .unwrap();
    let anchor = &registry.entities()["service"];
    assert!(authority_transaction
        .query_opt(
            &format!(
                "SELECT record_id FROM registry_data.\"{}\" WHERE record_id=$1 FOR UPDATE",
                anchor.physical_table
            ),
            &[&uuid::Uuid::parse_str(&record_id).unwrap()],
        )
        .await
        .expect("exact Get authority may lock its claimed anchor")
        .is_some());
    let denied = authority_transaction
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"='active' WHERE record_id=$1",
                anchor.physical_table, anchor.fields["status"].physical_name
            ),
            &[&uuid::Uuid::parse_str(&record_id).unwrap()],
        )
        .await;
    assert!(
        denied.is_err(),
        "the exact Get lock policy must never authorize an anchor mutation"
    );
    authority_transaction.rollback().await.unwrap();
    resume.notify_one();
    assert!(
        execution.await.expect("worker task joins").is_err(),
        "the injected pre-commit failure remains visible"
    );
    let first_attempt = database
        .admin
        .query_one(
            "SELECT state,executed_attempt_count,retry_at,
                    (SELECT count(*)
                       FROM registry_internal.registry_record_timer_attempts AS attempt
                      WHERE attempt.occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_generations AS generation
              WHERE occurrence_id=$1",
            &[&occurrence],
        )
        .await
        .expect("the rolled-back attempt has one durable technical settlement");
    assert_eq!(first_attempt.get::<_, String>(0), "pending");
    assert_eq!(first_attempt.get::<_, i32>(1), 1);
    assert!(first_attempt
        .get::<_, Option<chrono::DateTime<Utc>>>(2)
        .is_some());
    assert_eq!(first_attempt.get::<_, i64>(3), 1);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the persisted retry gate is a normal idle scan"),
        0
    );
    let operation = &target.fields["operation-id"].physical_name;
    assert_eq!(
        database
            .admin
            .query_one(
                &format!(
                    "SELECT count(*) FROM registry_data.\"{}\" WHERE \"{operation}\"=$1",
                    target.physical_table
                ),
                &[&occurrence],
            )
            .await
            .expect("the rolled-back Create leaves no target record")
            .get::<_, i64>(0),
        0
    );
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(
        worker
            .clone()
            .with_fault_for_test(MutationFaultPoint::AfterCommitBeforeResponseRelease)
            .run_once()
            .await
            .is_err(),
        "lost response after the retried Create commit remains visible"
    );
    assert_eq!(timer_state(&database, &record_id).await, "completed");
    assert_eq!(
        record_values(&database, &registry, &record_id).await.0,
        "scheduled"
    );
    let activation_number = &target.fields["activation-number"].physical_name;
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*), min(record_id::text), min(\"{operation}\"::text),
                        min(\"{activation_number}\"::text)
                   FROM registry_data.\"{}\" WHERE \"{operation}\"=$1",
                target.physical_table
            ),
            &[&occurrence],
        )
        .await
        .expect("one created effect is queryable");
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(
        row.get::<_, Option<String>>(1).as_deref(),
        Some(derived_target_id.to_string().as_str())
    );
    assert_eq!(
        row.get::<_, Option<String>>(2).as_deref(),
        Some(occurrence.to_string().as_str())
    );
    assert_eq!(row.get::<_, Option<String>>(3).as_deref(), Some("ACT-0001"));
    let effects = database
        .admin
        .query_one(
            &format!(
                "SELECT
                (SELECT count(*) FROM registry_internal.registry_revisions
                  WHERE entity_id='activation-log' AND record_id=$1),
                (SELECT count(*) FROM registry_internal.registry_outbox
                  WHERE entity_id='activation-log'),
                (SELECT count(*) FROM registry_internal.registry_idempotency
                  WHERE result_kind='immediate_action'),
                (SELECT count(*) FROM registry_internal.registry_record_timer_attempts
                  WHERE occurrence_id=$2),
                (SELECT count(*)
                   FROM registry_data.\"{}\"
                  WHERE \"{activation_number}\"='ACT-0002')",
                target.physical_table
            ),
            &[&derived_target_id, &occurrence],
        )
        .await
        .expect("the retried Create has one bounded durable effect set");
    assert_eq!(effects.get::<_, i64>(0), 1);
    assert_eq!(effects.get::<_, i64>(1), 1);
    assert_eq!(effects.get::<_, i64>(2), 1);
    assert_eq!(effects.get::<_, i64>(3), 2);
    assert_eq!(effects.get::<_, i64>(4), 0);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("completed timer does not refire"),
        0
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_action_locks_a_declared_secondary_get_target() {
    let harness = timer_outcome_harness(
        compiled_secondary_get_registry(),
        "record-timer-secondary-get",
        0x66,
    )
    .await;
    let approval_claims = ClaimContext::for_compiled(
        &harness.registry,
        "approval",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("approval authority is compiler-bound");
    let approval_plan =
        MutationPlan::from_compiled(&harness.registry, "records.approval.create").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let mut approval_ids = Vec::new();
    for (key, status) in [
        ("create-secondary-approval-original", "approved"),
        ("create-secondary-approval-current", "approved"),
        ("create-secondary-approval-unbound", "approved"),
    ] {
        let approval = harness
            .coordinator
            .execute(
                &mut client,
                MutationRequest {
                    plan: &approval_plan,
                    idempotency_key: key,
                    claims: &approval_claims,
                    record_id: None,
                    expected_etag: None,
                    body: MutationBody::Create(Map::from_iter([
                        ("jurisdiction".to_owned(), json!("zone-a")),
                        ("status".to_owned(), json!(status)),
                    ])),
                    response_fields: BTreeSet::from([
                        "jurisdiction".to_owned(),
                        "status".to_owned(),
                    ]),
                    representation: RecordRepresentation::Json,
                    correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
                },
            )
            .await
            .expect("secondary guard target is created");
        approval_ids.push(response_id(&approval));
    }
    let service_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.create").unwrap();
    let service = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &service_plan,
                idempotency_key: "create-secondary-get-anchor",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("approval".to_owned(), json!(approval_ids[0])),
                    ("note".to_owned(), json!("secondary get anchor")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("timer anchor is created");
    let service_id = response_id(&service);
    let occurrence_id = timer_occurrence(&harness.database, &service_id).await;
    let patch_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.patch").unwrap();
    let service_etag = response_etag(&service);
    let patched = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "move-secondary-get-target",
                claims: &harness.claims,
                record_id: Some(service_id.as_str()),
                expected_etag: Some(service_etag.as_str()),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/approval".to_owned(),
                    value: json!(approval_ids[1]),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary input write refreshes the live target binding");
    assert!(!patched.replayed());
    assert_eq!(
        timer_occurrence(&harness.database, &service_id).await,
        occurrence_id,
        "a live target refresh must not replace the occurrence"
    );
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let waiting_worker = harness
        .worker(Duration::from_secs(10))
        .with_claim_barrier_for_test(claimed.clone(), resume.clone());
    let mut execution = tokio::spawn(async move { waiting_worker.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;
    let claim = harness
        .database
        .admin
        .query_one(
            "SELECT claim_token,claim_owner_id,claim_epoch,claimed_control_epoch,
                    claimed_instance_epoch,claimed_activation_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("worker persisted one exact live claim");
    let timer = &harness.registry.entities()["service"].timers["activate"];
    let read_fields = &timer
        .system_grant
        .targets
        .iter()
        .find(|target| {
            target.entity_id == "approval"
                && target.operation == registry_breg::contract::Operation::Get
        })
        .expect("timer grant carries the declared secondary read ceiling")
        .read_fields;
    let context = json!({
        "version":1,
        "actorKind":"system",
        "systemActor":"record-timer",
        "timerId":timer.id,
        "targetInputId":"approval",
        "occurrenceId":occurrence_id,
        "anchorRecordId":service_id,
        "claimToken":claim.get::<_, uuid::Uuid>(0),
        "claimOwnerId":claim.get::<_, uuid::Uuid>(1),
        "claimEpoch":claim.get::<_, i64>(2),
        "controlEpoch":claim.get::<_, i64>(3),
        "instanceEpoch":claim.get::<_, i64>(4),
        "activationId":claim.get::<_, uuid::Uuid>(5),
        "systemGrantRevision":timer.system_grant.revision,
        "actionId":timer.invoke,
        "contractFingerprint":timer.action_revision,
        "activePackageRevision":harness.identity.activation_id,
        "selectedAccessProfile":"system-record-timer",
        "principal":"urn:registrystack:breg:system:record-timer",
        "purpose":null,
        "effectIds":[],
        "applicationId":occurrence_id,
        "targetEntityId":"approval",
        "targetRecordId":approval_ids[2],
        "operation":"get",
        "fields":read_fields,
        "expectedRevision":null,
        "lockOnly":true,
        "targetRowBoundaries":[]
    });
    let context = String::from_utf8(canonicalize_json(&context).unwrap()).unwrap();
    let mut authority_client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let authority_transaction = authority_client.transaction().await.unwrap();
    authority_transaction
        .execute(
            "SELECT set_config('registry.principal',$1,true),
                    set_config('registry.access_profile',$2,true),
                    set_config('registry.active_package_revision',$3,true),
                    set_config('registry.immediate_action_target_context',$4,true)",
            &[
                &"urn:registrystack:breg:system:record-timer",
                &"system-record-timer",
                &harness.identity.activation_id,
                &context,
            ],
        )
        .await
        .unwrap();
    let approval = &harness.registry.entities()["approval"];
    assert!(authority_transaction
        .query_opt(
            &format!(
                "SELECT record_id FROM registry_data.\"{}\" WHERE record_id=$1 FOR UPDATE",
                approval.physical_table
            ),
            &[&uuid::Uuid::parse_str(&approval_ids[2]).unwrap()],
        )
        .await
        .expect("unbound target denial is evaluated without a database error")
        .is_none());
    authority_transaction.rollback().await.unwrap();
    resume.notify_one();
    assert_eq!(
        execution
            .await
            .expect("worker task joins")
            .expect("declared secondary Get executes"),
        1
    );
    assert_eq!(
        timer_state(&harness.database, &service_id).await,
        "completed"
    );
    assert_eq!(
        record_values(&harness.database, &harness.registry, &service_id)
            .await
            .0,
        "active"
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_literal_secondary_get_target_is_terminal_input_refusal() {
    let harness = timer_outcome_harness(
        compiled_missing_literal_secondary_get_registry(),
        "record-timer-missing-literal-target",
        0x71,
    )
    .await;
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let service_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.create").unwrap();
    let service = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &service_plan,
                idempotency_key: "create-anchor-with-missing-literal-target",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("missing literal target anchor")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("timer anchor is created");
    let service_id = response_id(&service);
    let occurrence_id = timer_occurrence(&harness.database, &service_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("missing literal target settles as an input refusal"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "refused", 1, "input-refused").await;
    assert_eq!(
        record_values(&harness.database, &harness.registry, &service_id)
            .await
            .0,
        "scheduled"
    );
    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("terminal refusal is not claimed again"),
        0
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn secondary_mapping_change_after_preflight_retries_the_current_target() {
    let harness = timer_outcome_harness(
        compiled_secondary_get_registry(),
        "record-timer-secondary-preflight-race",
        0x74,
    )
    .await;
    let approval_claims = ClaimContext::for_compiled(
        &harness.registry,
        "approval",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("approval authority is compiler-bound");
    let approval_plan =
        MutationPlan::from_compiled(&harness.registry, "records.approval.create").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let mut approval_ids = Vec::new();
    for key in [
        "create-preflight-old-approval",
        "create-preflight-current-approval",
    ] {
        let approval = harness
            .coordinator
            .execute(
                &mut client,
                MutationRequest {
                    plan: &approval_plan,
                    idempotency_key: key,
                    claims: &approval_claims,
                    record_id: None,
                    expected_etag: None,
                    body: MutationBody::Create(Map::from_iter([
                        ("jurisdiction".to_owned(), json!("zone-a")),
                        ("status".to_owned(), json!("approved")),
                    ])),
                    response_fields: BTreeSet::from([
                        "jurisdiction".to_owned(),
                        "status".to_owned(),
                    ]),
                    representation: RecordRepresentation::Json,
                    correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
                },
            )
            .await
            .expect("approval target is created");
        approval_ids.push(response_id(&approval));
    }
    let service_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.create").unwrap();
    let service = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &service_plan,
                idempotency_key: "create-preflight-race-anchor",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("approval".to_owned(), json!(approval_ids[0])),
                    ("note".to_owned(), json!("preflight race anchor")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("timer anchor is created");
    let service_id = response_id(&service);
    let occurrence_id = timer_occurrence(&harness.database, &service_id).await;
    let preflight = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let waiting_worker = harness
        .worker(Duration::from_secs(2))
        .with_preflight_barrier_for_test(preflight.clone(), resume.clone());
    let mut execution = tokio::spawn(async move { waiting_worker.run_once().await });
    wait_for_timer_barrier(&preflight, &mut execution, "the post-preflight barrier").await;
    let patch_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.patch").unwrap();
    let patched = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "move-target-after-preflight",
                claims: &harness.claims,
                record_id: Some(&service_id),
                expected_etag: Some(&response_etag(&service)),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/approval".to_owned(),
                    value: json!(approval_ids[1]),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary write changes the mapped target after preflight");
    assert!(!patched.replayed());
    assert_eq!(
        timer_occurrence(&harness.database, &service_id).await,
        occurrence_id
    );
    resume.notify_one();
    assert!(matches!(
        execution.await.expect("worker task joins"),
        Err(registry_breg::mutation::MutationError::RetryableConflict)
    ));
    assert_timer_technical_failure(&harness, occurrence_id, "concurrency-conflict").await;
    harness
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_generations
                SET retry_at=clock_timestamp()
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("fixture advances only the persisted retry gate");
    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("retry executes against the current mapped target"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 2, "completed").await;
    assert_eq!(
        record_values(&harness.database, &harness.registry, &service_id)
            .await
            .0,
        "active"
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrated_secondary_mapping_refreshes_digest_before_current_action() {
    let harness = timer_outcome_harness(
        compiled_secondary_get_registry(),
        "record-timer-migrated-secondary-mapping",
        0x79,
    )
    .await;
    let approval_claims = ClaimContext::for_compiled(
        &harness.registry,
        "approval",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("approval authority is compiler-bound");
    let approval_plan =
        MutationPlan::from_compiled(&harness.registry, "records.approval.create").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let mut approval_ids = Vec::new();
    for (key, status) in [
        ("create-migrated-mapping-old-approval", "pending"),
        ("create-migrated-mapping-current-approval", "approved"),
    ] {
        let approval = harness
            .coordinator
            .execute(
                &mut client,
                MutationRequest {
                    plan: &approval_plan,
                    idempotency_key: key,
                    claims: &approval_claims,
                    record_id: None,
                    expected_etag: None,
                    body: MutationBody::Create(Map::from_iter([
                        ("jurisdiction".to_owned(), json!("zone-a")),
                        ("status".to_owned(), json!(status)),
                    ])),
                    response_fields: BTreeSet::from([
                        "jurisdiction".to_owned(),
                        "status".to_owned(),
                    ]),
                    representation: RecordRepresentation::Json,
                    correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
                },
            )
            .await
            .expect("migration target approval is created");
        approval_ids.push(response_id(&approval));
    }
    let service_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.create").unwrap();
    let service = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &service_plan,
                idempotency_key: "create-migrated-mapping-anchor",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("approval".to_owned(), json!(approval_ids[0])),
                    ("note".to_owned(), json!("migrated mapping anchor")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("migrated mapping anchor is created");
    let service_id = response_id(&service);
    let occurrence_id = timer_occurrence(&harness.database, &service_id).await;
    let before_digest: Value = harness
        .database
        .admin
        .query_one(
            "SELECT target_binding_digests
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the predecessor digest is queryable")
        .get(0);
    let service_entity = &harness.registry.entities()["service"];
    let approval_field = &service_entity.fields["approval"];
    let (mut migration, migration_task) = harness.database.connect_migration().await;
    let migration_transaction = migration
        .transaction()
        .await
        .expect("the reviewed migration transaction starts");
    registry_breg::postgres::set_force_row_security_for_test(
        &migration_transaction,
        std::slice::from_ref(&service_entity.physical_table),
        false,
    )
    .await
    .expect("reviewed migration uses the maintained row authority");
    let affected = migration_transaction
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"=$1 WHERE record_id=$2",
                service_entity.physical_table, approval_field.physical_name,
            ),
            &[
                &uuid::Uuid::parse_str(&approval_ids[1]).unwrap(),
                &uuid::Uuid::parse_str(&service_id).unwrap(),
            ],
        )
        .await
        .expect("fixture models one reviewed SQL migration of the mapped field");
    assert_eq!(affected, 1, "reviewed migration changes the current fact");
    registry_breg::postgres::set_force_row_security_for_test(
        &migration_transaction,
        std::slice::from_ref(&service_entity.physical_table),
        true,
    )
    .await
    .expect("reviewed migration restores forced row security");
    migration_transaction
        .commit()
        .await
        .expect("the reviewed migration transaction commits");
    migration_task.abort();
    let stored_mapping: uuid::Uuid = harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT \"{}\" FROM registry_data.\"{}\" WHERE record_id=$1",
                approval_field.physical_name, service_entity.physical_table,
            ),
            &[&uuid::Uuid::parse_str(&service_id).unwrap()],
        )
        .await
        .expect("the reviewed migration's current fact is queryable")
        .get(0);
    assert_eq!(stored_mapping.to_string(), approval_ids[1]);
    let unchanged_digest: Value = harness
        .database
        .admin
        .query_one(
            "SELECT target_binding_digests
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("migration bypasses ordinary timer staging by construction")
        .get(0);
    assert_eq!(unchanged_digest, before_digest);

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("current mapped facts are reconciled before target locks"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    assert_eq!(
        record_values(&harness.database, &harness.registry, &service_id)
            .await
            .0,
        "active"
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existence_only_secondary_get_locks_only_the_bound_uuid() {
    let harness = timer_outcome_harness(
        compiled_existence_only_secondary_get_registry(),
        "record-timer-existence-only-get",
        0x73,
    )
    .await;
    let approval_claims = ClaimContext::for_compiled(
        &harness.registry,
        "approval",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("approval authority is compiler-bound");
    let approval_plan =
        MutationPlan::from_compiled(&harness.registry, "records.approval.create").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let mut approval_ids = Vec::new();
    for key in ["create-bound-approval", "create-unbound-approval"] {
        let approval = harness
            .coordinator
            .execute(
                &mut client,
                MutationRequest {
                    plan: &approval_plan,
                    idempotency_key: key,
                    claims: &approval_claims,
                    record_id: None,
                    expected_etag: None,
                    body: MutationBody::Create(Map::from_iter([
                        ("jurisdiction".to_owned(), json!("zone-a")),
                        ("status".to_owned(), json!("approved")),
                    ])),
                    response_fields: BTreeSet::from([
                        "jurisdiction".to_owned(),
                        "status".to_owned(),
                    ]),
                    representation: RecordRepresentation::Json,
                    correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
                },
            )
            .await
            .expect("approval target is created");
        approval_ids.push(response_id(&approval));
    }
    let service_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.create").unwrap();
    let service = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &service_plan,
                idempotency_key: "create-existence-only-anchor",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("approval".to_owned(), json!(approval_ids[0])),
                    ("note".to_owned(), json!("existence-only anchor")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("timer anchor is created");
    let service_id = response_id(&service);
    let occurrence_id = timer_occurrence(&harness.database, &service_id).await;
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let waiting_worker = harness
        .worker(Duration::from_secs(10))
        .with_claim_barrier_for_test(claimed.clone(), resume.clone());
    let mut execution = tokio::spawn(async move { waiting_worker.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;
    let claim = harness
        .database
        .admin
        .query_one(
            "SELECT claim_token,claim_owner_id,claim_epoch,claimed_control_epoch,
                    claimed_instance_epoch,claimed_activation_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("worker persisted one exact live claim");
    let timer = &harness.registry.entities()["service"].timers["activate"];
    let read_fields = &timer
        .system_grant
        .targets
        .iter()
        .find(|target| {
            target.entity_id == "approval"
                && target.operation == registry_breg::contract::Operation::Get
        })
        .expect("timer grant carries an existence-only Get")
        .read_fields;
    assert!(read_fields.is_empty());
    let context = json!({
        "version":1,
        "actorKind":"system",
        "systemActor":"record-timer",
        "timerId":timer.id,
        "targetInputId":"approval",
        "occurrenceId":occurrence_id,
        "anchorRecordId":service_id,
        "claimToken":claim.get::<_, uuid::Uuid>(0),
        "claimOwnerId":claim.get::<_, uuid::Uuid>(1),
        "claimEpoch":claim.get::<_, i64>(2),
        "controlEpoch":claim.get::<_, i64>(3),
        "instanceEpoch":claim.get::<_, i64>(4),
        "activationId":claim.get::<_, uuid::Uuid>(5),
        "systemGrantRevision":timer.system_grant.revision,
        "actionId":timer.invoke,
        "contractFingerprint":timer.action_revision,
        "activePackageRevision":harness.identity.activation_id,
        "selectedAccessProfile":"system-record-timer",
        "principal":"urn:registrystack:breg:system:record-timer",
        "purpose":null,
        "effectIds":[],
        "applicationId":occurrence_id,
        "targetEntityId":"approval",
        "targetRecordId":approval_ids[1],
        "operation":"get",
        "fields":[],
        "expectedRevision":null,
        "lockOnly":true,
        "targetRowBoundaries":[]
    });
    let context = String::from_utf8(canonicalize_json(&context).unwrap()).unwrap();
    let mut authority_client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let authority_transaction = authority_client.transaction().await.unwrap();
    authority_transaction
        .execute(
            "SELECT set_config('registry.principal',$1,true),
                    set_config('registry.access_profile',$2,true),
                    set_config('registry.active_package_revision',$3,true),
                    set_config('registry.immediate_action_target_context',$4,true)",
            &[
                &"urn:registrystack:breg:system:record-timer",
                &"system-record-timer",
                &harness.identity.activation_id,
                &context,
            ],
        )
        .await
        .unwrap();
    let approval = &harness.registry.entities()["approval"];
    assert!(authority_transaction
        .query_opt(
            &format!(
                "SELECT record_id FROM registry_data.\"{}\" WHERE record_id=$1 FOR UPDATE",
                approval.physical_table
            ),
            &[&uuid::Uuid::parse_str(&approval_ids[1]).unwrap()],
        )
        .await
        .expect("unbound existence-only target denial is evaluated")
        .is_none());
    authority_transaction.rollback().await.unwrap();
    resume.notify_one();
    assert_eq!(
        execution
            .await
            .expect("worker task joins")
            .expect("bound existence-only Get executes"),
        1
    );
    assert_eq!(
        timer_state(&harness.database, &service_id).await,
        "completed"
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_action_locks_a_same_type_non_anchor_get_target() {
    let harness = timer_outcome_harness(
        compiled_same_type_get_registry(),
        "record-timer-same-type-get",
        0x69,
    )
    .await;
    let create_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.create").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let target = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-same-type-get-target",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("approved")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() + chrono::Duration::hours(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("same-type target")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("same-type guard target is created");
    let target_id = response_id(&target);
    let anchor = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-same-type-get-anchor",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("relatedService".to_owned(), json!(target_id)),
                    ("note".to_owned(), json!("same-type anchor")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("same-type timer anchor is created");
    let anchor_id = response_id(&anchor);
    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("same-type non-anchor Get executes"),
        1
    );
    assert_eq!(
        timer_state(&harness.database, &anchor_id).await,
        "completed"
    );
    assert_eq!(
        record_values(&harness.database, &harness.registry, &anchor_id)
            .await
            .0,
        "active"
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_predicate_write_opens_the_same_occurrence_and_maps_current_plaintext() {
    use registry_platform_testing::CapturedDiagnosticLogs;
    use tracing::instrument::WithSubscriber;

    const ENCRYPTED_NOTE_CANARY: &str = "encrypted-note-plaintext-must-not-enter-timer-ledger";
    let harness = encrypted_timer_harness("record-timer-encrypted-current", 0x68).await;
    let created = create_outcome_service(
        &harness,
        "encrypted-current",
        "inactive",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    assert!(!timer_gate_open(&harness.database, &record_id).await);
    let patch_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.patch").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "open-encrypted-current-gate",
                claims: &harness.claims,
                record_id: Some(&record_id),
                expected_etag: Some(&response_etag(&created)),
                body: MutationBody::Patch(vec![
                    PatchOperation::Replace {
                        path: "/data/status".to_owned(),
                        value: json!("scheduled"),
                    },
                    PatchOperation::Replace {
                        path: "/data/note".to_owned(),
                        value: json!(ENCRYPTED_NOTE_CANARY),
                    },
                ]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary encrypted predicate write opens the cached gate");
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id,
        "predicate-only changes retain occurrence identity"
    );
    assert!(timer_gate_open(&harness.database, &record_id).await);
    let captured_logs = CapturedDiagnosticLogs::default();
    let worker_result = async {
        tracing::info!(
            code = "record_timer.test.capture",
            message = "record timer test capture is active"
        );
        harness.worker(Duration::from_secs(2)).run_once().await
    }
    .with_subscriber(captured_logs.subscriber())
    .await;
    assert_eq!(
        worker_result.expect("worker opens grant-covered current fields"),
        1
    );
    assert_eq!(
        timer_state(&harness.database, &record_id).await,
        "completed"
    );
    let entity = &harness.registry.entities()["service"];
    let copied = &entity.fields["copied-note"].physical_name;
    let copied: String = harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT \"{copied}\" FROM registry_data.\"{}\" WHERE record_id=$1::text::uuid",
                entity.physical_table
            ),
            &[&record_id],
        )
        .await
        .expect("mapped result is queryable")
        .get(0);
    assert_eq!(copied, ENCRYPTED_NOTE_CANARY);
    let operator_profile = AuditProfile::production_from_secret_bytes(vec![0x68; 32].into())
        .expect("test owns the operator projection audit profile");
    let operator_detail = record_timer_operator_detail_for_test(
        &harness.pool,
        &harness.identity,
        harness.lock_key,
        Duration::from_secs(2),
        occurrence_id,
        &operator_profile,
    )
    .await
    .expect("the real operator projection reads the completed occurrence");
    let operator_output =
        serde_json::to_string(&operator_detail).expect("operator detail serializes");
    let operational_logs = captured_logs.text();
    assert!(
        operational_logs.contains("record_timer.test.capture"),
        "the scoped tracing capture must observe its positive control"
    );
    assert_timer_metadata_excludes_plaintext_canaries(
        &harness.database,
        &operator_output,
        &operational_logs,
        &[ENCRYPTED_NOTE_CANARY],
    )
    .await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_field_key_is_a_bounded_technical_failure_without_business_effects() {
    let harness = encrypted_timer_harness("record-timer-missing-key", 0x68).await;
    let created = create_outcome_service(
        &harness,
        "missing-key-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;
    set_timer_gate_open_for_fixture(&harness.database, &record_id).await;
    let coordinator_without_key = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        harness.identity.clone(),
        INSTANCE_ID,
        harness
            .database
            .audit(AuditProfile::production_from_secret_bytes(vec![0x78; 32].into()).unwrap()),
    );
    let worker = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        Arc::clone(&harness.registry),
        coordinator_without_key,
        harness.identity.clone(),
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    assert!(matches!(
        worker.run_once().await,
        Err(registry_breg::mutation::MutationError::FieldEncryptionUnavailable)
    ));
    assert_timer_technical_failure(&harness, occurrence_id, "field-encryption-unavailable").await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_encrypted_current_field_is_a_bounded_technical_failure() {
    let harness = encrypted_timer_harness("record-timer-tampered-current", 0x69).await;
    let created = create_outcome_service(
        &harness,
        "tampered-current-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;
    set_timer_gate_open_for_fixture(&harness.database, &record_id).await;
    let entity = &harness.registry.entities()["service"];
    harness
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"=decode('AA==','base64') WHERE record_id=$1::text::uuid",
                entity.physical_table, entity.fields["status"].physical_name
            ),
            &[&record_id],
        )
        .await
        .expect("fixture tampers only the encrypted envelope bytes");
    assert!(matches!(
        harness.worker(Duration::from_secs(2)).run_once().await,
        Err(registry_breg::mutation::MutationError::FieldEncryptionUnavailable)
    ));
    assert_timer_technical_failure(&harness, occurrence_id, "field-encryption-unavailable").await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timestamp_predicate_matches_equivalent_offset_and_database_projection() {
    let due = chrono::DateTime::parse_from_rfc3339("2020-01-02T03:04:05.123456Z")
        .unwrap()
        .with_timezone(&Utc);
    let offset = chrono::FixedOffset::east_opt(7 * 60 * 60).unwrap();
    let mut source = timer_project_source();
    source["recordTypes"][0]["timers"][0]["when"] = json!({
        "type":"fields",
        "equals":{"activates-at":due.with_timezone(&offset).to_rfc3339_opts(SecondsFormat::Micros, false)}
    });
    let harness =
        timer_outcome_harness(compile_registry(source), "record-timer-offset-gate", 0x6a).await;
    let created =
        create_outcome_service(&harness, "offset-gate-anchor", "scheduled", due, None, None).await;
    let record_id = response_id(&created);
    assert!(timer_gate_open(&harness.database, &record_id).await);
    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("equivalent timestamp predicate executes"),
        1
    );
    assert_eq!(
        timer_state(&harness.database, &record_id).await,
        "completed"
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorized_int64_rearm_write_changes_material_identity() {
    let harness = timer_outcome_harness(
        compiled_int64_rearm_registry(),
        "record-timer-int64-rearm",
        0x6b,
    )
    .await;
    let create_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.create").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let created = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-int64-rearm",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() + chrono::Duration::hours(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    (
                        "activationRevision".to_owned(),
                        json!(9_007_199_254_740_990_i64),
                    ),
                    ("note".to_owned(), json!("int64 rearm")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("the supported Int64 value arms");
    let record_id = response_id(&created);
    let initial_occurrence = timer_occurrence(&harness.database, &record_id).await;
    let initial_signature = timer_material_signature(&harness.database, &record_id).await;
    let patch_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.patch").unwrap();
    harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "patch-int64-rearm",
                claims: &harness.claims,
                record_id: Some(&record_id),
                expected_etag: Some(&response_etag(&created)),
                body: MutationBody::Patch(vec![
                    PatchOperation::Replace {
                        path: "/data/activationRevision".to_owned(),
                        value: json!(9_007_199_254_740_991_i64),
                    },
                    PatchOperation::Replace {
                        path: "/data/note".to_owned(),
                        value: json!("updated int64 rearm"),
                    },
                ]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("the authorized material control write rearms");
    assert_ne!(
        timer_occurrence(&harness.database, &record_id).await,
        initial_occurrence
    );
    assert_ne!(
        timer_material_signature(&harness.database, &record_id).await,
        initial_signature
    );
    let history: i64 = harness
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_record_timer_generations
              WHERE record_type='service' AND record_id=$1::text::uuid AND timer_id='activate'",
            &[&record_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(history, 2);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inconsistent_current_marker_refuses_the_record_write_atomically() {
    let harness =
        timer_outcome_harness(compiled_registry(), "record-timer-marker-mismatch", 0x6c).await;
    let created = create_outcome_service(
        &harness,
        "marker-mismatch-anchor",
        "scheduled",
        Utc::now() + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    harness
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_current
                SET material_signature='sha256:0000000000000000000000000000000000000000000000000000000000000000'
              WHERE record_type='service' AND record_id=$1::text::uuid AND timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("fixture creates one structurally valid but inconsistent pointer");
    let patch_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.patch").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let result = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "patch-under-inconsistent-timer-marker",
                claims: &harness.claims,
                record_id: Some(&record_id),
                expected_etag: Some(&response_etag(&created)),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/note".to_owned(),
                    value: json!("must roll back"),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await;
    assert!(
        result.is_err(),
        "an inconsistent current marker fails closed"
    );
    assert_eq!(
        record_values(&harness.database, &harness.registry, &record_id)
            .await
            .1,
        "marker-mismatch-anchor",
        "the Record write rolls back with timer staging"
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_entity_timer_bindings_keep_distinct_managed_policies() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = compiled_same_entity_timer_registry();
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("every timer binding remains present in the managed catalog");
    let policy_count: i64 = database
        .admin
        .query_one(
            "SELECT count(*)
               FROM pg_catalog.pg_policy AS policy
               JOIN pg_catalog.pg_class AS relation ON relation.oid=policy.polrelid
               JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
              WHERE namespace.nspname='registry_data'
                AND policy.polname LIKE 'record_timer_%'",
            &[],
        )
        .await
        .expect("installed timer policies are queryable")
        .get(0);
    assert_eq!(
        policy_count, 6,
        "each of two bindings retains SELECT, lock-only UPDATE, and effect UPDATE policies"
    );
    drop(migration);
    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn false_gate_from_start_is_not_claimed_until_an_ordinary_write_opens_it() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs timer state");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-package-held-gate",
        },
    )
    .await
    .expect("migration initializes the active package");
    drop(migration);
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x74; 32].into())
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
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.service.create").unwrap();
    let patch_plan = MutationPlan::from_compiled(&registry, "records.service.patch").unwrap();
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let created = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-held-gate-service",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("paused")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("held gate canary")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms the held occurrence");
    let record_id = response_id(&created);
    let etag = response_etag(&created);
    let occurrence = timer_occurrence(&database, &record_id).await;
    let before = effect_counts(&database, &registry, &record_id).await;
    let worker = RecordTimerWorker::new_for_test(
        pool,
        registry.clone(),
        coordinator.clone(),
        identity,
        lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );

    assert_eq!(
        worker.run_once().await.expect("false gate is not runnable"),
        0
    );
    assert_eq!(timer_state(&database, &record_id).await, "pending");
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence);
    assert!(!timer_gate_open(&database, &record_id).await);
    assert!(timer_claim_is_clear(&database, &record_id).await);
    let claim_epoch: i64 = database
        .admin
        .query_one(
            "SELECT claim_epoch
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence],
        )
        .await
        .expect("unclaimed occurrence is queryable")
        .get(0);
    assert_eq!(claim_epoch, 0, "a closed cached gate is never claimed");
    let attempt_count: i64 = database
        .admin
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_record_timer_attempts
              WHERE occurrence_id=$1",
            &[&occurrence],
        )
        .await
        .expect("attempt history is queryable")
        .get(0);
    assert_eq!(attempt_count, 0, "a closed cached gate starts no attempt");
    assert_eq!(
        effect_counts(&database, &registry, &record_id).await,
        before
    );
    let timer_audit = database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["operationId"] == "timers.service.activate.invoke")
        .collect::<Vec<_>>();
    assert!(
        timer_audit.is_empty(),
        "a closed cached gate is not admitted to the Action boundary"
    );
    database.assert_every_audit_request_answered_once();

    coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "open-held-gate-service",
                claims: &claims,
                record_id: Some(&record_id),
                expected_etag: Some(&etag),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/status".to_owned(),
                    value: json!("scheduled"),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary predicate write opens the same occurrence");
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence);
    assert_eq!(
        worker.run_once().await.expect("opened occurrence executes"),
        1
    );
    assert_eq!(timer_state(&database, &record_id).await, "completed");
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_closing_after_claim_holds_the_same_occurrence_with_paired_audit() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs timer state");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-package-racing-gate",
        },
    )
    .await
    .expect("migration initializes the active package");
    drop(migration);
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x78; 32].into())
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
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.service.create").unwrap();
    let patch_plan = MutationPlan::from_compiled(&registry, "records.service.patch").unwrap();
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let created = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-racing-gate-service",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("racing gate canary")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms the open occurrence");
    let record_id = response_id(&created);
    let occurrence = timer_occurrence(&database, &record_id).await;
    let worker = RecordTimerWorker::new_for_test(
        pool,
        registry.clone(),
        coordinator.clone(),
        identity,
        lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let waiting_worker = worker
        .clone()
        .with_claim_barrier_for_test(claimed.clone(), resume.clone());
    let mut execution = tokio::spawn(async move { waiting_worker.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;

    let closed = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "close-racing-gate-service",
                claims: &claims,
                record_id: Some(&record_id),
                expected_etag: Some(&response_etag(&created)),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/status".to_owned(),
                    value: json!("paused"),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary predicate write closes the claimed occurrence");
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence);
    let before_hold = effect_counts(&database, &registry, &record_id).await;
    resume.notify_one();
    assert_eq!(
        execution
            .await
            .expect("worker task joins")
            .expect("claimed work reaches final admission"),
        1
    );
    assert_eq!(timer_state(&database, &record_id).await, "pending");
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence);
    assert!(timer_claim_is_clear(&database, &record_id).await);
    assert!(!timer_gate_open(&database, &record_id).await);
    let execution_counts = database
        .admin
        .query_one(
            "SELECT generation.executed_attempt_count,
                    (SELECT count(*)
                       FROM registry_internal.registry_record_timer_attempts AS attempt
                      WHERE attempt.occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_generations AS generation
              WHERE generation.occurrence_id=$1",
            &[&occurrence],
        )
        .await
        .expect("held occurrence attempt state is queryable");
    assert_eq!(execution_counts.get::<_, i32>(0), 0);
    assert_eq!(execution_counts.get::<_, i64>(1), 0);
    assert_eq!(
        effect_counts(&database, &registry, &record_id).await,
        before_hold
    );
    let timer_audit = database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["operationId"] == "timers.service.activate.invoke")
        .collect::<Vec<_>>();
    assert_eq!(timer_audit.len(), 2, "hold has one request and one outcome");
    assert_eq!(timer_audit[0]["phase"], "request");
    assert_eq!(timer_audit[1]["phase"], "response");
    assert_eq!(timer_audit[1]["record"]["phase"], "refusal");
    database.assert_every_audit_request_answered_once();
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("a held false predicate is not rediscovered"),
        0
    );
    assert!(timer_claim_is_clear(&database, &record_id).await);
    assert_eq!(
        database
            .audit_entries()
            .into_iter()
            .filter(|entry| entry["record"]["operationId"] == "timers.service.activate.invoke")
            .count(),
        2,
        "a held false predicate does not emit another audit pair"
    );

    coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &patch_plan,
                idempotency_key: "reopen-racing-gate-service",
                claims: &claims,
                record_id: Some(&record_id),
                expected_etag: Some(&response_etag(&closed)),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/status".to_owned(),
                    value: json!("scheduled"),
                }]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary predicate write reopens the same occurrence");
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence);
    assert!(timer_gate_open(&database, &record_id).await);
    assert_eq!(worker.run_once().await.expect("reopened gate executes"), 1);
    assert_eq!(timer_state(&database, &record_id).await, "completed");
    assert_eq!(timer_occurrence(&database, &record_id).await, occurrence);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_timer_protocol_refuses_a_timer_free_record_mutation() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_timer_and_timer_free_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs timer state");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-protocol-admission",
        },
    )
    .await
    .expect("migration initializes the active package");
    drop(migration);
    migration_task.abort();
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_control
                SET protocol_version=2
              WHERE singleton",
            &[],
        )
        .await
        .expect("the fixture installs a structurally valid future protocol");

    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x79; 32].into())
            .expect("test owns a keyed audit profile"),
    );
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key is bounded");
    let coordinator = MutationTransaction::new(
        lock_key,
        Duration::from_secs(2),
        identity,
        INSTANCE_ID,
        audit,
    );
    let claims = ClaimContext::for_compiled(
        &registry,
        "case-note",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("timer-free mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.case-note.create")
        .expect("timer-free create route is compiled");
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let result = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "unsupported-timer-protocol-case-note",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("body".to_owned(), json!("must not commit")),
                ])),
                response_fields: BTreeSet::from(["jurisdiction".to_owned(), "body".to_owned()]),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await;
    assert!(
        result.is_err(),
        "an unsupported timer protocol fails closed before a timer-free write"
    );
    let entity = &registry.entities()["case-note"];
    let stored: i64 = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.\"{}\"",
                entity.physical_table
            ),
            &[],
        )
        .await
        .expect("timer-free table remains queryable")
        .get(0);
    assert_eq!(stored, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn technical_fault_rolls_back_effects_and_exhausts_five_bounded_attempts() {
    let database = TestDatabase::create(6).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs timer state");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-package-rollback",
        },
    )
    .await
    .expect("migration initializes the active package");
    drop(migration);
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x72; 32].into())
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
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.service.create").unwrap();
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let created = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-past-due-service",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("rollback canary")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms one due generation");
    let record_id = response_id(&created);
    let before = effect_counts(&database, &registry, &record_id).await;
    let occurrence_id = timer_occurrence(&database, &record_id).await;
    let faulting_worker = RecordTimerWorker::new_for_test(
        pool,
        registry.clone(),
        coordinator,
        identity,
        lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .with_fault_for_test(MutationFaultPoint::BeforeCommit);
    for attempt_number in 1..=5_i32 {
        let failed = faulting_worker.run_once().await;
        assert!(
            matches!(
                failed,
                Err(registry_breg::mutation::MutationError::Unavailable)
            ),
            "the injected pre-commit failure remains a definite rollback: {failed:?}"
        );
        assert_eq!(
            record_values(&database, &registry, &record_id).await.0,
            "scheduled"
        );
        assert_eq!(
            effect_counts(&database, &registry, &record_id).await,
            before
        );
        let generation = database
            .admin
            .query_one(
                "SELECT state,executed_attempt_count,retry_allowance,block_kind,outcome_code,
                        retry_at,EXTRACT(EPOCH FROM (retry_at-updated_at))::float8,
                        (SELECT count(*)
                           FROM registry_internal.registry_record_timer_attempts AS attempt
                          WHERE attempt.occurrence_id=generation.occurrence_id)
                   FROM registry_internal.registry_record_timer_generations AS generation
                  WHERE occurrence_id=$1",
                &[&occurrence_id],
            )
            .await
            .expect("technical settlement is queryable");
        assert_eq!(generation.get::<_, i32>(1), attempt_number);
        assert_eq!(generation.get::<_, i16>(2), 0);
        assert_eq!(generation.get::<_, i64>(7), i64::from(attempt_number));
        let attempt = database
            .admin
            .query_one(
                "SELECT finished_at IS NOT NULL,block_kind,outcome_code,
                        technical_code,receipt_correlation
                   FROM registry_internal.registry_record_timer_attempts
                  WHERE occurrence_id=$1 AND attempt_number=$2",
                &[&occurrence_id, &attempt_number],
            )
            .await
            .expect("the exact technical attempt is retained");
        assert!(attempt.get::<_, bool>(0));
        assert_eq!(
            attempt.get::<_, Option<String>>(1).as_deref(),
            Some("technical")
        );
        assert!(attempt.get::<_, Option<String>>(3).is_some());
        assert!(attempt.get::<_, Option<uuid::Uuid>>(4).is_none());
        if attempt_number < 5 {
            assert_eq!(generation.get::<_, String>(0), "pending");
            assert!(generation.get::<_, Option<String>>(3).is_none());
            assert!(generation.get::<_, Option<String>>(4).is_none());
            assert!(generation
                .get::<_, Option<chrono::DateTime<Utc>>>(5)
                .is_some());
            let delay_seconds = generation
                .get::<_, Option<f64>>(6)
                .expect("technical retry has a database-time deadline");
            let expected_delay = f64::from(1_i32 << (attempt_number - 1));
            assert!(
                (delay_seconds - expected_delay).abs() < 0.01,
                "attempt {attempt_number} delay {delay_seconds} differs from {expected_delay}"
            );
            database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_record_timer_generations
                        SET retry_at=clock_timestamp()
                      WHERE occurrence_id=$1",
                    &[&occurrence_id],
                )
                .await
                .expect("fixture advances only the persisted retry gate");
        } else {
            assert_eq!(generation.get::<_, String>(0), "blocked");
            assert_eq!(
                generation.get::<_, Option<String>>(3).as_deref(),
                Some("technical")
            );
            assert_eq!(
                generation.get::<_, Option<String>>(4).as_deref(),
                Some("attempts-exhausted")
            );
            assert!(generation
                .get::<_, Option<chrono::DateTime<Utc>>>(5)
                .is_none());
            assert_eq!(
                attempt.get::<_, Option<String>>(2).as_deref(),
                Some("attempts-exhausted")
            );
        }
    }
    let timer_audit = database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["operationId"] == "timers.service.activate.invoke")
        .collect::<Vec<_>>();
    assert_eq!(timer_audit.len(), 10);
    for pair in timer_audit.chunks_exact(2) {
        assert_eq!(pair[0]["phase"], "request");
        assert_eq!(pair[1]["phase"], "response");
        assert_eq!(pair[1]["record"]["phase"], "unfinished");
    }
    database.assert_every_audit_request_answered_once();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn business_guard_refusal_is_terminal_and_consumes_one_attempt() {
    let mut source = timer_project_source();
    source["actions"][0]["commitGuards"] = json!({"targets":[{
        "input":"service","field":"status","equals":"active"
    }]});
    let harness = timer_outcome_harness(
        compile_registry(source),
        "record-timer-declared-refusal",
        0x61,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "declared-refusal-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("a declared business refusal settles normally"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "refused", 1, "declared-refusal").await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mapped_required_input_refusal_is_terminal_and_consumes_one_attempt() {
    let mut source = timer_project_source();
    source["recordTypes"][0]["timers"][0]["input"]["required-revision"] =
        json!({"fromField":"activation-revision"});
    source["actions"][0]["inputs"]
        .as_array_mut()
        .expect("Action inputs are an array")
        .push(json!({
            "id":"required-revision","type":"uuid","required":true,
            "classification":"internal"
        }));
    let harness =
        timer_outcome_harness(compile_registry(source), "record-timer-input-refusal", 0x62).await;
    let created = create_outcome_service(
        &harness,
        "input-refusal-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("a malformed live mapped input settles normally"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "refused", 1, "input-refused").await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unique_effect_conflict_is_terminal_and_consumes_one_attempt() {
    let mut source = timer_project_source();
    source["recordTypes"][0]["constraints"] =
        json!([{"id":"status-unique","type":"unique","fields":["status"]}]);
    let harness = timer_outcome_harness(
        compile_registry(source),
        "record-timer-effect-conflict",
        0x63,
    )
    .await;
    create_outcome_service(
        &harness,
        "effect-conflict-existing-active",
        "active",
        Utc::now() + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "effect-conflict-due-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("a unique effect conflict settles normally"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "refused", 1, "effect-conflict").await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_expiring_after_claim_is_missed_without_an_attempt() {
    let harness =
        timer_outcome_harness(compiled_registry(), "record-timer-window-expired", 0x64).await;
    let not_after = Utc::now() + chrono::Duration::seconds(2);
    let created = create_outcome_service(
        &harness,
        "window-expired-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        Some(not_after),
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;
    let claimed = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let waiting_worker = harness
        .worker(Duration::from_secs(5))
        .with_claim_barrier_for_test(claimed.clone(), resume.clone());
    let mut execution = tokio::spawn(async move { waiting_worker.run_once().await });
    wait_for_timer_barrier(&claimed, &mut execution, "the claim barrier").await;
    loop {
        let elapsed: bool = harness
            .database
            .admin
            .query_one("SELECT clock_timestamp() >= $1", &[&not_after])
            .await
            .expect("the fixture reads the database clock")
            .get(0);
        if elapsed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    resume.notify_one();
    assert_eq!(
        execution
            .await
            .expect("worker task joins")
            .expect("the elapsed valid window settles normally"),
        1
    );
    assert_terminal_timer_outcome(
        &harness,
        occurrence_id,
        "missed",
        0,
        "execution-window-expired",
    )
    .await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn elapsed_false_gate_is_discovered_and_missed_without_a_claim() {
    let harness =
        timer_outcome_harness(compiled_registry(), "record-timer-elapsed-false-gate", 0x84).await;
    let due_at = Utc::now() - chrono::Duration::seconds(3);
    let created = create_outcome_service(
        &harness,
        "elapsed-false-gate-anchor",
        "reviewed",
        due_at,
        Some(due_at + chrono::Duration::seconds(1)),
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("elapsed-window discovery does not require an open cached gate"),
        1
    );
    assert_terminal_timer_outcome(
        &harness,
        occurrence_id,
        "missed",
        0,
        "execution-window-expired",
    )
    .await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    patch_outcome_service_for_registry(
        &harness,
        &harness.registry,
        &harness.identity,
        &record_id,
        "elapsed-false-gate-open-after-terminal",
        PatchOperation::Replace {
            path: "/data/status".to_owned(),
            value: json!("scheduled"),
        },
        0x85,
    )
    .await;
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id,
        "a predicate-only write cannot reopen a terminal missed marker"
    );
    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("a missed current marker never refires"),
        0
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_window_blocks_expire_without_a_new_attempt_or_predicate_release() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-valid-window-block-expiry",
        0x9b,
    )
    .await;
    let technical_end = Utc::now() + chrono::Duration::seconds(8);
    let technical = create_outcome_service(
        &harness,
        "valid-window-technical-block",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        Some(technical_end),
        None,
    )
    .await;
    let technical_record = response_id(&technical);
    let technical_occurrence = timer_occurrence(&harness.database, &technical_record).await;
    let faulting = harness
        .worker(Duration::from_secs(2))
        .with_fault_for_test(MutationFaultPoint::BeforeCommit);
    for attempt in 1..=5_i32 {
        assert!(
            faulting.run_once().await.is_err(),
            "the injected technical failure remains visible"
        );
        if attempt < 5 {
            harness
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_record_timer_generations
                        SET retry_at=clock_timestamp()
                      WHERE occurrence_id=$1",
                    &[&technical_occurrence],
                )
                .await
                .expect("fixture advances only the persisted retry gate");
        }
    }
    let blocked = harness
        .database
        .admin
        .query_one(
            "SELECT state,block_kind,executed_attempt_count,
                    (SELECT count(*)
                       FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_generations AS generation
              WHERE occurrence_id=$1",
            &[&technical_occurrence],
        )
        .await
        .expect("the actual technical exhaustion is queryable");
    assert_eq!(blocked.get::<_, String>(0), "blocked");
    assert_eq!(
        blocked.get::<_, Option<String>>(1).as_deref(),
        Some("technical")
    );
    assert_eq!(blocked.get::<_, i32>(2), 5);
    assert_eq!(blocked.get::<_, i64>(3), 5);

    patch_outcome_service_for_registry(
        &harness,
        &harness.registry,
        &harness.identity,
        &technical_record,
        "technical-block-predicate-close",
        PatchOperation::Replace {
            path: "/data/status".to_owned(),
            value: json!("reviewed"),
        },
        0x9c,
    )
    .await;
    patch_outcome_service_for_registry(
        &harness,
        &harness.registry,
        &harness.identity,
        &technical_record,
        "technical-block-predicate-open",
        PatchOperation::Replace {
            path: "/data/status".to_owned(),
            value: json!("scheduled"),
        },
        0x9d,
    )
    .await;
    let still_blocked = harness
        .database
        .admin
        .query_one(
            "SELECT state,block_kind,executed_attempt_count
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&technical_occurrence],
        )
        .await
        .expect("predicate-only writes retain the technical block");
    assert_eq!(still_blocked.get::<_, String>(0), "blocked");
    assert_eq!(
        still_blocked.get::<_, Option<String>>(1).as_deref(),
        Some("technical")
    );
    assert_eq!(still_blocked.get::<_, i32>(2), 5);
    loop {
        let expired: bool = harness
            .database
            .admin
            .query_one("SELECT clock_timestamp() >= $1", &[&technical_end])
            .await
            .expect("fixture reads the database clock")
            .get(0);
        if expired {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let worker = harness.worker(Duration::from_secs(2));
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the valid technical window expiry settles normally"),
        1
    );
    assert_terminal_timer_outcome(
        &harness,
        technical_occurrence,
        "missed",
        5,
        "execution-window-expired",
    )
    .await;

    let configuration_due = Utc::now() - chrono::Duration::seconds(3);
    let configuration = create_outcome_service(
        &harness,
        "valid-window-configuration-block",
        "reviewed",
        configuration_due,
        Some(configuration_due + chrono::Duration::seconds(1)),
        None,
    )
    .await;
    let configuration_record = response_id(&configuration);
    let configuration_occurrence = timer_occurrence(&harness.database, &configuration_record).await;
    let updated = harness
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_generations AS generation
                SET state='blocked',block_kind='configuration',outcome_code=NULL,
                    updated_at=clock_timestamp()
               FROM registry_internal.registry_record_timer_current AS current
              WHERE current.record_type='service'
                AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'
                AND generation.record_type=current.record_type
                AND generation.record_id=current.record_id
                AND generation.timer_id=current.timer_id
                AND generation.occurrence_id=current.occurrence_id
                AND generation.binding_incarnation=current.binding_incarnation
                AND generation.material_signature=current.material_signature
                AND generation.state='pending'",
            &[&configuration_record],
        )
        .await
        .expect("fixture installs one valid-window configuration block");
    assert_eq!(updated, 1);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the valid configuration window expiry settles normally"),
        1
    );
    assert_terminal_timer_outcome(
        &harness,
        configuration_occurrence,
        "missed",
        0,
        "execution-window-expired",
    )
    .await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_commit_timer_fault_retains_committed_audit_and_does_not_replay() {
    let harness =
        timer_outcome_harness(compiled_registry(), "record-timer-after-commit", 0x65).await;
    let created = create_outcome_service(
        &harness,
        "after-commit-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    let result = harness
        .worker(Duration::from_secs(2))
        .with_fault_for_test(MutationFaultPoint::AfterCommitBeforeResponseRelease)
        .run_once()
        .await;
    assert_eq!(
        result,
        Err(registry_breg::mutation::MutationError::Unavailable),
        "lost post-commit response remains visible"
    );
    let after = effect_counts(&harness.database, &harness.registry, &record_id).await;
    assert_eq!(after.revisions, before.revisions + 1);
    assert_eq!(after.outbox, before.outbox + 1);
    assert_eq!(after.action_receipts, before.action_receipts + 1);
    let generation = harness
        .database
        .admin
        .query_one(
            "SELECT state,executed_attempt_count,outcome_code,receipt_correlation
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the committed timer generation remains queryable");
    assert_eq!(generation.get::<_, String>(0), "completed");
    assert_eq!(generation.get::<_, i32>(1), 1);
    assert_eq!(
        generation.get::<_, Option<String>>(2).as_deref(),
        Some("completed")
    );
    assert!(generation.get::<_, Option<uuid::Uuid>>(3).is_some());
    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("a peer scans the committed occurrence without replay"),
        0
    );
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        after
    );

    let boundary = harness
        .database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["operationId"] == "timers.service.activate.invoke")
        .collect::<Vec<_>>();
    let boundary_shape = boundary
        .iter()
        .map(|entry| {
            (
                entry["phase"].as_str().unwrap_or("missing").to_owned(),
                entry["record"]["phase"]
                    .as_str()
                    .unwrap_or("missing")
                    .to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        boundary
            .iter()
            .filter(|entry| entry["phase"] == "request")
            .count(),
        1,
        "boundary audit shape: {boundary_shape:?}"
    );
    assert_eq!(
        boundary
            .iter()
            .filter(|entry| entry["phase"] == "response"
                && entry["record"]["phase"] == "terminal"
                && entry["record"]["outcome"] == "committed")
            .count(),
        1,
        "boundary audit shape: {boundary_shape:?}"
    );
    assert_eq!(
        boundary
            .iter()
            .filter(|entry| entry["record"]["phase"] == "refusal")
            .count(),
        0
    );
    assert_eq!(
        boundary
            .iter()
            .filter(|entry| entry["record"]["phase"] == "unfinished")
            .count(),
        0
    );
    assert_eq!(boundary.len(), 2, "the boundary attempt is answered once");
    harness
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_generations
                SET detail_expires_at=clock_timestamp()-interval '1 second'
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("fixture advances the completed detail deadline");
    let pruner = harness.worker(Duration::from_secs(2));
    assert_eq!(
        pruner
            .prune_retention_once_for_test()
            .await
            .expect("the actual retention worker expires completed attempt detail"),
        1
    );
    let retained = harness
        .database
        .admin
        .query_one(
            "SELECT current.occurrence_id,generation.state,
                    (SELECT count(*) FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_current AS current
               JOIN registry_internal.registry_record_timer_generations AS generation
                 ON generation.occurrence_id=current.occurrence_id
              WHERE current.record_type='service' AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("pruning retains the exact terminal current marker");
    assert_eq!(retained.get::<_, uuid::Uuid>(0), occurrence_id);
    assert_eq!(retained.get::<_, String>(1), "completed");
    assert_eq!(retained.get::<_, i64>(2), 0);
    assert_eq!(
        pruner
            .run_once()
            .await
            .expect("pruning terminal detail cannot reopen the current marker"),
        0
    );
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        after
    );
    harness.database.assert_every_audit_request_answered_once();
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_occurrences_remain_closed_across_writes_activation_and_pruning() {
    let registry = compiled_terminal_lifecycle_registry(false);
    let harness = timer_outcome_harness(registry, "record-timer-terminal-lifecycle", 0x95).await;
    let now = Utc::now();
    let completed = create_outcome_service(
        &harness,
        "allow",
        "scheduled",
        now - chrono::Duration::seconds(2),
        None,
        None,
    )
    .await;
    let refused = create_outcome_service(
        &harness,
        "refuse",
        "scheduled",
        now - chrono::Duration::seconds(2),
        None,
        None,
    )
    .await;
    let missed_due = now - chrono::Duration::seconds(4);
    let missed = create_outcome_service(
        &harness,
        "missed",
        "reviewed",
        missed_due,
        Some(missed_due + chrono::Duration::seconds(1)),
        None,
    )
    .await;
    let cancelled = create_outcome_service(
        &harness,
        "cancelled",
        "scheduled",
        now + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let records = [
        (response_id(&completed), "completed"),
        (response_id(&refused), "refused"),
        (response_id(&missed), "missed"),
        (response_id(&cancelled), "cancelled"),
    ];
    let mut occurrences = Vec::with_capacity(records.len());
    for (record_id, _) in &records {
        occurrences.push(timer_occurrence(&harness.database, record_id).await);
    }
    patch_outcome_service_for_registry(
        &harness,
        &harness.registry,
        &harness.identity,
        &records[3].0,
        "cancel-terminal-control",
        PatchOperation::Remove {
            path: "/data/activatesAt".to_owned(),
        },
        0x96,
    )
    .await;

    let worker = harness.worker(Duration::from_secs(2));
    assert_eq!(worker.run_once().await.expect("first terminal settles"), 1);
    assert_eq!(worker.run_once().await.expect("second terminal settles"), 1);
    assert_eq!(worker.run_once().await.expect("third terminal settles"), 1);
    assert_eq!(worker.run_once().await.expect("terminal queue drains"), 0);
    for ((record_id, expected_state), occurrence_id) in records.iter().zip(&occurrences) {
        let state = timer_state(&harness.database, record_id).await;
        assert_eq!(&state, expected_state);
        assert_eq!(
            timer_occurrence(&harness.database, record_id).await,
            *occurrence_id
        );
    }

    for (index, (record_id, _)) in records.iter().enumerate() {
        patch_outcome_service_for_registry(
            &harness,
            &harness.registry,
            &harness.identity,
            record_id,
            &format!("terminal-predicate-close-{index}"),
            PatchOperation::Replace {
                path: "/data/status".to_owned(),
                value: json!("paused"),
            },
            0x97,
        )
        .await;
        patch_outcome_service_for_registry(
            &harness,
            &harness.registry,
            &harness.identity,
            record_id,
            &format!("terminal-predicate-open-{index}"),
            PatchOperation::Replace {
                path: "/data/status".to_owned(),
                value: json!("scheduled"),
            },
            0x98,
        )
        .await;
        patch_outcome_service_for_registry(
            &harness,
            &harness.registry,
            &harness.identity,
            record_id,
            &format!("terminal-unrelated-{index}"),
            PatchOperation::Replace {
                path: "/data/note".to_owned(),
                value: json!(format!("terminal unrelated {index}")),
            },
            0x99,
        )
        .await;
    }

    let successor_registry = Arc::new(compiled_terminal_lifecycle_registry(true));
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-terminal-lifecycle-successor",
    )
    .await;
    let successor_worker = successor_worker(&harness, successor_registry, successor, 0x9a);
    assert_eq!(
        successor_worker
            .run_once()
            .await
            .expect("terminal successor scan succeeds"),
        0
    );
    harness
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_generations
                SET detail_expires_at=clock_timestamp()-interval '1 second'
              WHERE occurrence_id=ANY($1::uuid[])",
            &[&occurrences],
        )
        .await
        .expect("fixture advances only terminal detail deadlines");
    assert!(
        successor_worker
            .prune_retention_once_for_test()
            .await
            .expect("terminal detail pruning succeeds")
            > 0
    );
    assert_eq!(
        successor_worker
            .run_once()
            .await
            .expect("pruned terminal markers remain closed"),
        0
    );
    for (((record_id, expected_state), occurrence_id), expected_attempts) in
        records.iter().zip(&occurrences).zip([1_i64, 1, 0, 0])
    {
        let terminal = harness
            .database
            .admin
            .query_one(
                "SELECT current.occurrence_id,generation.state,
                        generation.executed_attempt_count,
                        (SELECT count(*)
                           FROM registry_internal.registry_record_timer_attempts
                          WHERE occurrence_id=generation.occurrence_id)
                   FROM registry_internal.registry_record_timer_current AS current
                   JOIN registry_internal.registry_record_timer_generations AS generation
                     ON generation.occurrence_id=current.occurrence_id
                  WHERE current.record_type='service'
                    AND current.record_id=$1::text::uuid
                    AND current.timer_id='activate'",
                &[record_id],
            )
            .await
            .expect("the exact terminal current marker is retained");
        assert_eq!(terminal.get::<_, uuid::Uuid>(0), *occurrence_id);
        assert_eq!(terminal.get::<_, String>(1), *expected_state);
        assert_eq!(terminal.get::<_, i64>(3), 0);
        assert_eq!(
            i64::from(terminal.get::<_, i32>(2)),
            expected_attempts,
            "cumulative attempt count survives detail pruning"
        );
    }
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_action_can_clear_its_own_due_field_before_exact_completion() {
    let harness = timer_outcome_harness(
        compiled_self_clearing_registry(),
        "record-timer-self-clear",
        0x66,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "self-clear-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let record_uuid = uuid::Uuid::parse_str(&record_id).unwrap();
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("the exact firing occurrence survives its self-clear"),
        1
    );
    let after = effect_counts(&harness.database, &harness.registry, &record_id).await;
    assert_eq!(after.revisions, before.revisions + 1);
    assert_eq!(after.outbox, before.outbox + 1);
    assert_eq!(after.action_receipts, before.action_receipts + 1);
    let entity = &harness.registry.entities()["service"];
    let row = harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT record.\"{}\", generation.state,
                        generation.executed_attempt_count,generation.receipt_correlation,
                        (SELECT count(*)
                           FROM registry_internal.registry_record_timer_generations AS retained
                          WHERE retained.record_type='service' AND retained.record_id=$1
                            AND retained.timer_id='activate'),
                        current.occurrence_id
                   FROM registry_data.\"{}\" AS record
                   JOIN registry_internal.registry_record_timer_current AS current
                     ON current.record_type='service' AND current.record_id=record.record_id
                    AND current.timer_id='activate'
                   JOIN registry_internal.registry_record_timer_generations AS generation
                     ON generation.occurrence_id=current.occurrence_id
                  WHERE record.record_id=$1",
                entity.fields["activates-at"].physical_name, entity.physical_table,
            ),
            &[&record_uuid],
        )
        .await
        .expect("the self-cleared record and exact occurrence are queryable");
    assert!(row.get::<_, Option<chrono::DateTime<Utc>>>(0).is_none());
    assert_eq!(row.get::<_, String>(1), "completed");
    assert_eq!(row.get::<_, i32>(2), 1);
    assert!(row.get::<_, Option<uuid::Uuid>>(3).is_some());
    assert_eq!(row.get::<_, i64>(4), 1);
    assert_eq!(row.get::<_, uuid::Uuid>(5), occurrence_id);
    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("a restart does not rearm the cleared control"),
        0
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_action_combines_two_declared_anchor_patch_effects() {
    let harness = timer_outcome_harness(
        compiled_two_anchor_patch_effects_registry(),
        "record-timer-two-anchor-patches",
        0x78,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "two-anchor-patches",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("both declared anchor patches execute in one timer Action"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    let (status, note, _) = record_values(&harness.database, &harness.registry, &record_id).await;
    assert_eq!(status, "active");
    assert_eq!(note, "activated by two effects");
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_timer_binding_survives_an_unrelated_package_activation() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-unrelated-activation",
        0x6b,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "unrelated-activation-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let predecessor_activation = harness.identity.activation_uuid().unwrap();
    let successor = ExpectedRegistryIdentity {
        package_id: harness.identity.package_id.clone(),
        database_id: harness.identity.database_id.clone(),
        package_digest: test_package_digest("record-timer-unrelated-activation-successor"),
        activation_id: test_activation_id("record-timer-unrelated-activation-successor"),
        schema_fingerprint: harness.identity.schema_fingerprint.clone(),
    };
    let mut apply = DedicatedApplyConnection::acquire(
        &harness.database.migration_config,
        harness.lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("the successor obtains the exclusive Registry lock");
    apply
        .mark_applying(&harness.identity, &successor.package_digest)
        .await
        .expect("the successor enters governed maintenance");
    apply
        .activate_compiled_for_catalog(
            &harness.registry,
            &successor,
            &ExpectedManagedCatalog::compiled(&harness.registry),
            &harness.database.migration_role,
            &harness.database.runtime_role,
        )
        .await
        .expect("the unchanged compiled timer binding activates atomically");
    apply
        .release()
        .await
        .expect("the successor releases the Registry lock");

    let binding = harness
        .database
        .admin
        .query_one(
            "SELECT binding.incarnation,binding.created_activation_id,
                    binding.current_policy_activation_id,
                    generation.current_policy_activation_id
               FROM registry_internal.registry_record_timer_bindings AS binding
               JOIN registry_internal.registry_record_timer_generations AS generation
                 ON generation.record_type=binding.record_type
                AND generation.timer_id=binding.timer_id
                AND generation.binding_incarnation=binding.incarnation
              WHERE binding.record_type='service' AND binding.timer_id='activate'
                AND binding.removed_activation_id IS NULL
                AND generation.occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the unchanged binding and generation remain queryable");
    assert_eq!(binding.get::<_, i64>(0), 1);
    assert_eq!(binding.get::<_, uuid::Uuid>(1), predecessor_activation);
    assert_eq!(
        binding.get::<_, uuid::Uuid>(2),
        successor.activation_uuid().unwrap()
    );
    assert_eq!(
        binding.get::<_, uuid::Uuid>(3),
        predecessor_activation,
        "the occurrence retains its historical policy activation"
    );
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id
    );

    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        successor.clone(),
        INSTANCE_ID,
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x6c; 32].into())
                .expect("test owns a keyed successor audit profile"),
        ),
    );
    let worker = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        Arc::clone(&harness.registry),
        coordinator,
        successor.clone(),
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("unchanged timer work executes under the successor activation"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    let execution_activation: uuid::Uuid = harness
        .database
        .admin
        .query_one(
            "SELECT executed_activation_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the completed generation remains queryable")
        .get(0);
    assert_eq!(execution_activation, successor.activation_uuid().unwrap());
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the unchanged occurrence remains terminal after restart"),
        0
    );
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_timer_policy_refreshes_the_current_occurrence_before_claim() {
    let harness =
        timer_outcome_harness(compiled_registry(), "record-timer-policy-refresh", 0x6d).await;
    let created = create_outcome_service(
        &harness,
        "policy-refresh-anchor",
        "reviewed",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let successor_registry = Arc::new(compiled_changed_predicate_registry());
    let successor_timer = &successor_registry.entities()["service"].timers["activate"];
    let successor_catalog = ExpectedManagedCatalog::compiled(&successor_registry);
    let (mut fingerprint_client, fingerprint_task) = harness.database.connect_migration().await;
    let fingerprint_transaction = fingerprint_client.transaction().await.unwrap();
    reconcile_record_timer_runtime_acl_for_test(
        &fingerprint_transaction,
        &successor_registry,
        &harness.database.runtime_role,
    )
    .await
    .expect("the successor timer policies rehearse transactionally");
    reconcile_compiled_runtime_acl_for_test(
        &fingerprint_transaction,
        &successor_registry,
        &harness.database.runtime_role,
    )
    .await
    .expect("the successor runtime ACL rehearses transactionally");
    let successor_fingerprint = managed_schema_fingerprint(
        &fingerprint_transaction,
        &harness.database.runtime_role,
        &successor_catalog,
    )
    .await
    .expect("the successor managed fingerprint is measured exactly");
    fingerprint_transaction.rollback().await.unwrap();
    fingerprint_task.abort();
    let successor = ExpectedRegistryIdentity {
        package_id: harness.identity.package_id.clone(),
        database_id: harness.identity.database_id.clone(),
        package_digest: test_package_digest("record-timer-policy-refresh-successor"),
        activation_id: test_activation_id("record-timer-policy-refresh-successor"),
        schema_fingerprint: successor_fingerprint,
    };
    let mut apply = DedicatedApplyConnection::acquire(
        &harness.database.migration_config,
        harness.lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("the semantic successor obtains the exclusive Registry lock");
    apply
        .mark_applying(&harness.identity, &successor.package_digest)
        .await
        .expect("the semantic successor enters governed maintenance");
    apply
        .activate_compiled_for_catalog(
            &successor_registry,
            &successor,
            &successor_catalog,
            &harness.database.migration_role,
            &harness.database.runtime_role,
        )
        .await
        .expect("the semantic successor and binding activate atomically");
    apply.release().await.unwrap();

    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        successor.clone(),
        INSTANCE_ID,
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x6d; 32].into())
                .expect("test owns a keyed successor audit profile"),
        ),
    );
    let worker = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        Arc::clone(&successor_registry),
        coordinator.clone(),
        successor,
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the worker reconciles one semantically stale occurrence"),
        1
    );
    let refreshed = harness
        .database
        .admin
        .query_one(
            "SELECT occurrence_id,definition_revision,action_revision,
                    system_grant_revision,gate_open,current_policy_activation_id,
                    executed_attempt_count
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the refreshed occurrence remains queryable");
    assert_eq!(refreshed.get::<_, uuid::Uuid>(0), occurrence_id);
    assert_eq!(
        refreshed.get::<_, String>(1),
        successor_timer.definition_revision
    );
    assert_eq!(
        refreshed.get::<_, String>(2),
        successor_timer.action_revision
    );
    assert_eq!(
        refreshed.get::<_, String>(3),
        successor_timer.system_grant.revision
    );
    assert!(refreshed.get::<_, bool>(4));
    assert_eq!(refreshed.get::<_, i32>(6), 0);
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id,
        "semantic policy refresh never rearms the record"
    );

    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id
    );
    assert!(timer_gate_open(&harness.database, &record_id).await);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the refreshed occurrence executes once"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successor_null_at_cancels_current_occurrence_without_refresh_loop() {
    let harness = timer_outcome_harness(
        compiled_nullable_timer_at_registry(false),
        "record-timer-null-successor-at",
        0x8b,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "null-successor-at-anchor",
        "scheduled",
        Utc::now() + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let successor_registry = Arc::new(compiled_nullable_timer_at_registry(true));
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-null-successor-at-activation",
    )
    .await;
    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        successor.clone(),
        INSTANCE_ID,
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x8b; 32].into())
                .expect("test owns a keyed successor audit profile"),
        ),
    );
    let worker = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        Arc::clone(&successor_registry),
        coordinator,
        successor.clone(),
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );

    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the null successor control settles the stale occurrence"),
        1
    );
    let cancelled = harness
        .database
        .admin
        .query_one(
            "SELECT generation.state,generation.outcome_code,
                    generation.executed_attempt_count,current.occurrence_id
               FROM registry_internal.registry_record_timer_generations AS generation
               JOIN registry_internal.registry_record_timer_current AS current
                 ON current.record_type=generation.record_type
                AND current.record_id=generation.record_id
                AND current.timer_id=generation.timer_id
                AND current.occurrence_id=generation.occurrence_id
                AND current.binding_incarnation=generation.binding_incarnation
                AND current.material_signature=generation.material_signature
              WHERE generation.occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the control-cleared current occurrence remains queryable");
    assert_eq!(cancelled.get::<_, String>(0), "cancelled");
    assert_eq!(
        cancelled.get::<_, Option<String>>(1).as_deref(),
        Some("control-cleared")
    );
    assert_eq!(cancelled.get::<_, i32>(2), 0);
    assert_eq!(cancelled.get::<_, uuid::Uuid>(3), occurrence_id);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the settled current marker is not refreshed repeatedly"),
        0
    );

    patch_outcome_service_for_registry(
        &harness,
        &successor_registry,
        &successor,
        &record_id,
        "rearm-null-successor-at",
        PatchOperation::Add {
            path: "/data/successorAt".to_owned(),
            value: json!((Utc::now() - chrono::Duration::seconds(1))
                .to_rfc3339_opts(SecondsFormat::Micros, true)),
        },
        0x8b,
    )
    .await;
    let rearmed_occurrence = timer_occurrence(&harness.database, &record_id).await;
    assert_ne!(rearmed_occurrence, occurrence_id);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the deliberate successor control write executes once"),
        1
    );
    assert_terminal_timer_outcome(&harness, rearmed_occurrence, "completed", 1, "completed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborted_stale_refresh_retries_the_same_occurrence_without_an_attempt() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-aborted-policy-refresh",
        0x7d,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "aborted-policy-refresh-anchor",
        "reviewed",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let predecessor_revision =
        generation_definition_revision(&harness.database, occurrence_id).await;
    let successor_registry = Arc::new(compiled_changed_predicate_registry());
    let successor_timer = &successor_registry.entities()["service"].timers["activate"];
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-aborted-policy-refresh-successor",
    )
    .await;
    let faulting = successor_worker(
        &harness,
        Arc::clone(&successor_registry),
        successor.clone(),
        0x7e,
    )
    .with_fault_for_test(registry_breg::mutation::MutationFaultPoint::BeforeCommit);

    assert!(matches!(
        faulting.run_once().await,
        Err(registry_breg::mutation::MutationError::Unavailable)
    ));
    assert_eq!(
        generation_definition_revision(&harness.database, occurrence_id).await,
        predecessor_revision,
        "the aborted metadata transaction leaves the durable generation unchanged"
    );
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id
    );
    let unchanged = harness
        .database
        .admin
        .query_one(
            "SELECT state,executed_attempt_count,claim_owner_id,claim_token,claim_until,
                    (SELECT count(*) FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=$1)
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the aborted occurrence remains queryable");
    assert_eq!(unchanged.get::<_, String>(0), "pending");
    assert_eq!(unchanged.get::<_, i32>(1), 0);
    assert!(unchanged.get::<_, Option<uuid::Uuid>>(2).is_none());
    assert!(unchanged.get::<_, Option<uuid::Uuid>>(3).is_none());
    assert!(unchanged
        .get::<_, Option<chrono::DateTime<Utc>>>(4)
        .is_none());
    assert_eq!(unchanged.get::<_, i64>(5), 0);

    let worker = successor_worker(&harness, Arc::clone(&successor_registry), successor, 0x7f);
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the same stale occurrence is refreshed after the aborted transaction"),
        1
    );
    assert_eq!(
        generation_definition_revision(&harness.database, occurrence_id).await,
        successor_timer.definition_revision
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the refreshed occurrence executes once"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activation_waits_for_an_in_flight_refresh_without_losing_the_occurrence() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-refresh-activation-race",
        0x86,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "refresh-activation-race-anchor",
        "reviewed",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let semantic_registry = Arc::new(compiled_changed_predicate_registry());
    let semantic_timer = &semantic_registry.entities()["service"].timers["activate"];
    let semantic_identity = activate_timer_successor(
        &harness,
        &semantic_registry,
        "record-timer-refresh-activation-race-semantic",
    )
    .await;
    let (mut lock_client, lock_task) = harness.database.connect_migration().await;
    let generation_lock = lock_client
        .transaction()
        .await
        .expect("fixture can hold the exact stale generation");
    generation_lock
        .query_one(
            "SELECT occurrence_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1
              FOR UPDATE",
            &[&occurrence_id],
        )
        .await
        .expect("fixture locks the stale generation");

    let refreshing = successor_worker(
        &harness,
        Arc::clone(&semantic_registry),
        semantic_identity.clone(),
        0x87,
    );
    let refresh_task = tokio::spawn(async move { refreshing.run_once().await });
    wait_for_role_lock_wait(&harness, &harness.database.runtime_role).await;

    let later_identity = ExpectedRegistryIdentity {
        package_id: semantic_identity.package_id.clone(),
        database_id: semantic_identity.database_id.clone(),
        package_digest: test_package_digest("record-timer-refresh-activation-race-later"),
        activation_id: test_activation_id("record-timer-refresh-activation-race-later"),
        schema_fingerprint: semantic_identity.schema_fingerprint.clone(),
    };
    let migration_config = harness.database.migration_config.clone();
    let lock_key = harness.lock_key;
    let migration_role = harness.database.migration_role.clone();
    let runtime_role = harness.database.runtime_role.clone();
    let activation_registry = Arc::clone(&semantic_registry);
    let activation_predecessor = semantic_identity.clone();
    let activation_successor = later_identity.clone();
    let activation_task = tokio::spawn(async move {
        let catalog = ExpectedManagedCatalog::compiled(&activation_registry);
        let mut apply =
            DedicatedApplyConnection::acquire(&migration_config, lock_key, Duration::from_secs(5))
                .await
                .expect("the later activation opens its governed connection");
        apply
            .mark_applying(
                &activation_predecessor,
                &activation_successor.package_digest,
            )
            .await
            .expect("the later activation waits behind the in-flight refresh");
        apply
            .activate_compiled_for_catalog(
                &activation_registry,
                &activation_successor,
                &catalog,
                &migration_role,
                &runtime_role,
            )
            .await
            .expect("the later activation commits after the refresh");
        apply.release().await.expect("the apply lock is released");
    });
    wait_for_role_lock_wait(&harness, &harness.database.migration_role).await;
    generation_lock
        .rollback()
        .await
        .expect("fixture releases the stale generation");
    lock_task.abort();

    assert_eq!(
        refresh_task
            .await
            .expect("refresh task joins")
            .expect("the older admitted refresh commits before activation"),
        1
    );
    activation_task.await.expect("activation task joins");
    let refreshed = harness
        .database
        .admin
        .query_one(
            "SELECT generation.occurrence_id,generation.definition_revision,
                    generation.current_policy_activation_id,generation.executed_attempt_count,
                    binding.current_policy_activation_id
               FROM registry_internal.registry_record_timer_generations AS generation
               JOIN registry_internal.registry_record_timer_bindings AS binding
                 ON binding.record_type=generation.record_type
                AND binding.timer_id=generation.timer_id
                AND binding.incarnation=generation.binding_incarnation
              WHERE generation.occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the refreshed generation and later binding remain queryable");
    assert_eq!(refreshed.get::<_, uuid::Uuid>(0), occurrence_id);
    assert_eq!(
        refreshed.get::<_, String>(1),
        semantic_timer.definition_revision
    );
    assert_eq!(
        refreshed.get::<_, uuid::Uuid>(2),
        semantic_identity.activation_uuid().unwrap()
    );
    assert_eq!(refreshed.get::<_, i32>(3), 0);
    assert_eq!(
        refreshed.get::<_, uuid::Uuid>(4),
        later_identity.activation_uuid().unwrap()
    );

    let later_worker = successor_worker(&harness, semantic_registry, later_identity, 0x88);
    assert_eq!(
        later_worker
            .run_once()
            .await
            .expect("unchanged semantic work executes under the later activation"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_stale_refreshers_commit_once_without_losing_work() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-concurrent-policy-refresh",
        0x89,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "concurrent-policy-refresh-anchor",
        "reviewed",
        Utc::now() + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let successor_registry = Arc::new(compiled_changed_predicate_registry());
    let successor_definition_revision = successor_registry.entities()["service"].timers["activate"]
        .definition_revision
        .clone();
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-concurrent-policy-refresh-successor",
    )
    .await;
    let first = successor_worker(
        &harness,
        Arc::clone(&successor_registry),
        successor.clone(),
        0x8a,
    );
    let second = successor_worker(&harness, successor_registry, successor, 0x8b);
    let (mut lock_client, lock_task) = harness.database.connect_migration().await;
    let generation_lock = lock_client
        .transaction()
        .await
        .expect("fixture can hold the exact stale generation");
    generation_lock
        .query_one(
            "SELECT occurrence_id
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1
              FOR UPDATE",
            &[&occurrence_id],
        )
        .await
        .expect("fixture locks the stale generation while both refreshers discover it");
    let first = tokio::spawn(async move { first.run_once().await });
    let second = tokio::spawn(async move { second.run_once().await });
    wait_for_role_lock_wait(&harness, &harness.database.runtime_role).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !first.is_finished() && !second.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("one concurrent refresher skips the already-locked anchor");
    generation_lock
        .rollback()
        .await
        .expect("fixture releases both concurrent refreshers");
    lock_task.abort();
    let first = first.await.expect("first refresh task joins");
    let second = second.await.expect("second refresh task joins");
    let results = [first, second]
        .into_iter()
        .map(|result| result.expect("a losing concurrent refresher is a clean no-op"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().sum::<usize>(), 1);
    assert_eq!(
        generation_definition_revision(&harness.database, occurrence_id).await,
        successor_definition_revision
    );
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id
    );
    let attempts: i64 = harness
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_record_timer_attempts
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("concurrent refresh attempt count is queryable")
        .get(0);
    assert_eq!(attempts, 0);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_successor_window_blocks_until_a_reviewed_correction() {
    let predecessor_registry = compiled_no_window_registry();
    let harness = timer_outcome_harness(
        predecessor_registry,
        "record-timer-invalid-successor-window",
        0x81,
    )
    .await;
    let due_at = Utc::now() - chrono::Duration::seconds(1);
    let invalid_end = due_at - chrono::Duration::seconds(1);
    let created = create_outcome_service(
        &harness,
        "invalid-successor-window-anchor",
        "scheduled",
        due_at,
        Some(invalid_end),
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;

    let invalid_registry = Arc::new(compiled_registry());
    let invalid_timer = &invalid_registry.entities()["service"].timers["activate"];
    let invalid_identity = activate_timer_successor(
        &harness,
        &invalid_registry,
        "record-timer-invalid-successor-window-invalid",
    )
    .await;
    let invalid_worker = successor_worker(
        &harness,
        Arc::clone(&invalid_registry),
        invalid_identity.clone(),
        0x82,
    );
    assert_eq!(
        invalid_worker
            .run_once()
            .await
            .expect("the invalid successor window becomes a configuration block"),
        1
    );
    let blocked = harness
        .database
        .admin
        .query_one(
            "SELECT occurrence_id,state,block_kind,outcome_code,executed_attempt_count,
                    definition_revision
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the configuration block is queryable");
    assert_eq!(blocked.get::<_, uuid::Uuid>(0), occurrence_id);
    assert_eq!(blocked.get::<_, String>(1), "blocked");
    assert_eq!(
        blocked.get::<_, Option<String>>(2).as_deref(),
        Some("configuration")
    );
    assert!(blocked.get::<_, Option<String>>(3).is_none());
    assert_eq!(blocked.get::<_, i32>(4), 0);
    assert_eq!(
        blocked.get::<_, String>(5),
        invalid_timer.definition_revision
    );
    assert_eq!(
        invalid_worker
            .run_once()
            .await
            .expect("a current configuration block is not rediscovered in a hot loop"),
        0
    );

    let corrected_registry = Arc::new(compiled_no_window_registry());
    let corrected_definition_revision = corrected_registry.entities()["service"].timers["activate"]
        .definition_revision
        .clone();
    let corrected_identity = activate_timer_successor_from(
        &harness,
        &invalid_identity,
        &corrected_registry,
        "record-timer-invalid-successor-window-corrected",
    )
    .await;
    let corrected_worker = successor_worker(&harness, corrected_registry, corrected_identity, 0x83);
    assert_eq!(
        corrected_worker
            .run_once()
            .await
            .expect("the reviewed correction refreshes the same occurrence"),
        1
    );
    let recovered = harness
        .database
        .admin
        .query_one(
            "SELECT occurrence_id,state,block_kind,executed_attempt_count,definition_revision
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the recovered occurrence is queryable");
    assert_eq!(recovered.get::<_, uuid::Uuid>(0), occurrence_id);
    assert_eq!(recovered.get::<_, String>(1), "pending");
    assert!(recovered.get::<_, Option<String>>(2).is_none());
    assert_eq!(recovered.get::<_, i32>(3), 0);
    assert_eq!(recovered.get::<_, String>(4), corrected_definition_revision);
    assert_eq!(
        corrected_worker
            .run_once()
            .await
            .expect("the corrected occurrence executes once"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_and_readded_timer_keeps_its_fence_until_a_material_change() {
    let harness =
        timer_outcome_harness(compiled_registry(), "record-timer-remove-readd", 0x5b).await;
    let created = create_outcome_service(
        &harness,
        "remove-readd-anchor",
        "scheduled",
        Utc::now() + chrono::Duration::hours(1),
        None,
        Some(uuid::Uuid::new_v4()),
    )
    .await;
    let record_id = response_id(&created);
    let predecessor_occurrence = timer_occurrence(&harness.database, &record_id).await;

    let removed_registry = Arc::new(compiled_timer_free_registry());
    let removed_identity = activate_timer_successor(
        &harness,
        &removed_registry,
        "record-timer-remove-readd-removed",
    )
    .await;
    let removed_worker = successor_worker(
        &harness,
        Arc::clone(&removed_registry),
        removed_identity.clone(),
        0x5c,
    );
    assert_eq!(
        removed_worker
            .run_once()
            .await
            .expect("the removed binding closes one retained occurrence"),
        1
    );
    assert_terminal_timer_outcome(
        &harness,
        predecessor_occurrence,
        "cancelled",
        0,
        "binding-removed",
    )
    .await;

    let unrelated = patch_outcome_service_for_registry(
        &harness,
        &removed_registry,
        &removed_identity,
        &record_id,
        "remove-readd-unrelated-while-removed",
        PatchOperation::Replace {
            path: "/data/note".to_owned(),
            value: json!("unrelated while removed"),
        },
        0x5d,
    )
    .await;
    let _ = unrelated;
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        predecessor_occurrence
    );

    let readded_registry = Arc::new(compiled_registry());
    let readded_identity = activate_timer_successor_from(
        &harness,
        &removed_identity,
        &readded_registry,
        "record-timer-remove-readd-readded",
    )
    .await;
    let unrelated = patch_outcome_service_for_registry(
        &harness,
        &readded_registry,
        &readded_identity,
        &record_id,
        "remove-readd-unrelated-after-readd",
        PatchOperation::Replace {
            path: "/data/note".to_owned(),
            value: json!("unrelated after readd"),
        },
        0x5e,
    )
    .await;
    let _ = unrelated;
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        predecessor_occurrence,
        "re-adding the binding does not arm historical current facts"
    );

    patch_outcome_service_for_registry(
        &harness,
        &readded_registry,
        &readded_identity,
        &record_id,
        "remove-readd-material-change",
        PatchOperation::Add {
            path: "/data/activationRevision".to_owned(),
            value: json!(uuid::Uuid::new_v4()),
        },
        0x5f,
    )
    .await;
    let successor_occurrence = timer_occurrence(&harness.database, &record_id).await;
    assert_ne!(successor_occurrence, predecessor_occurrence);
    let incarnations = harness
        .database
        .admin
        .query(
            "SELECT occurrence_id,binding_incarnation,state
               FROM registry_internal.registry_record_timer_generations
              WHERE record_type='service' AND record_id=$1::text::uuid AND timer_id='activate'
              ORDER BY binding_incarnation,created_at,occurrence_id",
            &[&record_id],
        )
        .await
        .expect("both timer incarnations remain queryable");
    assert_eq!(incarnations.len(), 2);
    assert_eq!(
        incarnations[0].get::<_, uuid::Uuid>(0),
        predecessor_occurrence
    );
    assert_eq!(incarnations[0].get::<_, i64>(1), 1);
    assert_eq!(incarnations[0].get::<_, String>(2), "cancelled");
    assert_eq!(
        incarnations[1].get::<_, uuid::Uuid>(0),
        successor_occurrence
    );
    assert_eq!(incarnations[1].get::<_, i64>(1), 2);
    assert_eq!(incarnations[1].get::<_, String>(2), "pending");

    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adding_a_timer_does_not_arm_historical_records() {
    let harness = timer_outcome_harness(
        compiled_timer_free_registry(),
        "record-timer-added-no-history-scan",
        0x63,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "timer-added-existing-record",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let successor_registry = Arc::new(compiled_registry());
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-added-no-history-scan-successor",
    )
    .await;
    let worker = successor_worker(
        &harness,
        Arc::clone(&successor_registry),
        successor.clone(),
        0x64,
    );

    assert_eq!(
        worker
            .run_once()
            .await
            .expect("adding a timer does not scan historical Records"),
        0
    );
    let counts = harness
        .database
        .admin
        .query_one(
            "SELECT
                 (SELECT count(*) FROM registry_internal.registry_record_timer_current
                   WHERE record_type='service' AND record_id=$1::text::uuid),
                 (SELECT count(*) FROM registry_internal.registry_record_timer_generations
                   WHERE record_type='service' AND record_id=$1::text::uuid)",
            &[&record_id],
        )
        .await
        .expect("historical timer metadata is queryable");
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 0);

    patch_outcome_service_for_registry(
        &harness,
        &successor_registry,
        &successor,
        &record_id,
        "timer-added-historical-predicate-only",
        PatchOperation::Replace {
            path: "/data/status".to_owned(),
            value: json!("reviewed"),
        },
        0x65,
    )
    .await;
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("predicate-only historical write remains unarmed"),
        0
    );
    let unmarked = harness
        .database
        .admin
        .query_one(
            "SELECT
                 (SELECT count(*) FROM registry_internal.registry_record_timer_current
                   WHERE record_type='service' AND record_id=$1::text::uuid),
                 (SELECT count(*) FROM registry_internal.registry_record_timer_generations
                   WHERE record_type='service' AND record_id=$1::text::uuid)",
            &[&record_id],
        )
        .await
        .expect("predicate-only historical timer metadata is queryable");
    assert_eq!(unmarked.get::<_, i64>(0), 0);
    assert_eq!(unmarked.get::<_, i64>(1), 0);

    patch_outcome_service_for_registry(
        &harness,
        &successor_registry,
        &successor,
        &record_id,
        "timer-added-historical-material-change",
        PatchOperation::Replace {
            path: "/data/activationRevision".to_owned(),
            value: json!(uuid::Uuid::new_v4()),
        },
        0x66,
    )
    .await;
    let armed = harness
        .database
        .admin
        .query_one(
            "SELECT
                 (SELECT count(*) FROM registry_internal.registry_record_timer_current
                   WHERE record_type='service' AND record_id=$1::text::uuid),
                 (SELECT count(*) FROM registry_internal.registry_record_timer_generations
                   WHERE record_type='service' AND record_id=$1::text::uuid),
                 (SELECT state FROM registry_internal.registry_record_timer_generations
                   WHERE record_type='service' AND record_id=$1::text::uuid
                   ORDER BY created_at DESC,occurrence_id DESC LIMIT 1)",
            &[&record_id],
        )
        .await
        .expect("material historical timer metadata is queryable");
    assert_eq!(armed.get::<_, i64>(0), 1);
    assert_eq!(armed.get::<_, i64>(1), 1);
    assert_eq!(armed.get::<_, String>(2), "pending");
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_timer_removal_keeps_the_worker_admitted_for_retained_cleanup() {
    let never_timered = timer_outcome_harness(
        compiled_timer_free_registry(),
        "record-timer-never-timered-worker-admission",
        0x65,
    )
    .await;
    assert!(!retained_record_timer_state_exists_for_test(
        &never_timered.pool,
        &never_timered.identity,
        never_timered.lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("a never-timered Registry has no retained worker duty"));
    never_timered.database.cleanup().await;

    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-last-removed-worker-admission",
        0x66,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "last-removed-retained-anchor",
        "scheduled",
        Utc::now() + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let removed_registry = Arc::new(compiled_timer_free_registry());
    let removed_identity = activate_timer_successor(
        &harness,
        &removed_registry,
        "record-timer-last-removed-worker-admission-successor",
    )
    .await;
    assert!(retained_record_timer_state_exists_for_test(
        &harness.pool,
        &removed_identity,
        harness.lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("last-timer removal retains a cleanup duty for startup"));
    let removed_worker = successor_worker(&harness, removed_registry, removed_identity, 0x67);
    assert_eq!(
        removed_worker
            .run_once()
            .await
            .expect("the startup-admitted worker closes retained removed work"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "cancelled", 0, "binding-removed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_refresh_skips_a_busy_anchor_and_revisits_it_after_cursor_wrap() {
    let mut harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-refresh-fair-cursor",
        0x60,
    )
    .await;
    for suffix in ["a", "b"] {
        create_outcome_service(
            &harness,
            &format!("refresh-fair-{suffix}"),
            "reviewed",
            Utc::now() + chrono::Duration::hours(1),
            None,
            None,
        )
        .await;
    }
    let successor_registry = Arc::new(compiled_changed_predicate_registry());
    let successor_timer = &successor_registry.entities()["service"].timers["activate"];
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-refresh-fair-cursor-successor",
    )
    .await;
    let candidates = harness
        .database
        .admin
        .query(
            "SELECT record_id,occurrence_id
               FROM registry_internal.registry_record_timer_generations
              WHERE definition_revision<>$1
              ORDER BY record_type,occurrence_id",
            &[&successor_timer.definition_revision],
        )
        .await
        .expect("the two stale candidates are queryable");
    assert_eq!(candidates.len(), 2);
    let busy_record: uuid::Uuid = candidates[0].get(0);
    let busy_occurrence: uuid::Uuid = candidates[0].get(1);
    let available_occurrence: uuid::Uuid = candidates[1].get(1);
    let entity = &successor_registry.entities()["service"];
    let worker = successor_worker(
        &harness,
        Arc::clone(&successor_registry),
        successor.clone(),
        0x61,
    );
    let due = create_outcome_service_for_registry(
        &harness,
        &successor_registry,
        &successor,
        "refresh-fair-due",
        Utc::now() - chrono::Duration::seconds(1),
    )
    .await;
    let due_occurrence = timer_occurrence(&harness.database, &response_id(&due)).await;
    let locked = harness
        .database
        .admin
        .transaction()
        .await
        .expect("the fixture opens a competing anchor transaction");
    locked
        .query_one(
            &format!(
                "SELECT record_id FROM registry_data.\"{}\" WHERE record_id=$1 FOR UPDATE",
                entity.physical_table
            ),
            &[&busy_record],
        )
        .await
        .expect("the first stale anchor is busy");

    assert_eq!(
        worker
            .run_once()
            .await
            .expect("a busy stale anchor does not block already-current due work"),
        1
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the stable cursor reaches the next stale anchor"),
        1
    );
    assert_eq!(
        generation_definition_revision_via_pool(&harness.pool, available_occurrence).await,
        successor_timer.definition_revision
    );
    assert_ne!(
        generation_definition_revision_via_pool(&harness.pool, busy_occurrence).await,
        successor_timer.definition_revision
    );

    locked
        .rollback()
        .await
        .expect("the busy anchor is released");
    assert_terminal_timer_outcome(&harness, due_occurrence, "completed", 1, "completed").await;
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("cursor wrap revisits the formerly busy anchor"),
        1
    );
    assert_eq!(
        generation_definition_revision(&harness.database, busy_occurrence).await,
        successor_timer.definition_revision
    );

    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_timer_mapping_refreshes_target_digest_without_rearming() {
    let harness = timer_outcome_harness(
        compiled_secondary_get_registry(),
        "record-timer-mapping-refresh",
        0x75,
    )
    .await;
    let approval_claims = ClaimContext::for_compiled(
        &harness.registry,
        "approval",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("approval authority is compiler-bound");
    let approval_plan =
        MutationPlan::from_compiled(&harness.registry, "records.approval.create").unwrap();
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection");
    let mut approval_ids = Vec::new();
    for (key, status) in [
        ("create-mapping-refresh-old-approval", "pending"),
        ("create-mapping-refresh-current-approval", "approved"),
    ] {
        let approval = harness
            .coordinator
            .execute(
                &mut client,
                MutationRequest {
                    plan: &approval_plan,
                    idempotency_key: key,
                    claims: &approval_claims,
                    record_id: None,
                    expected_etag: None,
                    body: MutationBody::Create(Map::from_iter([
                        ("jurisdiction".to_owned(), json!("zone-a")),
                        ("status".to_owned(), json!(status)),
                    ])),
                    response_fields: BTreeSet::from([
                        "jurisdiction".to_owned(),
                        "status".to_owned(),
                    ]),
                    representation: RecordRepresentation::Json,
                    correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
                },
            )
            .await
            .expect("mapping refresh approval is created");
        approval_ids.push(response_id(&approval));
    }
    let service_plan =
        MutationPlan::from_compiled(&harness.registry, "records.service.create").unwrap();
    let service = harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &service_plan,
                idempotency_key: "create-mapping-refresh-anchor",
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("approval".to_owned(), json!(approval_ids[0])),
                    ("backupApproval".to_owned(), json!(approval_ids[1])),
                    ("note".to_owned(), json!("mapping refresh anchor")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("mapping refresh anchor is created");
    let record_id = response_id(&service);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let old_digest: Value = harness
        .database
        .admin
        .query_one(
            "SELECT target_binding_digests
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the predecessor target digest is queryable")
        .get(0);

    let successor_registry = Arc::new(compiled_secondary_get_registry_for("backup-approval"));
    let successor_timer = &successor_registry.entities()["service"].timers["activate"];
    let successor_catalog = ExpectedManagedCatalog::compiled(&successor_registry);
    let (mut fingerprint_client, fingerprint_task) = harness.database.connect_migration().await;
    let fingerprint_transaction = fingerprint_client.transaction().await.unwrap();
    reconcile_record_timer_runtime_acl_for_test(
        &fingerprint_transaction,
        &successor_registry,
        &harness.database.runtime_role,
    )
    .await
    .expect("the successor timer policies rehearse transactionally");
    reconcile_compiled_runtime_acl_for_test(
        &fingerprint_transaction,
        &successor_registry,
        &harness.database.runtime_role,
    )
    .await
    .expect("the successor runtime ACL rehearses transactionally");
    let successor_fingerprint = managed_schema_fingerprint(
        &fingerprint_transaction,
        &harness.database.runtime_role,
        &successor_catalog,
    )
    .await
    .expect("the successor managed fingerprint is measured exactly");
    fingerprint_transaction.rollback().await.unwrap();
    fingerprint_task.abort();
    let successor = ExpectedRegistryIdentity {
        package_id: harness.identity.package_id.clone(),
        database_id: harness.identity.database_id.clone(),
        package_digest: test_package_digest("record-timer-mapping-refresh-successor"),
        activation_id: test_activation_id("record-timer-mapping-refresh-successor"),
        schema_fingerprint: successor_fingerprint,
    };
    let mut apply = DedicatedApplyConnection::acquire(
        &harness.database.migration_config,
        harness.lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("the mapping successor obtains the exclusive Registry lock");
    apply
        .mark_applying(&harness.identity, &successor.package_digest)
        .await
        .expect("the mapping successor enters governed maintenance");
    apply
        .activate_compiled_for_catalog(
            &successor_registry,
            &successor,
            &successor_catalog,
            &harness.database.migration_role,
            &harness.database.runtime_role,
        )
        .await
        .expect("the mapping successor and binding activate atomically");
    apply.release().await.unwrap();

    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        successor.clone(),
        INSTANCE_ID,
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x75; 32].into())
                .expect("test owns a keyed successor audit profile"),
        ),
    );
    let worker = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        Arc::clone(&successor_registry),
        coordinator,
        successor,
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the stale mapping is reconciled before claim"),
        1
    );
    let refreshed = harness
        .database
        .admin
        .query_one(
            "SELECT occurrence_id,definition_revision,target_binding_digests,
                    executed_attempt_count
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the refreshed target digest is queryable");
    assert_eq!(refreshed.get::<_, uuid::Uuid>(0), occurrence_id);
    assert_eq!(
        refreshed.get::<_, String>(1),
        successor_timer.definition_revision
    );
    let current_digest = refreshed.get::<_, Value>(2);
    assert_ne!(current_digest, old_digest);
    assert_eq!(refreshed.get::<_, i32>(3), 0);
    assert_eq!(
        timer_occurrence(&harness.database, &record_id).await,
        occurrence_id
    );

    assert_eq!(
        worker
            .run_once()
            .await
            .expect("the refreshed mapping executes against the current target"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "completed", 1, "completed").await;
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_refresh_audit_refusal_precedes_the_protected_anchor_read() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-refresh-audit-order",
        0x76,
    )
    .await;
    let due = Utc::now() + chrono::Duration::hours(1);
    let created = create_outcome_service(
        &harness,
        "refresh-audit-order-anchor",
        "reviewed",
        due,
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let predecessor_revision = harness.registry.entities()["service"].timers["activate"]
        .definition_revision
        .clone();
    let successor_registry = Arc::new(compiled_changed_predicate_registry());
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-refresh-audit-order-successor",
    )
    .await;
    let entity = &successor_registry.entities()["service"];
    harness
        .database
        .admin
        .batch_execute(&format!(
            "REVOKE SELECT ON TABLE registry_data.\"{}\" FROM \"{}\"",
            entity.physical_table,
            harness.database.runtime_role.as_str(),
        ))
        .await
        .expect("fixture denies the exact protected anchor read");
    harness
        .database
        .audit_capture()
        .fail_on(TIMER_MAINTENANCE_AUDIT_SCHEMA, "attempt");
    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        successor.clone(),
        INSTANCE_ID,
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x76; 32].into())
                .expect("test owns a keyed successor audit profile"),
        ),
    );
    let worker = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        Arc::clone(&successor_registry),
        coordinator,
        successor,
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    let result = worker.run_once().await;
    harness
        .database
        .admin
        .batch_execute(&format!(
            "GRANT SELECT ON TABLE registry_data.\"{}\" TO \"{}\"",
            entity.physical_table,
            harness.database.runtime_role.as_str(),
        ))
        .await
        .expect("fixture restores the runtime table grant");

    assert!(matches!(
        result,
        Err(registry_breg::mutation::MutationError::Unavailable)
    ));
    assert_eq!(harness.database.audit_capture().matched_refusal_count(), 1);
    let retained = harness
        .database
        .admin
        .query_one(
            "SELECT definition_revision,executed_attempt_count
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("audit refusal leaves the stale occurrence unchanged");
    assert_eq!(retained.get::<_, String>(0), predecessor_revision);
    assert_eq!(retained.get::<_, i32>(1), 0);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_refresh_commit_uncertainty_is_audited_unfinished_and_not_repeated() {
    let harness = timer_outcome_harness(
        compiled_registry(),
        "record-timer-refresh-commit-uncertain",
        0x77,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "refresh-commit-uncertain-anchor",
        "reviewed",
        Utc::now() + chrono::Duration::hours(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let successor_registry = Arc::new(compiled_changed_predicate_registry());
    let successor_timer = &successor_registry.entities()["service"].timers["activate"];
    let successor = activate_timer_successor(
        &harness,
        &successor_registry,
        "record-timer-refresh-commit-uncertain-successor",
    )
    .await;
    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        successor.clone(),
        INSTANCE_ID,
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x77; 32].into())
                .expect("test owns a keyed successor audit profile"),
        ),
    );
    let worker = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        Arc::clone(&successor_registry),
        coordinator.clone(),
        successor.clone(),
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .with_fault_for_test(MutationFaultPoint::AfterCommitBeforeResponseRelease);
    assert!(matches!(
        worker.run_once().await,
        Err(registry_breg::mutation::MutationError::CommitUnresolved)
    ));
    let refreshed = harness
        .database
        .admin
        .query_one(
            "SELECT definition_revision,executed_attempt_count
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the uncertain response follows a committed metadata refresh");
    assert_eq!(
        refreshed.get::<_, String>(0),
        successor_timer.definition_revision
    );
    assert_eq!(refreshed.get::<_, i32>(1), 0);
    let maintenance = harness
        .database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["schema"] == TIMER_MAINTENANCE_AUDIT_SCHEMA)
        .collect::<Vec<_>>();
    assert_eq!(maintenance.len(), 2);
    assert_eq!(maintenance[0]["record"]["phase"], "attempt");
    assert_eq!(maintenance[1]["record"]["phase"], "terminal");
    assert_eq!(maintenance[1]["record"]["outcome"], "unfinished");

    let restarted = RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        successor_registry,
        coordinator,
        successor,
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    assert_eq!(
        restarted
            .run_once()
            .await
            .expect("the committed refresh is not repeated after restart"),
        0
    );
    let maintenance_after_restart = harness
        .database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["schema"] == TIMER_MAINTENANCE_AUDIT_SCHEMA)
        .count();
    assert_eq!(maintenance_after_restart, 2);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_action_that_would_arm_a_successor_refuses_atomically() {
    let harness = timer_outcome_harness(
        compiled_self_rearming_registry(),
        "record-timer-self-rearm-refusal",
        0x67,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "self-rearm-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("a generation-producing Action is a settled business refusal"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "refused", 1, "declared-refusal").await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    let retained = harness
        .database
        .admin
        .query_one(
            "SELECT count(*),
                    (SELECT occurrence_id
                       FROM registry_internal.registry_record_timer_current
                      WHERE record_type='service' AND record_id=$1::text::uuid
                        AND timer_id='activate')
               FROM registry_internal.registry_record_timer_generations
              WHERE record_type='service' AND record_id=$1::text::uuid
                AND timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("the refused Action retains only its original occurrence");
    assert_eq!(retained.get::<_, i64>(0), 1);
    assert_eq!(retained.get::<_, uuid::Uuid>(1), occurrence_id);
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_runtime_refuses_a_compiler_unreachable_proposal_required_target() {
    let harness = timer_outcome_harness(
        compiled_illegal_proposal_required_timer_registry(),
        "record-timer-proposal-required-runtime-refusal",
        0x8b,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "proposal-required-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert!(matches!(
        harness.worker(Duration::from_secs(2)).run_once().await,
        Err(registry_breg::mutation::MutationError::InvalidRequest)
    ));
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before,
        "the runtime Proposal-policy backstop leaves no partial effect"
    );
    let generation = harness
        .database
        .admin
        .query_one(
            "SELECT state,executed_attempt_count,
                    (SELECT count(*)
                       FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_generations AS generation
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the refused illegal fixture retains its claimed generation");
    assert_ne!(generation.get::<_, String>(0), "completed");
    assert_eq!(generation.get::<_, i32>(1), 0);
    assert_eq!(generation.get::<_, i64>(2), 0);
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_action_that_would_arm_another_anchor_timer_refuses_atomically() {
    let harness = timer_outcome_harness(
        compiled_cross_timer_rearming_registry(),
        "record-timer-cross-timer-rearm-refusal",
        0x8c,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "cross-timer-rearm-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("cross-timer generation creation is a settled business refusal"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "refused", 1, "declared-refusal").await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    let state = record_values(&harness.database, &harness.registry, &record_id).await;
    assert_eq!(state.0, "scheduled");
    let followup = harness
        .database
        .admin
        .query_one(
            "SELECT count(*) FILTER (WHERE timer_id='activate-followup'),
                    count(*) FILTER (WHERE timer_id='activate')
               FROM registry_internal.registry_record_timer_generations
              WHERE record_type='service' AND record_id=$1::text::uuid",
            &[&record_id],
        )
        .await
        .expect("only the original timer occurrence is retained");
    assert_eq!(followup.get::<_, i64>(0), 0);
    assert_eq!(followup.get::<_, i64>(1), 1);
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_action_that_would_arm_a_created_record_timer_refuses_atomically() {
    let harness = timer_outcome_harness(
        compiled_created_record_timer_rearming_registry(),
        "record-timer-created-record-rearm-refusal",
        0x8d,
    )
    .await;
    let created = create_outcome_service(
        &harness,
        "created-record-rearm-anchor",
        "scheduled",
        Utc::now() - chrono::Duration::seconds(1),
        None,
        None,
    )
    .await;
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&harness.database, &record_id).await;
    let before = effect_counts(&harness.database, &harness.registry, &record_id).await;

    assert_eq!(
        harness
            .worker(Duration::from_secs(2))
            .run_once()
            .await
            .expect("created-record generation creation is a settled business refusal"),
        1
    );
    assert_terminal_timer_outcome(&harness, occurrence_id, "refused", 1, "declared-refusal").await;
    assert_eq!(
        effect_counts(&harness.database, &harness.registry, &record_id).await,
        before
    );
    assert_eq!(
        record_values(&harness.database, &harness.registry, &record_id)
            .await
            .0,
        "scheduled"
    );
    let task_entity = &harness.registry.entities()["activation-task"];
    let refused_effects = harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT
                    (SELECT count(*) FROM registry_data.\"{}\"),
                    (SELECT count(*) FROM registry_internal.registry_revisions
                      WHERE entity_id='activation-task'),
                    (SELECT count(*) FROM registry_internal.registry_outbox
                      WHERE entity_id='activation-task'),
                    (SELECT count(*) FROM registry_internal.registry_record_timer_generations
                      WHERE record_type='activation-task')",
                task_entity.physical_table
            ),
            &[],
        )
        .await
        .expect("the refused created-record effect leaves no durable artifact");
    for column in 0..4 {
        assert_eq!(refused_effects.get::<_, i64>(column), 0);
    }

    let task_claims = ClaimContext::for_compiled(
        &harness.registry,
        "activation-task",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary activation-task create authority is compiler-bound");
    let task_plan =
        MutationPlan::from_compiled(&harness.registry, "records.activation-task.create")
            .expect("activation-task create route is compiled");
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &task_plan,
                idempotency_key: "create-task-after-refused-timer-action",
                claims: &task_claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() + chrono::Duration::hours(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                ])),
                response_fields: BTreeSet::from([
                    "jurisdiction".to_owned(),
                    "task-number".to_owned(),
                    "status".to_owned(),
                    "activates-at".to_owned(),
                ]),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("the first legitimate task create succeeds after the refusal");
    let task_number = &task_entity.fields["task-number"].physical_name;
    let created_task = harness
        .database
        .admin
        .query_one(
            &format!(
                "SELECT count(*),min(\"{task_number}\"::text)
                   FROM registry_data.\"{}\"",
                task_entity.physical_table
            ),
            &[],
        )
        .await
        .expect("the legitimate task create is queryable");
    assert_eq!(created_task.get::<_, i64>(0), 1);
    assert_eq!(
        created_task.get::<_, Option<String>>(1).as_deref(),
        Some("TASK-0001"),
        "the refused timer transaction consumes no generated identifier"
    );
    assert_timer_refusal_audit(&harness.database);
    harness.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_crash_consumes_no_attempt_and_reclaim_commits_one_attempt() {
    let database = TestDatabase::create(6).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs timer state");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            database_id: DATABASE_ID,
            label: "record-timer-package-claim-attempt",
        },
    )
    .await
    .expect("migration initializes the active package");
    drop(migration);
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x77; 32].into())
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
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    let create_plan = MutationPlan::from_compiled(&registry, "records.service.create").unwrap();
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let created = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key: "create-claim-attempt-service",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("scheduled")),
                    (
                        "activatesAt".to_owned(),
                        json!((Utc::now() - chrono::Duration::seconds(1))
                            .to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!("claim attempt canary")),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms one due occurrence");
    let record_id = response_id(&created);
    let occurrence_id = timer_occurrence(&database, &record_id).await;

    let failed = RecordTimerWorker::new_for_test(
        pool.clone(),
        registry.clone(),
        coordinator.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        Duration::from_millis(100),
    )
    .with_fault_for_test(MutationFaultPoint::AfterClaim)
    .run_once()
    .await;
    assert!(failed.is_err(), "the post-claim crash is visible");
    let claimed = database
        .admin
        .query_one(
            "SELECT state, claim_epoch, executed_attempt_count, retry_allowance,
                    (SELECT count(*) FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=$1)
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("claim-only durable state is queryable");
    assert_eq!(claimed.get::<_, String>(0), "leased");
    assert_eq!(claimed.get::<_, i64>(1), 1);
    assert_eq!(claimed.get::<_, i32>(2), 0);
    assert_eq!(claimed.get::<_, i16>(3), 0);
    assert_eq!(claimed.get::<_, i64>(4), 0);

    tokio::time::sleep(Duration::from_millis(120)).await;
    let peer = RecordTimerWorker::new_for_test(
        pool,
        registry,
        coordinator,
        identity,
        lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    assert_eq!(
        peer.run_once().await.expect("peer reclaims and executes"),
        1
    );
    let completed = database
        .admin
        .query_one(
            "SELECT generation.state, generation.claim_epoch,
                    generation.executed_attempt_count, generation.retry_allowance,
                    generation.receipt_correlation, attempt.claim_epoch,
                    attempt.outcome_code, attempt.receipt_correlation,
                    (SELECT count(*) FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_generations AS generation
               JOIN registry_internal.registry_record_timer_attempts AS attempt
                 ON attempt.occurrence_id=generation.occurrence_id
                AND attempt.attempt_number=1
              WHERE generation.occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("one committed execution attempt is queryable");
    assert_eq!(completed.get::<_, String>(0), "completed");
    assert_eq!(completed.get::<_, i64>(1), 2);
    assert_eq!(completed.get::<_, i32>(2), 1);
    assert_eq!(completed.get::<_, i16>(3), 0);
    assert_eq!(completed.get::<_, i64>(5), 2);
    assert_eq!(completed.get::<_, String>(6), "completed");
    assert_eq!(
        completed.get::<_, Option<uuid::Uuid>>(4),
        completed.get::<_, Option<uuid::Uuid>>(7)
    );
    assert_eq!(completed.get::<_, i64>(8), 1);
    database.cleanup().await;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectCounts {
    revisions: i64,
    outbox: i64,
    action_receipts: i64,
}

struct TimerOutcomeHarness {
    database: TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    pool: RuntimePool,
    coordinator: MutationTransaction,
    claims: ClaimContext,
    lock_key: RegistryLockKey,
}

impl TimerOutcomeHarness {
    fn worker(&self, lease_duration: Duration) -> RecordTimerWorker {
        RecordTimerWorker::new_for_test(
            self.pool.clone(),
            Arc::clone(&self.registry),
            self.coordinator.clone(),
            self.identity.clone(),
            self.lock_key,
            Duration::from_secs(2),
            lease_duration,
        )
    }
}

async fn timer_outcome_harness(
    registry: registry_breg::CompiledRegistry,
    label: &'static str,
    audit_seed: u8,
) -> TimerOutcomeHarness {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(registry);
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs timer state");
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
    drop(migration);
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
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
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    TimerOutcomeHarness {
        database,
        registry,
        identity,
        pool,
        coordinator,
        claims,
        lock_key,
    }
}

async fn activate_timer_successor(
    harness: &TimerOutcomeHarness,
    successor_registry: &Arc<registry_breg::CompiledRegistry>,
    label: &str,
) -> ExpectedRegistryIdentity {
    activate_timer_successor_from(harness, &harness.identity, successor_registry, label).await
}

async fn wait_for_role_lock_wait(harness: &TimerOutcomeHarness, role: &SqlIdentifier) {
    wait_for_role_lock_waits(harness, role, 1).await;
}

async fn wait_for_role_lock_waits(
    harness: &TimerOutcomeHarness,
    role: &SqlIdentifier,
    minimum: i64,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: i64 = harness
                .database
                .admin
                .query_one(
                    "SELECT count(*)
                       FROM (
                         SELECT DISTINCT lock.pid
                           FROM pg_catalog.pg_locks AS lock
                           JOIN pg_catalog.pg_stat_activity AS activity
                             ON activity.pid=lock.pid
                          WHERE activity.usename=$1 AND NOT lock.granted
                       ) AS waiting",
                    &[&role.as_str()],
                )
                .await
                .expect("fixture can observe role lock waits")
                .get(0);
            if waiting >= minimum {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the expected role reaches its bounded lock wait");
}

async fn activate_timer_successor_from(
    harness: &TimerOutcomeHarness,
    predecessor: &ExpectedRegistryIdentity,
    successor_registry: &Arc<registry_breg::CompiledRegistry>,
    label: &str,
) -> ExpectedRegistryIdentity {
    let successor_catalog = ExpectedManagedCatalog::compiled(successor_registry);
    let (mut fingerprint_client, fingerprint_task) = harness.database.connect_migration().await;
    let fingerprint_transaction = fingerprint_client.transaction().await.unwrap();
    reconcile_record_timer_runtime_acl_for_test(
        &fingerprint_transaction,
        successor_registry,
        &harness.database.runtime_role,
    )
    .await
    .expect("the successor timer policies rehearse transactionally");
    reconcile_compiled_runtime_acl_for_test(
        &fingerprint_transaction,
        successor_registry,
        &harness.database.runtime_role,
    )
    .await
    .expect("the successor runtime ACL rehearses transactionally");
    let successor_fingerprint = managed_schema_fingerprint(
        &fingerprint_transaction,
        &harness.database.runtime_role,
        &successor_catalog,
    )
    .await
    .expect("the successor managed fingerprint is measured exactly");
    fingerprint_transaction.rollback().await.unwrap();
    fingerprint_task.abort();
    let successor = ExpectedRegistryIdentity {
        package_id: harness.identity.package_id.clone(),
        database_id: harness.identity.database_id.clone(),
        package_digest: test_package_digest(label),
        activation_id: test_activation_id(label),
        schema_fingerprint: successor_fingerprint,
    };
    let mut apply = DedicatedApplyConnection::acquire(
        &harness.database.migration_config,
        harness.lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("the successor obtains the exclusive Registry lock");
    apply
        .mark_applying(predecessor, &successor.package_digest)
        .await
        .expect("the successor enters governed maintenance");
    apply
        .activate_compiled_for_catalog(
            successor_registry,
            &successor,
            &successor_catalog,
            &harness.database.migration_role,
            &harness.database.runtime_role,
        )
        .await
        .expect("the successor and timer binding activate atomically");
    apply.release().await.unwrap();
    successor
}

fn successor_worker(
    harness: &TimerOutcomeHarness,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    audit_seed: u8,
) -> RecordTimerWorker {
    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        identity.clone(),
        INSTANCE_ID,
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![audit_seed; 32].into())
                .expect("test owns a keyed successor audit profile"),
        ),
    );
    RecordTimerWorker::new_for_test(
        harness.pool.clone(),
        registry,
        coordinator,
        identity,
        harness.lock_key,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
}

async fn create_outcome_service_for_registry(
    harness: &TimerOutcomeHarness,
    registry: &Arc<registry_breg::CompiledRegistry>,
    identity: &ExpectedRegistryIdentity,
    idempotency_key: &str,
    due_at: chrono::DateTime<Utc>,
) -> registry_breg::mutation::MutationOutcome {
    let claims = ClaimContext::for_compiled(
        registry,
        "service",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("successor ordinary create authority is compiler-bound");
    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        identity.clone(),
        INSTANCE_ID,
        harness.database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x62; 32].into())
                .expect("test owns a keyed successor create audit profile"),
        ),
    );
    let plan = MutationPlan::from_compiled(registry, "records.service.create")
        .expect("successor create route is compiled");
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("pool is available");
    coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &plan,
                idempotency_key,
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("status".to_owned(), json!("reviewed")),
                    (
                        "activatesAt".to_owned(),
                        json!(due_at.to_rfc3339_opts(SecondsFormat::Micros, true)),
                    ),
                    ("note".to_owned(), json!(idempotency_key)),
                ])),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("the successor ordinary create succeeds")
}

#[allow(clippy::too_many_arguments)]
async fn patch_outcome_service_for_registry(
    harness: &TimerOutcomeHarness,
    registry: &Arc<registry_breg::CompiledRegistry>,
    identity: &ExpectedRegistryIdentity,
    record_id: &str,
    idempotency_key: &str,
    operation: PatchOperation,
    audit_seed: u8,
) -> registry_breg::mutation::MutationOutcome {
    try_patch_outcome_service_for_registry(
        harness,
        registry,
        identity,
        record_id,
        idempotency_key,
        operation,
        audit_seed,
    )
    .await
    .unwrap_or_else(|error| {
        panic!("the successor ordinary patch {idempotency_key} succeeds: {error:?}")
    })
}

#[allow(clippy::too_many_arguments)]
async fn try_patch_outcome_service_for_registry(
    harness: &TimerOutcomeHarness,
    registry: &Arc<registry_breg::CompiledRegistry>,
    identity: &ExpectedRegistryIdentity,
    record_id: &str,
    idempotency_key: &str,
    operation: PatchOperation,
    audit_seed: u8,
) -> Result<registry_breg::mutation::MutationOutcome, registry_breg::mutation::MutationError> {
    let claims = ClaimContext::for_compiled(
        registry,
        "service",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("successor ordinary mutation authority is compiler-bound");
    let profile = AuditProfile::production_from_secret_bytes(vec![audit_seed; 32].into())
        .expect("test owns a keyed mutation audit profile");
    let record_revision = record_values(&harness.database, registry, record_id)
        .await
        .2;
    let expected_etag = strong_record_etag_for_test(
        &profile,
        &claims,
        &identity.activation_id,
        record_id,
        record_revision,
        &response_fields(),
    )
    .expect("the successor ETag is bound to the active package and request authority");
    let coordinator = MutationTransaction::new(
        harness.lock_key,
        Duration::from_secs(2),
        identity.clone(),
        INSTANCE_ID,
        harness.database.audit(profile),
    );
    let plan = MutationPlan::from_compiled(registry, "records.service.patch")
        .expect("successor patch route is compiled");
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("pool is available");
    coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &plan,
                idempotency_key,
                claims: &claims,
                record_id: Some(record_id),
                expected_etag: Some(&expected_etag),
                body: MutationBody::Patch(vec![operation]),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
}

async fn encrypted_timer_harness(label: &'static str, audit_seed: u8) -> TimerOutcomeHarness {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_encrypted_current_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs encrypted timer state");
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
    .expect("migration initializes the active encrypted timer package");
    let field_encryption = test_timer_field_encryption_service(
        &migration,
        registry.registry_id(),
        &identity.activation_id,
    )
    .await;
    drop(migration);
    migration_task.abort();
    let pool = database.runtime_config.build_pool().expect("pool builds");
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
    )
    .with_field_encryption(field_encryption);
    let claims = ClaimContext::for_compiled(
        &registry,
        "service",
        Some("timer-test-operator".to_owned()),
        "service-editor",
        Some("service-administration".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("ordinary mutation authority is compiler-bound");
    TimerOutcomeHarness {
        database,
        registry,
        identity,
        pool,
        coordinator,
        claims,
        lock_key,
    }
}

async fn test_timer_field_encryption_service(
    store: &tokio_postgres::Client,
    registry_id: &str,
    package_revision: &str,
) -> Arc<FieldEncryptionService> {
    let root = tempfile::Builder::new()
        .prefix("breg-record-timer-field-dek-")
        .tempdir_in(std::env::temp_dir())
        .expect("field-encryption secret root creates");
    let key_path = root.path().join("field-dek");
    fs::write(&key_path, STANDARD.encode([0x42_u8; 32])).expect("test key writes");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .expect("test key permissions are private");
    let dek_ref =
        SecretReference::parse("secret:file/field-dek").expect("local-file key reference parses");
    let secrets = SecretResolver::new([SecretProvider::File], root.path())
        .expect("local-file secret resolver builds");
    Arc::new(
        FieldEncryptionService::activate(
            &FieldEncryptionProvider::LocalFile { dek_ref },
            registry_id,
            package_revision,
            &secrets,
            store,
        )
        .await
        .expect("governed apply activates local-file key state"),
    )
}

async fn create_outcome_service(
    harness: &TimerOutcomeHarness,
    idempotency_key: &str,
    status: &str,
    due_at: chrono::DateTime<Utc>,
    not_after: Option<chrono::DateTime<Utc>>,
    activation_revision: Option<uuid::Uuid>,
) -> registry_breg::mutation::MutationOutcome {
    let create_plan = MutationPlan::from_compiled(&harness.registry, "records.service.create")
        .expect("create route is compiled");
    let mut data = Map::from_iter([
        ("jurisdiction".to_owned(), json!("zone-a")),
        ("status".to_owned(), json!(status)),
        (
            "activatesAt".to_owned(),
            json!(due_at.to_rfc3339_opts(SecondsFormat::Micros, true)),
        ),
        ("note".to_owned(), json!(idempotency_key)),
    ]);
    if let Some(not_after) = not_after {
        data.insert(
            "activationWindowEnd".to_owned(),
            json!(not_after.to_rfc3339_opts(SecondsFormat::Micros, true)),
        );
    }
    if let Some(revision) = activation_revision {
        data.insert("activationRevision".to_owned(), json!(revision));
    }
    let mut client = harness
        .pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    harness
        .coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &create_plan,
                idempotency_key,
                claims: &harness.claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(data),
                response_fields: response_fields(),
                representation: RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary create arms the outcome-test occurrence")
}

async fn assert_terminal_timer_outcome(
    harness: &TimerOutcomeHarness,
    occurrence_id: uuid::Uuid,
    state: &str,
    executed_attempt_count: i32,
    outcome_code: &str,
) {
    let row = harness
        .database
        .admin
        .query_one(
            "SELECT generation.state,generation.executed_attempt_count,
                    generation.retry_allowance,generation.block_kind,generation.outcome_code,
                    generation.retry_at,generation.claim_owner_id,generation.claim_token,
                    generation.claim_until,generation.completed_at,generation.receipt_correlation,
                    (SELECT count(*)
                       FROM registry_internal.registry_record_timer_attempts AS attempt
                      WHERE attempt.occurrence_id=generation.occurrence_id),
                    (SELECT min(started_at)
                       FROM registry_internal.registry_record_timer_attempts AS attempt
                      WHERE attempt.occurrence_id=generation.occurrence_id),
                    (SELECT max(finished_at)
                       FROM registry_internal.registry_record_timer_attempts AS attempt
                      WHERE attempt.occurrence_id=generation.occurrence_id)
               FROM registry_internal.registry_record_timer_generations AS generation
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("terminal timer outcome is queryable");
    assert_eq!(row.get::<_, String>(0), state);
    assert_eq!(row.get::<_, i32>(1), executed_attempt_count);
    assert_eq!(row.get::<_, i16>(2), 0);
    assert!(row.get::<_, Option<String>>(3).is_none());
    assert_eq!(
        row.get::<_, Option<String>>(4).as_deref(),
        Some(outcome_code)
    );
    assert!(row.get::<_, Option<chrono::DateTime<Utc>>>(5).is_none());
    assert!(row.get::<_, Option<uuid::Uuid>>(6).is_none());
    assert!(row.get::<_, Option<uuid::Uuid>>(7).is_none());
    assert!(row.get::<_, Option<chrono::DateTime<Utc>>>(8).is_none());
    assert!(row.get::<_, Option<chrono::DateTime<Utc>>>(9).is_some());
    if state == "completed" {
        assert!(row.get::<_, Option<uuid::Uuid>>(10).is_some());
    } else {
        assert!(row.get::<_, Option<uuid::Uuid>>(10).is_none());
    }
    assert_eq!(row.get::<_, i64>(11), i64::from(executed_attempt_count));
    let started_at = row.get::<_, Option<chrono::DateTime<Utc>>>(12);
    let finished_at = row.get::<_, Option<chrono::DateTime<Utc>>>(13);
    if executed_attempt_count == 0 {
        assert!(started_at.is_none());
        assert!(finished_at.is_none());
    } else {
        assert!(started_at.is_some());
        assert!(finished_at.is_some());
        assert!(
            started_at <= finished_at,
            "normal-clock attempt timing preserves the database-observed execution interval"
        );
    }
}

fn assert_timer_refusal_audit(database: &TestDatabase) {
    let timer_audit = database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["operationId"] == "timers.service.activate.invoke")
        .collect::<Vec<_>>();
    assert_eq!(
        timer_audit.len(),
        2,
        "outcome has one request and one response"
    );
    assert_eq!(timer_audit[0]["phase"], "request");
    assert_eq!(timer_audit[1]["phase"], "response");
    assert_eq!(timer_audit[1]["record"]["phase"], "refusal");
    database.assert_every_audit_request_answered_once();
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
                      WHERE entity_id = 'service' AND record_id = $1::text::uuid),
                    (SELECT count(*) FROM registry_internal.registry_outbox
                      WHERE entity_id = 'service' AND application_reference IS NOT NULL),
                    (SELECT count(*) FROM registry_internal.registry_idempotency
                      WHERE result_kind = 'immediate_action'),
                    (SELECT count(*) FROM registry_data.\"{table}\"
                      WHERE record_id = $1::text::uuid)"
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

async fn timer_state(database: &TestDatabase, record_id: &str) -> String {
    database
        .admin
        .query_one(
            "SELECT generation.state
               FROM registry_internal.registry_record_timer_current AS current
               JOIN registry_internal.registry_record_timer_generations AS generation
                 ON generation.occurrence_id=current.occurrence_id
              WHERE current.record_type='service' AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("one current generation exists")
        .get(0)
}

async fn timer_gate_open(database: &TestDatabase, record_id: &str) -> bool {
    database
        .admin
        .query_one(
            "SELECT generation.gate_open
               FROM registry_internal.registry_record_timer_current AS current
               JOIN registry_internal.registry_record_timer_generations AS generation
                 ON generation.occurrence_id=current.occurrence_id
              WHERE current.record_type='service' AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("one current generation exists")
        .get(0)
}

async fn set_timer_gate_open_for_fixture(database: &TestDatabase, record_id: &str) {
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_generations AS generation
                SET gate_open=true
               FROM registry_internal.registry_record_timer_current AS current
              WHERE current.record_type='service' AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'
                AND current.occurrence_id=generation.occurrence_id",
            &[&record_id],
        )
        .await
        .expect("fixture opens only the cached eligibility gate");
}

async fn timer_material_signature(database: &TestDatabase, record_id: &str) -> String {
    database
        .admin
        .query_one(
            "SELECT material_signature
               FROM registry_internal.registry_record_timer_current
              WHERE record_type='service' AND record_id=$1::text::uuid AND timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("one current marker exists")
        .get(0)
}

async fn assert_timer_technical_failure(
    harness: &TimerOutcomeHarness,
    occurrence_id: uuid::Uuid,
    technical_code: &str,
) {
    let row = harness
        .database
        .admin
        .query_one(
            "SELECT generation.state,generation.executed_attempt_count,generation.retry_at,
                    attempt.technical_code
               FROM registry_internal.registry_record_timer_generations AS generation
               JOIN registry_internal.registry_record_timer_attempts AS attempt
                 ON attempt.occurrence_id=generation.occurrence_id
              WHERE generation.occurrence_id=$1 AND attempt.attempt_number=1",
            &[&occurrence_id],
        )
        .await
        .expect("technical timer attempt is retained");
    assert_eq!(row.get::<_, String>(0), "pending");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert!(row.get::<_, Option<chrono::DateTime<Utc>>>(2).is_some());
    assert_eq!(
        row.get::<_, Option<String>>(3).as_deref(),
        Some(technical_code)
    );
}

async fn assert_timer_metadata_excludes_plaintext_canaries(
    database: &TestDatabase,
    operator_output: &str,
    operational_logs: &str,
    canaries: &[&str],
) {
    let rendered: String = database
        .admin
        .query_one(
            "SELECT jsonb_build_object(
                    'current',(SELECT COALESCE(jsonb_agg(to_jsonb(current)),'[]'::jsonb)
                                 FROM registry_internal.registry_record_timer_current AS current),
                    'generations',(SELECT COALESCE(jsonb_agg(to_jsonb(generation)),'[]'::jsonb)
                                     FROM registry_internal.registry_record_timer_generations AS generation),
                    'attempts',(SELECT COALESCE(jsonb_agg(to_jsonb(attempt)),'[]'::jsonb)
                                  FROM registry_internal.registry_record_timer_attempts AS attempt),
                    'bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(binding)),'[]'::jsonb)
                                  FROM registry_internal.registry_record_timer_bindings AS binding),
                    'control',(SELECT COALESCE(jsonb_agg(to_jsonb(control)),'[]'::jsonb)
                                 FROM registry_internal.registry_record_timer_control AS control)
                 )::text",
            &[],
        )
        .await
        .expect("the value-free timer ledger is queryable")
        .get(0);
    let audit = serde_json::to_string(&database.audit_entries())
        .expect("captured timer audit entries serialize");
    for canary in canaries {
        assert!(
            !rendered.contains(canary),
            "timer metadata disclosed an encrypted plaintext canary"
        );
        assert!(
            !audit.contains(canary),
            "timer audit disclosed an encrypted plaintext canary"
        );
        assert!(
            !operator_output.contains(canary),
            "timer operator projection disclosed an encrypted plaintext canary"
        );
        assert!(
            !operational_logs.contains(canary),
            "timer operational logs disclosed an encrypted plaintext canary"
        );
    }
}

async fn timer_occurrence(database: &TestDatabase, record_id: &str) -> uuid::Uuid {
    database
        .admin
        .query_one(
            "SELECT occurrence_id FROM registry_internal.registry_record_timer_current
              WHERE record_type='service' AND record_id=$1::text::uuid AND timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("one current generation exists")
        .get(0)
}

async fn generation_definition_revision(
    database: &TestDatabase,
    occurrence_id: uuid::Uuid,
) -> String {
    database
        .admin
        .query_one(
            "SELECT definition_revision
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the generation revision is queryable")
        .get(0)
}

async fn generation_definition_revision_via_pool(
    pool: &RuntimePool,
    occurrence_id: uuid::Uuid,
) -> String {
    pool.get_for_test()
        .await
        .expect("the runtime connection is available")
        .query_one(
            "SELECT definition_revision
               FROM registry_internal.registry_record_timer_generations
              WHERE occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("the generation revision is queryable through the runtime role")
        .get(0)
}

async fn timer_claim_is_clear(database: &TestDatabase, record_id: &str) -> bool {
    let row = database
        .admin
        .query_one(
            "SELECT claim_token IS NULL, claim_until IS NULL,
                    claimed_control_epoch IS NULL, claimed_instance_epoch IS NULL
               FROM registry_internal.registry_record_timer_current AS current
               JOIN registry_internal.registry_record_timer_generations AS generation
                 ON generation.occurrence_id=current.occurrence_id
              WHERE current.record_type='service' AND current.record_id=$1::text::uuid
                AND current.timer_id='activate'",
            &[&record_id],
        )
        .await
        .expect("held generation remains present");
    row.get::<_, bool>(0) && row.get::<_, bool>(1) && row.get::<_, bool>(2) && row.get::<_, bool>(3)
}

async fn record_values(
    database: &TestDatabase,
    registry: &registry_breg::CompiledRegistry,
    record_id: &str,
) -> (String, String, i64) {
    let entity = &registry.entities()["service"];
    let status = &entity.fields["status"].physical_name;
    let note = &entity.fields["note"].physical_name;
    database
        .admin
        .query_one(
            &format!(
                "SELECT \"{status}\", \"{note}\", record_revision
                   FROM registry_data.\"{}\" WHERE record_id = $1::text::uuid",
                entity.physical_table
            ),
            &[&record_id],
        )
        .await
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .expect("record is readable")
}

fn response_fields() -> BTreeSet<String> {
    BTreeSet::from([
        "jurisdiction".to_owned(),
        "status".to_owned(),
        "activates-at".to_owned(),
        "note".to_owned(),
    ])
}

fn response_id(outcome: &registry_breg::mutation::MutationOutcome) -> String {
    let body: Value = serde_json::from_slice(outcome.response().body()).unwrap();
    body["data"]["recordIdentifier"]
        .as_str()
        .expect("response contains record id")
        .to_owned()
}

fn response_etag(outcome: &registry_breg::mutation::MutationOutcome) -> String {
    String::from_utf8(outcome.response().headers()[&PermittedResponseHeader::Etag].clone())
        .expect("etag is UTF-8")
}

#[allow(clippy::too_many_arguments)]
fn timer_patch_context(
    registry: &registry_breg::CompiledRegistry,
    identity: &ExpectedRegistryIdentity,
    occurrence_id: uuid::Uuid,
    anchor_record_id: uuid::Uuid,
    target_record_id: uuid::Uuid,
    claim_token: uuid::Uuid,
    claim_owner_id: uuid::Uuid,
    claim_epoch: i64,
    control_epoch: i64,
    instance_epoch: i64,
    activation_id: uuid::Uuid,
    expected_revision: i64,
) -> String {
    let timer = &registry.entities()["service"].timers["activate"];
    let context = json!({
        "version":1,
        "actorKind":"system",
        "systemActor":"record-timer",
        "timerId":timer.id,
        "occurrenceId":occurrence_id,
        "anchorRecordId":anchor_record_id,
        "claimToken":claim_token,
        "claimOwnerId":claim_owner_id,
        "claimEpoch":claim_epoch,
        "controlEpoch":control_epoch,
        "instanceEpoch":instance_epoch,
        "activationId":activation_id,
        "systemGrantRevision":timer.system_grant.revision,
        "actionId":timer.invoke,
        "contractFingerprint":timer.action_revision,
        "activePackageRevision":identity.activation_id,
        "selectedAccessProfile":"system-record-timer",
        "principal":"urn:registrystack:breg:system:record-timer",
        "purpose":null,
        "effectIds":["activated"],
        "applicationId":occurrence_id,
        "targetEntityId":"service",
        "targetRecordId":target_record_id,
        "operation":"patch",
        "fields":["status"],
        "expectedRevision":expected_revision,
        "lockOnly":false,
        "targetRowBoundaries":[]
    });
    String::from_utf8(canonicalize_json(&context).unwrap()).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn timer_create_context(
    identity: &ExpectedRegistryIdentity,
    timer: &registry_breg::model::CompiledTimer,
    occurrence_id: uuid::Uuid,
    anchor_record_id: uuid::Uuid,
    target_record_id: uuid::Uuid,
    claim_token: uuid::Uuid,
    claim_owner_id: uuid::Uuid,
    claim_epoch: i64,
    control_epoch: i64,
    instance_epoch: i64,
    activation_id: uuid::Uuid,
) -> String {
    let context = json!({
        "version":1,
        "actorKind":"system",
        "systemActor":"record-timer",
        "timerId":timer.id,
        "occurrenceId":occurrence_id,
        "anchorRecordId":anchor_record_id,
        "claimToken":claim_token,
        "claimOwnerId":claim_owner_id,
        "claimEpoch":claim_epoch,
        "controlEpoch":control_epoch,
        "instanceEpoch":instance_epoch,
        "activationId":activation_id,
        "systemGrantRevision":timer.system_grant.revision,
        "actionId":timer.invoke,
        "contractFingerprint":timer.action_revision,
        "activePackageRevision":identity.activation_id,
        "selectedAccessProfile":"system-record-timer",
        "principal":"urn:registrystack:breg:system:record-timer",
        "purpose":null,
        "effectIds":["activation-log"],
        "applicationId":occurrence_id,
        "targetEntityId":"activation-log",
        "targetRecordId":target_record_id,
        "operation":"create",
        "fields":["activation-number","operation-id","planned-at"],
        "expectedRevision":null,
        "lockOnly":false,
        "targetRowBoundaries":[]
    });
    String::from_utf8(canonicalize_json(&context).unwrap()).unwrap()
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    compile_registry(timer_project_source())
}

fn compiled_changed_predicate_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["timers"][0]["when"] =
        json!({"type":"fields","equals":{"status":"reviewed"}});
    compile_registry(source)
}

fn compiled_nullable_timer_at_registry(use_successor_at: bool) -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .expect("service fields are an array")
        .push(json!({
            "id":"successor-at","type":"timestamp","classification":"internal"
        }));
    for access_key in ["readableFields", "writableFields"] {
        source["accessProfiles"][0]["permissions"]["records"][0][access_key]
            .as_array_mut()
            .expect("service access fields are an array")
            .push(json!("successor-at"));
    }
    if use_successor_at {
        source["recordTypes"][0]["timers"][0]["at"] = json!("successor-at");
    }
    compile_registry(source)
}

fn compiled_no_window_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["timers"][0]
        .as_object_mut()
        .expect("timer fixture is an object")
        .remove("notAfter");
    compile_registry(source)
}

fn compiled_timer_free_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]
        .as_object_mut()
        .expect("service fixture is an object")
        .remove("timers");
    source["timerGrants"] = json!([]);
    source["actions"] = json!([]);
    compile_registry(source)
}

fn timer_project_source() -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{"id":PACKAGE_ID,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://timers.example.test"},
        "datasets":[{"id":"services"}],
        "recordTypes":[{
            "id":"service","primaryDataset":"services","route":"services","mutationMode":"mutable",
            "fields":[
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"status","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"activates-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"activation-window-end","type":"timestamp","classification":"internal"},
                {"id":"activation-revision","type":"uuid","classification":"internal"},
                {"id":"note","type":"string","required":true,"maximumLength":128,"classification":"internal"}
            ],
            "timers":[{
                "id":"activate","at":"activates-at","notAfter":"activation-window-end","rearmOn":"activation-revision",
                "when":{"type":"fields","equals":{"status":"scheduled"}},
                "invoke":"activate-service",
                "input":{
                    "service":{"fromRecordId":true},
                    "planned-at":{"fromField":"activates-at"},
                    "operation-id":{"fromTimer":"occurrence-id"}
                }
            }],
            "hooks":[{"phase":"after","id":"service-patched","trigger":"patched","projection":["status","note"],
                "when":{"type":"fields","afterEquals":{"status":"active"}}}]
        }],
        "timerGrants":[{"recordType":"service","timer":"activate"}],
        "actions":[{
            "id":"activate-service","execution":{"mode":"immediate"},
            "inputs":[
                {"id":"service","type":"reference","target":"service","required":true,"classification":"internal"},
                {"id":"planned-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
            ],
            "plan":{"type":"fixed","effects":[{
                "id":"activated","target":{"fromInput":"service"},"operation":"patch","set":{"status":{"value":"active"}}
            }]}
        }],
        "accessProfiles":[{
            "id":"service-editor","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
            "requiredPurposes":["service-administration"],
            "permissions":{"records":[{
                "recordType":"service","operations":["create","get","patch"],
                "readableFields":["jurisdiction","status","activates-at","activation-window-end","activation-revision","note"],
                "writableFields":["jurisdiction","status","activates-at","activation-window-end","activation-revision","note"],
                "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
        }]
    })
}

fn compile_registry(source: Value) -> registry_breg::CompiledRegistry {
    let bytes = serde_json::to_vec(&source).expect("fixture serializes");
    let project = parse_project_json(&bytes).expect("timer fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("timer fixture compiles to a bounded action and timer grant")
}

fn compiled_create_only_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["datasets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"activation-logs"}));
    source["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"activation-log","primaryDataset":"activation-logs","route":"activation-logs","mutationMode":"mutable",
            "fields":[
                {"id":"activation-number","type":"string","minimumLength":8,"maximumLength":32,"required":true,"classification":"internal",
                 "generate":{"type":"sequence","prefix":"ACT-","minimumDigits":4}},
                {"id":"planned-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
            ],
            "hooks":[{"phase":"after","id":"activation-log-created","trigger":"created",
                "projection":["activation-number","operation-id"]}]
        }));
    source["recordTypes"][0]["timers"][0]["input"] = json!({
        "planned-at":{"fromField":"activates-at"},
        "operation-id":{"fromTimer":"occurrence-id"}
    });
    source["actions"][0]["inputs"] = json!([
        {"id":"planned-at","type":"timestamp","required":true,"classification":"internal"},
        {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
    ]);
    source["actions"][0]["plan"] = json!({"type":"fixed","effects":[{
        "id":"activation-log","target":{"recordType":"activation-log"},"operation":"create",
        "set":{
            "planned-at":{"fromInput":"planned-at"},
            "operation-id":{"fromInput":"operation-id"}
        }
    }]});
    compile_registry(source)
}

fn compiled_two_anchor_patch_effects_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["actions"][0]["plan"]["effects"] = json!([
        {
            "id":"activate-status",
            "target":{"fromInput":"service"},
            "operation":"patch",
            "set":{"status":{"value":"active"}}
        },
        {
            "id":"activation-note",
            "target":{"fromInput":"service"},
            "operation":"patch",
            "set":{"note":{"value":"activated by two effects"}}
        }
    ]);
    compile_registry(source)
}

fn compiled_secondary_get_registry() -> registry_breg::CompiledRegistry {
    compiled_secondary_get_registry_for("approval")
}

fn compiled_secondary_get_registry_for(mapping_field: &str) -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval","primaryDataset":"services","route":"approvals","mutationMode":"mutable",
            "fields":[
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"status","type":"string","required":true,"maximumLength":32,"classification":"internal"}
            ]
        }));
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval","type":"reference","target":"approval","required":true,
            "classification":"internal"
        }));
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"backup-approval","type":"reference","target":"approval",
            "classification":"internal"
        }));
    source["recordTypes"][0]["timers"][0]["input"]["approval"] = json!({"fromField":mapping_field});
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("approval"));
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("backup-approval"));
    source["accessProfiles"][0]["permissions"]["records"][0]["writableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("approval"));
    source["accessProfiles"][0]["permissions"]["records"][0]["writableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("backup-approval"));
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval","type":"reference","target":"approval","required":true,
            "classification":"internal"
        }));
    source["actions"][0]["commitGuards"] = json!({
        "targets":[{"input":"approval","field":"status","equals":"approved"}]
    });
    source["accessProfiles"][0]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "recordType":"approval","operations":["create","get","patch"],
            "readableFields":["jurisdiction","status"],
            "writableFields":["jurisdiction","status"],
            "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
        }));
    compile_registry(source)
}

fn compiled_missing_literal_secondary_get_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval","primaryDataset":"services","route":"approvals","mutationMode":"mutable",
            "fields":[
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"status","type":"string","required":true,"maximumLength":32,"classification":"internal"}
            ]
        }));
    source["recordTypes"][0]["timers"][0]["input"]["approval"] =
        json!({"value":"00000000-0000-0000-0000-000000000404"});
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval","type":"reference","target":"approval","required":true,
            "classification":"internal"
        }));
    source["actions"][0]["commitGuards"] = json!({
        "targets":[{"input":"approval","field":"status","equals":"approved"}]
    });
    source["accessProfiles"][0]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "recordType":"approval","operations":["get"],
            "readableFields":["jurisdiction","status"],
            "writableFields":[],
            "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
        }));
    compile_registry(source)
}

fn compiled_existence_only_secondary_get_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval","primaryDataset":"services","route":"approvals","mutationMode":"mutable",
            "fields":[
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"status","type":"string","required":true,"maximumLength":32,"classification":"internal"}
            ]
        }));
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval","type":"reference","target":"approval","required":true,
            "classification":"internal"
        }));
    source["recordTypes"][0]["timers"][0]["input"]["approval"] = json!({"fromField":"approval"});
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("approval"));
    source["accessProfiles"][0]["permissions"]["records"][0]["writableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("approval"));
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval","type":"reference","target":"approval","required":true,
            "classification":"internal"
        }));
    source["accessProfiles"][0]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "recordType":"approval","operations":["create","get"],
            "readableFields":["jurisdiction","status"],
            "writableFields":["jurisdiction","status"],
            "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
        }));
    compile_registry(source)
}

fn compiled_same_type_get_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"related-service","type":"reference","target":"service",
            "classification":"internal"
        }));
    source["recordTypes"][0]["timers"][0]["input"]["related-service"] =
        json!({"fromField":"related-service"});
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("related-service"));
    source["accessProfiles"][0]["permissions"]["records"][0]["writableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("related-service"));
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"related-service","type":"reference","target":"service","required":true,
            "classification":"internal"
        }));
    source["actions"][0]["commitGuards"] = json!({
        "targets":[{"input":"related-service","field":"status","equals":"approved"}]
    });
    compile_registry(source)
}

fn compiled_encrypted_current_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["hooks"] = json!([]);
    source["recordTypes"][0]["fields"][1]["encrypted"] = json!(true);
    source["recordTypes"][0]["fields"][1]["classification"] = json!("restricted");
    source["recordTypes"][0]["fields"][5]["encrypted"] = json!(true);
    source["recordTypes"][0]["fields"][5]["classification"] = json!("restricted");
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"copied-note","type":"string","maximumLength":128,
            "classification":"internal"
        }));
    source["recordTypes"][0]["timers"][0]["input"]["current-note"] = json!({"fromField":"note"});
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"current-note","type":"string","maximumLength":128,"required":true,
            "classification":"internal"
        }));
    source["actions"][0]["plan"]["effects"][0]["set"]["copied-note"] =
        json!({"fromInput":"current-note"});
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("copied-note"));
    source["accessProfiles"][0]["permissions"]["records"][0]["writableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("copied-note"));
    compile_registry(source)
}

fn compiled_int64_rearm_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["fields"][4]["type"] = json!("int64");
    compile_registry(source)
}

fn compiled_self_clearing_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["fields"][2]
        .as_object_mut()
        .expect("the activates-at field is an object")
        .remove("required");
    source["actions"][0]["plan"] = json!({"type":"fixed","effects":[{
        "id":"activated","target":{"fromInput":"service"},"operation":"patch",
        "set":{"status":{"value":"active"}},"clear":["activates-at"]
    }]});
    compile_registry(source)
}

fn compiled_self_rearming_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["actions"][0]["plan"] = json!({"type":"fixed","effects":[{
        "id":"activated","target":{"fromInput":"service"},"operation":"patch",
        "set":{
            "status":{"value":"active"},
            "activation-revision":{"fromInput":"operation-id"}
        }
    }]});
    compile_registry(source)
}

fn compiled_terminal_lifecycle_registry(
    successor_predicate: bool,
) -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["fields"][2]
        .as_object_mut()
        .expect("the activates-at field is an object")
        .remove("required");
    source["actions"][0]["commitGuards"] = json!({"targets":[{
        "input":"service","field":"note","equals":"allow"
    }]});
    if successor_predicate {
        source["recordTypes"][0]["timers"][0]["when"] =
            json!({"type":"fields","equals":{"status":"reviewed"}});
    }
    compile_registry(source)
}

fn compiled_illegal_proposal_required_timer_registry() -> registry_breg::CompiledRegistry {
    let registry = compile_registry(timer_project_source());
    let mut compiled =
        serde_json::to_value(registry).expect("the legal compiled timer fixture serializes");
    compiled["entities"]["service"]["changeControl"] = json!({"requiredFor":["patch"]});
    serde_json::from_value(compiled)
        .expect("the deliberately illegal compiled fixture injects Proposal-required Patch policy")
}

fn compiled_cross_timer_rearming_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .expect("service fields are an array")
        .push(json!({
            "id":"followup-at","type":"timestamp","classification":"internal"
        }));
    for access_key in ["readableFields", "writableFields"] {
        source["accessProfiles"][0]["permissions"]["records"][0][access_key]
            .as_array_mut()
            .expect("service access fields are an array")
            .push(json!("followup-at"));
    }
    source["recordTypes"][0]["timers"]
        .as_array_mut()
        .expect("service timers are an array")
        .push(json!({
            "id":"activate-followup","at":"followup-at",
            "when":{"type":"fields","equals":{"status":"active"}},
            "invoke":"activate-service",
            "input":{
                "service":{"fromRecordId":true},
                "planned-at":{"fromField":"followup-at"},
                "operation-id":{"fromTimer":"occurrence-id"}
            }
        }));
    source["timerGrants"]
        .as_array_mut()
        .expect("timer grants are an array")
        .push(json!({"recordType":"service","timer":"activate-followup"}));
    source["actions"][0]["plan"]["effects"][0]["set"]["followup-at"] =
        json!({"fromInput":"planned-at"});
    compile_registry(source)
}

fn compiled_created_record_timer_rearming_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["datasets"]
        .as_array_mut()
        .expect("datasets are an array")
        .push(json!({"id":"activation-tasks"}));
    source["recordTypes"]
        .as_array_mut()
        .expect("record types are an array")
        .push(json!({
            "id":"activation-task","primaryDataset":"activation-tasks",
            "route":"activation-tasks","mutationMode":"mutable",
            "fields":[
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"task-number","type":"string","minimumLength":9,"maximumLength":32,"required":true,"classification":"internal",
                 "generate":{"type":"sequence","prefix":"TASK-","minimumDigits":4}},
                {"id":"status","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"activates-at","type":"timestamp","required":true,"classification":"internal"}
            ],
            "timers":[{
                "id":"dispatch","at":"activates-at",
                "when":{"type":"fields","equals":{"status":"scheduled"}},
                "invoke":"dispatch-task",
                "input":{
                    "task":{"fromRecordId":true},
                    "operation-id":{"fromTimer":"occurrence-id"}
                }
            }],
            "hooks":[{"phase":"after","id":"activation-task-created","trigger":"created",
                "projection":["task-number","status"]}]
        }));
    source["timerGrants"]
        .as_array_mut()
        .expect("timer grants are an array")
        .push(json!({"recordType":"activation-task","timer":"dispatch"}));
    source["actions"]
        .as_array_mut()
        .expect("actions are an array")
        .push(json!({
            "id":"dispatch-task","execution":{"mode":"immediate"},
            "inputs":[
                {"id":"task","type":"reference","target":"activation-task","required":true,"classification":"internal"},
                {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
            ],
            "plan":{"type":"fixed","effects":[{
                "id":"dispatched","target":{"fromInput":"task"},"operation":"patch",
                "set":{"status":{"value":"active"}}
            }]}
        }));
    source["actions"][0]["plan"]["effects"] = json!([
        {
            "id":"activated","target":{"fromInput":"service"},"operation":"patch",
            "set":{"status":{"value":"active"}}
        },
        {
            "id":"activation-task","target":{"recordType":"activation-task"},
            "operation":"create",
            "set":{
                "jurisdiction":{"value":"zone-a"},
                "status":{"value":"scheduled"},
                "activates-at":{"fromInput":"planned-at"}
            }
        }
    ]);
    source["accessProfiles"][0]["permissions"]["records"]
        .as_array_mut()
        .expect("profile record permissions are an array")
        .push(json!({
            "recordType":"activation-task","operations":["create","get","patch"],
            "readableFields":["jurisdiction","task-number","status","activates-at"],
            "writableFields":["jurisdiction","status","activates-at"],
            "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
        }));
    compile_registry(source)
}

fn compiled_timer_and_timer_free_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    source["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"case-note","primaryDataset":"services","route":"case-notes","mutationMode":"mutable",
            "fields":[
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":32,"classification":"internal"},
                {"id":"body","type":"string","required":true,"maximumLength":128,"classification":"internal"}
            ]
        }));
    source["accessProfiles"][0]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "recordType":"case-note","operations":["create","get","patch"],
            "readableFields":["jurisdiction","body"],
            "writableFields":["jurisdiction","body"],
            "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
        }));
    compile_registry(source)
}

fn compiled_same_entity_timer_registry() -> registry_breg::CompiledRegistry {
    let mut source = timer_project_source();
    let mut second = source["recordTypes"][0]["timers"][0].clone();
    second["id"] = json!("activate-followup");
    source["recordTypes"][0]["timers"]
        .as_array_mut()
        .unwrap()
        .push(second);
    source["timerGrants"]
        .as_array_mut()
        .unwrap()
        .push(json!({"recordType":"service","timer":"activate-followup"}));
    compile_registry(source)
}
