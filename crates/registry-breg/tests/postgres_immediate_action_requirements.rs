// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "support/action_requirements.rs"]
mod support;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use postgres_harness::TestDatabase;
use registry_breg::{
    api::{
        router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
        VerifiedClaimValue, VerifiedRequestClaims,
    },
    compiler::{compile_project, CompileProfile},
    contract::parse_project_json,
    cursor::CursorCodec,
    mutation::MutationFaultPoint,
    postgres::{
        initialize_registry_state_for_catalog_test, install_compiled_schema,
        ExpectedManagedCatalog, ExpectedRegistryIdentity, PostgresRecordMutationService,
        PostgresRecordReadService, RegistryLockKey, RegistryStateTestIdentity,
    },
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const ID: &str = "00000000-0000-4000-8000-000000000101";
const PACKAGE: &str = "action-requirements";

async fn setup() -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    let database = TestDatabase::create(8).await;
    let registry = Arc::new(
        compile_project(
            &parse_project_json(&serde_json::to_vec(&support::project()).unwrap()).unwrap(),
            &[],
            CompileProfile::Authoring,
        )
        .unwrap(),
    );
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            environment: "local",
            instance_id: "requirements-instance",
            database_id: "requirements-database",
            package_revision: "requirements-1",
            package_sequence: 1,
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();
    let parent = &registry.entities()["parent"];
    database.admin.execute(&format!("INSERT INTO registry_data.{} (record_id, record_revision, record_lifecycle, active_package_revision, {}, {}) VALUES ($1, 1, 'active', $2, 'active', 'zone-a')", q(&parent.physical_table), q(&parent.fields["status"].physical_name), q(&parent.fields["zone"].physical_name)), &[&Uuid::parse_str(ID).unwrap(), &identity.package_revision]).await.unwrap();
    (database, registry, identity)
}

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn app(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    fault: Option<MutationFaultPoint>,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().unwrap();
    let audit = AuditProfile::production_from_secret_bytes(vec![0x42; 32].into()).unwrap();
    let lock = RegistryLockKey::derive(PACKAGE).unwrap();
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300)).unwrap(),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        Duration::from_secs(5),
        audit.clone(),
        cursors.clone(),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity,
        lock,
        Duration::from_secs(5),
        audit,
    );
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    router(Arc::new(
        HttpService::new(registry, read_identity, reads, Arc::new(Ready), cursors)
            .with_postgres_mutations(Arc::new(mutations)),
    ))
}

async fn invoke(mut app: axum::Router, key: &str, parent: &str) -> (StatusCode, Value) {
    let claims = VerifiedRequestClaims::authenticated(
        "registry_principal",
        "registrar",
        BTreeSet::from([
            "registry:register".to_owned(),
            "registry:parent:process".to_owned(),
        ]),
        None,
        BTreeMap::from([(
            "zone".to_owned(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap();
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/actions/register-child")
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(
            serde_json::to_vec(&json!({"input": {"parentId": parent, "label": "synthetic"}}))
                .unwrap(),
        ))
        .unwrap();
    request.extensions_mut().insert(claims);
    let response = app.call(request).await.unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap();
    (status, body)
}

fn status_sql(registry: &registry_breg::CompiledRegistry) -> String {
    let parent = &registry.entities()["parent"];
    format!("UPDATE registry_data.{} SET {} = $1, record_revision = record_revision + 1 WHERE record_id = $2", q(&parent.physical_table), q(&parent.fields["status"].physical_name))
}

async fn counts(database: &TestDatabase, registry: &registry_breg::CompiledRegistry) -> Vec<i64> {
    let row = database.admin.query_one(&format!("SELECT (SELECT count(*) FROM registry_data.{}), (SELECT count(*) FROM registry_internal.registry_revisions), (SELECT count(*) FROM registry_internal.registry_outbox), (SELECT count(*) FROM registry_internal.registry_idempotency), (SELECT count(*) FROM registry_internal.registry_immediate_action_applications), (SELECT count(*) FROM registry_internal.registry_immediate_action_results)", q(&registry.entities()["child"].physical_table)), &[]).await.unwrap();
    (0..6).map(|index| row.get(index)).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_requirements_are_acceptance_only_atomic_and_replayable() {
    let (database, registry, identity) = setup().await;
    let app = app(&database, registry.clone(), identity, None);
    let accepted = invoke(app.clone(), "accepted", ID).await;
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    assert!(accepted.1.get("status").is_none());
    let after = counts(&database, &registry).await;
    assert!(after.iter().all(|count| *count == 1), "{after:?}");
    database
        .admin
        .execute(
            &status_sql(&registry),
            &[&"inactive", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let replay = invoke(app.clone(), "accepted", ID).await;
    assert_eq!(
        accepted, replay,
        "replay recovers the accepted result without requiring a still-active parent"
    );
    let inactive = invoke(app.clone(), "inactive", ID).await;
    assert_eq!(
        inactive.0,
        StatusCode::PRECONDITION_FAILED,
        "{}",
        inactive.1
    );
    assert!(!inactive.1.to_string().contains("inactive"));
    let missing = invoke(
        app.clone(),
        "missing",
        "00000000-0000-4000-8000-000000000999",
    )
    .await;
    assert_eq!(missing.0, inactive.0);
    assert_eq!(missing.1["code"], inactive.1["code"]);
    assert_eq!(after, counts(&database, &registry).await);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_requirements_hold_reference_lock_against_concurrent_inactivation() {
    let (mut database, registry, identity) = setup().await;
    let app = app(&database, registry.clone(), identity, None);
    // Inactivation takes the row first. Invocation must wait and inspect its committed value.
    let transaction = database.admin.transaction().await.unwrap();
    transaction
        .execute(
            &status_sql(&registry),
            &[&"inactive", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    let pending = tokio::spawn(invoke(app.clone(), "inactivation-first", ID));
    wait_for_lock(
        &transaction,
        database.runtime_role.as_str(),
        "transactionid",
    )
    .await;
    transaction.commit().await.unwrap();
    let refused = pending.await.unwrap();
    assert_eq!(refused.0, StatusCode::PRECONDITION_FAILED, "{}", refused.1);
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database
        .admin
        .execute(
            &status_sql(&registry),
            &[&"active", &Uuid::parse_str(ID).unwrap()],
        )
        .await
        .unwrap();
    // Invocation takes the row first. Pause before INSERT, after the requirement was checked.
    let child = &registry.entities()["child"];
    database.admin.batch_execute(&format!("CREATE FUNCTION registry_internal.pause_required_action() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(819274); RETURN NEW; END; $$; CREATE TRIGGER pause_required_action BEFORE INSERT ON registry_data.{} FOR EACH ROW EXECUTE FUNCTION registry_internal.pause_required_action();", q(&child.physical_table))).await.unwrap();
    database
        .admin
        .query_one("SELECT pg_advisory_lock(819274)", &[])
        .await
        .unwrap();
    let pending = tokio::spawn(invoke(app, "invocation-first", ID));
    wait_for_lock(&database.admin, database.runtime_role.as_str(), "advisory").await;
    let database_name: String = database
        .admin
        .query_one("SELECT current_database()", &[])
        .await
        .unwrap()
        .get(0);
    let mut writer_config: tokio_postgres::Config = std::env::var("BREG_TEST_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    writer_config
        .dbname(&database_name)
        .application_name("required-action-competing-writer");
    let (writer, connection) = writer_config.connect(tokio_postgres::NoTls).await.unwrap();
    let writer_task = tokio::spawn(async move { connection.await.unwrap() });
    let sql = status_sql(&registry);
    let write = tokio::spawn(async move {
        writer
            .execute(&sql, &[&"inactive", &Uuid::parse_str(ID).unwrap()])
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: bool = database.admin.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = 'required-action-competing-writer' AND wait_event_type = 'Lock')", &[]).await.unwrap().get(0);
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("inactivation waits for the invocation's reference lock");
    database
        .admin
        .query_one("SELECT pg_advisory_unlock(819274)", &[])
        .await
        .unwrap();
    let accepted = pending.await.unwrap();
    assert_eq!(accepted.0, StatusCode::OK, "{}", accepted.1);
    assert_eq!(write.await.unwrap().unwrap(), 1);
    writer_task.abort();
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 1));
    database.cleanup().await;
}

async fn wait_for_lock(
    client: &(impl tokio_postgres::GenericClient + Sync),
    role: &str,
    event: &str,
) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            client.query_one("SELECT pg_stat_clear_snapshot()", &[]).await.unwrap();
            let waiting: bool = client.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename = $1 AND wait_event_type = 'Lock' AND lower(wait_event) = $2)", &[&role, &event]).await.unwrap().get(0);
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("competing transaction reached expected lock before proceeding");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_requirements_preserve_fault_rollback() {
    let (database, registry, identity) = setup().await;
    let app = app(
        &database,
        registry.clone(),
        identity,
        Some(MutationFaultPoint::BeforeOutbox),
    );
    let refused = invoke(app, "fault", ID).await;
    assert!(!refused.0.is_success());
    assert!(counts(&database, &registry)
        .await
        .iter()
        .all(|count| *count == 0));
    database.cleanup().await;
}

fn q(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
