// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

#[path = "support/postgres_harness.rs"]
mod postgres_harness;

use std::time::Duration;

use postgres_harness::TestDatabase;
use registry_breg::postgres::{
    begin_record_transaction, initialize_kernel_registry_state_for_test, install_kernel_schema,
    verify_btree_gist, verify_catalog_identity, verify_migration_role, verify_runtime_role,
    ClaimContext, DedicatedApplyConnection, ExpectedRegistryIdentity, PostgresKernelError,
    RegistryLockKey, RegistryStateTestIdentity,
};

const RECORD_ALPHA: &str = "00000000-0000-0000-0000-000000000001";
const PACKAGE_ID: &str = "kernel-registry";
const INSTANCE_ID: &str = "kernel-instance";
const DATABASE_ID: &str = "kernel-database";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_kernel_proves_roles_rls_interlock_and_pool_isolation() {
    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;

    let missing_extension = verify_btree_gist(&migration).await;
    assert!(matches!(
        missing_extension,
        Err(PostgresKernelError::CatalogInvariant(_))
    ));
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the declared prerequisite");
    verify_btree_gist(&migration)
        .await
        .expect("migration preflight sees administrator-installed btree_gist");
    verify_migration_role(&migration, &database.migration_role)
        .await
        .expect("migration role owns schemas without administrative database authority");
    install_kernel_schema(&migration, &database.runtime_role)
        .await
        .expect("migration role installs managed kernel objects");
    let initial = initialize_kernel_registry_state_for_test(
        &migration,
        &database.runtime_role,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "package-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("migration role initializes exact Registry identity");
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded verified-recycling pool builds");
    let server_tls: String = database
        .admin
        .query_one("SHOW ssl", &[])
        .await
        .expect("test server reports its TLS posture")
        .get(0);
    assert_eq!(server_tls, "off", "the pinned test service is plaintext");
    let tls_pool = database
        .tls_runtime_config
        .build_pool()
        .expect("strict TLS pool configuration builds");
    assert!(
        tls_pool.get_for_test().await.is_err(),
        "required TLS must not downgrade against a plaintext server"
    );
    let runtime = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    verify_runtime_role(&**runtime, &database.migration_role)
        .await
        .expect("runtime role has no ownership, bypass, or DDL authority");
    assert!(runtime
        .batch_execute("CREATE TABLE registry_data.forbidden (id integer)")
        .await
        .is_err());
    assert!(runtime
        .batch_execute("CREATE EXTENSION hstore")
        .await
        .is_err());
    assert!(runtime
        .batch_execute("UPDATE registry_internal.registry_state SET maintenance_status = 'failed'")
        .await
        .is_err());
    verify_catalog_identity(
        &**runtime,
        &initial,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("runtime verifies exact package and catalog identity");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_data TO \"{}\";\n\
             GRANT SELECT ON registry_data.kernel_records TO \"{}\";",
            database.intruder_role.as_str(),
            database.intruder_role.as_str(),
        ))
        .await
        .expect("test administrator can seed unexpected ACL drift");
    let acl_drift = verify_catalog_identity(
        &**runtime,
        &initial,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert!(matches!(
        acl_drift,
        Err(PostgresKernelError::CatalogInvariant(_))
            | Err(PostgresKernelError::RegistryUnavailable)
    ));
    database
        .admin
        .batch_execute(&format!(
            "REVOKE SELECT ON registry_data.kernel_records FROM \"{}\";\n\
             REVOKE USAGE ON SCHEMA registry_data FROM \"{}\";",
            database.intruder_role.as_str(),
            database.intruder_role.as_str(),
        ))
        .await
        .expect("test administrator can remove seeded ACL drift");
    verify_catalog_identity(
        &**runtime,
        &initial,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("exact ACL restoration returns the catalog to its package identity");

    let invisible: i64 = runtime
        .query_one("SELECT count(*) FROM registry_data.kernel_records", &[])
        .await
        .expect("missing context remains a valid empty RLS view")
        .get(0);
    assert_eq!(invisible, 0);
    assert!(runtime
        .execute(
            "INSERT INTO registry_data.kernel_records
             (record_id, authority, payload, package_revision)
             VALUES (CAST($1::text AS uuid), 'alpha', 'secret', 'package-1')",
            &[&RECORD_ALPHA],
        )
        .await
        .is_err());
    drop(runtime);

    let lock_key = RegistryLockKey::derive("registry-under-test")
        .expect("bounded Registry id derives a lock key");
    let alpha = claims("alpha");
    let beta = claims("beta");

    let mut client = pool
        .get_for_test()
        .await
        .expect("pooled client is available");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &initial,
        &alpha,
    )
    .await
    .expect("matching package and complete claims pass the record gate");
    transaction
        .transaction_for_test()
        .execute(
            "INSERT INTO registry_data.kernel_records
             (record_id, authority, payload, package_revision)
             VALUES (CAST($1::text AS uuid), 'alpha', 'secret', 'package-1')",
            &[&RECORD_ALPHA],
        )
        .await
        .expect("RLS permits the matching authority");
    let dynamic = transaction
        .transaction_for_test()
        .query_one(
            "SELECT record_id::text, authority, payload
             FROM registry_data.kernel_records WHERE record_id = CAST($1::text AS uuid)",
            &[&RECORD_ALPHA],
        )
        .await
        .expect("dynamic result query succeeds");
    let dynamic_columns: Vec<&str> = dynamic
        .columns()
        .iter()
        .map(tokio_postgres::Column::name)
        .collect();
    assert_eq!(dynamic_columns, ["record_id", "authority", "payload"]);
    assert_eq!(
        dynamic.try_get::<_, String>(1).expect("authority is text"),
        "alpha"
    );
    transaction
        .commit()
        .await
        .expect("record transaction commits");
    drop(client);
    assert_pool_context_clean(&pool).await;

    let mut client = pool
        .get_for_test()
        .await
        .expect("same-size pool remains available");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &initial,
        &beta,
    )
    .await
    .expect("a second authority obtains a fresh transaction");
    let count: i64 = transaction
        .transaction_for_test()
        .query_one("SELECT count(*) FROM registry_data.kernel_records", &[])
        .await
        .expect("RLS query succeeds")
        .get(0);
    assert_eq!(count, 0, "alpha authority must not leak to beta");
    transaction
        .rollback()
        .await
        .expect("explicit rollback succeeds");
    drop(client);
    assert_pool_context_clean(&pool).await;

    sql_error_does_not_leak(&pool, lock_key, &initial, &alpha).await;
    query_cancellation_does_not_leak(&pool, lock_key, &initial, &alpha).await;
    task_cancellation_does_not_leak(&pool, lock_key, &initial, &alpha).await;
    panic_does_not_leak(&pool, lock_key, &initial, &alpha).await;
    forced_disconnect_is_recycled(&database, &pool).await;

    let target = ExpectedRegistryIdentity {
        package_id: initial.package_id.clone(),
        environment: initial.environment.clone(),
        instance_id: initial.instance_id.clone(),
        database_id: initial.database_id.clone(),
        package_revision: "package-2".to_owned(),
        schema_fingerprint: initial.schema_fingerprint.clone(),
        package_sequence: 2,
    };
    let mut apply = DedicatedApplyConnection::acquire(
        &database.migration_config,
        lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("dedicated migration connection acquires exclusive lock");
    apply
        .mark_applying(&initial, &target.package_revision)
        .await
        .expect("maintenance is durably committed while lock remains held");
    let pool_for_blocked_record = pool.clone();
    let old_for_blocked_record = initial.clone();
    let blocked = tokio::spawn(async move {
        let mut client = pool_for_blocked_record
            .get_for_test()
            .await
            .expect("pool get succeeds");
        begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_millis(100),
            &old_for_blocked_record,
            &claims("alpha"),
        )
        .await
        .map(|_| ())
    })
    .await
    .expect("blocked record task joins");
    assert!(matches!(
        blocked,
        Err(PostgresKernelError::RegistryUnavailable)
    ));
    database
        .admin
        .batch_execute(&format!(
            "ALTER TABLE registry_data.kernel_records OWNER TO \"{}\";\n\
             ALTER TABLE registry_internal.registry_state OWNER TO \"{}\";\n\
             ALTER SCHEMA registry_data OWNER TO \"{}\";\n\
             ALTER SCHEMA registry_internal OWNER TO \"{}\";",
            database.intruder_role.as_str(),
            database.intruder_role.as_str(),
            database.intruder_role.as_str(),
            database.intruder_role.as_str(),
        ))
        .await
        .expect("test administrator can seed coherent ownership drift");
    let owner_drift = apply
        .activate(&target, &database.migration_role, &database.runtime_role)
        .await;
    assert!(matches!(
        owner_drift,
        Err(PostgresKernelError::CatalogInvariant(_))
    ));
    let maintenance_status: String = database
        .admin
        .query_one(
            "SELECT maintenance_status FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("maintenance state remains readable")
        .get(0);
    assert_eq!(maintenance_status, "applying");
    database
        .admin
        .batch_execute(&format!(
            "ALTER TABLE registry_data.kernel_records OWNER TO \"{}\";\n\
             ALTER TABLE registry_internal.registry_state OWNER TO \"{}\";\n\
             ALTER SCHEMA registry_data OWNER TO \"{}\";\n\
             ALTER SCHEMA registry_internal OWNER TO \"{}\";",
            database.migration_role.as_str(),
            database.migration_role.as_str(),
            database.migration_role.as_str(),
            database.migration_role.as_str(),
        ))
        .await
        .expect("test administrator restores exact migration ownership");
    apply
        .activate(&target, &database.migration_role, &database.runtime_role)
        .await
        .expect("target activates atomically");
    apply
        .release()
        .await
        .expect("exclusive apply lock releases");

    let mut client = pool
        .get_for_test()
        .await
        .expect("pool recovers after activation");
    {
        let old_runtime = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(1),
            &initial,
            &alpha,
        )
        .await;
        assert!(matches!(
            old_runtime,
            Err(PostgresKernelError::RegistryUnavailable)
        ));
    }
    let current_runtime = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &target,
        &alpha,
    )
    .await;
    current_runtime
        .expect("runtime loaded with the activated package becomes usable")
        .rollback()
        .await
        .expect("final rollback succeeds");
    drop(client);

    let failed_target = ExpectedRegistryIdentity {
        package_revision: "package-3".to_owned(),
        package_sequence: 3,
        ..target.clone()
    };
    let mut apply = DedicatedApplyConnection::acquire(
        &database.migration_config,
        lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("second apply obtains the exclusive lock");
    apply
        .mark_applying(&target, &failed_target.package_revision)
        .await
        .expect("second maintenance transition commits");
    apply
        .mark_failed()
        .await
        .expect("failed maintenance is durable");
    apply
        .release()
        .await
        .expect("failed apply releases its lock");
    let mut client = pool
        .get_for_test()
        .await
        .expect("pool is reachable after failed apply");
    {
        let unavailable = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(1),
            &target,
            &alpha,
        )
        .await;
        assert!(matches!(
            unavailable,
            Err(PostgresKernelError::RegistryUnavailable)
        ));
    }
    drop(client);

    let mut recovery = DedicatedApplyConnection::acquire(
        &database.migration_config,
        lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("recovery obtains the exclusive Registry lock");
    recovery
        .activate(
            &failed_target,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .expect("failed maintenance clears only through reconciled activation");
    recovery
        .release()
        .await
        .expect("recovery releases the Registry lock");
    let mut client = pool
        .get_for_test()
        .await
        .expect("pool remains available after recovery");
    begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &failed_target,
        &alpha,
    )
    .await
    .expect("reconciled package is record-ready")
    .rollback()
    .await
    .expect("recovery proof rollback succeeds");
    drop(client);

    let crash_lock = DedicatedApplyConnection::acquire(
        &database.migration_config,
        lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("dedicated apply connection acquires a final lock");
    drop(crash_lock);
    let recovered_lock = DedicatedApplyConnection::acquire(
        &database.migration_config,
        lock_key,
        Duration::from_secs(2),
    )
    .await
    .expect("connection loss releases the session advisory lock");
    recovered_lock
        .release()
        .await
        .expect("recovered apply lock releases cleanly");

    database.cleanup().await;
}

fn claims(authority: &str) -> ClaimContext {
    ClaimContext::kernel_for_test(
        format!("principal-{authority}"),
        "operator".to_owned(),
        Some("registry-administration".to_owned()),
        authority.to_owned(),
    )
    .expect("kernel test claims are bounded")
}

async fn assert_pool_context_clean(pool: &registry_breg::postgres::RuntimePool) {
    let client = pool
        .get_for_test()
        .await
        .expect("pool returns a connection");
    let clean: bool = client
        .query_one(
            "SELECT NULLIF(current_setting('registry.principal', true), '') IS NULL
                 AND NULLIF(current_setting('registry.access_profile', true), '') IS NULL
                 AND NULLIF(current_setting('registry.purpose', true), '') IS NULL
                 AND NULLIF(current_setting('registry.row_boundaries', true), '') IS NULL
                 AND NULLIF(current_setting('registry.active_package_revision', true), '') IS NULL",
            &[],
        )
        .await
        .expect("context probe succeeds")
        .get(0);
    assert!(
        clean,
        "transaction-local claims must not survive pool return"
    );
}

async fn sql_error_does_not_leak(
    pool: &registry_breg::postgres::RuntimePool,
    lock_key: RegistryLockKey,
    identity: &ExpectedRegistryIdentity,
    context: &ClaimContext,
) {
    let mut client = pool
        .get_for_test()
        .await
        .expect("pool returns a connection");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        identity,
        context,
    )
    .await
    .expect("record transaction starts");
    assert!(transaction
        .transaction_for_test()
        .query_one("SELECT 'not-an-integer'::integer", &[])
        .await
        .is_err());
    drop(transaction);
    drop(client);
    assert_pool_context_clean(pool).await;
}

async fn query_cancellation_does_not_leak(
    pool: &registry_breg::postgres::RuntimePool,
    lock_key: RegistryLockKey,
    identity: &ExpectedRegistryIdentity,
    context: &ClaimContext,
) {
    let mut client = pool
        .get_for_test()
        .await
        .expect("pool returns a connection");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        identity,
        context,
    )
    .await
    .expect("record transaction starts");
    let cancellation = transaction.transaction_for_test().client().cancel_token();
    {
        let query = transaction
            .transaction_for_test()
            .query_one("SELECT pg_sleep(10)", &[]);
        tokio::pin!(query);
        tokio::select! {
            result = &mut query => panic!("sleep query completed before cancellation: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(25)) => {
                cancellation
                    .cancel_query(tokio_postgres::NoTls)
                    .await
                    .expect("query cancellation reaches the same test server");
            }
        }
        assert!(query.await.is_err(), "cancelled query must fail");
    }
    drop(transaction);
    drop(client);
    assert_pool_context_clean(pool).await;
}

async fn task_cancellation_does_not_leak(
    pool: &registry_breg::postgres::RuntimePool,
    lock_key: RegistryLockKey,
    identity: &ExpectedRegistryIdentity,
    context: &ClaimContext,
) {
    let task_pool = pool.clone();
    let identity = identity.clone();
    let context = context.clone();
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut client = task_pool
            .get_for_test()
            .await
            .expect("pool returns a connection");
        let _transaction = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(1),
            &identity,
            &context,
        )
        .await
        .expect("record transaction starts");
        ready
            .send(())
            .expect("cancellation proof receiver remains available");
        std::future::pending::<()>().await;
    });
    started
        .await
        .expect("cancellation proof reaches the guarded transaction");
    task.abort();
    let _ = task.await;
    assert_pool_context_clean(pool).await;
}

async fn panic_does_not_leak(
    pool: &registry_breg::postgres::RuntimePool,
    lock_key: RegistryLockKey,
    identity: &ExpectedRegistryIdentity,
    context: &ClaimContext,
) {
    let task_pool = pool.clone();
    let identity = identity.clone();
    let context = context.clone();
    let task = tokio::spawn(async move {
        let mut client = task_pool
            .get_for_test()
            .await
            .expect("pool returns a connection");
        let _transaction = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(1),
            &identity,
            &context,
        )
        .await
        .expect("record transaction starts");
        panic!("intentional pool-isolation proof panic");
    });
    assert!(task
        .await
        .expect_err("task intentionally panics")
        .is_panic());
    assert_pool_context_clean(pool).await;
}

async fn forced_disconnect_is_recycled(
    database: &TestDatabase,
    pool: &registry_breg::postgres::RuntimePool,
) {
    let client = pool
        .get_for_test()
        .await
        .expect("pool returns a connection");
    let process_id: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("backend pid is available")
        .get(0);
    database
        .admin
        .execute("SELECT pg_terminate_backend($1)", &[&process_id])
        .await
        .expect("test administrator can terminate the isolated runtime backend");
    drop(client);
    assert_pool_context_clean(pool).await;
}
