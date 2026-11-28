// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

use registry_adapter::payments::store::{migrate, PaymentStore};
use registry_payment_protocol::PaymentProblemCode;

#[tokio::test]
async fn same_key_different_body_never_aliases_a_command() {
    let url = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("postgres-test requires ADAPTER_TEST_DATABASE_URL");
    let config = url.parse().unwrap();
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(4)
        .build()
        .unwrap();
    let mut client = pool.get().await.unwrap();
    migrate(&mut client).await.unwrap();
    let store = PaymentStore::new(
        pool,
        format!("payment-test-{}", uuid::Uuid::new_v4()),
        registry_platform_config::Posture::Production,
    );
    let id = uuid::Uuid::new_v4();
    store
        .claim_command("fees", "caller", "receipt", "key", "digest-1", id)
        .await
        .unwrap();
    assert_eq!(
        store
            .lookup_command("fees", "caller", "receipt", "key", "digest-1")
            .await
            .unwrap(),
        Some(id)
    );
    assert_eq!(
        store
            .lookup_command("fees", "caller", "receipt", "key", "digest-2")
            .await
            .unwrap_err(),
        PaymentProblemCode::Conflict
    );
    assert_eq!(
        store
            .lookup_command("fees", "other-caller", "receipt", "key", "digest-1")
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn payment_access_audit_records_the_declared_posture() {
    let url = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("postgres-test requires ADAPTER_TEST_DATABASE_URL");
    let manager = deadpool_postgres::Manager::new(url.parse().unwrap(), tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager).build().unwrap();
    let mut client = pool.get().await.unwrap();
    migrate(&mut client).await.unwrap();
    for posture in [
        registry_platform_config::Posture::Production,
        registry_platform_config::Posture::Development,
    ] {
        let deployment = format!("payment-test-{}", uuid::Uuid::new_v4());
        let store = PaymentStore::new(pool.clone(), deployment.clone(), posture);
        store.audit_access("caller", "read", None).await.unwrap();
        let row = client
            .query_one(
                "SELECT posture FROM adapter_payment_events WHERE deployment = $1",
                &[&deployment],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, &str>(0), posture.as_str());
    }
}

#[tokio::test]
async fn payment_audit_constraints_keep_old_rows_and_require_posture_on_inserts() {
    use registry_adapter::payments::g2p_store::migrate_g2p;
    use tokio_postgres::error::SqlState;

    let url = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("postgres-test requires ADAPTER_TEST_DATABASE_URL");
    let manager = deadpool_postgres::Manager::new(url.parse().unwrap(), tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager).build().unwrap();
    let mut client = pool.get().await.unwrap();
    let schema = format!("payment_audit_{}", uuid::Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();

    let tables = [
        (
            "adapter_payment_events",
            "adapter_payment_events_posture_check",
        ),
        (
            "adapter_g2p_events",
            "adapter_g2p_events_declared_posture_check",
        ),
    ];
    let attempt = uuid::Uuid::new_v4();
    for (table, _) in tables {
        client
            .batch_execute(&format!(
                "CREATE TABLE {table} (
                    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                    deployment text NOT NULL,
                    attempt_id uuid NOT NULL,
                    principal text NOT NULL,
                    kind text NOT NULL,
                    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
                )"
            ))
            .await
            .unwrap();
        client
            .execute(
                &format!(
                    "INSERT INTO {table} (deployment, attempt_id, principal, kind)
                    VALUES ('legacy', $1, 'caller', 'read')"
                ),
                &[&attempt],
            )
            .await
            .unwrap();
    }

    migrate(&mut client).await.unwrap();
    migrate_g2p(&mut client).await.unwrap();
    for (table, constraint) in tables {
        let row = client
            .query_one(
                &format!("SELECT posture FROM {table} WHERE deployment = 'legacy'"),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, Option<String>>(0), None, "{table}");
        for (column, value) in [("", ""), (", posture", ", 'staging'")] {
            let error = client
                .execute(
                    &format!(
                        "INSERT INTO {table} (deployment, attempt_id, principal, kind{column})
                        VALUES ('new', $1, 'caller', 'read'{value})"
                    ),
                    &[&attempt],
                )
                .await
                .expect_err("each new event must carry a known posture");
            assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION), "{table}");
            assert_eq!(error.as_db_error().unwrap().constraint(), Some(constraint));
        }
    }
}
