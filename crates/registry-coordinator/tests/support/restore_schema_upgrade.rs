// SPDX-License-Identifier: Apache-2.0
//! Explicit migration and narrowly governed zero-attempt hold shape.
use super::*;
use registry_platform_dispatch::postgres::JobTable;

#[tokio::test]
async fn revision_two_upgrade_preserves_pending_identity_and_is_idempotent() {
    let h = harness().await;
    let run = h.admit().await;
    let identity = restored_lease_identity(&h, run).await;
    let job = restored_current_job(&h, run).await;
    let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client.batch_execute(&format!("ALTER TABLE {0}.jobs DROP CONSTRAINT jobs_shape;
        ALTER TABLE {0}.jobs ADD CONSTRAINT jobs_shape CHECK ({1});
        ALTER TABLE {0}.control DROP CONSTRAINT control_schema_version_check;
        UPDATE {0}.control SET schema_version=2;
        ALTER TABLE {0}.control ADD CONSTRAINT control_schema_version_check CHECK(schema_version=2)",
        h.namespace, JobTable::shape_predicate())).await.unwrap();
    assert!(
        h.store.doctor().await.is_err(),
        "runtime never upgrades implicitly"
    );
    h.store.migrate().await.unwrap();
    assert_eq!(h.store.doctor().await.unwrap().schema_version, 3);
    assert_eq!(restored_current_job(&h, run).await, job);
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    h.store.migrate().await.unwrap();
    assert_eq!(restored_current_job(&h, run).await, job);
    assert_eq!(restored_lease_identity(&h, run).await, identity);

    // The shared default still rejects every zero-attempt dead letter.
    client
        .batch_execute(&format!(
            "CREATE TABLE {0}.default_shape (LIKE {0}.jobs INCLUDING DEFAULTS);
        ALTER TABLE {0}.default_shape ADD CONSTRAINT default_shape CHECK ({1});
        INSERT INTO {0}.default_shape SELECT * FROM {0}.jobs",
            h.namespace,
            JobTable::shape_predicate()
        ))
        .await
        .unwrap();
    let held = "state='dead_lettered',next_attempt_at=NULL,dead_lettered_at=transaction_timestamp(),failure_code='restore-pre-command-held'";
    assert!(client
        .batch_execute(&format!("UPDATE {}.default_shape SET {held}", h.namespace))
        .await
        .is_err());
    for extra in [
        ",failure_code=NULL",
        ",failure_code='other'",
        ",command='{}'::jsonb",
        ",uncertain=true",
        ",receipt_expired=true",
        ",expired_at=transaction_timestamp()",
        ",lease_token=gen_random_uuid()",
    ] {
        let assignment = if extra.starts_with(",failure_code=") {
            format!("state='dead_lettered',next_attempt_at=NULL,dead_lettered_at=transaction_timestamp(){}", extra)
        } else {
            format!("{held}{extra}")
        };
        let error = client
            .batch_execute(&format!("UPDATE {}.jobs SET {assignment}", h.namespace))
            .await
            .expect_err("refuse malformed held state");
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION),
            "shape refuses {extra}"
        );
        assert_eq!(restored_current_job(&h, run).await, job);
    }
    client
        .batch_execute(&format!("UPDATE {}.jobs SET {held}", h.namespace))
        .await
        .unwrap();
    assert_eq!(restored_current_job(&h, run).await["attempt"], 0);
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    h.store.migrate().await.unwrap();
    assert_eq!(
        restored_current_job(&h, run).await["state"],
        "dead_lettered"
    );
}
