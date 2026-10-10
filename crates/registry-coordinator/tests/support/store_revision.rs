// SPDX-License-Identifier: Apache-2.0
//! The one schema revision and its narrowly governed zero-attempt hold shape.
use super::*;
use registry_platform_dispatch::postgres::JobTable;

#[tokio::test]
async fn job_shape_admits_only_the_governed_zero_attempt_hold() {
    let h = harness().await;
    let run = h.admit().await;
    let identity = restored_lease_identity(&h, run).await;
    let job = restored_current_job(&h, run).await;
    let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });

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
    let held = "state='dead-lettered',next_attempt_at=NULL,dead_lettered_at=transaction_timestamp(),failure_code='restore-pre-command-held'";
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
            format!("state='dead-lettered',next_attempt_at=NULL,dead_lettered_at=transaction_timestamp(){}", extra)
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
        "dead-lettered"
    );
}

#[tokio::test]
async fn a_store_recording_another_revision_is_refused_unchanged() {
    for other in [3, 5] {
        let h = harness().await;
        let run = h.admit().await;
        let identity = restored_lease_identity(&h, run).await;
        let job = restored_current_job(&h, run).await;
        let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        h.sql(&format!(
            "ALTER TABLE {{schema}}.control DROP CONSTRAINT control_schema_version_check;
             UPDATE {{schema}}.control SET schema_version={other}"
        ))
        .await;
        for _ in 0..2 {
            let error = h.store.migrate().await.unwrap_err();
            assert_eq!(error.code, "schema-version", "revision {other}");
            assert!(
                error.message.contains("apply to a new database"),
                "revision {other}"
            );
            assert!(h.store.doctor().await.is_err(), "revision {other}");
            assert_eq!(restored_current_job(&h, run).await, job);
            assert_eq!(restored_lease_identity(&h, run).await, identity);
            let recorded: i32 = client
                .query_one(
                    &format!(
                        "SELECT schema_version FROM {}.control WHERE id",
                        h.namespace
                    ),
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(recorded, other, "refusal changes nothing");
        }
    }
}
