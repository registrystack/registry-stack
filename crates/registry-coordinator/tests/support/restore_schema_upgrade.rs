// SPDX-License-Identifier: Apache-2.0
//! Explicit migration and narrowly governed zero-attempt hold shape.
use super::*;
use registry_platform_dispatch::postgres::JobTable;

async fn install_legacy_dispatch_shape(h: &Harness, version: i32) {
    let shape = include_str!("../fixtures/dispatch-revision-two-shape.sql");
    let hold = if version == 3 {
        "OR (state='dead_lettered' AND attempt=0 AND command IS NULL
         AND NOT uncertain AND NOT receipt_expired
         AND next_attempt_at IS NULL AND attempt_started_at IS NULL
         AND lease_expires_at IS NULL AND lease_token IS NULL
         AND delivered_at IS NULL AND expired_at IS NULL
         AND dead_lettered_at IS NOT NULL
         AND failure_code IS NOT DISTINCT FROM 'restore-pre-command-held')"
    } else {
        ""
    };
    h.sql(&format!(
        "ALTER TABLE {{schema}}.jobs DROP CONSTRAINT jobs_shape;
         ALTER TABLE {{schema}}.jobs DROP CONSTRAINT jobs_state_values;
         UPDATE {{schema}}.jobs SET state='dead_lettered' WHERE state='dead-lettered';
         ALTER TABLE {{schema}}.jobs ADD CONSTRAINT jobs_state_values CHECK (
             state IN ('pending','leased','delivered','dead_lettered','expired','unknown','cancelled'));
         ALTER TABLE {{schema}}.jobs ADD CONSTRAINT jobs_shape CHECK (({shape}) {hold});
         ALTER TABLE {{schema}}.control DROP CONSTRAINT control_schema_version_check;
         UPDATE {{schema}}.control SET schema_version={version};
         ALTER TABLE {{schema}}.control ADD CONSTRAINT control_schema_version_check CHECK(schema_version={version})"
    )).await;
}

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
    install_legacy_dispatch_shape(&h, 2).await;
    assert!(
        h.store.doctor().await.is_err(),
        "runtime never upgrades implicitly"
    );
    h.store.migrate().await.unwrap();
    assert_eq!(h.store.doctor().await.unwrap().schema_version, 4);
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
async fn spelling_upgrade_preserves_prepared_uncertainty_leases_and_restore_holds() {
    for version in [2, 3] {
        for state in ["dead-lettered", "unknown", "leased", "restore-hold"] {
            if version == 2 && state == "restore-hold" {
                continue; // Revision two did not admit zero-attempt holds.
            }
            let (h, run) = if state == "restore-hold" {
                let h = harness().await;
                let run = h.admit().await;
                h.sql(
                    "UPDATE {schema}.jobs SET state='dead-lettered',next_attempt_at=NULL,
                    dead_lettered_at=clock_timestamp(),failure_code='restore-pre-command-held'",
                )
                .await;
                (h, run)
            } else {
                let (h, run, _, _) = prepared_pending_mutation("message").await;
                let change = match state {
                    "dead-lettered" => "state='dead-lettered',next_attempt_at=NULL,
                        dead_lettered_at=clock_timestamp(),uncertain=true,receipt_expired=true",
                    "unknown" => "state='unknown',next_attempt_at=NULL,uncertain=true",
                    "leased" => "state='leased',next_attempt_at=NULL,uncertain=true,
                        attempt_started_at=clock_timestamp(),lease_expires_at=clock_timestamp()+interval '5 minutes',
                        lease_token=gen_random_uuid()",
                    _ => unreachable!(),
                };
                h.sql(&format!(
                    "UPDATE {{schema}}.jobs SET {change} WHERE step='message'"
                ))
                .await;
                (h, run)
            };
            install_legacy_dispatch_shape(&h, version).await;
            let identity = restored_lease_identity(&h, run).await;
            let mut expected = restored_current_job(&h, run).await;
            if expected["state"] == "dead_lettered" {
                expected["state"] = json!("dead-lettered");
            }
            assert!(
                h.store.doctor().await.is_err(),
                "old revision requires explicit apply"
            );
            for _ in 0..2 {
                h.store.migrate().await.unwrap();
                assert_eq!(h.store.doctor().await.unwrap().schema_version, 4);
                assert_eq!(
                    restored_current_job(&h, run).await,
                    expected,
                    "revision {version}, {state}"
                );
                assert_eq!(restored_lease_identity(&h, run).await, identity);
            }
        }
    }
}
