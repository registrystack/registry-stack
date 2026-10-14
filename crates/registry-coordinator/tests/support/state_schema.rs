// SPDX-License-Identifier: Apache-2.0
//! The protected state schema is created once, at one version, with the
//! narrowly governed zero-attempt hold shape.
use super::*;
use registry_platform_dispatch::postgres::JobTable;

/// Every catalog row a DDL statement on the namespace would rewrite, with the
/// transaction that last wrote it.
async fn catalog(h: &Harness) -> Vec<String> {
    let (client, connection) = tokio_postgres::connect(&h.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
        .query(
            "SELECT format('namespace %s %s %s', n.oid, n.xmin, obj_description(n.oid,'pg_namespace'))
               FROM pg_namespace n WHERE n.nspname=$1
             UNION ALL
             SELECT format('relation %s %s %s %s', c.relname, c.oid, c.xmin, c.relfilenode)
               FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1
             UNION ALL
             SELECT format('constraint %s.%s %s %s %s', t.relname, k.conname, k.oid, k.xmin, pg_get_constraintdef(k.oid))
               FROM pg_constraint k JOIN pg_class t ON t.oid=k.conrelid
               JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=$1
             UNION ALL
             SELECT format('column %s.%s %s %s', t.relname, a.attname, a.attnum, a.xmin)
               FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid
               JOIN pg_namespace n ON n.oid=t.relnamespace
               WHERE n.nspname=$1 AND a.attnum>0 AND NOT a.attisdropped
             ORDER BY 1",
            &[&h.namespace],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
async fn a_second_migration_changes_no_schema_object_or_protected_row() {
    let h = harness().await;
    let run = h.admit().await;
    let job = restored_current_job(&h, run).await;
    let identity = restored_lease_identity(&h, run).await;
    let before = catalog(&h).await;
    h.store
        .migrate()
        .await
        .expect("an existing namespace migrates");
    assert_eq!(catalog(&h).await, before, "the second migration ran DDL");
    assert_eq!(restored_current_job(&h, run).await, job);
    assert_eq!(restored_lease_identity(&h, run).await, identity);
    assert_eq!(h.store.doctor().await.unwrap().schema_version, 3);
}

#[tokio::test]
async fn a_prior_schema_without_authored_cancellation_state_is_refused_unchanged() {
    let h = harness().await;
    h.sql(
        "ALTER TABLE {schema}.control DROP CONSTRAINT control_schema_version_check;
         UPDATE {schema}.control SET schema_version=1;
         ALTER TABLE {schema}.runs DROP COLUMN authored_cancel_pending_step;
         ALTER TABLE {schema}.runs DROP COLUMN authored_cancel_requested",
    )
    .await;
    let before = catalog(&h).await;
    assert_eq!(
        h.store.migrate().await.expect_err("prior version").code,
        "schema-version"
    );
    assert!(
        h.store.doctor().await.is_err(),
        "the runtime never adopts it"
    );
    assert_eq!(catalog(&h).await, before);
}

#[tokio::test]
async fn a_prior_schema_without_shared_completion_waits_is_refused_unchanged() {
    let h = harness().await;
    h.sql(
        "ALTER TABLE {schema}.control DROP CONSTRAINT control_schema_version_check;
         UPDATE {schema}.control SET schema_version=2;
         DROP TABLE {schema}.completion_waits",
    )
    .await;
    let before = catalog(&h).await;
    assert_eq!(
        h.store
            .migrate()
            .await
            .expect_err("prior completion format")
            .code,
        "schema-version"
    );
    assert!(
        h.store.doctor().await.is_err(),
        "the runtime never adopts it"
    );
    assert_eq!(catalog(&h).await, before, "version refusal ran DDL");
}

#[tokio::test]
async fn the_job_shape_admits_only_the_governed_zero_attempt_hold() {
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
