// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use postgres_harness::TestDatabase;
use registry_server::mutation::install_mutation_schema;

#[tokio::test]
async fn application_receipt_upgrade_preserves_legacy_results_and_enforces_shape() {
    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;
    migration
        .batch_execute(
            "CREATE TABLE registry_internal.registry_idempotency (
                 key_reference text PRIMARY KEY CHECK (key_reference <> ''),
                 binding_reference text NOT NULL CHECK (binding_reference <> ''),
                 result_kind text NOT NULL CHECK (result_kind IN ('record', 'batch')),
                 record_reference text CHECK (record_reference <> ''),
                 record_revision bigint CHECK (record_revision > 0),
                 result_count smallint CHECK (result_count > 0 AND result_count <= 100),
                 response_status smallint NOT NULL CHECK (response_status BETWEEN 200 AND 299),
                 response_body bytea NOT NULL,
                 response_headers bytea NOT NULL,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 CHECK (
                     (result_kind = 'record' AND record_reference IS NOT NULL
                         AND record_revision IS NOT NULL AND result_count IS NULL)
                     OR (result_kind = 'batch' AND record_reference IS NULL
                         AND record_revision IS NULL AND result_count IS NOT NULL)
                 )
             );
             INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_reference,
                  record_revision, result_count, response_status, response_body, response_headers)
             VALUES ('legacy-record', 'binding-record', 'record', 'record-ref', 3, NULL,
                         200, convert_to('{\"legacy\":true}', 'UTF8'), decode('0000', 'hex')),
                    ('legacy-batch', 'binding-batch', 'batch', NULL, NULL, 2,
                         200, convert_to('[]', 'UTF8'), decode('0000', 'hex'));",
        )
        .await
        .expect("test installs the previous receipt schema and retained results");

    for _ in 0..2 {
        install_mutation_schema(&migration, &database.runtime_role)
            .await
            .expect("schema installation upgrades retained receipts repeatably");
    }
    let rows = migration
        .query(
            "SELECT key_reference, response_body, proposal_version
               FROM registry_internal.registry_idempotency ORDER BY key_reference",
            &[],
        )
        .await
        .expect("retained receipt bytes remain available");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, Vec<u8>>(1), b"[]");
    assert_eq!(rows[1].get::<_, Vec<u8>>(1), br#"{"legacy":true}"#);
    assert!(rows
        .iter()
        .all(|row| row.get::<_, Option<i64>>(2).is_none()));

    let insert_application = "INSERT INTO registry_internal.registry_idempotency
             (key_reference, binding_reference, result_kind, record_reference,
              record_revision, result_count, proposal_version, response_status,
              response_body, response_headers)
         VALUES ($1, 'application-binding', 'application', 'request-ref', 7, $2, $3,
                 200, convert_to('{}', 'UTF8'), decode('0000', 'hex'))";
    migration
        .execute(
            insert_application,
            &[&"applied", &Some(2_i16), &Some(1_i64)],
        )
        .await
        .expect("application receipt records its proposal and bounded target count");
    for (key, count, version) in [
        ("missing-count", None, Some(1_i64)),
        ("zero-count", Some(0_i16), Some(1)),
        ("excess-count", Some(17), Some(1)),
        ("missing-version", Some(1), None),
        ("zero-version", Some(1), Some(0)),
    ] {
        assert!(
            migration
                .execute(insert_application, &[&key, &count, &version])
                .await
                .is_err(),
            "database refuses an incomplete or out-of-bound application receipt"
        );
    }
    assert!(
        migration
            .execute(
                "UPDATE registry_internal.registry_idempotency
                    SET proposal_version = 1 WHERE key_reference = 'legacy-record'",
                &[],
            )
            .await
            .is_err(),
        "record receipts cannot masquerade as proposal-bound application results"
    );
    assert!(
        migration
            .execute(
                insert_application,
                &[&"applied", &Some(2_i16), &Some(1_i64)]
            )
            .await
            .is_err(),
        "a stored idempotency key cannot acquire a second result"
    );
    assert!(
        migration
            .execute(
                "UPDATE registry_internal.registry_idempotency
                SET response_body = NULL WHERE key_reference = 'applied'",
                &[],
            )
            .await
            .is_err(),
        "receipt bytes cannot disappear without an erasure marker"
    );
    assert!(
        migration
            .execute(
                "UPDATE registry_internal.registry_idempotency
                SET erased_at = transaction_timestamp() WHERE key_reference = 'applied'",
                &[],
            )
            .await
            .is_err(),
        "an erased receipt cannot retain response payload bytes"
    );
    migration
        .execute(
            "UPDATE registry_internal.registry_idempotency
                SET response_body = NULL, erased_at = transaction_timestamp()
              WHERE key_reference = 'applied'",
            &[],
        )
        .await
        .expect("operator can erase bytes while preserving the result identity");
    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("schema reinstallation preserves erased receipts");
    migration_task.abort();
    database.cleanup().await;
}
