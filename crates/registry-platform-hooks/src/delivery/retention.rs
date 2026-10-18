// SPDX-License-Identifier: Apache-2.0

//! Product-invoked cleanup after delivery and replay retention.
use std::time::SystemTime;

use registry_platform_dispatch::postgres::{
    prune_terminal, JobKey, JobTable, RetentionError, MAX_PRUNE_BATCH,
};
use tokio_postgres::Transaction;

/// Prune one bounded batch of terminal delivery metadata and unreferenced
/// events, within a product-owned transaction and metadata horizon.
///
/// Pending and leased work remains. Dead letters require completed payload
/// expiry, including erasure of the shared payload, before their metadata can
/// age out. Their metadata horizon starts at `dead_lettered_at`; later
/// completed expiry does not restart it. Discarded payloads do not wait for
/// their obsolete scheduled expiry deadline. The expiry worker supplies the
/// per-delivery audit first; this cleanup never substitutes for expiry or
/// deletes the audit journal.
/// State, delivery, then unreferenced event are removed in that order. Locked
/// rows are skipped, and retained siblings keep their shared event.
///
/// # Errors
/// Returns [`RetentionError::Identifier`] for an invalid schema, and the
/// value-free database cause (its SQLSTATE, never a row value or message) for
/// a failed statement. The caller must roll back its transaction on error.
pub async fn prune_terminal_deliveries(
    transaction: &Transaction<'_>,
    schema: &str,
    before: SystemTime,
) -> Result<u64, RetentionError> {
    let table = JobTable::new(
        schema,
        "registry_webhook_delivery_state",
        "event_id",
        "compiled_delivery_id",
    )
    .map_err(|_| RetentionError::Identifier)?;
    let rows = transaction
        .query(
            &format!(
                "SELECT state.event_id, state.compiled_delivery_id
         FROM {schema}.registry_webhook_delivery_state AS state
         JOIN {schema}.registry_outbox AS outbox ON outbox.event_id=state.event_id
         WHERE (state.updated_at <= $1
                  AND (state.state='delivered'
                    OR (state.state='expired'
                        AND state.expired_at <= $1 AND outbox.payload IS NULL)))
            OR (state.state='dead-lettered' AND state.dead_lettered_at <= $1
                AND state.expired_at IS NOT NULL AND outbox.payload IS NULL)
         ORDER BY state.updated_at, state.event_id, state.compiled_delivery_id
         LIMIT {MAX_PRUNE_BATCH} FOR UPDATE OF state, outbox SKIP LOCKED"
            ),
            &[&before],
        )
        .await?;
    let keys = rows
        .into_iter()
        .map(|row| JobKey::new(row.get(0), row.get::<_, String>(1)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RetentionError::Identifier)?;
    let deleted = prune_terminal(transaction, &table, &keys, before).await?;
    for key in &deleted {
        transaction.execute(&format!(
            "DELETE FROM {schema}.registry_webhook_deliveries WHERE event_id=$1 AND compiled_delivery_id=$2"
        ), &[&key.id(), &key.part()]).await?;
        transaction
            .execute(
                &format!(
                    "DELETE FROM {schema}.registry_outbox AS outbox WHERE event_id=$1
             AND NOT EXISTS (SELECT 1 FROM {schema}.registry_webhook_deliveries AS delivery
                             WHERE delivery.event_id=outbox.event_id)"
                ),
                &[&key.id()],
            )
            .await?;
    }
    Ok(deleted.len() as u64)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use uuid::Uuid;

    use super::prune_terminal_deliveries;
    use crate::delivery::{insert_delivery, DeliveryCapture};
    use crate::delivery_schema;
    use crate::HookHandlerKind;

    const PACKAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BINDING: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FINGERPRINT: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    async fn connect(schema: &str) -> tokio_postgres::Client {
        let url = std::env::var("HOOKS_TEST_DATABASE_URL")
            .expect("HOOKS_TEST_DATABASE_URL is required for the real PostgreSQL test");
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect to the local PostgreSQL test database");
        tokio::spawn(async move {
            let _closed = connection.await;
        });
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
            ))
            .await
            .expect("reset the test schema");
        delivery_schema::install(&client, schema)
            .await
            .expect("install the delivery schema");
        client
    }

    // One event with an erased payload and one pending delivery per id.
    async fn capture(
        client: &mut tokio_postgres::Client,
        schema: &str,
        deliveries: &[&str],
    ) -> Uuid {
        let event_id = Uuid::new_v4();
        client
            .execute(
                &format!(
                    "INSERT INTO {schema}.registry_outbox
                     (event_id, event_type, trigger, entity_id, record_reference,
                      record_revision, package_revision, schema_fingerprint,
                      payload_expires_at)
                     VALUES ($1, 'record.changed', 'test', 'record', 'record-1', 1, $2, $3,
                             transaction_timestamp() - interval '30 days')"
                ),
                &[&event_id, &PACKAGE, &FINGERPRINT],
            )
            .await
            .expect("insert the outbox row");
        let transaction = client.transaction().await.expect("insert transaction");
        for id in deliveries {
            insert_delivery(
                &transaction,
                schema,
                event_id,
                DeliveryCapture {
                    compiled_delivery_id: id,
                    handler_kind: HookHandlerKind::Rhai,
                    logical_destination_id: None,
                    destination_binding_digest: BINDING,
                    package_revision: PACKAGE,
                    schema_fingerprint: FINGERPRINT,
                    data_schema: "https://example.test/schema",
                    classification_ceiling: "public",
                    authentication_profile: "hmac-sha256-v1",
                    delivery_mode: "after-commit",
                    attempt_timeout_ms: 1_000,
                    initial_backoff_ms: 1_000,
                    maximum_backoff_ms: 1_000,
                    exponential_backoff_multiplier: 2,
                    maximum_attempts: 1,
                    retry_delays_ms: &[],
                    maximum_payload_bytes: 65_536,
                    payload: b"{}",
                    deployed_attempt_timeout_ms: 1_000,
                    deployed_maximum_attempts: 1,
                    dead_letter: "required",
                    operator_replay: false,
                },
            )
            .await
            .expect("insert the delivery row");
        }
        transaction.commit().await.expect("commit the capture");
        event_id
    }

    async fn deliver(
        client: &tokio_postgres::Client,
        schema: &str,
        event: Uuid,
        id: &str,
        at: SystemTime,
    ) {
        client
            .execute(
                &format!(
                    "UPDATE {schema}.registry_webhook_delivery_state
                     SET state='delivered', attempt=1, next_attempt_at=NULL,
                         delivered_at=$3, updated_at=$3
                     WHERE event_id=$1 AND compiled_delivery_id=$2"
                ),
                &[&event, &id, &at],
            )
            .await
            .expect("mark the delivery delivered");
    }

    async fn count(client: &tokio_postgres::Client, schema: &str, table: &str, event: Uuid) -> i64 {
        client
            .query_one(
                &format!("SELECT count(*) FROM {schema}.{table} WHERE event_id=$1"),
                &[&event],
            )
            .await
            .expect("count rows")
            .get(0)
    }

    async fn prune(client: &mut tokio_postgres::Client, schema: &str, before: SystemTime) -> u64 {
        let transaction = client.transaction().await.expect("retention transaction");
        let pruned = prune_terminal_deliveries(&transaction, schema, before)
            .await
            .expect("prune terminal deliveries");
        transaction.commit().await.expect("commit retention");
        pruned
    }

    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn dead_letter_horizon_requires_terminal_age_completed_expiry_and_erased_payload() {
        let schema = "hooks_retention_dead_letter_test";
        let mut client = connect(schema).await;
        let cutoff = SystemTime::now() - Duration::from_secs(7 * 24 * 3600);
        let old = cutoff - Duration::from_secs(1);
        let recent = cutoff + Duration::from_secs(1);
        let mut cases = Vec::new();
        for (terminal, expired, erased, remove) in [
            (old, true, true, true),
            (cutoff, true, true, true),
            (recent, true, true, false),
            (old, false, true, false),
            (old, true, false, false),
        ] {
            let event = capture(&mut client, schema, &["only"]).await;
            client.execute(&format!(
                "UPDATE {schema}.registry_webhook_delivery_state
                 SET state='dead-lettered', attempt=1, next_attempt_at=NULL,
                     dead_lettered_at=$2, expired_at=CASE WHEN $3 THEN $4::timestamptz ELSE NULL END,
                     updated_at=$4 WHERE event_id=$1"
            ), &[&event, &terminal, &expired, &recent]).await.unwrap();
            client.execute(&format!(
                "UPDATE {schema}.registry_outbox SET payload=CASE WHEN $2 THEN NULL ELSE '\\x63616e617279'::bytea END WHERE event_id=$1"
            ), &[&event, &erased]).await.unwrap();
            cases.push((event, remove));
        }
        assert_eq!(prune(&mut client, schema, cutoff).await, 2);
        for (event, removed) in cases {
            for table in [
                "registry_webhook_delivery_state",
                "registry_webhook_deliveries",
                "registry_outbox",
            ] {
                assert_eq!(
                    count(&client, schema, table, event).await,
                    i64::from(!removed)
                );
            }
        }
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn pruning_respects_foreign_key_order_and_keeps_a_shared_event_until_its_last_delivery() {
        let schema = "hooks_retention_prune_test";
        let mut client = connect(schema).await;
        let cutoff = SystemTime::now() - Duration::from_secs(7 * 24 * 3600);
        let old = cutoff - Duration::from_secs(1);
        let recent = cutoff + Duration::from_secs(1);
        let shared = capture(&mut client, schema, &["first", "second"]).await;
        let kept = capture(&mut client, schema, &["only"]).await;
        deliver(&client, schema, shared, "first", old).await;
        deliver(&client, schema, kept, "only", recent).await;

        // The restrictive foreign keys refuse any other order, so a committed
        // prune proves state, then delivery, then unreferenced event.
        assert_eq!(prune(&mut client, schema, cutoff).await, 1);
        assert_eq!(
            count(&client, schema, "registry_webhook_delivery_state", shared).await,
            1
        );
        assert_eq!(
            count(&client, schema, "registry_webhook_deliveries", shared).await,
            1
        );
        assert_eq!(
            count(&client, schema, "registry_outbox", shared).await,
            1,
            "a pending sibling keeps the shared event"
        );
        assert_eq!(
            count(&client, schema, "registry_webhook_deliveries", kept).await,
            1
        );
        assert_eq!(count(&client, schema, "registry_outbox", kept).await, 1);

        deliver(&client, schema, shared, "second", old).await;
        assert_eq!(prune(&mut client, schema, cutoff).await, 1);
        for table in [
            "registry_webhook_delivery_state",
            "registry_webhook_deliveries",
            "registry_outbox",
        ] {
            assert_eq!(
                count(&client, schema, table, shared).await,
                0,
                "{table} is empty once the last delivery is pruned"
            );
        }
        assert_eq!(count(&client, schema, "registry_outbox", kept).await, 1);
        assert_eq!(prune(&mut client, schema, cutoff).await, 0);
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .await
            .expect("drop the test schema");
    }

    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn a_refused_prune_names_only_its_sqlstate() {
        let schema = "hooks_retention_refusal_test";
        let mut client = connect(schema).await;
        let cutoff = SystemTime::now() - Duration::from_secs(60);
        let event = capture(&mut client, schema, &["canary-pinned"]).await;
        deliver(
            &client,
            schema,
            event,
            "canary-pinned",
            cutoff - Duration::from_secs(1),
        )
        .await;
        client
            .batch_execute(&format!(
                "CREATE TABLE {schema}.canary_dependency (
                 event_id uuid NOT NULL, compiled_delivery_id text NOT NULL,
                 FOREIGN KEY (event_id, compiled_delivery_id)
                 REFERENCES {schema}.registry_webhook_deliveries (event_id, compiled_delivery_id));"
            ))
            .await
            .expect("create the dependent table");
        client
            .execute(
                &format!("INSERT INTO {schema}.canary_dependency VALUES ($1, 'canary-pinned')"),
                &[&event],
            )
            .await
            .expect("pin the delivery");
        let transaction = client.transaction().await.expect("retention transaction");
        let refused = prune_terminal_deliveries(&transaction, schema, cutoff)
            .await
            .expect_err("the dependent row refuses the delivery deletion");
        transaction.rollback().await.expect("roll back retention");
        assert_eq!(refused.sqlstate(), Some("23503"));
        let reported = refused.to_string();
        assert!(!reported.contains("canary"), "{reported}");
        assert!(!reported.contains(&event.to_string()), "{reported}");
        assert_eq!(
            count(&client, schema, "registry_webhook_delivery_state", event).await,
            1
        );
        client
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE;"))
            .await
            .expect("drop the test schema");
    }
}
