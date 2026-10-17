// SPDX-License-Identifier: Apache-2.0

//! Product-invoked cleanup after delivery and replay retention.
use std::time::SystemTime;

use registry_platform_dispatch::postgres::{prune_terminal, JobKey, JobTable, MAX_PRUNE_BATCH};
use tokio_postgres::Transaction;

use super::DeliveryError;

/// Prune one bounded batch of terminal delivery metadata and unreferenced
/// events, within a product-owned transaction and metadata horizon.
///
/// Pending and leased work remains. Dead letters require completed payload
/// expiry, including erasure of the shared payload, before their metadata can
/// age out. The expiry worker supplies the per-delivery audit first; this
/// cleanup never substitutes for expiry or deletes the audit journal.
/// State, delivery, then unreferenced event are removed in that order. Locked
/// rows are skipped, and retained siblings keep their shared event.
///
/// # Errors
/// Returns `Unavailable` for an invalid schema or a database failure. The
/// caller must roll back its transaction on error.
pub async fn prune_terminal_deliveries(
    transaction: &Transaction<'_>,
    schema: &str,
    before: SystemTime,
) -> Result<u64, DeliveryError> {
    let table = JobTable::new(
        schema,
        "registry_webhook_delivery_state",
        "event_id",
        "compiled_delivery_id",
    )
    .map_err(|_| DeliveryError::Unavailable)?;
    let rows = transaction
        .query(
            &format!(
                "SELECT state.event_id, state.compiled_delivery_id
         FROM {schema}.registry_webhook_delivery_state AS state
         JOIN {schema}.registry_outbox AS outbox ON outbox.event_id=state.event_id
         WHERE state.updated_at <= $1
           AND (state.state='delivered'
             OR (state.state IN ('expired','dead-lettered')
                 AND state.expired_at <= $1 AND outbox.payload IS NULL
                 AND outbox.payload_expires_at <= $1))
         ORDER BY state.updated_at, state.event_id, state.compiled_delivery_id
         LIMIT {MAX_PRUNE_BATCH} FOR UPDATE OF state, outbox SKIP LOCKED"
            ),
            &[&before],
        )
        .await
        .map_err(|_| DeliveryError::Unavailable)?;
    let keys = rows
        .into_iter()
        .map(|row| JobKey::new(row.get(0), row.get::<_, String>(1)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DeliveryError::Unavailable)?;
    let deleted = prune_terminal(transaction, &table, &keys, before)
        .await
        .map_err(|_| DeliveryError::Unavailable)?;
    for key in &deleted {
        transaction.execute(&format!(
            "DELETE FROM {schema}.registry_webhook_deliveries WHERE event_id=$1 AND compiled_delivery_id=$2"
        ), &[&key.id(), &key.part()]).await.map_err(|_| DeliveryError::Unavailable)?;
        transaction
            .execute(
                &format!(
                    "DELETE FROM {schema}.registry_outbox AS outbox WHERE event_id=$1
             AND NOT EXISTS (SELECT 1 FROM {schema}.registry_webhook_deliveries AS delivery
                             WHERE delivery.event_id=outbox.event_id)"
                ),
                &[&key.id()],
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
    }
    Ok(deleted.len() as u64)
}
