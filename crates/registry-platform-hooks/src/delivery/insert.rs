// SPDX-License-Identifier: Apache-2.0

//! The neutral delivery INSERT: one captured delivery row and its pending
//! delivery state row, written inside the caller's transaction.
//!
//! This is the moved capture INSERT. The statements join the caller's
//! transaction and are rendered with the product's schema name, the way
//! [`crate::delivery_schema`] renders the tables; the stored vocabulary
//! values in the capture (`classification_ceiling`, `authentication_profile`,
//! `delivery_mode`, `dead_letter`) are the delivery tables' own, so the
//! product maps its vocabulary onto them before capturing.

use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::seams::DeliveryError;
use crate::delivery_schema;

/// The product-owned capture of one delivery: everything the INSERT needs,
/// already resolved from the product's compiled authority and its activated
/// deployment binding.
pub struct DeliveryCapture<'a> {
    pub compiled_delivery_id: &'a str,
    pub logical_destination_id: &'a str,
    /// Digest of the exact binding this delivery was captured under.
    pub destination_binding_digest: &'a str,
    pub package_revision: &'a str,
    pub schema_fingerprint: &'a str,
    pub data_schema: &'a str,
    /// The delivery table's stored classification ceiling.
    pub classification_ceiling: &'a str,
    /// The delivery table's stored authentication profile.
    pub authentication_profile: &'a str,
    /// The delivery table's stored delivery mode.
    pub delivery_mode: &'a str,
    pub attempt_timeout_ms: i64,
    pub initial_backoff_ms: i64,
    pub maximum_backoff_ms: i64,
    pub exponential_backoff_multiplier: i16,
    pub maximum_attempts: i16,
    /// The frozen retry delays for attempts two and onward.
    pub retry_delays_ms: &'a [i64],
    pub maximum_payload_bytes: i64,
    /// The canonical payload bytes; their SHA-256 digest is computed here.
    pub payload: &'a [u8],
    pub deployed_attempt_timeout_ms: i64,
    pub deployed_maximum_attempts: i16,
    /// The delivery table's stored dead-letter mode.
    pub dead_letter: &'a str,
    pub operator_replay: bool,
}

/// Insert one captured delivery and its pending delivery state.
///
/// Joins the caller's transaction; this function performs no transaction
/// management of its own.
///
/// # Panics
///
/// Panics when `schema` is not a plain lowercase SQL identifier of at most 63
/// bytes, because the schema name is interpolated into the statements.
pub async fn insert_delivery(
    transaction: &Transaction<'_>,
    schema: &str,
    event_id: Uuid,
    capture: DeliveryCapture<'_>,
) -> Result<(), DeliveryError> {
    let schema = delivery_schema::require_plain_identifier(schema);
    let DeliveryCapture {
        compiled_delivery_id,
        logical_destination_id,
        destination_binding_digest,
        package_revision,
        schema_fingerprint,
        data_schema,
        classification_ceiling,
        authentication_profile,
        delivery_mode,
        attempt_timeout_ms,
        initial_backoff_ms,
        maximum_backoff_ms,
        exponential_backoff_multiplier,
        maximum_attempts,
        retry_delays_ms,
        maximum_payload_bytes,
        payload,
        deployed_attempt_timeout_ms,
        deployed_maximum_attempts,
        dead_letter,
        operator_replay,
    } = capture;
    let payload_digest = Sha256::digest(payload).to_vec();
    let changed = transaction
        .execute(
            &delivery_schema::render(
                schema,
                "INSERT INTO {schema}.registry_webhook_deliveries
                 (event_id, compiled_delivery_id, logical_destination_id,
                  destination_binding_digest, package_revision, schema_fingerprint,
                  data_schema,
                  classification_ceiling, authentication_profile, delivery_mode,
                  attempt_timeout_ms, initial_backoff_ms, maximum_backoff_ms,
                  exponential_backoff_multiplier, maximum_attempts, retry_delays_ms,
                  maximum_payload_bytes, payload_digest, deployed_attempt_timeout_ms,
                  deployed_maximum_attempts, dead_letter, operator_replay)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                     $11, $12, $13, $14, $15, $16, $17, $18, $19,
                     $20, $21, $22)",
            ),
            &[
                &event_id,
                &compiled_delivery_id,
                &logical_destination_id,
                &destination_binding_digest,
                &package_revision,
                &schema_fingerprint,
                &data_schema,
                &classification_ceiling,
                &authentication_profile,
                &delivery_mode,
                &attempt_timeout_ms,
                &initial_backoff_ms,
                &maximum_backoff_ms,
                &exponential_backoff_multiplier,
                &maximum_attempts,
                &retry_delays_ms,
                &maximum_payload_bytes,
                &payload_digest,
                &deployed_attempt_timeout_ms,
                &deployed_maximum_attempts,
                &dead_letter,
                &operator_replay,
            ],
        )
        .await?;
    if changed != 1 {
        return Err(DeliveryError::Unavailable);
    }
    let changed = transaction
        .execute(
            &delivery_schema::render(
                schema,
                "INSERT INTO {schema}.registry_webhook_delivery_state
                 (event_id, compiled_delivery_id, generation, state, attempt, next_attempt_at)
             VALUES ($1, $2, 1, 'pending', 0, transaction_timestamp())",
            ),
            &[&event_id, &compiled_delivery_id],
        )
        .await?;
    if changed != 1 {
        return Err(DeliveryError::Unavailable);
    }
    Ok(())
}
