// SPDX-License-Identifier: Apache-2.0

//! Immutable configured events created inside the owning record transaction.

use std::collections::BTreeMap;
use std::time::Duration;

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::contract::{
    Classification, EventConditionSource, EventScalarValue, EventSource, EventTrigger,
    WebhookAuthenticationProfile, WebhookDeadLetterMode,
};
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::model::{CompiledEventDelivery, CompiledWebhookDeliveryMode};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OutboxError {
    #[error("configured event projection is invalid")]
    InvalidProjection,
    #[error("mutation outbox is unavailable")]
    Unavailable,
}

pub(crate) struct OutboxMutation<'a> {
    pub trigger: EventTrigger,
    pub entity_id: &'a str,
    pub record_id: &'a str,
    pub record_reference: &'a str,
    pub record_revision: i64,
    pub package_revision: &'a str,
    pub schema_fingerprint: &'a str,
    pub before: Option<&'a Map<String, Value>>,
    pub after: Option<&'a Map<String, Value>>,
    pub payload_retention: Duration,
}

pub(crate) async fn insert_configured_events(
    transaction: &Transaction<'_>,
    events: &BTreeMap<String, EventSource>,
    deliveries: &[CompiledEventDelivery],
    destinations: Option<&ActivatedEventDestinationRegistry>,
    mutation: OutboxMutation<'_>,
) -> Result<(), OutboxError> {
    for event in events
        .values()
        .filter(|event| event.trigger == mutation.trigger)
    {
        if !condition_matches(event.when.as_ref(), mutation.before, mutation.after)? {
            continue;
        }
        let delivery = deliveries
            .iter()
            .find(|delivery| delivery.event_id == event.id);
        let projection_fields = delivery.map_or_else(
            || {
                event
                    .projection
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            },
            |delivery| {
                delivery
                    .projection_fields
                    .iter()
                    .map(String::as_str)
                    .collect()
            },
        );
        let snapshot = match mutation.trigger {
            EventTrigger::Created | EventTrigger::Patched => mutation.after,
            EventTrigger::Tombstoned => mutation.before,
            EventTrigger::RequestLifecycle => return Err(OutboxError::InvalidProjection),
        }
        .ok_or(OutboxError::InvalidProjection)?;
        let mut values = Map::new();
        for field in projection_fields {
            let value = snapshot.get(field).ok_or(OutboxError::InvalidProjection)?;
            values.insert(field.to_owned(), value.clone());
        }
        let payload = canonicalize_json(&json!({
            "entity": mutation.entity_id,
            "recordId": mutation.record_id,
            "revision": mutation.record_revision,
            "trigger": trigger_name(mutation.trigger),
            "packageRevision": mutation.package_revision,
            "values": values,
        }))
        .map_err(|_| OutboxError::InvalidProjection)?;
        let event_id = Uuid::new_v4();
        let activated = if let Some(delivery) = delivery {
            if payload.len()
                > usize::try_from(delivery.maximum_payload_bytes)
                    .map_err(|_| OutboxError::InvalidProjection)?
            {
                return Err(OutboxError::InvalidProjection);
            }
            let destination = destinations
                .and_then(|destinations| destinations.lookup(&delivery.destination_id))
                .ok_or(OutboxError::Unavailable)?;
            let deployed_attempt_timeout = u32::try_from(destination.attempt_timeout().as_millis())
                .map_err(|_| OutboxError::Unavailable)?;
            if deployed_attempt_timeout > delivery.attempt_timeout_ms
                || destination.maximum_attempts() > delivery.maximum_attempts
            {
                return Err(OutboxError::Unavailable);
            }
            Some((delivery, destination))
        } else {
            None
        };
        let retention_milliseconds = i64::try_from(mutation.payload_retention.as_millis())
            .ok()
            .filter(|value| (86_400_000..=2_592_000_000).contains(value))
            .ok_or(OutboxError::Unavailable)?;
        let changed = transaction
            .execute(
                "INSERT INTO registry_internal.registry_outbox
                     (event_id, event_type, trigger, entity_id, record_reference,
                      record_revision, package_revision, schema_fingerprint, payload,
                      payload_expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                         transaction_timestamp() + $10::bigint * interval '1 millisecond')",
                &[
                    &event_id,
                    &event.id,
                    &trigger_name(mutation.trigger),
                    &mutation.entity_id,
                    &mutation.record_reference,
                    &mutation.record_revision,
                    &mutation.package_revision,
                    &mutation.schema_fingerprint,
                    &payload,
                    &retention_milliseconds,
                ],
            )
            .await
            .map_err(|_| OutboxError::Unavailable)?;
        if changed != 1 {
            return Err(OutboxError::Unavailable);
        }
        if let Some((delivery, destination)) = activated {
            insert_webhook_delivery(
                transaction,
                event_id,
                WebhookCapture {
                    delivery,
                    payload: &payload,
                    destination_binding_digest: destination.binding_digest(),
                    deployed_attempt_timeout: destination.attempt_timeout(),
                    deployed_maximum_attempts: destination.maximum_attempts(),
                    package_revision: mutation.package_revision,
                    schema_fingerprint: mutation.schema_fingerprint,
                },
            )
            .await?;
        }
    }
    Ok(())
}

fn condition_matches(
    condition: Option<&EventConditionSource>,
    before: Option<&Map<String, Value>>,
    after: Option<&Map<String, Value>>,
) -> Result<bool, OutboxError> {
    let Some(condition) = condition else {
        return Ok(true);
    };
    let EventConditionSource::Fields {
        changed,
        before_equals,
        after_equals,
    } = condition
    else {
        return Err(OutboxError::InvalidProjection);
    };
    for field in changed {
        let before_value = before
            .and_then(|snapshot| snapshot.get(field))
            .ok_or(OutboxError::InvalidProjection)?;
        let after_value = after
            .and_then(|snapshot| snapshot.get(field))
            .ok_or(OutboxError::InvalidProjection)?;
        if before_value == after_value {
            return Ok(false);
        }
    }
    for (field, expected) in before_equals {
        let actual = before
            .and_then(|snapshot| snapshot.get(field))
            .ok_or(OutboxError::InvalidProjection)?;
        if actual != &scalar_value(expected) {
            return Ok(false);
        }
    }
    for (field, expected) in after_equals {
        let actual = after
            .and_then(|snapshot| snapshot.get(field))
            .ok_or(OutboxError::InvalidProjection)?;
        if actual != &scalar_value(expected) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn scalar_value(value: &EventScalarValue) -> Value {
    match value {
        EventScalarValue::Null => Value::Null,
        EventScalarValue::Boolean(value) => Value::Bool(*value),
        EventScalarValue::Number(value) => Value::Number(value.clone()),
        EventScalarValue::String(value) => Value::String(value.clone()),
    }
}

pub(crate) struct WebhookCapture<'a> {
    pub delivery: &'a CompiledEventDelivery,
    pub payload: &'a [u8],
    pub destination_binding_digest: &'a str,
    pub deployed_attempt_timeout: std::time::Duration,
    pub deployed_maximum_attempts: u8,
    pub package_revision: &'a str,
    pub schema_fingerprint: &'a str,
}

pub(crate) async fn insert_webhook_delivery(
    transaction: &Transaction<'_>,
    event_id: Uuid,
    capture: WebhookCapture<'_>,
) -> Result<(), OutboxError> {
    let WebhookCapture {
        delivery,
        payload,
        destination_binding_digest,
        deployed_attempt_timeout,
        deployed_maximum_attempts,
        package_revision,
        schema_fingerprint,
    } = capture;
    let retry_delays_ms = delivery
        .retry_delays_ms
        .iter()
        .copied()
        .map(i64::from)
        .collect::<Vec<_>>();
    let payload_digest = Sha256::digest(payload).to_vec();
    let deployed_attempt_timeout_ms = i64::try_from(deployed_attempt_timeout.as_millis())
        .map_err(|_| OutboxError::Unavailable)?;
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_webhook_deliveries
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
            &[
                &event_id,
                &delivery.id,
                &delivery.destination_id,
                &destination_binding_digest,
                &package_revision,
                &schema_fingerprint,
                &delivery.data_schema,
                &classification_name(delivery.classification_ceiling),
                &authentication_profile_name(delivery.authentication_profile),
                &delivery_mode_name(delivery.delivery_mode),
                &i64::from(delivery.attempt_timeout_ms),
                &i64::from(delivery.initial_backoff_ms),
                &i64::from(delivery.maximum_backoff_ms),
                &i16::from(delivery.exponential_backoff_multiplier),
                &i16::from(delivery.maximum_attempts),
                &retry_delays_ms,
                &i64::from(delivery.maximum_payload_bytes),
                &payload_digest,
                &deployed_attempt_timeout_ms,
                &i16::from(deployed_maximum_attempts),
                &dead_letter_name(delivery.dead_letter),
                &delivery.operator_replay,
            ],
        )
        .await
        .map_err(|_| OutboxError::Unavailable)?;
    if changed != 1 {
        return Err(OutboxError::Unavailable);
    }
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_webhook_delivery_state
                 (event_id, compiled_delivery_id, generation, state, attempt, next_attempt_at)
             VALUES ($1, $2, 1, 'pending', 0, transaction_timestamp())",
            &[&event_id, &delivery.id],
        )
        .await
        .map_err(|_| OutboxError::Unavailable)?;
    if changed != 1 {
        return Err(OutboxError::Unavailable);
    }
    Ok(())
}

fn classification_name(classification: Classification) -> &'static str {
    match classification {
        Classification::Public => "public",
        Classification::Internal => "internal",
        Classification::Restricted => "restricted",
    }
}

fn authentication_profile_name(profile: WebhookAuthenticationProfile) -> &'static str {
    match profile {
        WebhookAuthenticationProfile::HmacSha256V1 => "hmac_sha256_v1",
    }
}

fn delivery_mode_name(mode: CompiledWebhookDeliveryMode) -> &'static str {
    match mode {
        CompiledWebhookDeliveryMode::AfterCommit => "after_commit",
    }
}

fn dead_letter_name(mode: WebhookDeadLetterMode) -> &'static str {
    match mode {
        WebhookDeadLetterMode::Required => "required",
    }
}

fn trigger_name(trigger: EventTrigger) -> &'static str {
    match trigger {
        EventTrigger::Created => "created",
        EventTrigger::Patched => "patched",
        EventTrigger::Tombstoned => "tombstoned",
        EventTrigger::RequestLifecycle => "request_lifecycle",
    }
}
