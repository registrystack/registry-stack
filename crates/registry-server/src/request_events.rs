// SPDX-License-Identifier: Apache-2.0

//! Classified change-request lifecycle events captured in the request transaction.

use std::collections::BTreeMap;
use std::time::Duration;

use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::contract::{EventConditionSource, EventSource, EventTrigger};
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::model::CompiledEventDelivery;
use crate::outbox::{insert_webhook_delivery, OutboxError, WebhookCapture};

#[doc(hidden)]
pub struct RequestLifecycleEvent<'a> {
    pub request_entity_id: &'a str,
    pub request_id: Uuid,
    pub request_record_reference: &'a str,
    pub request_record_revision: i64,
    pub proposal_version: u32,
    pub workflow_revision: u64,
    pub from_state: &'a str,
    pub to_state: &'a str,
    pub transition: &'a str,
    pub stage_id: Option<&'a str>,
    pub effect_digest: Option<&'a str>,
    pub package_revision: &'a str,
    pub schema_fingerprint: &'a str,
    pub request_values: &'a Map<String, Value>,
    pub payload_retention: Duration,
}

#[doc(hidden)]
pub async fn insert_request_lifecycle_events(
    transaction: &Transaction<'_>,
    events: &BTreeMap<String, EventSource>,
    deliveries: &[CompiledEventDelivery],
    destinations: Option<&ActivatedEventDestinationRegistry>,
    event: RequestLifecycleEvent<'_>,
) -> Result<(), OutboxError> {
    if event.request_record_revision <= 0
        || event.proposal_version == 0
        || event.workflow_revision == 0
        || event.request_entity_id.is_empty()
        || event.from_state.is_empty()
        || event.to_state.is_empty()
        || event.transition.is_empty()
    {
        return Err(OutboxError::InvalidProjection);
    }

    for source in events
        .values()
        .filter(|source| source.trigger == EventTrigger::RequestLifecycle)
    {
        if !lifecycle_condition_matches(source.when.as_ref(), &event)? {
            continue;
        }
        let delivery = deliveries
            .iter()
            .find(|delivery| delivery.event_id == source.id);
        let projection_fields = delivery.map_or_else(
            || {
                source
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
        let mut values = Map::new();
        for field in projection_fields {
            let value = event
                .request_values
                .get(field)
                .ok_or(OutboxError::InvalidProjection)?;
            values.insert(field.to_owned(), value.clone());
        }

        let deduplication_key = lifecycle_deduplication_key(&source.id, &event);
        let payload = canonicalize_json(&json!({
            "entity": event.request_entity_id,
            "recordId": event.request_id.to_string(),
            "revision": event.request_record_revision,
            "trigger": "request_lifecycle",
            "packageRevision": event.package_revision,
            "request": {
                "proposalVersion": event.proposal_version,
                "workflowRevision": event.workflow_revision,
                "transition": event.transition,
                "fromState": event.from_state,
                "toState": event.to_state,
                "stage": event.stage_id,
                "effectDigest": event.effect_digest,
                "deduplicationKey": deduplication_key,
            },
            "values": values,
        }))
        .map_err(|_| OutboxError::InvalidProjection)?;
        let activated = if let Some(delivery) = delivery {
            if delivery.trigger != EventTrigger::RequestLifecycle {
                return Err(OutboxError::InvalidProjection);
            }
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
        let retention_milliseconds = i64::try_from(event.payload_retention.as_millis())
            .ok()
            .filter(|value| (86_400_000..=2_592_000_000).contains(value))
            .ok_or(OutboxError::Unavailable)?;
        let event_id = lifecycle_event_id(&source.id, &event);
        let changed = transaction
            .execute(
                "INSERT INTO registry_internal.registry_outbox
                     (event_id, event_type, trigger, entity_id, record_reference,
                      record_revision, package_revision, schema_fingerprint, payload,
                      payload_expires_at)
                 VALUES ($1, $2, 'request_lifecycle', $3, $4, $5, $6, $7, $8,
                         transaction_timestamp() + $9::bigint * interval '1 millisecond')
                 ON CONFLICT (event_id) DO NOTHING",
                &[
                    &event_id,
                    &source.id,
                    &event.request_entity_id,
                    &event.request_record_reference,
                    &event.request_record_revision,
                    &event.package_revision,
                    &event.schema_fingerprint,
                    &payload,
                    &retention_milliseconds,
                ],
            )
            .await
            .map_err(|_| OutboxError::Unavailable)?;
        if changed == 0 {
            verify_existing_event(transaction, event_id, &source.id, &payload).await?;
            continue;
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
                    package_revision: event.package_revision,
                    schema_fingerprint: event.schema_fingerprint,
                },
            )
            .await?;
        }
    }
    Ok(())
}

fn lifecycle_condition_matches(
    condition: Option<&EventConditionSource>,
    event: &RequestLifecycleEvent<'_>,
) -> Result<bool, OutboxError> {
    let Some(condition) = condition else {
        return Ok(true);
    };
    let EventConditionSource::RequestLifecycle {
        transitions,
        to_states,
        stages,
    } = condition
    else {
        return Err(OutboxError::InvalidProjection);
    };
    if !transitions.is_empty() && !transitions.contains(event.transition) {
        return Ok(false);
    }
    if !to_states.is_empty() && !to_states.contains(event.to_state) {
        return Ok(false);
    }
    if !stages.is_empty() && !event.stage_id.is_some_and(|stage| stages.contains(stage)) {
        return Ok(false);
    }
    Ok(true)
}

async fn verify_existing_event(
    transaction: &Transaction<'_>,
    event_id: Uuid,
    event_type: &str,
    payload: &[u8],
) -> Result<(), OutboxError> {
    let row = transaction
        .query_opt(
            "SELECT event_type, payload FROM registry_internal.registry_outbox
             WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .map_err(|_| OutboxError::Unavailable)?
        .ok_or(OutboxError::Unavailable)?;
    let existing_type = row
        .try_get::<_, String>(0)
        .map_err(|_| OutboxError::Unavailable)?;
    let existing_payload = row
        .try_get::<_, Option<Vec<u8>>>(1)
        .map_err(|_| OutboxError::Unavailable)?
        .ok_or(OutboxError::Unavailable)?;
    if existing_type == event_type && existing_payload == payload {
        Ok(())
    } else {
        Err(OutboxError::Unavailable)
    }
}

fn lifecycle_event_id(event_type: &str, event: &RequestLifecycleEvent<'_>) -> Uuid {
    let digest = lifecycle_digest(event_type, event);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn lifecycle_deduplication_key(event_type: &str, event: &RequestLifecycleEvent<'_>) -> String {
    format!(
        "sha256:{}",
        hex::encode(lifecycle_digest(event_type, event))
    )
}

// Proposal version, workflow revision, transition, and stage id are relied on to uniquely
// determine from_state, to_state, and effect_digest for one request lifecycle event, so this
// digest omits those three fields from its input; verify_existing_event catches any divergence
// when an insert reuses the event_id this digest derives.
fn lifecycle_digest(event_type: &str, event: &RequestLifecycleEvent<'_>) -> [u8; 32] {
    let mut input = Vec::new();
    append_length_prefixed(&mut input, b"registry-server-request-lifecycle-event-v1");
    append_length_prefixed(&mut input, event_type.as_bytes());
    append_length_prefixed(&mut input, event.package_revision.as_bytes());
    append_length_prefixed(&mut input, event.schema_fingerprint.as_bytes());
    append_length_prefixed(&mut input, event.request_entity_id.as_bytes());
    append_length_prefixed(&mut input, event.request_id.to_string().as_bytes());
    append_length_prefixed(&mut input, event.proposal_version.to_string().as_bytes());
    append_length_prefixed(&mut input, event.workflow_revision.to_string().as_bytes());
    append_length_prefixed(&mut input, event.transition.as_bytes());
    append_length_prefixed(&mut input, event.stage_id.unwrap_or("").as_bytes());
    let digest = Sha256::digest(input);
    digest.into()
}

fn append_length_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&value.len().to_be_bytes());
    out.extend_from_slice(value);
}
