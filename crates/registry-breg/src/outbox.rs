// SPDX-License-Identifier: Apache-2.0

//! Immutable configured events created inside the owning record transaction.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use registry_platform_hooks::delivery::DeliveryCapture;
use registry_platform_hooks::{Causation, EnvelopeLimits, EventSubject, HookEnvelope};
use serde_json::{json, Map, Value};
use time::OffsetDateTime;
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::artifacts::event_data_schema_binding;
use crate::contract::{
    Classification, EventConditionSource, EventScalarValue, EventTrigger, HookSource,
    WebhookAuthenticationProfile, WebhookDeadLetterMode,
};
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::history_schema::tagged_envelope_member;
use crate::model::{CompiledEntity, CompiledEventDelivery, CompiledWebhookDeliveryMode};
use crate::webhook::DELIVERY_SCHEMA;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OutboxError {
    #[error("configured event projection is invalid")]
    InvalidProjection,
    #[error("mutation outbox is unavailable")]
    Unavailable,
}

/// The deployment identity and chain position every captured envelope carries.
#[doc(hidden)]
pub struct EnvelopeBinding<'a> {
    /// The producing deployment, the same source the delivery worker renders
    /// as the `ce-source` header.
    pub source: &'a str,
    /// The data contract id for each hook's `data`, by hook id.
    pub data_schemas: &'a BTreeMap<String, String>,
    /// The chain this capture belongs to. `None` starts a new chain at the
    /// captured event; a capture caused by an earlier event passes the child
    /// causation that event produced.
    pub causation: Option<&'a Causation>,
}

pub(crate) struct OutboxMutation<'a> {
    pub trigger: EventTrigger,
    pub application_reference: Option<&'a str>,
    pub entity_id: &'a str,
    pub record_id: &'a str,
    pub record_reference: &'a str,
    pub record_revision: i64,
    pub package_revision: &'a str,
    pub schema_fingerprint: &'a str,
    pub before: Option<&'a Map<String, Value>>,
    pub after: Option<&'a Map<String, Value>>,
    pub payload_retention: Duration,
    pub envelope: EnvelopeBinding<'a>,
}

/// One captured event, before it becomes envelope bytes.
pub(crate) struct CapturedEvent<'a> {
    pub event_id: Uuid,
    pub event_type: &'a str,
    pub created_at: OffsetDateTime,
    pub record_reference: &'a str,
    pub record_revision: i64,
    pub data: Value,
}

/// Build the shared hook envelope one captured event is stored and delivered
/// as. `data` is the product projection, carried unchanged.
pub(crate) fn capture_envelope(
    binding: &EnvelopeBinding<'_>,
    event: CapturedEvent<'_>,
) -> Result<HookEnvelope, OutboxError> {
    let id = event.event_id.to_string();
    let causation = binding
        .causation
        .cloned()
        .unwrap_or_else(|| Causation::root(&id));
    let dataschema = binding
        .data_schemas
        .get(event.event_type)
        .ok_or(OutboxError::InvalidProjection)?
        .clone();
    Ok(HookEnvelope {
        id,
        event_type: event.event_type.to_owned(),
        source: binding.source.to_owned(),
        time: event.created_at,
        subject: EventSubject {
            record_reference: event.record_reference.to_owned(),
            record_revision: event.record_revision,
        },
        dataschema,
        data: event.data,
        causation,
    })
}

/// The canonical envelope bytes the outbox stores and the worker delivers
/// unchanged.
///
/// `maximum_payload_bytes` is the compiled per-delivery bound. It measures the
/// whole envelope, not the `data` object alone; an event with no compiled
/// delivery carries the store's own 2 MiB bound.
pub(crate) fn envelope_payload(
    envelope: &HookEnvelope,
    maximum_payload_bytes: Option<u32>,
) -> Result<Vec<u8>, OutboxError> {
    let limits = match maximum_payload_bytes {
        Some(bytes) => EnvelopeLimits::tightened_to(
            usize::try_from(bytes).map_err(|_| OutboxError::InvalidProjection)?,
        ),
        None => EnvelopeLimits::default(),
    };
    envelope
        .to_canonical_bytes(&limits)
        .map_err(|_| OutboxError::InvalidProjection)
}

/// Resolve the data contract id of every hook of `entity` that `trigger` fires.
///
/// A hook with a compiled delivery carries the id the compiler already proved.
/// A hook without one still writes an outbox row, so its id is derived from the
/// same binding the compiler derives it from.
pub(crate) fn event_data_schemas(
    registry_id: &str,
    entity: &CompiledEntity,
    trigger: EventTrigger,
    deliveries: &[CompiledEventDelivery],
) -> Result<BTreeMap<String, String>, OutboxError> {
    entity
        .hooks
        .values()
        .filter(|event| event.trigger == trigger)
        .map(|event| {
            let data_schema = match deliveries
                .iter()
                .find(|delivery| delivery.event_id == event.id)
            {
                Some(delivery) => delivery.data_schema.clone(),
                None => {
                    event_data_schema_binding(registry_id, entity, event)
                        .map_err(|_| OutboxError::InvalidProjection)?
                        .data_schema
                }
            };
            Ok((event.id.clone(), data_schema))
        })
        .collect()
}

/// The commit instant every envelope of one transaction carries.
///
/// Truncated to the millisecond the envelope's wire form spells, and written to
/// the outbox row so the delivery worker's `ce-time` header repeats the
/// envelope's own `time` byte for byte.
pub(crate) async fn capture_time(transaction: &Transaction<'_>) -> Result<SystemTime, OutboxError> {
    transaction
        .query_one(
            "SELECT date_trunc('milliseconds', transaction_timestamp())",
            &[],
        )
        .await
        .map_err(|_| OutboxError::Unavailable)?
        .try_get::<_, SystemTime>(0)
        .map_err(|_| OutboxError::Unavailable)
}

pub(crate) async fn insert_configured_events(
    transaction: &Transaction<'_>,
    events: &BTreeMap<String, HookSource>,
    deliveries: &[CompiledEventDelivery],
    destinations: Option<&ActivatedEventDestinationRegistry>,
    mutation: OutboxMutation<'_>,
) -> Result<(), OutboxError> {
    let mut captured_at = None;
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
        let values = projected_event_values(&projection_fields, snapshot)?;
        let data = json!({
            "entity": mutation.entity_id,
            "recordId": mutation.record_id,
            "revision": mutation.record_revision,
            "trigger": trigger_name(mutation.trigger),
            "packageRevision": mutation.package_revision,
            "values": values,
        });
        let event_id = Uuid::new_v4();
        let created_at = match captured_at {
            Some(created_at) => created_at,
            None => {
                let created_at = capture_time(transaction).await?;
                captured_at = Some(created_at);
                created_at
            }
        };
        let envelope = capture_envelope(
            &mutation.envelope,
            CapturedEvent {
                event_id,
                event_type: &event.id,
                created_at: OffsetDateTime::from(created_at),
                record_reference: mutation.record_reference,
                record_revision: mutation.record_revision,
                data,
            },
        )?;
        let payload = envelope_payload(
            &envelope,
            delivery.map(|delivery| delivery.maximum_payload_bytes),
        )?;
        let activated = delivery
            .map(|delivery| activate_delivery(delivery, destinations))
            .transpose()?;
        let retention_milliseconds = i64::try_from(mutation.payload_retention.as_millis())
            .ok()
            .filter(|value| (86_400_000..=2_592_000_000).contains(value))
            .ok_or(OutboxError::Unavailable)?;
        // Capture time is written explicitly rather than left to the column
        // default, because the envelope spells the same instant and payload
        // expiry is measured from it.
        let changed = transaction
            .execute(
                "INSERT INTO registry_internal.registry_outbox
                     (event_id, event_type, trigger, entity_id, record_reference,
                      record_revision, application_reference, package_revision, schema_fingerprint,
                      payload, created_at, payload_expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                         $11::timestamptz + $12::bigint * interval '1 millisecond')",
                &[
                    &event_id,
                    &event.id,
                    &trigger_name(mutation.trigger),
                    &mutation.entity_id,
                    &mutation.record_reference,
                    &mutation.record_revision,
                    &mutation.application_reference,
                    &mutation.package_revision,
                    &mutation.schema_fingerprint,
                    &payload,
                    &created_at,
                    &retention_milliseconds,
                ],
            )
            .await
            .map_err(|_| OutboxError::Unavailable)?;
        if changed != 1 {
            return Err(OutboxError::Unavailable);
        }
        if let Some(activated) = activated {
            insert_webhook_delivery(
                transaction,
                event_id,
                WebhookCapture {
                    activated: &activated,
                    payload: &payload,
                    package_revision: mutation.package_revision,
                    schema_fingerprint: mutation.schema_fingerprint,
                },
            )
            .await?;
        }
    }
    Ok(())
}

/// Project the event's fields out of the trigger snapshot.
///
/// A missing field and a tagged envelope member both refuse the projection:
/// the compiler refuses event projections naming encrypted fields, so an
/// envelope member reaching here means that boundary was bypassed, and a
/// sealed value must never enter an outbox payload.
fn projected_event_values(
    projection_fields: &[&str],
    snapshot: &Map<String, Value>,
) -> Result<Map<String, Value>, OutboxError> {
    let mut values = Map::new();
    for field in projection_fields {
        let value = snapshot
            .get(*field)
            .filter(|value| !tagged_envelope_member(value))
            .ok_or(OutboxError::InvalidProjection)?;
        values.insert((*field).to_owned(), value.clone());
    }
    Ok(values)
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
    pub activated: &'a ActivatedDelivery<'a>,
    pub payload: &'a [u8],
    pub package_revision: &'a str,
    pub schema_fingerprint: &'a str,
}

/// One compiled delivery paired with the identity and budgets it is captured
/// under.
///
/// A `url` delivery takes them from the operator's bound destination. A local
/// delivery has no destination to bind, so it is captured under the reviewed
/// program's digest and the compiled budgets themselves.
pub(crate) struct ActivatedDelivery<'a> {
    pub delivery: &'a CompiledEventDelivery,
    pub binding_digest: &'a str,
    pub attempt_timeout: std::time::Duration,
    pub maximum_attempts: u8,
}

pub(crate) fn activate_delivery<'a>(
    delivery: &'a CompiledEventDelivery,
    destinations: Option<&'a ActivatedEventDestinationRegistry>,
) -> Result<ActivatedDelivery<'a>, OutboxError> {
    let Some(logical_destination_id) = delivery.destination_id.as_deref() else {
        // A local handler is bound to its reviewed program, not to an
        // operator destination, and the compiled budgets are the deployed
        // ones because no configuration can lower them.
        let binding_digest = delivery.handler_digest().ok_or(OutboxError::Unavailable)?;
        return Ok(ActivatedDelivery {
            delivery,
            binding_digest,
            attempt_timeout: std::time::Duration::from_millis(u64::from(
                delivery.attempt_timeout_ms,
            )),
            maximum_attempts: delivery.maximum_attempts,
        });
    };
    let destination = destinations
        .and_then(|destinations| destinations.lookup(logical_destination_id))
        .ok_or(OutboxError::Unavailable)?;
    let deployed_attempt_timeout = u32::try_from(destination.attempt_timeout().as_millis())
        .map_err(|_| OutboxError::Unavailable)?;
    if deployed_attempt_timeout > delivery.attempt_timeout_ms
        || destination.maximum_attempts() > delivery.maximum_attempts
    {
        return Err(OutboxError::Unavailable);
    }
    Ok(ActivatedDelivery {
        delivery,
        binding_digest: destination.binding_digest(),
        attempt_timeout: destination.attempt_timeout(),
        maximum_attempts: destination.maximum_attempts(),
    })
}

/// Capture one webhook delivery through the platform delivery INSERT, under
/// Base Registry Engine's schema and stored vocabulary.
pub(crate) async fn insert_webhook_delivery(
    transaction: &Transaction<'_>,
    event_id: Uuid,
    capture: WebhookCapture<'_>,
) -> Result<(), OutboxError> {
    let WebhookCapture {
        activated,
        payload,
        package_revision,
        schema_fingerprint,
    } = capture;
    let &ActivatedDelivery {
        delivery,
        binding_digest,
        attempt_timeout,
        maximum_attempts,
    } = activated;
    let retry_delays_ms = delivery
        .retry_delays_ms
        .iter()
        .copied()
        .map(i64::from)
        .collect::<Vec<_>>();
    let deployed_attempt_timeout_ms =
        i64::try_from(attempt_timeout.as_millis()).map_err(|_| OutboxError::Unavailable)?;
    registry_platform_hooks::delivery::insert_delivery(
        transaction,
        DELIVERY_SCHEMA,
        event_id,
        DeliveryCapture {
            compiled_delivery_id: &delivery.id,
            handler_kind: delivery.handler_kind(),
            logical_destination_id: delivery.destination_id.as_deref(),
            destination_binding_digest: binding_digest,
            package_revision,
            schema_fingerprint,
            data_schema: &delivery.data_schema,
            classification_ceiling: classification_name(delivery.classification_ceiling),
            authentication_profile: authentication_profile_name(delivery.authentication_profile),
            delivery_mode: delivery_mode_name(delivery.delivery_mode),
            attempt_timeout_ms: i64::from(delivery.attempt_timeout_ms),
            initial_backoff_ms: i64::from(delivery.initial_backoff_ms),
            maximum_backoff_ms: i64::from(delivery.maximum_backoff_ms),
            exponential_backoff_multiplier: i16::from(delivery.exponential_backoff_multiplier),
            maximum_attempts: i16::from(delivery.maximum_attempts),
            retry_delays_ms: &retry_delays_ms,
            maximum_payload_bytes: i64::from(delivery.maximum_payload_bytes),
            payload,
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts: i16::from(maximum_attempts),
            dead_letter: dead_letter_name(delivery.dead_letter),
            operator_replay: delivery.operator_replay,
        },
    )
    .await
    .map_err(|_| OutboxError::Unavailable)
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

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT_ID: &str = "4e2f6d6c-6f0a-4c2f-9c1a-2d0f7a8b6c51";
    const SOURCE: &str = "urn:registrystack:registry:permits:instance:eu-west-1";
    const DATA_SCHEMA: &str = "urn:breg:event-schema:permits:permit:permit.granted:sha256:\
        3f786850e387550fdab836ed7e6dc881de23001b";

    fn data_schemas() -> BTreeMap<String, String> {
        BTreeMap::from([("permit.granted".to_owned(), DATA_SCHEMA.to_owned())])
    }

    fn captured(data: Value) -> CapturedEvent<'static> {
        CapturedEvent {
            event_id: Uuid::parse_str(EVENT_ID).expect("event id"),
            event_type: "permit.granted",
            created_at: OffsetDateTime::from_unix_timestamp_nanos(1_767_225_600_123_000_000)
                .expect("capture instant"),
            record_reference:
                "hmac-sha256:8f14e45fceea467a9cc18b2a4b9e2a1103b41d5ad4c88c8f2a0a9ac4f4c0d2b7",
            record_revision: 3,
            data,
        }
    }

    fn projection() -> Value {
        json!({
            "entity": "permit",
            "recordId": "8f14e45f-ceea-467a-9cc1-8b2a4b9e2a11",
            "revision": 3,
            "trigger": "created",
            "packageRevision": "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
            "values": { "status": "granted" },
        })
    }

    #[test]
    fn capture_carries_the_product_projection_unchanged() {
        let schemas = data_schemas();
        let binding = EnvelopeBinding {
            source: SOURCE,
            data_schemas: &schemas,
            causation: None,
        };
        let envelope = capture_envelope(&binding, captured(projection())).expect("envelope");
        assert_eq!(envelope.data, projection());
        assert_eq!(envelope.id, EVENT_ID);
        assert_eq!(envelope.causation, Causation::root(EVENT_ID));
        assert_eq!(envelope.dataschema, DATA_SCHEMA);
        assert_eq!(
            envelope.subject.record_reference,
            "hmac-sha256:8f14e45fceea467a9cc18b2a4b9e2a1103b41d5ad4c88c8f2a0a9ac4f4c0d2b7"
        );
        assert_eq!(envelope.subject.record_revision, 3);
    }

    #[test]
    fn capture_refuses_a_hook_without_a_data_contract() {
        let schemas = BTreeMap::new();
        let binding = EnvelopeBinding {
            source: SOURCE,
            data_schemas: &schemas,
            causation: None,
        };
        assert_eq!(
            capture_envelope(&binding, captured(projection())).unwrap_err(),
            OutboxError::InvalidProjection
        );
    }

    #[test]
    fn envelope_payload_is_the_canonical_wire_form() {
        let schemas = data_schemas();
        let binding = EnvelopeBinding {
            source: SOURCE,
            data_schemas: &schemas,
            causation: None,
        };
        let envelope = capture_envelope(&binding, captured(projection())).expect("envelope");
        let payload = envelope_payload(&envelope, None).expect("payload");
        let expected = concat!(
            r#"{"causation":{"hop":0,"root":"4e2f6d6c-6f0a-4c2f-9c1a-2d0f7a8b6c51"},"#,
            r#""data":{"entity":"permit","packageRevision":"sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03","#,
            r#""recordId":"8f14e45f-ceea-467a-9cc1-8b2a4b9e2a11","revision":3,"#,
            r#""trigger":"created","values":{"status":"granted"}},"#,
            r#""dataschema":"urn:breg:event-schema:permits:permit:permit.granted:sha256:3f786850e387550fdab836ed7e6dc881de23001b","#,
            r#""id":"4e2f6d6c-6f0a-4c2f-9c1a-2d0f7a8b6c51","#,
            r#""source":"urn:registrystack:registry:permits:instance:eu-west-1","#,
            r#""subject":{"recordReference":"hmac-sha256:8f14e45fceea467a9cc18b2a4b9e2a1103b41d5ad4c88c8f2a0a9ac4f4c0d2b7","recordRevision":3},"#,
            r#""time":"2026-01-01T00:00:00.123Z","type":"permit.granted"}"#,
        );
        assert_eq!(String::from_utf8(payload.clone()).expect("utf-8"), expected);
        let decoded = HookEnvelope::from_canonical_bytes(&payload, &EnvelopeLimits::default())
            .expect("round trip");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.data, projection());
    }

    #[test]
    fn the_delivery_ceiling_bounds_envelope_bytes_not_data_bytes() {
        let schemas = data_schemas();
        let binding = EnvelopeBinding {
            source: SOURCE,
            data_schemas: &schemas,
            causation: None,
        };
        let envelope = capture_envelope(&binding, captured(projection())).expect("envelope");
        let payload = envelope_payload(&envelope, None).expect("payload");
        let data_bytes = serde_json::to_vec(&envelope.data)
            .expect("data bytes")
            .len();
        assert!(data_bytes < payload.len());
        let between = u32::try_from(data_bytes + 1).expect("bound");
        assert!(usize::try_from(between).expect("bound") < payload.len());
        assert_eq!(
            envelope_payload(&envelope, Some(between)).unwrap_err(),
            OutboxError::InvalidProjection
        );
        let exact = u32::try_from(payload.len()).expect("bound");
        assert_eq!(
            envelope_payload(&envelope, Some(exact)).expect("payload"),
            payload
        );
    }

    /// The compile-time envelope wrapper proof against the widest envelope the
    /// runtime can build for one hook.
    ///
    /// Every member is at its own bound: an instance id of exactly
    /// `MAX_BUILD_ID_BYTES` in `source`, a caused chain so `causation` carries
    /// a parent, the longest audit reference prefix and the largest positive
    /// revision in `subject`, and a capture instant that spells its
    /// milliseconds. The wrapper the compiler proves must be exactly the bytes
    /// the canonical form spends outside `data`, so the compile-time refusal
    /// and the runtime ceiling measure one document.
    #[test]
    fn the_compiled_envelope_wrapper_matches_the_widest_canonical_wrapper() {
        const REGISTRY_ID: &str = "widest-registry-identifier";
        const ENTITY_ID: &str = "widest-entity-identifier";
        const EVENT_ID: &str = "widest-event-identifier";
        let source = crate::webhook::delivery_source(
            REGISTRY_ID,
            &"i".repeat(crate::compiler::MAX_BUILD_ID_BYTES as usize),
        );
        let data_schema = format!(
            "urn:breg:event-schema:{REGISTRY_ID}:{ENTITY_ID}:{EVENT_ID}:sha256:{}",
            "e".repeat(64)
        );
        let schemas = BTreeMap::from([(EVENT_ID.to_owned(), data_schema)]);
        let parent = Causation::root("2b8f0a24-6a1e-4a0e-9b5d-6c7f0a3d1e42");
        let caused = parent
            .child("2b8f0a24-6a1e-4a0e-9b5d-6c7f0a3d1e42")
            .expect("child causation");
        let binding = EnvelopeBinding {
            source: &source,
            data_schemas: &schemas,
            causation: Some(&caused),
        };
        let record_reference = format!("hmac-sha256:{}", "f".repeat(64));
        let envelope = capture_envelope(
            &binding,
            CapturedEvent {
                event_id: Uuid::parse_str("4e2f6d6c-6f0a-4c2f-9c1a-2d0f7a8b6c51")
                    .expect("event id"),
                event_type: EVENT_ID,
                created_at: OffsetDateTime::from_unix_timestamp_nanos(1_767_225_600_123_000_000)
                    .expect("capture instant"),
                record_reference: &record_reference,
                // The largest i64 canonical JSON accepts, and the widest
                // decimal spelling any revision can reach: 2^63 - 2^10.
                record_revision: 9_223_372_036_854_774_784,
                data: projection(),
            },
        )
        .expect("envelope");
        let payload = envelope_payload(&envelope, None).expect("payload");
        let data_bytes = registry_platform_canonical_json::canonicalize_json(&envelope.data)
            .expect("canonical data")
            .len();
        let wrapper =
            crate::compiler::maximum_envelope_wrapper_bytes(REGISTRY_ID, ENTITY_ID, EVENT_ID)
                .expect("wrapper bound");
        assert_eq!(
            u64::try_from(payload.len() - data_bytes).expect("bound"),
            wrapper
        );
    }

    /// The wrapper proof budgets `source`'s instance id at its raw byte
    /// length, `compiler::MAX_BUILD_ID_BYTES`, so the budget only holds while
    /// `package::valid_build_id` accepts nothing longer and no byte its
    /// grammar admits needs JSON escaping. The runtime deployment identity
    /// cannot extend the value either: startup holds it to exact equality
    /// with the package manifest identity, whose instance id `valid_build_id`
    /// already bound at package build.
    #[test]
    fn the_widest_build_id_fits_the_envelope_source_term_unescaped() {
        let widest = "i".repeat(crate::compiler::MAX_BUILD_ID_BYTES as usize);
        assert!(crate::package::valid_build_id(&widest));
        let past_the_bound = format!("i{widest}");
        assert!(!crate::package::valid_build_id(&past_the_bound));
        // Bytes serde_json would escape must stay outside the grammar, or the
        // serialized spelling would outgrow the raw byte budget.
        for escaped in ['"', '\\', '\n', '\r', '\t'] {
            assert!(!crate::package::valid_build_id(&format!("a{escaped}")));
        }
        let source = crate::webhook::delivery_source("widest-registry-identifier", &widest);
        let serialized = serde_json::to_string(&source).expect("serialized source");
        assert_eq!(serialized.len(), 2 + source.len());
    }

    #[test]
    fn a_caused_capture_keeps_the_chain_it_was_given() {
        let schemas = data_schemas();
        let parent = Causation::root("2b8f0a24-6a1e-4a0e-9b5d-6c7f0a3d1e42");
        let caused = parent
            .child("2b8f0a24-6a1e-4a0e-9b5d-6c7f0a3d1e42")
            .expect("child causation");
        let binding = EnvelopeBinding {
            source: SOURCE,
            data_schemas: &schemas,
            causation: Some(&caused),
        };
        let envelope = capture_envelope(&binding, captured(projection())).expect("envelope");
        assert_eq!(envelope.causation, caused);
        assert_eq!(envelope.causation.hop, 1);
    }

    #[test]
    fn event_projection_refuses_envelope_members_and_missing_fields() {
        let mut snapshot = Map::new();
        snapshot.insert("label".to_owned(), json!("visible"));
        snapshot.insert(
            "secret".to_owned(),
            json!({ crate::history_schema::ENVELOPE_MEMBER_TAG: "c2VhbGVk"}),
        );
        let projected =
            projected_event_values(&["label"], &snapshot).expect("plaintext fields project");
        assert_eq!(projected.get("label"), Some(&json!("visible")));
        assert!(projected_event_values(&["missing"], &snapshot).is_err());
        assert!(
            projected_event_values(&["secret"], &snapshot).is_err(),
            "a sealed member must never enter an outbox payload"
        );
    }
}
