// SPDX-License-Identifier: Apache-2.0
//! Webhook developer and operator workflows.
//!
//! This module renders offline examples from compiled authority and delegates
//! live inspection and replay to Registry Server. It deliberately owns no SQL,
//! signature construction, retry policy, or replay semantics.

use std::collections::BTreeMap;
use std::path::Path;

use registry_platform_canonical_json::canonicalize_json;
use registry_server::contract::{Crs84BboxSource, EventTrigger, FieldTypeSource};
use registry_server::model::CompiledRegistry;
use registry_server::webhook::{
    WebhookDeliveryStatus, WebhookDeliveryStatusKind, WebhookOperatorService,
    MAX_WEBHOOK_STATUS_RESULTS,
};
use serde::Serialize;
use serde_json::{json, Map, Number, Value};
use uuid::Uuid;

const SAMPLE_EVENT_ID: &str = "00000000-0000-4000-8000-000000000001";
const SAMPLE_RECORD_ID: &str = "00000000-0000-4000-8000-000000000002";
const SAMPLE_TIME: &str = "2026-01-01T00:00:00Z";
const SAMPLE_PACKAGE_REVISION: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const SAMPLE_IDEMPOTENCY_KEY: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const SAMPLE_REQUEST_TARGET: &str = "<configured-webhook-request-target>";
const SAMPLE_SIGNATURE: &str = "v1=<computed-at-delivery>";
const MAX_SCHEMA_SYNTHESIS_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebhookLifecycleError {
    Event,
    Sample,
    Operator,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WebhookSampleOutcome {
    pub event_id: String,
    pub request: WebhookSampleRequest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WebhookSampleRequest {
    pub method: &'static str,
    pub request_target: &'static str,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
    pub canonical_body: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WebhookListOutcome {
    pub deliveries: Vec<WebhookListItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WebhookListItem {
    pub event_id: String,
    pub delivery_id: String,
    pub generation: i64,
    pub state: &'static str,
    pub attempt: i16,
    pub payload_available: bool,
    pub payload_expires_at: String,
    pub replay_eligible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WebhookReplayOutcome {
    pub event_id: String,
    pub delivery_id: String,
    pub generation: i64,
}

pub(crate) fn sample(
    registry: &CompiledRegistry,
    authored_event_id: &str,
) -> Result<WebhookSampleOutcome, WebhookLifecycleError> {
    let delivery = registry
        .event_deliveries()
        .deliveries
        .iter()
        .find(|delivery| delivery.event_id == authored_event_id)
        .ok_or(WebhookLifecycleError::Event)?;
    let entity = registry
        .entities()
        .get(&delivery.entity_id)
        .ok_or(WebhookLifecycleError::Sample)?;
    let mut values = Map::new();
    for field_id in &delivery.projection_fields {
        let field = entity
            .fields
            .get(field_id)
            .ok_or(WebhookLifecycleError::Sample)?;
        let value = synthetic_field_value(&field.field_type)?;
        values.insert(field_id.clone(), value);
    }
    let body = json!({
        "entity": delivery.entity_id,
        "recordId": SAMPLE_RECORD_ID,
        "revision": 1,
        "trigger": trigger_name(delivery.trigger),
        "packageRevision": SAMPLE_PACKAGE_REVISION,
        "values": values,
    });
    let canonical_body_bytes =
        canonicalize_json(&body).map_err(|_| WebhookLifecycleError::Sample)?;
    let canonical_body =
        String::from_utf8(canonical_body_bytes).map_err(|_| WebhookLifecycleError::Sample)?;
    let headers = BTreeMap::from([
        ("Accept".to_owned(), "application/json".to_owned()),
        ("Content-Type".to_owned(), "application/json".to_owned()),
        (
            "Idempotency-Key".to_owned(),
            SAMPLE_IDEMPOTENCY_KEY.to_owned(),
        ),
        ("X-Registry-Delivery-Attempt".to_owned(), "1".to_owned()),
        (
            "X-Registry-Delivery-Time".to_owned(),
            SAMPLE_TIME.to_owned(),
        ),
        ("X-Registry-Event-Generation".to_owned(), "1".to_owned()),
        (
            "X-Registry-Signature".to_owned(),
            SAMPLE_SIGNATURE.to_owned(),
        ),
        ("ce-dataschema".to_owned(), delivery.data_schema.clone()),
        ("ce-id".to_owned(), SAMPLE_EVENT_ID.to_owned()),
        (
            "ce-source".to_owned(),
            format!(
                "urn:registrystack:registry:{}:instance:<configured-instance>",
                registry.registry_id()
            ),
        ),
        ("ce-specversion".to_owned(), "1.0".to_owned()),
        ("ce-time".to_owned(), SAMPLE_TIME.to_owned()),
        ("ce-type".to_owned(), delivery.event_id.clone()),
    ]);
    Ok(WebhookSampleOutcome {
        event_id: delivery.event_id.clone(),
        request: WebhookSampleRequest {
            method: "POST",
            request_target: SAMPLE_REQUEST_TARGET,
            headers,
            body,
            canonical_body,
        },
    })
}

pub(crate) fn list(
    runtime_config: &Path,
    limit: u16,
) -> Result<WebhookListOutcome, WebhookLifecycleError> {
    let runtime = operator_runtime()?;
    list_with(runtime_config, limit, |runtime_config, limit| {
        runtime.block_on(async {
            let service = WebhookOperatorService::from_runtime_config(runtime_config).await?;
            service.list(limit).await
        })
    })
}

fn list_with<E>(
    runtime_config: &Path,
    limit: u16,
    operation: impl FnOnce(&Path, u16) -> Result<Vec<WebhookDeliveryStatus>, E>,
) -> Result<WebhookListOutcome, WebhookLifecycleError> {
    if !runtime_config.is_absolute() || limit == 0 || limit > MAX_WEBHOOK_STATUS_RESULTS {
        return Err(WebhookLifecycleError::Operator);
    }
    let deliveries =
        operation(runtime_config, limit).map_err(|_| WebhookLifecycleError::Operator)?;
    Ok(WebhookListOutcome {
        deliveries: deliveries.into_iter().map(list_item).collect(),
    })
}

pub(crate) fn replay(
    runtime_config: &Path,
    event_id: &str,
    delivery_id: &str,
    expected_generation: i64,
) -> Result<WebhookReplayOutcome, WebhookLifecycleError> {
    let runtime = operator_runtime()?;
    replay_with(
        runtime_config,
        event_id,
        delivery_id,
        expected_generation,
        |runtime_config, event_id, delivery_id, expected_generation| {
            runtime.block_on(async {
                let service = WebhookOperatorService::from_runtime_config(runtime_config).await?;
                service
                    .replay(event_id, delivery_id, expected_generation)
                    .await
            })
        },
    )
}

fn replay_with<E>(
    runtime_config: &Path,
    event_id: &str,
    delivery_id: &str,
    expected_generation: i64,
    operation: impl FnOnce(&Path, Uuid, &str, i64) -> Result<i64, E>,
) -> Result<WebhookReplayOutcome, WebhookLifecycleError> {
    if !runtime_config.is_absolute()
        || delivery_id.is_empty()
        || delivery_id.len() > 256
        || expected_generation <= 0
    {
        return Err(WebhookLifecycleError::Operator);
    }
    let event_id = Uuid::parse_str(event_id).map_err(|_| WebhookLifecycleError::Operator)?;
    let generation = operation(runtime_config, event_id, delivery_id, expected_generation)
        .map_err(|_| WebhookLifecycleError::Operator)?;
    Ok(WebhookReplayOutcome {
        event_id: event_id.to_string(),
        delivery_id: delivery_id.to_owned(),
        generation,
    })
}

fn operator_runtime() -> Result<tokio::runtime::Runtime, WebhookLifecycleError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| WebhookLifecycleError::Operator)
}

fn list_item(status: WebhookDeliveryStatus) -> WebhookListItem {
    let (state, replay_eligible) = match status.state {
        WebhookDeliveryStatusKind::Pending => ("pending", false),
        WebhookDeliveryStatusKind::DeadLettered => ("dead_lettered", status.payload_available),
        WebhookDeliveryStatusKind::Expired => ("expired", false),
    };
    WebhookListItem {
        event_id: status.event_id.to_string(),
        delivery_id: status.compiled_delivery_id,
        generation: status.generation,
        state,
        attempt: status.attempt,
        payload_available: status.payload_available,
        payload_expires_at: status.payload_expires_at,
        replay_eligible,
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

fn synthetic_field_value(field_type: &FieldTypeSource) -> Result<Value, WebhookLifecycleError> {
    match field_type {
        FieldTypeSource::Boolean => Ok(Value::Bool(true)),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => {
            let length =
                usize::try_from((*min_length).max(1)).map_err(|_| WebhookLifecycleError::Sample)?;
            let length_u32 = u32::try_from(length).map_err(|_| WebhookLifecycleError::Sample)?;
            if *max_length == 0 || length_u32 > *max_length {
                return Err(WebhookLifecycleError::Sample);
            }
            Ok(Value::String("x".repeat(length)))
        }
        FieldTypeSource::Text { max_length } => {
            if *max_length == 0 {
                Ok(Value::String(String::new()))
            } else {
                Ok(Value::String(
                    "example".chars().take(*max_length as usize).collect(),
                ))
            }
        }
        FieldTypeSource::Int64 => Ok(json!(1)),
        FieldTypeSource::Decimal {
            scale,
            minimum,
            maximum,
            ..
        } => {
            let zero = if *scale == 0 {
                "0".to_owned()
            } else {
                format!("0.{}", "0".repeat(usize::from(*scale)))
            };
            let value = minimum.as_ref().map_or_else(
                || {
                    maximum
                        .as_ref()
                        .filter(|value| value.starts_with('-'))
                        .cloned()
                        .unwrap_or(zero)
                },
                Clone::clone,
            );
            Ok(Value::String(value))
        }
        FieldTypeSource::Date => Ok(Value::String("2026-01-01".to_owned())),
        FieldTypeSource::Timestamp => Ok(Value::String(SAMPLE_TIME.to_owned())),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => {
            Ok(Value::String(SAMPLE_RECORD_ID.to_owned()))
        }
        FieldTypeSource::VocabularyCode { values, .. } => values
            .first()
            .cloned()
            .map(Value::String)
            .ok_or(WebhookLifecycleError::Sample),
        FieldTypeSource::Crs84Point { bbox, .. } => {
            let (longitude, latitude) = point_in_bbox(bbox.as_ref())?;
            Ok(json!({"type": "Point", "coordinates": [longitude, latitude]}))
        }
        FieldTypeSource::Structured { schema, .. } => synthesize_schema(schema, schema, 0),
    }
}

fn point_in_bbox(
    bbox: Option<&Crs84BboxSource>,
) -> Result<(Number, Number), WebhookLifecycleError> {
    let coordinate = |minimum: Option<&str>, maximum: Option<&str>| {
        let minimum = minimum.and_then(|value| value.parse::<f64>().ok());
        let maximum = maximum.and_then(|value| value.parse::<f64>().ok());
        let value = match (minimum, maximum) {
            (Some(minimum), Some(maximum)) if minimum <= 0.0 && maximum >= 0.0 => 0.0,
            (Some(minimum), Some(_)) => minimum,
            _ => 0.0,
        };
        Number::from_f64(value).ok_or(WebhookLifecycleError::Sample)
    };
    let longitude = coordinate(
        bbox.map(|bbox| bbox.west.as_str()),
        bbox.map(|bbox| bbox.east.as_str()),
    )?;
    let latitude = coordinate(
        bbox.map(|bbox| bbox.south.as_str()),
        bbox.map(|bbox| bbox.north.as_str()),
    )?;
    Ok((longitude, latitude))
}

fn synthesize_schema(
    root: &Value,
    schema: &Value,
    depth: usize,
) -> Result<Value, WebhookLifecycleError> {
    if depth > MAX_SCHEMA_SYNTHESIS_DEPTH {
        return Err(WebhookLifecycleError::Sample);
    }
    let object = schema.as_object().ok_or(WebhookLifecycleError::Sample)?;
    for key in ["const", "default"] {
        if let Some(value) = object.get(key) {
            return Ok(value.clone());
        }
    }
    if let Some(value) = object
        .get("examples")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return Ok(value.clone());
    }
    if let Some(value) = object
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return Ok(value.clone());
    }
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let pointer = reference
            .strip_prefix('#')
            .ok_or(WebhookLifecycleError::Sample)?;
        let referred = root.pointer(pointer).ok_or(WebhookLifecycleError::Sample)?;
        return synthesize_schema(root, referred, depth + 1);
    }
    for keyword in ["oneOf", "anyOf"] {
        if let Some(first) = object
            .get(keyword)
            .and_then(Value::as_array)
            .and_then(|values| values.first())
        {
            return synthesize_schema(root, first, depth + 1);
        }
    }
    let schema_type = match object.get("type") {
        Some(Value::String(value)) => value.as_str(),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .find(|value| *value != "null")
            .unwrap_or("null"),
        None if object.contains_key("properties") => "object",
        None => return Ok(Value::Object(Map::new())),
        _ => return Err(WebhookLifecycleError::Sample),
    };
    match schema_type {
        "null" => Ok(Value::Null),
        "boolean" => Ok(Value::Bool(true)),
        "integer" => Ok(object
            .get("minimum")
            .and_then(Value::as_i64)
            .map_or_else(|| json!(1), Value::from)),
        "number" => Ok(object.get("minimum").cloned().unwrap_or_else(|| json!(1))),
        "string" => {
            let value = match object.get("format").and_then(Value::as_str) {
                Some("date") => "2026-01-01".to_owned(),
                Some("date-time") => SAMPLE_TIME.to_owned(),
                Some("uuid") => SAMPLE_RECORD_ID.to_owned(),
                _ => {
                    let length = object
                        .get("minLength")
                        .and_then(Value::as_u64)
                        .unwrap_or(1)
                        .max(1);
                    "x".repeat(usize::try_from(length).map_err(|_| WebhookLifecycleError::Sample)?)
                }
            };
            Ok(Value::String(value))
        }
        "array" => {
            let minimum = object.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            let prefixes = object.get("prefixItems").and_then(Value::as_array);
            let item_schema = object.get("items");
            let mut result = Vec::new();
            for index in 0..minimum {
                let schema = prefixes
                    .and_then(|values| {
                        usize::try_from(index)
                            .ok()
                            .and_then(|index| values.get(index))
                    })
                    .or(item_schema)
                    .ok_or(WebhookLifecycleError::Sample)?;
                result.push(synthesize_schema(root, schema, depth + 1)?);
            }
            Ok(Value::Array(result))
        }
        "object" => {
            let properties = object.get("properties").and_then(Value::as_object);
            let required = object
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten();
            let mut result = Map::new();
            for field in required {
                let field = field.as_str().ok_or(WebhookLifecycleError::Sample)?;
                let field_schema = properties
                    .and_then(|properties| properties.get(field))
                    .ok_or(WebhookLifecycleError::Sample)?;
                result.insert(
                    field.to_owned(),
                    synthesize_schema(root, field_schema, depth + 1)?,
                );
            }
            Ok(Value::Object(result))
        }
        _ => Err(WebhookLifecycleError::Sample),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn structured_sample_synthesis_is_deterministic_and_uses_required_typed_properties() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "active": {"type": "boolean"},
                "code": {"type": "string", "minLength": 3},
                "ignored": {"type": "string"}
            },
            "required": ["active", "code"]
        });

        assert_eq!(
            synthesize_schema(&schema, &schema, 0).expect("sample synthesizes"),
            json!({"active": true, "code": "xxx"})
        );
    }

    #[test]
    fn sample_placeholders_never_claim_a_deployed_target_or_secret() {
        assert!(SAMPLE_REQUEST_TARGET.starts_with('<'));
        assert_eq!(SAMPLE_SIGNATURE, "v1=<computed-at-delivery>");
        assert!(!SAMPLE_SIGNATURE.contains("secret"));
    }

    #[test]
    fn operator_list_delegates_bounded_arguments_and_returns_only_value_free_status() {
        let called = Cell::new(false);
        let event_id = Uuid::parse_str(SAMPLE_EVENT_ID).expect("sample event UUID parses");
        let outcome = list_with(
            Path::new("/operator/runtime.yaml"),
            17,
            |runtime_config, limit| {
                called.set(true);
                assert_eq!(runtime_config, Path::new("/operator/runtime.yaml"));
                assert_eq!(limit, 17);
                Ok::<_, ()>(vec![WebhookDeliveryStatus {
                    event_id,
                    compiled_delivery_id: "record.record-created-v1.webhook".to_owned(),
                    generation: 2,
                    state: WebhookDeliveryStatusKind::DeadLettered,
                    attempt: 3,
                    payload_available: true,
                    payload_expires_at: "2026-01-02T00:00:00Z".to_owned(),
                }])
            },
        )
        .expect("delegated list succeeds");

        assert!(called.get());
        assert_eq!(outcome.deliveries.len(), 1);
        assert_eq!(outcome.deliveries[0].state, "dead_lettered");
        assert!(outcome.deliveries[0].replay_eligible);
    }

    #[test]
    fn operator_replay_delegates_the_exact_optimistic_identity() {
        let called = Cell::new(false);
        let outcome = replay_with(
            Path::new("/operator/runtime.yaml"),
            SAMPLE_EVENT_ID,
            "record.record-created-v1.webhook",
            7,
            |runtime_config, event_id, delivery_id, expected_generation| {
                called.set(true);
                assert_eq!(runtime_config, Path::new("/operator/runtime.yaml"));
                assert_eq!(event_id.to_string(), SAMPLE_EVENT_ID);
                assert_eq!(delivery_id, "record.record-created-v1.webhook");
                assert_eq!(expected_generation, 7);
                Ok::<_, ()>(8)
            },
        )
        .expect("delegated replay succeeds");

        assert!(called.get());
        assert_eq!(outcome.generation, 8);
    }
}
