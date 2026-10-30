// SPDX-License-Identifier: Apache-2.0
//! Hook developer and operator workflows.
//!
//! This module renders offline examples from compiled authority and delegates
//! live inspection, replay, and discard to Base Registry Engine. It deliberately owns no SQL,
//! signature construction, retry policy, or recovery semantics.

use std::collections::BTreeMap;
use std::path::Path;

use registry_breg::contract::{Crs84BboxSource, EventTrigger, FieldTypeSource};
use registry_breg::hooks::{
    HookDeliveryStatus, HookDeliveryStatusKind, HookDrainReport, HookOperatorError,
    HookOperatorService, MAX_HOOK_STATUS_RESULTS,
};
use registry_breg::model::CompiledRegistry;
use registry_platform_config::PackageDigestMismatch;
use registry_platform_hooks::{Causation, EnvelopeLimits, EventSubject, HookEnvelope};
use serde::Serialize;
use serde_json::{json, Map, Number, Value};
use uuid::Uuid;

const SAMPLE_EVENT_ID: &str = "00000000-0000-4000-8000-000000000001";
const SAMPLE_RECORD_ID: &str = "00000000-0000-4000-8000-000000000002";
const SAMPLE_RECORD_REFERENCE: &str =
    "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000002";
const SAMPLE_TIME: &str = "2026-01-01T00:00:00Z";
const SAMPLE_PACKAGE_REVISION: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const SAMPLE_IDEMPOTENCY_KEY: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const SAMPLE_REQUEST_TARGET: &str = "<configured-hook-request-target>";
const SAMPLE_SIGNATURE: &str = "v1=<computed-at-delivery>";
const MAX_SCHEMA_SYNTHESIS_DEPTH: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HookLifecycleError {
    Event,
    Sample,
    Operator,
    /// The configured active package does not match the runtime file's
    /// `package.expectedDigest` pin.
    PackagePinMismatch(PackageDigestMismatch),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HookSampleOutcome {
    pub event_id: String,
    pub request: HookSampleRequest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HookSampleRequest {
    pub method: &'static str,
    pub request_target: &'static str,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
    pub canonical_body: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HookListOutcome {
    pub deliveries: Vec<HookListItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HookListItem {
    pub event_id: String,
    pub delivery_id: String,
    pub generation: i64,
    pub state: &'static str,
    pub attempt: i16,
    pub payload_available: bool,
    pub payload_expires_at: String,
    pub replay_eligible: bool,
    pub discard_eligible: bool,
    pub binding_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dead_letter_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal_summary: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HookReplayOutcome {
    pub event_id: String,
    pub delivery_id: String,
    pub generation: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HookDiscardOutcome {
    pub event_id: String,
    pub delivery_id: String,
    pub generation: i64,
    pub state: &'static str,
}

pub(crate) fn sample(
    registry: &CompiledRegistry,
    authored_event_id: &str,
) -> Result<HookSampleOutcome, HookLifecycleError> {
    let mut matching = registry
        .event_deliveries()
        .deliveries
        .iter()
        .filter(|delivery| {
            delivery.event_id == authored_event_id || delivery.id == authored_event_id
        });
    let delivery = matching.next().ok_or(HookLifecycleError::Event)?;
    if matching.next().is_some() {
        return Err(HookLifecycleError::Event);
    }
    let (data, event_type, subject) = match &delivery.owner {
        registry_breg::model::CompiledEventOwner::RecordType {
            record_type,
            trigger,
        } => {
            let entity = registry
                .entities()
                .get(record_type)
                .ok_or(HookLifecycleError::Sample)?;
            let mut values = Map::new();
            for field_id in &delivery.projection_fields {
                let field = entity
                    .fields
                    .get(field_id)
                    .ok_or(HookLifecycleError::Sample)?;
                values.insert(field_id.clone(), synthetic_field_value(&field.field_type)?);
            }
            (
                json!({"recordType":record_type,"recordId":SAMPLE_RECORD_ID,"revision":1,"trigger":trigger_name(*trigger),"packageRevision":SAMPLE_PACKAGE_REVISION,"values":values}),
                delivery.event_id.clone(),
                EventSubject::record(SAMPLE_RECORD_REFERENCE, 1),
            )
        }
        registry_breg::model::CompiledEventOwner::ProposalAction { action } => {
            let action = registry
                .actions()
                .actions
                .iter()
                .find(|entry| &entry.id == action)
                .ok_or(HookLifecycleError::Sample)?;
            let registry_breg::model::CompiledActionExecution::Proposal { proposal } =
                &action.execution
            else {
                return Err(HookLifecycleError::Sample);
            };
            let hook = proposal
                .hooks
                .iter()
                .find(|hook| hook.id == delivery.event_id)
                .ok_or(HookLifecycleError::Sample)?;
            let transition = registry_breg::proposal_hooks::matching_transitions(&hook.transitions)
                .next()
                .ok_or(HookLifecycleError::Sample)?;
            use registry_breg::contract::ProposalEventTransition as Transition;
            let (from, state, turn) = match transition {
                Transition::Started => ("none", "draft", "party"),
                Transition::Edited => ("draft", "draft", "party"),
                Transition::Submitted => ("draft", "submitted", "official"),
                Transition::Revised | Transition::Rebased => ("submitted", "draft", "party"),
                Transition::Retried => ("submitted", "submitted", "official"),
                Transition::Cancelled => ("draft", "cancelled", "nobody"),
                Transition::Applied => ("submitted", "applied", "nobody"),
                Transition::Rejected => ("submitted", "rejected", "nobody"),
                Transition::ReviewReturned => ("submitted", "submitted", "party"),
            };
            let authority_kind = match transition {
                Transition::Rejected | Transition::ReviewReturned => "review",
                _ => "caller",
            };
            (
                json!({"actionId":action.id,"actionRevision":action.definition_revision,"proposalId":SAMPLE_RECORD_ID,"submissionVersion":1,"revision":1,"fromState":from,"state":state,"transition":transition.as_str(),"effectDigest":null,"authorityKind":authority_kind,"systemApplyGrantRevision":null,"turn":turn}),
                format!("proposal.{}", transition.as_str()),
                EventSubject::proposal(format!("/v1/proposals/{SAMPLE_RECORD_ID}"), 1),
            )
        }
    };
    let source = format!(
        "urn:registrystack:registry:{}:instance:<configured-instance>",
        registry.registry_id()
    );
    let envelope = HookEnvelope {
        id: SAMPLE_EVENT_ID.to_owned(),
        event_type: event_type.clone(),
        source: source.clone(),
        time: sample_time()?,
        subject,
        dataschema: delivery.data_schema.clone(),
        data,
        causation: Causation::root(SAMPLE_EVENT_ID),
    };
    let canonical_body_bytes = envelope
        .to_canonical_bytes(&EnvelopeLimits::tightened_to(
            usize::try_from(delivery.maximum_payload_bytes)
                .map_err(|_| HookLifecycleError::Sample)?,
        ))
        .map_err(|_| HookLifecycleError::Sample)?;
    let canonical_body =
        String::from_utf8(canonical_body_bytes).map_err(|_| HookLifecycleError::Sample)?;
    let body = serde_json::to_value(&envelope).map_err(|_| HookLifecycleError::Sample)?;
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
        ("ce-source".to_owned(), source),
        ("ce-specversion".to_owned(), "1.0".to_owned()),
        ("ce-time".to_owned(), SAMPLE_TIME.to_owned()),
        ("ce-type".to_owned(), event_type),
    ]);
    Ok(HookSampleOutcome {
        event_id: delivery.event_id.clone(),
        request: HookSampleRequest {
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
) -> Result<HookListOutcome, HookLifecycleError> {
    let runtime = operator_runtime()?;
    list_with(runtime_config, limit, |runtime_config, limit| {
        runtime.block_on(async {
            let service = HookOperatorService::from_runtime_config(runtime_config).await?;
            service.list(limit).await
        })
    })
}

fn list_with(
    runtime_config: &Path,
    limit: u16,
    operation: impl FnOnce(&Path, u16) -> Result<Vec<HookDeliveryStatus>, HookOperatorError>,
) -> Result<HookListOutcome, HookLifecycleError> {
    if !runtime_config.is_absolute() || limit == 0 || limit > MAX_HOOK_STATUS_RESULTS {
        return Err(HookLifecycleError::Operator);
    }
    let deliveries = operation(runtime_config, limit).map_err(operator_failure)?;
    Ok(HookListOutcome {
        deliveries: deliveries.into_iter().map(list_item).collect(),
    })
}

pub(crate) fn drain(
    runtime_config: &Path,
    max_attempts: u16,
    timeout_seconds: u16,
) -> Result<HookDrainReport, HookLifecycleError> {
    if !runtime_config.is_absolute()
        || !(1..=1000).contains(&max_attempts)
        || !(1..=300).contains(&timeout_seconds)
    {
        return Err(HookLifecycleError::Operator);
    }
    operator_runtime()?
        .block_on(HookOperatorService::drain_local(
            runtime_config,
            max_attempts,
            std::time::Duration::from_secs(u64::from(timeout_seconds)),
        ))
        .map_err(operator_failure)
}

pub(crate) fn replay(
    runtime_config: &Path,
    event_id: &str,
    delivery_id: &str,
    expected_generation: i64,
) -> Result<HookReplayOutcome, HookLifecycleError> {
    let runtime = operator_runtime()?;
    replay_with(
        runtime_config,
        event_id,
        delivery_id,
        expected_generation,
        |runtime_config, event_id, delivery_id, expected_generation| {
            runtime.block_on(async {
                let service = HookOperatorService::from_runtime_config(runtime_config).await?;
                service
                    .replay(event_id, delivery_id, expected_generation)
                    .await
            })
        },
    )
}

fn replay_with(
    runtime_config: &Path,
    event_id: &str,
    delivery_id: &str,
    expected_generation: i64,
    operation: impl FnOnce(&Path, Uuid, &str, i64) -> Result<i64, HookOperatorError>,
) -> Result<HookReplayOutcome, HookLifecycleError> {
    if !runtime_config.is_absolute()
        || delivery_id.is_empty()
        || delivery_id.len() > 256
        || expected_generation <= 0
    {
        return Err(HookLifecycleError::Operator);
    }
    let event_id = Uuid::parse_str(event_id).map_err(|_| HookLifecycleError::Operator)?;
    let generation = operation(runtime_config, event_id, delivery_id, expected_generation)
        .map_err(operator_failure)?;
    Ok(HookReplayOutcome {
        event_id: event_id.to_string(),
        delivery_id: delivery_id.to_owned(),
        generation,
    })
}

pub(crate) fn discard(
    runtime_config: &Path,
    event_id: &str,
    delivery_id: &str,
    expected_generation: i64,
) -> Result<HookDiscardOutcome, HookLifecycleError> {
    let runtime = operator_runtime()?;
    discard_with(
        runtime_config,
        event_id,
        delivery_id,
        expected_generation,
        |runtime_config, event_id, delivery_id, expected_generation| {
            runtime.block_on(async {
                let service = HookOperatorService::from_runtime_config(runtime_config).await?;
                service
                    .discard(event_id, delivery_id, expected_generation)
                    .await
            })
        },
    )
}

fn discard_with(
    runtime_config: &Path,
    event_id: &str,
    delivery_id: &str,
    expected_generation: i64,
    operation: impl FnOnce(&Path, Uuid, &str, i64) -> Result<i64, HookOperatorError>,
) -> Result<HookDiscardOutcome, HookLifecycleError> {
    if !runtime_config.is_absolute()
        || delivery_id.is_empty()
        || delivery_id.len() > 256
        || expected_generation <= 0
    {
        return Err(HookLifecycleError::Operator);
    }
    let event_id = Uuid::parse_str(event_id).map_err(|_| HookLifecycleError::Operator)?;
    let generation = operation(runtime_config, event_id, delivery_id, expected_generation)
        .map_err(operator_failure)?;
    Ok(HookDiscardOutcome {
        event_id: event_id.to_string(),
        delivery_id: delivery_id.to_owned(),
        generation,
        state: "discarded",
    })
}

/// A package pin mismatch keeps both digests; every other operator failure
/// stays the one value-free refusal.
fn operator_failure(error: HookOperatorError) -> HookLifecycleError {
    match error {
        HookOperatorError::PackagePinMismatch(mismatch) => {
            HookLifecycleError::PackagePinMismatch(mismatch)
        }
        HookOperatorError::Unavailable => HookLifecycleError::Operator,
    }
}

fn operator_runtime() -> Result<tokio::runtime::Runtime, HookLifecycleError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| HookLifecycleError::Operator)
}

fn list_item(status: HookDeliveryStatus) -> HookListItem {
    let state = match status.state {
        HookDeliveryStatusKind::Pending => "pending",
        HookDeliveryStatusKind::Leased => "leased",
        HookDeliveryStatusKind::DeadLettered => "dead-lettered",
        HookDeliveryStatusKind::Expired => "expired",
    };
    // This product-owned diagnostic contains activation identities only.
    // Other proposal summaries may contain handler-authored text and are
    // not part of the value-free operator list.
    let package_unavailable =
        status.proposal_code.as_deref() == Some("hook.proposal.package_unavailable");
    HookListItem {
        event_id: status.event_id.to_string(),
        delivery_id: status.compiled_delivery_id,
        generation: status.generation,
        state,
        attempt: status.attempt,
        payload_available: status.payload_available,
        payload_expires_at: status.payload_expires_at,
        replay_eligible: status.replay_eligible,
        discard_eligible: status.discard_eligible,
        binding_active: status.binding_active,
        dead_letter_reason: status.dead_letter_reason.map(|reason| reason.as_str()),
        proposal_code: status.proposal_code,
        proposal_summary: status.proposal_summary.filter(|_| package_unavailable),
    }
}

/// The sample capture instant, the one [`SAMPLE_TIME`] spells.
fn sample_time() -> Result<time::OffsetDateTime, HookLifecycleError> {
    time::OffsetDateTime::parse(SAMPLE_TIME, &time::format_description::well_known::Rfc3339)
        .map_err(|_| HookLifecycleError::Sample)
}

fn trigger_name(trigger: EventTrigger) -> &'static str {
    match trigger {
        EventTrigger::Created => "created",
        EventTrigger::Patched => "patched",
        EventTrigger::Tombstoned => "tombstoned",
    }
}

fn synthetic_field_value(field_type: &FieldTypeSource) -> Result<Value, HookLifecycleError> {
    match field_type {
        FieldTypeSource::Boolean => Ok(Value::Bool(true)),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => {
            let length =
                usize::try_from((*min_length).max(1)).map_err(|_| HookLifecycleError::Sample)?;
            let length_u32 = u32::try_from(length).map_err(|_| HookLifecycleError::Sample)?;
            if *max_length == 0 || length_u32 > *max_length {
                return Err(HookLifecycleError::Sample);
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
            .ok_or(HookLifecycleError::Sample),
        FieldTypeSource::Crs84Point { bbox, .. } => {
            let (longitude, latitude) = point_in_bbox(bbox.as_ref())?;
            Ok(json!({"type": "Point", "coordinates": [longitude, latitude]}))
        }
        FieldTypeSource::Structured { schema, .. } => synthesize_schema(schema, schema, 0),
    }
}

fn point_in_bbox(bbox: Option<&Crs84BboxSource>) -> Result<(Number, Number), HookLifecycleError> {
    let coordinate = |minimum: Option<&str>, maximum: Option<&str>| {
        let minimum = minimum.and_then(|value| value.parse::<f64>().ok());
        let maximum = maximum.and_then(|value| value.parse::<f64>().ok());
        let value = match (minimum, maximum) {
            (Some(minimum), Some(maximum)) if minimum <= 0.0 && maximum >= 0.0 => 0.0,
            (Some(minimum), Some(_)) => minimum,
            _ => 0.0,
        };
        Number::from_f64(value).ok_or(HookLifecycleError::Sample)
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
) -> Result<Value, HookLifecycleError> {
    if depth > MAX_SCHEMA_SYNTHESIS_DEPTH {
        return Err(HookLifecycleError::Sample);
    }
    let object = schema.as_object().ok_or(HookLifecycleError::Sample)?;
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
            .ok_or(HookLifecycleError::Sample)?;
        let referred = root.pointer(pointer).ok_or(HookLifecycleError::Sample)?;
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
        _ => return Err(HookLifecycleError::Sample),
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
                    "x".repeat(usize::try_from(length).map_err(|_| HookLifecycleError::Sample)?)
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
                    .ok_or(HookLifecycleError::Sample)?;
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
                let field = field.as_str().ok_or(HookLifecycleError::Sample)?;
                let field_schema = properties
                    .and_then(|properties| properties.get(field))
                    .ok_or(HookLifecycleError::Sample)?;
                result.insert(
                    field.to_owned(),
                    synthesize_schema(root, field_schema, depth + 1)?,
                );
            }
            Ok(Value::Object(result))
        }
        _ => Err(HookLifecycleError::Sample),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use registry_breg::hooks::HookDeliveryFailureReason;

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
                Ok::<_, HookOperatorError>(vec![HookDeliveryStatus {
                    event_id,
                    compiled_delivery_id: "record.record-created-v1.webhook".to_owned(),
                    generation: 2,
                    state: HookDeliveryStatusKind::DeadLettered,
                    attempt: 3,
                    payload_available: true,
                    payload_expires_at: "2026-01-02T00:00:00Z".to_owned(),
                    dead_letter_reason: Some(HookDeliveryFailureReason::AlwaysDeniedAddress),
                    binding_active: true,
                    discard_eligible: true,
                    replay_eligible: true,
                    proposal_code: None,
                    proposal_summary: None,
                }])
            },
        )
        .expect("delegated list succeeds");

        assert!(called.get());
        assert_eq!(outcome.deliveries.len(), 1);
        assert_eq!(outcome.deliveries[0].state, "dead-lettered");
        assert!(outcome.deliveries[0].replay_eligible);
        assert!(outcome.deliveries[0].discard_eligible);
        assert_eq!(
            outcome.deliveries[0].dead_letter_reason,
            Some("always-denied-address")
        );
    }

    #[test]
    fn operator_list_exposes_activation_refusal_but_omits_other_summaries() {
        let mut status = HookDeliveryStatus {
            event_id: Uuid::parse_str(SAMPLE_EVENT_ID).unwrap(),
            compiled_delivery_id: "record.created".to_owned(),
            generation: 1,
            state: HookDeliveryStatusKind::DeadLettered,
            attempt: 1,
            payload_available: true,
            payload_expires_at: "2026-01-02T00:00:00Z".to_owned(),
            dead_letter_reason: None,
            binding_active: true,
            discard_eligible: true,
            replay_eligible: false,
            proposal_code: Some("hook.proposal.package_unavailable".to_owned()),
            proposal_summary: Some(
                "Captured activation A, replaced by active activation B.".to_owned(),
            ),
        };
        let item = list_item(status.clone());
        assert!(!item.replay_eligible);
        assert!(item.discard_eligible);
        assert_eq!(item.proposal_summary, status.proposal_summary);
        status.proposal_code = Some("hook.proposal.document_refused".to_owned());
        status.proposal_summary = Some("handler-authored-value-canary".to_owned());
        let encoded = serde_json::to_string(&list_item(status)).unwrap();
        assert!(!encoded.contains("handler-authored-value-canary"));
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
                Ok::<_, HookOperatorError>(8)
            },
        )
        .expect("delegated replay succeeds");

        assert!(called.get());
        assert_eq!(outcome.generation, 8);
    }

    #[test]
    fn operator_discard_delegates_the_exact_optimistic_identity() {
        let called = Cell::new(false);
        let outcome = discard_with(
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
                Ok::<_, HookOperatorError>(8)
            },
        )
        .expect("delegated discard succeeds");

        assert!(called.get());
        assert_eq!(outcome.generation, 8);
        assert_eq!(outcome.state, "discarded");
    }

    #[test]
    fn operator_discard_refuses_unbounded_or_stale_identity_before_io() {
        for (runtime_config, event_id, delivery_id, generation) in [
            (
                Path::new("relative-runtime.yaml"),
                SAMPLE_EVENT_ID,
                "record.record-created-v1.webhook",
                1,
            ),
            (
                Path::new("/operator/runtime.yaml"),
                "not-an-event-id",
                "record.record-created-v1.webhook",
                1,
            ),
            (Path::new("/operator/runtime.yaml"), SAMPLE_EVENT_ID, "", 1),
            (
                Path::new("/operator/runtime.yaml"),
                SAMPLE_EVENT_ID,
                "record.record-created-v1.webhook",
                0,
            ),
        ] {
            let called = Cell::new(false);
            assert_eq!(
                discard_with(
                    runtime_config,
                    event_id,
                    delivery_id,
                    generation,
                    |_, _, _, _| {
                        called.set(true);
                        Ok::<_, HookOperatorError>(2)
                    },
                ),
                Err(HookLifecycleError::Operator)
            );
            assert!(!called.get());
        }

        let oversized = "d".repeat(257);
        let called = Cell::new(false);
        assert_eq!(
            discard_with(
                Path::new("/operator/runtime.yaml"),
                SAMPLE_EVENT_ID,
                &oversized,
                1,
                |_, _, _, _| {
                    called.set(true);
                    Ok::<_, HookOperatorError>(2)
                },
            ),
            Err(HookLifecycleError::Operator)
        );
        assert!(!called.get());
    }
}
