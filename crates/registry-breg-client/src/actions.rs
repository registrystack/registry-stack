// SPDX-License-Identifier: Apache-2.0

//! Metadata-bound immediate-action inputs, target conditions, and receipts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jsonschema::{Draft, JSONSchema};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use time::{format_description::well_known::Rfc3339, Date, Month, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    BRegComplete, BRegIdempotencyKey, BRegImmediateActionBinding, BaseRegistryClient,
    BaseRegistryClientError,
};

const MAXIMUM_CONDITION_BYTES: usize = 256;

/// A value-free reason an immediate-action request or response is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegImmediateActionError {
    #[error("the Base Registry Engine action input object contains an unknown field")]
    UnknownInput,
    #[error("the Base Registry Engine action input object is missing a required field")]
    MissingInput,
    #[error("a Base Registry Engine action input does not match its declared type and bounds")]
    InvalidInput,
    #[error("the Base Registry Engine action has no target-condition exchange")]
    TargetConditionsUnavailable,
    #[error("the Base Registry Engine action target inputs do not match its declared conditions")]
    TargetConditionInputMismatch,
    #[error("the Base Registry Engine action target conditions belong to another selected action")]
    TargetConditionBindingMismatch,
    #[error("the Base Registry Engine action body exceeds its declared byte bound")]
    BodyTooLarge,
    #[error("the Base Registry Engine action body could not be encoded")]
    BodyEncoding,
    #[error("the Base Registry Engine action response does not match the selected action")]
    InvalidResponse,
}

/// Exact condition-input request bound to one caller-filtered immediate action.
pub struct BRegActionTargetConditionsRequest {
    body: Zeroizing<Vec<u8>>,
    binding: ActionRequestBinding,
}

impl BRegActionTargetConditionsRequest {
    /// Build the explicit target-condition exchange from only the action's
    /// declared condition-bearing reference inputs.
    pub fn new(
        action: &BRegImmediateActionBinding,
        inputs: Map<String, Value>,
    ) -> Result<Self, BRegImmediateActionError> {
        if action.target_conditions_path().is_none() {
            return Err(BRegImmediateActionError::TargetConditionsUnavailable);
        }
        validate_inputs(action, &inputs, ActionInputUse::TargetConditions)?;
        let body = encode_bounded(
            &ActionInputEnvelope { input: &inputs },
            action.bounds().maximum_snapshot_bytes(),
        )?;
        Ok(Self {
            body: Zeroizing::new(body),
            binding: ActionRequestBinding::from_action(action),
        })
    }

    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl fmt::Debug for BRegActionTargetConditionsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegActionTargetConditionsRequest")
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Saved opaque target conditions returned by an explicit condition exchange.
///
/// Serialization yields the exact `{ "preconditions": ... }` wire member so a
/// language binding can retain it with the caller's form state. Deserialization
/// is deliberately unavailable: only a validated server response can construct
/// a condition value executable by this client.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegActionTargetConditions {
    preconditions: BTreeMap<String, BRegActionPrecondition>,
    #[serde(skip)]
    target_input_body: Zeroizing<Vec<u8>>,
    #[serde(skip)]
    binding: ActionRequestBinding,
}

impl BRegActionTargetConditions {
    pub fn precondition_keys(&self) -> impl Iterator<Item = &str> {
        self.preconditions.keys().map(String::as_str)
    }
}

impl fmt::Debug for BRegActionTargetConditions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegActionTargetConditions")
            .field("precondition_count", &self.preconditions.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BRegActionPrecondition {
    if_match: String,
}

/// Exact invocation request bound to one caller-filtered immediate action and
/// the caller's explicitly acquired target conditions.
pub struct BRegActionInvocationRequest {
    body: Zeroizing<Vec<u8>>,
    binding: ActionRequestBinding,
}

impl BRegActionInvocationRequest {
    pub fn new(
        action: &BRegImmediateActionBinding,
        inputs: Map<String, Value>,
        conditions: Option<&BRegActionTargetConditions>,
    ) -> Result<Self, BRegImmediateActionError> {
        validate_inputs(action, &inputs, ActionInputUse::Invoke)?;
        let requires_conditions = !action.required_condition_keys().is_empty();
        let preconditions = match (requires_conditions, conditions) {
            (false, None) => None,
            (_, Some(conditions)) => {
                let binding = ActionRequestBinding::from_action(action);
                if conditions.binding != binding {
                    return Err(BRegImmediateActionError::TargetConditionBindingMismatch);
                }
                let target_inputs = action
                    .required_condition_keys()
                    .iter()
                    .map(|name| inputs.get(name).cloned().map(|value| (name.clone(), value)))
                    .collect::<Option<Map<_, _>>>()
                    .ok_or(BRegImmediateActionError::TargetConditionInputMismatch)?;
                let target_input_body = Zeroizing::new(encode_bounded(
                    &ActionInputEnvelope {
                        input: &target_inputs,
                    },
                    action.bounds().maximum_snapshot_bytes(),
                )?);
                if target_input_body.as_slice() != conditions.target_input_body.as_slice() {
                    return Err(BRegImmediateActionError::TargetConditionInputMismatch);
                }
                Some(&conditions.preconditions)
            }
            (true, None) => {
                return Err(BRegImmediateActionError::TargetConditionBindingMismatch);
            }
        };
        let body = encode_bounded(
            &ActionInvocationEnvelope {
                input: &inputs,
                preconditions,
            },
            action.bounds().maximum_snapshot_bytes(),
        )?;
        Ok(Self {
            body: Zeroizing::new(body),
            binding: ActionRequestBinding::from_action(action),
        })
    }

    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl fmt::Debug for BRegActionInvocationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegActionInvocationRequest")
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ActionRequestBinding {
    source_binding: String,
    registry_revision: String,
    action_identifier: String,
    access_profile: String,
    contract_fingerprint: String,
}

impl ActionRequestBinding {
    fn from_action(action: &BRegImmediateActionBinding) -> Self {
        Self {
            source_binding: action.source_binding().to_owned(),
            registry_revision: action.registry_revision().to_owned(),
            action_identifier: action.action_identifier().to_owned(),
            access_profile: action.access_profile().to_owned(),
            contract_fingerprint: action.contract_fingerprint().to_owned(),
        }
    }
}

#[derive(Serialize)]
struct ActionInputEnvelope<'a> {
    input: &'a Map<String, Value>,
}

#[derive(Serialize)]
struct ActionInvocationEnvelope<'a> {
    input: &'a Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preconditions: Option<&'a BTreeMap<String, BRegActionPrecondition>>,
}

/// One disclosed effect reference in a successful action receipt.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegActionResultReference {
    entity: String,
    #[serde(serialize_with = "serialize_uuid")]
    record_id: Uuid,
    revision: u64,
}

impl BRegActionResultReference {
    #[must_use]
    pub fn entity_identifier(&self) -> &str {
        &self.entity
    }

    #[must_use]
    pub const fn record_identifier(&self) -> Uuid {
        self.record_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Successful immediate-action application receipt.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegActionReceipt {
    action: String,
    #[serde(serialize_with = "serialize_uuid")]
    application_id: Uuid,
    results: BTreeMap<String, BRegActionResultReference>,
}

impl BRegActionReceipt {
    #[must_use]
    pub fn action_identifier(&self) -> &str {
        &self.action
    }

    #[must_use]
    pub const fn application_identifier(&self) -> Uuid {
        self.application_id
    }

    #[must_use]
    pub fn results(&self) -> &BTreeMap<String, BRegActionResultReference> {
        &self.results
    }
}

impl BaseRegistryClient {
    /// Fetch target conditions for the caller's currently selected records.
    /// This performs exactly one exchange and never refreshes a condition.
    pub async fn action_target_conditions(
        &self,
        action: &BRegImmediateActionBinding,
        request: &BRegActionTargetConditionsRequest,
    ) -> Result<BRegComplete<BRegActionTargetConditions>, BaseRegistryClientError> {
        self.validate_action_request(action, &request.binding)?;
        let path = action.target_conditions_path().ok_or_else(|| {
            BaseRegistryClientError::invalid_request(
                "the Base Registry Engine action has no target-condition exchange",
            )
        })?;
        let raw = self
            .execute_bound_json(path, action.access_profile(), request.body.to_vec(), None)
            .await?;
        let conditions =
            decode_conditions(raw.value.as_bytes(), action, request).map_err(|_| {
                BaseRegistryClientError::protocol(
                    200,
                    crate::BRegProtocolFailure::Body,
                    Some(raw.metadata.trace_id().clone()),
                )
            })?;
        Ok(BRegComplete {
            value: conditions,
            metadata: raw.metadata,
        })
    }

    /// Invoke one action with the caller's original input, target conditions,
    /// and idempotency key. The client never retries the mutation.
    pub async fn invoke_action(
        &self,
        action: &BRegImmediateActionBinding,
        request: &BRegActionInvocationRequest,
        idempotency_key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegActionReceipt>, BaseRegistryClientError> {
        self.validate_action_request(action, &request.binding)?;
        let raw = self
            .execute_bound_json(
                action.invoke_path(),
                action.access_profile(),
                request.body.to_vec(),
                Some(idempotency_key),
            )
            .await?;
        let receipt = decode_receipt(raw.value.as_bytes(), action).map_err(|_| {
            BaseRegistryClientError::protocol(
                200,
                crate::BRegProtocolFailure::Body,
                Some(raw.metadata.trace_id().clone()),
            )
        })?;
        Ok(BRegComplete {
            value: receipt,
            metadata: raw.metadata,
        })
    }

    fn validate_action_request(
        &self,
        action: &BRegImmediateActionBinding,
        request: &ActionRequestBinding,
    ) -> Result<(), BaseRegistryClientError> {
        if !action.matches_source(&self.source_binding())
            || request != &ActionRequestBinding::from_action(action)
        {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine action request belongs to another selected action",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ActionInputUse {
    TargetConditions,
    Invoke,
}

fn validate_inputs(
    action: &BRegImmediateActionBinding,
    inputs: &Map<String, Value>,
    use_for: ActionInputUse,
) -> Result<(), BRegImmediateActionError> {
    let accepted = match use_for {
        ActionInputUse::TargetConditions => {
            if action.required_condition_keys().iter().any(|name| {
                !action
                    .reference_inputs()
                    .iter()
                    .any(|reference| reference.api_name() == name)
            }) {
                return Err(BRegImmediateActionError::InvalidInput);
            }
            action.required_condition_keys().clone()
        }
        ActionInputUse::Invoke => action
            .inputs()
            .iter()
            .map(|input| input.api_name().to_owned())
            .collect::<BTreeSet<_>>(),
    };
    if inputs.keys().any(|name| !accepted.contains(name)) {
        return Err(BRegImmediateActionError::UnknownInput);
    }
    for name in accepted {
        let contract = action
            .inputs()
            .iter()
            .find(|input| input.api_name() == name)
            .ok_or(BRegImmediateActionError::InvalidInput)?;
        let required = match use_for {
            ActionInputUse::TargetConditions => true,
            ActionInputUse::Invoke => contract.required(),
        };
        let Some(value) = inputs.get(&name) else {
            if required {
                return Err(BRegImmediateActionError::MissingInput);
            }
            continue;
        };
        if value.is_null() {
            if contract.nullable() {
                continue;
            }
            return Err(BRegImmediateActionError::InvalidInput);
        }
        if !valid_action_input(
            value,
            contract.field_type(),
            action.maximum_input_string_bytes(),
        ) {
            return Err(BRegImmediateActionError::InvalidInput);
        }
    }
    Ok(())
}

fn decode_conditions(
    bytes: &[u8],
    action: &BRegImmediateActionBinding,
    request: &BRegActionTargetConditionsRequest,
) -> Result<BRegActionTargetConditions, BRegImmediateActionError> {
    let value = crate::strict_json::from_slice(bytes)
        .map_err(|_| BRegImmediateActionError::InvalidResponse)?;
    let object = value
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or(BRegImmediateActionError::InvalidResponse)?;
    let conditions = object
        .get("preconditions")
        .and_then(Value::as_object)
        .ok_or(BRegImmediateActionError::InvalidResponse)?;
    if conditions.len() != action.required_condition_keys().len()
        || conditions
            .keys()
            .any(|name| !action.required_condition_keys().contains(name))
    {
        return Err(BRegImmediateActionError::InvalidResponse);
    }
    let preconditions = conditions
        .iter()
        .map(|(name, value)| {
            let condition = value
                .as_object()
                .filter(|condition| condition.len() == 1)
                .ok_or(BRegImmediateActionError::InvalidResponse)?;
            let if_match = condition
                .get("ifMatch")
                .and_then(Value::as_str)
                .filter(|value| valid_condition(value))
                .ok_or(BRegImmediateActionError::InvalidResponse)?;
            Ok((
                name.clone(),
                BRegActionPrecondition {
                    if_match: if_match.to_owned(),
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(BRegActionTargetConditions {
        preconditions,
        target_input_body: request.body.clone(),
        binding: request.binding.clone(),
    })
}

fn decode_receipt(
    bytes: &[u8],
    action: &BRegImmediateActionBinding,
) -> Result<BRegActionReceipt, BRegImmediateActionError> {
    let value = crate::strict_json::from_slice(bytes)
        .map_err(|_| BRegImmediateActionError::InvalidResponse)?;
    let object = value
        .as_object()
        .filter(|object| object.len() == 3)
        .ok_or(BRegImmediateActionError::InvalidResponse)?;
    if object.get("action").and_then(Value::as_str) != Some(action.action_identifier()) {
        return Err(BRegImmediateActionError::InvalidResponse);
    }
    let application_id = object
        .get("applicationId")
        .and_then(Value::as_str)
        .and_then(canonical_uuid)
        .ok_or(BRegImmediateActionError::InvalidResponse)?;
    let values = object
        .get("results")
        .and_then(Value::as_object)
        .ok_or(BRegImmediateActionError::InvalidResponse)?;
    if values.len() > action.result_effects().len()
        || (!action.is_handler() && values.len() != action.result_effects().len())
        || values
            .keys()
            .any(|name| !action.result_effects().contains_key(name))
    {
        return Err(BRegImmediateActionError::InvalidResponse);
    }
    let results = values
        .iter()
        .map(|(effect, value)| {
            let result = value
                .as_object()
                .filter(|result| result.len() == 3)
                .ok_or(BRegImmediateActionError::InvalidResponse)?;
            let entity = result
                .get("entity")
                .and_then(Value::as_str)
                .filter(|entity| {
                    action
                        .result_effects()
                        .get(effect)
                        .is_some_and(|v| v == entity)
                })
                .ok_or(BRegImmediateActionError::InvalidResponse)?;
            let record_id = result
                .get("recordId")
                .and_then(Value::as_str)
                .and_then(canonical_uuid)
                .ok_or(BRegImmediateActionError::InvalidResponse)?;
            let revision = result
                .get("revision")
                .and_then(Value::as_u64)
                .filter(|revision| *revision > 0 && *revision <= i64::MAX as u64)
                .ok_or(BRegImmediateActionError::InvalidResponse)?;
            Ok((
                effect.clone(),
                BRegActionResultReference {
                    entity: entity.to_owned(),
                    record_id,
                    revision,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(BRegActionReceipt {
        action: action.action_identifier().to_owned(),
        application_id,
        results,
    })
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|identifier| identifier.to_string() == value)
}

fn serialize_uuid<S: Serializer>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

fn valid_condition(value: &str) -> bool {
    value.len() > 2
        && value.len() <= MAXIMUM_CONDITION_BYTES
        && value.starts_with('"')
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

fn encode_bounded(
    value: &impl Serialize,
    maximum_bytes: u64,
) -> Result<Vec<u8>, BRegImmediateActionError> {
    let body = serde_json::to_vec(value).map_err(|_| BRegImmediateActionError::BodyEncoding)?;
    if u64::try_from(body.len()).map_or(true, |length| length > maximum_bytes) {
        return Err(BRegImmediateActionError::BodyTooLarge);
    }
    Ok(body)
}

fn valid_action_input(
    value: &Value,
    field_type: &Value,
    maximum_string_bytes: Option<u64>,
) -> bool {
    if !valid_json_value(value)
        || value.as_str().is_some_and(|value| {
            maximum_string_bytes.is_some_and(|maximum| value.len() as u64 > maximum)
        })
    {
        return false;
    }
    let Some(contract) = field_type.as_object() else {
        return false;
    };
    match contract.get("type").and_then(Value::as_str) {
        Some("boolean") => value.is_boolean(),
        Some("string") => valid_string(value, contract),
        Some("text") => valid_text(value, contract),
        Some("int64") => value.as_i64().is_some(),
        Some("decimal") => valid_decimal(value, contract),
        Some("date") => value.as_str().is_some_and(valid_date),
        Some("timestamp") => value
            .as_str()
            .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_ok()),
        Some("uuid") | Some("reference") => value.as_str().and_then(canonical_uuid).is_some(),
        Some("vocabulary-code") => value.as_str().is_some_and(|value| {
            contract
                .get("values")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|candidate| candidate == value))
        }),
        Some("crs84-point") => valid_point(value, contract),
        Some("structured") => valid_structured(value, contract),
        _ => false,
    }
}

fn valid_string(value: &Value, contract: &Map<String, Value>) -> bool {
    let Some(value) = value.as_str() else {
        return false;
    };
    let Some(maximum) = contract.get("maxLength").and_then(Value::as_u64) else {
        return false;
    };
    let minimum = contract
        .get("minLength")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let length = value.chars().count() as u64;
    length >= minimum && length <= maximum
}

fn valid_text(value: &Value, contract: &Map<String, Value>) -> bool {
    value.as_str().is_some_and(|value| {
        contract
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| value.chars().count() as u64 <= maximum)
    })
}

fn valid_decimal(value: &Value, contract: &Map<String, Value>) -> bool {
    let Some(value) = value.as_str() else {
        return false;
    };
    let Some(precision) = contract.get("precision").and_then(Value::as_u64) else {
        return false;
    };
    let Some(scale) = contract.get("scale").and_then(Value::as_u64) else {
        return false;
    };
    let Some(scaled) = decimal_scaled(value, precision, scale) else {
        return false;
    };
    for (name, lower) in [("minimum", true), ("maximum", false)] {
        if let Some(bound) = contract.get(name).and_then(Value::as_str) {
            let Some(bound) = decimal_scaled(bound, precision, scale) else {
                return false;
            };
            if (lower && scaled < bound) || (!lower && scaled > bound) {
                return false;
            }
        }
    }
    true
}

fn decimal_scaled(value: &str, precision: u64, scale: u64) -> Option<i128> {
    if !(1..=38).contains(&precision) || scale > precision || value.starts_with('+') {
        return None;
    }
    let negative = value.starts_with('-');
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let integer_digits = precision - scale;
    if integer.is_empty()
        || integer.bytes().any(|byte| !byte.is_ascii_digit())
        || integer.len() > 1 && integer.starts_with('0')
        || integer != "0" && integer.len() as u64 > integer_digits
        || fraction.len() as u64 != scale
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || scale == 0 && unsigned.contains('.')
    {
        return None;
    }
    let digits = format!("{integer}{fraction}").parse::<i128>().ok()?;
    if negative && digits == 0 {
        None
    } else {
        Some(if negative { -digits } else { digits })
    }
}

fn valid_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value
            .bytes()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[0..4].parse::<i32>() else {
        return false;
    };
    let Some(month) = value[5..7]
        .parse::<u8>()
        .ok()
        .and_then(|month| Month::try_from(month).ok())
    else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u8>() else {
        return false;
    };
    (1..=9999).contains(&year) && Date::from_calendar_date(year, month, day).is_ok()
}

fn valid_point(value: &Value, contract: &Map<String, Value>) -> bool {
    let Some(precision) = contract.get("precision").and_then(Value::as_u64) else {
        return false;
    };
    if precision > 9 {
        return false;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 2 || object.get("type").and_then(Value::as_str) != Some("Point") {
        return false;
    }
    let Some(coordinates) = object.get("coordinates").and_then(Value::as_array) else {
        return false;
    };
    if coordinates.len() != 2 {
        return false;
    }
    let Some(longitude) = coordinate(&coordinates[0], precision, -180.0, 180.0) else {
        return false;
    };
    let Some(latitude) = coordinate(&coordinates[1], precision, -90.0, 90.0) else {
        return false;
    };
    let Some(bbox) = contract.get("bbox") else {
        return true;
    };
    let Some(bbox) = bbox.as_object() else {
        return false;
    };
    let bounds = [
        ("west", -180.0, 180.0),
        ("south", -90.0, 90.0),
        ("east", -180.0, 180.0),
        ("north", -90.0, 90.0),
    ]
    .map(|(name, minimum, maximum)| {
        bbox.get(name)
            .and_then(Value::as_str)
            .and_then(|value| coordinate_text(value, precision, minimum, maximum))
    });
    let [Some(west), Some(south), Some(east), Some(north)] = bounds else {
        return false;
    };
    west <= longitude && longitude <= east && south <= latitude && latitude <= north
}

fn coordinate(value: &Value, precision: u64, minimum: f64, maximum: f64) -> Option<f64> {
    value
        .is_number()
        .then(|| coordinate_text(&value.to_string(), precision, minimum, maximum))
        .flatten()
}

fn coordinate_text(value: &str, precision: u64, minimum: f64, maximum: f64) -> Option<f64> {
    if value.is_empty() || value.starts_with('+') || value.contains(['e', 'E']) {
        return None;
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if integer.is_empty()
        || integer.bytes().any(|byte| !byte.is_ascii_digit())
        || fraction.bytes().any(|byte| !byte.is_ascii_digit())
        || integer.len() > 1 && integer.starts_with('0')
        || fraction.len() as u64 > precision
    {
        return None;
    }
    value
        .parse::<f64>()
        .ok()
        .filter(|parsed| *parsed >= minimum && *parsed <= maximum)
}

fn valid_structured(value: &Value, contract: &Map<String, Value>) -> bool {
    let Some(maximum) = contract.get("maxBytes").and_then(Value::as_u64) else {
        return false;
    };
    let Some(schema) = contract.get("schema") else {
        return false;
    };
    registry_platform_canonical_json::canonicalize_json(value)
        .is_ok_and(|bytes| bytes.len() as u64 <= maximum)
        && JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(schema)
            .is_ok_and(|compiled| compiled.is_valid(value))
}

fn valid_json_value(value: &Value) -> bool {
    let mut pending = vec![(value, 1usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > 128 {
            return false;
        }
        match value {
            Value::Number(number) if !number_is_exact_binary64(number) => return false,
            Value::Array(values) => pending.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    true
}

fn number_is_exact_binary64(number: &serde_json::Number) -> bool {
    let magnitude = number
        .as_i64()
        .map(i64::unsigned_abs)
        .or_else(|| number.as_u64());
    magnitude.map_or_else(
        || number.as_f64().is_some_and(f64::is_finite),
        |value| {
            if value == 0 {
                return true;
            }
            let significant_bits = u64::BITS - value.leading_zeros();
            significant_bits <= 53 || value.trailing_zeros() >= significant_bits - 53
        },
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn action_binding(handler: bool) -> BRegImmediateActionBinding {
        let input_mode = if handler { "handler" } else { "fixed" };
        let maximum_string_bytes = handler.then_some(json!(16_384)).unwrap_or(Value::Null);
        let optional_nullable = handler;
        let metadata = json!({
            "id": "fixture-registry",
            "version": "1",
            "revision": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "metadataVersion": "1",
            "entities": [],
            "operations": [],
            "actions": [{
                "id": "update-item",
                "route": "/v1/actions/update-item",
                "conditionRoute": "/v1/actions/update-item/target-conditions",
                "contractFingerprint": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inputMode": input_mode,
                "maximumInputStringBytes": maximum_string_bytes,
                "inputs": [
                    {
                        "id": "target", "apiName": "targetId", "required": true,
                        "nullable": false, "classification": "internal",
                        "fieldType": {"type":"reference","target":"item","onDelete":"restrict"}
                    },
                    {
                        "id": "label", "apiName": "label", "required": false,
                        "nullable": optional_nullable, "classification": "internal",
                        "fieldType": {"type":"string","minLength":1,"maxLength":16}
                    }
                ],
                "referenceInputs": [{"input":"target","apiName":"targetId","targetEntity":"item"}],
                "requiredConditionKeys": ["targetId"],
                "resultEffects": [{"effect":"item","entity":"item","operation":"patch"}],
                "access": {"selectedProfile":"writer"},
                "routes": {
                    "invoke": {
                        "method":"POST", "path":"/v1/actions/update-item",
                        "operationId":"actions.update-item.invoke", "requiresIdempotencyKey":true,
                        "inputSchema":"action-update-item-invoke-input",
                        "responseSchema":"action-update-item-invoke-response"
                    },
                    "targetConditions": {
                        "method":"POST", "path":"/v1/actions/update-item/target-conditions",
                        "operationId":"actions.update-item.target_conditions", "requiresIdempotencyKey":false,
                        "inputSchema":"action-update-item-target-conditions-input",
                        "responseSchema":"action-update-item-target-conditions-response"
                    }
                },
                "bounds": {"maximumTargets":16,"maximumFieldMutations":128,"maximumSnapshotBytes":2097152}
            }]
        });
        crate::BRegMetadata::from_slice(&serde_json::to_vec(&metadata).unwrap())
            .unwrap()
            .bind_source("https://registry.example/".to_owned())
            .select_immediate_action("update-item", "writer")
            .unwrap()
    }

    #[test]
    fn condition_tokens_are_exact_and_redacted() {
        assert!(valid_condition("\"opaque-condition\""));
        assert!(!valid_condition("W/\"opaque-condition\""));
        assert!(!valid_condition("\"has space\""));
        let condition = BRegActionPrecondition {
            if_match: "\"secret-condition-canary\"".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&condition).unwrap(),
            json!({"ifMatch": "\"secret-condition-canary\""})
        );
    }

    #[test]
    fn scalar_contracts_preserve_wire_types_and_bounds() {
        assert!(valid_action_input(
            &json!("éé"),
            &json!({"type":"string","minLength":2,"maxLength":2}),
            Some(4),
        ));
        assert!(!valid_action_input(
            &json!("éé"),
            &json!({"type":"string","minLength":2,"maxLength":2}),
            Some(3),
        ));
        assert!(valid_action_input(
            &json!("12.30"),
            &json!({"type":"decimal","precision":4,"scale":2,"minimum":"0.00","maximum":"99.99"}),
            None,
        ));
        assert!(!valid_action_input(
            &json!(12.30),
            &json!({"type":"decimal","precision":4,"scale":2}),
            None,
        ));
        assert!(valid_action_input(
            &json!("2026-09-10"),
            &json!({"type":"date"}),
            None,
        ));
        assert!(!valid_action_input(
            &json!("2026-02-30"),
            &json!({"type":"date"}),
            None,
        ));
        assert!(valid_action_input(
            &json!("2026-09-10T12:00:00Z"),
            &json!({"type":"timestamp"}),
            None,
        ));
        assert!(!valid_action_input(
            &json!(9_007_199_254_740_993_i64),
            &json!({"type":"int64"}),
            None,
        ));
        assert!(valid_action_input(
            &json!("00000000-0000-4000-8000-000000000001"),
            &json!({"type":"reference","target":"item","onDelete":"restrict"}),
            None,
        ));
        assert!(valid_action_input(
            &json!("active"),
            &json!({"type":"vocabulary-code","vocabulary":"state","values":["active","closed"]}),
            None,
        ));
        assert!(!valid_action_input(
            &json!("unknown"),
            &json!({"type":"vocabulary-code","vocabulary":"state","values":["active","closed"]}),
            None,
        ));
        assert!(valid_action_input(
            &json!({"type":"Point","coordinates":[100.5,13.7]}),
            &json!({
                "type":"crs84-point", "precision":6,
                "bbox":{"west":"100.0","south":"13.0","east":"101.0","north":"14.0"}
            }),
            None,
        ));
        assert!(!valid_action_input(
            &json!({"type":"Point","coordinates":[102.0,13.7]}),
            &json!({
                "type":"crs84-point", "precision":6,
                "bbox":{"west":"100.0","south":"13.0","east":"101.0","north":"14.0"}
            }),
            None,
        ));
        assert!(valid_action_input(
            &json!({"flag":true}),
            &json!({
                "type":"structured", "maxBytes":64,
                "schema":{
                    "type":"object", "additionalProperties":false,
                    "required":["flag"], "properties":{"flag":{"type":"boolean"}}
                }
            }),
            None,
        ));
        assert!(!valid_action_input(
            &json!({"flag":"yes"}),
            &json!({
                "type":"structured", "maxBytes":64,
                "schema":{
                    "type":"object", "additionalProperties":false,
                    "required":["flag"], "properties":{"flag":{"type":"boolean"}}
                }
            }),
            None,
        ));
    }

    #[test]
    fn requests_bind_saved_conditions_to_the_original_target() {
        let action = action_binding(false);
        let target = json!({"targetId":"00000000-0000-4000-8000-000000000001"})
            .as_object()
            .unwrap()
            .clone();
        let condition_request = BRegActionTargetConditionsRequest::new(&action, target).unwrap();
        let conditions = decode_conditions(
            br#"{"preconditions":{"targetId":{"ifMatch":"\"opaque-condition\""}}}"#,
            &action,
            &condition_request,
        )
        .unwrap();
        let invocation = json!({
            "targetId":"00000000-0000-4000-8000-000000000001",
            "label":"Changed"
        })
        .as_object()
        .unwrap()
        .clone();
        let request = BRegActionInvocationRequest::new(&action, invocation, Some(&conditions))
            .expect("saved conditions bind the same target");
        assert_eq!(
            crate::strict_json::from_slice(&request.body).unwrap(),
            json!({
                "input": {
                    "targetId":"00000000-0000-4000-8000-000000000001",
                    "label":"Changed"
                },
                "preconditions":{"targetId":{"ifMatch":"\"opaque-condition\""}}
            })
        );

        let wrong_target = json!({
            "targetId":"00000000-0000-4000-8000-000000000002",
            "label":"Changed"
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(matches!(
            BRegActionInvocationRequest::new(&action, wrong_target, Some(&conditions)),
            Err(BRegImmediateActionError::TargetConditionInputMismatch)
        ));
    }

    #[test]
    fn nullability_and_declared_types_are_enforced_before_an_exchange() {
        let fixed = action_binding(false);
        assert!(matches!(
            BRegActionTargetConditionsRequest::new(&fixed, Map::new()),
            Err(BRegImmediateActionError::MissingInput)
        ));
        let invalid = json!({
            "targetId":"00000000-0000-4000-8000-000000000001",
            "label":null
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(matches!(
            BRegActionInvocationRequest::new(&fixed, invalid, None),
            Err(BRegImmediateActionError::InvalidInput)
        ));

        let handler = action_binding(true);
        let target = json!({"targetId":"00000000-0000-4000-8000-000000000001"})
            .as_object()
            .unwrap()
            .clone();
        let condition_request = BRegActionTargetConditionsRequest::new(&handler, target).unwrap();
        let conditions = decode_conditions(
            br#"{"preconditions":{"targetId":{"ifMatch":"\"opaque-condition\""}}}"#,
            &handler,
            &condition_request,
        )
        .unwrap();
        assert!(matches!(
            BRegActionInvocationRequest::new(&handler, Map::new(), Some(&conditions)),
            Err(BRegImmediateActionError::MissingInput)
        ));
        let nullable = json!({
            "targetId":"00000000-0000-4000-8000-000000000001",
            "label":null
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(BRegActionInvocationRequest::new(&handler, nullable, Some(&conditions)).is_ok());
    }

    #[test]
    fn receipts_release_only_selected_effect_references() {
        let action = action_binding(false);
        let receipt = decode_receipt(
            br#"{"action":"update-item","applicationId":"00000000-0000-4000-8000-000000000010","results":{"item":{"entity":"item","recordId":"00000000-0000-4000-8000-000000000001","revision":2}}}"#,
            &action,
        )
        .unwrap();
        assert_eq!(receipt.results().len(), 1);
        assert_eq!(
            serde_json::to_value(&receipt).unwrap()["results"]["item"]["revision"],
            2
        );

        let undisclosed = br#"{"action":"update-item","applicationId":"00000000-0000-4000-8000-000000000010","results":{"secret":{"entity":"hidden","recordId":"00000000-0000-4000-8000-000000000002","revision":1}}}"#;
        assert!(matches!(
            decode_receipt(undisclosed, &action),
            Err(BRegImmediateActionError::InvalidResponse)
        ));
    }
}
