// SPDX-License-Identifier: Apache-2.0

//! Metadata-bound immediate-action inputs, target conditions, and receipts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jsonschema::{Draft, JSONSchema};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};
use time::{format_description::well_known::Rfc3339, Date, Month, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    BRegActionBinding, BRegComplete, BRegIdempotencyKey, BaseRegistryClient,
    BaseRegistryClientError,
};

const MAXIMUM_CONDITION_BYTES: usize = 256;

/// A value-free reason an immediate-action request or response is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegActionError {
    #[error("the Base Registry Engine action input object contains an unknown field")]
    UnknownInput,
    #[error("the Base Registry Engine action input object is missing a required field")]
    MissingInput,
    #[error("a Base Registry Engine action input does not match its declared type and bounds")]
    InvalidInput,
    #[error("the Base Registry Engine action has no target-condition exchange")]
    TargetConditionsUnavailable,
    #[error("the Base Registry Engine action has no availability exchange")]
    AvailabilityUnavailable,
    #[error("the Base Registry Engine action availability target is invalid")]
    InvalidAvailabilityTarget,
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

/// Exact availability request bound to one caller-filtered immediate action.
pub struct BRegActionAvailabilityRequest {
    body: Zeroizing<Vec<u8>>,
    binding: ActionAvailabilityRequestBinding,
    supplied_inputs: BTreeSet<String>,
}

impl BRegActionAvailabilityRequest {
    /// Build one per-reference availability query. Every supplied value is
    /// validated, while unrelated required form inputs may remain absent.
    pub fn new(
        action: &BRegActionBinding,
        target_input: impl Into<String>,
        inputs: Map<String, Value>,
    ) -> Result<Self, BRegActionError> {
        let target_input = target_input.into();
        let path = action
            .availability_path()
            .ok_or(BRegActionError::AvailabilityUnavailable)?;
        validate_availability_inputs(action, &target_input, &inputs)?;
        let supplied_inputs = inputs.keys().cloned().collect();
        let body = encode_bounded(
            &ActionAvailabilityEnvelope {
                target_input: &target_input,
                input: &inputs,
            },
            action.bounds().maximum_snapshot_bytes(),
        )?;
        Ok(Self {
            body: Zeroizing::new(body),
            binding: ActionAvailabilityRequestBinding::from_action(action, path),
            supplied_inputs,
        })
    }

    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl fmt::Debug for BRegActionAvailabilityRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegActionAvailabilityRequest")
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Validated availability of one immediate action for one selected reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegActionAvailability {
    available: Option<bool>,
    observed_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guard_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    missing_inputs: Option<Vec<String>>,
}

impl BRegActionAvailability {
    #[must_use]
    pub const fn available(&self) -> Option<bool> {
        self.available
    }

    #[must_use]
    pub const fn observed_revision(&self) -> Option<u64> {
        self.observed_revision
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Authored copy key disclosed only with readable guard and boundary facts.
    pub fn guard_reason(&self) -> Option<&str> {
        self.guard_reason.as_deref()
    }

    #[must_use]
    pub fn recovery(&self) -> Option<&str> {
        self.recovery.as_deref()
    }

    #[must_use]
    pub fn missing_inputs(&self) -> Option<&[String]> {
        self.missing_inputs.as_deref()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ActionAvailabilityRequestBinding {
    source_binding: String,
    registry_revision: String,
    action_identifier: String,
    access_profile: String,
    action_revision: String,
    path: String,
}

impl ActionAvailabilityRequestBinding {
    fn from_action(action: &BRegActionBinding, path: &str) -> Self {
        Self {
            source_binding: action.source_binding().to_owned(),
            registry_revision: action.registry_revision().to_owned(),
            action_identifier: action.action_identifier().to_owned(),
            access_profile: action.access_profile().to_owned(),
            action_revision: action.definition_revision().to_owned(),
            path: path.to_owned(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionAvailabilityEnvelope<'a> {
    target_input: &'a str,
    input: &'a Map<String, Value>,
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
        action: &BRegActionBinding,
        inputs: Map<String, Value>,
    ) -> Result<Self, BRegActionError> {
        if action.target_conditions_path().is_none() {
            return Err(BRegActionError::TargetConditionsUnavailable);
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
    /// Validate invocation inputs before acquiring any target conditions.
    pub fn validate_inputs(
        action: &BRegActionBinding,
        inputs: &Map<String, Value>,
    ) -> Result<(), BRegActionError> {
        validate_inputs(action, inputs, ActionInputUse::Invoke)
    }

    pub fn new(
        action: &BRegActionBinding,
        inputs: Map<String, Value>,
        conditions: Option<&BRegActionTargetConditions>,
    ) -> Result<Self, BRegActionError> {
        validate_inputs(action, &inputs, ActionInputUse::Invoke)?;
        let requires_conditions = !action.required_condition_keys().is_empty();
        let preconditions = match (requires_conditions, conditions) {
            (false, None) => None,
            (_, Some(conditions)) => {
                let binding = ActionRequestBinding::from_action(action);
                if conditions.binding != binding {
                    return Err(BRegActionError::TargetConditionBindingMismatch);
                }
                let target_inputs = action
                    .required_condition_keys()
                    .iter()
                    .map(|name| inputs.get(name).cloned().map(|value| (name.clone(), value)))
                    .collect::<Option<Map<_, _>>>()
                    .ok_or(BRegActionError::TargetConditionInputMismatch)?;
                let target_input_body = Zeroizing::new(encode_bounded(
                    &ActionInputEnvelope {
                        input: &target_inputs,
                    },
                    action.bounds().maximum_snapshot_bytes(),
                )?);
                if target_input_body.as_slice() != conditions.target_input_body.as_slice() {
                    return Err(BRegActionError::TargetConditionInputMismatch);
                }
                Some(&conditions.preconditions)
            }
            (true, None) => {
                return Err(BRegActionError::TargetConditionBindingMismatch);
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

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ActionRequestBinding {
    source_binding: String,
    registry_revision: String,
    action_identifier: String,
    access_profile: String,
    action_revision: String,
    mode: crate::BRegActionMode,
    path: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActionRecoveryEvidence {
    version: u8,
    binding: ActionRequestBinding,
    body: String,
    idempotency_key: String,
}

/// Inert original invocation evidence for explicit recovery after a lost response.
/// These bytes contain inputs and target conditions, never a bearer token. Keep
/// them in application-protected storage and reacquire caller-filtered metadata.
pub struct BRegPreparedAction(Zeroizing<Vec<u8>>);

impl BRegPreparedAction {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BaseRegistryClientError> {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(action_recovery_refusal());
        }
        let value = crate::strict_json::from_slice(bytes).map_err(|_| action_recovery_refusal())?;
        let evidence: ActionRecoveryEvidence =
            serde_json::from_value(value).map_err(|_| action_recovery_refusal())?;
        if evidence.version != 1 {
            return Err(action_recovery_refusal());
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BRegPreparedAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegPreparedAction(<redacted>)")
    }
}

fn action_recovery_refusal() -> BaseRegistryClientError {
    BaseRegistryClientError::invalid_request(
        "the prepared action does not match the original input, key, or current authority",
    )
}

impl ActionRequestBinding {
    fn from_action(action: &BRegActionBinding) -> Self {
        Self {
            source_binding: action.source_binding().to_owned(),
            registry_revision: action.registry_revision().to_owned(),
            action_identifier: action.action_identifier().to_owned(),
            access_profile: action.access_profile().to_owned(),
            action_revision: action.definition_revision().to_owned(),
            mode: action.mode(),
            path: action.invoke_path().to_owned(),
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct BRegActionResultReference {
    #[serde(rename = "recordType")]
    entity: String,
    #[serde(serialize_with = "serialize_uuid")]
    record_id: Uuid,
    revision: u64,
}

impl BRegActionResultReference {
    #[must_use]
    pub fn record_type_identifier(&self) -> &str {
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// Read the current field-guard availability for one selected reference.
    /// This performs exactly one exchange and never retries automatically.
    pub async fn action_availability(
        &self,
        action: &BRegActionBinding,
        request: &BRegActionAvailabilityRequest,
    ) -> Result<BRegComplete<BRegActionAvailability>, BaseRegistryClientError> {
        let path = action.availability_path().ok_or_else(|| {
            BaseRegistryClientError::invalid_request(
                "the Base Registry Engine action has no availability exchange",
            )
        })?;
        let expected = ActionAvailabilityRequestBinding::from_action(action, path);
        if request.binding != expected || !action.matches_source(&self.source_binding()) {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine availability request belongs to another selected action",
            ));
        }
        let raw = self
            .execute_bound_json(path, action.access_profile(), request.body.to_vec(), None)
            .await?;
        let availability =
            decode_availability(raw.value.as_bytes(), action, &request.supplied_inputs).map_err(
                |_| {
                    BaseRegistryClientError::protocol(
                        200,
                        crate::BRegProtocolFailure::Body,
                        Some(raw.metadata.trace_id().clone()),
                    )
                },
            )?;
        Ok(BRegComplete {
            value: availability,
            metadata: raw.metadata,
        })
    }

    /// Retain the exact invocation and idempotency key before sending. No I/O.
    pub fn prepare_action(
        &self,
        action: &BRegActionBinding,
        request: &BRegActionInvocationRequest,
        key: &BRegIdempotencyKey,
    ) -> Result<BRegPreparedAction, BaseRegistryClientError> {
        self.validate_action_request(action, &request.binding)?;
        let value = ActionRecoveryEvidence {
            version: 1,
            binding: request.binding.clone(),
            body: std::str::from_utf8(&request.body)
                .map_err(|_| action_recovery_refusal())?
                .to_owned(),
            idempotency_key: key.as_str().to_owned(),
        };
        let bytes =
            Zeroizing::new(serde_json::to_vec(&value).map_err(|_| action_recovery_refusal())?);
        BRegPreparedAction::from_slice(&bytes)
    }

    /// Restore the original request under fresh caller-filtered metadata. Saved
    /// target conditions are reused exactly; this never fetches newer conditions
    /// or sends a mutation. The caller explicitly invokes with the same key.
    pub fn recover_action(
        &self,
        action: &BRegActionBinding,
        prepared: &BRegPreparedAction,
        original_inputs: &Map<String, Value>,
        original_key: &BRegIdempotencyKey,
    ) -> Result<BRegActionInvocationRequest, BaseRegistryClientError> {
        let saved: ActionRecoveryEvidence =
            serde_json::from_slice(prepared.as_bytes()).map_err(|_| action_recovery_refusal())?;
        self.validate_action_request(action, &saved.binding)?;
        if saved.idempotency_key != original_key.as_str() {
            return Err(action_recovery_refusal());
        }
        let value = crate::strict_json::from_slice(saved.body.as_bytes())
            .map_err(|_| action_recovery_refusal())?;
        let object = value.as_object().ok_or_else(action_recovery_refusal)?;
        if object.get("input") != Some(&Value::Object(original_inputs.clone()))
            || object
                .keys()
                .any(|key| !matches!(key.as_str(), "input" | "preconditions"))
        {
            return Err(action_recovery_refusal());
        }
        let conditions = if action.required_condition_keys().is_empty()
            && !object.contains_key("preconditions")
        {
            None
        } else {
            let inputs = action
                .required_condition_keys()
                .iter()
                .map(|key| {
                    original_inputs
                        .get(key)
                        .cloned()
                        .map(|value| (key.clone(), value))
                })
                .collect::<Option<Map<String, Value>>>()
                .ok_or_else(action_recovery_refusal)?;
            let request = BRegActionTargetConditionsRequest::new(action, inputs)
                .map_err(|_| action_recovery_refusal())?;
            let bytes = serde_json::to_vec(
                &serde_json::json!({"preconditions": object.get("preconditions")}),
            )
            .map_err(|_| action_recovery_refusal())?;
            Some(
                decode_conditions(&bytes, action, &request)
                    .map_err(|_| action_recovery_refusal())?,
            )
        };
        let restored =
            BRegActionInvocationRequest::new(action, original_inputs.clone(), conditions.as_ref())
                .map_err(|_| action_recovery_refusal())?;
        if restored.body.as_slice() != saved.body.as_bytes() {
            return Err(action_recovery_refusal());
        }
        Ok(restored)
    }

    /// Fetch target conditions for the caller's currently selected records.
    /// This performs exactly one exchange and never refreshes a condition.
    pub async fn action_target_conditions(
        &self,
        action: &BRegActionBinding,
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
    /// and idempotency key. An invocation whose outcome is unknown is resent
    /// identically under the same key, at most as many times as the configured
    /// mutation retry count.
    pub async fn invoke_action(
        &self,
        action: &BRegActionBinding,
        request: &BRegActionInvocationRequest,
        idempotency_key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegActionReceipt>, BaseRegistryClientError> {
        self.validate_action_request(action, &request.binding)?;
        if action.mode() != crate::BRegActionMode::Immediate {
            return Err(action_recovery_refusal());
        }
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

    /// Start a distinct Proposal using this Action's authored fixed mode.
    pub async fn start_proposal(
        &self,
        action: &BRegActionBinding,
        request: &BRegActionInvocationRequest,
        idempotency_key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<crate::BRegProposal>, BaseRegistryClientError> {
        self.validate_action_request(action, &request.binding)?;
        if action.mode() != crate::BRegActionMode::Proposal {
            return Err(action_recovery_refusal());
        }
        let raw = self
            .execute_action_start(
                action.invoke_path(),
                action.access_profile(),
                request.body.to_vec(),
                idempotency_key,
            )
            .await?;
        let invalid_receipt = || {
            BaseRegistryClientError::protocol(
                201,
                crate::BRegProtocolFailure::Body,
                Some(raw.metadata.trace_id().clone()),
            )
        };
        let proposal =
            crate::BRegProposal::from_slice(raw.value.as_bytes()).map_err(|_| invalid_receipt())?;
        if proposal.action_id() != action.action_identifier()
            || proposal.action_revision() != action.definition_revision()
            || proposal.state() != crate::BRegProposalState::Draft
        {
            return Err(invalid_receipt());
        }
        Ok(BRegComplete {
            value: proposal
                .bind_profile(self.source_binding(), action.access_profile())
                .map_err(|_| invalid_receipt())?,
            metadata: raw.metadata,
        })
    }

    fn validate_action_request(
        &self,
        action: &BRegActionBinding,
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
    action: &BRegActionBinding,
    inputs: &Map<String, Value>,
    use_for: ActionInputUse,
) -> Result<(), BRegActionError> {
    let accepted = match use_for {
        ActionInputUse::TargetConditions => {
            if action.required_condition_keys().iter().any(|name| {
                !action
                    .reference_inputs()
                    .iter()
                    .any(|reference| reference.api_name() == name)
            }) {
                return Err(BRegActionError::InvalidInput);
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
        return Err(BRegActionError::UnknownInput);
    }
    for name in accepted {
        let contract = action
            .inputs()
            .iter()
            .find(|input| input.api_name() == name)
            .ok_or(BRegActionError::InvalidInput)?;
        let required = match use_for {
            ActionInputUse::TargetConditions => true,
            ActionInputUse::Invoke => {
                contract.required() && action.mode() == crate::BRegActionMode::Immediate
            }
        };
        let Some(value) = inputs.get(&name) else {
            if required {
                return Err(BRegActionError::MissingInput);
            }
            continue;
        };
        if value.is_null() {
            if contract.nullable() {
                continue;
            }
            return Err(BRegActionError::InvalidInput);
        }
        if !valid_action_input(
            value,
            contract.field_type(),
            action.maximum_input_string_bytes(),
        ) {
            return Err(BRegActionError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_availability_inputs(
    action: &BRegActionBinding,
    target_input: &str,
    inputs: &Map<String, Value>,
) -> Result<(), BRegActionError> {
    let reference = action
        .reference_inputs()
        .iter()
        .find(|reference| reference.api_name() == target_input)
        .ok_or(BRegActionError::InvalidAvailabilityTarget)?;
    let target = inputs
        .get(reference.api_name())
        .filter(|value| !value.is_null())
        .ok_or(BRegActionError::InvalidAvailabilityTarget)?;
    if target.as_str().and_then(canonical_uuid).is_none() {
        return Err(BRegActionError::InvalidAvailabilityTarget);
    }
    for (name, value) in inputs {
        let contract = action
            .inputs()
            .iter()
            .find(|input| input.api_name() == name)
            .ok_or(BRegActionError::UnknownInput)?;
        if value.is_null() {
            if contract.nullable() && name != target_input {
                continue;
            }
            return Err(BRegActionError::InvalidInput);
        }
        if !valid_action_input(
            value,
            contract.field_type(),
            action.maximum_input_string_bytes(),
        ) {
            return Err(BRegActionError::InvalidInput);
        }
    }
    Ok(())
}

fn decode_availability(
    bytes: &[u8],
    action: &BRegActionBinding,
    supplied_inputs: &BTreeSet<String>,
) -> Result<BRegActionAvailability, BRegActionError> {
    let value =
        crate::strict_json::from_slice(bytes).map_err(|_| BRegActionError::InvalidResponse)?;
    let outer = value
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or(BRegActionError::InvalidResponse)?;
    let availability = outer
        .get("availability")
        .and_then(Value::as_object)
        .ok_or(BRegActionError::InvalidResponse)?;
    if availability.keys().any(|key| {
        !matches!(
            key.as_str(),
            "available"
                | "observedRevision"
                | "reason"
                | "recovery"
                | "missingInputs"
                | "guardReason"
        )
    }) {
        return Err(BRegActionError::InvalidResponse);
    }
    let available = match availability.get("available") {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::Null) => None,
        _ => return Err(BRegActionError::InvalidResponse),
    };
    let observed_revision = match availability.get("observedRevision") {
        Some(Value::Number(value)) => value
            .as_u64()
            .filter(|revision| *revision > 0 && *revision <= i64::MAX as u64),
        Some(Value::Null) => None,
        _ => return Err(BRegActionError::InvalidResponse),
    };
    if availability.get("observedRevision") != Some(&Value::Null) && observed_revision.is_none() {
        return Err(BRegActionError::InvalidResponse);
    }
    let optional_string = |name: &str| match availability.get(name) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(BRegActionError::InvalidResponse),
    };
    let reason = optional_string("reason")?;
    let guard_reason = optional_string("guardReason")?;
    let recovery = optional_string("recovery")?;
    let missing_inputs = availability
        .get("missingInputs")
        .map(|value| {
            value
                .as_array()
                .ok_or(BRegActionError::InvalidResponse)?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(BRegActionError::InvalidResponse)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let valid = match (
        available,
        observed_revision,
        reason.as_deref(),
        recovery.as_deref(),
        missing_inputs.as_deref(),
    ) {
        (Some(true), Some(_), None, None, None) => true,
        (Some(false), Some(_), Some("guard-not-satisfied"), Some("none"), None) => true,
        (None, Some(_), Some("input-required"), Some("correct-input"), Some(missing)) => {
            let unique = missing.iter().collect::<BTreeSet<_>>();
            !missing.is_empty()
                && unique.len() == missing.len()
                && missing.iter().all(|name| {
                    !supplied_inputs.contains(name)
                        && action.inputs().iter().any(|input| input.api_name() == name)
                })
        }
        (None, None, Some("not-disclosed"), Some("none"), None) => true,
        _ => false,
    };
    if !valid
        || guard_reason.as_deref().is_some_and(|reason| {
            available != Some(false) || !crate::error::valid_guard_reason(reason)
        })
    {
        return Err(BRegActionError::InvalidResponse);
    }
    Ok(BRegActionAvailability {
        available,
        observed_revision,
        reason,
        guard_reason,
        recovery,
        missing_inputs,
    })
}

fn decode_conditions(
    bytes: &[u8],
    action: &BRegActionBinding,
    request: &BRegActionTargetConditionsRequest,
) -> Result<BRegActionTargetConditions, BRegActionError> {
    let value =
        crate::strict_json::from_slice(bytes).map_err(|_| BRegActionError::InvalidResponse)?;
    let object = value
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or(BRegActionError::InvalidResponse)?;
    let conditions = object
        .get("preconditions")
        .and_then(Value::as_object)
        .ok_or(BRegActionError::InvalidResponse)?;
    if conditions.len() != action.required_condition_keys().len()
        || conditions
            .keys()
            .any(|name| !action.required_condition_keys().contains(name))
    {
        return Err(BRegActionError::InvalidResponse);
    }
    let preconditions = conditions
        .iter()
        .map(|(name, value)| {
            let condition = value
                .as_object()
                .filter(|condition| condition.len() == 1)
                .ok_or(BRegActionError::InvalidResponse)?;
            let if_match = condition
                .get("ifMatch")
                .and_then(Value::as_str)
                .filter(|value| valid_condition(value))
                .ok_or(BRegActionError::InvalidResponse)?;
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
    action: &BRegActionBinding,
) -> Result<BRegActionReceipt, BRegActionError> {
    let value =
        crate::strict_json::from_slice(bytes).map_err(|_| BRegActionError::InvalidResponse)?;
    let object = value
        .as_object()
        .filter(|object| object.len() == 3)
        .ok_or(BRegActionError::InvalidResponse)?;
    if object.get("action").and_then(Value::as_str) != Some(action.action_identifier()) {
        return Err(BRegActionError::InvalidResponse);
    }
    let application_id = object
        .get("applicationId")
        .and_then(Value::as_str)
        .and_then(canonical_uuid)
        .filter(|identifier| !identifier.is_nil())
        .ok_or(BRegActionError::InvalidResponse)?;
    let values = object
        .get("results")
        .and_then(Value::as_object)
        .ok_or(BRegActionError::InvalidResponse)?;
    if values.len() > action.result_effects().len()
        || (!action.is_handler() && values.len() != action.result_effects().len())
        || values
            .keys()
            .any(|name| !action.result_effects().contains_key(name))
    {
        return Err(BRegActionError::InvalidResponse);
    }
    let results = values
        .iter()
        .map(|(effect, value)| {
            let result = value
                .as_object()
                .filter(|result| result.len() == 3)
                .ok_or(BRegActionError::InvalidResponse)?;
            let entity = result
                .get("recordType")
                .and_then(Value::as_str)
                .filter(|entity| {
                    action
                        .result_effects()
                        .get(effect)
                        .is_some_and(|v| v == entity)
                })
                .ok_or(BRegActionError::InvalidResponse)?;
            let record_id = result
                .get("recordId")
                .and_then(Value::as_str)
                .and_then(canonical_uuid)
                .ok_or(BRegActionError::InvalidResponse)?;
            let revision = result
                .get("revision")
                .and_then(Value::as_u64)
                .filter(|revision| *revision > 0 && *revision <= i64::MAX as u64)
                .ok_or(BRegActionError::InvalidResponse)?;
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

fn encode_bounded(value: &impl Serialize, maximum_bytes: u64) -> Result<Vec<u8>, BRegActionError> {
    let body = serde_json::to_vec(value).map_err(|_| BRegActionError::BodyEncoding)?;
    if u64::try_from(body.len()).map_or(true, |length| length > maximum_bytes) {
        return Err(BRegActionError::BodyTooLarge);
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
    let Some(maximum) = contract.get("maximumLength").and_then(Value::as_u64) else {
        return false;
    };
    let minimum = contract
        .get("minimumLength")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let length = value.chars().count() as u64;
    length >= minimum && length <= maximum
}

fn valid_text(value: &Value, contract: &Map<String, Value>) -> bool {
    value.as_str().is_some_and(|value| {
        contract
            .get("maximumLength")
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
    let Some(maximum) = contract.get("maximumBytes").and_then(Value::as_u64) else {
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

    fn action_binding(handler: bool) -> BRegActionBinding {
        action_binding_with_conditions(handler, true)
    }

    fn action_binding_with_conditions(handler: bool, required: bool) -> BRegActionBinding {
        action_binding_at_source(handler, required, "https://registry.example/")
    }

    fn action_binding_at_source(handler: bool, required: bool, source: &str) -> BRegActionBinding {
        let input_mode = if handler { "handler" } else { "fixed" };
        let maximum_string_bytes = handler.then_some(json!(16_384)).unwrap_or(Value::Null);
        let optional_nullable = handler;
        let metadata = json!({
            "id": "fixture-registry",
            "version": "1",
            "revision": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "metadataVersion": "2",
            "recordTypes": [],
            "operations": [],
            "actions": [{
                "id": "update-item", "apiName":"updateItem", "revision":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "display":{}, "execution":{"mode":"immediate"},
                "route": "/v1/actions/update-item",
                "conditionRoute": "/v1/actions/update-item/target-conditions",
                "inputMode": input_mode,
                "maximumInputStringBytes": maximum_string_bytes,
                "inputs": [
                    {
                        "id": "target", "apiName": "targetId", "required": true,
                        "nullable": false, "classification": "internal",
                        "schema": {"type":"string","format":"uuid"},
                        "fieldType": {"type":"reference","target":"item","onDelete":"restrict"}
                    },
                    {
                        "id": "label", "apiName": "label", "required": false,
                        "nullable": optional_nullable, "classification": "internal",
                        "schema": if optional_nullable { json!({"anyOf":[{"type":"string","minLength":1,"maxLength":16},{"type":"null"}]}) } else { json!({"type":"string","minLength":1,"maxLength":16}) },
                        "fieldType": {"type":"string","minimumLength":1,"maximumLength":16}
                    }
                ],
                "referenceInputs": [{"input":"target","apiName":"targetId","targetRecordType":"item"}],
                "requiredConditionKeys": if required { json!(["targetId"]) } else { json!([]) },
                "resultEffects": [{"effect":"item","recordType":"item","operation":"patch"}],
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
                        "operationId":"actions.update-item.target-conditions", "requiresIdempotencyKey":false,
                        "inputSchema":"action-update-item-target-conditions-input",
                        "responseSchema":"action-update-item-target-conditions-response"
                    },
                    "availability": {
                        "method":"POST", "path":"/v1/actions/update-item/availability",
                        "operationId":"actions.update-item.availability", "requiresIdempotencyKey":false,
                        "inputSchema":"action-update-item-availability-input",
                        "responseSchema":"action-update-item-availability-response"
                    }
                },
                "bounds": {"maximumTargets":16,"maximumFieldMutations":128,"maximumSnapshotBytes":2097152}
            }]
        });
        crate::BRegMetadata::from_slice(&serde_json::to_vec(&metadata).unwrap())
            .unwrap()
            .bind_source(source.to_owned())
            .select_action("update-item", "writer")
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
    fn availability_request_validates_subset_and_response_cases() {
        let action = action_binding(true);
        let target = "00000000-0000-4000-8000-000000000001";
        let request = BRegActionAvailabilityRequest::new(
            &action,
            "targetId",
            json!({"targetId": target}).as_object().unwrap().clone(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).unwrap(),
            json!({"targetInput":"targetId","input":{"targetId":target}})
        );
        assert!(BRegActionAvailabilityRequest::new(
            &action,
            "targetId",
            json!({"targetId":target,"label":false})
                .as_object()
                .unwrap()
                .clone(),
        )
        .is_err());
        assert!(BRegActionAvailabilityRequest::new(
            &action,
            "label",
            json!({"targetId":target}).as_object().unwrap().clone(),
        )
        .is_err());

        let cases = [
            (
                json!({"availability":{"available":true,"observedRevision":3}}),
                Some(true),
            ),
            (
                json!({"availability":{"available":true,"observedRevision":i64::MAX}}),
                Some(true),
            ),
            (
                json!({"availability":{"available":false,"observedRevision":3,"reason":"guard-not-satisfied","recovery":"none"}}),
                Some(false),
            ),
            (
                json!({"availability":{"available":null,"observedRevision":3,"reason":"input-required","recovery":"correct-input","missingInputs":["label"]}}),
                None,
            ),
            (
                json!({"availability":{"available":null,"observedRevision":null,"reason":"not-disclosed","recovery":"none"}}),
                None,
            ),
        ];
        for (document, expected) in cases {
            let decoded = decode_availability(
                &serde_json::to_vec(&document).unwrap(),
                &action,
                &request.supplied_inputs,
            )
            .unwrap();
            assert_eq!(decoded.available(), expected);
        }
        for invalid in [
            json!({"availability":{"available":true,"observedRevision":0}}),
            json!({"availability":{"available":true,"observedRevision":u64::MAX}}),
            json!({"availability":{"available":false,"observedRevision":3,"reason":"other","recovery":"none"}}),
            json!({"availability":{"available":null,"observedRevision":3,"reason":"input-required","recovery":"correct-input","missingInputs":[]}}),
            json!({"availability":{"available":null,"observedRevision":3,"reason":"input-required","recovery":"correct-input","missingInputs":["label","label"]}}),
            json!({"availability":{"available":null,"observedRevision":3,"reason":"input-required","recovery":"correct-input","missingInputs":["targetId"]}}),
            json!({"availability":{"available":null,"observedRevision":null,"reason":"not-disclosed","recovery":"none","missingInputs":[]}}),
        ] {
            assert!(decode_availability(
                &serde_json::to_vec(&invalid).unwrap(),
                &action,
                &request.supplied_inputs,
            )
            .is_err());
        }
    }

    #[test]
    fn prepared_action_preserves_original_conditions_and_refuses_changed_authority_or_input() {
        let client = BaseRegistryClient::new(crate::BaseRegistryClientConfig::new(
            "https://registry.example/".parse().unwrap(),
        ))
        .unwrap();
        let action = action_binding(false);
        let target = serde_json::json!({"targetId":"00000000-0000-4000-8000-000000000001"})
            .as_object()
            .unwrap()
            .clone();
        let condition_request =
            BRegActionTargetConditionsRequest::new(&action, target.clone()).unwrap();
        let conditions = decode_conditions(
            br#"{"preconditions":{"targetId":{"ifMatch":"\"original-condition-canary\""}}}"#,
            &action,
            &condition_request,
        )
        .unwrap();
        let mut input = target;
        input.insert("label".to_owned(), serde_json::json!("Input canary"));
        let request =
            BRegActionInvocationRequest::new(&action, input.clone(), Some(&conditions)).unwrap();
        let key = BRegIdempotencyKey::parse("original-action-key").unwrap();
        let prepared = client.prepare_action(&action, &request, &key).unwrap();
        let parsed = BRegPreparedAction::from_slice(prepared.as_bytes()).unwrap();
        assert!(!format!("{parsed:?}").contains("canary"));
        let recovered = client
            .recover_action(&action, &parsed, &input, &key)
            .unwrap();
        assert_eq!(recovered.body.as_slice(), request.body.as_slice());
        assert!(client
            .recover_action(
                &action,
                &parsed,
                &input,
                &BRegIdempotencyKey::parse("different-key").unwrap()
            )
            .is_err());
        let mut changed_input = input.clone();
        changed_input.insert(
            "targetId".to_owned(),
            serde_json::json!("00000000-0000-4000-8000-000000000002"),
        );
        assert!(client
            .recover_action(&action, &parsed, &changed_input, &key)
            .is_err());
        for path in [
            "/binding/source_binding",
            "/binding/access_profile",
            "/binding/registry_revision",
            "/binding/action_revision",
            "/binding/action_identifier",
        ] {
            let mut changed: Value = serde_json::from_slice(prepared.as_bytes()).unwrap();
            *changed.pointer_mut(path).unwrap() = serde_json::json!("changed");
            let parsed =
                BRegPreparedAction::from_slice(&serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(client
                .recover_action(&action, &parsed, &input, &key)
                .is_err());
        }
        let mut changed: Value = serde_json::from_slice(prepared.as_bytes()).unwrap();
        changed["body"] = serde_json::json!("{\"input\":{},\"unexpected\":true}");
        let parsed =
            BRegPreparedAction::from_slice(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(client
            .recover_action(&action, &parsed, &input, &key)
            .is_err());
        assert!(BRegPreparedAction::from_slice(br#"{"version":1,"version":1}"#).is_err());
    }

    #[test]
    fn prepared_action_roundtrips_absent_and_explicit_empty_conditions() {
        let client = BaseRegistryClient::new(crate::BaseRegistryClientConfig::new(
            "https://registry.example/".parse().unwrap(),
        ))
        .unwrap();
        let action = action_binding_with_conditions(false, false);
        let inputs = json!({"targetId":"00000000-0000-4000-8000-000000000001"})
            .as_object()
            .unwrap()
            .clone();
        let conditions_request =
            BRegActionTargetConditionsRequest::new(&action, Map::new()).unwrap();
        let empty =
            decode_conditions(br#"{"preconditions":{}}"#, &action, &conditions_request).unwrap();
        let key = BRegIdempotencyKey::parse("empty-conditions").unwrap();
        for conditions in [None, Some(&empty)] {
            let request =
                BRegActionInvocationRequest::new(&action, inputs.clone(), conditions).unwrap();
            let prepared = client.prepare_action(&action, &request, &key).unwrap();
            let recovered = client
                .recover_action(&action, &prepared, &inputs, &key)
                .unwrap();
            assert_eq!(recovered.body.as_slice(), request.body.as_slice());
        }
    }

    #[test]
    fn scalar_contracts_preserve_wire_types_and_bounds() {
        assert!(valid_action_input(
            &json!("éé"),
            &json!({"type":"string","minimumLength":2,"maximumLength":2}),
            Some(4),
        ));
        assert!(!valid_action_input(
            &json!("éé"),
            &json!({"type":"string","minimumLength":2,"maximumLength":2}),
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
                "type":"structured", "maximumBytes":64,
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
                "type":"structured", "maximumBytes":64,
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
            Err(BRegActionError::TargetConditionInputMismatch)
        ));
    }

    #[test]
    fn nullability_and_declared_types_are_enforced_before_an_exchange() {
        let fixed = action_binding(false);
        assert!(matches!(
            BRegActionTargetConditionsRequest::new(&fixed, Map::new()),
            Err(BRegActionError::MissingInput)
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
            Err(BRegActionError::InvalidInput)
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
            Err(BRegActionError::MissingInput)
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

    #[tokio::test]
    async fn invocation_receipts_require_non_nil_application_ids_without_restricting_record_ids() {
        use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post, Json, Router};
        use std::sync::{Arc, Mutex};
        type InvocationFixture = (Arc<Mutex<Value>>, Arc<Mutex<Vec<(String, Vec<u8>)>>>);
        let nil = "00000000-0000-0000-0000-000000000000";
        let canonical = "123e4567-e89b-42d3-a456-426614174000";
        let receipt = Arc::new(Mutex::new(
            json!({"action":"update-item","applicationId":nil,
            "results":{"item":{"recordType":"item","recordId":nil,"revision":2}}}),
        ));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route(
                "/v1/actions/update-item",
                post(
                    |State((receipt, requests)): State<InvocationFixture>,
                     headers: HeaderMap,
                     body: Bytes| async move {
                        requests.lock().unwrap().push((
                            headers["idempotency-key"].to_str().unwrap().to_owned(),
                            body.to_vec(),
                        ));
                        (
                            [
                                (
                                    "traceparent",
                                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                                ),
                                ("cache-control", "no-store"),
                                ("vary", "authorization, accept"),
                            ],
                            Json(receipt.lock().unwrap().clone()),
                        )
                    },
                ),
            )
            .with_state((receipt.clone(), requests.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        // Keep the default retry budget: malformed successful evidence is never resent.
        let client = BaseRegistryClient::new(crate::BaseRegistryClientConfig::new(
            format!("http://{address}/").parse().unwrap(),
        ))
        .unwrap();
        let action = action_binding_at_source(false, false, &client.source_binding());
        let input = json!({"targetId":"00000000-0000-4000-8000-000000000001"})
            .as_object()
            .unwrap()
            .clone();
        let request = BRegActionInvocationRequest::new(&action, input.clone(), None).unwrap();
        let key = BRegIdempotencyKey::parse("application-identity").unwrap();
        let prepared = client.prepare_action(&action, &request, &key).unwrap();
        for application_id in [
            nil.to_owned(),
            canonical.to_uppercase(),
            canonical.replace('-', ""),
        ] {
            receipt.lock().unwrap()["applicationId"] = json!(application_id);
            let count = requests.lock().unwrap().len();
            let error = client
                .invoke_action(&action, &request, &key)
                .await
                .expect_err("malformed application evidence");
            assert!(matches!(
                error,
                BaseRegistryClientError::Protocol {
                    status: 200,
                    failure: crate::BRegProtocolFailure::Body,
                    ..
                }
            ));
            assert!(error.is_outcome_unknown());
            assert_eq!(requests.lock().unwrap().len(), count + 1);
        }
        for application_id in [
            "123e4567-e89b-12d3-a456-426614174000",
            canonical,
            "0192a870-1234-7abc-8def-123456789abc",
        ] {
            receipt.lock().unwrap()["applicationId"] = json!(application_id);
            let observed = client
                .invoke_action(&action, &request, &key)
                .await
                .unwrap()
                .value;
            assert_eq!(
                observed.application_identifier().to_string(),
                application_id
            );
            assert!(observed.results()["item"].record_identifier().is_nil());
        }
        let sent = requests.lock().unwrap().last().unwrap().clone();
        let restored = BRegPreparedAction::from_slice(prepared.as_bytes()).unwrap();
        let recovered = client
            .recover_action(&action, &restored, &input, &key)
            .unwrap();
        client
            .invoke_action(&action, &recovered, &key)
            .await
            .unwrap();
        assert_eq!(requests.lock().unwrap().last().unwrap(), &sent);
        server.abort();
    }

    #[test]
    fn receipts_release_only_selected_effect_references() {
        let action = action_binding(false);
        let receipt = decode_receipt(
            br#"{"action":"update-item","applicationId":"00000000-0000-4000-8000-000000000010","results":{"item":{"recordType":"item","recordId":"00000000-0000-4000-8000-000000000001","revision":2}}}"#,
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
            Err(BRegActionError::InvalidResponse)
        ));
    }
}
