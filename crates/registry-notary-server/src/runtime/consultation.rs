// SPDX-License-Identifier: Apache-2.0
//! Request-scoped Relay consultation coalescing.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, Once, OnceLock};

use base64::Engine as _;
use registry_notary_core::{EvidenceAuthProfileId, RelayFactContract};
use registry_platform_crypto::canonicalize_json;
use registry_platform_httputil::destination::json::ProjectedJsonScalar;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::Notify;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::relay_client::{
    RelayClientError, RelayConsultationOutcome, RelayInputNames, RelayMatchData,
    VerifiedRelayClient,
};

pub(crate) const MAX_CONSULTATION_GROUPS_V1: usize = 16;
pub(crate) const MAX_BATCH_CONSULTATION_GROUPS_V1: usize = 256;
const MAX_CHECKED_SCOPES_V1: usize = 16;
const MAX_PRINCIPAL_ID_BYTES: usize = 256;
const MAX_PROFILE_ID_BYTES: usize = 96;
const MAX_PROFILE_VERSION_BYTES: usize = 10;
const MAX_PURPOSE_BYTES: usize = 256;
const MAX_INPUT_NAME_BYTES: usize = 96;
const MAX_INPUT_VALUE_BYTES: usize = 256;
const MAX_OUTPUT_NAME_BYTES: usize = 96;
const MAX_OUTPUT_STRING_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RuntimeRelayExpectedResult {
    FactMap(BTreeMap<String, RelayFactContract>),
    ProjectedString(Box<str>),
    PresenceOnly,
}

impl RuntimeRelayExpectedResult {
    pub(crate) fn fact_map(
        facts: BTreeMap<String, RelayFactContract>,
    ) -> Result<Self, ConsultationPlanError> {
        if facts.is_empty() || facts.len() > 64 {
            return Err(ConsultationPlanError::InvalidGroupKey);
        }
        Ok(Self::FactMap(facts))
    }

    pub(crate) fn projected_string(
        name: impl Into<Box<str>>,
    ) -> Result<Self, ConsultationPlanError> {
        let name = name.into();
        if !input_name(&name, MAX_OUTPUT_NAME_BYTES) {
            return Err(ConsultationPlanError::InvalidGroupKey);
        }
        Ok(Self::ProjectedString(name))
    }

    #[cfg(feature = "registry-notary-cel")]
    pub(crate) const fn fact_contracts(&self) -> Option<&BTreeMap<String, RelayFactContract>> {
        match self {
            Self::FactMap(facts) => Some(facts),
            Self::ProjectedString(_) | Self::PresenceOnly => None,
        }
    }
}

impl fmt::Debug for RuntimeRelayExpectedResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeRelayExpectedResult([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelayClientSelectionV1 {
    profile_id: Box<str>,
    profile_version: Box<str>,
    profile_contract_hash: Box<str>,
    purpose: Box<str>,
    input_names: Box<[String]>,
    expected_result: RuntimeRelayExpectedResult,
}

impl RelayClientSelectionV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        profile_id: impl Into<Box<str>>,
        profile_version: impl Into<Box<str>>,
        profile_contract_hash: impl Into<Box<str>>,
        purpose: impl Into<Box<str>>,
        input_names: impl Into<RelayInputNames>,
        expected_result: RuntimeRelayExpectedResult,
    ) -> Result<Self, ConsultationPlanError> {
        let profile_id = profile_id.into();
        let profile_version = profile_version.into();
        let profile_contract_hash = profile_contract_hash.into();
        let purpose = purpose.into();
        let mut input_names = input_names.into().into_vec();
        input_names.sort();
        input_names.dedup();
        if !stable_id(&profile_id, MAX_PROFILE_ID_BYTES)
            || !canonical_version(&profile_version)
            || !sha256_uri(&profile_contract_hash)
            || !valid_purpose(&purpose)
            || !(1..=4).contains(&input_names.len())
            || input_names
                .iter()
                .any(|name| !input_name(name, MAX_INPUT_NAME_BYTES))
        {
            return Err(ConsultationPlanError::InvalidGroupKey);
        }
        Ok(Self {
            profile_id,
            profile_version,
            profile_contract_hash,
            purpose,
            input_names: input_names.into_boxed_slice(),
            expected_result,
        })
    }

    fn from_key(key: &ConsultationGroupKeyV1) -> Self {
        Self {
            profile_id: key.profile_id.clone(),
            profile_version: key.profile_version.clone(),
            profile_contract_hash: key.profile_contract_hash.clone(),
            purpose: key.canonical_purpose.clone(),
            input_names: key.canonical_inputs.keys().cloned().collect(),
            expected_result: key.expected_result.clone(),
        }
    }
}

impl fmt::Debug for RelayClientSelectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayClientSelectionV1([REDACTED])")
    }
}

/// The complete typed equality boundary for request-scoped consultation reuse.
///
/// This type deliberately implements neither `Debug` nor `Serialize`. It can
/// contain authenticated principal and subject-selector material and must
/// remain request-scoped memory only.
#[derive(Clone)]
pub(crate) struct ConsultationGroupKeyV1 {
    evaluation_id: Ulid,
    auth_profile_id: EvidenceAuthProfileId,
    principal_id: Zeroizing<String>,
    checked_scopes_sorted: Box<[String]>,
    profile_id: Box<str>,
    profile_version: Box<str>,
    profile_contract_hash: Box<str>,
    canonical_purpose: Box<str>,
    canonical_inputs: BTreeMap<String, Zeroizing<String>>,
    expected_result: RuntimeRelayExpectedResult,
}

impl ConsultationGroupKeyV1 {
    /// Build one canonical key after Notary has completed all
    /// pre-consultation gates.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        evaluation_id: Ulid,
        auth_profile_id: EvidenceAuthProfileId,
        principal_id: String,
        checked_scopes: Vec<String>,
        profile_id: impl Into<Box<str>>,
        profile_version: impl Into<Box<str>>,
        profile_contract_hash: impl Into<Box<str>>,
        canonical_purpose: impl Into<Box<str>>,
        canonical_inputs: BTreeMap<String, Zeroizing<String>>,
    ) -> Result<Self, ConsultationPlanError> {
        Self::new_with_expected_result(
            evaluation_id,
            auth_profile_id,
            principal_id,
            checked_scopes,
            profile_id,
            profile_version,
            profile_contract_hash,
            canonical_purpose,
            canonical_inputs,
            RuntimeRelayExpectedResult::projected_string("registration_status")?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_expected_result(
        evaluation_id: Ulid,
        auth_profile_id: EvidenceAuthProfileId,
        principal_id: String,
        mut checked_scopes: Vec<String>,
        profile_id: impl Into<Box<str>>,
        profile_version: impl Into<Box<str>>,
        profile_contract_hash: impl Into<Box<str>>,
        canonical_purpose: impl Into<Box<str>>,
        canonical_inputs: BTreeMap<String, Zeroizing<String>>,
        expected_result: RuntimeRelayExpectedResult,
    ) -> Result<Self, ConsultationPlanError> {
        let profile_id = profile_id.into();
        let profile_version = profile_version.into();
        let profile_contract_hash = profile_contract_hash.into();
        let canonical_purpose = canonical_purpose.into();
        if !valid_principal_id(&principal_id)
            || checked_scopes.is_empty()
            || checked_scopes.iter().any(|scope| !valid_scope(scope))
            || !stable_id(&profile_id, MAX_PROFILE_ID_BYTES)
            || !canonical_version(&profile_version)
            || !sha256_uri(&profile_contract_hash)
            || !valid_purpose(&canonical_purpose)
            || !valid_canonical_inputs(&canonical_inputs)
        {
            return Err(ConsultationPlanError::InvalidGroupKey);
        }
        checked_scopes.sort_unstable();
        checked_scopes.dedup();
        if checked_scopes.len() > MAX_CHECKED_SCOPES_V1 {
            return Err(ConsultationPlanError::InvalidGroupKey);
        }
        Ok(Self {
            evaluation_id,
            auth_profile_id,
            principal_id: Zeroizing::new(principal_id),
            checked_scopes_sorted: checked_scopes.into_boxed_slice(),
            profile_id,
            profile_version,
            profile_contract_hash,
            canonical_purpose,
            canonical_inputs,
            expected_result,
        })
    }

    #[must_use]
    pub(crate) const fn evaluation_id(&self) -> Ulid {
        self.evaluation_id
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn auth_profile_id(&self) -> EvidenceAuthProfileId {
        self.auth_profile_id
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn principal_id(&self) -> &str {
        self.principal_id.as_str()
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn checked_scopes_sorted(&self) -> &[String] {
        &self.checked_scopes_sorted
    }

    #[must_use]
    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub(crate) fn profile_version(&self) -> &str {
        &self.profile_version
    }

    #[must_use]
    pub(crate) fn profile_contract_hash(&self) -> &str {
        &self.profile_contract_hash
    }

    #[must_use]
    pub(crate) fn canonical_purpose(&self) -> &str {
        &self.canonical_purpose
    }

    /// Return the canonical profile inputs in bytewise key order. Values
    /// remain owned by zeroizing allocations for the request lifetime.
    #[must_use]
    pub(crate) const fn canonical_inputs(&self) -> &BTreeMap<String, Zeroizing<String>> {
        &self.canonical_inputs
    }

    fn with_canonical_inputs(
        mut self,
        inputs: BTreeMap<String, Zeroizing<String>>,
    ) -> Result<Self, RelayClientError> {
        if !valid_canonical_inputs(&inputs) {
            return Err(RelayClientError::InvalidRequest);
        }
        self.canonical_inputs = inputs;
        Ok(self)
    }

    #[must_use]
    #[cfg(feature = "registry-notary-cel")]
    pub(crate) const fn expected_fact_contracts(
        &self,
    ) -> Option<&BTreeMap<String, RelayFactContract>> {
        self.expected_result.fact_contracts()
    }
}

impl Ord for ConsultationGroupKeyV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.evaluation_id
            .cmp(&other.evaluation_id)
            .then_with(|| self.auth_profile_id.cmp(&other.auth_profile_id))
            .then_with(|| self.principal_id.as_str().cmp(other.principal_id.as_str()))
            .then_with(|| self.checked_scopes_sorted.cmp(&other.checked_scopes_sorted))
            .then_with(|| self.profile_id.cmp(&other.profile_id))
            .then_with(|| self.profile_version.cmp(&other.profile_version))
            .then_with(|| self.profile_contract_hash.cmp(&other.profile_contract_hash))
            .then_with(|| self.canonical_purpose.cmp(&other.canonical_purpose))
            .then_with(|| compare_canonical_inputs(&self.canonical_inputs, &other.canonical_inputs))
    }
}

impl PartialEq for ConsultationGroupKeyV1 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ConsultationGroupKeyV1 {}

/// Opaque restart-stable identity for one item-local Relay consultation.
///
/// The type deliberately exposes neither its preimage nor `Display`. Its
/// redacted `Debug` implementation is safe for error paths.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BatchChildIdentityV1(Box<str>);

/// Canonical, value-bearing preimage used only while deriving an opaque child
/// identity. It is deliberately not serializable through a general-purpose
/// interface and its diagnostics are value-free.
struct BatchConsultationGroupCommitmentV1<'a> {
    key: &'a ConsultationGroupKeyV1,
}

impl BatchConsultationGroupCommitmentV1<'_> {
    fn canonical_json(&self) -> Result<Vec<u8>, ConsultationPlanError> {
        let key = self.key;
        let caller = serde_json::json!({
            "auth_profile_id": key.auth_profile_id.as_str(),
            "principal_id": key.principal_id.as_str(),
            "checked_scopes_sorted": key.checked_scopes_sorted,
        });
        let commitment = serde_json::json!({
            "authenticated_evaluation_caller_binding": caller,
            "profile": {
                "id": key.profile_id.as_ref(),
                "version": key.profile_version.as_ref(),
                "contract_hash": key.profile_contract_hash.as_ref(),
            },
            "canonical_purpose": key.canonical_purpose.as_ref(),
            "canonical_inputs": key.canonical_inputs.iter().map(|(name, value)| {
                (name.clone(), Value::String(value.as_str().to_string()))
            }).collect::<Map<String, Value>>(),
        });
        canonicalize_json(&commitment).map_err(|_| ConsultationPlanError::InvalidGroupKey)
    }
}

impl fmt::Debug for BatchConsultationGroupCommitmentV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BatchConsultationGroupCommitmentV1([REDACTED])")
    }
}

impl BatchChildIdentityV1 {
    pub(crate) fn derive(
        outer_key: &str,
        item_position: usize,
        key: &ConsultationGroupKeyV1,
    ) -> Result<Self, ConsultationPlanError> {
        if outer_key.is_empty() || outer_key.len() > 256 {
            return Err(ConsultationPlanError::InvalidGroupKey);
        }
        let item_position =
            u64::try_from(item_position).map_err(|_| ConsultationPlanError::InvalidGroupKey)?;
        let commitment = BatchConsultationGroupCommitmentV1 { key }.canonical_json()?;

        let mut outer = Sha256::new();
        frame_hash(&mut outer, b"registry.notary.batch-outer.v1");
        frame_hash(&mut outer, key.auth_profile_id.as_str().as_bytes());
        frame_hash(&mut outer, key.principal_id.as_bytes());
        for scope in &key.checked_scopes_sorted {
            frame_hash(&mut outer, scope.as_bytes());
        }
        frame_hash(&mut outer, outer_key.as_bytes());
        let outer = outer.finalize();

        let mut child = Sha256::new();
        frame_hash(&mut child, b"registry.notary.relay-batch-child.v1");
        frame_hash(&mut child, &outer);
        frame_hash(&mut child, &item_position.to_be_bytes());
        frame_hash(&mut child, &commitment);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(child.finalize());
        Ok(Self(encoded.into_boxed_str()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BatchChildIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BatchChildIdentityV1([REDACTED])")
    }
}

fn frame_hash(hash: &mut Sha256, bytes: &[u8]) {
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(bytes);
}

impl PartialOrd for ConsultationGroupKeyV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_canonical_inputs(
    left: &BTreeMap<String, Zeroizing<String>>,
    right: &BTreeMap<String, Zeroizing<String>>,
) -> Ordering {
    let mut left = left.iter();
    let mut right = right.iter();
    loop {
        match (left.next(), right.next()) {
            (Some((left_name, left_value)), Some((right_name, right_value))) => {
                let ordering = left_name
                    .cmp(right_name)
                    .then_with(|| left_value.as_str().cmp(right_value.as_str()));
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Value-free planning failures for the request-scoped grouping boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConsultationPlanError {
    #[error("consultation group key is invalid")]
    InvalidGroupKey,
    #[error("an evaluation cannot contain more than 16 consultation groups")]
    TooManyGroups,
}

/// Private request-scoped correlation retained across successful and failed
/// claim evaluation. The collector is neither serializable nor publicly
/// exposed, and its diagnostics never reveal correlation values.
pub(crate) struct EvaluationAuditCollector {
    state: Mutex<EvaluationAuditState>,
}

#[derive(Default)]
struct EvaluationAuditState {
    evaluation_id: Option<Ulid>,
    relay_forwarded_count: u64,
    relay_consultation_ids: BTreeSet<Ulid>,
}

pub(crate) struct EvaluationAuditSnapshot {
    evaluation_id: Option<String>,
    relay_forwarded_count: u64,
    relay_consultation_ids: Vec<String>,
}

impl EvaluationAuditCollector {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(EvaluationAuditState::default()),
        }
    }

    pub(crate) fn begin_evaluation(&self) -> Ulid {
        let evaluation_id = Ulid::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.evaluation_id.replace(evaluation_id).is_none(),
            "an evaluation audit collector cannot be reused"
        );
        evaluation_id
    }

    fn record_relay_consultation(&self, consultation_id: Ulid) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.evaluation_id.is_some(),
            "a Relay consultation cannot precede its Notary evaluation"
        );
        state.relay_consultation_ids.insert(consultation_id);
    }

    fn record_relay_forwarded(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.evaluation_id.is_some(),
            "a Relay consultation cannot be forwarded before its Notary evaluation"
        );
        state.relay_forwarded_count = state.relay_forwarded_count.saturating_add(1);
    }

    pub(crate) fn snapshot(&self) -> EvaluationAuditSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EvaluationAuditSnapshot {
            evaluation_id: state.evaluation_id.map(|id| id.to_string()),
            relay_forwarded_count: state.relay_forwarded_count,
            relay_consultation_ids: state
                .relay_consultation_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

impl fmt::Debug for EvaluationAuditCollector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvaluationAuditCollector([REDACTED])")
    }
}

impl EvaluationAuditSnapshot {
    pub(crate) fn evaluation_id(&self) -> Option<&str> {
        self.evaluation_id.as_deref()
    }

    pub(crate) const fn relay_forwarded_count(&self) -> u64 {
        self.relay_forwarded_count
    }

    pub(crate) fn into_parts(self) -> (Option<String>, Vec<String>) {
        (self.evaluation_id, self.relay_consultation_ids)
    }
}

/// Runtime-neutral closed consultation outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeRelayOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

impl fmt::Debug for RuntimeRelayOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeRelayOutcome([REDACTED])")
    }
}

/// The one decoded Relay string output released for a successful match.
/// Both its name and its zeroizing value are redacted from `Debug`.
pub(crate) struct RuntimeRelayOutput {
    name: Box<str>,
    value: Zeroizing<String>,
}

impl RuntimeRelayOutput {
    pub(crate) fn new(
        name: impl Into<Box<str>>,
        value: Zeroizing<String>,
    ) -> Result<Self, RelayClientError> {
        let name = name.into();
        if !input_name(&name, MAX_OUTPUT_NAME_BYTES) || value.len() > MAX_OUTPUT_STRING_BYTES {
            return Err(RelayClientError::InvalidResult);
        }
        Ok(Self { name, value })
    }

    #[must_use]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub(crate) fn value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for RuntimeRelayOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeRelayOutput")
            .field("name", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Match-only data released by the verified Relay client.
pub(crate) enum RuntimeRelayMatchData {
    FactMap(RuntimeRelayFactMap),
    ProjectedString(RuntimeRelayOutput),
    PresenceOnly,
}

pub(crate) struct RuntimeRelayFactMap {
    fields: BTreeMap<Box<str>, RuntimeRelayFactValue>,
}

enum RuntimeRelayFactValue {
    Null,
    Boolean(bool),
    Integer(i64),
    String(Zeroizing<String>),
}

impl RuntimeRelayFactMap {
    #[cfg(feature = "registry-notary-cel")]
    pub(crate) fn from_json(fields: BTreeMap<String, Value>) -> Result<Self, RelayClientError> {
        let fields = fields
            .into_iter()
            .map(|(name, value)| {
                let value = match value {
                    Value::Null => RuntimeRelayFactValue::Null,
                    Value::Bool(value) => RuntimeRelayFactValue::Boolean(value),
                    Value::Number(value) => value
                        .as_i64()
                        .map(RuntimeRelayFactValue::Integer)
                        .ok_or(RelayClientError::InvalidResult)?,
                    Value::String(value) => RuntimeRelayFactValue::String(Zeroizing::new(value)),
                    Value::Array(_) | Value::Object(_) => {
                        return Err(RelayClientError::InvalidResult)
                    }
                };
                Ok((name.into_boxed_str(), value))
            })
            .collect::<Result<BTreeMap<_, _>, RelayClientError>>()?;
        Ok(Self { fields })
    }

    fn from_relay(facts: &crate::relay_client::RelayFactMap) -> Result<Self, RelayClientError> {
        let fields = facts
            .fields()
            .map(|(name, value)| {
                let value = match value {
                    ProjectedJsonScalar::Null => RuntimeRelayFactValue::Null,
                    ProjectedJsonScalar::Boolean(value) => RuntimeRelayFactValue::Boolean(*value),
                    ProjectedJsonScalar::Integer(value) => RuntimeRelayFactValue::Integer(*value),
                    ProjectedJsonScalar::String(value) => {
                        RuntimeRelayFactValue::String(Zeroizing::new(value.to_string()))
                    }
                    ProjectedJsonScalar::Number(_) => return Err(RelayClientError::InvalidResult),
                };
                Ok((name.into(), value))
            })
            .collect::<Result<BTreeMap<_, _>, RelayClientError>>()?;
        Ok(Self { fields })
    }

    pub(crate) fn to_json_object(&self) -> Map<String, Value> {
        self.fields
            .iter()
            .map(|(name, value)| {
                let value = match value {
                    RuntimeRelayFactValue::Null => Value::Null,
                    RuntimeRelayFactValue::Boolean(value) => Value::Bool(*value),
                    RuntimeRelayFactValue::Integer(value) => Value::Number((*value).into()),
                    RuntimeRelayFactValue::String(value) => Value::String(value.to_string()),
                };
                (name.to_string(), value)
            })
            .collect()
    }
}

impl fmt::Debug for RuntimeRelayFactMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeRelayFactMap")
            .field("fields", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for RuntimeRelayMatchData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeRelayMatchData([REDACTED])")
    }
}

/// The only Relay result shape visible to the evaluation runtime.
pub(crate) struct RuntimeRelayConsultationResult {
    consultation_id: Ulid,
    outcome: RuntimeRelayOutcome,
    match_data: Option<RuntimeRelayMatchData>,
    acquired_at: OffsetDateTime,
}

impl RuntimeRelayConsultationResult {
    pub(crate) fn new(
        consultation_id: Ulid,
        outcome: RuntimeRelayOutcome,
        match_data: Option<RuntimeRelayMatchData>,
        acquired_at: OffsetDateTime,
    ) -> Result<Self, RelayClientError> {
        let output_shape_valid = match outcome {
            RuntimeRelayOutcome::Match => match_data.is_some(),
            RuntimeRelayOutcome::NoMatch | RuntimeRelayOutcome::Ambiguous => match_data.is_none(),
        };
        if !output_shape_valid {
            return Err(RelayClientError::InvalidResult);
        }
        Ok(Self {
            consultation_id,
            outcome,
            match_data,
            acquired_at,
        })
    }

    #[must_use]
    pub(crate) const fn consultation_id(&self) -> Ulid {
        self.consultation_id
    }

    #[must_use]
    pub(crate) const fn outcome(&self) -> RuntimeRelayOutcome {
        self.outcome
    }

    #[must_use]
    pub(crate) const fn output(&self) -> Option<&RuntimeRelayOutput> {
        match self.match_data.as_ref() {
            Some(RuntimeRelayMatchData::ProjectedString(output)) => Some(output),
            Some(RuntimeRelayMatchData::FactMap(_) | RuntimeRelayMatchData::PresenceOnly)
            | None => None,
        }
    }

    #[must_use]
    pub(crate) const fn facts(&self) -> Option<&RuntimeRelayFactMap> {
        match self.match_data.as_ref() {
            Some(RuntimeRelayMatchData::FactMap(facts)) => Some(facts),
            Some(
                RuntimeRelayMatchData::ProjectedString(_) | RuntimeRelayMatchData::PresenceOnly,
            )
            | None => None,
        }
    }

    #[must_use]
    pub(crate) const fn acquired_at(&self) -> OffsetDateTime {
        self.acquired_at
    }
}

impl fmt::Debug for RuntimeRelayConsultationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeRelayConsultationResult")
            .field("consultation_id", &"[REDACTED]")
            .field("outcome", &"[REDACTED]")
            .field("output", &"[REDACTED]")
            .field("acquired_at", &"[REDACTED]")
            .finish()
    }
}

/// Activated, startup-verified Relay consultations available to one runtime.
/// The trait is dyn-safe and releases only the runtime-neutral closed result.
#[async_trait::async_trait]
pub(crate) trait ActivatedRelayConsultations: Send + Sync + fmt::Debug {
    async fn check_ready(&self) -> Result<(), RelayClientError>;

    async fn readiness(&self) -> RelayProfileReadiness {
        RelayProfileReadiness::single(self.check_ready().await.is_ok())
    }

    fn profile_count(&self) -> usize {
        1
    }

    fn validate(&self, key: &ConsultationGroupKeyV1) -> Result<(), RelayClientError>;

    fn canonicalize(
        &self,
        key: ConsultationGroupKeyV1,
    ) -> Result<ConsultationGroupKeyV1, RelayClientError> {
        self.validate(&key)?;
        Ok(key)
    }

    async fn execute(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError>;

    async fn execute_batch(
        &self,
        key: &ConsultationGroupKeyV1,
        _child_identity: &BatchChildIdentityV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
        self.execute(key).await
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RelayProfileReadiness {
    total: usize,
    ready: usize,
}

impl RelayProfileReadiness {
    const fn single(ready: bool) -> Self {
        Self {
            total: 1,
            ready: ready as usize,
        }
    }

    pub(crate) const fn all_failed(total: usize) -> Self {
        Self { total, ready: 0 }
    }

    fn add(&mut self, other: Self) {
        self.total += other.total;
        self.ready += other.ready;
    }

    pub(crate) const fn total(self) -> usize {
        self.total
    }

    pub(crate) const fn ready(self) -> usize {
        self.ready
    }

    pub(crate) const fn failed(self) -> usize {
        self.total - self.ready
    }

    pub(crate) const fn is_ready(self) -> bool {
        self.total > 0 && self.ready == self.total
    }
}

pub(crate) struct ActivatedRelayClientSet {
    clients: BTreeMap<RelayClientSelectionV1, Arc<dyn ActivatedRelayConsultations>>,
}

impl ActivatedRelayClientSet {
    pub(crate) fn new(
        entries: impl IntoIterator<
            Item = (RelayClientSelectionV1, Arc<dyn ActivatedRelayConsultations>),
        >,
    ) -> Result<Self, ConsultationPlanError> {
        let mut clients = BTreeMap::new();
        for (selection, client) in entries {
            if clients.insert(selection, client).is_some() {
                return Err(ConsultationPlanError::InvalidGroupKey);
            }
        }
        if clients.is_empty() {
            return Err(ConsultationPlanError::InvalidGroupKey);
        }
        Ok(Self { clients })
    }

    fn client_for(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<&Arc<dyn ActivatedRelayConsultations>, RelayClientError> {
        self.clients
            .get(&RelayClientSelectionV1::from_key(key))
            .ok_or(RelayClientError::InvalidRequest)
    }
}

impl fmt::Debug for ActivatedRelayClientSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedRelayClientSet")
            .field("clients", &"[REDACTED]")
            .finish()
    }
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for ActivatedRelayClientSet {
    async fn check_ready(&self) -> Result<(), RelayClientError> {
        if self.readiness().await.is_ready() {
            Ok(())
        } else {
            Err(RelayClientError::Unavailable)
        }
    }

    async fn readiness(&self) -> RelayProfileReadiness {
        let mut readiness = RelayProfileReadiness::default();
        for client in self.clients.values() {
            readiness.add(client.readiness().await);
        }
        readiness
    }

    fn profile_count(&self) -> usize {
        self.clients.len()
    }

    fn validate(&self, key: &ConsultationGroupKeyV1) -> Result<(), RelayClientError> {
        self.client_for(key)?.validate(key)
    }

    fn canonicalize(
        &self,
        key: ConsultationGroupKeyV1,
    ) -> Result<ConsultationGroupKeyV1, RelayClientError> {
        self.client_for(&key)?.canonicalize(key)
    }

    async fn execute(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
        self.client_for(key)?.execute(key).await
    }

    async fn execute_batch(
        &self,
        key: &ConsultationGroupKeyV1,
        child_identity: &BatchChildIdentityV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
        self.client_for(key)?
            .execute_batch(key, child_identity)
            .await
    }
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for VerifiedRelayClient {
    async fn check_ready(&self) -> Result<(), RelayClientError> {
        self.verify_current_profile().await
    }

    fn validate(&self, key: &ConsultationGroupKeyV1) -> Result<(), RelayClientError> {
        let profile = self.profile();
        if profile.pin().id() != key.profile_id()
            || profile.pin().version() != key.profile_version()
            || profile.pin().contract_hash() != key.profile_contract_hash()
            || profile.purpose() != key.canonical_purpose()
            || profile
                .input_names()
                .iter()
                .ne(key.canonical_inputs().keys())
        {
            return Err(RelayClientError::InvalidRequest);
        }
        self.canonicalize_execute_inputs(&key.evaluation_id().to_string(), key.canonical_inputs())
            .map(|_| ())
    }

    fn canonicalize(
        &self,
        key: ConsultationGroupKeyV1,
    ) -> Result<ConsultationGroupKeyV1, RelayClientError> {
        let inputs = self.canonicalize_execute_inputs(
            &key.evaluation_id().to_string(),
            key.canonical_inputs(),
        )?;
        key.with_canonical_inputs(inputs)
    }

    async fn execute(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
        self.validate(key)?;
        let result = self
            .execute_inputs(
                &key.evaluation_id().to_string(),
                key.canonical_inputs().clone(),
            )
            .await?;
        relay_result_to_runtime(result)
    }

    async fn execute_batch(
        &self,
        key: &ConsultationGroupKeyV1,
        child_identity: &BatchChildIdentityV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
        self.validate(key)?;
        let result = self
            .execute_batch_inputs(
                &key.evaluation_id().to_string(),
                key.canonical_inputs().clone(),
                child_identity.as_str(),
            )
            .await?;
        relay_result_to_runtime(result)
    }
}

fn relay_result_to_runtime(
    result: crate::relay_client::RelayConsultationResult,
) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
    let outcome = match result.outcome() {
        RelayConsultationOutcome::Match => RuntimeRelayOutcome::Match,
        RelayConsultationOutcome::NoMatch => RuntimeRelayOutcome::NoMatch,
        RelayConsultationOutcome::Ambiguous => RuntimeRelayOutcome::Ambiguous,
    };
    let match_data = match result.match_data() {
        Some(RelayMatchData::FactMap(facts)) => Some(RuntimeRelayMatchData::FactMap(
            RuntimeRelayFactMap::from_relay(facts)?,
        )),
        Some(RelayMatchData::ProjectedString(output)) => Some(
            RuntimeRelayOutput::new(output.name(), Zeroizing::new(output.value().to_string()))
                .map(RuntimeRelayMatchData::ProjectedString)?,
        ),
        Some(RelayMatchData::PresenceOnly) => Some(RuntimeRelayMatchData::PresenceOnly),
        None => None,
    };
    RuntimeRelayConsultationResult::new(
        result.consultation_id(),
        outcome,
        match_data,
        result.provenance().relay_acquired_at(),
    )
}

type SharedConsultationResult = Result<Arc<RuntimeRelayConsultationResult>, RelayClientError>;

/// One cancellation-safe execution slot.
///
/// The outbound operation runs in a detached task after `started` is sealed.
/// Cancelling the first request waiter therefore cannot cause a later waiter
/// to dispatch the same consultation again.
struct CoalescedConsultation {
    started: Once,
    result: OnceLock<SharedConsultationResult>,
    completed: Notify,
}

impl CoalescedConsultation {
    fn new() -> Self {
        Self {
            started: Once::new(),
            result: OnceLock::new(),
            completed: Notify::new(),
        }
    }

    fn start(
        self: &Arc<Self>,
        activated: Arc<dyn ActivatedRelayConsultations>,
        audit: Arc<EvaluationAuditCollector>,
        key: ConsultationGroupKeyV1,
        child_identity: Option<BatchChildIdentityV1>,
    ) {
        let state = Arc::clone(self);
        self.started.call_once(move || {
            // Seal a conservative dispatch-attempt marker into the request
            // audit before permit acquisition, credential loading, or network
            // I/O. It means the operation may reach Relay, not that Relay
            // received it. Recording here prevents cancellation from creating
            // a false negative after the detached task outlives an early
            // sibling failure. Relay also receives the Notary evaluation id,
            // so an audit can reconcile a late Relay completion when present.
            audit.record_relay_forwarded();
            tokio::spawn(async move {
                let execution = tokio::spawn(async move {
                    match child_identity.as_ref() {
                        Some(identity) => activated.execute_batch(&key, identity).await,
                        None => activated.execute(&key).await,
                    }
                });
                let result = match execution.await {
                    Ok(result) => result.map(Arc::new),
                    Err(_) => Err(RelayClientError::Unavailable),
                };
                let _ = state.result.set(result);
                state.completed.notify_waiters();
            });
        });
    }

    async fn wait(&self) -> SharedConsultationResult {
        loop {
            let completed = self.completed.notified();
            if let Some(result) = self.result.get() {
                return match result {
                    Ok(result) => Ok(Arc::clone(result)),
                    Err(error) => Err(*error),
                };
            }
            completed.await;
        }
    }
}

/// Fresh per-evaluation coordination state. Groups must be fully planned
/// before construction; execution can never insert a new group dynamically.
pub(crate) struct RequestScopedConsultationCoordinator {
    groups: BTreeMap<ConsultationGroupKeyV1, Arc<CoalescedConsultation>>,
    activated: Arc<dyn ActivatedRelayConsultations>,
    audit: Arc<EvaluationAuditCollector>,
}

impl RequestScopedConsultationCoordinator {
    pub(crate) fn new(
        keys: impl IntoIterator<Item = ConsultationGroupKeyV1>,
        activated: Arc<dyn ActivatedRelayConsultations>,
        audit: Arc<EvaluationAuditCollector>,
    ) -> Result<Self, ConsultationPlanError> {
        let mut groups = BTreeMap::new();
        for key in keys {
            groups
                .entry(key)
                .or_insert_with(|| Arc::new(CoalescedConsultation::new()));
            if groups.len() > MAX_CONSULTATION_GROUPS_V1 {
                return Err(ConsultationPlanError::TooManyGroups);
            }
        }
        Ok(Self {
            groups,
            activated,
            audit,
        })
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.groups.len()
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) async fn consult(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<Arc<RuntimeRelayConsultationResult>, RelayClientError> {
        self.consult_with_child(key, None).await
    }

    async fn consult_with_child(
        &self,
        key: &ConsultationGroupKeyV1,
        child_identity: Option<&BatchChildIdentityV1>,
    ) -> Result<Arc<RuntimeRelayConsultationResult>, RelayClientError> {
        let cell = self
            .groups
            .get(key)
            .ok_or(RelayClientError::InvalidRequest)?;
        cell.start(
            Arc::clone(&self.activated),
            Arc::clone(&self.audit),
            key.clone(),
            child_identity.cloned(),
        );
        cell.wait().await
    }
}

impl fmt::Debug for RequestScopedConsultationCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestScopedConsultationCoordinator")
            .field("groups", &"[REDACTED]")
            .field("activated", &"[REDACTED]")
            .field("audit", &"[REDACTED]")
            .finish()
    }
}

/// Fully planned Registry-backed consultations for one evaluation.
///
/// Claim ids are non-secret configuration identifiers. Group keys remain
/// private because they contain caller and subject-selector material.
pub(crate) struct RequestScopedRelayPlan {
    keys_by_claim: BTreeMap<String, ConsultationGroupKeyV1>,
    coordinator: RequestScopedConsultationCoordinator,
    audit: Arc<EvaluationAuditCollector>,
    child_identities: BTreeMap<ConsultationGroupKeyV1, BatchChildIdentityV1>,
}

impl RequestScopedRelayPlan {
    pub(crate) fn new(
        entries: impl IntoIterator<Item = (String, ConsultationGroupKeyV1)>,
        activated: Arc<dyn ActivatedRelayConsultations>,
        audit: Arc<EvaluationAuditCollector>,
    ) -> Result<Self, ConsultationPlanError> {
        Self::new_internal(
            entries.into_iter().map(|(claim, key)| (claim, key, None)),
            activated,
            audit,
        )
    }

    pub(crate) fn new_batch(
        entries: impl IntoIterator<Item = (String, ConsultationGroupKeyV1)>,
        outer_key: &str,
        item_position: usize,
        activated: Arc<dyn ActivatedRelayConsultations>,
        audit: Arc<EvaluationAuditCollector>,
    ) -> Result<Self, ConsultationPlanError> {
        Self::new_internal(
            entries
                .into_iter()
                .map(|(claim, key)| (claim, key, Some((outer_key, item_position)))),
            activated,
            audit,
        )
    }

    fn new_internal<'a>(
        entries: impl IntoIterator<Item = (String, ConsultationGroupKeyV1, Option<(&'a str, usize)>)>,
        activated: Arc<dyn ActivatedRelayConsultations>,
        audit: Arc<EvaluationAuditCollector>,
    ) -> Result<Self, ConsultationPlanError> {
        let mut keys_by_claim = BTreeMap::new();
        let mut child_identities = BTreeMap::new();
        for (claim_id, key, child_context) in entries {
            let key = activated
                .canonicalize(key)
                .map_err(|_| ConsultationPlanError::InvalidGroupKey)?;
            if let Some((outer_key, item_position)) = child_context {
                let child_identity = BatchChildIdentityV1::derive(outer_key, item_position, &key)?;
                match child_identities.entry(key.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(child_identity);
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get() == &child_identity => {}
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(ConsultationPlanError::InvalidGroupKey);
                    }
                }
            }
            if claim_id.is_empty()
                || activated.validate(&key).is_err()
                || keys_by_claim.insert(claim_id, key).is_some()
            {
                return Err(ConsultationPlanError::InvalidGroupKey);
            }
        }
        let coordinator = RequestScopedConsultationCoordinator::new(
            keys_by_claim.values().cloned(),
            activated,
            Arc::clone(&audit),
        )?;
        Ok(Self {
            keys_by_claim,
            coordinator,
            audit,
            child_identities,
        })
    }

    pub(crate) fn group_count(&self) -> usize {
        self.coordinator.groups.len()
    }

    pub(crate) async fn consult(
        &self,
        claim_id: &str,
    ) -> Result<Arc<RuntimeRelayConsultationResult>, RelayClientError> {
        let key = self
            .keys_by_claim
            .get(claim_id)
            .ok_or(RelayClientError::InvalidRequest)?;
        let result = self
            .coordinator
            .consult_with_child(key, self.child_identities.get(key))
            .await?;
        self.audit
            .record_relay_consultation(result.consultation_id());
        Ok(result)
    }
}

impl fmt::Debug for RequestScopedRelayPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestScopedRelayPlan")
            .field("keys_by_claim", &"[REDACTED]")
            .field("coordinator", &self.coordinator)
            .field("audit", &"[REDACTED]")
            .finish()
    }
}

fn valid_principal_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PRINCIPAL_ID_BYTES
        && value.chars().all(|character| !character.is_control())
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| matches!(byte, b'!' | b'#'..=b'[' | b']'..=b'~'))
}

fn stable_id(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= max_bytes
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn input_name(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= max_bytes
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn canonical_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROFILE_VERSION_BYTES
        && matches!(value.as_bytes().first(), Some(b'1'..=b'9'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn sha256_uri(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn valid_purpose(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PURPOSE_BYTES
        && !value.contains(',')
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn valid_canonical_inputs(inputs: &BTreeMap<String, Zeroizing<String>>) -> bool {
    (1..=4).contains(&inputs.len())
        && inputs.iter().all(|(name, value)| {
            input_name(name, MAX_INPUT_NAME_BYTES)
                && !value.is_empty()
                && value.len() <= MAX_INPUT_VALUE_BYTES
                && value.chars().all(|character| !character.is_control())
        })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    const CONTRACT_HASH: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_CONTRACT_HASH: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TARGET_VALUE: &str = "target-value-SENSITIVE";
    const OUTPUT_VALUE: &str = "registry-value-SENSITIVE";

    fn canonical_inputs(name: &str, value: &str) -> BTreeMap<String, Zeroizing<String>> {
        BTreeMap::from([(name.to_string(), Zeroizing::new(value.to_string()))])
    }

    fn group_key(evaluation_random: u128) -> ConsultationGroupKeyV1 {
        group_key_with_scopes(
            evaluation_random,
            vec![
                "registry:scope:z".to_string(),
                "registry:scope:a".to_string(),
            ],
        )
    }

    fn group_key_with_scopes(
        evaluation_random: u128,
        scopes: Vec<String>,
    ) -> ConsultationGroupKeyV1 {
        ConsultationGroupKeyV1::new(
            Ulid::from_parts(1, evaluation_random),
            EvidenceAuthProfileId::StaticApiKey,
            "principal-SENSITIVE".to_string(),
            scopes,
            "example.person-status.exact",
            "1",
            CONTRACT_HASH,
            "benefit-verification",
            canonical_inputs("subject_id", TARGET_VALUE),
        )
        .expect("valid group key")
    }

    fn success_result() -> RuntimeRelayConsultationResult {
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::Match,
            Some(
                RuntimeRelayOutput::new(
                    "registration_status",
                    Zeroizing::new(OUTPUT_VALUE.to_string()),
                )
                .map(RuntimeRelayMatchData::ProjectedString)
                .expect("valid output"),
            ),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("valid result")
    }

    #[derive(Debug)]
    struct CountingActivated {
        calls: AtomicUsize,
        readiness_checks: AtomicUsize,
        failure: Option<RelayClientError>,
        delay: Duration,
    }

    impl CountingActivated {
        fn success() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                readiness_checks: AtomicUsize::new(0),
                failure: None,
                delay: Duration::from_millis(20),
            }
        }

        fn failure(error: RelayClientError) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                readiness_checks: AtomicUsize::new(0),
                failure: Some(error),
                delay: Duration::from_millis(20),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn readiness_checks(&self) -> usize {
            self.readiness_checks.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl ActivatedRelayConsultations for CountingActivated {
        async fn check_ready(&self) -> Result<(), RelayClientError> {
            self.readiness_checks.fetch_add(1, Ordering::SeqCst);
            self.failure.map_or(Ok(()), Err)
        }

        fn validate(&self, _key: &ConsultationGroupKeyV1) -> Result<(), RelayClientError> {
            Ok(())
        }

        async fn execute(
            &self,
            _key: &ConsultationGroupKeyV1,
        ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            match self.failure {
                Some(error) => Err(error),
                None => Ok(success_result()),
            }
        }
    }

    #[derive(Debug)]
    struct RejectingActivated;

    #[async_trait::async_trait]
    impl ActivatedRelayConsultations for RejectingActivated {
        async fn check_ready(&self) -> Result<(), RelayClientError> {
            Ok(())
        }

        fn validate(&self, _key: &ConsultationGroupKeyV1) -> Result<(), RelayClientError> {
            Err(RelayClientError::InvalidRequest)
        }

        async fn execute(
            &self,
            _key: &ConsultationGroupKeyV1,
        ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
            panic!("a locally invalid consultation must never execute")
        }
    }

    fn coordinator(
        keys: Vec<ConsultationGroupKeyV1>,
        activated: &Arc<CountingActivated>,
    ) -> RequestScopedConsultationCoordinator {
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let audit = Arc::new(EvaluationAuditCollector::new());
        audit.begin_evaluation();
        RequestScopedConsultationCoordinator::new(keys, bound, audit).expect("valid coordinator")
    }

    #[test]
    fn local_profile_input_rejection_precedes_forward_audit_and_execution() {
        let audit = Arc::new(EvaluationAuditCollector::new());
        audit.begin_evaluation();
        let activated: Arc<dyn ActivatedRelayConsultations> = Arc::new(RejectingActivated);

        let error = RequestScopedRelayPlan::new(
            [("claim".to_string(), group_key(1))],
            activated,
            Arc::clone(&audit),
        )
        .expect_err("profile-specific input rejection must fail during request planning");

        assert_eq!(error, ConsultationPlanError::InvalidGroupKey);
        assert_eq!(audit.snapshot().relay_forwarded_count(), 0);
    }

    #[tokio::test]
    async fn concurrent_identical_keys_execute_once_and_share_success() {
        let key = group_key(1);
        assert_eq!(key.auth_profile_id(), EvidenceAuthProfileId::StaticApiKey);
        assert_eq!(key.principal_id(), "principal-SENSITIVE");
        assert_eq!(
            key.checked_scopes_sorted(),
            ["registry:scope:a", "registry:scope:z"]
        );
        assert_eq!(key.profile_id(), "example.person-status.exact");
        assert_eq!(key.profile_version(), "1");
        assert_eq!(key.profile_contract_hash(), CONTRACT_HASH);
        assert_eq!(key.canonical_purpose(), "benefit-verification");
        assert_eq!(key.canonical_inputs()["subject_id"].as_str(), TARGET_VALUE);
        let activated = Arc::new(CountingActivated::success());
        let coordinator = coordinator(vec![key.clone()], &activated);

        let (left, right) = tokio::join!(coordinator.consult(&key), coordinator.consult(&key));
        let left = left.expect("first consultation succeeds");
        let right = right.expect("second consultation succeeds");

        assert_eq!(activated.calls(), 1);
        assert!(Arc::ptr_eq(&left, &right));
        assert_eq!(left.outcome(), RuntimeRelayOutcome::Match);
        let output = left.output().expect("match output");
        assert_eq!(output.name(), "registration_status");
        assert_eq!(output.value(), OUTPUT_VALUE);
    }

    #[tokio::test]
    async fn concurrent_identical_keys_execute_once_and_share_failure() {
        let key = group_key(1);
        let activated = Arc::new(CountingActivated::failure(RelayClientError::Denied));
        let coordinator = coordinator(vec![key.clone()], &activated);

        let (left, right) = tokio::join!(coordinator.consult(&key), coordinator.consult(&key));

        assert!(matches!(left, Err(RelayClientError::Denied)));
        assert!(matches!(right, Err(RelayClientError::Denied)));
        assert_eq!(activated.calls(), 1);
    }

    #[tokio::test]
    async fn cancelling_first_waiter_does_not_repeat_dispatched_consultation() {
        let key = group_key(1);
        let activated = Arc::new(CountingActivated {
            calls: AtomicUsize::new(0),
            readiness_checks: AtomicUsize::new(0),
            failure: None,
            delay: Duration::from_millis(100),
        });
        let coordinator = Arc::new(coordinator(vec![key.clone()], &activated));
        let first = tokio::spawn({
            let coordinator = Arc::clone(&coordinator);
            let key = key.clone();
            async move { coordinator.consult(&key).await }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while activated.calls() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the first consultation is dispatched");
        first.abort();
        let _ = first.await;

        coordinator
            .consult(&key)
            .await
            .expect("a later waiter receives the original result");
        assert_eq!(activated.calls(), 1);
    }

    #[tokio::test]
    async fn later_waiter_records_original_id_after_first_waiter_is_cancelled() {
        let audit = Arc::new(EvaluationAuditCollector::new());
        let evaluation_id = audit.begin_evaluation();
        let mut key = group_key(1);
        key.evaluation_id = evaluation_id;
        let activated = Arc::new(CountingActivated {
            calls: AtomicUsize::new(0),
            readiness_checks: AtomicUsize::new(0),
            failure: None,
            delay: Duration::from_millis(100),
        });
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let plan = Arc::new(
            RequestScopedRelayPlan::new([("claim".to_string(), key)], bound, Arc::clone(&audit))
                .expect("valid Relay plan"),
        );
        let first = tokio::spawn({
            let plan = Arc::clone(&plan);
            async move { plan.consult("claim").await }
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while activated.calls() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the first consultation is dispatched");
        let in_flight = audit.snapshot();
        assert_eq!(in_flight.relay_forwarded_count(), 1);
        assert!(in_flight.relay_consultation_ids.is_empty());
        first.abort();
        let _ = first.await;

        plan.consult("claim")
            .await
            .expect("a later waiter receives the original result");
        let completed = audit.snapshot();
        assert_eq!(completed.relay_forwarded_count(), 1);
        let (recorded_evaluation_id, consultation_ids) = completed.into_parts();
        assert_eq!(recorded_evaluation_id, Some(evaluation_id.to_string()));
        assert_eq!(consultation_ids, vec![Ulid::from_parts(2, 1).to_string()]);
        assert_eq!(activated.calls(), 1);
    }

    #[tokio::test]
    async fn new_coordinator_and_new_evaluation_execute_again() {
        let key = group_key(1);
        let activated = Arc::new(CountingActivated::success());
        let first = coordinator(vec![key.clone()], &activated);
        first.consult(&key).await.expect("first request succeeds");

        let second = coordinator(vec![key.clone()], &activated);
        second.consult(&key).await.expect("second request succeeds");

        let next_evaluation = group_key(2);
        let third = coordinator(vec![next_evaluation.clone()], &activated);
        third
            .consult(&next_evaluation)
            .await
            .expect("next evaluation succeeds");

        assert_eq!(activated.calls(), 3);
    }

    #[tokio::test]
    async fn every_group_key_field_mismatch_executes_separately() {
        let base = group_key(1);
        let mut keys = vec![base.clone()];

        let mut mismatch = base.clone();
        mismatch.evaluation_id = Ulid::from_parts(1, 2);
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.auth_profile_id = EvidenceAuthProfileId::ExternalOidc;
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.principal_id = Zeroizing::new("other-principal".to_string());
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.checked_scopes_sorted =
            vec!["registry:scope:other".to_string()].into_boxed_slice();
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.profile_id = "other.person-status.exact".into();
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.profile_version = "2".into();
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.profile_contract_hash = OTHER_CONTRACT_HASH.into();
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.canonical_purpose = "other-verification".into();
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.canonical_inputs = canonical_inputs("person_id", TARGET_VALUE);
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.canonical_inputs = canonical_inputs("subject_id", "different-target");
        keys.push(mismatch);

        let mut mismatch = base.clone();
        mismatch.expected_result = RuntimeRelayExpectedResult::PresenceOnly;
        assert!(base == mismatch, "result decoding is not a group-key field");

        let mut mismatch = base.clone();
        mismatch.canonical_inputs.insert(
            "birth_date".to_string(),
            Zeroizing::new("2000-01-02".to_string()),
        );
        keys.push(mismatch);

        let canonical_scope_order = group_key_with_scopes(
            1,
            vec![
                "registry:scope:a".to_string(),
                "registry:scope:z".to_string(),
            ],
        );
        assert!(base == canonical_scope_order);

        let activated = Arc::new(CountingActivated::success());
        let coordinator = coordinator(keys.clone(), &activated);
        for key in &keys {
            coordinator
                .consult(key)
                .await
                .expect("consultation succeeds");
        }
        assert_eq!(activated.calls(), keys.len());

        coordinator
            .consult(&base)
            .await
            .expect("base result remains coalesced");
        assert_eq!(activated.calls(), keys.len());
    }

    #[test]
    fn batch_child_identity_is_canonical_position_bound_and_redacted() {
        let base = group_key_with_scopes(
            1,
            vec![
                "registry:scope:z".to_string(),
                "registry:scope:a".to_string(),
            ],
        );
        let reordered = group_key_with_scopes(
            2,
            vec![
                "registry:scope:a".to_string(),
                "registry:scope:z".to_string(),
            ],
        );
        let first = BatchChildIdentityV1::derive("outer-key", 3, &base)
            .expect("first child identity derives");
        let canonical_repeat = BatchChildIdentityV1::derive("outer-key", 3, &reordered)
            .expect("canonical repeat derives");
        let next_position = BatchChildIdentityV1::derive("outer-key", 4, &base)
            .expect("next-position child identity derives");
        let next_outer = BatchChildIdentityV1::derive("other-outer-key", 3, &base)
            .expect("next-outer child identity derives");

        assert_eq!(first, canonical_repeat);
        assert_ne!(first, next_position);
        assert_ne!(first, next_outer);
        assert_eq!(first.as_str().len(), 43);
        let debug = format!("{first:?}");
        assert_eq!(debug, "BatchChildIdentityV1([REDACTED])");
        assert!(!debug.contains(TARGET_VALUE));
        assert_eq!(
            format!("{:?}", BatchConsultationGroupCommitmentV1 { key: &base }),
            "BatchConsultationGroupCommitmentV1([REDACTED])"
        );
    }

    #[test]
    fn batch_child_identity_changes_for_each_canonical_input_field() {
        let base = group_key(1);
        let base_child = BatchChildIdentityV1::derive("outer-key", 0, &base)
            .expect("base child identity derives");
        let mut changed_name = base.clone();
        changed_name.canonical_inputs = canonical_inputs("person_id", TARGET_VALUE);
        let mut changed_value = base.clone();
        changed_value.canonical_inputs = canonical_inputs("subject_id", "other-target");
        let mut added_input = base.clone();
        added_input.canonical_inputs.insert(
            "birth_date".to_string(),
            Zeroizing::new("2000-01-02".to_string()),
        );

        for changed in [changed_name, changed_value, added_input] {
            assert_ne!(
                base_child,
                BatchChildIdentityV1::derive("outer-key", 0, &changed)
                    .expect("changed child identity derives")
            );
        }
    }

    #[tokio::test]
    async fn activated_client_set_dispatches_each_exact_selection_independently() {
        let first_key = group_key(1);
        let mut second_key = group_key(1);
        second_key.profile_id = "example.other-status.exact".into();
        second_key.canonical_purpose = "other-verification".into();

        let first = Arc::new(CountingActivated::success());
        let second = Arc::new(CountingActivated::success());
        let first_bound: Arc<dyn ActivatedRelayConsultations> = first.clone();
        let second_bound: Arc<dyn ActivatedRelayConsultations> = second.clone();
        let clients = Arc::new(
            ActivatedRelayClientSet::new([
                (RelayClientSelectionV1::from_key(&first_key), first_bound),
                (RelayClientSelectionV1::from_key(&second_key), second_bound),
            ])
            .expect("two exact clients activate"),
        );
        let bound: Arc<dyn ActivatedRelayConsultations> = clients;
        bound
            .check_ready()
            .await
            .expect("every exact client remains ready");
        let audit = Arc::new(EvaluationAuditCollector::new());
        audit.begin_evaluation();
        let coordinator = RequestScopedConsultationCoordinator::new(
            [first_key.clone(), second_key.clone()],
            bound,
            audit,
        )
        .expect("both selections are preplanned");

        coordinator
            .consult(&first_key)
            .await
            .expect("first selection executes");
        coordinator
            .consult(&second_key)
            .await
            .expect("second selection executes");

        assert_eq!(first.calls(), 1);
        assert_eq!(second.calls(), 1);
        assert_eq!(first.readiness_checks(), 1);
        assert_eq!(second.readiness_checks(), 1);
    }

    #[tokio::test]
    async fn activated_client_set_keeps_readiness_and_dispatch_per_profile() {
        let ready_key = group_key(1);
        let mut unavailable_key = group_key(2);
        unavailable_key.profile_id = "example.snapshot-status.exact".into();

        let ready = Arc::new(CountingActivated::success());
        let unavailable = Arc::new(CountingActivated::failure(RelayClientError::Unavailable));
        let ready_bound: Arc<dyn ActivatedRelayConsultations> = ready.clone();
        let unavailable_bound: Arc<dyn ActivatedRelayConsultations> = unavailable.clone();
        let clients = ActivatedRelayClientSet::new([
            (RelayClientSelectionV1::from_key(&ready_key), ready_bound),
            (
                RelayClientSelectionV1::from_key(&unavailable_key),
                unavailable_bound,
            ),
        ])
        .expect("two exact clients remain independently addressable");

        let readiness = clients.readiness().await;
        assert_eq!(readiness.total(), 2);
        assert_eq!(readiness.ready(), 1);
        assert_eq!(readiness.failed(), 1);
        assert!(!readiness.is_ready());

        clients
            .execute(&ready_key)
            .await
            .expect("the unrelated ready profile still executes");
        assert_eq!(ready.calls(), 1);
        assert_eq!(
            clients
                .execute(&unavailable_key)
                .await
                .expect_err("the unavailable profile fails closed"),
            RelayClientError::Unavailable
        );
        assert_eq!(unavailable.calls(), 1);
    }

    #[test]
    fn more_than_sixteen_preplanned_groups_is_rejected() {
        let base = group_key(1);
        let keys = (0..=MAX_CONSULTATION_GROUPS_V1)
            .map(|index| {
                let mut key = base.clone();
                key.profile_id = format!("example.profile-{index}").into();
                key
            })
            .collect::<Vec<_>>();
        let activated: Arc<dyn ActivatedRelayConsultations> =
            Arc::new(CountingActivated::success());
        let audit = Arc::new(EvaluationAuditCollector::new());
        audit.begin_evaluation();

        let error = RequestScopedConsultationCoordinator::new(keys, activated, audit)
            .expect_err("17 distinct groups must be rejected");

        assert_eq!(error, ConsultationPlanError::TooManyGroups);
    }

    #[test]
    fn checked_scope_bound_applies_after_canonical_deduplication() {
        let duplicates = vec!["registry:scope:a".to_string(); MAX_CHECKED_SCOPES_V1 + 1];
        let canonical = group_key_with_scopes(1, duplicates);
        assert_eq!(canonical.checked_scopes_sorted(), ["registry:scope:a"]);

        let distinct = (0..=MAX_CHECKED_SCOPES_V1)
            .map(|index| format!("registry:scope:{index}"))
            .collect();
        let error = match ConsultationGroupKeyV1::new(
            Ulid::from_parts(1, 1),
            EvidenceAuthProfileId::StaticApiKey,
            "principal-SENSITIVE".to_string(),
            distinct,
            "example.person-status.exact",
            "1",
            CONTRACT_HASH,
            "benefit-verification",
            canonical_inputs("subject_id", TARGET_VALUE),
        ) {
            Ok(_) => panic!("more than sixteen distinct scopes must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error, ConsultationPlanError::InvalidGroupKey);
    }

    #[tokio::test]
    async fn execution_cannot_insert_an_unplanned_group() {
        let planned = group_key(1);
        let unplanned = group_key(2);
        let activated = Arc::new(CountingActivated::success());
        let coordinator = coordinator(vec![planned], &activated);

        let error = coordinator
            .consult(&unplanned)
            .await
            .expect_err("unplanned keys cannot be inserted dynamically");

        assert_eq!(error, RelayClientError::InvalidRequest);
        assert_eq!(activated.calls(), 0);
        assert_eq!(coordinator.len(), 1);
        assert!(!coordinator.is_empty());
    }

    #[test]
    fn result_shape_is_sealed_fact_map_legacy_presence_or_no_match_data() {
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::Match,
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("match requires one output");

        let facts = RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::Match,
            Some(RuntimeRelayMatchData::FactMap(RuntimeRelayFactMap {
                fields: BTreeMap::from([("exists".into(), RuntimeRelayFactValue::Boolean(true))]),
            })),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("typed fact map is explicit match data");
        assert_eq!(
            Value::Object(facts.facts().unwrap().to_json_object()),
            serde_json::json!({"exists": true})
        );

        let presence = RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::Match,
            Some(RuntimeRelayMatchData::PresenceOnly),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("presence-only is explicit match data");
        assert!(presence.output().is_none());

        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::NoMatch,
            Some(RuntimeRelayMatchData::ProjectedString(
                RuntimeRelayOutput::new("status", Zeroizing::new("value".to_string())).unwrap(),
            )),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("no_match cannot release output");

        let no_match = RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::NoMatch,
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("no_match without output is valid");
        assert!(no_match.output().is_none());

        let ambiguous = RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::Ambiguous,
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("ambiguous without output is valid");
        assert_eq!(ambiguous.outcome(), RuntimeRelayOutcome::Ambiguous);

        RuntimeRelayOutput::new("nested.name", Zeroizing::new("value".to_string()))
            .expect_err("output names use the input-name grammar");
        RuntimeRelayOutput::new(
            "status",
            Zeroizing::new("x".repeat(MAX_OUTPUT_STRING_BYTES + 1)),
        )
        .expect_err("oversized string output is rejected");
    }

    #[test]
    fn debug_output_is_value_free_and_redacted() {
        let key = group_key(1);
        let activated = Arc::new(CountingActivated::success());
        let coordinator = coordinator(vec![key.clone()], &activated);
        let result = success_result();
        let output = result.output().expect("match output");

        let rendered = format!(
            "{coordinator:?} {result:?} {output:?} {:?}",
            RuntimeRelayOutcome::Match
        );
        let evaluation_id = key.evaluation_id().to_string();
        let consultation_id = result.consultation_id().to_string();
        let acquired_at = result.acquired_at().to_string();
        for sensitive in [
            "principal-SENSITIVE",
            TARGET_VALUE,
            OUTPUT_VALUE,
            "registration_status",
            CONTRACT_HASH,
            "benefit-verification",
            evaluation_id.as_str(),
            consultation_id.as_str(),
            acquired_at.as_str(),
        ] {
            assert!(!rendered.contains(sensitive), "leaked debug value");
        }
        assert!(!rendered.contains("Match"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
