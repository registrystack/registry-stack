// SPDX-License-Identifier: Apache-2.0
//! Request-scoped Relay consultation coalescing.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, Once, OnceLock};

use registry_notary_core::EvidenceAuthProfileId;
use time::OffsetDateTime;
use tokio::sync::Notify;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::relay_client::{RelayClientError, RelayConsultationOutcome, VerifiedRelayClient};

pub(crate) const MAX_CONSULTATION_GROUPS_V1: usize = 16;
const MAX_CHECKED_SCOPES_V1: usize = 16;
const MAX_PRINCIPAL_ID_BYTES: usize = 256;
const MAX_PROFILE_ID_BYTES: usize = 96;
const MAX_PROFILE_VERSION_BYTES: usize = 10;
const MAX_PURPOSE_BYTES: usize = 256;
const MAX_INPUT_NAME_BYTES: usize = 96;
const MAX_INPUT_VALUE_BYTES: usize = 256;
const MAX_OUTPUT_NAME_BYTES: usize = 96;
const MAX_OUTPUT_STRING_BYTES: usize = 64 * 1024;

/// The complete typed equality boundary for request-scoped consultation reuse.
///
/// This type deliberately implements neither `Debug` nor `Serialize`. It can
/// contain authenticated principal and subject-selector material and must
/// remain request-scoped memory only.
#[derive(Clone, PartialEq, Eq)]
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
}

impl ConsultationGroupKeyV1 {
    /// Build one canonical key after Notary has completed all
    /// pre-consultation gates.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        evaluation_id: Ulid,
        auth_profile_id: EvidenceAuthProfileId,
        principal_id: String,
        mut checked_scopes: Vec<String>,
        profile_id: impl Into<Box<str>>,
        profile_version: impl Into<Box<str>>,
        profile_contract_hash: impl Into<Box<str>>,
        canonical_purpose: impl Into<Box<str>>,
        canonical_inputs: BTreeMap<String, Zeroizing<String>>,
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

    /// Return the one canonical profile input. The value remains owned by a
    /// zeroizing allocation for the lifetime of the request key.
    #[must_use]
    pub(crate) fn canonical_input(&self) -> (&str, &str) {
        let (name, value) = self
            .canonical_inputs
            .first_key_value()
            .expect("ConsultationGroupKeyV1 construction requires one input");
        (name, value.as_str())
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

/// The only Relay result shape visible to the evaluation runtime.
pub(crate) struct RuntimeRelayConsultationResult {
    consultation_id: Ulid,
    outcome: RuntimeRelayOutcome,
    output: Option<RuntimeRelayOutput>,
    acquired_at: OffsetDateTime,
}

impl RuntimeRelayConsultationResult {
    pub(crate) fn new(
        consultation_id: Ulid,
        outcome: RuntimeRelayOutcome,
        output: Option<RuntimeRelayOutput>,
        acquired_at: OffsetDateTime,
    ) -> Result<Self, RelayClientError> {
        let output_shape_valid = match outcome {
            RuntimeRelayOutcome::Match => output.is_some(),
            RuntimeRelayOutcome::NoMatch | RuntimeRelayOutcome::Ambiguous => output.is_none(),
        };
        if !output_shape_valid {
            return Err(RelayClientError::InvalidResult);
        }
        Ok(Self {
            consultation_id,
            outcome,
            output,
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
        self.output.as_ref()
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

    fn validate(&self, key: &ConsultationGroupKeyV1) -> Result<(), RelayClientError>;

    async fn execute(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError>;
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for VerifiedRelayClient {
    async fn check_ready(&self) -> Result<(), RelayClientError> {
        self.verify_current_profile().await
    }

    fn validate(&self, key: &ConsultationGroupKeyV1) -> Result<(), RelayClientError> {
        let profile = self.profile();
        let (input_name, input_value) = key.canonical_input();
        if profile.pin().id() != key.profile_id()
            || profile.pin().version() != key.profile_version()
            || profile.pin().contract_hash() != key.profile_contract_hash()
            || profile.purpose() != key.canonical_purpose()
            || profile.input_name() != input_name
        {
            return Err(RelayClientError::InvalidRequest);
        }
        self.validate_execute_input(&key.evaluation_id().to_string(), input_value)
    }

    async fn execute(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
        self.validate(key)?;
        let (_, input_value) = key.canonical_input();
        let result = self
            .execute(
                &key.evaluation_id().to_string(),
                Zeroizing::new(input_value.to_string()),
            )
            .await?;
        let outcome = match result.outcome() {
            RelayConsultationOutcome::Match => RuntimeRelayOutcome::Match,
            RelayConsultationOutcome::NoMatch => RuntimeRelayOutcome::NoMatch,
            RelayConsultationOutcome::Ambiguous => RuntimeRelayOutcome::Ambiguous,
        };
        let output = result
            .data()
            .map(|output| {
                RuntimeRelayOutput::new(output.name(), Zeroizing::new(output.value().to_string()))
            })
            .transpose()?;
        RuntimeRelayConsultationResult::new(
            result.consultation_id(),
            outcome,
            output,
            result.provenance().relay_acquired_at(),
        )
    }
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
                let execution = tokio::spawn(async move { activated.execute(&key).await });
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

    pub(crate) async fn consult(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<Arc<RuntimeRelayConsultationResult>, RelayClientError> {
        let cell = self
            .groups
            .get(key)
            .ok_or(RelayClientError::InvalidRequest)?;
        cell.start(
            Arc::clone(&self.activated),
            Arc::clone(&self.audit),
            key.clone(),
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
}

impl RequestScopedRelayPlan {
    pub(crate) fn new(
        entries: impl IntoIterator<Item = (String, ConsultationGroupKeyV1)>,
        activated: Arc<dyn ActivatedRelayConsultations>,
        audit: Arc<EvaluationAuditCollector>,
    ) -> Result<Self, ConsultationPlanError> {
        let mut keys_by_claim = BTreeMap::new();
        for (claim_id, key) in entries {
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
        })
    }

    pub(crate) async fn consult(
        &self,
        claim_id: &str,
    ) -> Result<Arc<RuntimeRelayConsultationResult>, RelayClientError> {
        let key = self
            .keys_by_claim
            .get(claim_id)
            .ok_or(RelayClientError::InvalidRequest)?;
        let result = self.coordinator.consult(key).await?;
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
    inputs.len() == 1
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
                .expect("valid output"),
            ),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("valid result")
    }

    #[derive(Debug)]
    struct CountingActivated {
        calls: AtomicUsize,
        failure: Option<RelayClientError>,
        delay: Duration,
    }

    impl CountingActivated {
        fn success() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                failure: None,
                delay: Duration::from_millis(20),
            }
        }

        fn failure(error: RelayClientError) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                failure: Some(error),
                delay: Duration::from_millis(20),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl ActivatedRelayConsultations for CountingActivated {
        async fn check_ready(&self) -> Result<(), RelayClientError> {
            Ok(())
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
        assert_eq!(key.canonical_input(), ("subject_id", TARGET_VALUE));
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
    fn result_shape_is_one_bounded_zeroizing_string_or_no_output() {
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::Match,
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("match requires one output");

        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::NoMatch,
            Some(RuntimeRelayOutput::new("status", Zeroizing::new("value".to_string())).unwrap()),
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
