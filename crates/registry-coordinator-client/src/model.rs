// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartRunRequest {
    pub workflow: String,
    #[serde(deserialize_with = "revision")]
    pub workflow_revision: String,
    pub input: Value,
}

/// The active compiled contract visible to a caller allowed to start it.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowContract {
    pub workflow: String,
    #[serde(deserialize_with = "revision")]
    pub workflow_revision: String,
    pub input: Value,
    pub outcomes: BTreeMap<String, Value>,
}

/// The authenticated runtime's progress, not authorization to source records.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", try_from = "RunStatusDocument")]
pub struct RunStatus {
    pub run_id: Uuid,
    pub workflow: String,
    pub workflow_revision: String,

    pub binding_digest: String,
    pub step: String,
    pub state: String,
    pub outcome: Option<String>,
    pub output: Option<Value>,
    pub failure_code: Option<String>,
    /// Where a refused call input left its operation contract, as an RFC 6901
    /// pointer that names no value.
    pub failure_path: Option<String>,
    pub admitted_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub next_due_at: Option<DateTime<Utc>>,
    pub uncertain: bool,
    pub restore_review_required: bool,
    pub cancel_requested: bool,
    pub authored_cancel_requested: bool,
}

// Admissions add a positive authored duration; retained status keeps that deadline.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunStatusDocument {
    #[serde(deserialize_with = "run_id")]
    run_id: Uuid,
    workflow: String,
    #[serde(deserialize_with = "revision")]
    workflow_revision: String,

    binding_digest: String,
    step: String,
    #[serde(deserialize_with = "run_state")]
    state: String,
    outcome: Option<String>,
    output: Option<Value>,
    failure_code: Option<String>,
    #[serde(default, deserialize_with = "failure_path")]
    failure_path: Option<String>,
    admitted_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    next_due_at: Option<DateTime<Utc>>,
    uncertain: bool,
    restore_review_required: bool,
    cancel_requested: bool,
    authored_cancel_requested: bool,
}

impl TryFrom<RunStatusDocument> for RunStatus {
    type Error = &'static str;

    fn try_from(document: RunStatusDocument) -> Result<Self, Self::Error> {
        if document.deadline_at <= document.admitted_at {
            return Err("expected a deadline after admission");
        }
        // A leased Finish may commit while restore review projects attention.
        // Retention can erase output without erasing the completed outcome.
        let finished = document.state == "finished";
        let restore_review = document.state == "attention" && document.restore_review_required;
        if document.outcome.is_some() && !(finished || restore_review)
            || document.outcome.is_none() && (finished || document.output.is_some())
        {
            return Err("expected terminal evidence consistent with the run state");
        }
        Ok(Self {
            run_id: document.run_id,
            workflow: document.workflow,
            workflow_revision: document.workflow_revision,
            binding_digest: document.binding_digest,
            step: document.step,
            state: document.state,
            outcome: document.outcome,
            output: document.output,
            failure_code: document.failure_code,
            failure_path: document.failure_path,
            admitted_at: document.admitted_at,
            deadline_at: document.deadline_at,
            next_due_at: document.next_due_at,
            uncertain: document.uncertain,
            restore_review_required: document.restore_review_required,
            cancel_requested: document.cancel_requested,
            authored_cancel_requested: document.authored_cancel_requested,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepStatus {
    pub step: String,
    pub state: String,
    pub generation: i64,
    pub attempt: i16,
    pub next_due_at: Option<DateTime<Utc>>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub command_prepared: bool,
    pub uncertain: bool,
    pub receipt_expired: bool,
    pub failure_code: Option<String>,
    /// Where a refused call input left its operation contract, as an RFC 6901
    /// pointer that names no value.
    #[serde(default, deserialize_with = "failure_path")]
    pub failure_path: Option<String>,
    /// What a person needs to clear a hold: for `in-force-ambiguous`, the
    /// two records in force and the date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_detail: Option<HoldDetail>,
}

/// The records and date behind a held step.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoldDetail {
    pub date: String,
    pub record_identifiers: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RetryBlockReason {
    NotRecoverable,
    DeadlineReached,
    ReceiptExpired,
    BindingChanged,
    OtherBindingLive,
    SnapshotIncompatible,
    Cancelled,
    RestoreHold,
    RestoreReviewRequired,
    PayloadErased,
    EvaluationUncertain,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EffectKind {
    Read,
    Mutation,
    Evaluation,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRequirement {
    None,
    Required,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RecoverySemantics {
    ReadAgain,
    SameCommandAndReceipt,
    SameCommand,
    HoldAfterDispatch,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationIdentity {
    pub id: String,
    #[serde(deserialize_with = "operation_version")]
    pub version: u32,
    pub product: String,
    pub effect: EffectKind,
    pub key_requirement: KeyRequirement,
    pub requires_preparation: bool,
    pub recovery: RecoverySemantics,
    pub read_receipt: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", try_from = "RecoveryStatusDocument")]
pub struct RecoveryStatus {
    pub retry_allowed: bool,
    pub reason: Option<RetryBlockReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationIdentity>,
}
// Keep the wire shape strict while validating the runtime's one recovery decision.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryStatusDocument {
    retry_allowed: bool,
    reason: Option<RetryBlockReason>,
    operation: Option<OperationIdentity>,
}

impl TryFrom<RecoveryStatusDocument> for RecoveryStatus {
    type Error = &'static str;

    fn try_from(document: RecoveryStatusDocument) -> Result<Self, Self::Error> {
        if document.retry_allowed != document.reason.is_none() {
            return Err("expected a consistent recovery decision");
        }
        Ok(Self {
            retry_allowed: document.retry_allowed,
            reason: document.reason,
            operation: document.operation,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EffectState {
    Accepted,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectStatus {
    pub step: String,
    pub operation: OperationIdentity,
    #[serde(deserialize_with = "revision")]
    pub operation_revision: String,
    pub state: EffectState,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", try_from = "WaitStatusDocument")]
pub struct WaitStatus {
    pub step: String,
    pub accepted_step: String,
    pub completion: String,
    #[serde(deserialize_with = "revision")]
    pub completion_revision: String,
    pub timeout_at: DateTime<Utc>,
    pub next_observation_at: Option<DateTime<Utc>>,
    pub not_before: DateTime<Utc>,
    pub minimum_interval_seconds: u32,
    pub observations: u32,
    pub observation_limit: u32,
    /// What the latest answered read of a followed BReg Proposal showed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observation: Option<LastObservation>,
    /// The operator's "Open the request" link for a followed Proposal, when
    /// the deployment configures one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_link: Option<String>,
}

/// The latest answered read of a followed BReg Proposal. It carries no
/// Proposal input and names no person. `state_since` is when Coordinator
/// first saw the current state and turn, not when BReg entered it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LastObservation {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<String>,
    pub submission_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_refusal: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub state_since: DateTime<Utc>,
}

// The runtime owns the polling fence; inspection must preserve its valid budget.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WaitStatusDocument {
    step: String,
    accepted_step: String,
    completion: String,
    #[serde(deserialize_with = "revision")]
    completion_revision: String,
    timeout_at: DateTime<Utc>,
    next_observation_at: Option<DateTime<Utc>>,
    not_before: DateTime<Utc>,
    minimum_interval_seconds: u32,
    observations: u32,
    observation_limit: u32,
    #[serde(default)]
    last_observation: Option<LastObservation>,
    #[serde(default)]
    request_link: Option<String>,
}

impl TryFrom<WaitStatusDocument> for WaitStatus {
    type Error = &'static str;

    fn try_from(document: WaitStatusDocument) -> Result<Self, Self::Error> {
        if !(30..=86_400).contains(&document.minimum_interval_seconds)
            || document.observation_limit == 0
            || document.observations > document.observation_limit
        {
            return Err("expected a consistent observation budget");
        }
        Ok(Self {
            step: document.step,
            accepted_step: document.accepted_step,
            completion: document.completion,
            completion_revision: document.completion_revision,
            timeout_at: document.timeout_at,
            next_observation_at: document.next_observation_at,
            not_before: document.not_before,
            minimum_interval_seconds: document.minimum_interval_seconds,
            observations: document.observations,
            observation_limit: document.observation_limit,
            last_observation: document.last_observation,
            request_link: document.request_link,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", try_from = "RunInspectionDocument")]
pub struct RunInspection {
    pub run: RunStatus,
    pub steps: Vec<StepStatus>,
    pub effects: Vec<EffectStatus>,
    pub waits: Vec<WaitStatus>,
    pub recovery: RecoveryStatus,
}

// The runtime reads one step row per run step and builds each effect and wait
// from those rows in the same transaction, so evidence names this run's steps.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunInspectionDocument {
    run: RunStatus,
    steps: Vec<StepStatus>,
    effects: Vec<EffectStatus>,
    waits: Vec<WaitStatus>,
    recovery: RecoveryStatus,
}

impl TryFrom<RunInspectionDocument> for RunInspection {
    type Error = &'static str;

    fn try_from(document: RunInspectionDocument) -> Result<Self, Self::Error> {
        let mut steps = BTreeMap::new();
        for step in &document.steps {
            if steps.insert(step.step.as_str(), step).is_some() {
                return Err("expected one entry per run step");
            }
        }
        if !steps.contains_key(document.run.step.as_str()) {
            return Err("expected the current step among the run steps");
        }
        let mut effects = BTreeSet::new();
        for effect in &document.effects {
            let Some(step) = steps.get(effect.step.as_str()) else {
                return Err("expected each effect to name a run step");
            };
            let consistent = match effect.state {
                EffectState::Unknown => step.uncertain,
                EffectState::Accepted => !step.uncertain && step.state == "delivered",
            };
            if !effects.insert(effect.step.as_str()) || !consistent {
                return Err("expected one effect consistent with its run step");
            }
        }
        let mut waits = BTreeSet::new();
        for wait in &document.waits {
            if !steps.contains_key(wait.step.as_str()) || !waits.insert(wait.step.as_str()) {
                return Err("expected one wait per waiting run step");
            }
        }
        Ok(Self {
            run: document.run,
            steps: document.steps,
            effects: document.effects,
            waits: document.waits,
            recovery: document.recovery,
        })
    }
}

/// The closed effective states accepted by the run-list filter.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RunListState {
    Running,
    Finished,
    Failed,
    Cancelled,
    CancelledAfterEffect,
    Expired,
    Attention,
    CancelRequested,
}

impl RunListState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Finished => "finished",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::CancelledAfterEffect => "cancelled-after-effect",
            Self::Expired => "expired",
            Self::Attention => "attention",
            Self::CancelRequested => "cancel-requested",
        }
    }
}

/// Whose turn a followed BReg Proposal showed at its last answered read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalTurn {
    Party,
    Official,
    Nobody,
}

impl ProposalTurn {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Party => "party",
            Self::Official => "official",
            Self::Nobody => "nobody",
        }
    }
}

/// One caller-controlled page request. A continuation must preserve every
/// filter that produced its cursor. `proposal` selects runs waiting on that
/// Proposal; `turn` selects runs whose Proposal wait last showed that turn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunListQuery {
    pub limit: u32,
    pub cursor: Option<String>,
    pub state: Option<RunListState>,
    pub attention: Option<bool>,
    pub proposal: Option<Uuid>,
    pub turn: Option<ProposalTurn>,
}

impl RunListQuery {
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            cursor: None,
            state: None,
            attention: None,
            proposal: None,
            turn: None,
        }
    }
}

/// One stable page of runs the caller may read, newest admission first.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunList {
    pub runs: Vec<RunStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The runtime accepted a same-command retry; the worker has not run it yet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryScheduled {
    #[serde(deserialize_with = "run_id")]
    pub run_id: Uuid,
    /// Always `retry-scheduled`; any other answer is refused as a protocol failure.
    pub status: String,
}

// Inputs and authored outputs can carry protected source values. Debug is
// intentionally not derived for those documents.

// Response size is bounded by the client; diagnostic paths may include the root.
fn failure_path<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    if value.as_deref().is_none_or(|path| {
        path.is_empty()
            || path.starts_with('/')
                && path
                    .split('~')
                    .skip(1)
                    .all(|escaped| escaped.starts_with(['0', '1']))
    }) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "expected an RFC 6901 JSON Pointer",
        ))
    }
}

fn run_id<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
    let value = Uuid::deserialize(deserializer)?;
    if value.is_nil() {
        Err(serde::de::Error::custom("expected a nonnil run identity"))
    } else {
        Ok(value)
    }
}

fn operation_version<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let value = u32::deserialize(deserializer)?;
    if value == 0 {
        Err(serde::de::Error::custom(
            "expected a positive catalog operation version",
        ))
    } else {
        Ok(value)
    }
}

fn run_state<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    RunListState::deserialize(serde::de::value::StrDeserializer::<D::Error>::new(&value))
        .map(|state| state.as_str().to_owned())
        .map_err(|_| serde::de::Error::custom("expected a closed effective run state"))
}

fn revision<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    }) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "expected a computed workflow contract revision",
        ))
    }
}
