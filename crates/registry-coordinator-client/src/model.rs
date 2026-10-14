// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunStatus {
    pub run_id: Uuid,
    pub workflow: String,
    #[serde(deserialize_with = "revision")]
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
    pub failure_path: Option<String>,
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
    pub version: u32,
    pub product: String,
    pub effect: EffectKind,
    pub key_requirement: KeyRequirement,
    pub requires_preparation: bool,
    pub recovery: RecoverySemantics,
    pub read_receipt: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryStatus {
    pub retry_allowed: bool,
    pub reason: Option<RetryBlockReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationIdentity>,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunInspection {
    pub run: RunStatus,
    pub steps: Vec<StepStatus>,
    pub effects: Vec<EffectStatus>,
    pub waits: Vec<WaitStatus>,
    pub recovery: RecoveryStatus,
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

/// One caller-controlled page request. A continuation must preserve its state
/// and attention filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunListQuery {
    pub limit: u32,
    pub cursor: Option<String>,
    pub state: Option<RunListState>,
    pub attention: Option<bool>,
}

impl RunListQuery {
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            cursor: None,
            state: None,
            attention: None,
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
    pub run_id: Uuid,
    /// Always `retry-scheduled`; any other answer is refused as a protocol failure.
    pub status: String,
}

// Inputs and authored outputs can carry protected source values. Debug is
// intentionally not derived for those documents.

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
