// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{HolidaySetDocument, SubjectRef};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockRuntimeState {
    Running,
    Paused,
    Completed,
    Cancelled,
    VerificationPending,
    SourceFactsMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockOccurrenceView {
    pub clock_occurrence_id: Uuid,
    pub subject: SubjectRef,
    pub clock_id: String,
    pub state: ClockRuntimeState,
    pub policy_digest: String,
    pub calculation_generation: i64,
    pub recompute_generation: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_risk_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolidaySetRevisionInput {
    pub document: HolidaySetDocument,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockRecomputeRequest {
    pub clock_id: String,
    pub holiday_set: String,
    pub holiday_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockRecomputeChange {
    pub clock_occurrence_id: Uuid,
    pub item_id: Uuid,
    pub expected_calculation_generation: i64,
    pub old_due_at: DateTime<Utc>,
    pub proposed_due_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockRecomputePreview {
    pub preview_id: Uuid,
    pub clock_id: String,
    pub holiday_set: String,
    pub holiday_revision: u64,
    pub expires_at: DateTime<Utc>,
    pub changes: Vec<ClockRecomputeChange>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockRecomputeApplyRequest {
    pub preview_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockRecomputeResult {
    pub preview_id: Uuid,
    pub applied_occurrences: Vec<Uuid>,
}
