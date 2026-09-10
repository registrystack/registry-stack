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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_effect: Option<ClockNextEffect>,
}

/// The next unapplied effect authored by the pinned clock policy. Runtime
/// verification retry times and source timing inputs are deliberately absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClockNextEffect {
    Reminder {
        id: String,
        at: DateTime<Utc>,
    },
    Reassign {
        id: String,
        at: DateTime<Utc>,
        because: String,
        #[serde(rename = "queueId")]
        queue_id: String,
    },
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn occurrence_projection_exposes_only_the_next_authored_effect() {
        let at = DateTime::parse_from_rfc3339("2026-09-12T10:30:00+07:00")
            .unwrap()
            .with_timezone(&Utc);
        let view = ClockOccurrenceView {
            clock_occurrence_id: Uuid::nil(),
            subject: SubjectRef {
                source_id: "source-a".to_owned(),
                kind: "request".to_owned(),
                id: "subject-a".to_owned(),
            },
            clock_id: "review-clock".to_owned(),
            state: ClockRuntimeState::VerificationPending,
            policy_digest: "sha256:clock".to_owned(),
            calculation_generation: 2,
            recompute_generation: 1,
            anchor_at: None,
            started_at: None,
            due_at: Some(at),
            at_risk_at: None,
            completed_at: None,
            next_effect: Some(ClockNextEffect::Reassign {
                id: "deadline".to_owned(),
                at,
                because: "The review deadline passed.".to_owned(),
                queue_id: "overdue".to_owned(),
            }),
        };

        let wire = serde_json::to_value(view).unwrap();
        assert_eq!(
            wire["nextEffect"],
            json!({
                "kind": "reassign",
                "id": "deadline",
                "at": "2026-09-12T03:30:00Z",
                "because": "The review deadline passed.",
                "queueId": "overdue"
            })
        );
        for forbidden in [
            "nextActionAt",
            "sourceTiming",
            "holidayDocument",
            "predicate",
        ] {
            assert!(wire.get(forbidden).is_none());
        }
    }
}
