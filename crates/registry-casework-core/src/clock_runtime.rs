// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{HolidaySetDocument, SubjectBinding};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ClockRuntimeState {
    Running,
    Completed,
    Cancelled,
    VerificationPending,
    SourceFactsMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClockOccurrenceView {
    pub clock_occurrence_id: Uuid,
    pub subject: SubjectBinding,
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
    /// The earliest unapplied reminder and reassignment, ordered by time.
    /// At most two effects; these are authored instants, not retry timers.
    /// Completed, cancelled and source-facts-missing clocks omit them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upcoming_effects: Vec<ClockNextEffect>,
}

/// The next unapplied effect authored by the pinned clock policy. Runtime
/// verification retry times and source timing inputs are deliberately absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "kebab-case")]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HolidaySetRevisionInput {
    pub document: HolidaySetDocument,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn occurrence_projection_exposes_authored_effects_without_retry_inputs() {
        let at = DateTime::parse_from_rfc3339("2026-09-12T10:30:00+07:00")
            .unwrap()
            .with_timezone(&Utc);
        let view = ClockOccurrenceView {
            clock_occurrence_id: Uuid::nil(),
            subject: SubjectBinding {
                source: "source-a".to_owned(),
                subject_type: "request".to_owned(),
                id: "subject-a".to_owned(),
                version: "1".into(),
                digest: crate::ContentDigest::for_bytes(b"subject"),
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
            upcoming_effects: vec![ClockNextEffect::Reassign {
                id: "deadline".to_owned(),
                at,
                because: "The review deadline passed.".to_owned(),
                queue_id: "overdue".to_owned(),
            }],
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
        assert_eq!(wire["upcomingEffects"], json!([wire["nextEffect"]]));
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
