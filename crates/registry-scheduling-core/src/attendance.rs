// SPDX-License-Identifier: Apache-2.0

//! Appointment-level attendance observations and correction documents.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One authorized observation about a logical appointment.
///
/// This is deliberately appointment-level. It neither identifies one person
/// nor derives a count from the booking party or its reserved units.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AttendanceState {
    Arrived,
    Completed,
    NoShow,
}

impl AttendanceState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arrived => "arrived",
            Self::Completed => "completed",
            Self::NoShow => "no-show",
        }
    }
}

/// Record the first attendance fact for the current visit or correct it.
///
/// `observed_appointment_revision` binds the staff observation to the
/// booking version they read. `observed_revision` is the current attendance
/// revision for that visit, or zero when the visit has no observation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordAttendanceRequest {
    pub observed_appointment_revision: u64,
    pub observed_revision: u64,
    pub state: AttendanceState,
    pub observed_at: DateTime<Utc>,
}

/// The current attendance observation for one appointment visit.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct AttendanceDocument {
    pub appointment_id: String,
    /// The booking revision the recorder observed. A later cancellation may
    /// advance the current booking revision without changing this fact.
    pub appointment_revision: u64,
    /// Globally monotonic within the appointment, including across visits.
    pub revision: u64,
    pub state: AttendanceState,
    pub observed_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::{AttendanceDocument, RecordAttendanceRequest};
    use crate::AttendanceState;

    #[test]
    fn record_request_is_closed_and_keeps_the_effective_observation_time() {
        let observed_at = Utc.with_ymd_and_hms(2026, 10, 23, 8, 15, 0).unwrap();
        let request: RecordAttendanceRequest = serde_json::from_value(json!({
            "observedAppointmentRevision": 3,
            "observedRevision": 0,
            "state": "arrived",
            "observedAt": observed_at,
        }))
        .unwrap();
        assert_eq!(request.observed_appointment_revision, 3);
        assert_eq!(request.observed_revision, 0);
        assert_eq!(request.state, AttendanceState::Arrived);
        assert_eq!(request.observed_at, observed_at);

        let with_unknown = json!({
            "observedAppointmentRevision": 3,
            "observedRevision": 0,
            "state": "arrived",
            "observedAt": observed_at,
            "attendees": ["person-1"],
        });
        assert!(serde_json::from_value::<RecordAttendanceRequest>(with_unknown).is_err());
    }

    #[test]
    fn only_the_three_appointment_level_observations_are_accepted() {
        for state in ["arrived", "completed", "no-show"] {
            let request: RecordAttendanceRequest = serde_json::from_value(json!({
                "observedAppointmentRevision": 3,
                "observedRevision": 7,
                "state": state,
                "observedAt": "2026-10-23T08:15:00Z",
            }))
            .unwrap();
            assert_eq!(request.observed_revision, 7);
        }
        for state in ["notRecorded", "inService", "leftWithoutService"] {
            assert!(serde_json::from_value::<RecordAttendanceRequest>(json!({
                "observedAppointmentRevision": 3,
                "observedRevision": 0,
                "state": state,
                "observedAt": "2026-10-23T08:15:00Z",
            }))
            .is_err());
        }
    }

    #[test]
    fn current_document_keeps_attendance_and_booking_revisions_distinct() {
        let current: AttendanceDocument = serde_json::from_value(json!({
            "appointmentId": "25b91ea4-75ca-48de-b9ef-4326fec81f28",
            "appointmentRevision": 3,
            "revision": 2,
            "state": "completed",
            "observedAt": "2026-10-23T08:45:00Z",
            "recordedAt": "2026-10-23T09:00:00Z"
        }))
        .unwrap();
        assert_eq!(current.appointment_revision, 3);
        assert_eq!(current.revision, 2);
    }

    #[test]
    fn response_documents_tolerate_a_later_additive_member() {
        let current: AttendanceDocument = serde_json::from_value(json!({
            "appointmentId": "25b91ea4-75ca-48de-b9ef-4326fec81f28",
            "appointmentRevision": 3,
            "revision": 2,
            "state": "arrived",
            "observedAt": "2026-10-23T08:15:00Z",
            "recordedAt": "2026-10-23T08:16:00Z",
            "laterServerMember": true
        }))
        .unwrap();
        assert_eq!(current.state, AttendanceState::Arrived);
    }
}
