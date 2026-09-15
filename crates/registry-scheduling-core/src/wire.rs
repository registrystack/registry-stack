// SPDX-License-Identifier: Apache-2.0

//! The HTTP wire documents of the Scheduling API.
//!
//! These types are the contract between the runtime and every client, so they
//! live in the source-neutral core beside the model they project, the way the
//! Casework DTOs live in `registry-casework-core`. Every document is
//! camelCase on the wire and refuses unknown fields, so an undocumented
//! addition to a response is a compatibility event a caller notices, not a
//! field a lenient parser silently drops.
//!
//! The projections are deliberate: `because` review reasons are authoring
//! material and never published; occupied intervals (with buffers) are the
//! ledger's own view and callers see displayed times; and the one refusal
//! detail that names a resource appears only on the separately authorized
//! explain path.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::AdmissionRequest;

/// What `GET /v1/scheduling` answers: which deployment and which policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingServiceDocument {
    pub scheduling_id: String,
    pub policy_revision: u64,
    pub policy_digest: String,
}

/// One service in the catalogue.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceDocument {
    pub id: String,
    pub label: String,
}

/// One offering in the catalogue, the public view of the authored policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferingDocument {
    pub id: String,
    pub service: String,
    pub label: String,
    pub mode: SchedulingModeDocument,
    pub location: String,
    pub lead_time_minutes: u32,
    pub horizon_days: u32,
    pub cancellation_cutoff_minutes: u32,
    /// Present for exact-time offerings.
    pub duration_minutes: Option<u32>,
    /// Present for exact-time offerings.
    pub buffer_before_minutes: Option<u32>,
    /// Present for exact-time offerings.
    pub buffer_after_minutes: Option<u32>,
    /// Present for exact-time offerings.
    pub start_increment_minutes: Option<u32>,
    /// Present for exact-time offerings.
    pub max_recipients: Option<u32>,
    /// Present for arrival-window offerings.
    pub window: Option<WindowDocument>,
    pub reminders: Vec<ReminderDocument>,
    pub requires_capabilities: Vec<String>,
    pub prerequisites: Vec<String>,
}

/// How an offering delivers its service, on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchedulingModeDocument {
    ExactTime,
    ArrivalWindow,
}

/// One authored reminder offset, as the catalogue publishes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderDocument {
    pub minutes_before: u32,
}

/// A published arrival window in the catalogue.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowDocument {
    pub id: String,
    pub revision: u64,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub units: u32,
}

/// One backing resource in the resource listing: a concrete pool member,
/// because a pool is its members, never an independent counter.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceDocument {
    pub resource_id: String,
    pub pool: String,
    pub capabilities: Vec<String>,
    pub available: bool,
}

/// One location in the location listing, with the IANA timezone identifier
/// its published openings expand in.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocationDocument {
    pub location_id: String,
    pub timezone: String,
}

/// One availability answer entry. Exact-time offerings answer in grid slots;
/// arrival-window offerings answer in windows.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AvailabilityEntry {
    /// A grid slot and how many pool members are still free across it.
    Slot {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        free: u32,
    },
    /// A published window and its remaining recipient units, the caller's
    /// channel slice included when the window reserves one for it.
    Window {
        window: String,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        remaining: u32,
        channel_remaining: Option<u32>,
    },
}

/// One page of a bounded listing, with the opaque cursor that continues it.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageDocument<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

/// A minted hold, the answer to `POST /v1/holds`. The hold request body is
/// the same admission request shape a direct create carries: a hold is an
/// admission ask that reserves instead of committing.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoldDocument {
    pub hold_id: String,
    pub offering: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// The pool member held, for exact-time offerings.
    pub resource: Option<String>,
    pub units: u32,
    pub expires_at: DateTime<Utc>,
    pub policy_revision: u64,
}

/// The lifecycle state of an appointment on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppointmentStateDocument {
    Confirmed,
    Cancelled,
}

impl AppointmentStateDocument {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A confirmed appointment.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppointmentDocument {
    pub appointment_id: String,
    pub offering: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// The pool member serving the appointment, for exact-time offerings.
    pub resource: Option<String>,
    pub units: u32,
    pub channel: Option<String>,
    pub revision: u64,
    pub state: AppointmentStateDocument,
    pub policy_revision: u64,
    pub created_at: DateTime<Utc>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// The request behind `POST /v1/appointments`: confirm a held allocation, or
/// create an appointment directly.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAppointmentRequest {
    /// The hold being confirmed. Mutually exclusive with `admission`.
    pub hold: Option<String>,
    /// The direct-create admission request. Mutually exclusive with `hold`.
    pub admission: Option<AdmissionRequest>,
}

/// The request behind `POST /v1/appointments/{id}/reschedule`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescheduleAppointmentRequest {
    pub observed_revision: u64,
    pub admission: AdmissionRequest,
}

/// The request behind `POST /v1/appointments/{id}/cancel`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelAppointmentRequest {
    pub observed_revision: u64,
    #[serde(default)]
    pub reason: Option<String>,
}

/// One attributable step in an appointment's history.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppointmentHistoryEntryDocument {
    pub event_id: String,
    pub kind: String,
    pub revision: u64,
    pub occurred_at: DateTime<Utc>,
    /// The pseudonymized actor reference, when the step had one.
    pub actor: Option<String>,
    pub detail: Value,
}

/// The separately authorized answer to `GET /v1/availability/explain`: what
/// a refused start would have said, including the one detail the public path
/// never names.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExplainDocument {
    pub offering: String,
    pub start: DateTime<Utc>,
    /// The problem code every caller may see. Absent when the start admits
    /// as things stand: there is no refusal to explain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_code: Option<String>,
    /// The problem code only this path may disclose. Absent with
    /// `public_code`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detailed_code: Option<String>,
    /// The refusal in words, as the evaluator states it. Absent with
    /// `public_code`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PartyCounts;
    use chrono::TimeZone as _;

    fn utc(day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, day, hour, 0, 0).unwrap()
    }

    #[test]
    fn catalogue_documents_round_trip_and_refuse_unknown_fields() {
        let offering = OfferingDocument {
            id: "registry-update-30".to_owned(),
            service: "registry-update".to_owned(),
            label: "30-minute counter update".to_owned(),
            mode: SchedulingModeDocument::ExactTime,
            location: "north-counter".to_owned(),
            lead_time_minutes: 120,
            horizon_days: 60,
            cancellation_cutoff_minutes: 240,
            duration_minutes: Some(30),
            buffer_before_minutes: Some(5),
            buffer_after_minutes: Some(5),
            start_increment_minutes: Some(30),
            max_recipients: Some(1),
            window: None,
            reminders: vec![ReminderDocument {
                minutes_before: 1440,
            }],
            requires_capabilities: Vec::new(),
            prerequisites: Vec::new(),
        };
        let json = serde_json::to_value(&offering).unwrap();
        assert_eq!(json["mode"], "exact-time");
        assert_eq!(json["leadTimeMinutes"], 120);
        let parsed: OfferingDocument = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, offering);
        assert!(serde_json::from_str::<OfferingDocument>(
            &serde_json::to_string(&offering)
                .unwrap()
                .replace("\"reminders\"", "\"reminders\":{\"x\":1},\"stray\"",)
        )
        .is_err());
    }

    #[test]
    fn availability_entries_are_kind_tagged() {
        let slot = AvailabilityEntry::Slot {
            start: utc(5, 2),
            end: utc(5, 3),
            free: 2,
        };
        let json = serde_json::to_value(&slot).unwrap();
        assert_eq!(json["kind"], "slot");
        assert_eq!(json["free"], 2);

        let window = AvailabilityEntry::Window {
            window: "household-morning-window".to_owned(),
            start: utc(10, 8),
            end: utc(10, 10),
            remaining: 1,
            channel_remaining: Some(0),
        };
        let json = serde_json::to_value(&window).unwrap();
        assert_eq!(json["kind"], "window");
        assert_eq!(json["channelRemaining"], 0);
        assert_eq!(
            serde_json::from_value::<AvailabilityEntry>(json).unwrap(),
            window
        );
    }

    #[test]
    fn create_requests_enforce_their_exclusive_shape() {
        let admission = AdmissionRequest {
            offering: "registry-update-30".to_owned(),
            start: utc(5, 2),
            party: PartyCounts {
                recipients: 1,
                attendees: 1,
            },
            channel: None,
            duplicate_key: Some("subject:one".to_owned()),
            policy_revision: 1,
            window_revision: None,
            capabilities: Vec::new(),
            prerequisites: Vec::new(),
        };

        let direct = CreateAppointmentRequest {
            hold: None,
            admission: Some(admission.clone()),
        };
        let json = serde_json::to_value(&direct).unwrap();
        assert_eq!(json["admission"]["duplicateKey"], "subject:one");
        assert_eq!(
            serde_json::from_value::<CreateAppointmentRequest>(json).unwrap(),
            direct
        );

        let confirming = CreateAppointmentRequest {
            hold: Some("0b2bb6b6-3f3a-4c66-9a5a-2fbd8c72d1ee".to_owned()),
            admission: None,
        };
        let json = serde_json::to_value(&confirming).unwrap();
        assert_eq!(
            serde_json::from_value::<CreateAppointmentRequest>(json).unwrap(),
            confirming
        );

        // Neither branch present, or a stray field, is refused.
        assert!(serde_json::from_str::<CreateAppointmentRequest>("{}").is_ok());
        assert!(serde_json::from_str::<CreateAppointmentRequest>("{\"hold\":1}").is_err());
    }

    #[test]
    fn appointment_and_history_documents_round_trip() {
        let appointment = AppointmentDocument {
            appointment_id: "6e97f6a3-8524-4a13-9db8-ad0c4eb4d64b".to_owned(),
            offering: "registry-update-30".to_owned(),
            start: utc(5, 2),
            end: utc(5, 3),
            resource: Some("station-1".to_owned()),
            units: 1,
            channel: None,
            revision: 2,
            state: AppointmentStateDocument::Confirmed,
            policy_revision: 1,
            created_at: utc(4, 9),
            cancelled_at: None,
        };
        let json = serde_json::to_value(&appointment).unwrap();
        assert_eq!(json["state"], "confirmed");
        assert_eq!(
            serde_json::from_value::<AppointmentDocument>(json).unwrap(),
            appointment
        );

        let entry = AppointmentHistoryEntryDocument {
            event_id: "b31c0f4e-cc7f-4ba8-88f2-9c1a9102f0a1".to_owned(),
            kind: "rescheduled".to_owned(),
            revision: 2,
            occurred_at: utc(4, 10),
            actor: Some("hmac-sha256:v2:8f0a".to_owned()),
            detail: serde_json::json!({"start": "2026-10-05T03:00:00Z"}),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["kind"], "rescheduled");
        assert_eq!(
            serde_json::from_value::<AppointmentHistoryEntryDocument>(json).unwrap(),
            entry
        );
    }

    /// The explain document carries both projections, so a test can pin that
    /// the detailed code never equals a detailed-only value in the public
    /// position, and that an admitted start carries neither.
    #[test]
    fn explain_documents_carry_both_projections() {
        let explain = ExplainDocument {
            offering: "registry-update-30".to_owned(),
            start: utc(5, 2),
            public_code: Some("capacity.exhausted".to_owned()),
            detailed_code: Some("resource.unavailable".to_owned()),
            explanation: Some("every capable member is unavailable".to_owned()),
        };
        let json = serde_json::to_value(&explain).unwrap();
        assert_eq!(json["publicCode"], "capacity.exhausted");
        assert_eq!(json["detailedCode"], "resource.unavailable");
        assert_eq!(
            serde_json::from_value::<ExplainDocument>(json).unwrap(),
            explain
        );

        let admitted = ExplainDocument {
            public_code: None,
            detailed_code: None,
            explanation: None,
            ..explain
        };
        let json = serde_json::to_value(&admitted).unwrap();
        assert!(json.get("publicCode").is_none());
        assert!(json.get("detailedCode").is_none());
        assert!(json.get("explanation").is_none());
        assert_eq!(
            serde_json::from_value::<ExplainDocument>(json).unwrap(),
            admitted
        );
    }

    #[test]
    fn pages_carry_an_optional_cursor() {
        let page = PageDocument {
            items: vec![ServiceDocument {
                id: "registry-update".to_owned(),
                label: "Registry record update".to_owned(),
            }],
            next_cursor: None,
        };
        let json = serde_json::to_value(&page).unwrap();
        assert_eq!(json["nextCursor"], Value::Null);
        assert_eq!(
            serde_json::from_value::<PageDocument<ServiceDocument>>(json).unwrap(),
            page
        );
    }
}
