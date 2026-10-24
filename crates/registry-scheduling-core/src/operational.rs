// SPDX-License-Identifier: Apache-2.0

//! Minimal documents returned to an explicitly configured operational reader.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AllocationRequirementDocument, AppointmentStateDocument, ExternalReference, PartyCounts,
};

/// Pinned path for the bounded cross-owner appointment work list.
pub const OPERATIONAL_APPOINTMENTS_PATH: &str = "/v1/operational/appointments";

/// Which appointment interval an operational query overlaps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum OperationalTimeBasis {
    Displayed,
    Occupied,
}

/// The public request vocabulary. Runtime authorization converts this into a
/// separate normalized filter and never treats the profile selector as grant
/// material.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationalAppointmentQuery {
    pub service: String,
    pub location: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub time_basis: OperationalTimeBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offering: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<AppointmentStateDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_reference: Option<ExternalReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// One appointment in an operational work list. The fixed fields identify the
/// scheduled service and its displayed interval. Optional fields are emitted
/// only when the selected runtime profile explicitly projects them.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct OperationalAppointmentDocument {
    pub appointment_id: String,
    pub revision: u64,
    pub service: String,
    pub location: String,
    pub offering: String,
    pub state: AppointmentStateDocument,
    pub displayed_start: DateTime<Utc>,
    pub displayed_end: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occupied_start: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occupied_end: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party: Option<PartyCounts>,
    /// Physical allocation detail, only when the selected operational
    /// profile explicitly projects it. `None` or an empty list means the
    /// utilization detail is unavailable and must not be reconstructed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocations: Option<Vec<OperationalAllocationDocument>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attendance: Option<crate::AttendanceDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,
}

/// One explicitly projected physical allocation for operational reporting.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct OperationalAllocationDocument {
    pub requirement: AllocationRequirementDocument,
    pub offering: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub units: u32,
    pub occupied_start: DateTime<Utc>,
    pub occupied_end: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn the_query_keeps_the_exact_external_reference_tuple() {
        let query = OperationalAppointmentQuery {
            service: "registry-update".to_owned(),
            location: "north-counter".to_owned(),
            start: Utc.with_ymd_and_hms(2026, 10, 23, 9, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 10, 23, 17, 0, 0).unwrap(),
            time_basis: OperationalTimeBasis::Displayed,
            offering: None,
            state: Some(AppointmentStateDocument::Confirmed),
            resource: None,
            external_reference: Some(ExternalReference {
                product: "registry-casework".to_owned(),
                record_type: "case".to_owned(),
                identifier: "case:42".to_owned(),
            }),
            profile: Some("desk".to_owned()),
            cursor: None,
            limit: Some(50),
        };
        let encoded = serde_json::to_value(&query).unwrap();
        assert_eq!(encoded["externalReference"]["identifier"], "case:42");
        assert_eq!(
            serde_json::from_value::<OperationalAppointmentQuery>(encoded).unwrap(),
            query
        );
    }

    #[test]
    fn absent_optional_projection_members_are_omitted() {
        let document = OperationalAppointmentDocument {
            appointment_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            revision: 1,
            service: "registry-update".to_owned(),
            location: "north-counter".to_owned(),
            offering: "in-person".to_owned(),
            state: AppointmentStateDocument::Confirmed,
            displayed_start: Utc.with_ymd_and_hms(2026, 10, 23, 9, 0, 0).unwrap(),
            displayed_end: Utc.with_ymd_and_hms(2026, 10, 23, 9, 30, 0).unwrap(),
            occupied_start: None,
            occupied_end: None,
            resource: None,
            units: None,
            party: None,
            allocations: None,
            attendance: None,
            external_references: Vec::new(),
        };
        let encoded = serde_json::to_value(document).unwrap();
        for absent in [
            "occupiedStart",
            "occupiedEnd",
            "resource",
            "units",
            "party",
            "allocations",
            "externalReferences",
        ] {
            assert!(encoded.get(absent).is_none(), "{absent} was emitted");
        }
    }
}
