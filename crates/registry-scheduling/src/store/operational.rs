// SPDX-License-Identifier: Apache-2.0

//! Fail-closed persistence for cross-owner operational appointment reads.

use chrono::{DateTime, Utc};
use registry_scheduling_core::{
    AllocationRequirementDocument, AppointmentStateDocument, ExternalReference, PartyCounts,
};
use serde_json::Value;
use uuid::Uuid;

use crate::attendance::AttendanceObservation;
use crate::operational::{
    AuthorizedOperationalRead, AuthorizedResourceScope, OperationalProjectionField,
    OperationalTimeBasis,
};

use super::{PostgresStore, StoreError};

/// A row whose columns are already limited to the authorized projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalAppointmentRow {
    pub appointment_id: Uuid,
    pub revision: i64,
    pub service: String,
    pub location: String,
    pub offering: String,
    pub state: AppointmentStateDocument,
    pub displayed_start: DateTime<Utc>,
    pub displayed_end: DateTime<Utc>,
    pub occupied_start: Option<DateTime<Utc>>,
    pub occupied_end: Option<DateTime<Utc>>,
    pub resource: Option<String>,
    pub units: Option<i32>,
    pub party: Option<PartyCounts>,
    pub allocations: Option<Vec<OperationalAllocationRow>>,
    pub attendance: Option<AttendanceObservation>,
    pub external_references: Vec<ExternalReference>,
    /// The selected interval's start, used only for the opaque page position.
    pub position_start: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalAllocationRow {
    pub requirement: AllocationRequirementDocument,
    pub offering: String,
    pub resource: Option<String>,
    pub units: i32,
    pub occupied_start: DateTime<Utc>,
    pub occupied_end: DateTime<Utc>,
}

impl PostgresStore {
    /// Read one authorized operational page. The handle fixes identity,
    /// profile, filters and projection before this method can be called.
    pub async fn list_operational_appointments(
        &self,
        authority: &AuthorizedOperationalRead,
        after: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<OperationalAppointmentRow>, StoreError> {
        let mut client = self.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        let filter = authority.filter();
        let resources = match authority.resources() {
            AuthorizedResourceScope::Unrestricted => None,
            AuthorizedResourceScope::Exact { ids } => Some(ids.clone()),
        };
        let state = filter.state().map(|state| match state {
            AppointmentStateDocument::Confirmed => "active",
            AppointmentStateDocument::Cancelled => "cancelled",
        });
        let external_reference = filter
            .external_reference()
            .map(|reference| serde_json::to_value([reference]).map_err(|_| StoreError::Corrupt))
            .transpose()?;
        let (position_start, position_id) = after
            .map(|(instant, id)| (Some(instant), Some(id)))
            .unwrap_or((None, None));
        let projection = authority.projection();
        let includes_occupied = projection.allows(OperationalProjectionField::OccupiedInterval);
        let includes_resource = projection.allows(OperationalProjectionField::Resource);
        let includes_units = projection.allows(OperationalProjectionField::Units);
        let includes_party = projection.allows(OperationalProjectionField::PartyCounts);
        let includes_allocations = projection.allows(OperationalProjectionField::Allocations);
        let includes_attendance = projection.allows(OperationalProjectionField::Attendance);
        let includes_references = !projection.external_reference_products.is_empty();
        let (position_start_expression, interval_predicate) = match filter.time_basis() {
            OperationalTimeBasis::Displayed => (
                "c.displayed_start",
                "c.displayed_start < $4 AND c.displayed_end > $3",
            ),
            OperationalTimeBasis::Occupied => (
                "CASE WHEN c.operational_mode='arrival-window' THEN c.occupied_start \
                 ELSE (SELECT min(position.occupied_start) FROM scheduling_claim_allocations AS position \
                   WHERE position.claim_id=c.claim_id \
                     AND ($5::text[] IS NULL OR position.resource_id=ANY($5))) END",
                "(CASE WHEN c.operational_mode='arrival-window' \
                   THEN c.occupied_start < $4 AND c.occupied_end > $3 \
                 ELSE EXISTS (SELECT 1 FROM scheduling_claim_allocations AS occupied \
                   WHERE occupied.claim_id=c.claim_id \
                     AND occupied.occupied_start < $4 AND occupied.occupied_end > $3 \
                     AND ($5::text[] IS NULL OR occupied.resource_id=ANY($5))) END)",
            ),
        };
        let sql = format!(
            "SELECT c.claim_id, c.revision, c.operational_service, c.operational_location, c.offering, c.state, \
             c.displayed_start, c.displayed_end, \
             CASE WHEN $11 THEN c.occupied_start ELSE NULL END, \
             CASE WHEN $11 THEN c.occupied_end ELSE NULL END, \
             CASE WHEN $12 AND c.operational_mode='exact-time' \
                       AND ($5::text[] IS NULL OR c.supply_id=ANY($5)) \
                  THEN c.supply_id ELSE NULL END, \
             CASE WHEN $13 THEN c.units ELSE NULL END, \
             CASE WHEN $14 THEN c.recipient_count ELSE NULL END, \
             CASE WHEN $14 THEN c.attendee_count ELSE NULL END, \
             CASE WHEN $15 THEN c.external_references ELSE '[]'::jsonb END, \
             {position_start_expression} AS position_start \
             FROM scheduling_claims AS c \
             WHERE c.kind='booking' \
               AND c.operational_service=$1 AND c.operational_location=$2 \
               AND {interval_predicate} \
               AND ($5::text[] IS NULL OR (c.operational_mode='exact-time' AND EXISTS ( \
                    SELECT 1 FROM scheduling_claim_allocations AS resource \
                    WHERE resource.claim_id=c.claim_id \
                      AND resource.resource_id=ANY($5)))) \
               AND ($6::text IS NULL OR c.offering=$6) \
               AND ($7::text IS NULL OR c.state=$7) \
               AND ($8::jsonb IS NULL OR c.external_references @> $8) \
               AND ($9::timestamptz IS NULL OR ({position_start_expression}, c.claim_id) > ($9, $10)) \
             ORDER BY {position_start_expression}, c.claim_id LIMIT $16"
        );
        let rows = transaction
            .query(
                &sql,
                &[
                    &filter.service(),
                    &filter.location(),
                    &filter.start(),
                    &filter.end(),
                    &resources,
                    &filter.offering(),
                    &state,
                    &external_reference,
                    &position_start,
                    &position_id,
                    &includes_occupied,
                    &includes_resource,
                    &includes_units,
                    &includes_party,
                    &includes_references,
                    &limit,
                ],
            )
            .await?;
        let mut appointments = rows
            .iter()
            .map(|row| {
                let state: String = row.get(5);
                let state = match state.as_str() {
                    "active" => AppointmentStateDocument::Confirmed,
                    "cancelled" => AppointmentStateDocument::Cancelled,
                    _ => return Err(StoreError::Corrupt),
                };
                let party = match (row.get::<_, Option<i32>>(12), row.get::<_, Option<i32>>(13)) {
                    (Some(recipients), Some(attendees)) => Some(PartyCounts {
                        recipients: u32::try_from(recipients).map_err(|_| StoreError::Corrupt)?,
                        attendees: u32::try_from(attendees).map_err(|_| StoreError::Corrupt)?,
                    }),
                    (None, None) => None,
                    _ => return Err(StoreError::Corrupt),
                };
                let references: Value = row.get(14);
                let references: Vec<ExternalReference> =
                    serde_json::from_value(references).map_err(|_| StoreError::Corrupt)?;
                Ok(OperationalAppointmentRow {
                    appointment_id: row.get(0),
                    revision: row.get(1),
                    service: row.get(2),
                    location: row.get(3),
                    offering: row.get(4),
                    state,
                    displayed_start: row.get(6),
                    displayed_end: row.get(7),
                    occupied_start: row.get(8),
                    occupied_end: row.get(9),
                    resource: row.get(10),
                    units: row.get(11),
                    party,
                    allocations: includes_allocations.then(Vec::new),
                    attendance: None,
                    external_references: references
                        .into_iter()
                        .filter(|reference| {
                            projection.allows_external_reference_product(&reference.product)
                        })
                        .collect(),
                    position_start: row.get(15),
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        self.pause_operational_page_if_requested().await;
        if includes_attendance && !appointments.is_empty() {
            let ids: Vec<_> = appointments.iter().map(|row| row.appointment_id).collect();
            for observation in
                super::attendance::current_attendance_for_claims(&*transaction, &ids).await?
            {
                let appointment_id = observation.appointment_id;
                appointments
                    .iter_mut()
                    .find(|appointment| appointment.appointment_id == appointment_id)
                    .ok_or(StoreError::Corrupt)?
                    .attendance = Some(observation);
            }
        }
        if includes_allocations && !appointments.is_empty() {
            let ids: Vec<_> = appointments.iter().map(|row| row.appointment_id).collect();
            let allocations = transaction
                .query(
                    "SELECT claim_id, requirement_kind, requirement_index, offering, resource_id, \
                        units, occupied_start, occupied_end \
                 FROM scheduling_claim_allocations \
                 WHERE claim_id=ANY($1) AND operational_mode='exact-time' \
                   AND EXISTS (SELECT 1 FROM scheduling_claims c \
                       WHERE c.claim_id=scheduling_claim_allocations.claim_id AND c.operational_mode='exact-time') \
                 ORDER BY claim_id, requirement_kind DESC, requirement_index, part_index",
                    &[&ids],
                )
                .await?;
            for allocation in allocations {
                let claim_id: Uuid = allocation.get(0);
                let kind: String = allocation.get(1);
                let index: i16 = allocation.get(2);
                let requirement = match kind.as_str() {
                    "primary" if index == 0 => AllocationRequirementDocument::Primary,
                    "additional" => AllocationRequirementDocument::Additional {
                        index: u8::try_from(index).map_err(|_| StoreError::Corrupt)?,
                    },
                    _ => return Err(StoreError::Corrupt),
                };
                let resource_id: String = allocation.get(4);
                let resource = match &resources {
                    None => Some(resource_id),
                    Some(allowed) if allowed.contains(&resource_id) => Some(resource_id),
                    Some(_) => None,
                };
                let row = OperationalAllocationRow {
                    requirement,
                    offering: allocation.get(3),
                    resource,
                    units: allocation.get(5),
                    occupied_start: allocation.get(6),
                    occupied_end: allocation.get(7),
                };
                appointments
                    .iter_mut()
                    .find(|appointment| appointment.appointment_id == claim_id)
                    .ok_or(StoreError::Corrupt)?
                    .allocations
                    .as_mut()
                    .ok_or(StoreError::Corrupt)?
                    .push(row);
            }
        }
        transaction.commit().await?;
        Ok(appointments)
    }
}
