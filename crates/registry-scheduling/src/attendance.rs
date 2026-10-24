// SPDX-License-Identifier: Apache-2.0

//! Runtime attendance rows and their minimized public projection.

use chrono::{DateTime, Utc};
use registry_scheduling_core::{AttendanceDocument, AttendanceState};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One immutable attendance observation as retained by Scheduling.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttendanceObservation {
    pub observation_id: Uuid,
    pub appointment_id: Uuid,
    /// The confirmed/rescheduled history revision that identifies the visit.
    pub visit_revision: i64,
    pub appointment_revision: i64,
    /// Globally monotonic within the appointment, including across visits.
    pub revision: i64,
    pub state: AttendanceState,
    pub observed_at: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
}

impl AttendanceObservation {
    pub fn document(&self) -> Result<AttendanceDocument, AttendanceProjectionError> {
        Ok(AttendanceDocument {
            appointment_id: self.appointment_id.to_string(),
            appointment_revision: self
                .appointment_revision
                .try_into()
                .map_err(|_| AttendanceProjectionError)?,
            revision: self
                .revision
                .try_into()
                .map_err(|_| AttendanceProjectionError)?,
            state: self.state,
            observed_at: self.observed_at,
            recorded_at: self.recorded_at,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the stored attendance observation is invalid")]
pub struct AttendanceProjectionError;
