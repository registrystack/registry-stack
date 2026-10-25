// SPDX-License-Identifier: Apache-2.0

//! Immutable attendance observations, bound to one logical appointment visit.

use registry_scheduling_core::{AttendanceState, LedgerKind, RecordAttendanceRequest};
use serde_json::json;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::attendance::AttendanceObservation;

use super::{
    check_grant_current, replay_stored_attempt, AttemptState, CapacityStatements, ClaimState,
    CommitError, CommitOutcome, Commitment, PostgresStore, ReplayOutcome, StoreError,
};

const ATTENDANCE_WRITER_SETTING: &str = "registry_scheduling.attendance_writer";

impl PostgresStore {
    pub async fn record_attendance(
        &self,
        appointment_id: Uuid,
        request: &RecordAttendanceRequest,
        grant_reference: &str,
        commitment: Commitment<'_>,
    ) -> Result<CommitOutcome, CommitError> {
        let scope = format!("appointment:{appointment_id}:attendance");
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        mark_attendance_writer(&*transaction).await?;

        if let Some(replay) = replay_stored_attempt(&transaction, &commitment, &scope).await? {
            return match replay {
                ReplayOutcome::Replay {
                    status_code,
                    receipt,
                } => Ok(CommitOutcome::Replay {
                    status_code,
                    receipt,
                }),
                ReplayOutcome::Refused(error) => Err(error),
            };
        }
        check_grant_current(&commitment)?;

        let claim = transaction
            .claim_in_transaction(appointment_id)
            .await?
            .filter(|claim| {
                claim.kind == LedgerKind::Booking
                    && matches!(claim.state, ClaimState::Active | ClaimState::Cancelled)
            })
            .ok_or(CommitError::Unauthorized)?;
        let appointment_revision = i64::try_from(request.observed_appointment_revision)
            .map_err(|_| CommitError::RevisionMismatch)?;
        if claim.revision != appointment_revision {
            return Err(CommitError::RevisionMismatch);
        }

        let visit_revision = current_visit_revision(&*transaction, appointment_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        let current = current_for_visit(&*transaction, appointment_id, visit_revision).await?;
        let observed_revision =
            i64::try_from(request.observed_revision).map_err(|_| CommitError::RevisionMismatch)?;
        if current
            .as_ref()
            .map_or(0, |observation| observation.revision)
            != observed_revision
        {
            return Err(CommitError::RevisionMismatch);
        }

        let revision: i64 = transaction
            .query_one(
                "SELECT COALESCE(max(revision), 0) + 1 FROM scheduling_attendance_observations WHERE claim_id=$1",
                &[&appointment_id],
            )
            .await?
            .get(0);
        // Observe the recording decision only after the claim and attendance
        // head are locked and resolved. This is not a claim about the exact
        // database commit instant; it is the single effective timestamp used
        // by the row, history, receipt, and after-event this decision writes.
        let recorded_at = self.observed_now();
        if request.observed_at > recorded_at {
            return Err(CommitError::ObservationInFuture);
        }
        let observation = AttendanceObservation {
            observation_id: Uuid::new_v4(),
            appointment_id,
            visit_revision,
            appointment_revision,
            revision,
            state: request.state,
            observed_at: request.observed_at,
            recorded_at,
        };

        self.recheck_grant(&commitment)?;
        transaction
            .execute(
                "INSERT INTO scheduling_attendance_observations(\
                   observation_id,claim_id,visit_revision,appointment_revision,revision,state,\
                   observed_at,recorded_at,actor,grant_reference) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                &[
                    &observation.observation_id,
                    &observation.appointment_id,
                    &observation.visit_revision,
                    &observation.appointment_revision,
                    &observation.revision,
                    &observation.state.as_str(),
                    &observation.observed_at,
                    &observation.recorded_at,
                    &commitment.actor,
                    &grant_reference,
                ],
            )
            .await?;
        transaction
            .insert_history(
                appointment_id,
                appointment_revision,
                &format!("attendance.{}", observation.state.as_str()),
                recorded_at,
                commitment.actor,
                json!({
                    "attendanceRevision": observation.revision,
                    "state": observation.state,
                    "observedAt": observation.observed_at,
                    "recordedAt": observation.recorded_at,
                }),
            )
            .await?;
        if let Some(hooks) = commitment.hooks {
            hooks
                .capture_attendance(&transaction, &observation, commitment.policy_revision)
                .await?;
        }
        transaction
            .insert_attempt(
                Uuid::new_v4(),
                &commitment,
                &scope,
                AttemptState::Completed,
                200,
                serde_json::to_value(observation.document().map_err(|_| StoreError::Corrupt)?)
                    .map_err(|_| StoreError::Corrupt)?,
            )
            .await?;
        self.commit_capacity(transaction, Some(&commitment)).await?;
        Ok(CommitOutcome::Attendance(observation))
    }

    pub async fn current_attendance(
        &self,
        appointment_id: Uuid,
    ) -> Result<Option<AttendanceObservation>, StoreError> {
        let client = self.client().await?;
        let Some(visit_revision) = current_visit_revision(&**client, appointment_id).await? else {
            return Ok(None);
        };
        current_for_visit(&**client, appointment_id, visit_revision).await
    }
}

pub(super) async fn current_attendance_for_claims(
    client: &impl GenericClient,
    claim_ids: &[Uuid],
) -> Result<Vec<AttendanceObservation>, StoreError> {
    let rows = client
        .query(
            "SELECT DISTINCT ON (a.claim_id) a.observation_id,a.claim_id,a.visit_revision,\
               a.appointment_revision,a.revision,a.state,a.observed_at,a.recorded_at \
             FROM scheduling_attendance_observations a \
             JOIN LATERAL (\
               SELECT revision FROM scheduling_history h WHERE h.claim_id=a.claim_id \
                 AND h.kind IN ('confirmed','rescheduled') ORDER BY revision DESC LIMIT 1\
             ) visit ON visit.revision=a.visit_revision \
             WHERE a.claim_id=ANY($1) ORDER BY a.claim_id,a.revision DESC",
            &[&claim_ids],
        )
        .await?;
    rows.iter().map(observation_from_row).collect()
}

async fn current_visit_revision(
    client: &impl GenericClient,
    appointment_id: Uuid,
) -> Result<Option<i64>, StoreError> {
    Ok(client
        .query_opt(
            "SELECT revision FROM scheduling_history WHERE claim_id=$1 \
             AND kind IN ('confirmed','rescheduled') ORDER BY revision DESC LIMIT 1",
            &[&appointment_id],
        )
        .await?
        .map(|row| row.get(0)))
}

async fn current_for_visit(
    client: &impl GenericClient,
    appointment_id: Uuid,
    visit_revision: i64,
) -> Result<Option<AttendanceObservation>, StoreError> {
    let row = client
        .query_opt(
            "SELECT observation_id,claim_id,visit_revision,appointment_revision,revision,state,\
               observed_at,recorded_at FROM scheduling_attendance_observations \
             WHERE claim_id=$1 AND visit_revision=$2 ORDER BY revision DESC LIMIT 1",
            &[&appointment_id, &visit_revision],
        )
        .await?;
    row.as_ref().map(observation_from_row).transpose()
}

fn observation_from_row(row: &tokio_postgres::Row) -> Result<AttendanceObservation, StoreError> {
    let state = match row.get::<_, String>(5).as_str() {
        "arrived" => AttendanceState::Arrived,
        "completed" => AttendanceState::Completed,
        "no-show" => AttendanceState::NoShow,
        _ => return Err(StoreError::Corrupt),
    };
    Ok(AttendanceObservation {
        observation_id: row.get(0),
        appointment_id: row.get(1),
        visit_revision: row.get(2),
        appointment_revision: row.get(3),
        revision: row.get(4),
        state,
        observed_at: row.get(6),
        recorded_at: row.get(7),
    })
}

async fn mark_attendance_writer(client: &impl GenericClient) -> Result<(), StoreError> {
    client
        .execute(
            "SELECT set_config($1, 'v1', true)",
            &[&ATTENDANCE_WRITER_SETTING],
        )
        .await?;
    Ok(())
}
