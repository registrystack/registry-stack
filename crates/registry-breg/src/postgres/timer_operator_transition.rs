// SPDX-License-Identifier: Apache-2.0

//! Exact Record-timer operator transitions.

use std::str::FromStr as _;

use crate::timer_operator::{
    RawTimerControlTransition, RawTimerRetryOutcome, TimerControlState, TimerOccurrenceState,
    TimerOperatorError, ValidatedTimerControlChange, ValidatedTimerRetry,
};

use super::{timer, TimerOperatorStore};

const TIMER_CONTROL_ADVISORY_LOCK: &str = "breg/record-timer-control/v1";

impl TimerOperatorStore {
    pub(crate) async fn retry_technical(
        &self,
        request: &ValidatedTimerRetry,
    ) -> Result<RawTimerRetryOutcome, TimerOperatorError> {
        let expected_attempt_count = i32::try_from(request.expected_attempt_count)
            .map_err(|_| TimerOperatorError::OperationRefused)?;
        let mut client = self.client().await?;
        let (guarded, _) = self.begin_write(&mut client).await?;
        let transaction = guarded.transaction();
        crate::mutation::lock_timer_control(transaction)
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let admission = current_admission(transaction).await?;
        if admission.control_state != TimerControlState::Running {
            return Err(TimerOperatorError::RetryIneligible);
        }

        let row = transaction
            .query_opt(
                "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='pending', retry_allowance=1, retry_at=clock_timestamp(),
                        block_kind=NULL, outcome_code=NULL, completed_at=NULL,
                        updated_at=clock_timestamp()
                  WHERE generation.occurrence_id=$1
                    AND generation.executed_attempt_count=$2
                    AND generation.state='blocked'
                    AND generation.block_kind='technical'
                    AND generation.outcome_code='attempts-exhausted'
                    AND generation.retry_allowance=0
                    AND (generation.not_after IS NULL
                         OR clock_timestamp() < generation.not_after)
                    AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_record_timer_current AS current
                          JOIN registry_internal.registry_record_timer_bindings AS binding
                            ON binding.record_type=current.record_type
                           AND binding.timer_id=current.timer_id
                           AND binding.incarnation=current.binding_incarnation
                         WHERE current.occurrence_id=generation.occurrence_id
                           AND current.record_type=generation.record_type
                           AND current.record_id=generation.record_id
                           AND current.timer_id=generation.timer_id
                           AND current.binding_incarnation=generation.binding_incarnation
                           AND current.material_signature=generation.material_signature
                           AND binding.removed_activation_id IS NULL
                           AND binding.definition_revision=generation.definition_revision
                           AND binding.action_revision=generation.action_revision
                           AND binding.system_grant_revision=generation.system_grant_revision
                    )
                RETURNING generation.occurrence_id,generation.state,
                          generation.executed_attempt_count,generation.retry_allowance",
                &[&request.occurrence_id, &expected_attempt_count],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let Some(row) = row else {
            let observed = transaction
                .query_opt(
                    "SELECT executed_attempt_count
                       FROM registry_internal.registry_record_timer_generations
                      WHERE occurrence_id=$1",
                    &[&request.occurrence_id],
                )
                .await
                .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
            return match observed {
                None => Err(TimerOperatorError::OccurrenceNotFound),
                Some(row) if row.get::<_, i32>(0) != expected_attempt_count => {
                    Err(TimerOperatorError::OccurrenceChanged)
                }
                Some(_) => Err(TimerOperatorError::RetryIneligible),
            };
        };
        let outcome = RawTimerRetryOutcome {
            occurrence_id: row.get(0),
            state: TimerOccurrenceState::from_str(row.get(1))?,
            attempt_count: u32::try_from(row.get::<_, i32>(2))
                .map_err(|_| TimerOperatorError::DatabaseUnavailable)?,
            retry_allowance: u8::try_from(row.get::<_, i16>(3))
                .map_err(|_| TimerOperatorError::DatabaseUnavailable)?,
            control_epoch: admission.control_epoch,
        };
        guarded
            .commit()
            .await
            .map_err(|_| TimerOperatorError::OutcomeUnresolved)?;
        Ok(outcome)
    }

    pub(crate) async fn pause(
        &self,
        request: &ValidatedTimerControlChange,
    ) -> Result<RawTimerControlTransition, TimerOperatorError> {
        self.transition_control(request, TimerControlState::Paused)
            .await
    }

    pub(crate) async fn resume(
        &self,
        request: &ValidatedTimerControlChange,
    ) -> Result<RawTimerControlTransition, TimerOperatorError> {
        self.transition_control(request, TimerControlState::Running)
            .await
    }

    async fn transition_control(
        &self,
        request: &ValidatedTimerControlChange,
        target: TimerControlState,
    ) -> Result<RawTimerControlTransition, TimerOperatorError> {
        let mut client = self.client().await?;
        let (guarded, _) = self.begin_write(&mut client).await?;
        let transaction = guarded.transaction();
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock(
                     pg_catalog.hashtextextended($1, 0)
                 )",
                &[&TIMER_CONTROL_ADVISORY_LOCK],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let protocol = timer::read_timer_protocol(transaction)
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        if protocol.protocol_version != timer::SUPPORTED_TIMER_PROTOCOL_VERSION {
            return Err(TimerOperatorError::ProtocolUnsupported);
        }
        if protocol.bound_instance_epoch != protocol.registry_instance_epoch {
            return Err(TimerOperatorError::OperationRefused);
        }
        if protocol.control_epoch != request.expected_control_epoch {
            return Err(TimerOperatorError::ControlEpochMismatch);
        }
        let previous_state = TimerControlState::from_str(&protocol.control_state)?;
        if target == TimerControlState::Paused && previous_state == TimerControlState::AdoptionHold
        {
            return Err(TimerOperatorError::OperationRefused);
        }
        if previous_state == target {
            let outcome = RawTimerControlTransition {
                previous_control_epoch: protocol.control_epoch,
                control_epoch: protocol.control_epoch,
                state: target,
                changed: false,
            };
            guarded
                .commit()
                .await
                .map_err(|_| TimerOperatorError::OutcomeUnresolved)?;
            return Ok(outcome);
        }
        let next_epoch = protocol
            .control_epoch
            .checked_add(1)
            .ok_or(TimerOperatorError::OperationRefused)?;
        let updated = transaction
            .execute(
                "UPDATE registry_internal.registry_record_timer_control
                    SET control_state=$1,control_epoch=$2,updated_at=clock_timestamp()
                  WHERE singleton AND protocol_version=$3 AND control_epoch=$4
                    AND bound_instance_epoch=$5",
                &[
                    &target.as_str(),
                    &next_epoch,
                    &timer::SUPPORTED_TIMER_PROTOCOL_VERSION,
                    &protocol.control_epoch,
                    &protocol.registry_instance_epoch,
                ],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        if updated != 1 {
            return Err(TimerOperatorError::ControlEpochMismatch);
        }
        let outcome = RawTimerControlTransition {
            previous_control_epoch: protocol.control_epoch,
            control_epoch: next_epoch,
            state: target,
            changed: true,
        };
        guarded
            .commit()
            .await
            .map_err(|_| TimerOperatorError::OutcomeUnresolved)?;
        Ok(outcome)
    }
}

async fn current_admission(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<super::timer_operator_store::TimerStoreAdmission, TimerOperatorError> {
    let protocol = timer::read_timer_protocol(transaction)
        .await
        .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
    if protocol.protocol_version != timer::SUPPORTED_TIMER_PROTOCOL_VERSION {
        return Err(TimerOperatorError::ProtocolUnsupported);
    }
    if protocol.bound_instance_epoch != protocol.registry_instance_epoch {
        return Err(TimerOperatorError::OperationRefused);
    }
    Ok(super::timer_operator_store::TimerStoreAdmission {
        protocol_version: u32::try_from(protocol.protocol_version)
            .map_err(|_| TimerOperatorError::ProtocolUnsupported)?,
        control_state: TimerControlState::from_str(&protocol.control_state)?,
        control_epoch: protocol.control_epoch,
        instance_epoch: protocol.registry_instance_epoch,
    })
}
