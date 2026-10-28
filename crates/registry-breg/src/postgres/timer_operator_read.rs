// SPDX-License-Identifier: Apache-2.0

//! Bounded, value-free Record-timer operator reads.

use std::str::FromStr as _;

use tokio_postgres::Row;
use uuid::Uuid;

use crate::timer_operator::{
    RawTimerAttemptSummary, RawTimerOccurrenceDetail, RawTimerOccurrencePage,
    RawTimerOccurrenceSummary, RawTimerStatus, TimerBlockCounts, TimerBlockKind,
    TimerOccurrenceCounts, TimerOccurrenceState, TimerOperatorError, TimerOutcomeCode,
    TimerTechnicalCode, ValidatedTimerListQuery,
};

use super::timer_operator_store::{TimerOperatorStore, TimerStoreAdmission};

const STATUS_OCCURRENCE_SCAN_MAXIMUM: i64 = 10_000;
const STATUS_OCCURRENCE_SCAN_SENTINEL: i64 = STATUS_OCCURRENCE_SCAN_MAXIMUM + 1;
const SHOW_ATTEMPT_MAXIMUM: i64 = 100;
const SHOW_ATTEMPT_SENTINEL: i64 = SHOW_ATTEMPT_MAXIMUM + 1;

impl TimerOperatorStore {
    pub(crate) async fn status(&self) -> Result<RawTimerStatus, TimerOperatorError> {
        let mut client = self.client().await?;
        let (guarded, admission) = self.begin_read(&mut client).await?;
        let transaction = guarded.transaction();
        let category_samples = transaction
            .query(
                "WITH requested_state(value) AS (
                     VALUES ('pending'),('leased'),('completed'),('refused'),
                            ('blocked'),('cancelled'),('superseded'),('missed')
                 ), state_sample AS (
                     SELECT 'state'::text AS sample_kind,requested.value,
                            count(sample.present)::bigint AS sampled_count
                       FROM requested_state AS requested
                       LEFT JOIN LATERAL (
                           SELECT 1 AS present
                             FROM registry_internal.registry_record_timer_generations AS generation
                            WHERE generation.state=requested.value
                            LIMIT $1
                       ) AS sample ON true
                      GROUP BY requested.value
                 ), requested_block(value) AS (
                     VALUES ('technical'),('configuration')
                 ), block_sample AS (
                     SELECT 'block'::text AS sample_kind,requested.value,
                            count(sample.present)::bigint AS sampled_count
                       FROM requested_block AS requested
                       LEFT JOIN LATERAL (
                           SELECT 1 AS present
                             FROM registry_internal.registry_record_timer_generations AS generation
                            WHERE generation.state='blocked'
                              AND generation.block_kind=requested.value
                            LIMIT $1
                       ) AS sample ON true
                      GROUP BY requested.value
                 )
                 SELECT sample_kind,value,sampled_count FROM state_sample
                 UNION ALL
                 SELECT sample_kind,value,sampled_count FROM block_sample",
                &[&STATUS_OCCURRENCE_SCAN_SENTINEL],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let mut occurrence_counts = TimerOccurrenceCounts::default();
        let mut block_counts = TimerBlockCounts::default();
        let mut counts_truncated = false;
        for row in category_samples {
            let sampled_count = row.get::<_, i64>("sampled_count");
            counts_truncated |= sampled_count > STATUS_OCCURRENCE_SCAN_MAXIMUM;
            let bounded_count = u64::try_from(sampled_count.min(STATUS_OCCURRENCE_SCAN_MAXIMUM))
                .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
            match row.get::<_, &str>("sample_kind") {
                "state" => add_state_count(
                    &mut occurrence_counts,
                    parse_state(row.get("value"))?,
                    bounded_count,
                ),
                "block" => add_block_count(
                    &mut block_counts,
                    TimerBlockKind::from_str(row.get("value"))
                        .map_err(|_| TimerOperatorError::DatabaseUnavailable)?,
                    bounded_count,
                ),
                _ => return Err(TimerOperatorError::DatabaseUnavailable),
            }
        }
        let stale_revision_count = transaction
            .query_one(
                "WITH requested_state(value) AS (
                     VALUES ('pending'),('leased'),('blocked')
                 ), sampled AS (
                     SELECT generation.*
                       FROM requested_state AS requested
                       JOIN LATERAL (
                           SELECT generation.*
                             FROM registry_internal.registry_record_timer_generations AS generation
                            WHERE generation.state=requested.value
                            LIMIT $1
                       ) AS generation ON true
                 )
                 SELECT count(*) FILTER (
                            WHERE current.occurrence_id IS NOT NULL
                              AND (
                                  binding.definition_revision IS NULL
                                  OR binding.incarnation<>generation.binding_incarnation
                                  OR binding.definition_revision<>generation.definition_revision
                                  OR binding.action_revision<>generation.action_revision
                                  OR binding.system_grant_revision<>generation.system_grant_revision
                              )
                        )::bigint AS stale_revision_count
                   FROM sampled AS generation
                   LEFT JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                   LEFT JOIN registry_internal.registry_record_timer_bindings AS binding
                     ON binding.record_type=generation.record_type
                    AND binding.timer_id=generation.timer_id
                    AND binding.removed_activation_id IS NULL",
                &[&STATUS_OCCURRENCE_SCAN_MAXIMUM],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?
            .get::<_, i64>("stale_revision_count");
        let stale_revision_count = u64::try_from(stale_revision_count)
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let observed_lease_owner_count = transaction
            .query_one(
                "SELECT count(*)::bigint AS sampled_count,
                        count(DISTINCT claim_owner_id)::bigint AS owner_count
                   FROM (
                       SELECT generation.claim_owner_id
                         FROM registry_internal.registry_record_timer_generations AS generation
                         JOIN registry_internal.registry_record_timer_current AS current
                           ON current.occurrence_id=generation.occurrence_id
                          AND current.record_type=generation.record_type
                          AND current.record_id=generation.record_id
                          AND current.timer_id=generation.timer_id
                          AND current.binding_incarnation=generation.binding_incarnation
                          AND current.material_signature=generation.material_signature
                        WHERE generation.state='leased'
                          AND generation.claim_until > clock_timestamp()
                        ORDER BY generation.claim_until ASC,
                                 generation.claim_owner_id ASC,
                                 generation.occurrence_id ASC
                        LIMIT $1
                   ) AS sampled_leases",
                &[&STATUS_OCCURRENCE_SCAN_SENTINEL],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let sampled_lease_count = observed_lease_owner_count.get::<_, i64>("sampled_count");
        let observed_lease_owner_count = observed_lease_owner_count.get::<_, i64>("owner_count");
        counts_truncated |= sampled_lease_count > STATUS_OCCURRENCE_SCAN_MAXIMUM;
        let observed_lease_owner_count =
            u32::try_from(observed_lease_owner_count.min(STATUS_OCCURRENCE_SCAN_MAXIMUM))
                .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let oldest_due_lag_seconds = transaction
            .query_opt(
                "SELECT greatest(
                            0,
                            floor(extract(epoch FROM (clock_timestamp()-generation.due_at)))::bigint
                        ) AS lag_seconds
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                  WHERE generation.state IN ('pending','leased')
                    AND generation.gate_open
                    AND generation.due_at <= clock_timestamp()
                  ORDER BY generation.due_at ASC,generation.occurrence_id ASC
                  LIMIT 1",
                &[],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?
            .map(|row| row.get::<_, i64>("lag_seconds"))
            .map(u64::try_from)
            .transpose()
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let status = RawTimerStatus {
            protocol_version: admission.protocol_version,
            control_state: admission.control_state,
            control_epoch: admission.control_epoch,
            instance_epoch: admission.instance_epoch,
            observed_lease_owner_count,
            occurrence_counts,
            block_counts,
            stale_revision_count,
            oldest_due_lag_seconds,
            limits: self.limits(),
            counts_truncated,
        };
        guarded
            .commit()
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        Ok(status)
    }

    pub(crate) async fn list(
        &self,
        query: &ValidatedTimerListQuery,
    ) -> Result<RawTimerOccurrencePage, TimerOperatorError> {
        if query.limit == 0 || query.limit > self.limits().operator_list_maximum {
            return Err(TimerOperatorError::OperationRefused);
        }
        let mut client = self.client().await?;
        let (guarded, admission) = self.begin_read(&mut client).await?;
        let state = query.state.map(|state| state.as_str());
        let after_created_at = query.after.as_ref().map(|cursor| cursor.created_at());
        let after_occurrence_id = query.after.as_ref().map(|cursor| cursor.occurrence_id());
        let limit = i64::from(query.limit) + 1;
        let rows = guarded
            .transaction()
            .query(
                &format!(
                    "{} WHERE ($1::text IS NULL OR generation.state=$1)
                         AND ($2::text IS NULL OR generation.record_type=$2)
                         AND ($3::text IS NULL OR generation.timer_id=$3)
                         AND ($4::timestamptz IS NULL OR (generation.created_at,generation.occurrence_id) > ($4,$5))
                       ORDER BY generation.created_at ASC,generation.occurrence_id ASC
                       LIMIT $6",
                    summary_select_sql()
                ),
                &[
                    &state,
                    &query.record_type,
                    &query.timer,
                    &after_created_at,
                    &after_occurrence_id,
                    &limit,
                ],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let maximum = usize::from(query.limit);
        let has_next = rows.len() > maximum;
        let mut occurrences = rows
            .iter()
            .take(maximum)
            .map(|row| raw_summary(row, admission))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = has_next.then(|| occurrences.last()).flatten().map(|last| {
            crate::timer_operator::TimerListCursor::new(last.created_at, last.occurrence_id)
        });
        let page = RawTimerOccurrencePage {
            occurrences: std::mem::take(&mut occurrences),
            next_cursor,
        };
        guarded
            .commit()
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        Ok(page)
    }

    pub(crate) async fn show(
        &self,
        occurrence_id: Uuid,
    ) -> Result<Option<RawTimerOccurrenceDetail>, TimerOperatorError> {
        let mut client = self.client().await?;
        let (guarded, admission) = self.begin_read(&mut client).await?;
        let Some(row) = guarded
            .transaction()
            .query_opt(
                &format!(
                    "SELECT {},
                            generation.action_revision,
                            generation.created_activation_id,
                            generation.current_policy_activation_id,
                            generation.executed_activation_id,
                            coalesce(generation.claimed_control_epoch,latest.control_epoch) AS detail_control_epoch,
                            coalesce(generation.claimed_instance_epoch,latest.instance_epoch) AS detail_instance_epoch,
                            nullif(generation.claim_epoch,0) AS detail_claim_epoch,
                            generation.receipt_correlation
                       FROM ({}) AS generation
                       LEFT JOIN registry_internal.registry_record_timer_current AS current
                         ON current.occurrence_id=generation.occurrence_id
                        AND current.record_type=generation.record_type
                        AND current.record_id=generation.record_id
                        AND current.timer_id=generation.timer_id
                        AND current.binding_incarnation=generation.binding_incarnation
                        AND current.material_signature=generation.material_signature
                       LEFT JOIN registry_internal.registry_record_timer_bindings AS binding
                         ON binding.record_type=generation.record_type
                        AND binding.timer_id=generation.timer_id
                        AND binding.removed_activation_id IS NULL
                       LEFT JOIN LATERAL (
                           SELECT attempt.control_epoch,attempt.instance_epoch
                             FROM registry_internal.registry_record_timer_attempts AS attempt
                            WHERE attempt.occurrence_id=generation.occurrence_id
                            ORDER BY attempt.attempt_number DESC
                            LIMIT 1
                       ) AS latest ON true
                      WHERE generation.occurrence_id=$1",
                    summary_select_columns(), generation_source_sql()
                ),
                &[&occurrence_id],
            )
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?
        else {
            guarded
                .commit()
                .await
                .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
            return Ok(None);
        };
        let summary = raw_summary(&row, admission)?;
        let attempt_rows = if summary.detail_available {
            guarded
                .transaction()
                .query(
                    "SELECT attempt_number,started_at,finished_at,block_kind,outcome_code,
                            technical_code
                       FROM registry_internal.registry_record_timer_attempts
                      WHERE occurrence_id=$1
                      ORDER BY attempt_number DESC
                      LIMIT $2",
                    &[&occurrence_id, &SHOW_ATTEMPT_SENTINEL],
                )
                .await
                .map_err(|_| TimerOperatorError::DatabaseUnavailable)?
        } else {
            Vec::new()
        };
        let attempts_paginated = attempt_rows.len()
            > usize::try_from(SHOW_ATTEMPT_MAXIMUM)
                .map_err(|_| TimerOperatorError::OperationRefused)?;
        let mut attempts = attempt_rows
            .iter()
            .take(
                usize::try_from(SHOW_ATTEMPT_MAXIMUM)
                    .map_err(|_| TimerOperatorError::OperationRefused)?,
            )
            .map(raw_attempt)
            .collect::<Result<Vec<_>, _>>()?;
        attempts.reverse();
        let attempts_truncated =
            attempt_history_is_truncated(summary.attempt_count, attempts.len(), attempts_paginated);
        let detail = RawTimerOccurrenceDetail {
            summary,
            action_revision: row.get("action_revision"),
            created_activation_id: row.get("created_activation_id"),
            current_policy_activation_id: row.get("current_policy_activation_id"),
            executed_activation_id: row.get("executed_activation_id"),
            control_epoch: row.get("detail_control_epoch"),
            instance_epoch: row.get("detail_instance_epoch"),
            claim_epoch: row.get("detail_claim_epoch"),
            receipt_correlation: row.get("receipt_correlation"),
            attempts,
            attempts_truncated,
        };
        guarded
            .commit()
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        Ok(Some(detail))
    }
}

fn generation_source_sql() -> &'static str {
    "SELECT * FROM registry_internal.registry_record_timer_generations"
}

fn summary_select_sql() -> String {
    format!(
        "SELECT {} FROM ({}) AS generation
         LEFT JOIN registry_internal.registry_record_timer_current AS current
           ON current.occurrence_id=generation.occurrence_id
          AND current.record_type=generation.record_type
          AND current.record_id=generation.record_id
          AND current.timer_id=generation.timer_id
          AND current.binding_incarnation=generation.binding_incarnation
          AND current.material_signature=generation.material_signature
         LEFT JOIN registry_internal.registry_record_timer_bindings AS binding
           ON binding.record_type=generation.record_type
          AND binding.timer_id=generation.timer_id
          AND binding.removed_activation_id IS NULL",
        summary_select_columns(),
        generation_source_sql()
    )
}

fn summary_select_columns() -> &'static str {
    "generation.occurrence_id,
     generation.record_type,
     generation.timer_id,
     generation.record_id,
     generation.state,
     generation.definition_revision,
     generation.executed_attempt_count,
     generation.due_at,
     generation.not_after,
     generation.created_at,
     generation.updated_at,
     generation.completed_at,
     generation.block_kind,
     generation.outcome_code,
     generation.detail_expires_at,
     generation.detail_expires_at IS NULL OR generation.detail_expires_at > clock_timestamp()
         AS detail_available,
     COALESCE(generation.state='blocked'
         AND generation.block_kind='technical'
         AND generation.outcome_code='attempts-exhausted'
         AND generation.retry_allowance=0
         AND (generation.not_after IS NULL OR clock_timestamp() < generation.not_after)
         AND current.occurrence_id IS NOT NULL
         AND current.binding_incarnation=generation.binding_incarnation
         AND binding.incarnation=generation.binding_incarnation
         AND binding.definition_revision=generation.definition_revision
         AND binding.action_revision=generation.action_revision
         AND binding.system_grant_revision=generation.system_grant_revision,
         false) AS retry_eligible"
}

fn raw_summary(
    row: &Row,
    admission: TimerStoreAdmission,
) -> Result<RawTimerOccurrenceSummary, TimerOperatorError> {
    let attempt_count = u32::try_from(row.get::<_, i32>("executed_attempt_count"))
        .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
    Ok(RawTimerOccurrenceSummary {
        occurrence_id: row.get("occurrence_id"),
        record_type: row.get("record_type"),
        timer: row.get("timer_id"),
        record_id: row.get("record_id"),
        state: parse_state(row.get("state"))?,
        timer_revision: row.get("definition_revision"),
        attempt_count,
        retry_eligible: admission.control_state
            == crate::timer_operator::TimerControlState::Running
            && row.get::<_, bool>("retry_eligible"),
        due_at: row.get("due_at"),
        not_after: row.get("not_after"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        completed_at: row.get("completed_at"),
        block_kind: parse_optional_block_kind(row.get("block_kind"))?,
        outcome_code: parse_optional_outcome(row.get("outcome_code"))?,
        detail_available: row.get("detail_available"),
        detail_expires_at: row.get("detail_expires_at"),
    })
}

fn raw_attempt(row: &Row) -> Result<RawTimerAttemptSummary, TimerOperatorError> {
    Ok(RawTimerAttemptSummary {
        attempt: u32::try_from(row.get::<_, i32>("attempt_number"))
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?,
        started_at: row.get("started_at"),
        finished_at: row.get("finished_at"),
        block_kind: parse_optional_block_kind(row.get("block_kind"))?,
        outcome_code: parse_optional_outcome(row.get("outcome_code"))?,
        technical_code: parse_optional_technical_code(row.get("technical_code"))?,
    })
}

fn parse_state(value: &str) -> Result<TimerOccurrenceState, TimerOperatorError> {
    TimerOccurrenceState::from_str(value).map_err(|_| TimerOperatorError::DatabaseUnavailable)
}

fn parse_optional_block_kind(
    value: Option<&str>,
) -> Result<Option<TimerBlockKind>, TimerOperatorError> {
    value
        .map(TimerBlockKind::from_str)
        .transpose()
        .map_err(|_| TimerOperatorError::DatabaseUnavailable)
}

fn parse_optional_outcome(
    value: Option<&str>,
) -> Result<Option<TimerOutcomeCode>, TimerOperatorError> {
    value
        .map(TimerOutcomeCode::from_str)
        .transpose()
        .map_err(|_| TimerOperatorError::DatabaseUnavailable)
}

fn parse_optional_technical_code(
    value: Option<&str>,
) -> Result<Option<TimerTechnicalCode>, TimerOperatorError> {
    value
        .map(TimerTechnicalCode::from_str)
        .transpose()
        .map_err(|_| TimerOperatorError::DatabaseUnavailable)
}

fn attempt_history_is_truncated(
    executed_attempt_count: u32,
    retained_attempt_count: usize,
    paginated: bool,
) -> bool {
    paginated || u64::from(executed_attempt_count) > retained_attempt_count as u64
}

fn add_state_count(counts: &mut TimerOccurrenceCounts, state: TimerOccurrenceState, amount: u64) {
    let count = match state {
        TimerOccurrenceState::Pending => &mut counts.pending,
        TimerOccurrenceState::Leased => &mut counts.leased,
        TimerOccurrenceState::Completed => &mut counts.completed,
        TimerOccurrenceState::Refused => &mut counts.refused,
        TimerOccurrenceState::Blocked => &mut counts.blocked,
        TimerOccurrenceState::Cancelled => &mut counts.cancelled,
        TimerOccurrenceState::Superseded => &mut counts.superseded,
        TimerOccurrenceState::Missed => &mut counts.missed,
    };
    *count = count.saturating_add(amount);
}

fn add_block_count(counts: &mut TimerBlockCounts, kind: TimerBlockKind, amount: u64) {
    let count = match kind {
        TimerBlockKind::Technical => &mut counts.technical,
        TimerBlockKind::Configuration => &mut counts.configuration,
    };
    *count = count.saturating_add(amount);
}

#[cfg(test)]
mod tests {
    use super::attempt_history_is_truncated;

    #[test]
    fn pruned_or_paginated_attempt_history_is_reported_as_truncated() {
        assert!(!attempt_history_is_truncated(2, 2, false));
        assert!(attempt_history_is_truncated(2, 1, false));
        assert!(attempt_history_is_truncated(2, 0, false));
        assert!(attempt_history_is_truncated(100, 100, true));
    }
}
