//! Bounded review clocks and retention over the pinned review model.
use super::*;
impl CaseworkService {
    pub async fn process_due_review_clocks(
        &self,
        maximum: usize,
    ) -> Result<usize, ReviewRuntimeError> {
        if !self.store.audit_ready().await {
            return Err(StoreError::AuditUnavailable.into());
        }
        let candidates = self.store.due_review_clock_tasks(maximum).await?;
        let mut verified = Vec::new();
        for task_id in candidates {
            let record = self.store.review_request_for_task(task_id).await?;
            let current = match &record.policy.context {
                ReviewContextPolicy::Submitted => true,
                ReviewContextPolicy::CurrentSource { provider, contract } => {
                    let identity = ReviewContextIdentity {
                        subject: record.subject.clone(),
                        contract: contract.clone(),
                    };
                    match self.providers.get(provider) {
                        Some(provider) => tokio::time::timeout(
                            Duration::from_millis(
                                record.policy.dependencies.inbox.page_deadline_milliseconds,
                            ),
                            provider.service_status(&identity),
                        )
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .is_some_and(|o| o.identity == identity && o.reviewable),
                        None => false,
                    }
                }
            };
            if current {
                verified.push(task_id)
            } else {
                self.store.defer_review_clock_task(task_id).await?;
            }
        }
        self.store
            .process_due_review_clocks(maximum, &verified)
            .await
    }
}
impl PostgresStore {
    pub(super) async fn due_review_clock_tasks(
        &self,
        maximum: usize,
    ) -> Result<Vec<Uuid>, ReviewRuntimeError> {
        let limit =
            i64::try_from(maximum.clamp(1, 100)).map_err(|_| ReviewRuntimeError::Invalid)?;
        let client = self.client().await?;
        Ok(client
            .query(
                "SELECT task_id
                   FROM casework_review_clock_occurrences
                  WHERE scope='activity' AND task_id IS NOT NULL
                    AND ((state='source-facts-missing'
                          AND (next_action_at IS NULL OR next_action_at<=now()))
                         OR (state='running' AND next_action_at<=now()))
                  GROUP BY task_id
                  ORDER BY min(COALESCE(next_action_at,updated_at)),task_id
                  LIMIT $1",
                &[&limit],
            )
            .await?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }
    pub(super) async fn defer_review_clock_task(
        &self,
        task_id: Uuid,
    ) -> Result<(), ReviewRuntimeError> {
        let mut audit = self.begin_background_audit().await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE casework_review_clock_occurrences
                    SET next_action_at=transaction_timestamp()+interval '30 seconds',
                        updated_at=transaction_timestamp()
                  WHERE task_id=$1 AND scope='activity'
                    AND ((state='source-facts-missing'
                          AND (next_action_at IS NULL OR next_action_at<=now()))
                         OR (state='running' AND next_action_at<=now()))",
                &[&task_id],
            )
            .await?;
        if changed > 0 {
            record_maintenance(
                &mut audit,
                Uuid::new_v4(),
                "review-clock-deferred",
                "system:clocks",
                None,
                Some(task_id),
                None,
            )?;
        }
        audit.commit(transaction).await?;
        Ok(())
    }
    pub(super) async fn process_due_review_clocks(
        &self,
        maximum: usize,
        verified_tasks: &[Uuid],
    ) -> Result<usize, ReviewRuntimeError> {
        if verified_tasks.is_empty() {
            return Ok(0);
        }
        let limit =
            i64::try_from(maximum.clamp(1, 100)).map_err(|_| ReviewRuntimeError::Invalid)?;
        let mut audit = self.begin_background_audit().await?;
        let now = Utc::now();
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let rows = transaction
            .query(
                "SELECT clock_occurrence_id,request_id,task_id
                 FROM casework_review_clock_occurrences
                 WHERE scope='activity'
                   AND task_id=ANY($2)
                   AND ((state='source-facts-missing'
                        AND (next_action_at IS NULL OR next_action_at<=$3))
                        OR (state='running' AND next_action_at<=now()))
                 ORDER BY COALESCE(next_action_at,updated_at),clock_occurrence_id
                 LIMIT $1",
                &[&limit, &verified_tasks, &now],
            )
            .await?;
        let mut applied = 0usize;
        'occurrences: for row in rows {
            let occurrence_id: Uuid = row.get(0);
            let request_id: Uuid = row
                .get::<_, Option<Uuid>>(1)
                .ok_or(ReviewRuntimeError::Corrupt)?;
            let task_id: Uuid = row
                .get::<_, Option<Uuid>>(2)
                .ok_or(ReviewRuntimeError::Corrupt)?;
            let Some(request) = transaction
                .query_opt(
                    "SELECT lifecycle,active_stage_index
                     FROM casework_review_requests WHERE request_id=$1
                     FOR UPDATE SKIP LOCKED",
                    &[&request_id],
                )
                .await?
            else {
                continue;
            };
            let task = transaction
                .query_opt(
                    "SELECT state,queue_id,stage_index
                     FROM casework_review_tasks WHERE task_id=$1 AND request_id=$2
                     FOR UPDATE",
                    &[&task_id, &request_id],
                )
                .await?
                .ok_or(ReviewRuntimeError::Corrupt)?;
            let Some(occurrence) = transaction
                .query_opt(
                    "SELECT policy,state,anchor_at,holiday_document,reminders,steps
                     FROM casework_review_clock_occurrences
                     WHERE clock_occurrence_id=$1 AND scope='activity'
                       AND ((state='source-facts-missing'
                            AND (next_action_at IS NULL OR next_action_at<=$2))
                            OR (state='running' AND next_action_at<=$2))
                     FOR UPDATE",
                    &[&occurrence_id, &now],
                )
                .await?
            else {
                continue;
            };
            let applied_before = applied;
            let definition: ReviewClockDefinition = serde_json::from_value(occurrence.get(0))?;
            let state: String = occurrence.get(1);
            let anchor_at: DateTime<Utc> = occurrence.get(2);
            let (_holiday_document, reminders, steps): (
                HolidaySetDocument,
                Vec<ReminderOccurrence>,
                Vec<StepOccurrence>,
            ) = if state == "source-facts-missing" {
                let calendar = definition
                    .calendar
                    .as_ref()
                    .ok_or(ReviewRuntimeError::Corrupt)?;
                let Some(holiday_row) = transaction
                    .query_opt(
                        "SELECT document FROM casework_holiday_sets
                         WHERE holiday_set=$1 ORDER BY revision DESC LIMIT 1",
                        &[&calendar.holiday_set],
                    )
                    .await?
                else {
                    transaction
                        .execute(
                            "UPDATE casework_review_clock_occurrences
                             SET next_action_at=$2::timestamptz+interval '30 seconds',updated_at=$2
                             WHERE clock_occurrence_id=$1 AND state='source-facts-missing'",
                            &[&occurrence_id, &now],
                        )
                        .await?;
                    record_maintenance(
                        &mut audit,
                        Uuid::new_v4(),
                        "review-clock-deferred",
                        "system:clocks",
                        Some(request_id),
                        Some(task_id),
                        None,
                    )?;
                    continue;
                };
                let holiday: HolidaySetDocument = serde_json::from_value(holiday_row.get(0))?;
                let evaluated =
                    evaluate_activity_clock(&definition.clock, calendar, &holiday, anchor_at)
                        .map_err(|error| clock_evaluation_error(&definition.clock, error))?;
                let next_action_at = next_review_clock_action(
                    &evaluated.reminders,
                    &evaluated.steps,
                    &std::collections::BTreeSet::new(),
                );
                transaction
                    .execute(
                        "UPDATE casework_review_clock_occurrences
                         SET state='running',holiday_document=$2,reminders=$3,steps=$4,
                             due_at=$5,at_risk_at=$6,next_action_at=$7,updated_at=$8
                         WHERE clock_occurrence_id=$1 AND state='source-facts-missing'",
                        &[
                            &occurrence_id,
                            &serde_json::to_value(&holiday)?,
                            &serde_json::to_value(&evaluated.reminders)?,
                            &serde_json::to_value(&evaluated.steps)?,
                            &evaluated.due_at,
                            &evaluated.at_risk_at,
                            &next_action_at,
                            &now,
                        ],
                    )
                    .await?;
                refresh_review_deadlines(&transaction, request_id).await?;
                record_maintenance(
                    &mut audit,
                    Uuid::new_v4(),
                    "review-clock-scheduled",
                    "system:clocks",
                    Some(request_id),
                    Some(task_id),
                    None,
                )?;
                (holiday, evaluated.reminders, evaluated.steps)
            } else {
                let holiday = occurrence
                    .get::<_, Option<Value>>(3)
                    .map(serde_json::from_value)
                    .transpose()?
                    .ok_or(ReviewRuntimeError::Corrupt)?;
                let reminders = serde_json::from_value(occurrence.get(4))?;
                let steps = serde_json::from_value(occurrence.get(5))?;
                (holiday, reminders, steps)
            };
            let task_state: String = task.get(0);
            let current_stage: Option<i32> = request.get(1);
            if request.get::<_, String>(0) != "reviewing"
                || !matches!(task_state.as_str(), "open" | "claimed")
                || current_stage != Some(task.get::<_, i32>(2))
            {
                transaction
                    .execute(
                        "UPDATE casework_review_clock_occurrences
                         SET state='completed',completed_at=$2,next_action_at=NULL,updated_at=$2
                         WHERE clock_occurrence_id=$1 AND state='running'",
                        &[&occurrence_id, &now],
                    )
                    .await?;
                record_maintenance(
                    &mut audit,
                    Uuid::new_v4(),
                    "review-clock-completed",
                    "system:clocks",
                    Some(request_id),
                    Some(task_id),
                    None,
                )?;
                continue;
            }

            for reminder in reminders.iter().filter(|effect| effect.at <= now) {
                let event_id = Uuid::new_v4();
                if transaction
                    .execute(
                        "INSERT INTO casework_review_clock_effects(
                            clock_occurrence_id,effect_kind,effect_id,event_id,applied_at)
                         VALUES($1,'reminder',$2,$3,$4) ON CONFLICT DO NOTHING",
                        &[&occurrence_id, &reminder.id, &event_id, &now],
                    )
                    .await?
                    == 1
                {
                    transaction
                        .execute(
                            "INSERT INTO casework_review_history(
                                event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                             VALUES($1,$2,$3,'clock-reminder',NULL,$4,$5)",
                            &[
                                &event_id,
                                &request_id,
                                &task_id,
                                &json!({
                                    "clockOccurrenceId": occurrence_id,
                                    "clockId": definition.clock.id(),
                                    "effectId": reminder.id,
                                    "at": reminder.at,
                                }),
                                &now,
                            ],
                        )
                        .await?;
                    record_maintenance(
                        &mut audit,
                        event_id,
                        "review-clock-reminder",
                        "system:clocks",
                        Some(request_id),
                        Some(task_id),
                        None,
                    )?;
                    applied += 1;
                }
            }
            let applied_steps = transaction
                .query(
                    "SELECT effect_id FROM casework_review_clock_effects
                     WHERE clock_occurrence_id=$1 AND effect_kind='step'",
                    &[&occurrence_id],
                )
                .await?
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect::<std::collections::BTreeSet<_>>();
            let mut prior_queue: String = task.get(1);
            for step in steps.iter().filter(|effect| effect.at <= now) {
                // Completed steps keep their original effect even if their
                // former queue loses service before a later escalation.
                if applied_steps.contains(&step.id) {
                    continue;
                }
                // A reassignment no team serves would drop the task out of
                // every review inbox and record the effect as applied with
                // no retry left, so the occurrence defers until the queue is
                // served again instead of applying the step.
                let served: bool = transaction
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM casework_queue_service WHERE queue_id=$1)",
                        &[&step.reassign_queue],
                    )
                    .await?
                    .get(0);
                if !served {
                    transaction
                        .execute(
                            "UPDATE casework_review_clock_occurrences
                             SET next_action_at=$2::timestamptz+interval '30 seconds',updated_at=$2
                             WHERE clock_occurrence_id=$1 AND state='running'",
                            &[&occurrence_id, &now],
                        )
                        .await?;
                    record_maintenance(
                        &mut audit,
                        Uuid::new_v4(),
                        "review-clock-deferred",
                        "system:clocks",
                        Some(request_id),
                        Some(task_id),
                        None,
                    )?;
                    continue 'occurrences;
                }
                let event_id = Uuid::new_v4();
                if transaction
                    .execute(
                        "INSERT INTO casework_review_clock_effects(
                            clock_occurrence_id,effect_kind,effect_id,event_id,applied_at)
                         VALUES($1,'step',$2,$3,$4) ON CONFLICT DO NOTHING",
                        &[&occurrence_id, &step.id, &event_id, &now],
                    )
                    .await?
                    == 1
                {
                    transaction
                        .execute(
                            "UPDATE casework_review_tasks
                             SET queue_id=$2,state='open',holder_issuer=NULL,holder_subject=NULL,
                                 assignment_kind=NULL,assignment_owner_issuer=NULL,
                                 assignment_owner_subject=NULL,assigned_by_issuer=NULL,
                                 assigned_by_subject=NULL,assignment_absence_ids='{}',
                                 staffing_diagnostic=NULL,revision=revision+1,updated_at=$3
                             WHERE task_id=$1 AND state IN ('open','claimed')",
                            &[&task_id, &step.reassign_queue, &now],
                        )
                        .await?;
                    transaction
                        .execute(
                            "INSERT INTO casework_review_history(
                                event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                             VALUES($1,$2,$3,'clock-step-applied',NULL,$4,$5)",
                            &[
                                &event_id,
                                &request_id,
                                &task_id,
                                &json!({
                                    "clockOccurrenceId": occurrence_id,
                                    "clockId": definition.clock.id(),
                                    "effectId": step.id,
                                    "because": step.because,
                                    "previousQueue": prior_queue,
                                    "queue": step.reassign_queue,
                                }),
                                &now,
                            ],
                        )
                        .await?;
                    record_maintenance(
                        &mut audit,
                        event_id,
                        "review-clock-step-applied",
                        "system:clocks",
                        Some(request_id),
                        Some(task_id),
                        Some(&step.reassign_queue),
                    )?;
                    prior_queue.clone_from(&step.reassign_queue);
                    applied += 1;
                }
            }
            let effect_rows = transaction
                .query(
                    "SELECT effect_kind,effect_id FROM casework_review_clock_effects
                     WHERE clock_occurrence_id=$1",
                    &[&occurrence_id],
                )
                .await?;
            let completed = effect_rows
                .into_iter()
                .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
                .collect::<std::collections::BTreeSet<_>>();
            let next_action_at = next_review_clock_action(&reminders, &steps, &completed);
            let advanced=transaction
                .execute(
                    "UPDATE casework_review_clock_occurrences
                     SET next_action_at=$2,updated_at=$3
                     WHERE clock_occurrence_id=$1 AND state='running' AND next_action_at IS DISTINCT FROM $2",
                    &[&occurrence_id, &next_action_at, &now],
                )
                .await?;
            if advanced > 0 && applied == applied_before {
                record_maintenance(
                    &mut audit,
                    Uuid::new_v4(),
                    "review-clock-rescheduled",
                    "system:clocks",
                    Some(request_id),
                    Some(task_id),
                    None,
                )?;
            }
        }
        audit.commit(transaction).await?;
        Ok(applied)
    }
    pub(super) async fn erase_expired_reviews_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, ReviewRuntimeError> {
        let mut audit = self.begin_background_audit().await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let selected_rows = transaction
            .query(
                "SELECT request_id,producer_id,producer_issuer,producer_subject,result_erased_at,
                        initiator_issuer,initiator_subject
                   FROM casework_review_requests r
                 WHERE (result_available_until<=$1 AND (
                           result_erased_at IS NULL OR EXISTS(
                               SELECT 1 FROM casework_review_tasks t
                               WHERE t.request_id=r.request_id
                           ) OR EXISTS(
                               SELECT 1 FROM casework_review_clock_occurrences c
                               WHERE c.request_id=r.request_id
                           )
                       ))
                    OR (lifecycle<>'reviewing' AND accountability_retained_until<=$1)
                 ORDER BY request_id LIMIT $2 FOR UPDATE SKIP LOCKED",
                &[&now, &REVIEW_RETENTION_BATCH_SIZE],
            )
            .await?;
        let selected = selected_rows
            .iter()
            .map(|row| row.get::<_, Uuid>(0))
            .collect::<Vec<_>>();
        transaction
            .execute(
                "DELETE FROM casework_review_accountability
                 WHERE request_id=ANY($2) AND retained_until<=$1",
                &[&now, &selected],
            )
            .await?;
        for row in &selected_rows {
            if row.get::<_, Option<DateTime<Utc>>>(4).is_none() {
                let request_id = row.get::<_, Uuid>(0);
                let producer_tombstone = review_producer_tombstone(
                    request_id,
                    &row.get::<_, String>(1),
                    &row.get::<_, String>(2),
                    &row.get::<_, String>(3),
                );
                // The initiator keeps only a tombstone of their identity, so
                // they alone can still learn that the result expired.
                let initiator_tombstone = match (
                    row.get::<_, Option<String>>(5),
                    row.get::<_, Option<String>>(6),
                ) {
                    (Some(issuer), Some(subject)) => {
                        Some(review_initiator_tombstone(request_id, &issuer, &subject))
                    }
                    _ => None,
                };
                transaction
                    .execute(
                        "UPDATE casework_review_requests
                            SET producer_issuer=$2,producer_subject=$2,
                                initiator_issuer=$3,initiator_subject=$3
                          WHERE request_id=$1 AND result_erased_at IS NULL",
                        &[&request_id, &producer_tombstone, &initiator_tombstone],
                    )
                    .await?;
            }
        }
        transaction
            .execute(
                "DELETE FROM casework_review_completion_outbox
                 WHERE request_id=ANY($2) AND retained_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_review_terminal_events
                 WHERE request_id=ANY($2) AND retained_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_review_results
                 WHERE request_id=ANY($2) AND available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_review_decisions d USING casework_review_requests r
                 WHERE d.request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_idempotency i SET response=NULL
                  FROM casework_review_requests r
                 WHERE i.review_request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.result_available_until<=$1 AND i.response IS NOT NULL",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_review_requests
                 SET source_namespace=submission_digest,subject_source=submission_digest,
                     subject_type=submission_digest,subject_id=submission_digest,
                     subject_version=submission_digest,subject_digest=submission_digest,
                     requester_reference=submission_digest,context='{}'::jsonb,
                     result_constraints=NULL,
                     completion_destination=NULL,completion_recipient_binding=NULL
                 WHERE request_id=ANY($2) AND result_available_until<=$1
                   AND result_erased_at IS NULL",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_review_submission_reservations s
                 SET source_namespace=s.submission_digest,subject_source=s.submission_digest,
                     subject_type=s.submission_digest,subject_id=s.submission_digest,
                     subject_version=s.submission_digest
                 FROM casework_review_requests r
                 WHERE s.request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_review_task_drafts d
                  USING casework_review_tasks t,casework_review_requests r
                 WHERE d.task_id=t.task_id AND t.request_id=r.request_id
                   AND r.request_id=ANY($2) AND r.result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_review_history h USING casework_review_requests r
                 WHERE h.request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_review_cursors c
                 USING casework_review_tasks t,casework_review_requests r
                 WHERE c.last_task_id=t.task_id AND t.request_id=r.request_id
                   AND r.request_id=ANY($2) AND r.result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_review_tasks t USING casework_review_requests r
                 WHERE t.request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_review_requests
                 SET result_erased_at=COALESCE(result_erased_at,$1)
                 WHERE request_id=ANY($2) AND result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        // Each request owns its clock budget; erasure follows that request's
        // terminal retention independently of any successor request.
        transaction
            .execute(
                "DELETE FROM casework_review_clock_occurrences c USING casework_review_requests r
                 WHERE c.request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_idempotency i USING casework_review_requests r
                 WHERE i.review_request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.accountability_retained_until<=$1",
                &[&now, &selected],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM casework_review_submission_reservations s
                  USING casework_review_requests r
                 WHERE s.request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.accountability_retained_until<=$1",
                &[&now, &selected],
            )
            .await?;
        let erased = transaction
            .execute(
                "DELETE FROM casework_review_requests
                 WHERE request_id=ANY($2) AND accountability_retained_until<=$1",
                &[&now, &selected],
            )
            .await?;
        let expired_reservations = transaction
            .execute(
                "DELETE FROM casework_review_submission_reservations
                 WHERE ctid IN (
                    SELECT ctid FROM casework_review_submission_reservations
                     WHERE retained_until<=$1 AND request_id IS NULL
                     ORDER BY retained_until,producer_id,subject_id
                     LIMIT $2 FOR UPDATE SKIP LOCKED
                 )",
                &[&now, &REVIEW_RETENTION_BATCH_SIZE],
            )
            .await?;
        for request_id in &selected {
            record_maintenance(
                &mut audit,
                Uuid::new_v4(),
                "review-retention-erased",
                "system:review-retention",
                Some(*request_id),
                None,
                None,
            )?;
        }
        if expired_reservations > 0 {
            record_maintenance(
                &mut audit,
                Uuid::new_v4(),
                "review-recovery-retention-erased",
                "system:review-retention",
                None,
                None,
                None,
            )?;
        }
        audit.commit(transaction).await?;
        Ok(erased)
    }
}

fn record_maintenance(
    audit: &mut crate::audit::AuditOperation,
    event_id: Uuid,
    event: &str,
    profile: &str,
    request: Option<Uuid>,
    task: Option<Uuid>,
    queue: Option<&str>,
) -> Result<(), StoreError> {
    let mut record = json!({"event":format!("casework.{event}"),"profileId":profile});
    if let Some(id) = request {
        record["reviewRequestId"] = json!(id);
    }
    if let Some(id) = task {
        record["reviewTaskId"] = json!(id);
    }
    if let Some(id) = queue {
        record["queueId"] = json!(id);
    }
    audit.record(event_id, record)
}
