//! A reviewer's asks of the applicant. The task holder opens one ask at a time,
//! the producer reads it through its ask feed and reports the answer without
//! carrying its text, and the ask closes with its task or its request.
use super::*;
use chrono::SubsecRound;
use registry_casework_core::{
    ReviewAsk, ReviewAskAnswer, ReviewAskFeedEntry, ReviewAskFeedPage, ReviewAskState,
    ReviewAskWant,
};
use registry_casework_core::{ReviewContextAsk, ReviewTaskAskRequest, ReviewTaskAsked};

/// How far ahead of Casework's clock a producer's answer time may lie. The
/// producer records the time it committed the answer, and the two clocks may
/// differ a little.
const ASK_ANSWER_CLOCK_SKEW: TimeDelta = TimeDelta::minutes(5);

/// A time Casework stores and then serves or compares. PostgreSQL keeps
/// microseconds and the ask protocol carries them, so a time with a finer clock
/// part is cut before it is stored: otherwise the stored and the served value
/// differ on a platform whose clock reads nanoseconds.
fn stored_time(time: DateTime<Utc>) -> DateTime<Utc> {
    time.trunc_subsecs(6)
}

const ASK_COLUMNS: &str =
    "ask_id,request_id,task_id,text,wants,state,asked_at,answered_at,closed_at,due_at";

impl CaseworkService {
    /// Opens an ask from the task the caller holds.
    #[allow(clippy::too_many_arguments)]
    pub async fn ask_applicant(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        request: ReviewTaskAskRequest,
        source_profile_id: Option<&str>,
        token: &str,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTaskAsked, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        request.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await?;
        let record = self.store.review_request_for_task(task_id).await?;
        let producer_reads_asks = self
            .project
            .trusted_producers
            .iter()
            .any(|producer| producer.id == record.producer_id && producer.reads_asks);
        self.store
            .ask_applicant(
                actor,
                task_id,
                request,
                producer_reads_asks,
                expected_revision,
                idempotency_key,
            )
            .await
    }

    pub async fn review_ask_feed(
        &self,
        actor: &ActorContext,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewAskFeedPage, ReviewRuntimeError> {
        if limit == 0 || limit > MAXIMUM_REVIEW_FEED_PAGE {
            return Err(ReviewRuntimeError::Invalid);
        }
        let admission = self.producer_for_actor(actor)?;
        self.store
            .review_ask_feed(&admission.producer, cursor, limit)
            .await
    }

    pub async fn review_ask(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        ask_id: Uuid,
    ) -> Result<ReviewAsk, ReviewRuntimeError> {
        let admission = self.producer_for_actor(actor)?;
        self.store
            .review_ask(&admission.producer, request_id, ask_id)
            .await
    }

    pub async fn answer_review_ask(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        ask_id: Uuid,
        answer: ReviewAskAnswer,
        idempotency_key: &str,
    ) -> Result<ReviewAsk, ReviewRuntimeError> {
        answer.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        let admission = self.producer_for_actor(actor)?;
        self.store
            .answer_review_ask(
                &admission.producer,
                actor,
                request_id,
                ask_id,
                answer,
                idempotency_key,
            )
            .await
    }
}

impl PostgresStore {
    /// Expiry shares the request lock with answering and deciding. The answer
    /// time, rather than which transaction wins that lock, decides lateness.
    pub(super) async fn expire_due_review_asks(
        &self,
        maximum: usize,
    ) -> Result<usize, ReviewRuntimeError> {
        let now = stored_time(Utc::now());
        let limit =
            i64::try_from(maximum.clamp(1, 100)).map_err(|_| ReviewRuntimeError::Invalid)?;
        let mut client = self.client().await?;
        let rows = client
            .query(
                "SELECT a.ask_id,a.request_id,a.task_id FROM casework_review_asks a
             JOIN casework_review_requests r USING(request_id)
             WHERE a.state='open' AND a.due_at<$1 AND r.lifecycle='reviewing'
             ORDER BY a.due_at,a.ask_id LIMIT $2",
                &[&now, &limit],
            )
            .await?;
        let mut expired = 0;
        for row in rows {
            // Commit each request before taking another request lock. Holding
            // the producer's feed lock while waiting for its next request
            // would invert the lock order of an answering producer.
            let mut audit = self.begin_background_audit().await?;
            let tx = client.transaction().await?;
            let ask_id: Uuid = row.get(0);
            let request_id: Uuid = row.get(1);
            let task_id: Uuid = row.get(2);
            if tx.query_opt("SELECT request_id FROM casework_review_requests WHERE request_id=$1 AND lifecycle='reviewing' FOR UPDATE SKIP LOCKED", &[&request_id]).await?.is_none() {
                continue;
            }
            let record = load_request_by_id(&tx, request_id, false).await?;
            if tx.execute("UPDATE casework_review_asks SET state='expired',closed_at=$2 WHERE ask_id=$1 AND state='open' AND due_at<$2", &[&ask_id,&now]).await? == 0 {
                continue;
            }
            tx.execute("UPDATE casework_review_tasks SET ask_marker='expired',revision=revision+1,updated_at=$2 WHERE task_id=$1 AND state IN ('open','claimed')", &[&task_id,&now]).await?;
            tx.execute("UPDATE casework_review_requests SET revision=revision+1,updated_at=$2 WHERE request_id=$1", &[&request_id,&now]).await?;
            insert_ask_event(&tx, &record, ask_id, "expired", now).await?;
            super::ask_clocks::resume(&tx, request_id, ask_id, now).await?;
            let event_id = Uuid::new_v4();
            tx.execute("INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at) VALUES($1,$2,$3,'ask-expired',NULL,$4,$5)", &[&event_id,&request_id,&task_id,&json!({"askId":ask_id}),&now]).await?;
            audit.record(event_id, json!({"event":"casework.review-ask-expired","profileId":"system:clocks","reviewRequestId":request_id,"reviewTaskId":task_id,"reviewAskId":ask_id}))?;
            super::ask_clocks::audit_events(&tx, request_id, &mut audit).await?;
            audit.commit(tx).await?;
            expired += 1;
        }
        Ok(expired)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn ask_applicant(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        request: ReviewTaskAskRequest,
        producer_reads_asks: bool,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTaskAsked, ReviewRuntimeError> {
        let now = stored_time(Utc::now());
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "review-ask-opened",
                Some(actor),
                &actor.profile_id,
                json!({}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let request_id = transaction
            .query_opt(
                "SELECT request_id FROM casework_review_tasks WHERE task_id=$1",
                &[&task_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?
            .get::<_, Uuid>(0);
        let record = load_request_by_id(&transaction, request_id, true).await?;
        ensure_review_mutation_actor_authorized(&transaction, &record, actor, task_id).await?;
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(expected_revision, "ask", &request))?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.task.ask",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return serde_json::from_value(response).map_err(ReviewRuntimeError::from);
        }
        let row = transaction
            .query_one(
                "SELECT stage_index,stage_id,queue_id,state,holder_issuer,holder_subject,revision,
                        deadline_at,created_at,staffing_diagnostic
                 FROM casework_review_tasks WHERE task_id=$1 FOR UPDATE",
                &[&task_id],
            )
            .await?;
        let stage_index =
            u16::try_from(row.get::<_, i32>(0)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        if record.lifecycle != ReviewRequestLifecycle::Reviewing
            || record.active_stage != Some(stage_index)
        {
            return Err(ReviewRuntimeError::ReviewAskTaskInactive);
        }
        if row.get::<_, i64>(6) != expected_revision {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        if row.get::<_, String>(3) != "claimed"
            || row.get::<_, Option<String>>(4).as_deref() != Some(actor.principal.issuer.as_str())
            || row.get::<_, Option<String>>(5).as_deref() != Some(actor.principal.subject.as_str())
        {
            return Err(ReviewRuntimeError::TaskNotHeld);
        }
        let stage = record
            .policy
            .stages
            .get(usize::from(stage_index))
            .ok_or(ReviewRuntimeError::Corrupt)?;
        let options = stage.asks.ok_or(ReviewRuntimeError::ReviewAskNotOffered)?;
        if !producer_reads_asks {
            return Err(ReviewRuntimeError::ReviewAskProducerUnsupported);
        }
        let ask_id = Uuid::new_v4();
        let due_at = options
            .answer_within
            .map(|duration| now + TimeDelta::seconds(duration.seconds()));
        let actor_ref = actor_reference(&actor.principal);
        let wants = serde_json::to_value(&request.wants)?;
        transaction
            .execute(
                "INSERT INTO casework_review_asks(
                    ask_id,request_id,task_id,stage_index,text,wants,state,asked_at,asked_by_ref,due_at)
                 VALUES($1,$2,$3,$4,$5,$6,'open',$7,$8,$9)",
                &[
                    &ask_id,
                    &request_id,
                    &task_id,
                    &i32::from(stage_index),
                    &request.text,
                    &wants,
                    &now,
                    &actor_ref,
                    &due_at,
                ],
            )
            .await
            .map_err(map_open_ask_conflict)?;
        insert_ask_event(&transaction, &record, ask_id, "opened", now).await?;
        if options.pause_clocks {
            super::ask_clocks::pause(&transaction, request_id, ask_id, now).await?;
        }
        let metadata = transaction
            .query_one(
                "UPDATE casework_review_tasks
                 SET ask_marker='waiting',revision=revision+1,updated_at=$2
                 WHERE task_id=$1
                 RETURNING deadline_at,created_at,staffing_diagnostic,state,ask_marker",
                &[&task_id, &now],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_review_requests SET revision=revision+1,updated_at=$2
                 WHERE request_id=$1",
                &[&request_id, &now],
            )
            .await?;
        let task = ReviewTask {
            subject: record.subject.clone(),
            requester_reference: record.requester_reference.clone(),
            deadline_at: metadata.get(0),
            created_at: metadata.get(1),
            display_reference: None,
            task_id,
            request_id,
            stage_index,
            stage_id: row.get(1),
            queue: row.get(2),
            revision: expected_revision + 1,
            eligible_profiles: stage.deciding_profiles.clone(),
            state: ReviewTaskState::Held {
                holder: actor.principal.clone(),
            },
            staffing_diagnostic: staffing_diagnostic_from_row(&metadata)?,
            decided_by_caller: None,
            decision_receipt: None,
            marker: task_marker(metadata.get::<_, Option<String>>(4))?,
        };
        let ask = ReviewAsk {
            ask_id,
            request_id,
            subject: record.subject.clone(),
            text: request.text,
            wants: request.wants,
            asked_at: now,
            due_at,
            state: ReviewAskState::Open,
            answered_at: None,
            closed_at: None,
        };
        ask.check().map_err(|_| ReviewRuntimeError::Corrupt)?;
        let history_event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,'ask-opened',$4,$5,$6)",
                &[
                    &history_event_id,
                    &request_id,
                    &task_id,
                    &actor_ref,
                    &json!({"askId": ask_id}),
                    &now,
                ],
            )
            .await?;
        // The audit record carries identifiers only. The ask text stays in the
        // ask row and the producer's copy, so it expires with the review.
        audit.record(
            history_event_id,
            json!({
                "event": "casework.review-ask-opened",
                "eventId": history_event_id,
                "reviewRequestId": request_id,
                "reviewTaskId": task_id,
                "reviewAskId": ask_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
            }),
        )?;
        let response = ReviewTaskAsked { task, ask };
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.task.ask",
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&response)?,
        )
        .await?;
        super::ask_clocks::audit_events(&transaction, request_id, &mut audit).await?;
        audit.commit(transaction).await?;
        Ok(response)
    }

    pub(super) async fn review_ask_feed(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewAskFeedPage, ReviewRuntimeError> {
        let client = self.client().await?;
        let position = if let Some(cursor) = cursor {
            Some(
                client
                    .query_opt(
                        "SELECT e.feed_position FROM casework_review_ask_events e
                         JOIN casework_review_requests r USING(request_id)
                         WHERE e.producer_id=$1 AND r.producer_issuer=$2
                           AND r.producer_subject=$3 AND e.event_id=$4
                           AND r.result_erased_at IS NULL
                           AND (r.result_available_until IS NULL OR r.result_available_until>now())",
                        &[&producer.id, &producer.issuer, &producer.subject, &cursor],
                    )
                    .await?
                    .ok_or(ReviewRuntimeError::ResultExpired)?
                    .get::<_, i64>(0),
            )
        } else {
            None
        };
        let rows = client
            .query(
                "SELECT e.event_id,e.request_id,e.ask_id,e.changed_at
                 FROM casework_review_ask_events e
                 JOIN casework_review_requests r USING(request_id)
                 WHERE e.producer_id=$1 AND r.producer_issuer=$2
                   AND r.producer_subject=$3 AND r.result_erased_at IS NULL
                   AND (r.result_available_until IS NULL OR r.result_available_until>now())
                   AND ($4::bigint IS NULL OR e.feed_position>$4)
                 ORDER BY e.feed_position LIMIT $5",
                &[
                    &producer.id,
                    &producer.issuer,
                    &producer.subject,
                    &position,
                    &i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?,
                ],
            )
            .await?;
        let next_cursor = (rows.len() > limit).then(|| rows[limit - 1].get::<_, Uuid>(0));
        let items = rows
            .into_iter()
            .take(limit)
            .map(|row| ReviewAskFeedEntry {
                event_id: row.get(0),
                request_id: row.get(1),
                ask_id: row.get(2),
                changed_at: row.get(3),
            })
            .collect();
        Ok(ReviewAskFeedPage { items, next_cursor })
    }

    pub(super) async fn review_ask(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        request_id: Uuid,
        ask_id: Uuid,
    ) -> Result<ReviewAsk, ReviewRuntimeError> {
        let client = self.client().await?;
        let record = load_request_client(&client, producer, request_id).await?;
        ensure_ask_retained(&record)?;
        let row = client
            .query_opt(
                &format!(
                    "SELECT {ASK_COLUMNS} FROM casework_review_asks
                     WHERE ask_id=$1 AND request_id=$2"
                ),
                &[&ask_id, &request_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        ask_from_row(&row, &record)
    }

    pub(super) async fn answer_review_ask(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        actor: &ActorContext,
        request_id: Uuid,
        ask_id: Uuid,
        answer: ReviewAskAnswer,
        idempotency_key: &str,
    ) -> Result<ReviewAsk, ReviewRuntimeError> {
        let now = stored_time(Utc::now());
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "review-ask-answered",
                Some(actor),
                &actor.profile_id,
                json!({}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let record = load_request(&transaction, producer, request_id, true).await?;
        let resource = format!("review-ask:{request_id}:{ask_id}");
        let request_hash = review_request_hash(&answer)?;
        // The retention window, the subject binding and the ask's own request
        // all hold before a stored response can be returned.
        ensure_ask_retained(&record)?;
        if record.subject != answer.subject {
            return Err(ReviewRuntimeError::NotFound);
        }
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {ASK_COLUMNS} FROM casework_review_asks
                     WHERE ask_id=$1 AND request_id=$2 FOR UPDATE"
                ),
                &[&ask_id, &request_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.ask.answer",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return serde_json::from_value(response).map_err(ReviewRuntimeError::from);
        }
        let current = ask_from_row(&row, &record)?;
        if !matches!(
            current.state,
            ReviewAskState::Open | ReviewAskState::Expired
        ) || current.due_at.is_some_and(|due| answer.answered_at > due)
        {
            return Err(ReviewRuntimeError::ReviewAskNotOpen);
        }
        if answer.answered_at < current.asked_at || answer.answered_at > now + ASK_ANSWER_CLOCK_SKEW
        {
            return Err(ReviewRuntimeError::ReviewAskAnswerTimeInvalid);
        }
        let task_id = row.get::<_, Uuid>(2);
        let answered_at = transaction
            .query_one(
                "UPDATE casework_review_asks SET state='answered',answered_at=$2,closed_at=NULL
                 WHERE ask_id=$1 RETURNING answered_at",
                &[&ask_id, &answer.answered_at],
            )
            .await?
            .get::<_, DateTime<Utc>>(0);
        transaction
            .execute(
                "UPDATE casework_review_tasks
                 SET ask_marker='answered',revision=revision+1,updated_at=$2
                 WHERE task_id=$1 AND state IN ('open','claimed')",
                &[&task_id, &now],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_review_requests SET revision=revision+1,updated_at=$2
                 WHERE request_id=$1",
                &[&request_id, &now],
            )
            .await?;
        insert_ask_event(&transaction, &record, ask_id, "answered", now).await?;
        super::ask_clocks::resume(&transaction, request_id, ask_id, now).await?;
        let history_event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,'ask-answered',NULL,$4,$5)",
                &[
                    &history_event_id,
                    &request_id,
                    &task_id,
                    &json!({"askId": ask_id, "arrivedAfterDue": current.due_at.is_some_and(|due| now > due)}),
                    &now,
                ],
            )
            .await?;
        audit.record(
            history_event_id,
            json!({
                "event": "casework.review-ask-answered",
                "eventId": history_event_id,
                "reviewRequestId": request_id,
                "reviewTaskId": task_id,
                "reviewAskId": ask_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
            }),
        )?;
        let response = ReviewAsk {
            state: ReviewAskState::Answered,
            answered_at: Some(answered_at),
            closed_at: None,
            ..current
        };
        response.check().map_err(|_| ReviewRuntimeError::Corrupt)?;
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.ask.answer",
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&response)?,
        )
        .await?;
        super::ask_clocks::audit_events(&transaction, request_id, &mut audit).await?;
        audit.commit(transaction).await?;
        Ok(response)
    }

    /// The asks of a request, oldest first, as its reviewers read them.
    pub(super) async fn review_context_asks(
        &self,
        request_id: Uuid,
    ) -> Result<Vec<ReviewContextAsk>, ReviewRuntimeError> {
        let client = self.client().await?;
        client
            .query(
                "SELECT ask_id,task_id,text,wants,state,asked_at,answered_at
                 FROM casework_review_asks WHERE request_id=$1 ORDER BY asked_at,ask_id",
                &[&request_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(ReviewContextAsk {
                    ask_id: row.get(0),
                    task_id: row.get(1),
                    text: row.get(2),
                    wants: wants_from_json(row.get(3))?,
                    state: ask_state(&row.get::<_, String>(4))?,
                    asked_at: row.get(5),
                    answered_at: row.get(6),
                })
            })
            .collect()
    }
}

/// Closes open and expired asks when their task is decided or the request
/// ends. `task_id` limits the close to that task's asks. Every close
/// is announced on the producer's feed in the same transaction.
pub(super) async fn close_open_asks(
    transaction: &impl GenericClient,
    record: &ReviewRequestRecord,
    task_id: Option<Uuid>,
    now: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    let now = stored_time(now);
    let closed = transaction
        .query(
            "UPDATE casework_review_asks SET state='closed',closed_at=$2
             WHERE request_id=$1 AND state IN ('open','expired')
               AND ($3::uuid IS NULL OR task_id=$3)
             RETURNING ask_id",
            &[&record.request_id, &now, &task_id],
        )
        .await?;
    for row in closed {
        let ask_id = row.get(0);
        insert_ask_event(transaction, record, ask_id, "closed", now).await?;
        super::ask_clocks::resume(transaction, record.request_id, ask_id, now).await?;
    }
    Ok(())
}

async fn insert_ask_event(
    transaction: &impl GenericClient,
    record: &ReviewRequestRecord,
    ask_id: Uuid,
    change: &str,
    now: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    // The result feed's per-producer lock, held to commit: feed positions are
    // assigned in the order the events commit, so a reader never passes an
    // event that commits later.
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&record.producer_id],
        )
        .await?;
    let now = stored_time(now);
    transaction
        .execute(
            "INSERT INTO casework_review_ask_events(
                event_id,request_id,ask_id,producer_id,change,changed_at)
             VALUES($1,$2,$3,$4,$5,$6)",
            &[
                &Uuid::new_v4(),
                &record.request_id,
                &ask_id,
                &record.producer_id,
                &change,
                &now,
            ],
        )
        .await?;
    Ok(())
}

/// The ask and its events leave with the request's retained result.
fn ensure_ask_retained(record: &ReviewRequestRecord) -> Result<(), ReviewRuntimeError> {
    if record.result_erased_at.is_some()
        || record
            .result_available_until
            .is_some_and(|available_until| available_until <= Utc::now())
    {
        Err(ReviewRuntimeError::NotFound)
    } else {
        Ok(())
    }
}

/// One open ask per request is a storage rule; a second insert that reaches it
/// is the refusal the caller sees.
fn map_open_ask_conflict(error: tokio_postgres::Error) -> ReviewRuntimeError {
    if error
        .as_db_error()
        .is_some_and(|error| error.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
    {
        ReviewRuntimeError::ReviewAskAlreadyOpen
    } else {
        ReviewRuntimeError::from(error)
    }
}

fn ask_state(stored: &str) -> Result<ReviewAskState, ReviewRuntimeError> {
    match stored {
        "open" => Ok(ReviewAskState::Open),
        "answered" => Ok(ReviewAskState::Answered),
        "expired" => Ok(ReviewAskState::Expired),
        "closed" => Ok(ReviewAskState::Closed),
        _ => Err(ReviewRuntimeError::Corrupt),
    }
}

fn wants_from_json(stored: Value) -> Result<Vec<ReviewAskWant>, ReviewRuntimeError> {
    serde_json::from_value(stored).map_err(|_| ReviewRuntimeError::Corrupt)
}

fn ask_from_row(row: &Row, record: &ReviewRequestRecord) -> Result<ReviewAsk, ReviewRuntimeError> {
    let state = ask_state(&row.get::<_, String>(5))?;
    let ask = ReviewAsk {
        ask_id: row.get(0),
        request_id: row.get(1),
        subject: record.subject.clone(),
        text: row.get(3),
        wants: wants_from_json(row.get(4))?,
        asked_at: row.get(6),
        due_at: row.get(9),
        state,
        answered_at: row.get(7),
        closed_at: row.get(8),
    };
    ask.check().map_err(|_| ReviewRuntimeError::Corrupt)?;
    Ok(ask)
}

#[cfg(test)]
mod tests {
    use super::stored_time;
    use chrono::{TimeZone, Timelike, Utc};

    #[test]
    fn a_stored_time_keeps_no_sub_microsecond_part() {
        // A Linux clock reads nanoseconds. PostgreSQL would round the stored
        // value, so the served value must be the truncated one.
        let read = Utc
            .with_ymd_and_hms(2026, 11, 27, 10, 0, 0)
            .unwrap()
            .with_nanosecond(123_456_789)
            .unwrap();
        let stored = stored_time(read);
        assert_eq!(stored.nanosecond(), 123_456_000);
        assert_eq!(stored_time(stored), stored);
    }
}
