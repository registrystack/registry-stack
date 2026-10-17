//! One staffing surface over review tasks. Live projections never become an index.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

impl CaseworkService {
    pub async fn review_staffing_tasks(
        &self,
        actor: &ActorContext,
        source_profile: Option<&str>,
        token: &str,
        query: ReviewStaffingQuery,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        query.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        require_human_reviewer(actor)?;
        if source_profile.is_none() {
            let policies = self
                .project
                .review_policies
                .iter()
                .filter(|policy| {
                    policy.stages.iter().any(|stage| {
                        stage.deciding_profiles.contains(&actor.profile_id)
                            && (query
                                .queue
                                .as_ref()
                                .is_none_or(|queue| stage.queue == *queue)
                                || policy
                                    .routing
                                    .iter()
                                    .any(|rule| Some(&rule.queue) == query.queue.as_ref()))
                    })
                })
                .collect::<Vec<_>>();
            if !policies.is_empty()
                && policies.iter().all(|policy| {
                    matches!(policy.context, ReviewContextPolicy::CurrentSource { .. })
                })
            {
                return Err(ReviewRuntimeError::SourceProfileRequired);
            }
        }
        let mut limit = query
            .limit
            .unwrap_or(self.project.inbox.default_page_size)
            .min(100);
        let ordinary = query.reference.is_none() && query.sort != ReviewTaskSort::Reference;
        let until = tokio::time::Instant::now()
            + Duration::from_millis(self.project.inbox.page_deadline_milliseconds);
        let mut context = query.clone();
        context.cursor = None;
        let context_digest = review_request_hash(&(source_profile, context))?;
        let mut after = if ordinary {
            if let Some(cursor) = query.cursor {
                let client = self.store.client().await?;
                let row = client
                    .query_opt(
                        "SELECT position_key FROM casework_review_staffing_cursors
                     WHERE cursor_id=$1 AND issuer=$2 AND subject=$3 AND profile_id=$4
                     AND context_digest=$5 AND position_key IS NOT NULL AND expires_at>now()",
                        &[
                            &cursor,
                            &actor.principal.issuer,
                            &actor.principal.subject,
                            &actor.profile_id,
                            &context_digest,
                        ],
                    )
                    .await?
                    .ok_or(ReviewRuntimeError::ResultExpired)?;
                Some(row.get::<_, Value>(0))
            } else {
                None
            }
        } else {
            None
        };
        let mut observations = super::inbox::InboxObservations::default();
        if let Some(key) = &after {
            let anchor: Uuid = serde_json::from_value(
                key.get("taskId")
                    .cloned()
                    .ok_or(ReviewRuntimeError::Corrupt)?,
            )?;
            let check = async {
                let task = self.store.review_task(actor, anchor).await?;
                if query
                    .queue
                    .as_ref()
                    .is_some_and(|queue| task.queue != *queue)
                    || !review_task_matches_ownership(&task, actor, query.ownership)
                    || staffing_position(&task) != *key
                {
                    return Err(ReviewRuntimeError::ResultExpired);
                }
                let record = self.store.review_request_for_task(anchor).await?;
                let request_id = record.request_id;
                let records = BTreeMap::from([(request_id, record)]);
                observations
                    .prepare(self, &records, source_profile, token, until, true)
                    .await?;
                observations.display(&records[&request_id], source_profile, true, true)?;
                let current = self.store.review_task(actor, anchor).await?;
                if staffing_position(&current) != *key
                    || current.queue != task.queue
                    || !review_task_matches_ownership(&current, actor, query.ownership)
                {
                    return Err(ReviewRuntimeError::ResultExpired);
                }
                Ok(())
            };
            match tokio::time::timeout_at(until, check).await {
                Ok(Ok(())) => {}
                Ok(Err(
                    ReviewRuntimeError::Forbidden
                    | ReviewRuntimeError::NotFound
                    | ReviewRuntimeError::SourceProfileRequired
                    | ReviewRuntimeError::SourceProfileNotApplicable,
                )) => {
                    return Err(ReviewRuntimeError::ResultExpired);
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(ReviewRuntimeError::SourceUnavailable),
            }
        }
        if observations.source_reads() > 0 {
            // A continuation reserves its current anchor observation before
            // admitting candidates. Limit is an upper bound on returned rows.
            limit = limit.min(
                self.project
                    .inbox
                    .maximum_source_reads
                    .saturating_sub(observations.source_reads()),
            );
            if limit == 0 {
                return Err(ReviewRuntimeError::QueryTooBroad);
            }
        }
        let expected_subject = query.subject().map_err(|_| ReviewRuntimeError::Invalid)?;
        let mut position = None;
        let mut examined = 0;
        let mut items = Vec::new();
        loop {
            if examined >= self.project.inbox.maximum_candidate_scan
                || tokio::time::Instant::now() >= until
            {
                return Err(ReviewRuntimeError::QueryTooBroad);
            }
            let remaining = self.project.inbox.maximum_candidate_scan - examined;
            let batch_limit = if ordinary {
                (limit - items.len()).min(remaining)
            } else {
                100.min(remaining)
            };
            let page = if ordinary {
                self.store
                    .staffing_candidates(actor, &query, &after, batch_limit)
                    .await?
            } else {
                self.store
                    .review_tasks_filtered(
                        actor,
                        query.queue.as_deref(),
                        ReviewTaskListView::Reviewer(query.ownership),
                        position,
                        batch_limit,
                        expected_subject.as_ref(),
                    )
                    .await?
            };
            let records = self.store.inbox_records(&page.items).await?;
            observations
                .prepare(self, &records, source_profile, token, until, false)
                .await?;
            let ids = page
                .items
                .iter()
                .map(|task| task.task_id)
                .collect::<Vec<_>>();
            let mut current = self
                .store
                .inbox_current_tasks(actor, &ids, true, false)
                .await?;
            if tokio::time::Instant::now() >= until {
                return Err(ReviewRuntimeError::SourceUnavailable);
            }
            for task in &page.items {
                examined += 1;
                let record = records
                    .get(&task.request_id)
                    .ok_or(ReviewRuntimeError::Corrupt)?;
                let display_reference =
                    match observations.display(record, source_profile, true, false) {
                        Ok(reference) => reference,
                        Err(
                            ReviewRuntimeError::Forbidden
                            | ReviewRuntimeError::NotFound
                            | ReviewRuntimeError::SourceProfileRequired,
                        ) => continue,
                        Err(error) => return Err(error),
                    };
                let Some(mut row) = current.remove(&task.task_id) else {
                    continue;
                };
                if row.revision != task.revision
                    || row.queue != task.queue
                    || !review_task_matches_ownership(&row, actor, query.ownership)
                {
                    continue;
                }
                row.display_reference = display_reference;
                if query
                    .reference
                    .as_ref()
                    .is_some_and(|reference| row.display_reference.as_ref() != Some(reference))
                {
                    continue;
                }
                items.push(row);
            }
            if ordinary && items.len() == limit && page.next_cursor.is_some() {
                let key = staffing_position(&items[limit - 1]);
                let cursor = Uuid::new_v4();
                let client = self.store.client().await?;
                client.execute("INSERT INTO casework_review_staffing_cursors
                    (cursor_id,issuer,subject,profile_id,context_digest,snapshot_digest,position,position_key,expires_at)
                    VALUES($1,$2,$3,$4,$5,'',0,$6,now()+interval '15 minutes')",
                    &[&cursor,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&context_digest,&key]).await?;
                items.truncate(limit);
                return Ok(ReviewTaskPage {
                    items,
                    next_cursor: Some(cursor),
                    status: PageStatus::Complete,
                });
            }
            let Some(next) = page.next_cursor else { break };
            if position == Some(next) {
                return Err(ReviewRuntimeError::Corrupt);
            }
            position = Some(next);
            after = page.items.last().map(staffing_position);
        }
        if ordinary {
            return Ok(ReviewTaskPage {
                items,
                next_cursor: None,
                status: PageStatus::Complete,
            });
        }
        items.sort_by(|left, right| {
            let tie = || {
                left.created_at
                    .cmp(&right.created_at)
                    .then(left.task_id.cmp(&right.task_id))
            };
            match query.sort {
                ReviewTaskSort::Due => match (left.deadline_at, right.deadline_at) {
                    (Some(a), Some(b)) => a.cmp(&b),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    _ => std::cmp::Ordering::Equal,
                }
                .then_with(tie),
                ReviewTaskSort::Subject => (
                    &left.subject.source,
                    &left.subject.subject_type,
                    &left.subject.id,
                    &left.subject.version,
                    left.subject.digest.as_str(),
                )
                    .cmp(&(
                        &right.subject.source,
                        &right.subject.subject_type,
                        &right.subject.id,
                        &right.subject.version,
                        right.subject.digest.as_str(),
                    ))
                    .then_with(tie),
                ReviewTaskSort::Reference => {
                    match (&left.display_reference, &right.display_reference) {
                        (Some(a), Some(b)) => a.cmp(b),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        _ => std::cmp::Ordering::Equal,
                    }
                    .then_with(tie)
                }
            }
        });
        let mut context = query.clone();
        context.cursor = None;
        let context_digest = review_request_hash(&(source_profile, context))?;
        let snapshot_digest = review_request_hash(&items)?;
        let client = self.store.client().await?;
        let offset = if let Some(cursor) = query.cursor {
            let row=client.query_opt("SELECT position FROM casework_review_staffing_cursors WHERE cursor_id=$1 AND issuer=$2 AND subject=$3 AND profile_id=$4 AND context_digest=$5 AND snapshot_digest=$6 AND expires_at>now()",&[&cursor,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&context_digest,&snapshot_digest]).await?.ok_or(ReviewRuntimeError::ResultExpired)?;
            usize::try_from(row.get::<_, i32>(0)).map_err(|_| ReviewRuntimeError::Corrupt)?
        } else {
            0
        };
        if offset > items.len() {
            return Err(ReviewRuntimeError::ResultExpired);
        }
        let next_offset = (offset + limit).min(items.len());
        let next_cursor = if next_offset < items.len() {
            let cursor = Uuid::new_v4();
            client.execute("INSERT INTO casework_review_staffing_cursors(cursor_id,issuer,subject,profile_id,context_digest,snapshot_digest,position,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '15 minutes')",&[&cursor,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&context_digest,&snapshot_digest,&i32::try_from(next_offset).map_err(|_|ReviewRuntimeError::Corrupt)?]).await?;
            Some(cursor)
        } else {
            None
        };
        Ok(ReviewTaskPage {
            items: items.into_iter().skip(offset).take(limit).collect(),
            next_cursor,
            status: PageStatus::Complete,
        })
    }

    pub async fn preview_review_caseload(
        &self,
        actor: &ActorContext,
        source_profile: Option<&str>,
        token: &str,
        request: ReviewCaseloadMoveRequest,
    ) -> Result<ReviewCaseloadPreview, ReviewRuntimeError> {
        request.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        if actor.role != CaseworkRole::Supervisor {
            return Err(ReviewRuntimeError::Forbidden);
        }
        let client = self.store.client().await?;
        let rows=client.query("SELECT task_id FROM casework_review_tasks WHERE state='claimed' AND holder_issuer=$1 AND holder_subject=$2 AND ($3::text IS NULL OR queue_id=$3) ORDER BY task_id LIMIT 101",&[&request.from.issuer,&request.from.subject,&request.queue]).await?;
        if rows.len() > 100 {
            return Err(ReviewRuntimeError::QueryTooBroad);
        }
        let mut tasks = Vec::new();
        for row in rows {
            let task_id = row.get(0);
            let record = self.store.review_request_for_task(task_id).await?;
            // A caller cannot use a movement preview to discover another team's caseload.
            let task = self
                .store
                .review_task_by_activity(actor, task_id, false, true)
                .await?;
            self.preflight_review_record_source(
                &record,
                if matches!(record.policy.context, ReviewContextPolicy::Submitted) {
                    None
                } else {
                    source_profile
                },
                token,
            )
            .await?;
            tasks.push(ReviewCaseloadTask {
                task_id,
                revision: task.revision,
            });
        }
        let mut client = self.store.client().await?;
        let tx = client.transaction().await?;
        let directory_revision = lock_staffing_directory(&tx).await?;
        validate_caseload_set(&tx, actor, &request, &tasks).await?;
        let preview = ReviewCaseloadPreview {
            preview_id: Uuid::new_v4(),
            directory_revision,
            tasks,
            expires_at: Utc::now() + chrono::TimeDelta::minutes(15),
        };
        tx.execute("INSERT INTO casework_review_staffing_previews(preview_id,kind,issuer,subject,profile_id,directory_revision,request,tasks,expires_at) VALUES($1,'caseload',$2,$3,$4,$5,$6,$7,$8)",&[&preview.preview_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&directory_revision,&serde_json::to_value(&request)?,&serde_json::to_value(&preview.tasks)?,&preview.expires_at]).await?;
        tx.commit().await?;
        Ok(preview)
    }

    pub async fn apply_review_caseload(
        &self,
        actor: &ActorContext,
        source_profile: Option<&str>,
        token: &str,
        request: ReviewCaseloadApplyRequest,
    ) -> Result<ReviewCaseloadResult, ReviewRuntimeError> {
        request.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        if actor.role != CaseworkRole::Supervisor {
            return Err(ReviewRuntimeError::Forbidden);
        }
        let (movement, tasks, directory_revision) = self
            .store
            .staffing_preview::<ReviewCaseloadMoveRequest, ReviewCaseloadTask>(
                actor,
                request.preview_id,
                "caseload",
            )
            .await?;
        for task in &tasks {
            let record = self.store.review_request_for_task(task.task_id).await?;
            self.preflight_review_record_source(
                &record,
                if matches!(record.policy.context, ReviewContextPolicy::Submitted) {
                    None
                } else {
                    source_profile
                },
                token,
            )
            .await?;
        }
        let mut audit = self
            .store
            .begin_audit(crate::audit::request_record(
                "review-caseload-moved",
                Some(actor),
                &actor.profile_id,
                json!({"previewId":request.preview_id}),
            ))
            .await?;
        let mut client = self.store.client().await?;
        let tx = client.transaction().await?;
        let current_directory = lock_staffing_directory(&tx).await?;
        // An applied preview answers its stored result even after the
        // Directory moved on; only a pending apply is fenced by revision.
        if let Some(response) =
            lock_staffing_preview(&tx, actor, request.preview_id, "caseload").await?
        {
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(tx).await?;
            return Ok(serde_json::from_value(response)?);
        }
        if current_directory != directory_revision {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        validate_caseload_set(&tx, actor, &movement, &tasks).await?;
        let now = Utc::now();
        let mut moved = Vec::new();
        for task in &tasks {
            let row=tx.query_one("UPDATE casework_review_tasks SET holder_issuer=$2,holder_subject=$3,assignment_owner_issuer=$2,assignment_owner_subject=$3,assigned_by_issuer=$4,assigned_by_subject=$5,assignment_kind='nomination',assignment_absence_ids='{}',staffing_diagnostic=NULL,revision=revision+1,updated_at=$6 WHERE task_id=$1 RETURNING request_id,revision",&[&task.task_id,&movement.to.issuer,&movement.to.subject,&actor.principal.issuer,&actor.principal.subject,&now]).await?;
            let event_id = Uuid::new_v4();
            let request_id: Uuid = row.get(0);
            let revision: i64 = row.get(1);
            tx.execute("INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at) VALUES($1,$2,$3,'caseload-moved',$4,$5,$6)",&[&event_id,&request_id,&task.task_id,&actor_reference(&actor.principal),&json!({"revision":revision,"reason":movement.reason}),&now]).await?;
            audit.record(event_id,json!({"event":"casework.review-caseload-moved","reviewRequestId":request_id,"reviewTaskId":task.task_id,"taskRevision":revision,"profileId":actor.profile_id}))?;
            moved.push(ReviewCaseloadTask {
                task_id: task.task_id,
                revision,
            });
        }
        let result = ReviewCaseloadResult { moved };
        finish_staffing_preview(&tx, request.preview_id, &serde_json::to_value(&result)?).await?;
        audit.commit(tx).await?;
        Ok(result)
    }
}

async fn lock_staffing_directory(tx: &Transaction<'_>) -> Result<i64, ReviewRuntimeError> {
    Ok(tx
        .query_one(
            "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
            &[],
        )
        .await?
        .get(0))
}
async fn lock_staffing_preview(
    tx: &Transaction<'_>,
    actor: &ActorContext,
    id: Uuid,
    kind: &str,
) -> Result<Option<Value>, ReviewRuntimeError> {
    let row=tx.query_opt("SELECT response FROM casework_review_staffing_previews WHERE preview_id=$1 AND kind=$2 AND issuer=$3 AND subject=$4 AND profile_id=$5 AND expires_at>now() FOR UPDATE",&[&id,&kind,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id]).await?.ok_or(ReviewRuntimeError::ResultExpired)?;
    Ok(row.get(0))
}
/// Store the applied result and keep it for 24 hours, so a retry of the same
/// preview after a lost response recovers the committed outcome.
async fn finish_staffing_preview(
    tx: &Transaction<'_>,
    id: Uuid,
    response: &Value,
) -> Result<(), ReviewRuntimeError> {
    tx.execute("UPDATE casework_review_staffing_previews SET applied_at=now(),response=$2,expires_at=now()+interval '24 hours' WHERE preview_id=$1",&[&id,&response]).await?;
    Ok(())
}

impl PostgresStore {
    async fn staffing_preview<R: serde::de::DeserializeOwned, T: serde::de::DeserializeOwned>(
        &self,
        actor: &ActorContext,
        id: Uuid,
        kind: &str,
    ) -> Result<(R, Vec<T>, i64), ReviewRuntimeError> {
        let client = self.client().await?;
        let row=client.query_opt("SELECT request,tasks,directory_revision FROM casework_review_staffing_previews WHERE preview_id=$1 AND kind=$2 AND issuer=$3 AND subject=$4 AND profile_id=$5 AND expires_at>now()",&[&id,&kind,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id]).await?.ok_or(ReviewRuntimeError::ResultExpired)?;
        Ok((
            serde_json::from_value(row.get(0))?,
            serde_json::from_value(row.get(1))?,
            row.get(2),
        ))
    }
}
async fn validate_caseload_set(
    tx: &Transaction<'_>,
    actor: &ActorContext,
    movement: &ReviewCaseloadMoveRequest,
    tasks: &[ReviewCaseloadTask],
) -> Result<(), ReviewRuntimeError> {
    // Lock all requests before tasks, in the same order used by decision/cancellation.
    let ids = tasks.iter().map(|t| t.task_id).collect::<Vec<_>>();
    let rows=tx.query("SELECT r.request_id FROM casework_review_requests r WHERE r.request_id IN(SELECT request_id FROM casework_review_tasks WHERE task_id=ANY($1)) ORDER BY r.request_id FOR UPDATE",&[&ids]).await?;
    let requests = rows
        .into_iter()
        .map(|r| r.get::<_, Uuid>(0))
        .collect::<BTreeSet<_>>();
    let mut selected_stages = BTreeSet::new();
    for task in tasks {
        let row=tx.query_opt("SELECT request_id,stage_index,queue_id,revision,holder_issuer,holder_subject FROM casework_review_tasks WHERE task_id=$1 AND state='claimed' FOR UPDATE",&[&task.task_id]).await?.ok_or(ReviewRuntimeError::RevisionConflict)?;
        let request_id: Uuid = row.get(0);
        if !requests.contains(&request_id) {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        let record = load_request_by_id(tx, request_id, false).await?;
        let stage_index =
            u16::try_from(row.get::<_, i32>(1)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        if !selected_stages.insert((request_id, stage_index)) {
            return Err(ReviewRuntimeError::Forbidden);
        }
        let queue: String = row.get(2);
        if record.lifecycle != ReviewRequestLifecycle::Reviewing
            || record.active_stage != Some(stage_index)
            || row.get::<_, i64>(3) != task.revision
            || row.get::<_, Option<String>>(4).as_deref() != Some(&movement.from.issuer)
            || row.get::<_, Option<String>>(5).as_deref() != Some(&movement.from.subject)
            || movement.queue.as_ref().is_some_and(|q| q != &queue)
        {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        ensure_actor_serves_review_queue(tx, actor, &queue).await?;
        let stage = record
            .policy
            .stages
            .get(usize::from(stage_index))
            .ok_or(ReviewRuntimeError::Corrupt)?;
        let membership_kinds = record
            .policy
            .dependencies
            .access_profiles
            .iter()
            .filter(|profile| stage.deciding_profiles.contains(&profile.id))
            .filter_map(|profile| match profile.role {
                CaseworkRole::Staff => Some("staff".to_owned()),
                CaseworkRole::Supervisor => Some("supervisor".to_owned()),
                CaseworkRole::Administrator | CaseworkRole::Requester => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if membership_kinds.is_empty() {
            return Err(ReviewRuntimeError::Corrupt);
        }
        // Absence can become active without a Directory write. Check after
        // acquiring task locks and refuse the named target rather than
        // silently redirecting an exact previewed move set.
        if !active_review_absences(tx, &movement.to, Utc::now())
            .await?
            .is_empty()
        {
            return Err(ReviewRuntimeError::Forbidden);
        }
        ensure_review_identity_eligible(
            tx,
            &record,
            stage,
            stage_index,
            &movement.to,
            &queue,
            &membership_kinds,
        )
        .await?;
        if tx.query_opt("SELECT 1 FROM casework_review_tasks WHERE request_id=$1 AND stage_index=$2 AND task_id<>$3 AND holder_issuer=$4 AND holder_subject=$5 AND state IN('open','claimed')",&[&request_id,&i32::from(stage_index),&task.task_id,&movement.to.issuer,&movement.to.subject]).await?.is_some(){return Err(ReviewRuntimeError::Forbidden)}
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClockCalculationPlan {
    occurrence_id: Uuid,
    updated_at: DateTime<Utc>,
    holiday: HolidaySetDocument,
    due_at: DateTime<Utc>,
    at_risk_at: Option<DateTime<Utc>>,
    reminders: Vec<ReminderOccurrence>,
    steps: Vec<StepOccurrence>,
    next_action_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClockPreviewInputs {
    request: ReviewClockRecomputeRequest,
    calculations: Vec<ClockCalculationPlan>,
}

impl CaseworkService {
    pub async fn preview_review_clock_recompute(
        &self,
        actor: &ActorContext,
        source_profile: Option<&str>,
        token: &str,
        request: ReviewClockRecomputeRequest,
    ) -> Result<ReviewClockRecomputePreview, ReviewRuntimeError> {
        request.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        if actor.role != CaseworkRole::Administrator {
            return Err(ReviewRuntimeError::Forbidden);
        }
        for id in &request.task_ids {
            let record = self.store.review_request_for_task(*id).await?;
            self.preflight_review_record_source(
                &record,
                if matches!(record.policy.context, ReviewContextPolicy::Submitted) {
                    None
                } else {
                    source_profile
                },
                token,
            )
            .await?;
        }
        let mut client = self.store.client().await?;
        let tx = client.transaction().await?;
        let directory_revision = lock_staffing_directory(&tx).await?;
        let mut ids = request.task_ids.clone();
        ids.sort_unstable();
        let mut tasks = Vec::new();
        let mut calculations = Vec::new();
        for task_id in ids {
            let row=tx.query_opt("SELECT t.request_id,t.revision FROM casework_review_tasks t JOIN casework_review_requests r ON r.request_id=t.request_id WHERE t.task_id=$1 AND t.state IN('open','claimed') AND r.lifecycle='reviewing' AND t.stage_index=r.active_stage_index FOR SHARE OF r,t",&[&task_id]).await?.ok_or(ReviewRuntimeError::NotFound)?;
            let request_id: Uuid = row.get(0);
            let record = load_request_by_id(&tx, request_id, false).await?;
            let plans = calculate_review_clocks(&tx, &record, task_id).await?;
            let subject_due:Option<DateTime<Utc>>=tx.query_one("SELECT min(due_at) FROM casework_review_clock_occurrences WHERE request_id=$1 AND scope='subject' AND state='running'",&[&request_id]).await?.get(0);
            let deadline_at = plans.iter().map(|p| p.due_at).chain(subject_due).min();
            tasks.push(ReviewClockRecomputeTask {
                task_id,
                revision: row.get(1),
                deadline_at,
            });
            calculations.extend(plans);
        }
        let expires_at = Utc::now() + chrono::TimeDelta::minutes(15);
        let preview_id = Uuid::new_v4();
        let inputs = ClockPreviewInputs {
            request,
            calculations,
        };
        tx.execute("INSERT INTO casework_review_staffing_previews(preview_id,kind,issuer,subject,profile_id,directory_revision,request,tasks,expires_at) VALUES($1,'clock',$2,$3,$4,$5,$6,$7,$8)",&[&preview_id,&actor.principal.issuer,&actor.principal.subject,&actor.profile_id,&directory_revision,&serde_json::to_value(inputs)?,&serde_json::to_value(&tasks)?,&expires_at]).await?;
        tx.commit().await?;
        Ok(ReviewClockRecomputePreview {
            preview_id,
            directory_revision,
            tasks,
            expires_at,
        })
    }
    pub async fn apply_review_clock_recompute(
        &self,
        actor: &ActorContext,
        source_profile: Option<&str>,
        token: &str,
        request: ReviewClockRecomputeApplyRequest,
    ) -> Result<ReviewClockRecomputeResult, ReviewRuntimeError> {
        request.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        if actor.role != CaseworkRole::Administrator {
            return Err(ReviewRuntimeError::Forbidden);
        }
        let (inputs, tasks, directory_revision) = self
            .store
            .staffing_preview::<ClockPreviewInputs, ReviewClockRecomputeTask>(
                actor,
                request.preview_id,
                "clock",
            )
            .await?;
        for task in &tasks {
            let record = self.store.review_request_for_task(task.task_id).await?;
            self.preflight_review_record_source(
                &record,
                if matches!(record.policy.context, ReviewContextPolicy::Submitted) {
                    None
                } else {
                    source_profile
                },
                token,
            )
            .await?;
        }
        let mut audit = self
            .store
            .begin_audit(crate::audit::request_record(
                "review-clocks-recomputed",
                Some(actor),
                &actor.profile_id,
                json!({"previewId":request.preview_id}),
            ))
            .await?;
        let mut client = self.store.client().await?;
        let tx = client.transaction().await?;
        let current_directory = lock_staffing_directory(&tx).await?;
        // An applied preview answers its stored result even after the
        // Directory moved on; only a pending apply is fenced by revision.
        if let Some(response) =
            lock_staffing_preview(&tx, actor, request.preview_id, "clock").await?
        {
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(tx).await?;
            return Ok(serde_json::from_value(response)?);
        }
        if current_directory != directory_revision {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        let task_ids = tasks.iter().map(|t| t.task_id).collect::<Vec<_>>();
        tx.query("SELECT request_id FROM casework_review_requests WHERE request_id IN(SELECT request_id FROM casework_review_tasks WHERE task_id=ANY($1)) ORDER BY request_id FOR UPDATE",&[&task_ids]).await?;
        for task in &tasks {
            let row=tx.query_opt("SELECT t.request_id FROM casework_review_tasks t JOIN casework_review_requests r ON r.request_id=t.request_id WHERE t.task_id=$1 AND t.revision=$2 AND t.state IN('open','claimed') AND r.lifecycle='reviewing' AND t.stage_index=r.active_stage_index FOR UPDATE OF t",&[&task.task_id,&task.revision]).await?.ok_or(ReviewRuntimeError::RevisionConflict)?;
            let _: Uuid = row.get(0);
        }
        // The holiday revision is an explicit recompute input. New publication after
        // preview requires another preview; no accepted calculation is silently replaced.
        for plan in &inputs.calculations {
            let current=tx.query_opt("SELECT updated_at FROM casework_review_clock_occurrences WHERE clock_occurrence_id=$1 FOR UPDATE",&[&plan.occurrence_id]).await?.ok_or(ReviewRuntimeError::RevisionConflict)?;
            let revision: Option<i64> = tx
                .query_one(
                    "SELECT max(revision) FROM casework_holiday_sets WHERE holiday_set=$1",
                    &[&plan.holiday.holiday_set],
                )
                .await?
                .get(0);
            if current.get::<_, DateTime<Utc>>(0) != plan.updated_at
                || revision
                    != Some(
                        i64::try_from(plan.holiday.revision)
                            .map_err(|_| ReviewRuntimeError::Corrupt)?,
                    )
            {
                return Err(ReviewRuntimeError::RevisionConflict);
            }
        }
        let now = Utc::now();
        for plan in &inputs.calculations {
            tx.execute("UPDATE casework_review_clock_occurrences SET state='running',holiday_document=$2,due_at=$3,at_risk_at=$4,reminders=$5,steps=$6,next_action_at=$7,updated_at=$8 WHERE clock_occurrence_id=$1",&[&plan.occurrence_id,&serde_json::to_value(&plan.holiday)?,&plan.due_at,&plan.at_risk_at,&serde_json::to_value(&plan.reminders)?,&serde_json::to_value(&plan.steps)?,&plan.next_action_at,&now]).await?;
        }
        let mut completed = Vec::new();
        for task in tasks {
            let row=tx.query_one("UPDATE casework_review_tasks SET deadline_at=$2,revision=revision+1,updated_at=$3 WHERE task_id=$1 RETURNING request_id,revision",&[&task.task_id,&task.deadline_at,&now]).await?;
            let request_id: Uuid = row.get(0);
            let revision: i64 = row.get(1);
            let event_id = Uuid::new_v4();
            tx.execute("INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at) VALUES($1,$2,$3,'clocks-recomputed',$4,$5,$6)",&[&event_id,&request_id,&task.task_id,&actor_reference(&actor.principal),&json!({"revision":revision,"deadlineAt":task.deadline_at}),&now]).await?;
            audit.record(event_id,json!({"event":"casework.review-clocks-recomputed","reviewRequestId":request_id,"reviewTaskId":task.task_id,"taskRevision":revision,"profileId":actor.profile_id}))?;
            completed.push(ReviewClockRecomputeTask { revision, ..task });
        }
        let result = ReviewClockRecomputeResult { tasks: completed };
        finish_staffing_preview(&tx, request.preview_id, &serde_json::to_value(&result)?).await?;
        audit.commit(tx).await?;
        Ok(result)
    }
}
async fn calculate_review_clocks(
    tx: &Transaction<'_>,
    record: &ReviewRequestRecord,
    task_id: Uuid,
) -> Result<Vec<ClockCalculationPlan>, ReviewRuntimeError> {
    let rows=tx.query("SELECT clock_occurrence_id,policy,anchor_at,updated_at FROM casework_review_clock_occurrences WHERE request_id=$1 AND task_id=$2 AND scope='activity' AND state IN('running','source-facts-missing') ORDER BY clock_occurrence_id FOR SHARE",&[&record.request_id,&task_id]).await?;
    let mut plans = Vec::new();
    for row in rows {
        let definition: ReviewClockDefinition = serde_json::from_value(row.get(1))?;
        let calendar = definition
            .calendar
            .as_ref()
            .ok_or(ReviewRuntimeError::Corrupt)?;
        if !record
            .policy
            .dependencies
            .clocks
            .contains(&definition.clock)
            || !record.policy.dependencies.calendars.contains(calendar)
        {
            return Err(ReviewRuntimeError::Corrupt);
        }
        let holiday_row=tx.query_opt("SELECT document FROM casework_holiday_sets WHERE holiday_set=$1 ORDER BY revision DESC LIMIT 1",&[&calendar.holiday_set]).await?.ok_or(ReviewRuntimeError::Invalid)?;
        let holiday: HolidaySetDocument = serde_json::from_value(holiday_row.get(0))?;
        let evaluated = evaluate_stage_clock(&definition.clock, calendar, &holiday, row.get(2))
            .map_err(|error| clock_evaluation_error(&definition.clock, error))?;
        let occurrence_id: Uuid = row.get(0);
        let applied=tx.query("SELECT effect_kind,effect_id FROM casework_review_clock_effects WHERE clock_occurrence_id=$1",&[&occurrence_id]).await?.into_iter().map(|r|(r.get::<_,String>(0),r.get::<_,String>(1))).collect();
        let next_action_at =
            next_review_clock_action(&evaluated.reminders, &evaluated.steps, &applied);
        plans.push(ClockCalculationPlan {
            occurrence_id,
            updated_at: row.get(3),
            holiday,
            due_at: evaluated.due_at,
            at_risk_at: evaluated.at_risk_at,
            reminders: evaluated.reminders,
            steps: evaluated.steps,
            next_action_at,
        });
    }
    Ok(plans)
}

impl CaseworkService {
    pub async fn erase_expired_review_staffing(&self) -> Result<u64, ReviewRuntimeError> {
        let mut audit = self.store.begin_background_audit().await?;
        let mut client = self.store.client().await?;
        let transaction = client.transaction().await?;
        let mut erased = 0;
        for table in [
            "casework_review_staffing_previews",
            "casework_review_staffing_cursors",
            "casework_review_cursors",
        ] {
            let sql = format!(
                "DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} WHERE expires_at<=now() LIMIT 1000 FOR UPDATE SKIP LOCKED)"
            );
            erased += transaction.execute(&sql, &[]).await?;
        }
        if erased > 0 {
            audit.record(
                Uuid::new_v4(),
                json!({"event":"casework.review-discovery-retention-erased","profileId":"system:review-retention","erasedCount":erased}),
            )?;
        }
        audit.commit(transaction).await?;
        Ok(erased)
    }
}

fn staffing_position(task: &ReviewTask) -> Value {
    json!({"revision": task.revision, "deadlineAt": task.deadline_at, "createdAt": task.created_at, "taskId": task.task_id,
        "source": task.subject.source, "type": task.subject.subject_type, "id": task.subject.id,
        "version": task.subject.version, "digest": task.subject.digest.as_str()})
}
