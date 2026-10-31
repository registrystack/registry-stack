// SPDX-License-Identifier: Apache-2.0
//! Bounded, invocation-local source observations and set-based inbox hydration.
use super::*;
use futures::{stream, FutureExt, StreamExt};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct InboxObservations {
    human: BTreeMap<Uuid, Result<HumanDisplayObservation, ReviewContextError>>,
    status: BTreeMap<Uuid, Result<ServiceStatusObservation, ReviewContextError>>,
}

#[derive(Clone, Copy)]
pub(super) struct InboxDisplayCredential<'a> {
    token: &'a str,
    delegated: Option<&'a DelegatedCredentialContext>,
}

impl<'a> InboxDisplayCredential<'a> {
    pub(super) fn new(token: &'a str, delegated: Option<&'a DelegatedCredentialContext>) -> Self {
        Self { token, delegated }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct InboxRefusalSummary {
    concealed: bool,
    denied: bool,
    binding_moved: bool,
    contract_changed: bool,
}

impl InboxRefusalSummary {
    fn observe(&mut self, error: ReviewContextError) {
        match error {
            ReviewContextError::Concealed => self.concealed = true,
            ReviewContextError::Denied => self.denied = true,
            ReviewContextError::BindingMoved => self.binding_moved = true,
            ReviewContextError::ContractChanged => self.contract_changed = true,
            ReviewContextError::Unavailable
            | ReviewContextError::Unsupported
            | ReviewContextError::VersionMismatch
            | ReviewContextError::VersionUnavailable
            | ReviewContextError::Invalid => {}
        }
    }

    fn has_actionable_refusal(self) -> bool {
        self.denied || self.contract_changed
    }

    fn has_refusal(self) -> bool {
        self.concealed || self.denied || self.binding_moved || self.contract_changed
    }
}

impl InboxObservations {
    pub(super) fn source_reads(&self) -> usize {
        self.human.len()
    }

    pub(super) fn log_refusal_summary(&self, source_profile_required: bool) {
        let mut summary = InboxRefusalSummary::default();
        for error in self
            .human
            .values()
            .filter_map(|observation| observation.as_ref().err())
        {
            summary.observe(*error);
        }
        if !summary.has_refusal() && !source_profile_required {
            return;
        }
        if summary.has_actionable_refusal() || source_profile_required {
            tracing::warn!(
                source_concealed = summary.concealed,
                source_denied = summary.denied,
                source_binding_moved = summary.binding_moved,
                source_contract_changed = summary.contract_changed,
                source_profile_required,
                "Casework review inbox omitted current-source work after an explicit provider or configuration refusal"
            );
        } else {
            tracing::info!(
                source_concealed = summary.concealed,
                source_denied = summary.denied,
                source_binding_moved = summary.binding_moved,
                source_contract_changed = summary.contract_changed,
                source_profile_required,
                "Casework review inbox omitted current-source work during expected concealment or source authorization filtering"
            );
        }
    }

    pub(super) async fn prepare(
        &mut self,
        service: &CaseworkService,
        records: &BTreeMap<Uuid, ReviewRequestRecord>,
        profile: Option<&str>,
        credential: InboxDisplayCredential<'_>,
        deadline: tokio::time::Instant,
        with_status: bool,
    ) -> Result<(), ReviewRuntimeError> {
        let Some(profile) = profile else {
            return Ok(());
        };
        let mut groups: BTreeMap<String, Vec<(Uuid, ReviewContextIdentity)>> = BTreeMap::new();
        for (id, record) in records {
            if self.human.contains_key(id) {
                continue;
            }
            if let ReviewContextPolicy::CurrentSource { provider, contract } =
                &record.policy.context
            {
                groups.entry(provider.clone()).or_default().push((
                    *id,
                    ReviewContextIdentity {
                        subject: record.subject.clone(),
                        contract: contract.clone(),
                    },
                ));
            }
        }
        let needed: usize = groups.values().map(Vec::len).sum();
        if self.human.len() + needed > service.project.inbox.maximum_source_reads {
            return Err(ReviewRuntimeError::QueryTooBroad);
        }
        let concurrency = service.project.inbox.maximum_concurrent_source_reads;
        let mut batches = Vec::new();
        for (provider_id, entries) in groups {
            let provider = service
                .providers
                .get(&provider_id)
                .ok_or(ReviewRuntimeError::SourceUnavailable)?;
            // Legacy supervision feeds can return a partial deadline page.
            // Keep completed request observations available independently there.
            let chunk_size = if with_status { 1 } else { 100 };
            for entries in entries.chunks(chunk_size) {
                batches.push((provider.clone(), entries.to_vec()));
            }
        }
        let mut jobs = Vec::new();
        for (provider, entries) in batches {
            jobs.push(
                async move {
                    let identities = entries
                        .iter()
                        .map(|(_, identity)| identity.clone())
                        .collect::<Vec<_>>();
                    let observations = tokio::time::timeout_at(deadline, async {
                        match credential.delegated {
                            Some(context) => {
                                provider
                                    .delegated_display_batch(
                                        &identities,
                                        profile,
                                        EphemeralCredential::new(credential.token),
                                        context,
                                    )
                                    .await
                            }
                            None => {
                                provider
                                    .human_display_batch(
                                        &identities,
                                        profile,
                                        EphemeralCredential::new(credential.token),
                                    )
                                    .await
                            }
                        }
                    })
                    .await
                    .map_err(|_| ReviewRuntimeError::SourceUnavailable)?;
                    if observations.len() != entries.len() {
                        return Err(ReviewRuntimeError::SourceInvalid);
                    }
                    let mut results = Vec::with_capacity(entries.len());
                    for ((id, identity), observation) in entries.into_iter().zip(observations) {
                        let status = if with_status && observation.is_ok() {
                            Some(
                                tokio::time::timeout_at(
                                    deadline,
                                    provider.service_status(&identity),
                                )
                                .await
                                .map_err(|_| ReviewRuntimeError::SourceUnavailable)?,
                            )
                        } else {
                            None
                        };
                        results.push((id, observation, status));
                    }
                    Ok(results)
                }
                .boxed(),
            );
        }
        let mut pending = stream::iter(jobs).buffered(concurrency);
        while let Some(results) = pending.next().await {
            for (id, observation, status) in results? {
                if let Some(status) = status {
                    self.status.insert(id, status);
                }
                self.human.insert(id, observation);
            }
        }
        Ok(())
    }

    pub(super) fn complete(&self, record: &ReviewRequestRecord) -> bool {
        !matches!(
            record.policy.context,
            ReviewContextPolicy::CurrentSource { .. }
        ) || self
            .human
            .get(&record.request_id)
            .is_some_and(|observation| {
                observation.is_err() || self.status.contains_key(&record.request_id)
            })
    }

    pub(super) fn display(
        &self,
        record: &ReviewRequestRecord,
        profile: Option<&str>,
        reviewable: bool,
        with_status: bool,
    ) -> Result<Option<String>, ReviewRuntimeError> {
        let ReviewContextPolicy::CurrentSource { contract, .. } = &record.policy.context else {
            return Ok(Some(record.requester_reference.clone()));
        };
        profile.ok_or(ReviewRuntimeError::SourceProfileRequired)?;
        let identity = ReviewContextIdentity {
            subject: record.subject.clone(),
            contract: contract.clone(),
        };
        let view = self
            .human
            .get(&record.request_id)
            .ok_or(ReviewRuntimeError::Corrupt)?
            .as_ref()
            .map_err(|error| map_review_source_error(*error))?;
        if view.identity != identity || (reviewable && !view.reviewable) {
            return Err(ReviewRuntimeError::NotFound);
        }
        record
            .policy
            .validate_display(&serde_json::to_value(&view.fields)?)
            .map_err(|error| invalid_provider_display(&record.policy, error))?;
        if view
            .display_reference
            .as_ref()
            .is_some_and(|value| value.len() > 256 || value.chars().any(char::is_control))
        {
            return Err(ReviewRuntimeError::SourceInvalid);
        }
        if with_status {
            let status = self
                .status
                .get(&record.request_id)
                .ok_or(ReviewRuntimeError::Corrupt)?
                .as_ref()
                .map_err(|error| map_review_source_error(*error))?;
            if status.identity != identity || (reviewable && !status.reviewable) {
                return Err(ReviewRuntimeError::NotFound);
            }
        }
        Ok(view.display_reference.clone())
    }
}

impl PostgresStore {
    pub(super) async fn inbox_records(
        &self,
        tasks: &[ReviewTask],
    ) -> Result<BTreeMap<Uuid, ReviewRequestRecord>, ReviewRuntimeError> {
        let ids = tasks
            .iter()
            .map(|task| task.request_id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let client = self.client().await?;
        client
            .query(&request_query("request_id=ANY($1)"), &[&ids])
            .await?
            .iter()
            .map(|row| request_from_row(row).map(|record| (record.request_id, record)))
            .collect()
    }
}

impl PostgresStore {
    pub(super) async fn inbox_current_tasks(
        &self,
        actor: &ActorContext,
        task_ids: &[Uuid],
        active_only: bool,
        supervisory: bool,
    ) -> Result<BTreeMap<Uuid, ReviewTask>, ReviewRuntimeError> {
        let membership = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator | CaseworkRole::Requester => {
                return Err(ReviewRuntimeError::Forbidden);
            }
        };
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT DISTINCT t.task_id,t.request_id,t.stage_index,t.stage_id,t.queue_id,t.state,
                        t.holder_issuer,t.holder_subject,t.revision,r.policy_snapshot,
                        r.lifecycle,r.result_available_until,r.result_erased_at,
                        d.decision,d.outcome,d.decided_at,
                        r.subject_source,r.subject_type,r.subject_id,r.subject_version,r.subject_digest,r.requester_reference,t.deadline_at,t.created_at,t.staffing_diagnostic
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 JOIN casework_queue_service q ON q.queue_id=t.queue_id
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 LEFT JOIN casework_review_decisions d ON d.task_id=t.task_id
                     AND d.actor_issuer=$2 AND d.actor_subject=$3
                 WHERE t.task_id=ANY($1) AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4
                   AND (NOT $5 OR (r.lifecycle='reviewing'
                       AND t.stage_index=r.active_stage_index
                       AND t.state IN ('open','claimed')))",
                &[
                    &task_ids,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                    &active_only,
                ],
            )
            .await?;
        let mut tasks = BTreeMap::new();
        for row in rows {
            if row.get::<_, String>(10) != "reviewing"
                && (row.get::<_, Option<DateTime<Utc>>>(12).is_some()
                    || row
                        .get::<_, Option<DateTime<Utc>>>(11)
                        .is_none_or(|available_until| available_until <= Utc::now()))
            {
                continue;
            }
            let policy: ReviewPolicyClosure = serde_json::from_value(row.get(9))?;
            let stage_index =
                u16::try_from(row.get::<_, i32>(2)).map_err(|_| ReviewRuntimeError::Corrupt)?;
            if !supervisory
                && policy
                    .stages
                    .get(usize::from(stage_index))
                    .is_none_or(|stage| !stage.deciding_profiles.contains(&actor.profile_id))
            {
                continue;
            }
            let mut task = reviewer_task_from_row(&row, &policy)?;
            // Only the caller's own decision is compared, so the read confirms a
            // lost decide response without naming any other reviewer.
            if !active_only && !supervisory && task.state == ReviewTaskState::Decided {
                let decision = row.get::<_, Option<String>>(13);
                task.decided_by_caller = Some(decision.is_some());
                if let Some(decision) = decision {
                    task.decision_receipt = Some(review_decision_receipt(
                        &policy,
                        &decision,
                        row.get(14),
                        row.get::<_, Option<DateTime<Utc>>>(15)
                            .ok_or(ReviewRuntimeError::Corrupt)?,
                    )?);
                }
            }
            tasks.insert(task.task_id, task);
        }
        let shortfalls = review_task_staffing_shortfalls(&client, task_ids).await?;
        for task in tasks.values_mut() {
            current_staffing_diagnostic(
                task,
                shortfalls.get(&task.task_id).copied().unwrap_or(false),
            );
        }
        Ok(tasks)
    }
}

impl PostgresStore {
    pub(super) async fn staffing_candidates(
        &self,
        actor: &ActorContext,
        query: &ReviewStaffingQuery,
        after: &Option<Value>,
        limit: usize,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        let queue = query.queue.as_deref();
        let view = ReviewTaskListView::Reviewer(query.ownership);
        let subject_binding = query.subject().map_err(|_| ReviewRuntimeError::Invalid)?;
        let subject = subject_binding.as_ref();
        let membership = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator | CaseworkRole::Requester => {
                return Err(ReviewRuntimeError::Forbidden);
            }
        };
        let supervisory = view.is_supervisory();
        let ownership = match view.ownership() {
            None => None,
            Some(ReviewTaskOwnership::AssignedToMe) => Some("assigned-to-me"),
            Some(ReviewTaskOwnership::Unclaimed) => Some("unclaimed"),
        };
        let order = match query.sort {
            ReviewTaskSort::Due => {
                "COALESCE(t.deadline_at,'infinity'::timestamptz),t.created_at,t.task_id"
            }
            ReviewTaskSort::Subject => {
                "r.subject_source COLLATE \"C\",r.subject_type COLLATE \"C\",r.subject_id COLLATE \"C\",r.subject_version COLLATE \"C\",r.subject_digest COLLATE \"C\",t.created_at,t.task_id"
            }
            ReviewTaskSort::Reference => return Err(ReviewRuntimeError::Invalid),
        };
        let boundary = match query.sort {
            ReviewTaskSort::Due => {
                "(COALESCE(t.deadline_at,'infinity'::timestamptz),t.created_at,t.task_id) > (COALESCE(($5->>'deadlineAt')::timestamptz,'infinity'::timestamptz),($5->>'createdAt')::timestamptz,($5->>'taskId')::uuid)"
            }
            ReviewTaskSort::Subject => {
                "(r.subject_source COLLATE \"C\",r.subject_type COLLATE \"C\",r.subject_id COLLATE \"C\",r.subject_version COLLATE \"C\",r.subject_digest COLLATE \"C\",t.created_at,t.task_id) > ($5->>'source',$5->>'type',$5->>'id',$5->>'version',$5->>'digest',($5->>'createdAt')::timestamptz,($5->>'taskId')::uuid)"
            }
            ReviewTaskSort::Reference => return Err(ReviewRuntimeError::Invalid),
        };
        let client = self.client().await?;
        let rows = client
            .query(
                &format!("SELECT t.task_id,t.request_id,t.stage_index,t.stage_id,t.queue_id,t.state,
                        t.holder_issuer,t.holder_subject,t.revision,r.policy_snapshot,
                        r.subject_source,r.subject_type,r.subject_id,r.subject_version,r.subject_digest,r.requester_reference,t.deadline_at,t.created_at,t.staffing_diagnostic
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 WHERE NOT $6 AND r.result_erased_at IS NULL
                   AND (r.lifecycle='reviewing' OR r.result_available_until>now())
                   AND ($9 OR (r.lifecycle='reviewing' AND t.stage_index=r.active_stage_index
                               AND t.state IN ('open','claimed')))
                   AND EXISTS(SELECT 1 FROM casework_queue_service q JOIN casework_memberships m ON m.team_id=q.team_id WHERE q.queue_id=t.queue_id AND m.issuer=$1 AND m.subject=$2 AND m.membership_kind=$3)
                   AND ($4::text IS NULL OR t.queue_id=$4)
                   AND ($5::jsonb IS NULL OR {boundary})
                   AND ($9 OR ((r.policy_snapshot->'stages'->t.stage_index->'decidingProfiles') ? $8))
                   AND ($10::text IS NULL
                        OR ($10='unclaimed' AND t.state='open')
                        OR ($10='assigned-to-me' AND t.state='claimed'
                            AND t.holder_issuer=$1 AND t.holder_subject=$2))
                   AND ($11::uuid IS NULL OR t.request_id=$11)
                   AND ($12::text IS NULL OR (r.subject_source=$12 AND r.subject_type=$13
                        AND r.subject_id=$14 AND r.subject_version=$15 AND r.subject_digest=$16))
                 ORDER BY {order} LIMIT $7"),
                &[
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                    &queue,
                    &after,
                    &false,
                    &i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?,
                    &actor.profile_id,
                    &supervisory,
                    &ownership,
                    &view.request_id(),
                    &subject.map(|s|s.source.as_str()),
                    &subject.map(|s|s.subject_type.as_str()),
                    &subject.map(|s|s.id.as_str()),
                    &subject.map(|s|s.version.as_str()),
                    &subject.map(|s|s.digest.as_str()),
                ],
            )
            .await?;
        let mut items = rows
            .into_iter()
            .map(|row| {
                let policy = serde_json::from_value::<ReviewPolicyClosure>(row.get(9))?;
                reviewer_task_from_row(&row, &policy)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = (items.len() > limit).then(|| items[limit - 1].task_id);
        items.truncate(limit);
        Ok(ReviewTaskPage {
            items,
            next_cursor,
            status: PageStatus::Complete,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbox_refusal_summary_separates_routine_concealment_from_actionable_refusals() {
        let mut summary = InboxRefusalSummary::default();
        summary.observe(ReviewContextError::Concealed);
        summary.observe(ReviewContextError::BindingMoved);
        assert!(!summary.has_actionable_refusal());
        assert!(summary.concealed);
        assert!(summary.binding_moved);

        summary.observe(ReviewContextError::Denied);
        summary.observe(ReviewContextError::ContractChanged);
        assert!(summary.has_actionable_refusal());
        assert!(summary.denied);
        assert!(summary.contract_changed);

        let before = summary;
        for error in [
            ReviewContextError::Unavailable,
            ReviewContextError::Unsupported,
            ReviewContextError::VersionMismatch,
            ReviewContextError::VersionUnavailable,
            ReviewContextError::Invalid,
        ] {
            summary.observe(error);
        }
        assert_eq!(
            summary, before,
            "page-level failures have their own diagnostics"
        );
    }
}
