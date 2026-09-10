use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use registry_casework_core::{
    ActiveSubjectsPage, ActorContext, AttemptState, AttemptStatus, CallerSubjectView,
    CaseworkAction, CaseworkProject, ClockRuntimeState, DiscoveryCursor, Draft,
    EphemeralCredential, EventRequest, ExecutePreparedRequest, HistoryEntry, HoldingSummary,
    InboxPolicy, InboxView, MutationResponse, OccurrenceState, OperationName, Page, PageStatus,
    PrepareActionRequest, SourceAdapter, SourceAdapterError, SourceBinding, SourceReceipt,
    SubjectRef, WorkItem, WorkItemPage,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{PostgresStore, StoreError};

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceCursorContext<'a> {
    feed: &'static str,
    view: InboxView,
    queue: Option<&'a str>,
    subject: Option<&'a SubjectRef>,
    ordering: &'static str,
}

#[derive(Clone)]
pub struct CaseworkService {
    pub(crate) store: PostgresStore,
    adapters: Arc<BTreeMap<String, Arc<dyn SourceAdapter>>>,
    pub(crate) project: Arc<CaseworkProject>,
    audit_publisher_health: AuditPublisherHealth,
}

#[derive(Clone, Default)]
pub(crate) struct AuditPublisherHealth(Arc<AtomicBool>);

impl AuditPublisherHealth {
    pub(crate) fn mark_failed(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn mark_recovered(&self) {
        self.0.store(false, Ordering::Release);
    }

    pub(crate) fn is_ready(&self) -> bool {
        !self.0.load(Ordering::Acquire)
    }
}

impl std::fmt::Debug for CaseworkService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaseworkService")
            .field("sources", &self.adapters.keys())
            .field("project", &self.project.casework.id)
            .finish()
    }
}

impl CaseworkService {
    pub fn new(
        store: PostgresStore,
        project: CaseworkProject,
        adapters: impl IntoIterator<Item = Arc<dyn SourceAdapter>>,
    ) -> Result<Self, ServiceError> {
        let mut registered = BTreeMap::new();
        for adapter in adapters {
            if registered
                .insert(adapter.source_id().to_owned(), adapter)
                .is_some()
            {
                return Err(ServiceError::Configuration);
            }
        }
        if project
            .sources
            .iter()
            .any(|source| !registered.contains_key(&source.id))
        {
            return Err(ServiceError::Configuration);
        }
        let queues = project
            .queues
            .iter()
            .map(|queue| queue.id.clone())
            .collect();
        for source in &project.sources {
            for request in &source.requests {
                if request.routing.is_empty() && request.projection.is_empty() {
                    continue;
                }
                let metadata = registered[&source.id]
                    .routing_metadata()
                    .ok_or(ServiceError::Configuration)?;
                registry_casework_core::check_routing_policy(
                    &request.queue,
                    &request.projection,
                    &request.routing,
                    &queues,
                    Some(metadata),
                )
                .map_err(|_| ServiceError::Configuration)?;
            }
        }
        Ok(Self {
            store,
            adapters: Arc::new(registered),
            project: Arc::new(project),
            audit_publisher_health: AuditPublisherHealth::default(),
        })
    }

    #[must_use]
    pub fn store(&self) -> &PostgresStore {
        &self.store
    }

    pub(crate) fn audit_publisher_health(&self) -> AuditPublisherHealth {
        self.audit_publisher_health.clone()
    }

    pub async fn ready(&self) -> Result<(), ServiceError> {
        if !self.audit_publisher_health.is_ready() {
            return Err(StoreError::Unavailable.into());
        }
        self.store.ready().await?;
        Ok(())
    }

    pub async fn receive_event(
        &self,
        source_id: &str,
        request: EventRequest,
    ) -> Result<bool, ServiceError> {
        let adapter = self.adapter(source_id)?;
        let hint = match adapter.verify_transition(request).await {
            Ok(hint) => hint,
            Err(error) => {
                tracing::warn!(
                    source_id,
                    outcome = "refused",
                    reason = "verification",
                    "Casework source event refused"
                );
                return Err(error.into());
            }
        };
        if hint.subject.source_id != source_id {
            tracing::warn!(
                source_id,
                outcome = "refused",
                reason = "source_mismatch",
                "Casework source event refused"
            );
            return Err(ServiceError::SourceProtocol);
        }
        let accepted = self
            .store
            .ingest_transition(adapter.binding_generation(), &hint)
            .await
            .map_err(ServiceError::from)?;
        let event_id = bounded_event_identifier(&hint.deduplication_key);
        tracing::info!(
            source_id,
            event_id,
            event_id_truncated = hint.deduplication_key.len() > event_id.len(),
            source_revision = hint.ordered_revision,
            outcome = if accepted { "accepted" } else { "duplicate" },
            "Casework source event recorded"
        );
        if accepted {
            self.store
                .set_source_status(source_id, adapter.binding_generation(), false, false)
                .await?;
        }
        Ok(accepted)
    }

    /// Process queued invalidations with authoritative reads outside database
    /// transactions. The store rechecks generation and monotonic revision at
    /// commit, so delayed reads cannot replace a newer observation.
    pub async fn synchronize_pending(&self, maximum: i64) -> Result<usize, ServiceError> {
        let subjects = self.store.claim_sync_batch(maximum.min(100), 30).await?;
        let mut applied = 0;
        for subject in subjects {
            let adapter = self.adapter(&subject.source_id)?;
            match adapter.read_authoritative(&subject).await {
                Ok(observation) => {
                    let (routing, target) = self.routing_policy_for(&observation)?;
                    let routing_policy_digest =
                        routing_policy_digest(self.request_policy_for(&observation.subject)?)?;
                    let clock = self.clock_policy_for(&subject)?;
                    self.store
                        .apply_observation_with_policy_context(
                            &observation,
                            &routing.queue,
                            target,
                            Some(&routing),
                            Some(&routing_policy_digest),
                            clock.as_ref(),
                        )
                        .await?;
                    applied += 1;
                }
                Err(SourceAdapterError::Unavailable | SourceAdapterError::Concealed) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(applied)
    }

    async fn synchronize_source_pending(
        &self,
        source_id: &str,
        maximum: i64,
    ) -> Result<(usize, bool), ServiceError> {
        let adapter = self.adapter(source_id)?;
        let subjects = self
            .store
            .claim_source_sync_batch(
                source_id,
                adapter.binding_generation(),
                maximum.min(100),
                30,
            )
            .await?;
        let mut applied = 0;
        let mut unavailable = false;
        for subject in subjects {
            match adapter.read_authoritative(&subject).await {
                Ok(observation) => {
                    let (routing, target) = self.routing_policy_for(&observation)?;
                    let routing_policy_digest =
                        routing_policy_digest(self.request_policy_for(&observation.subject)?)?;
                    let clock = self.clock_policy_for(&subject)?;
                    self.store
                        .apply_observation_with_policy_context(
                            &observation,
                            &routing.queue,
                            target,
                            Some(&routing),
                            Some(&routing_policy_digest),
                            clock.as_ref(),
                        )
                        .await?;
                    applied += 1;
                }
                Err(SourceAdapterError::Unavailable | SourceAdapterError::Concealed) => {
                    unavailable = true
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok((applied, unavailable))
    }

    /// Run the two independent repair passes: remote-active discovery, then
    /// authoritative reads of every locally active subject.
    pub async fn reconcile_source(&self, source_id: &str) -> Result<usize, ServiceError> {
        let adapter = self.adapter(source_id)?;
        self.store
            .set_source_status(source_id, adapter.binding_generation(), false, false)
            .await?;
        let mut cursor: Option<DiscoveryCursor> = None;
        let mut discovered = 0;
        let mut discovery_error = None;
        let mut remote_complete = false;
        for _ in 0..100 {
            let ActiveSubjectsPage {
                subjects,
                next_cursor,
            } = match adapter.discover_active(cursor.as_ref(), 100).await {
                Ok(page) => page,
                Err(error) => {
                    self.store
                        .set_source_status(source_id, adapter.binding_generation(), false, true)
                        .await?;
                    discovery_error = Some(error);
                    break;
                }
            };
            self.store
                .enqueue_discovered(adapter.binding_generation(), &subjects)
                .await?;
            discovered += subjects.len();
            cursor = next_cursor;
            if cursor.is_none() {
                remote_complete = true;
                break;
            }
        }
        for subject in self.store.local_active_subjects(source_id, 10_000).await? {
            self.store
                .enqueue_discovered(adapter.binding_generation(), &[subject])
                .await?;
        }
        let (_, sync_unavailable) = self.synchronize_source_pending(source_id, 100).await?;
        if let Some(error) = discovery_error {
            return Err(error.into());
        }
        if sync_unavailable {
            self.store
                .set_source_status(source_id, adapter.binding_generation(), false, true)
                .await?;
            return Err(ServiceError::Adapter(SourceAdapterError::Unavailable));
        }
        let pending = self
            .store
            .source_has_pending(source_id, adapter.binding_generation())
            .await?;
        self.store
            .set_source_status(
                source_id,
                adapter.binding_generation(),
                remote_complete && !pending,
                false,
            )
            .await?;
        Ok(discovered)
    }

    pub async fn caller_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
        token: &str,
    ) -> Result<(WorkItem, CallerSubjectView), ServiceError> {
        let item = self.store.item(item_id).await?;
        if !self.store.can_view_item(actor, &item).await? {
            return Err(ServiceError::NotFound);
        }
        let view = self
            .adapter(&item.subject.source_id)?
            .read_for_caller(
                &item.subject,
                source_profile_id,
                EphemeralCredential::new(token),
            )
            .await?;
        let item = self
            .assemble_caller_visible_item(actor, item_id, source_profile_id, &view, None)
            .await?;
        Ok((item, view))
    }

    async fn assemble_caller_visible_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
        view: &CallerSubjectView,
        known_holder_timing: Option<(i64, Option<chrono::DateTime<chrono::Utc>>)>,
    ) -> Result<WorkItem, ServiceError> {
        // The source call is intentionally outside a database transaction.
        // Read local projections only after source disclosure succeeds, then
        // re-read the item last so an erasure committed during that work stays
        // the final visibility boundary.
        let item = self.store.item(item_id).await?;
        if !self.store.can_view_item(actor, &item).await? {
            return Err(ServiceError::NotFound);
        }
        let live_attempt = self
            .store
            .live_attempt_status_for_actor(actor, item_id, source_profile_id)
            .await?;
        let routing_copy = self.filtered_routing_copy(item_id, view).await?;
        let routing = self.store.work_item_routing(item_id).await?;
        let clock_occurrences = self.store.clock_occurrences_for_item(item_id).await?;
        let mut holder_timing = if let Some(timing) = known_holder_timing {
            Some(timing)
        } else {
            self.store
                .source_holder_timings(&[item_id])
                .await?
                .pop()
                .map(|(_, revision, held_since)| (revision, held_since))
        };

        let mut item = self.store.item(item_id).await?;
        if item.holder.is_some()
            && holder_timing
                .as_ref()
                .is_none_or(|(revision, _)| *revision != item.revision)
        {
            holder_timing = self
                .store
                .source_holder_timings(&[item_id])
                .await?
                .pop()
                .map(|(_, revision, held_since)| (revision, held_since));
            item = self.store.item(item_id).await?;
        }
        if !self.store.can_view_item(actor, &item).await? {
            return Err(ServiceError::NotFound);
        }
        item.held_since = if item.holder.is_some() {
            holder_timing
                .filter(|(revision, _)| *revision == item.revision)
                .and_then(|(_, held_since)| held_since)
        } else {
            None
        };
        item.live_attempt = live_attempt;
        if view.binding.generation != item.binding.generation {
            if item.live_attempt.is_some() {
                item.routing = routing;
                item.clock_occurrences = clock_occurrences;
                return Ok(item);
            }
            return Err(ServiceError::BindingMoved);
        }
        item.routing = routing;
        item.clock_occurrences = clock_occurrences;
        item.routing_copy = routing_copy;
        item.actions = local_actions(actor, &item, view);
        Ok(item)
    }

    pub async fn source_history(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
        token: &str,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Page<HistoryEntry>, ServiceError> {
        self.caller_item(actor, item_id, source_profile_id, token)
            .await?;
        self.store
            .history_page(actor, source_profile_id, item_id, limit, cursor)
            .await
            .map_err(ServiceError::from)
    }

    pub async fn erase_expired_source_history_cursors(&self) -> Result<usize, ServiceError> {
        self.store
            .erase_expired_source_history_cursors()
            .await
            .map_err(ServiceError::from)
    }

    pub async fn open_source_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
        token: &str,
    ) -> Result<WorkItem, ServiceError> {
        let item = self
            .caller_item(actor, item_id, source_profile_id, token)
            .await?
            .0;
        self.store.record_opened(actor, item_id).await?;
        Ok(item)
    }

    pub async fn claim_source_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        source_profile_id: &str,
        idempotency_key: &str,
        token: &str,
    ) -> Result<WorkItem, ServiceError> {
        self.preflight_source_claim(actor, item_id, expected_revision, idempotency_key)
            .await?;
        let (_, source) = self
            .caller_item(actor, item_id, source_profile_id, token)
            .await?;
        if source.permitted_operations.is_empty() {
            return Err(ServiceError::Forbidden);
        }
        self.store
            .claim(actor, item_id, expected_revision, idempotency_key)
            .await?;
        Ok(self
            .caller_item(actor, item_id, source_profile_id, token)
            .await?
            .0)
    }

    pub async fn release_source_item(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        source_profile_id: &str,
        idempotency_key: &str,
        token: &str,
    ) -> Result<WorkItem, ServiceError> {
        self.preflight_source_release(actor, item_id, expected_revision, idempotency_key)
            .await?;
        self.caller_item(actor, item_id, source_profile_id, token)
            .await?;
        self.store
            .release(actor, item_id, expected_revision, idempotency_key)
            .await?;
        Ok(self
            .caller_item(actor, item_id, source_profile_id, token)
            .await?
            .0)
    }

    pub async fn source_draft(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
        token: &str,
    ) -> Result<Draft, ServiceError> {
        self.caller_item(actor, item_id, source_profile_id, token)
            .await?;
        self.store
            .read_draft(actor, item_id)
            .await?
            .ok_or(ServiceError::NotFound)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn save_source_draft(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        source_profile_id: &str,
        binding: &SourceBinding,
        reason: &str,
        flagged_fields: &[String],
        idempotency_key: &str,
        token: &str,
    ) -> Result<Draft, ServiceError> {
        self.preflight_source_draft_save(
            actor,
            item_id,
            expected_revision,
            binding,
            reason,
            flagged_fields,
            idempotency_key,
        )
        .await?;
        self.caller_item(actor, item_id, source_profile_id, token)
            .await?;
        self.store
            .save_draft(
                actor,
                item_id,
                expected_revision,
                binding,
                reason,
                flagged_fields,
                idempotency_key,
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn delete_source_draft(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        source_profile_id: &str,
        idempotency_key: &str,
        token: &str,
    ) -> Result<(), ServiceError> {
        self.preflight_source_draft_delete(actor, item_id, expected_revision, idempotency_key)
            .await?;
        self.caller_item(actor, item_id, source_profile_id, token)
            .await?;
        self.store
            .delete_draft(actor, item_id, expected_revision, idempotency_key)
            .await?;
        Ok(())
    }

    pub async fn preflight_source_claim(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<(), ServiceError> {
        if actor.role != registry_casework_core::CaseworkRole::Staff {
            return Ok(());
        }
        self.store
            .preflight_erased_item_idempotency(
                actor,
                item_id,
                "item.claim",
                idempotency_key,
                &local_item_hash(item_id, expected_revision, true),
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn preflight_source_release(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<(), ServiceError> {
        if !matches!(
            actor.role,
            registry_casework_core::CaseworkRole::Staff
                | registry_casework_core::CaseworkRole::Supervisor
        ) {
            return Ok(());
        }
        self.store
            .preflight_erased_item_idempotency(
                actor,
                item_id,
                "item.release",
                idempotency_key,
                &local_item_hash(item_id, expected_revision, false),
            )
            .await
            .map_err(ServiceError::from)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn preflight_source_draft_save(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        binding: &SourceBinding,
        reason: &str,
        flagged_fields: &[String],
        idempotency_key: &str,
    ) -> Result<(), ServiceError> {
        if actor.role != registry_casework_core::CaseworkRole::Staff {
            return Ok(());
        }
        let hash = Sha256::digest(
            serde_json::to_vec(&(expected_revision, binding, reason, flagged_fields))
                .map_err(|_| ServiceError::Configuration)?,
        );
        self.store
            .preflight_erased_item_idempotency(
                actor,
                item_id,
                "draft.save",
                idempotency_key,
                &sha256_string(&hash),
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn preflight_source_draft_delete(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<(), ServiceError> {
        if actor.role != registry_casework_core::CaseworkRole::Staff {
            return Ok(());
        }
        let hash = Sha256::digest(format!("{item_id}:{expected_revision}:draft.delete"));
        self.store
            .preflight_erased_item_idempotency(
                actor,
                item_id,
                "draft.delete",
                idempotency_key,
                &sha256_string(&hash),
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn inbox(
        &self,
        actor: &ActorContext,
        source_profile_id: &str,
        token: &str,
        limit: usize,
        queue: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<WorkItemPage, ServiceError> {
        self.inbox_for_context(
            actor,
            source_profile_id,
            token,
            InboxView::MyTeams,
            limit,
            queue,
            None,
            cursor,
            "list",
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn inbox_for_view(
        &self,
        actor: &ActorContext,
        source_profile_id: &str,
        token: &str,
        view: InboxView,
        limit: usize,
        queue: Option<&str>,
        subject: Option<&SubjectRef>,
        cursor: Option<&str>,
    ) -> Result<WorkItemPage, ServiceError> {
        self.inbox_for_context(
            actor,
            source_profile_id,
            token,
            view,
            limit,
            queue,
            subject,
            cursor,
            "list",
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn inbox_for_context(
        &self,
        actor: &ActorContext,
        source_profile_id: &str,
        token: &str,
        view: InboxView,
        limit: usize,
        queue: Option<&str>,
        subject: Option<&SubjectRef>,
        cursor: Option<&str>,
        feed: &'static str,
    ) -> Result<WorkItemPage, ServiceError> {
        let policy = &self.project.inbox;
        let cursor_context = source_cursor_context(feed, view, queue, subject)?;
        let after = self
            .store
            .resolve_cursor(actor, source_profile_id, &cursor_context, cursor)
            .await?;
        let desired = limit.clamp(1, 100);
        let started = Instant::now();
        let deadline = Duration::from_millis(policy.page_deadline_milliseconds);
        let candidates = self
            .store
            .inbox_candidates_for_view(
                actor,
                view,
                policy.maximum_candidate_scan,
                after,
                queue,
                subject,
            )
            .await?;
        let candidate_ids = candidates
            .items
            .iter()
            .map(|candidate| candidate.item.item_id)
            .collect::<Vec<_>>();
        let holder_timings = self
            .store
            .source_holder_timings(&candidate_ids)
            .await?
            .into_iter()
            .map(|(item_id, revision, held_since)| (item_id, (revision, held_since)))
            .collect::<BTreeMap<_, _>>();
        let mut unavailable = false;
        let mut discovery_pending = false;
        let relevant_sources = self
            .project
            .sources
            .iter()
            .filter(|source| {
                subject.is_none_or(|subject| source.id == subject.source_id)
                    && source.requests.iter().any(|request| {
                        queue.is_none_or(|queue| request.queue == queue)
                            && subject.is_none_or(|subject| request.entity == subject.kind)
                    })
            })
            .collect::<Vec<_>>();
        if subject.is_none() {
            for source in &relevant_sources {
                let adapter = self.adapter(&source.id)?;
                let pending = self
                    .store
                    .source_has_pending(&source.id, adapter.binding_generation())
                    .await?;
                match self
                    .store
                    .source_status(&source.id, adapter.binding_generation())
                    .await?
                {
                    Some((true, false)) => {}
                    Some((_, true)) => unavailable = true,
                    _ => discovery_pending = true,
                }
                discovery_pending |= pending;
            }
        }
        if subject.is_none() && after.is_none() && candidates.items.is_empty() {
            unavailable = false;
            discovery_pending = false;
            for source in relevant_sources {
                let remaining = deadline.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    unavailable = true;
                    break;
                }
                match tokio::time::timeout(
                    remaining,
                    self.adapter(&source.id)?.discover_active(None, 1),
                )
                .await
                {
                    Ok(Ok(page)) => {
                        if !page.subjects.is_empty() {
                            self.store
                                .enqueue_discovered(
                                    self.adapter(&source.id)?.binding_generation(),
                                    &page.subjects,
                                )
                                .await?;
                        }
                        let complete = page.subjects.is_empty() && page.next_cursor.is_none();
                        self.store
                            .set_source_status(
                                &source.id,
                                self.adapter(&source.id)?.binding_generation(),
                                complete,
                                false,
                            )
                            .await?;
                        discovery_pending |= !complete;
                    }
                    Ok(Err(
                        SourceAdapterError::Unavailable
                        | SourceAdapterError::Concealed
                        | SourceAdapterError::Denied,
                    ))
                    | Err(_) => {
                        unavailable = true;
                        self.store
                            .set_source_status(
                                &source.id,
                                self.adapter(&source.id)?.binding_generation(),
                                false,
                                true,
                            )
                            .await?;
                    }
                    Ok(Err(error)) => return Err(error.into()),
                }
            }
        }
        let mut reads = 0;
        let mut examined = 0;
        let mut last_examined = after;
        let mut items = Vec::new();
        let candidate_count = candidates.items.len();
        for candidate in candidates.items {
            if items.len() == desired
                || reads == policy.maximum_source_reads
                || started.elapsed() >= deadline
            {
                break;
            }
            reads += 1;
            let item = candidate.item;
            let adapter = self.adapter(&item.subject.source_id)?;
            let remaining = deadline.saturating_sub(started.elapsed());
            let read = tokio::time::timeout(
                remaining,
                adapter.read_for_caller(
                    &item.subject,
                    source_profile_id,
                    EphemeralCredential::new(token),
                ),
            )
            .await;
            match read {
                Err(_) => {
                    unavailable = true;
                    break;
                }
                Ok(Ok(view)) => {
                    examined += 1;
                    last_examined = Some((
                        candidate.effective_due_at,
                        item.first_observed_at,
                        item.item_id,
                    ));
                    let item = match self
                        .assemble_caller_visible_item(
                            actor,
                            item.item_id,
                            source_profile_id,
                            &view,
                            holder_timings.get(&item.item_id).cloned(),
                        )
                        .await
                    {
                        Ok(current) => current,
                        Err(ServiceError::NotFound) => continue,
                        Err(error) => return Err(error),
                    };
                    items.push(item);
                }
                Ok(Err(SourceAdapterError::Concealed | SourceAdapterError::Denied)) => {
                    examined += 1;
                    last_examined = Some((
                        candidate.effective_due_at,
                        item.first_observed_at,
                        item.item_id,
                    ));
                }
                Ok(Err(SourceAdapterError::Unavailable)) => {
                    unavailable = true;
                    break;
                }
                Ok(Err(error)) => return Err(error.into()),
            }
        }
        let exhausted = reads == policy.maximum_source_reads
            || started.elapsed() >= deadline
            || discovery_pending
            || items.len() < desired && candidates.next_cursor.is_some();
        let status = if unavailable {
            PageStatus::SourceUnavailable
        } else if exhausted {
            PageStatus::BudgetExhausted
        } else {
            PageStatus::Complete
        };
        let unvisited =
            discovery_pending || examined < candidate_count || candidates.next_cursor.is_some();
        let next_cursor = if unvisited {
            Some(
                self.store
                    .issue_cursor(actor, source_profile_id, &cursor_context, last_examined)
                    .await?,
            )
        } else {
            None
        };
        let served_queues = match actor.role {
            registry_casework_core::CaseworkRole::Staff
            | registry_casework_core::CaseworkRole::Supervisor => {
                self.store.served_queues(actor).await?
            }
            registry_casework_core::CaseworkRole::Administrator
            | registry_casework_core::CaseworkRole::Requester => Vec::new(),
        };
        items.retain(|item| served_queues.binary_search(&item.queue_id).is_ok());
        Ok(WorkItemPage {
            items,
            next_cursor,
            status,
            served_queues,
        })
    }

    pub async fn next_item(
        &self,
        actor: &ActorContext,
        source_profile_id: &str,
        token: &str,
        queue: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<WorkItem, ServiceError> {
        let page = self
            .inbox_for_context(
                actor,
                source_profile_id,
                token,
                InboxView::MyTeams,
                1,
                queue,
                None,
                cursor,
                "next",
            )
            .await?;
        let item = if let Some(item) = page.items.into_iter().next() {
            item
        } else if page.status == PageStatus::Complete {
            return Err(ServiceError::NotFound);
        } else {
            return Err(ServiceError::Adapter(SourceAdapterError::Unavailable));
        };
        Ok(item)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn decide(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        source_profile_id: &str,
        operation: OperationName,
        reason: Option<&str>,
        flagged_fields: &[String],
        displayed_binding: &SourceBinding,
        idempotency_key: &str,
        token: &str,
    ) -> Result<(AttemptStatus, Option<SourceReceipt>), ServiceError> {
        let is_staff = actor.role == registry_casework_core::CaseworkRole::Staff;
        let request_hash = decision_hash(
            expected_revision,
            source_profile_id,
            &operation,
            reason,
            flagged_fields,
            displayed_binding,
        )?;
        if is_staff {
            self.store
                .preflight_erased_attempt(actor, item_id, idempotency_key, &request_hash)
                .await?;
        }
        let (item, view) = self
            .caller_item(actor, item_id, source_profile_id, token)
            .await?;
        if !is_staff {
            return Err(ServiceError::Forbidden);
        }
        if let Some(attempt) = self
            .store
            .attempt_by_key(actor, item_id, idempotency_key, &request_hash)
            .await?
        {
            return Ok((attempt.clone(), attempt.receipt));
        }
        if let Some(attempt_id) = self
            .store
            .live_attempt_for_actor(actor, item_id, source_profile_id)
            .await?
        {
            return Err(ServiceError::UncertainAttempt(attempt_id));
        }
        if item.state != OccurrenceState::Claimed
            || item.holder.as_ref() != Some(&actor.principal)
            || !view.permitted_operations.contains(&operation)
        {
            return Err(ServiceError::Forbidden);
        }
        let adapter = self.adapter(&item.subject.source_id)?;
        let prepared = adapter
            .prepare_action(PrepareActionRequest {
                subject: &item.subject,
                displayed_binding,
                operation: operation.clone(),
                reason,
                actor,
                source_profile_id,
                idempotency_key,
                credential: EphemeralCredential::new(token),
            })
            .await?;
        let reservation = self
            .store
            .reserve_attempt_for_execution(
                actor,
                item_id,
                expected_revision,
                source_profile_id,
                operation,
                reason,
                flagged_fields,
                idempotency_key,
                &request_hash,
                &prepared,
            )
            .await;
        let (attempt, execution_token) = match reservation {
            Ok(reservation) => reservation,
            Err(error @ StoreError::Conflict) => {
                if let Some(attempt_id) = self
                    .store
                    .live_attempt_for_actor(actor, item_id, source_profile_id)
                    .await?
                {
                    return Err(ServiceError::UncertainAttempt(attempt_id));
                }
                return Err(error.into());
            }
            Err(StoreError::AttemptPending) => {
                if let Some(attempt_id) = self
                    .store
                    .live_attempt_for_actor(actor, item_id, source_profile_id)
                    .await?
                {
                    return Err(ServiceError::UncertainAttempt(attempt_id));
                }
                return Err(ServiceError::Forbidden);
            }
            Err(error) => return Err(error.into()),
        };
        let execution = tokio::time::timeout(
            Duration::from_secs(300),
            adapter.execute_prepared(ExecutePreparedRequest {
                prepared: &prepared,
                execution: registry_casework_core::PreparedExecution::Initial,
                actor,
                source_profile_id,
                idempotency_key,
                credential: EphemeralCredential::new(token),
            }),
        )
        .await
        .unwrap_or(Err(SourceAdapterError::Uncertain));
        match execution {
            Ok(receipt) => {
                let settled = self
                    .store
                    .complete_attempt(actor, attempt.attempt_id, &receipt)
                    .await?;
                Ok((settled, Some(receipt)))
            }
            Err(SourceAdapterError::DefinitiveRefusal) => {
                if let Err(error) = self
                    .store
                    .refuse_original_attempt(actor, attempt.attempt_id, execution_token)
                    .await
                {
                    if matches!(error, StoreError::AttemptPending) {
                        return Err(ServiceError::UncertainAttempt(attempt.attempt_id));
                    }
                    return Err(error.into());
                }
                Err(ServiceError::Adapter(SourceAdapterError::DefinitiveRefusal))
            }
            Err(error) => {
                let unsettled = match self
                    .store
                    .mark_attempt_uncertain(actor, attempt.attempt_id, execution_token)
                    .await
                {
                    Ok(unsettled) => unsettled,
                    Err(StoreError::AttemptPending) => {
                        return Err(ServiceError::UncertainAttempt(attempt.attempt_id));
                    }
                    Err(error) => return Err(error.into()),
                };
                if error == SourceAdapterError::Uncertain {
                    Ok((unsettled, None))
                } else {
                    Err(ServiceError::UncertainAttempt(unsettled.attempt_id))
                }
            }
        }
    }

    pub async fn recover(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        attempt_id: Uuid,
        requested_source_profile_id: &str,
        token: &str,
    ) -> Result<(AttemptStatus, Option<SourceReceipt>), ServiceError> {
        let (item, _) = self
            .caller_item(actor, item_id, requested_source_profile_id, token)
            .await?;
        if let Some((saved_profile, attempt)) =
            self.store.terminal_attempt_by_id(actor, attempt_id).await?
        {
            if saved_profile != requested_source_profile_id || attempt.item_id != item_id {
                return Err(ServiceError::NotFound);
            }
            return Ok((attempt.clone(), attempt.receipt));
        }
        let (source_profile_id, idempotency_key, prepared) =
            self.store.load_prepared_attempt(actor, attempt_id).await?;
        if source_profile_id != requested_source_profile_id {
            return Err(ServiceError::Forbidden);
        }
        if self.store.attempt_item_id(attempt_id).await? != item_id {
            return Err(ServiceError::NotFound);
        }
        let execution_token = match self
            .store
            .acquire_recovery_execution(actor, attempt_id)
            .await
        {
            Ok(token) => token,
            Err(StoreError::AttemptPending) => {
                return Err(ServiceError::UncertainAttempt(attempt_id));
            }
            Err(error) => return Err(error.into()),
        };
        let adapter = self.adapter(&item.subject.source_id)?;
        let execution = tokio::time::timeout(
            Duration::from_secs(300),
            adapter.execute_prepared(ExecutePreparedRequest {
                prepared: &prepared,
                execution: registry_casework_core::PreparedExecution::Recovery,
                actor,
                source_profile_id: &source_profile_id,
                idempotency_key: &idempotency_key,
                credential: EphemeralCredential::new(token),
            }),
        )
        .await
        .unwrap_or(Err(SourceAdapterError::Uncertain));
        match execution {
            Ok(receipt) => {
                let settled = self
                    .store
                    .complete_attempt(actor, attempt_id, &receipt)
                    .await?;
                Ok((settled, Some(receipt)))
            }
            Err(SourceAdapterError::DefinitiveRefusal) => {
                if let Err(error) = self
                    .store
                    .refuse_original_attempt(actor, attempt_id, execution_token)
                    .await
                {
                    if matches!(error, StoreError::AttemptPending) {
                        return Err(ServiceError::UncertainAttempt(attempt_id));
                    }
                    return Err(error.into());
                }
                Err(ServiceError::Adapter(SourceAdapterError::DefinitiveRefusal))
            }
            Err(_) => {
                let unsettled = match self
                    .store
                    .mark_attempt_uncertain(actor, attempt_id, execution_token)
                    .await
                {
                    Ok(unsettled) => unsettled,
                    Err(StoreError::AttemptPending) => {
                        return Err(ServiceError::UncertainAttempt(attempt_id));
                    }
                    Err(error) => return Err(error.into()),
                };
                Ok((unsettled, None))
            }
        }
    }

    pub async fn recover_by_key(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        requested_source_profile_id: &str,
        idempotency_key: &str,
        token: &str,
    ) -> Result<(AttemptStatus, Option<SourceReceipt>), ServiceError> {
        let (item, _) = self
            .caller_item(actor, item_id, requested_source_profile_id, token)
            .await?;
        if let Some((saved_profile, attempt)) = self
            .store
            .terminal_attempt_by_key(actor, item_id, idempotency_key)
            .await?
        {
            if saved_profile != requested_source_profile_id {
                return Err(ServiceError::Forbidden);
            }
            return Ok((attempt.clone(), attempt.receipt));
        }
        let (attempt_id, source_profile_id, prepared) = self
            .store
            .load_prepared_attempt_by_key(actor, item_id, idempotency_key)
            .await?;
        if source_profile_id != requested_source_profile_id {
            return Err(ServiceError::Forbidden);
        }
        let execution_token = match self
            .store
            .acquire_recovery_execution(actor, attempt_id)
            .await
        {
            Ok(token) => token,
            Err(StoreError::AttemptPending) => {
                return Err(ServiceError::UncertainAttempt(attempt_id));
            }
            Err(error) => return Err(error.into()),
        };
        let adapter = self.adapter(&item.subject.source_id)?;
        let execution = tokio::time::timeout(
            Duration::from_secs(300),
            adapter.execute_prepared(ExecutePreparedRequest {
                prepared: &prepared,
                execution: registry_casework_core::PreparedExecution::Recovery,
                actor,
                source_profile_id: &source_profile_id,
                idempotency_key,
                credential: EphemeralCredential::new(token),
            }),
        )
        .await
        .unwrap_or(Err(SourceAdapterError::Uncertain));
        match execution {
            Ok(receipt) => {
                let settled = self
                    .store
                    .complete_attempt(actor, attempt_id, &receipt)
                    .await?;
                Ok((settled, Some(receipt)))
            }
            Err(SourceAdapterError::DefinitiveRefusal) => {
                if let Err(error) = self
                    .store
                    .refuse_original_attempt(actor, attempt_id, execution_token)
                    .await
                {
                    if matches!(error, StoreError::AttemptPending) {
                        return Err(ServiceError::UncertainAttempt(attempt_id));
                    }
                    return Err(error.into());
                }
                Err(ServiceError::Adapter(SourceAdapterError::DefinitiveRefusal))
            }
            Err(_) => {
                let unsettled = match self
                    .store
                    .mark_attempt_uncertain(actor, attempt_id, execution_token)
                    .await
                {
                    Ok(unsettled) => unsettled,
                    Err(StoreError::AttemptPending) => {
                        return Err(ServiceError::UncertainAttempt(attempt_id));
                    }
                    Err(error) => return Err(error.into()),
                };
                Ok((unsettled, None))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn decide_mutation(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        expected_revision: i64,
        source_profile_id: &str,
        operation: OperationName,
        reason: Option<&str>,
        flagged_fields: &[String],
        displayed_binding: &SourceBinding,
        idempotency_key: &str,
        token: &str,
    ) -> Result<MutationResponse, ServiceError> {
        let (attempt, _) = self
            .decide(
                actor,
                item_id,
                expected_revision,
                source_profile_id,
                operation,
                reason,
                flagged_fields,
                displayed_binding,
                idempotency_key,
                token,
            )
            .await?;
        self.source_mutation_response(actor, item_id, source_profile_id, token, attempt)
            .await
    }

    pub async fn recover_mutation(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        attempt_id: Uuid,
        source_profile_id: &str,
        token: &str,
    ) -> Result<MutationResponse, ServiceError> {
        let (attempt, _) = self
            .recover(actor, item_id, attempt_id, source_profile_id, token)
            .await?;
        self.source_mutation_response(actor, item_id, source_profile_id, token, attempt)
            .await
    }

    pub async fn recover_mutation_by_key(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
        idempotency_key: &str,
        token: &str,
    ) -> Result<MutationResponse, ServiceError> {
        let (attempt, _) = self
            .recover_by_key(actor, item_id, source_profile_id, idempotency_key, token)
            .await?;
        self.source_mutation_response(actor, item_id, source_profile_id, token, attempt)
            .await
    }

    async fn source_mutation_response(
        &self,
        actor: &ActorContext,
        item_id: Uuid,
        source_profile_id: &str,
        token: &str,
        attempt: AttemptStatus,
    ) -> Result<MutationResponse, ServiceError> {
        let item = match self
            .caller_item(actor, item_id, source_profile_id, token)
            .await
        {
            Ok((item, _)) => item,
            Err(ServiceError::Adapter(SourceAdapterError::Unavailable)) => {
                return Err(
                    if matches!(
                        attempt.state,
                        AttemptState::Pending | AttemptState::Uncertain
                    ) {
                        ServiceError::UncertainAttempt(attempt.attempt_id)
                    } else {
                        ServiceError::PostWriteSourceUnavailable(attempt.attempt_id)
                    },
                );
            }
            Err(error) => return Err(error),
        };
        Ok(MutationResponse {
            item,
            attempt: Some(attempt),
        })
    }

    pub async fn caller_visible_holdings(
        &self,
        actor: &ActorContext,
        source_profile_id: &str,
        token: &str,
        cursor: Option<&str>,
    ) -> Result<Page<HoldingSummary>, ServiceError> {
        if actor.role != registry_casework_core::CaseworkRole::Supervisor {
            return Err(ServiceError::Forbidden);
        }
        let page = self
            .inbox_for_context(
                actor,
                source_profile_id,
                token,
                InboxView::MyTeams,
                100,
                None,
                None,
                cursor,
                "holdings",
            )
            .await?;
        let status = page.status;
        let next_cursor = page.next_cursor;
        let mut holdings: BTreeMap<(registry_casework_core::IssuerPrincipal, String), (u32, u32)> =
            BTreeMap::new();
        let now = chrono::Utc::now();
        for item in page.items {
            let overdue = effective_due_at(&item).is_some_and(|due| due < now);
            if let Some(holder) = item.holder {
                let counts = holdings.entry((holder, item.queue_id)).or_insert((0, 0));
                counts.0 += 1;
                counts.1 += u32::from(overdue);
            }
        }
        let items = holdings
            .into_iter()
            .map(
                |((principal, queue_id), (active_items, overdue_items))| HoldingSummary {
                    principal,
                    queue_id,
                    active_items,
                    overdue_items,
                },
            )
            .collect();
        Ok(Page {
            items,
            next_cursor,
            status,
        })
    }

    pub(crate) fn adapter(&self, source_id: &str) -> Result<&Arc<dyn SourceAdapter>, ServiceError> {
        self.adapters.get(source_id).ok_or(ServiceError::Source)
    }

    pub(crate) fn request_policy_for(
        &self,
        subject: &SubjectRef,
    ) -> Result<&registry_casework_core::SourceRequestPolicy, ServiceError> {
        let source = self
            .project
            .sources
            .iter()
            .find(|source| source.id == subject.source_id)
            .ok_or(ServiceError::Source)?;
        source
            .requests
            .iter()
            .find(|request| request.entity == subject.kind)
            .ok_or(ServiceError::Source)
    }

    pub(crate) fn clock_policy_for(
        &self,
        subject: &SubjectRef,
    ) -> Result<Option<crate::ResolvedClockPolicy>, ServiceError> {
        let Some(clock_id) = self.request_policy_for(subject)?.clock.as_deref() else {
            return Ok(None);
        };
        let clock = self
            .project
            .clocks
            .iter()
            .find(|clock| clock.id() == clock_id)
            .ok_or(ServiceError::Configuration)?
            .clone();
        let calendar = match &clock {
            registry_casework_core::ClockPolicy::Activity { calendar, .. } => Some(
                self.project
                    .calendars
                    .iter()
                    .find(|candidate| candidate.id == *calendar)
                    .ok_or(ServiceError::Configuration)?
                    .clone(),
            ),
            registry_casework_core::ClockPolicy::Subject { .. } => None,
        };
        Ok(Some(crate::ResolvedClockPolicy { clock, calendar }))
    }

    pub(crate) fn routing_policy_for(
        &self,
        observation: &registry_casework_core::AuthoritativeObservation,
    ) -> Result<(registry_casework_core::RoutingDecision, Option<i64>), ServiceError> {
        let request = self.request_policy_for(&observation.subject)?;
        let target = request.target.as_ref().and_then(|target| {
            registry_casework_core::parse_elapsed_seconds(&target.after.elapsed)
        });
        let default = registry_casework_core::RoutingDecision {
            queue: request.queue.clone(),
            rule_id: None,
            because: None,
        };
        // Waiting and terminal observations retire or suspend work. They may
        // have no source review stage or permitted routing projection.
        if request.routing.is_empty()
            || !observation.state.is_active()
            || (observation.routing_context.is_none() && observation.state != OccurrenceState::Open)
        {
            return Ok((default, target));
        }
        let metadata = self
            .adapter(&observation.subject.source_id)?
            .routing_metadata()
            .ok_or(SourceAdapterError::Invalid)?;
        let context = observation
            .routing_context
            .as_ref()
            .ok_or(SourceAdapterError::Invalid)?;
        let decision = registry_casework_core::evaluate_routing(
            &request.queue,
            &request.projection,
            &request.routing,
            metadata,
            context,
        )
        .map_err(|_| SourceAdapterError::Invalid)?;
        Ok((decision, target))
    }

    #[must_use]
    pub fn inbox_policy(&self) -> &InboxPolicy {
        &self.project.inbox
    }

    async fn filtered_routing_copy(
        &self,
        item_id: Uuid,
        view: &CallerSubjectView,
    ) -> Result<Option<registry_casework_core::CorrectionRoutingCopy>, ServiceError> {
        let Some(mut copy) = self.store.correction_routing_copy(item_id).await? else {
            return Ok(None);
        };
        let reasons = view
            .disclosed
            .get("reasons")
            .and_then(serde_json::Value::as_array);
        if !reasons.is_some_and(|values| {
            copy.reason
                .as_ref()
                .is_some_and(|reason| values.iter().any(|value| value.as_str() == Some(reason)))
        }) {
            copy.reason = None;
        }
        let readable = view
            .disclosed
            .get("readableFields")
            .and_then(serde_json::Value::as_array);
        copy.flagged_fields.retain(|field| {
            !field.contains('.')
                && readable
                    .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(field)))
        });
        if copy.reason.is_none() && copy.flagged_fields.is_empty() {
            Ok(None)
        } else {
            Ok(Some(copy))
        }
    }
}

fn bounded_event_identifier(value: &str) -> &str {
    const MAX_BYTES: usize = 256;
    if value.len() <= MAX_BYTES {
        return value;
    }
    let mut end = MAX_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn source_cursor_context(
    feed: &'static str,
    view: InboxView,
    queue: Option<&str>,
    subject: Option<&SubjectRef>,
) -> Result<String, ServiceError> {
    serde_json::to_string(&SourceCursorContext {
        feed,
        view,
        queue,
        subject,
        ordering: "effective-due-v1",
    })
    .map_err(|_| ServiceError::Configuration)
}

fn effective_due_at(item: &WorkItem) -> Option<chrono::DateTime<chrono::Utc>> {
    if item.clock_occurrences.is_empty() {
        return item.passive_due_at;
    }
    item.clock_occurrences
        .iter()
        .filter(|clock| {
            matches!(
                clock.state,
                ClockRuntimeState::Running | ClockRuntimeState::VerificationPending
            )
        })
        .filter_map(|clock| clock.due_at)
        .min()
}

fn routing_policy_digest(
    request: &registry_casework_core::SourceRequestPolicy,
) -> Result<String, ServiceError> {
    let value = serde_json::json!({
        "entity": &request.entity,
        "queue": &request.queue,
        "projection": &request.projection,
        "routing": &request.routing,
    });
    let canonical = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| ServiceError::Configuration)?;
    Ok(sha256_string(&Sha256::digest(canonical)))
}

fn decision_hash(
    expected_revision: i64,
    source_profile_id: &str,
    operation: &OperationName,
    reason: Option<&str>,
    flagged_fields: &[String],
    binding: &SourceBinding,
) -> Result<String, ServiceError> {
    let bytes = serde_json::to_vec(&(
        expected_revision,
        source_profile_id,
        operation,
        reason,
        flagged_fields,
        binding,
    ))
    .map_err(|_| ServiceError::Configuration)?;
    let digest = Sha256::digest(bytes);
    Ok(format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

fn local_item_hash(item_id: Uuid, expected_revision: i64, claim: bool) -> String {
    let digest = Sha256::digest(format!("{item_id}:{expected_revision}:{claim}"));
    sha256_string(&digest)
}

fn sha256_string(digest: &[u8]) -> String {
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn local_actions(
    actor: &ActorContext,
    item: &WorkItem,
    source: &CallerSubjectView,
) -> Vec<CaseworkAction> {
    if item.live_attempt.is_some() {
        return Vec::new();
    }
    let if_match = format!("\"{}\"", item.revision);
    if actor.role == registry_casework_core::CaseworkRole::Supervisor {
        if !matches!(
            item.state,
            registry_casework_core::OccurrenceState::Open
                | registry_casework_core::OccurrenceState::Claimed
        ) {
            return Vec::new();
        }
        let mut actions = vec![CaseworkAction {
            operation: "assign".to_owned(),
            href: format!("/v1/work-items/{}/assign", item.item_id),
            if_match: if_match.clone(),
        }];
        if item.holder.is_some() && item.state == registry_casework_core::OccurrenceState::Claimed {
            actions.push(CaseworkAction {
                operation: "release".to_owned(),
                href: format!("/v1/work-items/{}/release", item.item_id),
                if_match,
            });
        }
        return actions;
    }
    if actor.role == registry_casework_core::CaseworkRole::Staff
        && item.holder.is_none()
        && item.state == registry_casework_core::OccurrenceState::Open
        && !source.permitted_operations.is_empty()
    {
        return vec![CaseworkAction {
            operation: "claim".to_owned(),
            href: format!("/v1/work-items/{}/claim", item.item_id),
            if_match,
        }];
    }
    if actor.role != registry_casework_core::CaseworkRole::Staff
        || item.holder.as_ref() != Some(&actor.principal)
        || item.state != registry_casework_core::OccurrenceState::Claimed
    {
        return Vec::new();
    }
    let mut actions = vec![
        CaseworkAction {
            operation: "release".to_owned(),
            href: format!("/v1/work-items/{}/release", item.item_id),
            if_match: if_match.clone(),
        },
        CaseworkAction {
            operation: "delegate".to_owned(),
            href: format!("/v1/work-items/{}/delegate", item.item_id),
            if_match: if_match.clone(),
        },
    ];
    actions.extend(
        source
            .permitted_operations
            .iter()
            .map(|operation| CaseworkAction {
                operation: operation.as_str().to_owned(),
                href: format!("/v1/work-items/{}/decisions", item.item_id),
                if_match: if_match.clone(),
            }),
    );
    actions
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("the Casework service configuration is invalid")]
    Configuration,
    #[error("the source is not registered")]
    Source,
    #[error("the source response does not match its registration")]
    SourceProtocol,
    #[error("the requested work item was not found")]
    NotFound,
    #[error("the caller is not authorized")]
    Forbidden,
    #[error("the displayed binding is no longer current")]
    BindingMoved,
    #[error("the source attempt remains uncertain")]
    UncertainAttempt(Uuid),
    #[error("the source became unavailable after the durable attempt was stored")]
    PostWriteSourceUnavailable(Uuid),
    #[error(transparent)]
    HostedValidation(#[from] registry_casework_core::HostedValidationError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Adapter(#[from] SourceAdapterError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_context_preserves_colons_in_typed_queue_identity() {
        let subject = SubjectRef {
            source_id: "source:west".to_owned(),
            kind: "request:appeal".to_owned(),
            id: "record:42".to_owned(),
        };
        let context = source_cursor_context(
            "list",
            InboxView::Mine,
            Some("region:appeals"),
            Some(&subject),
        )
        .expect("cursor context");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&context).expect("context JSON"),
            serde_json::json!({
                "feed": "list",
                "view": "mine",
                "queue": "region:appeals",
                "subject": {
                    "sourceId": "source:west",
                    "kind": "request:appeal",
                    "id": "record:42"
                },
                "ordering": "effective-due-v1"
            })
        );
    }

    #[test]
    fn effective_due_uses_passive_only_without_a_real_clock() {
        let passive = chrono::Utc::now();
        let mut item = WorkItem {
            item_id: Uuid::new_v4(),
            subject: SubjectRef {
                source_id: "source".to_owned(),
                kind: "request".to_owned(),
                id: "one".to_owned(),
            },
            occurrence_kind: registry_casework_core::OccurrenceKind::Review,
            stage: None,
            binding_reference: "binding".to_owned(),
            binding: SourceBinding {
                source_revision: "1".to_owned(),
                version: "1".to_owned(),
                integrity: None,
                generation: "1".to_owned(),
            },
            state: OccurrenceState::Open,
            queue_id: "queue".to_owned(),
            holder: None,
            held_since: None,
            assignment: None,
            revision: 1,
            first_observed_at: passive,
            passive_due_at: Some(passive),
            updated_at: passive,
            hosted: None,
            routing: None,
            clock_occurrences: Vec::new(),
            actions: Vec::new(),
            routing_copy: None,
            live_attempt: None,
        };
        assert_eq!(effective_due_at(&item), Some(passive));
        item.clock_occurrences
            .push(registry_casework_core::ClockOccurrenceView {
                clock_occurrence_id: Uuid::new_v4(),
                subject: item.subject.clone(),
                clock_id: "clock".to_owned(),
                state: ClockRuntimeState::Paused,
                policy_digest: "sha256:policy".to_owned(),
                calculation_generation: 1,
                recompute_generation: 0,
                anchor_at: Some(passive),
                started_at: Some(passive),
                due_at: Some(passive),
                at_risk_at: None,
                completed_at: None,
                next_effect: None,
                upcoming_effects: Vec::new(),
            });
        assert_eq!(effective_due_at(&item), None);
        item.clock_occurrences[0].state = ClockRuntimeState::VerificationPending;
        assert_eq!(effective_due_at(&item), Some(passive));
    }
}
