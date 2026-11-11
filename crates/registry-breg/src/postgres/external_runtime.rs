// SPDX-License-Identifier: Apache-2.0
//! Governed HTTP reads and bounded refresh of external views.

mod managed;
mod targeted;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use registry_adapter_core::{
    projection_token_valid, ProjectionRecord, ProjectionRequest, ProjectionResult,
};
use registry_adapter_engine::evidence::{
    EvidenceAcquisitionIntent, EvidenceHookError, EvidenceHookFuture, EvidenceHostHooks,
    EvidenceSendIntent,
};
use registry_adapter_engine::projection::ProjectionError as AdapterProjectionError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time::{timeout_at, Instant};
use uuid::Uuid;

use crate::api::external_views::{
    ExternalQuery, ExternalQueryMode, ExternalRefreshHint, ExternalViewError, ExternalViewRequest,
    ExternalViewService, HintAdmission, RefreshMode,
};
use crate::api::{
    AuthorizedRequestContext, RowBoundaryOperator, ServiceFuture, VerifiedRequestClaims,
};
use crate::audit::{
    begin_pre_io_audit, profile_is_keyed, read_terminal_entry, PreIoAudit, PreIoAuditKind,
    ReadTerminalAudit, RegistryAudit, TerminalAudit, TerminalAuditOutcome,
};
use crate::correlation::RequestCorrelation;
use crate::cursor::CursorCodec;
use crate::external_refresh_config::ResolvedExternalRefreshPlan;
use crate::external_source::{BoundExternalSource, ExternalSourceError, ExternalSourceService};
use crate::external_views::{
    ExternalCardinality, ExternalLinkPermissionSource, ExternalLinkSource, ExternalProjectionMode,
    ExternalProjectionSource, ExternalRecordTypeSource,
};
use crate::model::{CompiledEntity, CompiledRegistry, HttpMethod};

use super::cancellation::QueryCancellationGuard;
use super::external_label_acquisition::{LabelAcquisition, LabelAfter, SupportingSnapshot};
use super::external_projection::{
    self as store, AcceptedSnapshot, ProjectionGeneration, ProjectionRow, ProjectionScope,
    RefreshFailure, RefreshTicket, RetentionPermission,
};
use super::external_refresh_queue as queue;
use super::external_view_query::{
    self as indexed, ExternalAvailability, IndexedViewQuery, LabelScope, PageAfter, SortDirection,
};
use super::read::{strict_claim_context, ReadRelations};
use super::{
    begin_record_transaction, begin_registry_transaction, begin_registry_transaction_with_reason,
    ClaimContext, ExpectedRegistryIdentity, GuardedTransaction, RegistryLockKey,
    RetentionFailureReason, RuntimePool,
};

type Result<T> = std::result::Result<T, ExternalViewError>;
/// Rows one retention tick committed, as (snapshots, receipts) by projection
/// and reason.
type PurgeTally = BTreeMap<(String, store::PurgeReason), (u64, u64)>;

pub(crate) struct PostgresExternalViewService {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit: RegistryAudit,
    cursors: Arc<CursorCodec>,
    sources: ExternalSourceService,
    managed_refresh: BTreeMap<String, ResolvedExternalRefreshPlan>,
}

struct Plan<'a> {
    root: &'a CompiledEntity,
    link: &'a ExternalLinkSource,
    projection: &'a ExternalProjectionSource,
    external: &'a ExternalRecordTypeSource,
    grant: Option<&'a ExternalLinkPermissionSource>,
    source: &'a BoundExternalSource,
    label_parent: Option<LabelParent<'a>>,
}

struct LabelParent<'a> {
    projection: &'a ExternalProjectionSource,
    source: &'a BoundExternalSource,
}

impl Plan<'_> {
    fn grant_valid_until(&self) -> chrono::DateTime<Utc> {
        let cutoff = self.source.grant_valid_until();
        self.label_parent.as_ref().map_or(cutoff, |parent| {
            cutoff.min(parent.source.grant_valid_until())
        })
    }

    fn read_grant(&self) -> Result<&ExternalLinkPermissionSource> {
        self.grant.ok_or(ExternalViewError::Concealed)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Continuation {
    binding: String,
    expires_at: i64,
    query: ExternalQuery,
    position: Position,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Position {
    Read {
        root_id: Uuid,
        source_key: String,
        sort_value: Option<String>,
    },
    Refresh {
        after: RefreshAfter,
        minimum_sequence: i64,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RefreshAfter {
    Root { root_id: Uuid },
    Label { root_id: Uuid, member_key: String },
}

impl From<PageAfter> for Position {
    fn from(value: PageAfter) -> Self {
        Self::Read {
            root_id: value.root_id,
            source_key: value.source_key,
            sort_value: value.sort_value,
        }
    }
}

struct HeldResponse {
    body: Value,
    expires_at: i64,
}

impl HeldResponse {
    fn release(self) -> Result<Value> {
        if Utc::now().timestamp() >= self.expires_at {
            return Err(ExternalViewError::Unavailable);
        }
        Ok(self.body)
    }
}

impl PostgresExternalViewService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: RegistryAudit,
        cursors: Arc<CursorCodec>,
        sources: ExternalSourceService,
    ) -> Self {
        Self {
            pool,
            registry,
            expected,
            lock_key,
            lock_timeout,
            audit,
            cursors,
            sources,
            managed_refresh: BTreeMap::new(),
        }
    }

    /// Bind each configured indexed projection in its own transaction. A
    /// projection the database refuses becomes unavailable for this process,
    /// with the reason, while the others bind and serve. A database that
    /// cannot be reached still fails the whole start. With `persist` false
    /// (doctor) every bind rolls back, so a check never rotates a serving
    /// scope or writes one.
    pub(crate) async fn bind_configured_scopes(&mut self, persist: bool) -> Result<()> {
        let configured = self
            .registry
            .external_views()
            .projections
            .values()
            .filter_map(|projection| {
                let bound = self.sources.binding(projection.id.as_str())?;
                let ttl = bound.effective_cache_ttl_seconds()?;
                Some((
                    projection.id.to_string(),
                    ProjectionScope::new(
                        projection.id.as_str(),
                        Uuid::new_v4(),
                        bound.binding_fingerprint(),
                        bound.grant_fingerprint(),
                        i64::from(ttl),
                    ),
                ))
            })
            .collect::<Vec<_>>();
        if configured.is_empty() {
            return Ok(());
        }
        let mut session = self.session().await?;
        for (id, scope) in configured {
            let transaction = begin_registry_transaction(
                session.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
            )
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
            transaction
                .set_statement_budget(Duration::from_secs(10))
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            let bound = match scope {
                Ok(scope) => {
                    store::bind_initial_scope(&transaction, &self.registry, &self.expected, &scope)
                        .await
                }
                Err(error) => Err(error),
            };
            let refusal = match bound {
                Ok(_) => None,
                Err(store::ProjectionError::ScopeChanged) => Some(
                    "the database refused its cache scope; run migrate for this package with this release, then restart",
                ),
                Err(store::ProjectionError::InvalidScope) => {
                    Some("its cache scope is invalid for this package")
                }
                Err(_) => return Err(ExternalViewError::Unavailable),
            };
            if let Some(reason) = refusal {
                tracing::error!(
                    projection = %id,
                    reason,
                    "external projection is unavailable; its views answer source.unavailable"
                );
                self.sources.refuse(&id, reason.to_owned());
            }
            let finished = if persist && refusal.is_none() {
                transaction.commit().await
            } else {
                transaction.rollback().await
            };
            finished.map_err(|_| ExternalViewError::Unavailable)?;
        }
        session.disarm();
        Ok(())
    }

    /// Projections without a usable binding in this process, with the reason.
    pub(crate) fn unavailable_projections(&self) -> &BTreeMap<String, String> {
        self.sources.unavailable_projections()
    }

    /// Each bound projection's grant horizon and, for an indexed projection,
    /// when the newest snapshot its active epoch holds was observed. Reads
    /// only, in one transaction that is rolled back.
    pub(crate) async fn projection_status(
        &self,
    ) -> Result<Vec<crate::startup::ExternalProjectionStatus>> {
        let mut session = self.session().await?;
        let transaction = begin_registry_transaction(
            session.client(),
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(|_| ExternalViewError::Unavailable)?;
        transaction
            .set_statement_budget(Duration::from_secs(10))
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        let mut status = Vec::new();
        for (id, projection) in &self.registry.external_views().projections {
            let Some(source) = self.sources.binding(id.as_str()) else {
                continue;
            };
            let indexed = projection.mode == ExternalProjectionMode::Indexed;
            let newest_publication = if indexed {
                store::newest_publication(&transaction, id.as_str())
                    .await
                    .map_err(|_| ExternalViewError::Unavailable)?
            } else {
                None
            };
            status.push(crate::startup::ExternalProjectionStatus {
                projection: id.to_string(),
                indexed,
                grant_valid_until: source.grant_valid_until().timestamp(),
                newest_publication,
            });
        }
        transaction
            .rollback()
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        session.disarm();
        Ok(status)
    }

    pub(crate) async fn run_retention(
        self: Arc<Self>,
        last_success: Arc<crate::metrics::LastSuccess>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                change = shutdown.changed() => {
                    if change.is_err() || *shutdown.borrow() { return; }
                }
                _ = interval.tick() => {
                    if self.retention_tick().await {
                        last_success.record();
                    }
                }
            }
        }
    }

    /// One bounded purge pass. Logs the committed removals by projection and
    /// reason, and a failure by category; returns whether the pass completed.
    async fn retention_tick(&self) -> bool {
        let mut purged = PurgeTally::new();
        let outcome = timeout_at(
            Instant::now() + Duration::from_secs(5),
            self.purge_tick(&mut purged),
        )
        .await;
        for ((projection, reason), (snapshots, receipts)) in &purged {
            tracing::info!(
                projection = projection.as_str(),
                reason = reason.as_str(),
                snapshots,
                receipts,
                "external projection retention removed cache rows"
            );
        }
        let reason = match outcome {
            Ok(Ok(())) => return true,
            Ok(Err(reason)) => reason.as_str(),
            Err(_) => "deadline",
        };
        tracing::error!(reason, "external projection retention tick failed");
        false
    }

    async fn purge_tick(
        &self,
        purged: &mut PurgeTally,
    ) -> std::result::Result<(), RetentionFailureReason> {
        const BATCH: u32 = 1000;
        const BATCHES: usize = 8;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| RetentionFailureReason::Database)?;
        let mut session = QueryCancellationGuard::new(self.pool.clone(), client);
        for _ in 0..BATCHES {
            let transaction = begin_registry_transaction_with_reason(
                session.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
            )
            .await
            .map_err(RetentionFailureReason::admission)?;
            transaction
                .set_statement_budget(Duration::from_secs(2))
                .await
                .map_err(|_| RetentionFailureReason::Database)?;
            let batch = store::purge(&transaction, BATCH).await?;
            transaction
                .commit()
                .await
                .map_err(|_| RetentionFailureReason::Database)?;
            let (mut snapshots, mut receipts) = (0, 0);
            for removed in batch {
                snapshots += removed.snapshots;
                receipts += removed.receipts;
                let entry = purged
                    .entry((removed.projection, removed.reason))
                    .or_default();
                entry.0 += removed.snapshots;
                entry.1 += removed.receipts;
            }
            // The cache and queue have different lock orders. Commit the
            // cache purge before taking any queue locks.
            let transaction = begin_registry_transaction_with_reason(
                session.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
            )
            .await
            .map_err(RetentionFailureReason::admission)?;
            transaction
                .set_statement_budget(Duration::from_secs(2))
                .await
                .map_err(|_| RetentionFailureReason::Database)?;
            let queued = queue::purge_expired(&transaction, BATCH)
                .await
                .map_err(|_| RetentionFailureReason::Database)?;
            transaction
                .commit()
                .await
                .map_err(|_| RetentionFailureReason::Database)?;
            if queued.work != 0 || queued.receipts != 0 || queued.plans != 0 {
                tracing::info!(
                    work = queued.work,
                    receipts = queued.receipts,
                    plans = queued.plans,
                    "external refresh retention removed queue state"
                );
            }
            if [
                snapshots,
                receipts,
                queued.work,
                queued.receipts,
                queued.plans,
            ]
            .into_iter()
            .all(|count| count < u64::from(BATCH))
            {
                session.disarm();
                return Ok(());
            }
        }
        session.disarm();
        tracing::warn!(
            batches = BATCHES,
            "external projection retention reached its per-tick batch bound"
        );
        Ok(())
    }

    /// Called only after the caller's view, link and purpose were admitted.
    fn bound_source(&self, projection: &ExternalProjectionSource) -> Result<&BoundExternalSource> {
        self.sources
            .binding(projection.id.as_str())
            .ok_or_else(|| ExternalViewError::ProjectionUnavailable(projection.id.to_string()))
    }

    fn plan<'a>(
        &'a self,
        request: &ExternalViewRequest,
        refresh: Option<RefreshMode>,
    ) -> Result<Plan<'a>> {
        let inventory = self.registry.external_views();
        let profile = request.context.selected_profile();
        let view = inventory
            .views
            .get(&request.view)
            .ok_or(ExternalViewError::Concealed)?;
        let link = view
            .links
            .iter()
            .find(|link| link.id.as_str() == request.link)
            .ok_or(ExternalViewError::Concealed)?;
        let projection = inventory
            .projections
            .get(link.projection.as_str())
            .ok_or(ExternalViewError::Unavailable)?;
        if request.context.purpose() != Some(projection.purpose.as_str()) {
            return Err(ExternalViewError::Concealed);
        }
        let mut label_parent = None;
        let mut projection = projection;
        let grant = if let Some(mode) = refresh {
            let ids = inventory
                .refresh
                .get(profile)
                .ok_or(ExternalViewError::Concealed)?;
            if request.context.requester_client().is_none()
                || projection.mode != ExternalProjectionMode::Indexed
                || !ids.contains(&projection.id)
            {
                return Err(ExternalViewError::Concealed);
            }
            if mode == RefreshMode::Labels {
                let link_label = link.label.as_ref().ok_or(ExternalViewError::Concealed)?;
                let label = inventory
                    .projections
                    .get(link_label.projection.as_str())
                    .ok_or(ExternalViewError::Concealed)?;
                if projection.cardinality != ExternalCardinality::Many
                    || label.mode != ExternalProjectionMode::Indexed
                    || label.cardinality != ExternalCardinality::One
                    || label.purpose != projection.purpose
                    || !ids.contains(&label.id)
                {
                    return Err(ExternalViewError::Concealed);
                }
                label_parent = Some(LabelParent {
                    projection,
                    source: self.bound_source(projection)?,
                });
                projection = label;
            }
            None
        } else {
            Some(
                inventory
                    .grants
                    .get(profile)
                    .and_then(|views| views.get(&request.view))
                    .and_then(|view| view.links.iter().find(|grant| grant.link == link.id))
                    .ok_or(ExternalViewError::Concealed)?,
            )
        };
        let root = self
            .registry
            .entities()
            .get(view.record_type.as_str())
            .ok_or(ExternalViewError::Unavailable)?;
        let external = inventory
            .record_types
            .get(projection.record_type.as_str())
            .ok_or(ExternalViewError::Unavailable)?;
        let source = self.bound_source(projection)?;
        Ok(Plan {
            root,
            link,
            projection,
            external,
            grant,
            source,
            label_parent,
        })
    }

    async fn run(
        &self,
        request: ExternalViewRequest,
        refresh: Option<RefreshMode>,
    ) -> Result<Value> {
        if !profile_is_keyed(self.audit.profile()) {
            return Err(ExternalViewError::Unavailable);
        }
        let plan = self.plan(&request, refresh)?;
        let claims = strict_claim_context(&self.registry, &request.context, &plan.root.id)
            .map_err(|_| ExternalViewError::Unavailable)?;
        let operation = match refresh {
            Some(RefreshMode::Labels) => "external-projection-label-refresh",
            Some(RefreshMode::Projection) => "external-projection-refresh",
            None if plan.projection.mode == ExternalProjectionMode::Live => {
                "external-view-live-read"
            }
            None => "external-view-indexed-read",
        };
        let method = if refresh.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        };
        let target = request.root.map(|root| root.to_string());
        // The durable attempt precedes both protected SQL and any source I/O.
        let attempt = begin_pre_io_audit(
            &self.audit,
            &self.expected,
            &claims,
            PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method,
                operation_id: operation,
                target_record: target.as_deref(),
                refusal_reason: None,
                correlation: &request.correlation,
            },
        )
        .await
        .map_err(|_| ExternalViewError::Unavailable)?;
        let result = if refresh.is_some() {
            self.refresh_page(&request, &plan, &claims).await
        } else if plan.projection.mode == ExternalProjectionMode::Live {
            self.read_live(&request, &plan, &claims, operation).await
        } else {
            self.read_indexed(&request, &plan, &claims, operation).await
        };
        if !attempt.is_answered() {
            self.terminal(&request, &plan, operation, method, result.is_ok())
                .await?;
        }
        result?.release()
    }

    async fn transaction<'a>(
        &self,
        session: &'a mut QueryCancellationGuard,
        claims: &ClaimContext,
        deadline: Instant,
    ) -> Result<GuardedTransaction<'a>> {
        let transaction = begin_record_transaction(
            session.client(),
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            claims,
        )
        .await
        .map_err(|_| ExternalViewError::Unavailable)?;
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(30));
        if budget < Duration::from_millis(1) {
            return Err(ExternalViewError::Unavailable);
        }
        transaction
            .set_statement_budget(budget)
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        Ok(transaction)
    }

    async fn session(&self) -> Result<QueryCancellationGuard> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        Ok(QueryCancellationGuard::new(self.pool.clone(), client))
    }

    async fn read_live(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        claims: &ClaimContext,
        operation: &str,
    ) -> Result<HeldResponse> {
        let root = request.root.ok_or(ExternalViewError::Concealed)?;
        if !matches!(&request.query, ExternalQueryMode::First(_)) {
            return Err(ExternalViewError::InvalidCursor);
        }
        let mut session = self.session().await?;
        let transaction = self
            .transaction(&mut session, claims, request.deadline)
            .await?;
        // A root without a usable link key has no outside subject to fetch.
        let stored = RootKeys::new(plan)?
            .for_root(&transaction, root)
            .await?
            .ok_or(ExternalViewError::Concealed)?;
        if stored
            .as_deref()
            .is_some_and(|key| !key.is_empty() && !crate::external_views::link_key_acceptable(key))
        {
            tracing::warn!(
                view = request.view.as_str(),
                reason = "invalid-key",
                keys = 1,
                "external view live read skipped a key it would not send to the source"
            );
        }
        let key =
            stored.filter(|key| !key.is_empty() && crate::external_views::link_key_acceptable(key));
        transaction
            .commit()
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        session.disarm();
        drop(session);

        let fields = plan
            .read_grant()?
            .readable_fields
            .iter()
            .map(|field| field.as_str().to_owned())
            .collect();
        let result = if let Some(key) = &key {
            let source_request = match plan.projection.cardinality {
                ExternalCardinality::One => ProjectionRequest::Exact { key: key.clone() },
                ExternalCardinality::Many => ProjectionRequest::ByParent {
                    parent_key: key.clone(),
                },
            };
            live_acquisition(
                plan.projection.id.as_str(),
                self.acquire(request, plan, source_request, &fields, None, None)
                    .await,
            )
        } else {
            None
        };
        let mut session = self.session().await?;
        let transaction = self
            .transaction(&mut session, claims, request.deadline)
            .await?;
        // Re-evaluate RLS and the association after the network round trip.
        let current = RootKeys::new(plan)?
            .for_root(&transaction, root)
            .await?
            .ok_or(ExternalViewError::Concealed)?
            .filter(|key| !key.is_empty() && crate::external_views::link_key_acceptable(key));
        let (status, records) = if current != key {
            ("unavailable", Vec::new())
        } else if key.is_none() {
            match plan.projection.cardinality {
                ExternalCardinality::One => {
                    ("available", vec![response_row(root, "absent", json!({}))])
                }
                ExternalCardinality::Many => ("available", Vec::new()),
            }
        } else {
            self.live_records(request, plan, root, result)?
        };
        self.log_roots(&transaction, request, plan, &[root.to_string()], operation)
            .await?;
        self.terminal(request, plan, operation, HttpMethod::Get, true)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        session.disarm();
        Ok(HeldResponse {
            body: view_response(plan, status, records, None, None),
            expires_at: if status == "unavailable" {
                i64::MAX
            } else {
                plan.source.grant_valid_until().timestamp()
            },
        })
    }

    async fn read_indexed(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        claims: &ClaimContext,
        operation: &str,
    ) -> Result<HeldResponse> {
        let mut session = self.session().await?;
        let transaction = self
            .transaction(&mut session, claims, request.deadline)
            .await?;
        let (scope, generation) = match self
            .lock_scope(&transaction, plan.source, plan.projection.id.as_str())
            .await
        {
            Ok(scope) => scope,
            // A withdrawn or rebound projection still answers a plain detail
            // read with its root, as unavailable. Database and lock failures
            // are never reported as incomplete coverage or a bad cursor.
            Err(ExternalViewError::ProjectionUnavailable(_))
                if request.root.is_some()
                    && matches!(&request.query,
                ExternalQueryMode::First(query) if query.equality.is_none()
                    && query.order.is_none() && !query.include_count) =>
            {
                let root = request.root.ok_or(ExternalViewError::Concealed)?;
                RootKeys::new(plan)?
                    .for_root(&transaction, root)
                    .await?
                    .ok_or(ExternalViewError::Concealed)?;
                self.log_roots(&transaction, request, plan, &[root.to_string()], operation)
                    .await?;
                self.terminal(request, plan, operation, HttpMethod::Get, true)
                    .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| ExternalViewError::Unavailable)?;
                session.disarm();
                return Ok(HeldResponse {
                    body: view_response(plan, "unavailable", Vec::new(), None, None),
                    expires_at: i64::MAX,
                });
            }
            Err(ExternalViewError::ProjectionUnavailable(_))
                if matches!(&request.query, ExternalQueryMode::Continue(_)) =>
            {
                return Err(ExternalViewError::InvalidCursor);
            }
            Err(error) => return Err(error),
        };
        let grant = plan.read_grant()?;
        let label = if grant.label_fields.is_empty() {
            None
        } else {
            let label = plan
                .link
                .label
                .as_ref()
                .ok_or(ExternalViewError::Unavailable)?;
            match self.sources.binding(label.projection.as_str()) {
                Some(source) => {
                    match self
                        .lock_scope(&transaction, source, label.projection.as_str())
                        .await
                    {
                        Ok((scope, generation)) => {
                            Some((scope, generation, source.grant_valid_until().timestamp()))
                        }
                        // Labels from an unavailable projection read as unavailable.
                        Err(ExternalViewError::ProjectionUnavailable(_)) => None,
                        Err(error) => return Err(error),
                    }
                }
                None => None,
            }
        };
        let binding = self.cursor_binding(
            request,
            &scope,
            Some(generation),
            label.as_ref().map(|(_, generation, _)| *generation),
        )?;
        let (query, position) = self.page_request(&request.query, &binding)?;
        let after = match position {
            Some(Position::Read {
                root_id,
                source_key,
                sort_value,
            }) => Some(PageAfter {
                root_id,
                source_key,
                sort_value,
            }),
            Some(Position::Refresh { .. }) => return Err(ExternalViewError::InvalidCursor),
            None => None,
        };
        let mut expires_at = plan.source.grant_valid_until().timestamp();
        if let Some((_, _, label_expiry)) = &label {
            expires_at = expires_at.min(*label_expiry);
        }
        let page = indexed::query(
            &transaction,
            &self.registry,
            IndexedViewQuery {
                profile_id: request.context.selected_profile(),
                view_id: &request.view,
                link_id: &request.link,
                scope: &scope,
                generation,
                label_scope: label.as_ref().map(|(scope, generation, _)| LabelScope {
                    scope,
                    generation: *generation,
                }),
                now: Utc::now().timestamp(),
                root_id: request.root,
                fields: grant
                    .readable_fields
                    .iter()
                    .map(|field| field.as_str().to_owned())
                    .collect(),
                filter: query.equality.as_ref().map(|filter| indexed::ExactFilter {
                    field: filter.field.clone(),
                    value: filter.value.clone(),
                }),
                order: query.order.as_ref().map(|order| indexed::ExternalOrder {
                    field: order.field.clone(),
                    direction: if order.descending {
                        SortDirection::Descending
                    } else {
                        SortDirection::Ascending
                    },
                }),
                include_count: query.include_count,
                page_size: query.page_size,
                after,
            },
        )
        .await
        .map_err(|error| match error {
            indexed::ExternalQueryError::GenerationChanged => ExternalViewError::InvalidCursor,
            indexed::ExternalQueryError::NotPermitted => ExternalViewError::Concealed,
            _ => ExternalViewError::Unavailable,
        })?;
        if request.root.is_some() && !page.root_found {
            return Err(ExternalViewError::Concealed);
        }
        if !page.complete
            && (request.root.is_none()
                || query.equality.is_some()
                || query.order.is_some()
                || query.include_count
                || matches!(&request.query, ExternalQueryMode::Continue(_)))
        {
            return Err(ExternalViewError::Incomplete);
        }
        if let Some(cutoff) = page.minimum_expires_at {
            expires_at = expires_at.min(cutoff);
        }
        let next = page
            .continuation
            .map(|position| self.next_cursor(binding, query, position.into(), expires_at))
            .transpose()?;
        let root_ids = request
            .root
            .into_iter()
            .chain(page.rows.iter().map(|row| row.root_id))
            .map(|id| id.to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let status = if page.complete {
            "available"
        } else {
            "unavailable"
        };
        let records = page.rows.into_iter().map(|row| {
            let mut value = response_row(row.root_id, availability(row.availability), row.fields);
                if plan.projection.cardinality == ExternalCardinality::Many {
                    value["rowId"] = json!(self.row_id(request, plan, row.root_id, &row.source_key)?);
                }
                if let Some(label) = row.label {
                    let authority = plan.link.label.as_ref()
                        .and_then(|label| self.registry.external_views().projections.get(label.projection.as_str()))
                        .and_then(|projection| self.registry.external_views().record_types.get(projection.record_type.as_str()))
                        .map(|record_type| record_type.authority.as_str())
                        .ok_or(ExternalViewError::Unavailable)?;
                    value["label"] = json!({"authority": authority, "availability": availability(label.availability), "fields": label.fields});
                }
                Ok(value)
            })
            .collect::<Result<Vec<_>>>()?;
        self.log_roots(&transaction, request, plan, &root_ids, operation)
            .await?;
        self.terminal(request, plan, operation, HttpMethod::Get, true)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        session.disarm();
        Ok(HeldResponse {
            body: view_response(plan, status, records, page.total_count, next),
            expires_at,
        })
    }

    async fn lock_scope(
        &self,
        transaction: &GuardedTransaction<'_>,
        source: &BoundExternalSource,
        projection: &str,
    ) -> Result<(ProjectionScope, ProjectionGeneration)> {
        let scope = active_scope(transaction, source, projection).await?;
        let generation = store::lock_generation(transaction, &scope)
            .await
            .map_err(|error| match error {
                store::ProjectionError::ScopeChanged => {
                    ExternalViewError::ProjectionUnavailable(projection.to_owned())
                }
                _ => ExternalViewError::Unavailable,
            })?;
        Ok((scope, generation))
    }

    async fn log_roots(
        &self,
        transaction: &GuardedTransaction<'_>,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        roots: &[String],
        operation: &str,
    ) -> Result<()> {
        crate::subject_access_log::record_reads(
            transaction.transaction(),
            plan.root,
            &plan.root.id,
            &request.context,
            roots,
            operation,
            &self.expected,
            &request.correlation,
            &self.audit,
        )
        .await
        .map_err(|_| ExternalViewError::Unavailable)
    }

    async fn terminal(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        operation: &str,
        method: HttpMethod,
        permitted: bool,
    ) -> Result<()> {
        self.terminal_for(
            &request.context,
            &request.correlation,
            Some(&plan.root.id),
            request.root,
            operation,
            method,
            permitted,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)] // The audit entry records the admitted context and fixed operation.
    async fn terminal_for(
        &self,
        context: &AuthorizedRequestContext,
        correlation: &RequestCorrelation,
        entity: Option<&str>,
        root: Option<Uuid>,
        operation: &str,
        method: HttpMethod,
        permitted: bool,
    ) -> Result<()> {
        let entry = read_terminal_entry(
            self.audit.profile(),
            ReadTerminalAudit {
                terminal: TerminalAudit {
                    context: context.audit_context().cloned(),
                    outcome: if permitted {
                        TerminalAuditOutcome::Returned
                    } else {
                        TerminalAuditOutcome::Refused
                    },
                    method,
                    operation_id: operation.to_owned(),
                    entity_id: entity.map(str::to_owned),
                    action_id: None,
                    package_revision: self.expected.activation_id.clone(),
                    selected_access_profile: context.selected_profile().to_owned(),
                    purpose_present: context.purpose().is_some(),
                    principal_reference: context.principal().map(str::to_owned),
                    record_reference: root.map(|root| root.to_string()),
                    record_revision: None,
                    result_count: None,
                    field_set_reference: None,
                    correlation: correlation.clone(),
                },
                query_reference: None,
                row_boundary_reference: None,
            },
        )
        .map_err(|_| ExternalViewError::Unavailable)?;
        self.audit
            .append(entry)
            .await
            .map_err(|_| ExternalViewError::Unavailable)
    }

    async fn acquire(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        source_request: ProjectionRequest,
        fields: &BTreeSet<String>,
        supporting_until: Option<i64>,
        refresh_authority: Option<Arc<RefreshAuthority>>,
    ) -> std::result::Result<ProjectionResult, ExternalSourceError> {
        // Constructed only after the request's durable attempt and a
        // guarded root lookup. Source credentials come solely from the
        // pinned operator connection.
        let mut grant_until = plan.grant_valid_until();
        if let Some(expiry) = supporting_until {
            let cutoff =
                chrono::DateTime::from_timestamp(expiry, 0).ok_or(ExternalSourceError::Grant)?;
            grant_until = grant_until.min(cutoff);
        }
        let hooks = Arc::new(AcquisitionGate {
            deadline: request.deadline,
            grant_until,
            route: plan.projection.operation.as_str().to_owned(),
            refresh_authority,
        });
        self.sources
            .acquire(
                plan.projection.id.as_str(),
                hooks,
                source_request,
                fields,
                Utc::now,
            )
            .await
    }

    fn row_id(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        root: Uuid,
        source_key: &str,
    ) -> Result<String> {
        self.cursors
            .binding_digest(
                b"breg-external-view-row-v1",
                &json!([
                    self.registry.registry_id(),
                    request.view,
                    request.link,
                    root,
                    plan.source.binding_fingerprint(),
                    source_key
                ]),
            )
            .map_err(|_| ExternalViewError::Unavailable)
    }

    fn cursor_binding(
        &self,
        request: &ExternalViewRequest,
        scope: &ProjectionScope,
        generation: Option<ProjectionGeneration>,
        label: Option<ProjectionGeneration>,
    ) -> Result<String> {
        let context = &request.context;
        let boundaries = context
            .row_boundaries()
            .iter()
            .map(|boundary| {
                let operator = match boundary.operator() {
                    RowBoundaryOperator::Equals => "equals",
                    RowBoundaryOperator::In => "in",
                };
                json!([boundary.field(), operator, boundary.values()])
            })
            .collect::<Vec<_>>();
        self.cursors
            .binding_digest(
                b"breg-external-view-v1",
                &json!({
                    "activation": self.expected.activation_id,
                    "view": request.view,
                    "link": request.link,
                    "root": request.root,
                    "profile": context.selected_profile(),
                    "principal": context.principal(),
                    "requesterClient": context.requester_client(),
                    "purpose": context.purpose(),
                    "rowBoundaries": boundaries,
                    "recipients": context.recipients(),
                    "projection": scope.projection_id,
                    "epoch": scope.epoch,
                    "binding": scope.binding_digest,
                    "grant": scope.grant_digest,
                    "generation": generation.map(|value| value.generation),
                    "label": label.map(|value| (value.epoch, value.generation)),
                }),
            )
            .map_err(|_| ExternalViewError::Unavailable)
    }

    fn page_request(
        &self,
        mode: &ExternalQueryMode,
        binding: &str,
    ) -> Result<(ExternalQuery, Option<Position>)> {
        match mode {
            ExternalQueryMode::First(query) => Ok((query.clone(), None)),
            ExternalQueryMode::Continue(token) => {
                let payload: Continuation = self
                    .cursors
                    .open_external(token)
                    .map_err(|_| ExternalViewError::InvalidCursor)?;
                if payload.binding != binding || Utc::now().timestamp() >= payload.expires_at {
                    return Err(ExternalViewError::InvalidCursor);
                }
                Ok((payload.query, Some(payload.position)))
            }
        }
    }

    fn next_cursor(
        &self,
        binding: String,
        query: ExternalQuery,
        position: Position,
        expires_at: i64,
    ) -> Result<String> {
        let expires_at = expires_at.min(
            Utc::now()
                .timestamp()
                .saturating_add(self.cursors.max_age().as_secs() as i64),
        );
        seal_continuation(
            &self.cursors,
            &Continuation {
                binding,
                query,
                position,
                expires_at,
            },
        )
    }
}

/// Seal a continuation, refusing a sort value the next page would refuse, so
/// every cursor the server issues is one it accepts.
fn seal_continuation(cursors: &CursorCodec, continuation: &Continuation) -> Result<String> {
    if let Position::Read {
        sort_value: Some(value),
        ..
    } = &continuation.position
    {
        if !indexed::sort_value_resumable(value) {
            return Err(ExternalViewError::Unavailable);
        }
    }
    cursors
        .seal_external(continuation)
        .map_err(|_| ExternalViewError::Unavailable)
}

impl ExternalViewService for PostgresExternalViewService {
    fn managed_plan(&self, plan: &str) -> Option<&ResolvedExternalRefreshPlan> {
        self.managed_refresh.get(plan)
    }

    fn managed_step(
        &self,
        plan: String,
        request: ExternalViewRequest,
        start_sweep: bool,
    ) -> ServiceFuture<'_, Result<Value>> {
        Box::pin(async move {
            timeout_at(
                request.deadline,
                self.run_managed_step(&plan, request, start_sweep),
            )
            .await
            .map_err(|_| ExternalViewError::Unavailable)?
        })
    }

    fn admit_hint(
        &self,
        plan: String,
        claims: VerifiedRequestClaims,
        correlation: RequestCorrelation,
        deadline: Instant,
        hint: ExternalRefreshHint,
    ) -> ServiceFuture<'_, Result<HintAdmission>> {
        Box::pin(async move {
            timeout_at(
                deadline,
                self.run_hint(&plan, claims, correlation, deadline, hint),
            )
            .await
            .map_err(|_| ExternalViewError::Unavailable)?
        })
    }

    fn read(&self, request: ExternalViewRequest) -> ServiceFuture<'_, Result<Value>> {
        Box::pin(async move {
            timeout_at(request.deadline, self.run(request, None))
                .await
                .map_err(|_| ExternalViewError::Unavailable)?
        })
    }

    fn refresh(
        &self,
        request: ExternalViewRequest,
        mode: RefreshMode,
    ) -> ServiceFuture<'_, Result<Value>> {
        Box::pin(async move {
            let projection = self.refresh_projection(&request, mode);
            let outcome = timeout_at(request.deadline, self.run(request, Some(mode))).await;
            if let Some(projection) = projection {
                log_refresh(&projection, &outcome);
            }
            outcome.map_err(|_| ExternalViewError::Unavailable)?
        })
    }
}

impl PostgresExternalViewService {
    /// The projection a refresh request writes, when its view and link exist.
    fn refresh_projection(
        &self,
        request: &ExternalViewRequest,
        mode: RefreshMode,
    ) -> Option<String> {
        let link = self
            .registry
            .external_views()
            .views
            .get(&request.view)?
            .links
            .iter()
            .find(|link| link.id.as_str() == request.link)?;
        match mode {
            RefreshMode::Projection => Some(link.projection.to_string()),
            RefreshMode::Labels => link
                .label
                .as_ref()
                .map(|label| label.projection.to_string()),
        }
    }
}

/// A refresh page that fails as a whole is logged by projection and reason
/// category. Per-key outcomes of a completed page are logged when recorded.
fn log_refresh(
    projection: &str,
    outcome: &std::result::Result<Result<Value>, tokio::time::error::Elapsed>,
) {
    let reason = match outcome {
        Ok(Ok(_)) => return,
        Ok(Err(ExternalViewError::Concealed)) => "concealed",
        Ok(Err(ExternalViewError::InvalidCursor)) => "invalid-cursor",
        Ok(Err(ExternalViewError::Incomplete)) => "incomplete",
        Ok(Err(ExternalViewError::Unavailable)) => "unavailable",
        Ok(Err(ExternalViewError::ProjectionUnavailable(_))) => "projection-unavailable",
        Err(_) => "deadline",
    };
    tracing::warn!(projection, reason, "external projection refresh failed");
}

#[derive(Clone)]
struct RefreshAuthority {
    pool: RuntimePool,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    scope: ProjectionScope,
    parent: Option<(ProjectionScope, ProjectionGeneration)>,
    /// The parent snapshots that supplied this page's label selectors.
    supporting: Vec<SupportingSnapshot>,
    managed: Option<managed::AcquisitionAuthority>,
}

impl RefreshAuthority {
    async fn check(&self, deadline: Instant) -> std::result::Result<(), EvidenceHookError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| EvidenceHookError::Authority)?;
        let mut session = QueryCancellationGuard::new(self.pool.clone(), client);
        let transaction = if let Some(managed) = &self.managed {
            begin_record_transaction(
                session.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
                &managed.claims,
            )
            .await
        } else {
            begin_registry_transaction(
                session.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
            )
            .await
        }
        .map_err(|_| EvidenceHookError::Authority)?;
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2));
        if budget < Duration::from_millis(1) {
            return Err(EvidenceHookError::Authority);
        }
        transaction
            .set_statement_budget(budget)
            .await
            .map_err(|_| EvidenceHookError::Authority)?;
        let current = store::load_active_scope(
            &transaction,
            &self.scope.projection_id,
            &self.scope.binding_digest,
            &self.scope.grant_digest,
        )
        .await
        .map_err(|_| EvidenceHookError::Authority)?;
        if current.epoch != self.scope.epoch {
            return Err(EvidenceHookError::Authority);
        }
        if let Some(managed) = &self.managed {
            managed
                .check(&transaction)
                .await
                .map_err(|_| EvidenceHookError::Authority)?;
        }
        if let Some((parent, generation)) = &self.parent {
            let current = store::lock_generation(&transaction, parent)
                .await
                .map_err(|_| EvidenceHookError::Authority)?;
            if &current != generation {
                return Err(EvidenceHookError::Authority);
            }
            // Only the parent snapshots that supplied this page's selectors
            // matter; refreshes of other parents leave the sweep running.
            let keys = self
                .supporting
                .iter()
                .map(|parent| parent.subject_key.as_str())
                .collect::<Vec<_>>();
            let ids = self
                .supporting
                .iter()
                .map(|parent| parent.snapshot_id.as_str())
                .collect::<Vec<_>>();
            if !store::snapshots_current(&transaction, parent, &keys, &ids)
                .await
                .map_err(|_| EvidenceHookError::Authority)?
            {
                return Err(EvidenceHookError::Authority);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| EvidenceHookError::Authority)?;
        session.disarm();
        Ok(())
    }

    fn for_work(self: &Arc<Self>, work: &[RefreshWork]) -> Arc<Self> {
        if let Some(managed) = &self.managed {
            Arc::new(Self {
                managed: Some(managed.for_work(work)),
                ..self.as_ref().clone()
            })
        } else {
            Arc::clone(self)
        }
    }
}

struct AcquisitionGate {
    deadline: Instant,
    grant_until: chrono::DateTime<Utc>,
    route: String,
    refresh_authority: Option<Arc<RefreshAuthority>>,
}

impl AcquisitionGate {
    fn within_bounds(&self) -> std::result::Result<(), EvidenceHookError> {
        if Instant::now() >= self.deadline || Utc::now() >= self.grant_until {
            return Err(EvidenceHookError::Authority);
        }
        Ok(())
    }

    async fn admitted(&self) -> std::result::Result<(), EvidenceHookError> {
        self.within_bounds()?;
        if let Some(authority) = &self.refresh_authority {
            authority.check(self.deadline).await?;
        }
        self.within_bounds()
    }
}

impl EvidenceHostHooks for AcquisitionGate {
    fn before_acquisition<'a>(
        &'a self,
        intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async move {
            if intent.route != self.route {
                return Err(EvidenceHookError::Authority);
            }
            self.admitted().await
        })
    }

    fn before_credentials<'a>(&'a self, _intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        Box::pin(async { self.admitted().await })
    }
}

struct RootKeys {
    select: String,
    publication_eligibility: String,
    id: String,
    base_id: String,
}

impl RootKeys {
    fn new(plan: &Plan<'_>) -> Result<Self> {
        let key_field = plan.link.from_field.as_str();
        let relations = ReadRelations::statistics(plan.root, &[key_field.to_owned()])
            .map_err(|_| ExternalViewError::Unavailable)?;
        let key = relations
            .field_expression(plan.root, key_field)
            .map_err(|_| ExternalViewError::Unavailable)?;
        if key.encrypted {
            return Err(ExternalViewError::Unavailable);
        }
        Ok(Self {
            select: format!(
                "SELECT {}, ({})::text FROM {}",
                relations.id_expression, key.sql, relations.from_sql
            ),
            publication_eligibility: format!(
                "SELECT 1 FROM {} WHERE {} = ANY($12::uuid[]) AND ({})::text = $6::text",
                relations.from_sql, relations.id_expression, key.sql,
            ),
            id: relations.id_expression,
            base_id: format!("{}.record_id", relations.base_alias),
        })
    }

    async fn for_root(
        &self,
        transaction: &GuardedTransaction<'_>,
        root: Uuid,
    ) -> Result<Option<Option<String>>> {
        let row = transaction
            .transaction()
            .query_opt(&format!("{} WHERE {} = $1", self.select, self.id), &[&root])
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        Ok(row.map(|row| row.get(1)))
    }

    fn page_sql(&self) -> String {
        // The base table joins the source view on the record id, and
        // PostgreSQL does not carry an inequality across that equality.
        // Repeating the bound on the base table lets a merge join start its
        // primary key scan at the continuation instead of at the first record.
        format!(
            "{} WHERE ($1::uuid IS NULL OR ({} > $1 AND {} > $1)) ORDER BY {} LIMIT $2",
            self.select, self.id, self.base_id, self.id
        )
    }

    async fn page(
        &self,
        transaction: &GuardedTransaction<'_>,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<(Uuid, Option<String>)>> {
        // PostgreSQL can underestimate the population behind the RLS
        // predicates and pick a parallel scan plus a sort for every page.
        // Prefer the ordered primary-key path for this bounded selection
        // transaction. RLS still filters before LIMIT.
        transaction
            .transaction()
            .batch_execute("SET LOCAL enable_seqscan = off; SET LOCAL enable_sort = off;")
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        let rows = transaction
            .transaction()
            .query(&self.page_sql(), &[&after, &i64::from(limit)])
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }
}

async fn active_scope(
    transaction: &GuardedTransaction<'_>,
    source: &BoundExternalSource,
    projection: &str,
) -> Result<ProjectionScope> {
    let unavailable = || ExternalViewError::ProjectionUnavailable(projection.to_owned());
    if Utc::now() >= source.grant_valid_until() {
        return Err(unavailable());
    }
    // Another process bound this projection with different authority or a
    // different cache lifetime, or an operator withdrew it.
    let scope = store::load_active_scope(
        transaction,
        projection,
        source.binding_fingerprint(),
        source.grant_fingerprint(),
    )
    .await
    .map_err(|error| match error {
        store::ProjectionError::ScopeChanged | store::ProjectionError::InvalidScope => {
            unavailable()
        }
        _ => ExternalViewError::Unavailable,
    })?;
    if Some(scope.cache_ttl_seconds) != source.effective_cache_ttl_seconds().map(i64::from) {
        return Err(unavailable());
    }
    Ok(scope)
}

impl PostgresExternalViewService {
    fn live_records(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        root: Uuid,
        result: Option<ProjectionResult>,
    ) -> Result<(&'static str, Vec<Value>)> {
        let rows = match result {
            Some(ProjectionResult::Exact {
                record: ProjectionRecord::Present { fields, .. },
            }) => (
                "available",
                vec![response_row(root, "available", Value::Object(fields))],
            ),
            Some(ProjectionResult::Exact {
                record: ProjectionRecord::AuthoritativeAbsent { .. },
            }) => ("available", vec![response_row(root, "absent", json!({}))]),
            Some(ProjectionResult::ByParent { rows, .. }) => (
                "available",
                rows.into_iter()
                    .map(|row| {
                        let mut value = response_row(root, "available", Value::Object(row.fields));
                        value["rowId"] = json!(self.row_id(request, plan, root, &row.key)?);
                        Ok(value)
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => ("unavailable", Vec::new()),
        };
        Ok(rows)
    }
}

fn availability(value: ExternalAvailability) -> &'static str {
    match value {
        ExternalAvailability::Available => "available",
        ExternalAvailability::Absent => "absent",
        ExternalAvailability::Unavailable => "unavailable",
    }
}

fn response_row(root: Uuid, availability: &str, fields: Value) -> Value {
    json!({"rootId": root, "availability": availability, "fields": fields})
}

fn view_response(
    plan: &Plan<'_>,
    status: &str,
    records: Vec<Value>,
    count: Option<u64>,
    next: Option<String>,
) -> Value {
    let mut body = json!({
        "status": status,
        "authority": plan.external.authority,
        "records": records,
    });
    if let Some(count) = count {
        body["count"] = json!(count);
    }
    if let Some(next) = next {
        body["nextCursor"] = json!(next);
    }
    body
}

#[derive(Clone)]
struct RefreshRows {
    rows: Vec<(Uuid, Option<String>)>,
    next: Option<RefreshAfter>,
    eligibility: String,
    supporting_until: Option<i64>,
    supporting: Vec<SupportingSnapshot>,
}

struct RefreshWork {
    key: String,
    roots: BTreeSet<Uuid>,
    ticket: RefreshTicket,
    managed_targets: Vec<(i64, i64)>,
}

enum RefreshResult {
    Accepted(AcceptedSnapshot),
    Failed(RefreshFailure),
}

impl PostgresExternalViewService {
    async fn refresh_rows(
        &self,
        transaction: &GuardedTransaction<'_>,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        parent: Option<&(ProjectionScope, ProjectionGeneration)>,
        after: Option<RefreshAfter>,
        page_size: u16,
    ) -> Result<RefreshRows> {
        if let Some((parent_scope, parent_generation)) = parent {
            let after = match after {
                Some(RefreshAfter::Label {
                    root_id,
                    member_key,
                }) => Some(LabelAfter {
                    root_id,
                    member_key,
                }),
                Some(RefreshAfter::Root { .. }) => return Err(ExternalViewError::InvalidCursor),
                None => None,
            };
            let selectors = LabelAcquisition::new(
                &self.registry,
                request.context.selected_profile(),
                request
                    .context
                    .purpose()
                    .ok_or(ExternalViewError::Concealed)?,
                &request.view,
                &request.link,
                parent_scope,
                *parent_generation,
            )
            .map_err(|_| ExternalViewError::Concealed)?;
            let page = selectors
                .page(transaction, after.as_ref(), page_size)
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            return Ok(RefreshRows {
                rows: page
                    .rows
                    .into_iter()
                    .map(|row| (row.root_id, Some(row.selector)))
                    .collect(),
                next: page.continuation.map(|after| RefreshAfter::Label {
                    root_id: after.root_id,
                    member_key: after.member_key,
                }),
                eligibility: selectors.publication_eligibility().to_owned(),
                supporting_until: page.minimum_parent_expires_at,
                supporting: page.supporting,
            });
        }
        let after = match after {
            Some(RefreshAfter::Root { root_id }) => Some(root_id),
            Some(RefreshAfter::Label { .. }) => return Err(ExternalViewError::InvalidCursor),
            None => None,
        };
        // By-parent acquisitions use a smaller request budget.
        let size = if plan.projection.cardinality == ExternalCardinality::Many {
            page_size.min(10)
        } else {
            page_size
        };
        let keys = RootKeys::new(plan)?;
        let mut rows = keys.page(transaction, after, size + 1).await?;
        let has_more = rows.len() > usize::from(size);
        rows.truncate(usize::from(size));
        let next = rows
            .last()
            .filter(|_| has_more)
            .map(|(root_id, _)| RefreshAfter::Root { root_id: *root_id });
        Ok(RefreshRows {
            rows,
            next,
            eligibility: keys.publication_eligibility,
            supporting_until: None,
            supporting: Vec::new(),
        })
    }

    async fn refresh_page(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        claims: &ClaimContext,
    ) -> Result<HeldResponse> {
        let mut session = self.session().await?;
        let transaction = self
            .transaction(&mut session, claims, request.deadline)
            .await?;
        let scope = active_scope(&transaction, plan.source, plan.projection.id.as_str()).await?;
        let parent = if let Some(parent) = &plan.label_parent {
            Some(
                self.lock_scope(&transaction, parent.source, parent.projection.id.as_str())
                    .await?,
            )
        } else {
            None
        };
        let binding = self.cursor_binding(
            request,
            &scope,
            None,
            parent.as_ref().map(|(_, generation)| *generation),
        )?;
        let (query, position) = self.page_request(&request.query, &binding)?;
        let (after, minimum_sequence) = match position {
            Some(Position::Refresh {
                after,
                minimum_sequence,
            }) => (Some(after), minimum_sequence),
            Some(Position::Read { .. }) => return Err(ExternalViewError::InvalidCursor),
            None => (
                None,
                store::next_refresh_sequence(&transaction, &scope)
                    .await
                    .map_err(|_| ExternalViewError::Unavailable)?,
            ),
        };
        let page = self
            .refresh_rows(
                &transaction,
                request,
                plan,
                parent.as_ref(),
                after,
                query.page_size,
            )
            .await?;
        let (work, reused, invalid) = self
            .prepare_refresh(
                &transaction,
                request,
                plan,
                &scope,
                &page,
                minimum_sequence,
                &BTreeSet::new(),
            )
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        session.disarm();
        drop(session);

        let attempted = work.len();
        let tally = self
            .execute_refresh(
                request,
                plan,
                claims,
                &scope,
                parent.as_ref(),
                &page,
                work,
                None,
            )
            .await?;
        let published = tally.published;
        let unavailable = invalid + attempted - published;
        let expires_at = plan.grant_valid_until().timestamp();
        let mut body = json!({"processed": page.rows.len(), "published": published, "reused": reused, "unavailable": unavailable});
        if let Some(after) = page.next {
            body["nextCursor"] = json!(self.next_cursor(
                binding,
                query,
                Position::Refresh {
                    after,
                    minimum_sequence
                },
                expires_at
            )?);
        }
        Ok(HeldResponse { body, expires_at })
    }

    #[allow(clippy::too_many_arguments)] // Selection, per-key tickets and sweep baseline share a transaction.
    async fn prepare_refresh(
        &self,
        transaction: &GuardedTransaction<'_>,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        scope: &ProjectionScope,
        page: &RefreshRows,
        minimum_sequence: i64,
        required_keys: &BTreeSet<String>,
    ) -> Result<(Vec<RefreshWork>, usize, usize)> {
        // A root without a link key is covered with no outside value, so it
        // needs no acquisition. A key the store or the source contract would
        // refuse is never sent: its root stays unavailable, and the rest of
        // the page still refreshes.
        let mut by_key = BTreeMap::<String, BTreeSet<Uuid>>::new();
        let mut invalid = 0usize;
        for (root, key) in &page.rows {
            match key.as_deref() {
                None | Some("") => {}
                Some(key) if store::valid_key(key) && projection_token_valid(key) => {
                    by_key.entry(key.to_owned()).or_default().insert(*root);
                }
                Some(_) => invalid += 1,
            }
        }
        if invalid > 0 {
            tracing::warn!(
                projection = plan.projection.id.as_str(),
                reason = "invalid-key",
                keys = invalid,
                "external projection refresh failed for some keys"
            );
        }
        let keys = by_key.keys().cloned().collect::<Vec<_>>();
        let mut due = store::refresh_due_keys(
            transaction,
            scope,
            &keys,
            minimum_sequence,
            Utc::now().timestamp(),
        )
        .await
        .map_err(|_| ExternalViewError::Unavailable)?;
        due.extend(
            required_keys
                .iter()
                .filter(|key| by_key.contains_key(*key))
                .cloned(),
        );
        let reused = keys.len() - due.len();
        let lease = refresh_lease(request.deadline);
        let mut work = Vec::with_capacity(due.len());
        for (key, roots) in by_key {
            if !due.contains(&key) {
                continue;
            }
            let ticket = store::allocate_refresh(transaction, scope, &key, lease)
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            work.push(RefreshWork {
                key,
                roots,
                ticket,
                managed_targets: Vec::new(),
            });
        }
        Ok((work, reused, invalid))
    }

    #[allow(clippy::too_many_arguments)] // Both manual and managed pages carry the selected authority.
    async fn execute_refresh(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        claims: &ClaimContext,
        scope: &ProjectionScope,
        parent: Option<&(ProjectionScope, ProjectionGeneration)>,
        page: &RefreshRows,
        work: Vec<RefreshWork>,
        managed: Option<&managed::LeaseFence>,
    ) -> Result<RefreshTally> {
        if work.is_empty() {
            return Ok(RefreshTally::default());
        }
        let authority = Arc::new(RefreshAuthority {
            pool: self.pool.clone(),
            expected: self.expected.clone(),
            lock_key: self.lock_key,
            lock_timeout: self.lock_timeout,
            scope: scope.clone(),
            parent: parent.cloned(),
            supporting: page.supporting.clone(),
            managed: managed.map(|lease| managed::AcquisitionAuthority::new(lease, claims, page)),
        });
        let outcomes = self
            .fetch_refresh(request, plan, &work, page.supporting_until, authority)
            .await;
        self.record_refresh(
            request,
            plan,
            claims,
            scope,
            parent.map(|(_, generation)| generation),
            page,
            work.into_iter().zip(outcomes).collect(),
            managed,
        )
        .await
    }

    /// Records each acquisition outcome in its own short transaction and
    /// returns their internal outcomes. A publication holds the projection
    /// scope row until it commits, and indexed reads share that row, so one
    /// transaction for the whole page would hold readers back for every key.
    /// The committed outcomes are logged by reason category, without keys.
    #[allow(clippy::too_many_arguments)] // The page's scope, parent and rows come from its selection transaction.
    async fn record_refresh(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        claims: &ClaimContext,
        scope: &ProjectionScope,
        parent: Option<&ProjectionGeneration>,
        page: &RefreshRows,
        results: Vec<(RefreshWork, RefreshResult)>,
        managed: Option<&managed::LeaseFence>,
    ) -> Result<RefreshTally> {
        let mut tally = RefreshTally::default();
        let recorded = self
            .record_outcomes(
                request, plan, claims, scope, parent, page, results, &mut tally, managed,
            )
            .await;
        tally.log(plan.projection.id.as_str());
        recorded.map(|()| tally)
    }

    #[allow(clippy::too_many_arguments)] // See `record_refresh`.
    async fn record_outcomes(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        claims: &ClaimContext,
        scope: &ProjectionScope,
        parent: Option<&ProjectionGeneration>,
        page: &RefreshRows,
        results: Vec<(RefreshWork, RefreshResult)>,
        tally: &mut RefreshTally,
        managed: Option<&managed::LeaseFence>,
    ) -> Result<()> {
        let mut session = self.session().await?;
        let mut results = results.into_iter();
        while let Some((work, result)) = results.next() {
            let transaction = self
                .transaction(&mut session, claims, request.deadline)
                .await?;
            if let Some(lease) = managed {
                lease.check(&transaction, &work.managed_targets).await?;
            }
            let current =
                active_scope(&transaction, plan.source, plan.projection.id.as_str()).await?;
            if current.epoch != scope.epoch {
                return Err(ExternalViewError::Unavailable);
            }
            if let (Some(parent), Some(selected_generation)) = (&plan.label_parent, parent) {
                // A rotated or withdrawn parent abandons the rest of the
                // page. A database or lock failure is reported as such and
                // leaves the receipts to expire with their leases.
                let parent_is_current = match self
                    .lock_scope(&transaction, parent.source, parent.projection.id.as_str())
                    .await
                {
                    Ok((_, generation)) => generation == *selected_generation,
                    Err(ExternalViewError::ProjectionUnavailable(_)) => false,
                    Err(error) => return Err(error),
                };
                if !parent_is_current
                    || page
                        .supporting_until
                        .is_some_and(|cutoff| Utc::now().timestamp() >= cutoff)
                {
                    let abandoned = std::iter::once(work).chain(results.map(|(work, _)| work));
                    let mut keys = 0usize;
                    for work in abandoned {
                        store::fail_refresh(&transaction, &work.ticket, RefreshFailure::Abandoned)
                            .await
                            .map_err(|_| ExternalViewError::Unavailable)?;
                        keys += 1;
                    }
                    transaction
                        .commit()
                        .await
                        .map_err(|_| ExternalViewError::Unavailable)?;
                    session.disarm();
                    tally.failed(RefreshFailure::Abandoned, keys);
                    return Err(ExternalViewError::Unavailable);
                }
            }
            let outcome = match result {
                RefreshResult::Accepted(snapshot) => {
                    let root_ids = work.roots.into_iter().collect::<Vec<_>>();
                    // The RLS recheck and publication share a statement
                    // snapshot. A detached association does not erase a
                    // shared fact still used by another root.
                    match store::publish_for_roots(
                        &transaction,
                        &work.ticket,
                        &snapshot,
                        &page.eligibility,
                        &root_ids,
                    )
                    .await
                    {
                        Ok(store::Publication::Published | store::Publication::Replay) => {
                            RefreshOutcome::Published(if snapshot.is_authorised_absence() {
                                queue::Settlement::AuthorizedAbsence
                            } else if snapshot.is_empty_collection() {
                                queue::Settlement::EmptyCollection
                            } else {
                                queue::Settlement::Published
                            })
                        }
                        Ok(store::Publication::Ineligible)
                        | Err(store::ProjectionError::StaleRefresh) => {
                            store::fail_refresh(
                                &transaction,
                                &work.ticket,
                                RefreshFailure::Abandoned,
                            )
                            .await
                            .map_err(|_| ExternalViewError::Unavailable)?;
                            RefreshOutcome::Failed(RefreshFailure::Abandoned)
                        }
                        Err(_) => return Err(ExternalViewError::Unavailable),
                    }
                }
                RefreshResult::Failed(failure) => {
                    store::fail_refresh(&transaction, &work.ticket, failure)
                        .await
                        .map_err(|_| ExternalViewError::Unavailable)?;
                    RefreshOutcome::Failed(failure)
                }
            };
            transaction
                .commit()
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            match outcome {
                RefreshOutcome::Published(_) => tally.published += 1,
                RefreshOutcome::Failed(failure) => tally.failed(failure, 1),
            }
            if managed.is_some() {
                tally.by_key.insert(work.key, outcome);
            }
        }
        session.disarm();
        Ok(())
    }

    async fn fetch_refresh(
        &self,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        work: &[RefreshWork],
        supporting_until: Option<i64>,
        authority: Arc<RefreshAuthority>,
    ) -> Vec<RefreshResult> {
        let approved_fields = plan
            .projection
            .fields
            .iter()
            .map(|field| field.as_str().to_owned())
            .collect();
        let expires_at = plan.source.grant_valid_until().timestamp();
        let mut results = Vec::with_capacity(work.len());
        match plan.projection.cardinality {
            ExternalCardinality::One => {
                for chunk in work.chunks(plan.source.maximum_batch_keys().max(1)) {
                    let observed_at = Utc::now().timestamp();
                    let acquired = self
                        .acquire(
                            request,
                            plan,
                            ProjectionRequest::Batch {
                                keys: chunk.iter().map(|item| item.key.clone()).collect(),
                            },
                            &approved_fields,
                            supporting_until,
                            Some(authority.for_work(chunk)),
                        )
                        .await;
                    match acquired {
                        Ok(ProjectionResult::Batch { records }) => {
                            let mut records = records
                                .into_iter()
                                .map(|record| (record.key().to_owned(), record))
                                .collect::<BTreeMap<_, _>>();
                            results.extend(chunk.iter().map(|item| {
                                records.remove(&item.key).map_or(
                                    RefreshResult::Failed(RefreshFailure::Incomplete),
                                    |record| {
                                        accepted_record(
                                            &self.cursors,
                                            plan.source.binding_fingerprint(),
                                            record,
                                            observed_at,
                                            expires_at,
                                        )
                                    },
                                )
                            }));
                        }
                        result => {
                            let failure = acquisition_failure(result.err());
                            results.extend(chunk.iter().map(|_| RefreshResult::Failed(failure)));
                        }
                    }
                }
            }
            ExternalCardinality::Many => {
                for item in work {
                    let observed_at = Utc::now().timestamp();
                    let acquired = self
                        .acquire(
                            request,
                            plan,
                            ProjectionRequest::ByParent {
                                parent_key: item.key.clone(),
                            },
                            &approved_fields,
                            supporting_until,
                            Some(authority.for_work(std::slice::from_ref(item))),
                        )
                        .await;
                    let result = match acquired {
                        Ok(ProjectionResult::ByParent {
                            parent_key,
                            snapshot,
                            rows,
                        }) if parent_key == item.key => {
                            let rows = rows
                                .into_iter()
                                .map(|row| ProjectionRow::new(&row.key, Value::Object(row.fields)))
                                .collect::<std::result::Result<Vec<_>, _>>();
                            rows.and_then(|rows| {
                                let snapshot_id = snapshot_identity(
                                    &self.cursors,
                                    plan.source.binding_fingerprint(),
                                    Some(&snapshot),
                                )?;
                                AcceptedSnapshot::complete_collection(
                                    &item.key,
                                    &snapshot_id,
                                    observed_at,
                                    expires_at,
                                    RetentionPermission::PermittedUntil(expires_at),
                                    rows,
                                )
                            })
                            .map_or(
                                RefreshResult::Failed(RefreshFailure::Incomplete),
                                RefreshResult::Accepted,
                            )
                        }
                        result => RefreshResult::Failed(acquisition_failure(result.err())),
                    };
                    results.push(result);
                }
            }
        }
        results
    }
}

fn accepted_record(
    cursors: &CursorCodec,
    binding: &str,
    record: ProjectionRecord,
    observed_at: i64,
    expires_at: i64,
) -> RefreshResult {
    let source_revision = match &record {
        ProjectionRecord::Present {
            source_revision, ..
        }
        | ProjectionRecord::AuthoritativeAbsent {
            source_revision, ..
        } => source_revision.as_deref(),
        ProjectionRecord::Unavailable { .. } => None,
    };
    let Ok(id) = snapshot_identity(cursors, binding, source_revision) else {
        return RefreshResult::Failed(RefreshFailure::Incomplete);
    };
    let retention = RetentionPermission::PermittedUntil(expires_at);
    let snapshot = match record {
        ProjectionRecord::Present { key, fields, .. } => {
            ProjectionRow::new(&key, Value::Object(fields)).and_then(|row| {
                AcceptedSnapshot::one(&key, &id, observed_at, expires_at, retention, row)
            })
        }
        ProjectionRecord::AuthoritativeAbsent { key, .. } => {
            AcceptedSnapshot::authorized_absence(&key, &id, observed_at, expires_at, retention)
        }
        ProjectionRecord::Unavailable { .. } => {
            return RefreshResult::Failed(RefreshFailure::Unavailable)
        }
    };
    snapshot.map_or(
        RefreshResult::Failed(RefreshFailure::Incomplete),
        RefreshResult::Accepted,
    )
}

/// Time a refresh receipt stays live beyond the page deadline. It absorbs
/// scheduling delay and a publication committing as the deadline passes.
const REFRESH_LEASE_MARGIN: Duration = Duration::from_secs(10);

/// A refresh page acquires and publishes before its deadline, so its receipts
/// stay live for the time left plus a margin. A slow page is never treated
/// as abandoned while it can still publish.
fn refresh_lease(deadline: Instant) -> Duration {
    let remaining = deadline.saturating_duration_since(Instant::now());
    Duration::from_secs(remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0))
        + REFRESH_LEASE_MARGIN
}

/// Committed outcomes of one refresh page: published keys and failed keys by
/// reason category.
#[derive(Default)]
struct RefreshTally {
    published: usize,
    failed: BTreeMap<&'static str, usize>,
    by_key: BTreeMap<String, RefreshOutcome>,
}

#[derive(Clone, Copy)]
enum RefreshOutcome {
    Published(queue::Settlement),
    Failed(RefreshFailure),
}

impl RefreshOutcome {
    fn failure(self) -> Option<RefreshFailure> {
        match self {
            Self::Failed(failure) => Some(failure),
            Self::Published(_) => None,
        }
    }

    fn settlement(self) -> Option<queue::Settlement> {
        match self {
            Self::Published(outcome) => Some(outcome),
            Self::Failed(_) => None,
        }
    }
}

impl RefreshTally {
    fn failed(&mut self, failure: RefreshFailure, keys: usize) {
        *self.failed.entry(failure.as_str()).or_default() += keys;
    }

    fn log(&self, projection: &str) {
        tracing::info!(
            projection,
            published = self.published,
            "external projection refresh recorded"
        );
        for (reason, keys) in &self.failed {
            tracing::warn!(
                projection,
                reason,
                keys,
                "external projection refresh failed for some keys"
            );
        }
    }
}

/// A live read that cannot reach its source answers unavailable. The failure
/// is logged by projection and reason category, never with the key.
fn live_acquisition(
    projection: &str,
    result: std::result::Result<ProjectionResult, ExternalSourceError>,
) -> Option<ProjectionResult> {
    match result {
        Ok(result) => Some(result),
        Err(error) => {
            tracing::warn!(
                projection,
                reason = acquisition_failure(Some(error)).as_str(),
                "external projection live acquisition failed"
            );
            None
        }
    }
}

fn acquisition_failure(error: Option<ExternalSourceError>) -> RefreshFailure {
    match error {
        Some(ExternalSourceError::Grant) => RefreshFailure::Denied,
        Some(ExternalSourceError::Acquisition(
            AdapterProjectionError::NoStore | AdapterProjectionError::RetentionRefused,
        )) => RefreshFailure::RetentionRefused,
        Some(
            ExternalSourceError::Unbound
            | ExternalSourceError::Configuration
            | ExternalSourceError::Artifact
            | ExternalSourceError::Contract,
        ) => RefreshFailure::InvalidBinding,
        Some(ExternalSourceError::Result) => RefreshFailure::Incomplete,
        _ => RefreshFailure::Unavailable,
    }
}

fn snapshot_identity(
    cursors: &CursorCodec,
    binding: &str,
    source_revision: Option<&str>,
) -> std::result::Result<String, store::ProjectionError> {
    // Every fresh acquisition has its own receipt. Preserve a scoped,
    // keyed reference to an approved source revision when one was supplied.
    let capture = Uuid::new_v4();
    let Some(source_revision) = source_revision else {
        return Ok(capture.to_string());
    };
    let reference = cursors
        .binding_digest(
            b"breg-external-source-revision-v1",
            &json!([binding, source_revision]),
        )
        .map_err(|_| store::ProjectionError::InvalidSnapshot)?;
    Ok(format!("{capture}:{reference}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sort value past the 4096-byte filter bound travels inside the
    /// sealed continuation and opens unchanged.
    #[test]
    fn a_continuation_carries_a_long_sort_value() {
        let codec = CursorCodec::new(
            zeroize::Zeroizing::new(vec![42; 32]),
            Duration::from_secs(120),
        )
        .unwrap();
        let sort_value = "s".repeat(5000);
        let token = codec
            .seal_external(&Continuation {
                binding: "binding".to_owned(),
                expires_at: Utc::now().timestamp() + 60,
                query: ExternalQuery::default(),
                position: Position::Read {
                    root_id: Uuid::nil(),
                    source_key: "row".to_owned(),
                    sort_value: Some(sort_value.clone()),
                },
            })
            .unwrap();
        assert!(token.len() <= crate::query::MAX_CURSOR_TOKEN_BYTES);
        let opened: Continuation = codec.open_external(&token).unwrap();
        let Position::Read {
            sort_value: Some(opened),
            ..
        } = opened.position
        else {
            panic!("position changed");
        };
        assert_eq!(opened, sort_value);
    }

    fn continuation_at(sort_value: String) -> Continuation {
        Continuation {
            binding: "binding".to_owned(),
            expires_at: Utc::now().timestamp() + 60,
            query: ExternalQuery::default(),
            position: Position::Read {
                root_id: Uuid::nil(),
                source_key: "row".to_owned(),
                sort_value: Some(sort_value),
            },
        }
    }

    /// The server never issues a cursor it would refuse: a sort value past the
    /// resume bound fails when the cursor is issued, and every cursor that is
    /// issued opens and carries a value the continuation accepts.
    #[test]
    fn a_cursor_is_issued_only_for_a_sort_value_it_will_accept() {
        let codec = CursorCodec::new(
            zeroize::Zeroizing::new(vec![42; 32]),
            Duration::from_secs(120),
        )
        .unwrap();
        let bound = indexed::MAXIMUM_CURSOR_SORT_VALUE_BYTES;
        for value in [
            "a".repeat(bound),
            "\"".repeat(1000),
            "\u{7}".repeat(500),
            "\u{e9}".repeat(bound / 2),
        ] {
            let token = seal_continuation(&codec, &continuation_at(value.clone()))
                .unwrap_or_else(|_| panic!("a {}-byte value is issued", value.len()));
            let opened: Continuation = codec.open_external(&token).unwrap();
            let Position::Read {
                sort_value: Some(opened),
                ..
            } = opened.position
            else {
                panic!("position changed");
            };
            assert_eq!(opened, value);
            assert!(indexed::sort_value_resumable(&opened));
        }
        // Past the bound, and a value whose JSON escaping overflows the 8 KiB
        // payload, fail when issued rather than on the next page.
        for value in ["a".repeat(bound + 1), "\"".repeat(bound)] {
            assert!(
                matches!(
                    seal_continuation(&codec, &continuation_at(value)),
                    Err(ExternalViewError::Unavailable)
                ),
                "an oversized sort value is refused when the cursor is issued"
            );
        }
    }

    #[test]
    fn a_new_capture_preserves_a_scoped_source_revision_reference() {
        let codec = CursorCodec::new(
            zeroize::Zeroizing::new(vec![42; 32]),
            Duration::from_secs(120),
        )
        .unwrap();
        let revision = "synthetic-source-revision";
        let first = snapshot_identity(&codec, "binding-a", Some(revision)).unwrap();
        let second = snapshot_identity(&codec, "binding-a", Some(revision)).unwrap();
        let third = snapshot_identity(&codec, "binding-b", Some(revision)).unwrap();
        assert_ne!(first, second);
        assert!(!first.contains(revision));
        assert_eq!(
            first.split_once(':').unwrap().1,
            second.split_once(':').unwrap().1
        );
        assert_ne!(
            first.split_once(':').unwrap().1,
            third.split_once(':').unwrap().1
        );
        assert!(Uuid::parse_str(&snapshot_identity(&codec, "binding-a", None).unwrap()).is_ok());
    }

    #[test]
    fn a_no_store_acquisition_is_recorded_as_a_retention_refusal() {
        assert_eq!(
            acquisition_failure(Some(ExternalSourceError::Acquisition(
                AdapterProjectionError::NoStore
            ))),
            RefreshFailure::RetentionRefused
        );
    }

    #[test]
    fn a_failed_live_acquisition_is_logged_by_projection_and_reason() {
        let captured = registry_platform_testing::CapturedDiagnosticLogs::default();
        let kept = tracing::dispatcher::with_default(&captured.subscriber(), || {
            live_acquisition("person-live", Err(ExternalSourceError::Grant))
        });
        assert!(kept.is_none(), "the view answers unavailable");
        let logs = captured.text();
        assert_eq!(logs.lines().count(), 1, "{logs}");
        for expected in [
            r#""level":"WARN""#,
            r#""projection":"person-live""#,
            r#""reason":"denied""#,
        ] {
            assert!(logs.contains(expected), "{logs}");
        }
    }

    #[tokio::test]
    async fn a_failed_refresh_is_logged_by_projection_and_reason() {
        let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        let captured = registry_platform_testing::CapturedDiagnosticLogs::default();
        tracing::dispatcher::with_default(&captured.subscriber(), || {
            log_refresh("person-indexed", &Ok(Ok(json!({"published": 1}))));
            log_refresh("person-indexed", &Ok(Err(ExternalViewError::InvalidCursor)));
            log_refresh(
                "person-labels",
                &Ok(Err(ExternalViewError::ProjectionUnavailable(
                    "person-labels".to_owned(),
                ))),
            );
            log_refresh("person-indexed", &Err(elapsed));
        });
        let logs = captured.text();
        assert_eq!(
            logs.lines().count(),
            3,
            "a completed page adds no line: {logs}"
        );
        for (line, (projection, reason)) in logs.lines().zip([
            ("person-indexed", "invalid-cursor"),
            ("person-labels", "projection-unavailable"),
            ("person-indexed", "deadline"),
        ]) {
            assert!(line.contains(r#""level":"WARN""#), "{line}");
            assert!(
                line.contains(&format!(r#""projection":"{projection}""#)),
                "{line}"
            );
            assert!(line.contains(&format!(r#""reason":"{reason}""#)), "{line}");
        }
    }

    #[test]
    fn a_refresh_lease_outlives_the_page_deadline() {
        // The longest configurable request deadline is a minute.
        let lease = refresh_lease(Instant::now() + Duration::from_secs(60));
        assert!(
            lease > Duration::from_secs(60) + Duration::from_secs(5),
            "{lease:?}"
        );
        assert!(
            lease <= Duration::from_secs(60) + REFRESH_LEASE_MARGIN,
            "{lease:?}"
        );
        assert_eq!(refresh_lease(Instant::now()), REFRESH_LEASE_MARGIN);
    }
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod postgres_tests {
    use super::*;
    use crate::correlation::RequestCorrelation;
    use crate::postgres::external_projection::postgres_tests::{two_projection_project, Activated};

    fn service(registry: &CompiledRegistry, fixture: &Activated) -> PostgresExternalViewService {
        service_with(registry, fixture, Duration::from_secs(2))
    }

    fn service_with(
        registry: &CompiledRegistry,
        fixture: &Activated,
        lock_timeout: Duration,
    ) -> PostgresExternalViewService {
        service_from(registry, fixture, lock_timeout, indexed_sources())
    }

    fn indexed_sources() -> crate::external_source::ExternalSourceService {
        crate::external_source::tests::indexed_service(&[
            ("projection", "binding", "grant", 60),
            ("other", "other-binding", "other-grant", 120),
        ])
    }

    fn service_from(
        registry: &CompiledRegistry,
        fixture: &Activated,
        lock_timeout: Duration,
        sources: crate::external_source::ExternalSourceService,
    ) -> PostgresExternalViewService {
        PostgresExternalViewService::new(
            fixture.pool.clone(),
            Arc::new(registry.clone()),
            fixture.expected.clone(),
            RegistryLockKey::derive(registry.registry_id()).unwrap(),
            lock_timeout,
            crate::audit::test_support::capturing(
                registry_platform_audit::AuditProfile::production_from_secret_bytes(
                    vec![0x81; 32].into(),
                )
                .unwrap(),
            )
            .0,
            Arc::new(
                CursorCodec::new(
                    zeroize::Zeroizing::new(vec![7; 32]),
                    Duration::from_secs(60),
                )
                .unwrap(),
            ),
            sources,
        )
    }

    fn request(link: &str) -> ExternalViewRequest {
        ExternalViewRequest {
            context: crate::api::AuthorizedRequestContext::new(
                Some("reader-principal".to_owned()),
                Some("consultation".to_owned()),
                "reader".to_owned(),
                Vec::new(),
            ),
            correlation: RequestCorrelation::breg_created(),
            view: "view".to_owned(),
            link: link.to_owned(),
            root: None,
            query: ExternalQueryMode::First(ExternalQuery::default()),
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }

    async fn scopes(fixture: &Activated) -> BTreeMap<String, (String, bool)> {
        fixture
            .migration
            .query(
                "SELECT projection_id,contract_digest,active
                 FROM registry_internal.registry_external_projection_scopes",
                &[],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get(0), (row.get(1), row.get(2))))
            .collect()
    }

    #[tokio::test]
    async fn a_refused_projection_scope_leaves_the_other_projections_serving() {
        let registry =
            super::super::external_view_query::tests::compile_project(&two_projection_project());
        let fixture = Activated::new(&registry).await;

        let mut checked = service(&registry, &fixture);
        checked.bind_configured_scopes(false).await.ok().unwrap();
        assert!(checked.unavailable_projections().is_empty());
        assert!(
            scopes(&fixture).await.is_empty(),
            "a doctor check binds and rolls back"
        );

        // A scope this release did not reconcile: its stored contract differs.
        fixture
            .migration
            .execute(
                "INSERT INTO registry_internal.registry_external_projection_scopes
                 (projection_id,contract_digest,epoch,binding_digest,grant_digest,cache_ttl_seconds)
                 VALUES ('projection','sha256:another',gen_random_uuid(),'binding','grant',60)",
                &[],
            )
            .await
            .unwrap();

        let mut serving = service(&registry, &fixture);
        serving.bind_configured_scopes(true).await.ok().unwrap();
        let unavailable = serving.unavailable_projections();
        assert_eq!(
            unavailable.keys().collect::<Vec<_>>(),
            ["projection"],
            "only the refused projection is unavailable"
        );
        assert!(unavailable["projection"].contains("run migrate"));

        match serving.plan(&request("link"), None) {
            Err(ExternalViewError::ProjectionUnavailable(id)) => assert_eq!(id, "projection"),
            Err(_) => panic!("the refused projection must name itself"),
            Ok(_) => panic!("the refused projection must not plan"),
        }
        assert!(
            serving.plan(&request("other-link"), None).is_ok(),
            "the other projection still serves"
        );

        let stored = scopes(&fixture).await;
        assert_eq!(stored["projection"].0, "sha256:another");
        assert_eq!(
            stored["other"],
            (
                store::scope_contract_digest(&registry, "other").unwrap(),
                true
            )
        );
        fixture.cleanup().await;
    }

    const ROOTS: [(&str, &str, &str); 4] = [
        ("00000000-0000-4000-8000-000000000001", "first", "allowed"),
        ("00000000-0000-4000-8000-000000000002", "second", "allowed"),
        ("00000000-0000-4000-8000-000000000003", "third", "allowed"),
        ("00000000-0000-4000-8000-000000000004", "hidden", "other"),
    ];

    async fn bound_scope(fixture: &Activated, projection: &str) -> ProjectionScope {
        let row = fixture
            .migration
            .query_one(
                "SELECT epoch,binding_digest,grant_digest,cache_ttl_seconds
                 FROM registry_internal.registry_external_projection_scopes
                 WHERE projection_id=$1",
                &[&projection],
            )
            .await
            .unwrap();
        ProjectionScope::new(
            projection,
            row.get(0),
            row.get::<_, String>(1).as_str(),
            row.get::<_, String>(2).as_str(),
            row.get(3),
        )
        .unwrap()
    }

    /// A bound, keyed runtime behind the in-process HTTP router. Three roots
    /// sit in the `allowed` tenant and one outside it.
    struct Served {
        fixture: Activated,
        router: axum::Router,
        service: Arc<PostgresExternalViewService>,
        scope: ProjectionScope,
    }

    impl Served {
        async fn new(lock_timeout: Duration) -> Self {
            Self::with(&two_projection_project(), indexed_sources(), lock_timeout).await
        }

        async fn with(
            project: &Value,
            sources: crate::external_source::ExternalSourceService,
            lock_timeout: Duration,
        ) -> Self {
            Self::with_refresh(project, sources, lock_timeout, None).await
        }

        async fn with_refresh(
            project: &Value,
            sources: crate::external_source::ExternalSourceService,
            lock_timeout: Duration,
            refresh: Option<crate::external_refresh_config::ExternalRefreshResolution>,
        ) -> Self {
            let registry = Arc::new(super::super::external_view_query::tests::compile_project(
                project,
            ));
            let fixture = Activated::new(&registry).await;
            let mut service = service_from(&registry, &fixture, lock_timeout, sources);
            service.bind_configured_scopes(true).await.ok().unwrap();
            if let Some(refresh) = refresh {
                service
                    .configure_managed_refresh(refresh, true)
                    .await
                    .unwrap();
            }
            let service = Arc::new(service);
            let scope = bound_scope(&fixture, "projection").await;
            let entity = &registry.entities()["local-record"];
            let column = |id: &str| {
                entity
                    .stored_fields
                    .iter()
                    .find(|field| field.logical.id == id)
                    .unwrap()
                    .physical_name
                    .clone()
            };
            let values = ROOTS
                .iter()
                .map(|(id, key, tenant)| format!("('{id}','fixture','{key}','{tenant}')"))
                .collect::<Vec<_>>()
                .join(",");
            fixture
                .database
                .admin
                .batch_execute(&format!(
                    "INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{}\",\"{}\") VALUES {values}",
                    entity.physical_table,
                    column("subject-key"),
                    column("tenant"),
                ))
                .await
                .unwrap();
            let http = crate::api::HttpService::new(
                Arc::clone(&registry),
                crate::api::ReadRuntimeIdentity {
                    package_revision: "package-revision".to_owned(),
                    schema_fingerprint: "schema-fingerprint".to_owned(),
                },
                Arc::new(NoRecords),
                Arc::new(Ready),
                Arc::new(
                    CursorCodec::new(
                        zeroize::Zeroizing::new(vec![9; 32]),
                        Duration::from_secs(60),
                    )
                    .unwrap(),
                ),
            )
            .with_external_views(service.clone());
            Self {
                router: crate::api::router(Arc::new(http)),
                fixture,
                service,
                scope,
            }
        }

        async fn generation(&self) -> i64 {
            self.fixture
                .migration
                .query_one(
                    "SELECT generation FROM registry_internal.registry_external_projection_scopes WHERE projection_id=$1",
                    &[&self.scope.projection_id],
                )
                .await
                .unwrap()
                .get(0)
        }

        async fn publish_all(&self) {
            for (_, key, _) in ROOTS {
                self.fixture.publish_label(&self.scope, key, key).await;
            }
        }

        async fn get(
            &self,
            query: &str,
            claims: crate::api::VerifiedRequestClaims,
        ) -> (axum::http::StatusCode, Value) {
            let (status, _, body) = self
                .send(
                    &format!("/v1/external-views/view/link/records?accessProfile=reader{query}"),
                    claims,
                )
                .await;
            (status, body)
        }

        /// GET `uri`, returning the status, the content type and the body.
        async fn send(
            &self,
            uri: &str,
            claims: crate::api::VerifiedRequestClaims,
        ) -> (axum::http::StatusCode, String, Value) {
            use tower::ServiceExt;
            let mut request = axum::http::Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap();
            request.extensions_mut().insert(claims);
            let response = self.router.clone().oneshot(request).await.unwrap();
            let status = response.status();
            let content_type = response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            (
                status,
                content_type,
                serde_json::from_slice(&bytes).unwrap(),
            )
        }
    }

    fn reader(principal: &str, tenants: &[&str]) -> crate::api::VerifiedRequestClaims {
        crate::api::VerifiedRequestClaims::authenticated(
            "registry_principal",
            principal,
            BTreeSet::from(["registry.read".to_owned()]),
            Some("consultation".to_owned()),
            BTreeMap::from([(
                "tenant".to_owned(),
                crate::api::VerifiedClaimValue::direct_string_set(tenants.iter().copied()).unwrap(),
            )]),
        )
        .unwrap()
    }

    fn labels(body: &Value) -> Vec<String> {
        body["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["fields"]["label"].as_str().unwrap().to_owned())
            .collect()
    }

    struct Ready;
    impl crate::api::ReadinessProbe for Ready {
        fn is_ready(&self) -> ServiceFuture<'_, bool> {
            Box::pin(async { true })
        }
    }

    struct NoRecords;
    impl crate::api::RecordReadService for NoRecords {
        fn get(
            &self,
            _: crate::api::RecordReadRequest,
        ) -> ServiceFuture<
            '_,
            std::result::Result<Option<crate::api::HeldReadResponse>, crate::api::ReadServiceError>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn list(
            &self,
            _: crate::api::RecordReadRequest,
        ) -> ServiceFuture<
            '_,
            std::result::Result<crate::api::HeldReadResponse, crate::api::ReadServiceError>,
        > {
            Box::pin(async { Err(crate::api::ReadServiceError::Unavailable) })
        }
        fn lookup(
            &self,
            _: crate::api::RecordReadRequest,
        ) -> ServiceFuture<
            '_,
            std::result::Result<Option<crate::api::HeldReadResponse>, crate::api::ReadServiceError>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn refusal(
            &self,
            _: crate::api::RecordReadRefusal,
        ) -> ServiceFuture<'_, std::result::Result<(), crate::api::ReadServiceError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn a_scope_lock_timeout_is_unavailable_never_incomplete_or_an_invalid_cursor() {
        let served = Served::new(Duration::from_millis(300)).await;
        served.publish_all().await;
        let caller = reader("reader-principal", &["allowed"]);
        let (status, first) = served.get("&$top=1", caller.clone()).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{first}");
        let cursor = first["nextCursor"].as_str().unwrap().to_owned();

        // Another session holds the scope row, as a long publication would.
        served
            .fixture
            .database
            .admin
            .batch_execute(
                "BEGIN; SELECT 1 FROM registry_internal.registry_external_projection_scopes
                 WHERE projection_id='projection' FOR UPDATE",
            )
            .await
            .unwrap();
        let (status, problem) = served.get("&$top=1", caller.clone()).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(problem["code"], "source.unavailable", "{problem}");
        let (status, problem) = served
            .get(&format!("&$skiptoken={cursor}"), caller.clone())
            .await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(problem["code"], "source.unavailable", "{problem}");
        served
            .fixture
            .database
            .admin
            .batch_execute("COMMIT")
            .await
            .unwrap();

        let (status, next) = served.get(&format!("&$skiptoken={cursor}"), caller).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{next}");
        assert_eq!(labels(&next).len(), 1);
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_continuation_reads_through_a_concurrent_publish() {
        let served = Served::new(Duration::from_secs(2)).await;
        served.publish_all().await;
        let caller = reader("reader-principal", &["allowed"]);
        let ordered = "&$top=1&$orderby=label%20asc&$count=true";
        let (status, first) = served.get(ordered, caller.clone()).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{first}");
        assert_eq!(labels(&first), ["first"]);
        assert_eq!(first["count"], 3);
        let cursor = first["nextCursor"].as_str().unwrap().to_owned();

        // A refresh publishes a later key between pages. The continuation
        // keeps its position and reads the value current for its own page.
        served
            .fixture
            .publish_label(&served.scope, "third", "thirdly")
            .await;
        let (status, second) = served
            .get(&format!("&$skiptoken={cursor}"), caller.clone())
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{second}");
        assert_eq!(labels(&second), ["second"]);
        assert_eq!(second["count"], 3);
        let cursor = second["nextCursor"].as_str().unwrap().to_owned();
        let (status, third) = served.get(&format!("&$skiptoken={cursor}"), caller).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{third}");
        assert_eq!(labels(&third), ["thirdly"]);
        assert!(third.get("nextCursor").is_none());
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_label_sweep_survives_a_holdings_refresh_for_another_parent() {
        let served = Served::new(Duration::from_secs(2)).await;
        let registry =
            super::super::external_view_query::tests::compile_project(&two_projection_project());
        served.publish_all().await;
        let parent = served.scope.clone();
        let generation = ProjectionGeneration {
            epoch: parent.epoch,
            generation: served.generation().await,
        };
        let authority = RefreshAuthority {
            pool: served.fixture.pool.clone(),
            expected: served.fixture.expected.clone(),
            lock_key: RegistryLockKey::derive(registry.registry_id()).unwrap(),
            lock_timeout: Duration::from_secs(2),
            scope: bound_scope(&served.fixture, "other").await,
            parent: Some((parent.clone(), generation)),
            supporting: vec![SupportingSnapshot {
                subject_key: "first".to_owned(),
                snapshot_id: "first-first".to_owned(),
            }],
            managed: None,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        authority.check(deadline).await.unwrap();
        // A holdings refresh for another root leaves this sweep's parent as
        // selected, so acquisition for its selectors goes ahead.
        served
            .fixture
            .publish_label(&parent, "second", "renewed")
            .await;
        authority.check(deadline).await.unwrap();
        // A refresh of the sweep's own parent replaces the snapshot its
        // selectors came from, so acquisition stops before the source call.
        served
            .fixture
            .publish_label(&parent, "first", "renewed")
            .await;
        assert!(authority.check(deadline).await.is_err());
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_transient_one_key_failure_keeps_coverage_and_denial_removes_it() {
        let served = Served::new(Duration::from_secs(2)).await;
        served.publish_all().await;
        let caller = reader("reader-principal", &["allowed"]);
        let generation = served.generation().await;
        for reason in ["unavailable", "incomplete"] {
            served.fixture.fail(&served.scope, "second", reason).await;
            let (status, page) = served.get("&$count=true", caller.clone()).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{reason}: {page}");
            assert_eq!(
                page["count"], 3,
                "{reason} keeps the snapshot until it expires"
            );
            assert_eq!(labels(&page), ["first", "second", "third"]);
        }
        served.fixture.fail(&served.scope, "second", "denied").await;
        let (status, problem) = served.get("&$count=true", caller.clone()).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(problem["code"], "external_view.incomplete", "{problem}");
        // A per-key outcome never invalidates cursors over the rest of the scope.
        assert_eq!(served.generation().await, generation);
        served
            .fixture
            .publish_label(&served.scope, "second", "second")
            .await;
        served
            .fixture
            .fail(&served.scope, "second", "retention-refused")
            .await;
        let (status, problem) = served.get("&$count=true", caller).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(problem["code"], "external_view.incomplete", "{problem}");
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn indexed_reads_go_on_while_a_refresh_records_its_page() {
        const BARRIER: i64 = 732_995_011;
        let served = Served::new(Duration::from_millis(300)).await;
        served.publish_all().await;
        let caller = reader("reader-principal", &["allowed"]);
        // The refresh worker waits out the barrier below; readers keep the
        // short lock timeout.
        let mut worker = service_with(
            &served.service.registry,
            &served.fixture,
            Duration::from_secs(5),
        );
        worker.bind_configured_scopes(true).await.ok().unwrap();
        let refresh = request("link");
        let plan = worker.plan(&refresh, None).ok().unwrap();
        let claims = ClaimContext::for_compiled(
            &served.service.registry,
            &plan.root.id,
            Some("reader-principal".to_owned()),
            "reader",
            Some("consultation".to_owned()),
            vec![crate::postgres::context::RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "allowed".to_owned(),
            }],
        )
        .unwrap();
        // The second key's publication pauses in its eligibility recheck,
        // after the first key's publication.
        let eligibility = RootKeys::new(&plan).ok().unwrap().publication_eligibility;
        let page = RefreshRows {
            rows: Vec::new(),
            next: None,
            eligibility: format!(
                "SELECT 1 FROM ({eligibility}) AS eligible
                 WHERE CASE WHEN $6::text='second'
                     THEN pg_catalog.pg_advisory_xact_lock({BARRIER}) IS NOT NULL
                     ELSE true END"
            ),
            supporting_until: None,
            supporting: Vec::new(),
        };
        let mut results = Vec::new();
        for (id, key, _) in &ROOTS[..3] {
            let (ticket, snapshot) = served
                .fixture
                .label_refresh(&served.scope, key, "renewed")
                .await;
            results.push((
                RefreshWork {
                    key: (*key).to_owned(),
                    roots: BTreeSet::from([Uuid::parse_str(id).unwrap()]),
                    ticket,
                    managed_targets: Vec::new(),
                },
                RefreshResult::Accepted(snapshot),
            ));
        }
        served
            .fixture
            .migration
            .execute(&format!("SELECT pg_advisory_lock({BARRIER})"), &[])
            .await
            .unwrap();
        let read_during_refresh = async {
            let waited = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let waiting: bool = served
                        .fixture
                        .database
                        .admin
                        .query_one(
                            &format!(
                                "SELECT EXISTS (SELECT 1 FROM pg_locks
                                 WHERE locktype='advisory' AND NOT granted AND objid={BARRIER})"
                            ),
                            &[],
                        )
                        .await
                        .unwrap()
                        .get(0);
                    if waiting {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .is_ok();
            let read = if waited {
                Some(served.get("&$count=true", caller.clone()).await)
            } else {
                None
            };
            served
                .fixture
                .migration
                .execute(&format!("SELECT pg_advisory_unlock({BARRIER})"), &[])
                .await
                .unwrap();
            read.expect("the second publication reached the barrier")
        };
        let (recorded, (status, during)) = tokio::join!(
            worker.record_refresh(
                &refresh,
                &plan,
                &claims,
                &served.scope,
                None,
                &page,
                results,
                None,
            ),
            read_during_refresh,
        );
        // The reader sees the first key's new value and the previous values
        // of the keys still in flight, all under one complete coverage.
        assert_eq!(status, axum::http::StatusCode::OK, "{during}");
        assert_eq!(labels(&during), ["renewed", "second", "third"]);
        assert_eq!(during["count"], 3);
        assert_eq!(recorded.ok().map(|tally| tally.published), Some(3));
        let (status, after) = served.get("&$count=true", caller).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{after}");
        assert_eq!(labels(&after), ["renewed", "renewed", "renewed"]);
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_cursor_replayed_under_other_authority_is_an_invalid_cursor() {
        let served = Served::new(Duration::from_secs(2)).await;
        served.publish_all().await;
        let (status, first) = served
            .get("&$top=1", reader("reader-principal", &["allowed"]))
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{first}");
        let cursor = first["nextCursor"].as_str().unwrap().to_owned();
        for (caller, authority) in [
            (
                reader("another-principal", &["allowed"]),
                "another principal",
            ),
            (
                reader("reader-principal", &["other"]),
                "another row boundary",
            ),
        ] {
            let (status, problem) = served.get(&format!("&$skiptoken={cursor}"), caller).await;
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "{authority}: {problem}"
            );
            assert_eq!(
                problem["code"], "query.cursor_invalid",
                "{authority}: {problem}"
            );
        }
        let (status, next) = served
            .get(
                &format!("&$skiptoken={cursor}"),
                reader("reader-principal", &["allowed"]),
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{next}");
        assert_eq!(labels(&next), ["second"]);
        served.fixture.cleanup().await;
    }

    /// The fixture project with a live projection of a second external record
    /// type, linked from the same view and readable by the reader profile.
    fn live_and_indexed_project() -> Value {
        let mut project = two_projection_project();
        project["externalRecordTypes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"person","authority":"urn:test:authority","identifierScheme":"urn:test:keys",
                "fields":[{"id":"family-name","type":"string","classification":"internal"}]
            }));
        project["externalProjections"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"holder","recordType":"person","operation":"person-exact","operationVersion":"1",
                "purpose":"consultation","scope":"eligible","selectorScheme":"urn:test:keys",
                "mode":"live","cardinality":"one","fields":["family-name"]
            }));
        project["externalViews"][0]["links"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"holder-link","projection":"holder","fromField":"subject-key",
                "identifierScheme":"urn:test:keys","fields":["family-name"]
            }));
        project["accessProfiles"][0]["permissions"]["externalViews"][0]["links"]
            .as_array_mut()
            .unwrap()
            .push(json!({"link":"holder-link","readableFields":["family-name"]}));
        project
    }

    fn assert_problem(content_type: &str, problem: &Value, code: &str) {
        assert_eq!(content_type, "application/problem+json", "{problem}");
        assert_eq!(problem["code"], code, "{problem}");
        for member in ["type", "title", "status", "detail"] {
            assert!(problem.get(member).is_some(), "{member}: {problem}");
        }
        assert!(problem.get("records").is_none(), "{problem}");
    }

    /// Every table whose rows contain `needle` in their text form.
    async fn tables_holding(client: &tokio_postgres::Client, needle: &str) -> Vec<String> {
        let tables = client
            .query(
                "SELECT format('%I.%I', table_schema, table_name) FROM information_schema.tables
                 WHERE table_type = 'BASE TABLE'
                   AND table_schema NOT IN ('pg_catalog', 'information_schema')",
                &[],
            )
            .await
            .unwrap();
        let mut holding = Vec::new();
        for table in tables {
            let name: String = table.get(0);
            let found: bool = client
                .query_one(
                    &format!(
                        "SELECT EXISTS (SELECT 1 FROM {name} AS t WHERE strpos(t::text, $1) > 0)"
                    ),
                    &[&needle],
                )
                .await
                .unwrap()
                .get(0);
            if found {
                holding.push(name);
            }
        }
        holding
    }

    #[tokio::test]
    async fn a_live_read_over_http_answers_from_the_source_and_retains_nothing() {
        // Only the source holds this value, so finding it in any table
        // afterwards would mean the read retained it.
        const SOURCE_VALUE: &str = "synthetic-live-family-name";
        let transcript = Arc::new(
            registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                serde_json::from_value(
                    json!([{"type":"endpoint","endpoint":"synthetic-registry"}]),
                )
                .unwrap(),
                serde_json::from_value(json!([{
                    "request":{"endpoint":"synthetic-registry","method":"POST","path":"/people/exact","body":{
                        "type":"exact","key":"first","fields":["family-name"]
                    }},
                    "response":{"status":200,"body":{
                        "subject":"first","state":"found","properties":{"family-name":SOURCE_VALUE}
                    }}
                }]))
                .unwrap(),
            ),
        );
        let mut sources = indexed_sources();
        crate::external_source::tests::add_live_binding(
            &mut sources,
            "holder",
            "family-name",
            Arc::clone(&transcript),
        );
        let served =
            Served::with(&live_and_indexed_project(), sources, Duration::from_secs(2)).await;
        let caller = reader("reader-principal", &["allowed"]);
        let detail = |root: &str, query: &str| {
            format!(
                "/v1/external-views/view/holder-link/records/{root}?accessProfile=reader{query}"
            )
        };

        let (status, _, body) = served.send(&detail(ROOTS[0].0, ""), caller.clone()).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["status"], "available", "{body}");
        assert_eq!(
            body["records"][0]["fields"]["family-name"], SOURCE_VALUE,
            "{body}"
        );

        // A root outside the caller's row boundary, and a count the live
        // link's grant does not allow, are refused before any source call.
        let (status, content_type, problem) =
            served.send(&detail(ROOTS[3].0, ""), caller.clone()).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{problem}");
        assert_problem(&content_type, &problem, "resource.not_found");
        let (status, content_type, problem) = served
            .send(&detail(ROOTS[0].0, "&$count=true"), caller)
            .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{problem}");
        assert_problem(&content_type, &problem, "query.invalid");
        // The one recorded exchange was used, and nothing else reached it.
        transcript.finish().unwrap();

        let admin = &served.fixture.database.admin;
        for table in [
            "registry_external_projection_refreshes",
            "registry_external_projection_snapshots",
            "registry_external_projection_values",
        ] {
            let rows: i64 = admin
                .query_one(
                    &format!("SELECT count(*) FROM registry_internal.{table}"),
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(rows, 0, "{table}");
        }
        let scoped: Vec<String> = admin
            .query(
                "SELECT projection_id FROM registry_internal.registry_external_projection_scopes
                 ORDER BY projection_id",
                &[],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(
            scoped,
            ["other", "projection"],
            "only indexed projections bind"
        );
        // The scan finds a value the fixture did store, so an empty answer
        // below means the source value is absent, not that the scan is blind.
        let stored = tables_holding(admin, ROOTS[3].1).await;
        assert!(
            stored
                .iter()
                .any(|table| table.starts_with("registry_data.")),
            "{stored:?}"
        );
        assert_eq!(
            tables_holding(admin, SOURCE_VALUE).await,
            Vec::<String>::new()
        );
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_refresh_pages_a_dense_scope_in_key_order_without_sorting_it() {
        let served = Served::new(Duration::from_secs(2)).await;
        let entity = &served.service.registry.entities()["local-record"];
        let column = |id: &str| {
            entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == id)
                .unwrap()
                .physical_name
                .clone()
        };
        // Most of a large scope is eligible, so sorting it for each page
        // would read the whole scope.
        served
            .fixture
            .database
            .admin
            .batch_execute(&format!(
                "INSERT INTO registry_data.\"{table}\"
                 (record_id,active_package_revision,\"{key}\",\"{tenant}\")
                 SELECT gen_random_uuid(),'fixture','bulk-'||g,
                        CASE WHEN g % 20 = 0 THEN 'other' ELSE 'allowed' END
                 FROM generate_series(1,120000) AS g;
                 ANALYZE registry_data.\"{table}\";",
                table = entity.physical_table,
                key = column("subject-key"),
                tenant = column("tenant"),
            ))
            .await
            .unwrap();
        let refresh = request("link");
        let plan = served.service.plan(&refresh, None).ok().unwrap();
        let claims = ClaimContext::for_compiled(
            &served.service.registry,
            &plan.root.id,
            Some("reader-principal".to_owned()),
            "reader",
            Some("consultation".to_owned()),
            vec![crate::postgres::context::RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "allowed".to_owned(),
            }],
        )
        .unwrap();
        let keys = RootKeys::new(&plan).ok().unwrap();
        let middle = Uuid::parse_str("80000000-0000-4000-8000-000000000000").unwrap();
        for after in [None, Some(middle)] {
            let mut session = served.service.session().await.ok().unwrap();
            let transaction = served
                .service
                .transaction(
                    &mut session,
                    &claims,
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .ok()
                .unwrap();
            let page = keys.page(&transaction, after, 101).await.ok().unwrap();
            assert_eq!(page.len(), 101);
            let explained: Value = transaction
                .transaction()
                .query_one(
                    &format!(
                        "EXPLAIN (ANALYZE, FORMAT JSON, COSTS OFF, TIMING OFF, SUMMARY OFF) {}",
                        keys.page_sql()
                    ),
                    &[&after, &101i64],
                )
                .await
                .unwrap()
                .get(0);
            let mut nodes = Vec::new();
            plan_nodes(&explained[0]["Plan"], &mut nodes);
            assert!(
                !nodes.iter().any(|node| node["Node Type"]
                    .as_str()
                    .is_some_and(|kind| kind.contains("Sort"))),
                "after {after:?}: {explained}"
            );
            // Both copies of the table start at the continuation: a scan of
            // either from the first record would read about half of it here.
            for node in &nodes {
                let rows = node["Actual Rows"].as_f64().unwrap_or(0.0)
                    * node["Actual Loops"].as_f64().unwrap_or(1.0);
                let removed = node["Rows Removed by Filter"].as_f64().unwrap_or(0.0)
                    * node["Actual Loops"].as_f64().unwrap_or(1.0);
                assert!(
                    rows + removed <= 3.0 * 101.0,
                    "after {after:?} reads about one page at every node: {explained}"
                );
            }
        }
        served.fixture.cleanup().await;
    }

    fn plan_nodes<'a>(plan: &'a Value, nodes: &mut Vec<&'a Value>) {
        nodes.push(plan);
        for child in plan["Plans"].as_array().into_iter().flatten() {
            plan_nodes(child, nodes);
        }
    }

    #[tokio::test]
    async fn a_refresh_continuation_returns_each_root_once_in_order_past_an_insert_behind_it() {
        let served = Served::new(Duration::from_secs(2)).await;
        let entity = &served.service.registry.entities()["local-record"];
        let column = |id: &str| {
            entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == id)
                .unwrap()
                .physical_name
                .clone()
        };
        let insert = |rows: &[(&str, &str, &str)]| {
            format!(
                "INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{}\",\"{}\") VALUES {}",
                entity.physical_table,
                column("subject-key"),
                column("tenant"),
                rows.iter()
                    .map(|(id, key, tenant)| format!("('{id}','fixture','{key}','{tenant}')"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        served
            .fixture
            .database
            .admin
            .batch_execute(&insert(&[
                ("00000000-0000-4000-8000-000000000005", "fifth", "allowed"),
                ("00000000-0000-4000-8000-000000000006", "sixth", "other"),
                ("00000000-0000-4000-8000-000000000007", "seventh", "allowed"),
            ]))
            .await
            .unwrap();
        let refresh = request("link");
        let plan = served.service.plan(&refresh, None).ok().unwrap();
        let claims = ClaimContext::for_compiled(
            &served.service.registry,
            &plan.root.id,
            Some("reader-principal".to_owned()),
            "reader",
            Some("consultation".to_owned()),
            vec![crate::postgres::context::RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "allowed".to_owned(),
            }],
        )
        .unwrap();
        let keys = RootKeys::new(&plan).ok().unwrap();
        let mut after = None;
        let mut read = Vec::new();
        loop {
            let mut session = served.service.session().await.ok().unwrap();
            let transaction = served
                .service
                .transaction(
                    &mut session,
                    &claims,
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .ok()
                .unwrap();
            let page = keys.page(&transaction, after, 2).await.ok().unwrap();
            drop(transaction);
            if after.is_none() {
                // Another session commits one root behind the boundary and
                // one ahead of it before the next page.
                served
                    .fixture
                    .database
                    .admin
                    .batch_execute(&insert(&[
                        ("00000000-0000-4000-8000-000000000000", "behind", "allowed"),
                        ("00000000-0000-4000-8000-000000000008", "ahead", "allowed"),
                    ]))
                    .await
                    .unwrap();
            }
            let Some((last, _)) = page.last() else {
                break;
            };
            after = Some(*last);
            read.extend(page.into_iter().map(|(_, key)| key.unwrap()));
        }
        assert_eq!(
            read,
            ["first", "second", "third", "fifth", "seventh", "ahead"]
        );
        served.fixture.cleanup().await;
    }

    /// Insert local roots as (id, link key, tenant). Each key is a statement
    /// parameter, so a missing key or one with control characters is stored
    /// exactly as given.
    async fn insert_roots(served: &Served, rows: &[(&str, Option<&str>, &str)]) {
        let entity = &served.service.registry.entities()["local-record"];
        let column = |id: &str| {
            entity
                .stored_fields
                .iter()
                .find(|field| field.logical.id == id)
                .unwrap()
                .physical_name
                .clone()
        };
        let sql = format!(
            "INSERT INTO registry_data.\"{}\" (record_id,active_package_revision,\"{}\",\"{}\") VALUES ($1,'fixture',$2,$3)",
            entity.physical_table,
            column("subject-key"),
            column("tenant"),
        );
        for (id, key, tenant) in rows {
            served
                .fixture
                .database
                .admin
                .execute(&sql, &[&Uuid::parse_str(id).unwrap(), key, tenant])
                .await
                .unwrap();
        }
    }

    /// (root, availability, fields) for each record of a view page.
    fn availabilities(body: &Value) -> BTreeMap<String, (String, Value)> {
        body["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| {
                (
                    record["rootId"].as_str().unwrap().to_owned(),
                    (
                        record["availability"].as_str().unwrap().to_owned(),
                        record["fields"].clone(),
                    ),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn a_root_without_a_link_key_is_covered_and_reads_absent() {
        const UNLINKED: &str = "00000000-0000-4000-8000-000000000011";
        const EMPTY: &str = "00000000-0000-4000-8000-000000000012";
        const OUTSIDE: &str = "00000000-0000-4000-8000-000000000013";
        let served = Served::new(Duration::from_secs(2)).await;
        served.publish_all().await;
        insert_roots(
            &served,
            &[
                (UNLINKED, None, "allowed"),
                (EMPTY, Some(""), "allowed"),
                (OUTSIDE, None, "other"),
            ],
        )
        .await;
        let caller = reader("reader-principal", &["allowed"]);
        let mut expected = BTreeMap::new();
        for (id, key, _) in &ROOTS[..3] {
            expected.insert(
                (*id).to_owned(),
                ("available".to_owned(), json!({ "label": key })),
            );
        }
        for id in [UNLINKED, EMPTY] {
            expected.insert(id.to_owned(), ("absent".to_owned(), json!({})));
        }

        // A root with no link key has no outside value, so it is covered:
        // lists, counts, ordering and filters keep serving.
        let (status, page) = served.get("&$count=true", caller.clone()).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{page}");
        assert_eq!(page["status"], "available", "{page}");
        assert_eq!(page["count"], 5, "{page}");
        assert_eq!(availabilities(&page), expected);
        let (status, page) = served
            .get("&$orderby=label%20asc&$count=true", caller.clone())
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{page}");
        assert_eq!(availabilities(&page), expected);
        let (status, page) = served
            .get("&$filter=label%20eq%20'second'&$count=true", caller.clone())
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{page}");
        assert_eq!(page["count"], 1, "{page}");
        assert_eq!(labels(&page), ["second"]);

        for root in [UNLINKED, EMPTY] {
            let (status, _, body) = served
                .send(
                    &format!("/v1/external-views/view/link/records/{root}?accessProfile=reader"),
                    caller.clone(),
                )
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["status"], "available", "{body}");
            assert_eq!(
                availabilities(&body),
                BTreeMap::from([(root.to_owned(), ("absent".to_owned(), json!({})))])
            );
        }

        // An unlinked root outside the caller's row boundary stays concealed
        // and does not change the caller's count.
        let (status, content_type, problem) = served
            .send(
                &format!("/v1/external-views/view/link/records/{OUTSIDE}?accessProfile=reader"),
                caller,
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{problem}");
        assert_problem(&content_type, &problem, "resource.not_found");
        let (status, page) = served
            .get("&$count=true", reader("reader-principal", &["other"]))
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{page}");
        assert_eq!(page["count"], 2, "{page}");
        assert_eq!(
            availabilities(&page),
            BTreeMap::from([
                (
                    ROOTS[3].0.to_owned(),
                    ("available".to_owned(), json!({"label": "hidden"}))
                ),
                (OUTSIDE.to_owned(), ("absent".to_owned(), json!({}))),
            ])
        );
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_malformed_link_key_reads_as_no_outside_value_and_the_view_keeps_serving() {
        const PADDED: &str = "00000000-0000-4000-8000-000000000011";
        const BELL: &str = "00000000-0000-4000-8000-000000000012";
        const IDEOGRAPHIC_SPACE: &str = "00000000-0000-4000-8000-000000000014";
        let served = Served::new(Duration::from_secs(2)).await;
        served.publish_all().await;
        insert_roots(
            &served,
            &[
                (PADDED, Some(" padded-key"), "allowed"),
                (BELL, Some("bell\u{7}key"), "allowed"),
                (IDEOGRAPHIC_SPACE, Some("trailing\u{3000}"), "allowed"),
            ],
        )
        .await;
        let caller = reader("reader-principal", &["allowed"]);
        let mut expected = BTreeMap::new();
        for (id, key, _) in &ROOTS[..3] {
            expected.insert(
                (*id).to_owned(),
                ("available".to_owned(), json!({ "label": key })),
            );
        }
        for id in [PADDED, BELL, IDEOGRAPHIC_SPACE] {
            expected.insert(id.to_owned(), ("absent".to_owned(), json!({})));
        }

        let (status, page) = served.get("&$count=true", caller.clone()).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{page}");
        assert_eq!(page["status"], "available", "{page}");
        assert_eq!(page["count"], 6, "{page}");
        assert_eq!(availabilities(&page), expected);
        let (status, page) = served
            .get("&$orderby=label%20asc&$count=true", caller.clone())
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{page}");
        assert_eq!(availabilities(&page), expected);
        // A filter on an outside field leaves the malformed records out.
        let (status, page) = served
            .get("&$filter=label%20eq%20'second'&$count=true", caller.clone())
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{page}");
        assert_eq!(page["count"], 1, "{page}");
        assert_eq!(labels(&page), ["second"]);
        let (status, _, body) = served
            .send(
                &format!("/v1/external-views/view/link/records/{BELL}?accessProfile=reader"),
                caller,
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["status"], "available", "{body}");
        assert_eq!(
            availabilities(&body),
            BTreeMap::from([(BELL.to_owned(), ("absent".to_owned(), json!({})))])
        );
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_live_read_of_a_root_without_a_usable_link_key_answers_absent_without_a_source_call()
    {
        const UNLINKED: &str = "00000000-0000-4000-8000-000000000011";
        const EMPTY: &str = "00000000-0000-4000-8000-000000000012";
        const MALFORMED: &str = "00000000-0000-4000-8000-000000000013";
        let transcript = Arc::new(
            registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                serde_json::from_value(
                    json!([{"type":"endpoint","endpoint":"synthetic-registry"}]),
                )
                .unwrap(),
                serde_json::from_value(json!([])).unwrap(),
            ),
        );
        let mut sources = indexed_sources();
        crate::external_source::tests::add_live_binding(
            &mut sources,
            "holder",
            "family-name",
            Arc::clone(&transcript),
        );
        let served =
            Served::with(&live_and_indexed_project(), sources, Duration::from_secs(2)).await;
        insert_roots(
            &served,
            &[
                (UNLINKED, None, "allowed"),
                (EMPTY, Some(""), "allowed"),
                (MALFORMED, Some("bell\u{7}key"), "allowed"),
            ],
        )
        .await;
        let caller = reader("reader-principal", &["allowed"]);
        let captured = registry_platform_testing::CapturedDiagnosticLogs::default();
        for root in [UNLINKED, EMPTY, MALFORMED] {
            use tracing::instrument::WithSubscriber;
            let (status, _, body) = served
                .send(
                    &format!(
                        "/v1/external-views/view/holder-link/records/{root}?accessProfile=reader"
                    ),
                    caller.clone(),
                )
                .with_subscriber(captured.subscriber())
                .await;
            assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            assert_eq!(body["status"], "available", "{body}");
            assert_eq!(
                availabilities(&body),
                BTreeMap::from([(root.to_owned(), ("absent".to_owned(), json!({})))])
            );
        }
        // Nothing reached the source, and no acquisition failure was logged.
        transcript.finish().unwrap();
        let logs = captured.text();
        assert!(!logs.contains("live acquisition failed"), "{logs}");
        // Only the malformed key is logged, once, with the view and a count.
        let skipped = logs
            .lines()
            .filter(|line| line.contains(r#""reason":"invalid-key""#))
            .collect::<Vec<_>>();
        assert_eq!(skipped.len(), 1, "{logs}");
        assert!(skipped[0].contains(r#""level":"WARN""#), "{logs}");
        assert!(skipped[0].contains(r#""view":"view""#), "{logs}");
        assert!(skipped[0].contains(r#""keys":1"#), "{logs}");
        assert!(!logs.contains("bell"), "the key reached the log: {logs}");
        served.fixture.cleanup().await;
    }

    /// The fixture registry with an indexed person projection over the example
    /// pack's batch route, linked from the same local key. The local key
    /// admits 512 characters, which can exceed the store's byte bound.
    fn indexed_person_project() -> Value {
        let mut project = two_projection_project();
        project["recordTypes"][0]["fields"][0]["maximumLength"] = json!(512);
        project["externalRecordTypes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"person","authority":"urn:test:authority","identifierScheme":"urn:test:keys",
                "fields":[{"id":"family-name","type":"string","classification":"internal"}]
            }));
        project["externalProjections"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"people","recordType":"person","operation":"person-batch","operationVersion":"1",
                "purpose":"consultation","scope":"eligible","selectorScheme":"urn:test:keys",
                "mode":"indexed","cardinality":"one","cacheTtlSeconds":60,"fields":["family-name"]
            }));
        project["externalViews"][0]["links"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"people-link","projection":"people","fromField":"subject-key",
                "identifierScheme":"urn:test:keys","fields":["family-name"]
            }));
        project["accessProfiles"][0]["permissions"]["externalViews"][0]["links"]
            .as_array_mut()
            .unwrap()
            .push(json!({"link":"people-link","readableFields":["family-name"],"allowCount":true}));
        project
    }

    fn managed_person_plan() -> crate::external_refresh_config::ExternalRefreshResolution {
        use crate::external_refresh_config::*;
        let plan = ResolvedExternalRefreshPlan {
            id: "holders".to_owned(),
            worker: ResolvedExternalRefreshWorker {
                id: "worker".to_owned(),
                access_profile: "refresh".to_owned(),
                requester_client: "worker".to_owned(),
                principal: "worker-principal".to_owned(),
                principal_claim: "registry_principal".to_owned(),
                required_scopes: BTreeSet::from(["registry.refresh".to_owned()]),
                required_purposes: BTreeSet::from(["consultation".to_owned()]),
                row_claims: BTreeMap::from([(
                    "tenant".to_owned(),
                    BTreeSet::from(["allowed".to_owned()]),
                )]),
            },
            target: ResolvedExternalRefreshTarget {
                view: "view".to_owned(),
                link: "people-link".to_owned(),
                root_record_type: "local-record".to_owned(),
                from_field: "subject-key".to_owned(),
                row_boundaries: Vec::new(),
                row_boundary_fields: BTreeSet::from(["tenant".to_owned()]),
                target_claim_names: BTreeSet::from(["tenant".to_owned()]),
                primary_projection: ResolvedExternalRefreshProjection {
                    projection: "people".to_owned(),
                    operation: "person-batch".to_owned(),
                    operation_version: "1".to_owned(),
                    purpose: "consultation".to_owned(),
                    scope: "eligible".to_owned(),
                    selector_scheme: "urn:test:keys".to_owned(),
                    effective_cache_ttl_seconds: 60,
                    grant_valid_until: Utc::now() + chrono::Duration::hours(1),
                    binding_digest: "fixture-binding".to_owned(),
                },
                label_projection: None,
            },
            notifiers: BTreeMap::from([(
                "people".to_owned(),
                ResolvedExternalRefreshNotifier {
                    requester_client: "people-notifier".to_owned(),
                    required_scope: "people.changed".to_owned(),
                },
            )]),
            interval: Duration::from_secs(30),
            page_size: 2,
            refresh_labels: false,
            authority_digest: "fixture-authority".to_owned(),
        };
        ExternalRefreshResolution {
            available: BTreeMap::from([(plan.id.clone(), plan)]),
            unavailable: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn managed_refresh_resumes_sweeps_and_rereads_only_the_notified_subject() {
        use axum::http::StatusCode;
        use registry_platform_oidc::ActorKind;
        use tower::ServiceExt;
        let batch = |keys: &[&str], revision: &str| {
            json!({
                "request":{"endpoint":"synthetic-registry","method":"POST","path":"/people/batch","body":{
                    "type":"batch","keys":keys,"fields":["family-name"]
                }},
                "response":{"status":200,"body":{"records":keys.iter().map(|key| json!({
                    "subject":key,"state":"found","properties":{"family-name":format!("family-{key}-{revision}")}
                })).collect::<Vec<_>>()}}
            })
        };
        let mut denied_http = batch(&["first"], "discarded");
        denied_http["response"] = json!({"status":403,"body":{"error":"fixture-refusal"}});
        let transcript = Arc::new(
            registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                serde_json::from_value(
                    json!([{"type":"endpoint","endpoint":"synthetic-registry"}]),
                )
                .unwrap(),
                serde_json::from_value(json!([
                    batch(&["first", "second"], "initial"),
                    batch(&["third"], "initial"),
                    denied_http,
                    batch(&["first"], "corrected"),
                    batch(&["first", "second"], "corrected"),
                    batch(&["third"], "missed-notification"),
                ]))
                .unwrap(),
            ),
        );
        let mut sources = indexed_sources();
        crate::external_source::tests::add_indexed_binding(
            &mut sources,
            "people",
            "family-name",
            Arc::clone(&transcript),
        );
        let served = Served::with_refresh(
            &labelled_members_project(),
            sources,
            Duration::from_secs(2),
            Some(managed_person_plan()),
        )
        .await;
        let actor = |client: &str, principal: &str, scope: &str, tenant: &str| {
            crate::api::VerifiedRequestClaims::authenticated(
                "registry_principal",
                principal,
                BTreeSet::from([scope.to_owned()]),
                Some("consultation".to_owned()),
                BTreeMap::from([(
                    "tenant".to_owned(),
                    crate::api::VerifiedClaimValue::direct_string_set([tenant]).unwrap(),
                )]),
            )
            .unwrap()
            .with_contextual_authority(
                Some(ActorKind::Service),
                Some(client.to_owned()),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap()
        };
        let worker = actor("worker", "worker-principal", "registry.refresh", "allowed");
        let wrong_worker = actor("worker", "worker-principal", "registry.refresh", "denied");
        let notifier = actor(
            "people-notifier",
            "notifier-principal",
            "people.changed",
            "allowed",
        );
        let post = |action: &str, claims: crate::api::VerifiedRequestClaims, body: Value| {
            let router = served.router.clone();
            let mut request =
                axum::http::Request::post(format!("/v1/external-refresh-plans/holders/{action}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap();
            request.extensions_mut().insert(claims);
            async move {
                let response = router.oneshot(request).await.unwrap();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                (
                    status,
                    serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
                )
            }
        };
        let hint = |id: &str, selector: &str| {
            json!({
                "hintId":id, "projection":"people", "selectorScheme":"urn:test:keys", "selector":selector
            })
        };
        assert_eq!(
            post("step", wrong_worker, json!({})).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post("step", notifier.clone(), json!({})).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post("hints", worker.clone(), hint("invalid", "first"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );

        let (status, first) = post("step", worker.clone(), json!({})).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["published"], 2, "{first}");
        assert_eq!(first["moreWork"], true, "{first}");
        let (status, second) = post("step", worker.clone(), json!({})).await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_eq!(second["published"], 1, "{second}");
        assert_eq!(second["sweepCompleted"], true, "{second}");
        let (_, idle) = post("step", worker.clone(), json!({})).await;
        assert_eq!(idle["processed"], 0, "{idle}");
        let expiry = || async {
            served.fixture.migration.query_one(
                "SELECT expires_at FROM registry_internal.registry_external_projection_snapshots
                 WHERE projection_id='people' AND subject_key='first'",
                &[],
            ).await.unwrap().get::<_,i64>(0)
        };
        let original_expiry = expiry().await;

        let accepted = post("hints", notifier.clone(), hint("event-person", "first")).await;
        assert_eq!(accepted.0, StatusCode::ACCEPTED);
        assert_eq!(
            post("hints", notifier.clone(), hint("event-person", "first")).await,
            accepted
        );
        assert_eq!(
            post("hints", notifier.clone(), hint("event-person", "second"))
                .await
                .0,
            StatusCode::CONFLICT
        );
        // The protected fixture root is indistinguishable from the eligible
        // one at admission, but never causes a source request.
        assert_eq!(
            post("hints", notifier, hint("event-protected", ROOTS[3].1)).await,
            accepted
        );
        let (_, targeted) = post("step", worker.clone(), json!({})).await;
        assert_eq!(targeted["processed"], 2, "{targeted}");
        assert_eq!(targeted["published"], 0, "{targeted}");
        assert_eq!(targeted["settled"], 1, "{targeted}");
        assert_eq!(targeted["retried"], 1, "{targeted}");
        assert_eq!(targeted["moreWork"], false, "{targeted}");
        // An upstream HTTP 403 is an unavailable source response. It
        // leaves the accepted cache expiry intact and retries this key.
        assert_eq!(expiry().await, original_expiry);
        served
            .fixture
            .migration
            .execute(
                "UPDATE registry_internal.registry_external_refresh_work
             SET ready_at=clock_timestamp() WHERE plan_id='holders'",
                &[],
            )
            .await
            .unwrap();
        let (_, retried) = post("step", worker.clone(), json!({})).await;
        assert_eq!(retried["published"], 1, "{retried}");
        assert_eq!(retried["settled"], 1, "{retried}");
        let caller = reader("reader-principal", &["allowed"]);
        let lookup = |root| {
            format!("/v1/external-views/view/people-link/records/{root}?accessProfile=reader")
        };
        let (_, _, corrected) = served.send(&lookup(ROOTS[0].0), caller.clone()).await;
        assert_eq!(
            corrected["records"][0]["fields"]["family-name"], "family-first-corrected",
            "{corrected}"
        );
        let (_, _, unchanged) = served.send(&lookup(ROOTS[2].0), caller.clone()).await;
        assert_eq!(
            unchanged["records"][0]["fields"]["family-name"], "family-third-initial",
            "{unchanged}"
        );

        // Move the fixture clock's due point instead of waiting for a
        // production-sized interval. No source hint arrives for the third root.
        served.fixture.migration.execute(
            "UPDATE registry_internal.registry_external_refresh_plans SET next_due_at=clock_timestamp() WHERE plan_id='holders'", &[],
        ).await.unwrap();
        let (_, page) = post("step", worker.clone(), json!({})).await;
        assert_eq!(page["published"], 2, "{page}");
        let (_, page) = post("step", worker, json!({})).await;
        assert_eq!(page["sweepCompleted"], true, "{page}");
        let (_, _, reconciled) = served.send(&lookup(ROOTS[2].0), caller).await;
        assert_eq!(
            reconciled["records"][0]["fields"]["family-name"], "family-third-missed-notification",
            "{reconciled}"
        );
        transcript.finish().unwrap();
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn managed_related_labels_require_a_current_parent_and_local_change_reuses_it() {
        use axum::http::StatusCode;
        use registry_platform_oidc::ActorKind;
        use tower::ServiceExt;
        let endpoints = || {
            serde_json::from_value(json!([{"type":"endpoint","endpoint":"synthetic-registry"}]))
                .unwrap()
        };
        let label_exchange = |key: &str| {
            json!({
                "request":{"endpoint":"synthetic-registry","method":"POST","path":"/people/batch","body":{
                    "type":"batch","keys":[key],"fields":["family-name"]
                }},
                "response":{"status":200,"body":{"records":[{
                    "subject":key,"state":"found","properties":{"family-name":"current-label"}
                }]}}
            })
        };
        let transcript = Arc::new(
            registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                endpoints(),
                serde_json::from_value(json!([label_exchange("alpha"), label_exchange("beta")]))
                    .unwrap(),
            ),
        );
        let parent_transcript = Arc::new(
            registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                endpoints(),
                Vec::new(),
            ),
        );
        let mut sources = indexed_sources();
        crate::external_source::tests::add_indexed_binding(
            &mut sources,
            "people",
            "family-name",
            Arc::clone(&transcript),
        );
        crate::external_source::tests::add_indexed_binding(
            &mut sources,
            "members",
            "holder",
            Arc::clone(&parent_transcript),
        );
        let mut config = managed_person_plan();
        let plan = config.available.get_mut("holders").unwrap();
        plan.target.link = "members-link".to_owned();
        plan.target.label_projection = Some(plan.target.primary_projection.clone());
        plan.target.primary_projection.projection = "members".to_owned();
        plan.target.primary_projection.operation = "members".to_owned();
        plan.refresh_labels = true;
        let served = Served::with_refresh(
            &labelled_members_project(),
            sources,
            Duration::from_secs(2),
            Some(config),
        )
        .await;
        let parent = bound_scope(&served.fixture, "members").await;
        served
            .fixture
            .publish_collection(&parent, "first", &[("member", json!({"holder":"alpha"}))])
            .await;
        served
            .fixture
            .publish_collection(
                &parent,
                ROOTS[3].1,
                &[("member", json!({"holder":"hidden"}))],
            )
            .await;
        served
            .fixture
            .migration
            .execute(
                "UPDATE registry_internal.registry_external_refresh_plans
             SET reconciliation_due=false,next_due_at=clock_timestamp()+interval '30 seconds'
             WHERE plan_id='holders'",
                &[],
            )
            .await
            .unwrap();

        let actor = |client: &str, principal: &str, scope: &str| {
            crate::api::VerifiedRequestClaims::authenticated(
                "registry_principal",
                principal,
                BTreeSet::from([scope.to_owned()]),
                Some("consultation".to_owned()),
                BTreeMap::from([(
                    "tenant".to_owned(),
                    crate::api::VerifiedClaimValue::direct_string_set(["allowed"]).unwrap(),
                )]),
            )
            .unwrap()
            .with_contextual_authority(
                Some(ActorKind::Service),
                Some(client.to_owned()),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap()
        };
        let worker = actor("worker", "worker-principal", "registry.refresh");
        let notifier = actor("people-notifier", "notifier-principal", "people.changed");
        let post = |action: &str, claims: crate::api::VerifiedRequestClaims, body: Value| {
            let router = served.router.clone();
            let mut request =
                axum::http::Request::post(format!("/v1/external-refresh-plans/holders/{action}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap();
            request.extensions_mut().insert(claims);
            async move {
                let response = router.oneshot(request).await.unwrap();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                (
                    status,
                    serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
                )
            }
        };
        let hint = |id: &str, selector: &str| {
            json!({
                "hintId":id, "projection":"people", "selectorScheme":"urn:test:keys", "selector":selector
            })
        };
        for (id, selector) in [("label-approved", "alpha"), ("label-protected", "hidden")] {
            assert_eq!(
                post("hints", notifier.clone(), hint(id, selector)).await.0,
                StatusCode::ACCEPTED
            );
        }
        let (status, first) = post("step", worker.clone(), json!({})).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["settled"], 2, "{first}");
        assert_eq!(first["published"], 1, "{first}");
        served
            .fixture
            .publish_collection(&parent, "first", &[("member", json!({"holder":"beta"}))])
            .await;

        let mut client = served.fixture.pool.get().await.unwrap();
        let transaction = begin_registry_transaction(
            &mut client,
            served.service.lock_key,
            Duration::from_secs(2),
            &served.fixture.expected,
        )
        .await
        .unwrap();
        queue::capture_local_record(
            transaction.transaction(),
            "local-record",
            Uuid::parse_str(ROOTS[0].0).unwrap(),
            &BTreeSet::from(["subject-key".to_owned()]),
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        drop(client);
        let (status, parent_step) = post("step", worker.clone(), json!({})).await;
        assert_eq!(status, StatusCode::OK, "{parent_step}");
        assert_eq!(parent_step["reused"], 1, "{parent_step}");
        assert_eq!(parent_step["moreWork"], true, "{parent_step}");
        assert_eq!(
            post("hints", notifier, hint("label-detached", "alpha"))
                .await
                .0,
            StatusCode::ACCEPTED
        );
        let (status, label_step) = post("step", worker, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{label_step}");
        assert_eq!(label_step["settled"], 2, "{label_step}");
        assert_eq!(label_step["published"], 1, "{label_step}");
        transcript.finish().unwrap();
        parent_transcript.finish().unwrap();
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn invalid_link_keys_are_counted_without_failing_the_rest_of_the_refresh_page() {
        use tracing::instrument::WithSubscriber;
        let oversized = "\u{1D518}".repeat(300); // 1200 bytes in 300 characters
        let wide = "\u{E9}".repeat(300); // 600 bytes: over the source token bound
        let rows = [
            (
                "00000000-0000-4000-8000-000000000011",
                Some(oversized.as_str()),
            ),
            ("00000000-0000-4000-8000-000000000012", Some("bell\u{7}key")),
            ("00000000-0000-4000-8000-000000000013", Some(wide.as_str())),
            ("00000000-0000-4000-8000-000000000014", Some(" padded-key")),
            ("00000000-0000-4000-8000-000000000015", None),
            ("00000000-0000-4000-8000-000000000016", Some("")),
            ("00000000-0000-4000-8000-000000000017", Some("fifth")),
        ];
        let batch = |keys: &[&str]| {
            json!({
                "request":{"endpoint":"synthetic-registry","method":"POST","path":"/people/batch","body":{
                    "type":"batch","keys":keys,"fields":["family-name"]
                }},
                "response":{"status":200,"body":{"records":keys.iter().map(|key| json!({
                    "subject":key,"state":"found","properties":{"family-name":format!("family-{key}")}
                })).collect::<Vec<_>>()}}
            })
        };
        let transcript = Arc::new(
            registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                serde_json::from_value(
                    json!([{"type":"endpoint","endpoint":"synthetic-registry"}]),
                )
                .unwrap(),
                serde_json::from_value(json!([
                    batch(&["first", "second", "third"]),
                    batch(&["fifth"])
                ]))
                .unwrap(),
            ),
        );
        let mut sources = indexed_sources();
        crate::external_source::tests::add_indexed_binding(
            &mut sources,
            "people",
            "family-name",
            Arc::clone(&transcript),
        );
        let served = Served::with(&indexed_person_project(), sources, Duration::from_secs(2)).await;
        insert_roots(
            &served,
            &rows
                .iter()
                .map(|(id, key)| (*id, *key, "allowed"))
                .collect::<Vec<_>>(),
        )
        .await;
        let mut refresh = request("people-link");
        refresh.query = ExternalQueryMode::First(ExternalQuery {
            page_size: 9,
            ..ExternalQuery::default()
        });
        let plan = served.service.plan(&refresh, None).ok().unwrap();
        let claims = ClaimContext::for_compiled(
            &served.service.registry,
            &plan.root.id,
            Some("reader-principal".to_owned()),
            "reader",
            Some("consultation".to_owned()),
            vec![crate::postgres::context::RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "allowed".to_owned(),
            }],
        )
        .unwrap();

        // The first page holds the three valid fixture keys, four invalid
        // keys and two roots without a key.
        let captured = registry_platform_testing::CapturedDiagnosticLogs::default();
        let first = served
            .service
            .refresh_page(&refresh, &plan, &claims)
            .with_subscriber(captured.subscriber())
            .await
            .ok()
            .unwrap()
            .body;
        assert_eq!(first["processed"], 9, "{first}");
        assert_eq!(first["published"], 3, "{first}");
        assert_eq!(first["unavailable"], 4, "{first}");
        let cursor = first["nextCursor"].as_str().unwrap().to_owned();
        let logs = captured.text();
        let line = log_line(&logs, "people", "invalid-key");
        assert!(line.contains(r#""level":"WARN""#), "{line}");
        assert!(line.contains(r#""keys":4"#), "{line}");
        assert_value_free(&logs);
        for value in ["\u{1D518}", "\u{E9}", "bell", "padded", "family-"] {
            assert!(!logs.contains(value), "{value} reached the log: {logs}");
        }

        // The sweep moves past the page.
        refresh.query = ExternalQueryMode::Continue(cursor);
        let second = served
            .service
            .refresh_page(&refresh, &plan, &claims)
            .await
            .ok()
            .unwrap()
            .body;
        assert_eq!(second["processed"], 1, "{second}");
        assert_eq!(second["published"], 1, "{second}");
        assert_eq!(second["unavailable"], 0, "{second}");
        assert!(second.get("nextCursor").is_none(), "{second}");
        // Only the valid keys reached the source, in the two recorded calls.
        transcript.finish().unwrap();
        let stored: Vec<String> = served
            .fixture
            .database
            .admin
            .query(
                "SELECT subject_key FROM registry_internal.registry_external_projection_snapshots
                 WHERE projection_id='people' ORDER BY subject_key COLLATE \"C\"",
                &[],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(stored, ["fifth", "first", "second", "third"]);

        // A root whose key cannot be acquired reads as having no outside
        // value, so its view keeps serving the other records.
        let (status, _, body) = served
            .send(
                "/v1/external-views/view/people-link/records?accessProfile=reader&$count=true",
                reader("reader-principal", &["allowed"]),
            )
            .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["count"], 10, "{body}");
        let available = body["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| record["availability"] == "available")
            .count();
        assert_eq!(available, 4, "{body}");
        served.fixture.cleanup().await;
    }

    /// The person projection fixture plus a by-parent member projection whose
    /// link labels each member through the person projection, and a service
    /// profile that may refresh both.
    fn labelled_members_project() -> Value {
        let mut project = indexed_person_project();
        project["externalRecordTypes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"member","authority":"urn:test:authority","identifierScheme":"urn:test:members",
                "fields":[{"id":"holder","type":"string","classification":"internal","nullable":true}]
            }));
        project["externalProjections"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"members","recordType":"member","operation":"members","operationVersion":"1",
                "purpose":"consultation","scope":"eligible","selectorScheme":"urn:test:keys",
                "mode":"indexed","cardinality":"many","cacheTtlSeconds":60,"fields":["holder"]
            }));
        project["externalViews"][0]["links"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"members-link","projection":"members","fromField":"subject-key",
                "identifierScheme":"urn:test:keys","fields":["holder"],
                "label":{"projection":"people","fromField":"holder","identifierScheme":"urn:test:keys","fields":["family-name"]}
            }));
        project["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"refresh","principalClaim":"registry_principal","actorKind":"service",
                "requesterClients":["worker"],"requiredScopes":["registry.refresh"],"requiredPurposes":["consultation"],
                "permissions":{
                    "records":[{"recordType":"local-record","operations":["list"],"rowBoundaries":[{"field":"tenant","claim":"tenant","operator":"equals"}]}],
                    "refreshExternalProjections":["members","people"]
                }
            }));
        project
    }

    #[tokio::test]
    async fn invalid_label_selectors_are_unavailable_without_failing_the_rest_of_the_label_batch() {
        use tracing::instrument::WithSubscriber;
        let long = "q".repeat(513); // one byte over the source token bound
        let oversized = "\u{1D518}".repeat(300); // 1200 bytes: over the store key bound
        let endpoints = || {
            serde_json::from_value(json!([{"type":"endpoint","endpoint":"synthetic-registry"}]))
                .unwrap()
        };
        let batch = |keys: &[&str]| {
            json!({
                "request":{"endpoint":"synthetic-registry","method":"POST","path":"/people/batch","body":{
                    "type":"batch","keys":keys,"fields":["family-name"]
                }},
                "response":{"status":200,"body":{"records":keys.iter().map(|key| json!({
                    "subject":key,"state":"found","properties":{"family-name":format!("family-{key}")}
                })).collect::<Vec<_>>()}}
            })
        };
        let transcript = Arc::new(
            registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                endpoints(),
                serde_json::from_value(json!([batch(&["alpha", "beta"]), batch(&["delta"])]))
                    .unwrap(),
            ),
        );
        let mut sources = indexed_sources();
        crate::external_source::tests::add_indexed_binding(
            &mut sources,
            "people",
            "family-name",
            Arc::clone(&transcript),
        );
        // A label refresh never calls the parent's source.
        crate::external_source::tests::add_indexed_binding(
            &mut sources,
            "members",
            "holder",
            Arc::new(
                registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                    endpoints(),
                    serde_json::from_value(json!([])).unwrap(),
                ),
            ),
        );
        let served =
            Served::with(&labelled_members_project(), sources, Duration::from_secs(2)).await;
        let members = bound_scope(&served.fixture, "members").await;
        served
            .fixture
            .publish_collection(
                &members,
                "first",
                &[
                    ("m1", json!({"holder":"alpha"})),
                    ("m2", json!({"holder":long})),
                    ("m3", json!({"holder":"beta"})),
                    ("m4", json!({"holder":"gamma "})),
                    ("m5", json!({"holder":"bell\u{7}key"})),
                    ("m6", json!({"holder":oversized})),
                ],
            )
            .await;
        served
            .fixture
            .publish_collection(&members, "second", &[("m1", json!({"holder":"delta"}))])
            .await;

        let worker = crate::api::VerifiedRequestClaims::authenticated(
            "registry_principal",
            "worker-principal",
            BTreeSet::from(["registry.refresh".to_owned()]),
            Some("consultation".to_owned()),
            BTreeMap::new(),
        )
        .unwrap()
        .with_contextual_authority(
            Some(registry_platform_oidc::ActorKind::Service),
            Some("worker".to_owned()),
            None,
            None,
            BTreeMap::new(),
        )
        .unwrap();
        let mut refresh = ExternalViewRequest {
            context: crate::api::AuthorizedRequestContext::new(
                Some("worker-principal".to_owned()),
                Some("consultation".to_owned()),
                "refresh".to_owned(),
                Vec::new(),
            )
            .with_audit_context(&worker),
            correlation: RequestCorrelation::breg_created(),
            view: "view".to_owned(),
            link: "members-link".to_owned(),
            root: None,
            query: ExternalQueryMode::First(ExternalQuery {
                page_size: 6,
                ..ExternalQuery::default()
            }),
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let plan = served
            .service
            .plan(&refresh, Some(RefreshMode::Labels))
            .ok()
            .unwrap();
        let claims = ClaimContext::for_compiled(
            &served.service.registry,
            &plan.root.id,
            Some("worker-principal".to_owned()),
            "refresh",
            Some("consultation".to_owned()),
            vec![crate::postgres::context::RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "allowed".to_owned(),
            }],
        )
        .unwrap();

        // The first page holds the first parent's six members: two valid
        // selectors and four the source contract or the store would refuse.
        let captured = registry_platform_testing::CapturedDiagnosticLogs::default();
        let first = served
            .service
            .refresh_page(&refresh, &plan, &claims)
            .with_subscriber(captured.subscriber())
            .await
            .ok()
            .unwrap()
            .body;
        assert_eq!(first["processed"], 6, "{first}");
        assert_eq!(first["published"], 2, "{first}");
        assert_eq!(first["unavailable"], 4, "{first}");
        let cursor = first["nextCursor"].as_str().unwrap().to_owned();
        let logs = captured.text();
        let line = log_line(&logs, "people", "invalid-key");
        assert!(line.contains(r#""level":"WARN""#), "{line}");
        assert!(line.contains(r#""keys":4"#), "{line}");
        assert_value_free(&logs);
        for value in [
            "alpha",
            "beta",
            "gamma",
            "bell",
            "qqq",
            "\u{1D518}",
            "family-",
        ] {
            assert!(!logs.contains(value), "{value} reached the log: {logs}");
        }

        // The acquisition moves past the page.
        refresh.query = ExternalQueryMode::Continue(cursor);
        let second = served
            .service
            .refresh_page(&refresh, &plan, &claims)
            .await
            .ok()
            .unwrap()
            .body;
        assert_eq!(second["processed"], 1, "{second}");
        assert_eq!(second["published"], 1, "{second}");
        assert_eq!(second["unavailable"], 0, "{second}");
        assert!(second.get("nextCursor").is_none(), "{second}");
        // Only the valid selectors reached the source, in the two recorded
        // batches, and each of them now has its label.
        transcript.finish().unwrap();
        let stored: Vec<(String, Value)> = served
            .fixture
            .database
            .admin
            .query(
                "SELECT subject_key,fields FROM registry_internal.registry_external_projection_values
                 WHERE projection_id='people' ORDER BY subject_key COLLATE \"C\"",
                &[],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();
        assert_eq!(
            stored,
            ["alpha", "beta", "delta"].map(|key| (
                key.to_owned(),
                json!({"family-name": format!("family-{key}")})
            ))
        );
        served.fixture.cleanup().await;
    }

    /// Source keys, labels and snapshot identities the fixtures below store.
    /// None of them may reach an operational log line.
    const FIXTURE_VALUES: [&str; 7] = [
        "\"first",
        "\"second",
        "\"third",
        "\"hidden",
        "\"subject",
        "cached",
        "canary",
    ];

    fn assert_value_free(logs: &str) {
        for value in FIXTURE_VALUES {
            assert!(!logs.contains(value), "{value} reached the log: {logs}");
        }
    }

    fn log_line<'a>(logs: &'a str, projection: &str, reason: &str) -> &'a str {
        logs.lines()
            .find(|line| {
                line.contains(&format!(r#""projection":"{projection}""#))
                    && line.contains(&format!(r#""reason":"{reason}""#))
            })
            .unwrap_or_else(|| panic!("no {projection} {reason} line: {logs}"))
    }

    #[tokio::test]
    async fn a_recorded_refresh_page_logs_its_outcomes_by_reason_without_values() {
        use tracing::instrument::WithSubscriber;
        let served = Served::new(Duration::from_secs(2)).await;
        let refresh = request("link");
        let plan = served.service.plan(&refresh, None).ok().unwrap();
        let claims = ClaimContext::for_compiled(
            &served.service.registry,
            &plan.root.id,
            Some("reader-principal".to_owned()),
            "reader",
            Some("consultation".to_owned()),
            vec![crate::postgres::context::RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "allowed".to_owned(),
            }],
        )
        .unwrap();
        let page = RefreshRows {
            rows: Vec::new(),
            next: None,
            eligibility: RootKeys::new(&plan).ok().unwrap().publication_eligibility,
            supporting_until: None,
            supporting: Vec::new(),
        };
        let outcomes = [
            None,
            Some(RefreshFailure::Denied),
            Some(RefreshFailure::Unavailable),
        ];
        let mut results = Vec::new();
        for ((id, key, _), failure) in ROOTS[..3].iter().zip(outcomes) {
            let (ticket, snapshot) = served
                .fixture
                .label_refresh(&served.scope, key, "canary")
                .await;
            results.push((
                RefreshWork {
                    key: (*key).to_owned(),
                    roots: BTreeSet::from([Uuid::parse_str(id).unwrap()]),
                    ticket,
                    managed_targets: Vec::new(),
                },
                failure.map_or(RefreshResult::Accepted(snapshot), RefreshResult::Failed),
            ));
        }
        let captured = registry_platform_testing::CapturedDiagnosticLogs::default();
        let recorded = served
            .service
            .record_refresh(
                &refresh,
                &plan,
                &claims,
                &served.scope,
                None,
                &page,
                results,
                None,
            )
            .with_subscriber(captured.subscriber())
            .await;
        assert_eq!(recorded.ok().map(|tally| tally.published), Some(1));
        let logs = captured.text();
        let recorded = logs
            .lines()
            .find(|line| line.contains(r#""published":1"#))
            .unwrap_or_else(|| panic!("{logs}"));
        assert!(recorded.contains(r#""projection":"projection""#), "{logs}");
        for reason in ["denied", "unavailable"] {
            let line = log_line(&logs, "projection", reason);
            assert!(line.contains(r#""level":"WARN""#), "{line}");
            assert!(line.contains(r#""keys":1"#), "{line}");
        }
        assert_eq!(logs.lines().count(), 3, "{logs}");
        assert_value_free(&logs);
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_retention_tick_logs_what_it_purged_by_projection_and_reason() {
        use tracing::instrument::WithSubscriber;
        let served = Served::new(Duration::from_millis(300)).await;
        served.publish_all().await;
        let other = bound_scope(&served.fixture, "other").await;
        served.fixture.cache(&other).await;
        served
            .fixture
            .migration
            .batch_execute(
                "UPDATE registry_internal.registry_external_projection_snapshots
                 SET observed_at=0,expires_at=1 WHERE projection_id='projection';
                 SELECT registry_internal.withdraw_external_projection(
                     projection_id,epoch,binding_digest,grant_digest)
                 FROM registry_internal.registry_external_projection_scopes
                 WHERE projection_id='other';",
            )
            .await
            .unwrap();

        let captured = registry_platform_testing::CapturedDiagnosticLogs::default();
        assert!(
            served
                .service
                .retention_tick()
                .with_subscriber(captured.subscriber())
                .await
        );
        let logs = captured.text();
        let expired = log_line(&logs, "projection", "expired");
        assert!(expired.contains(r#""snapshots":4"#), "{expired}");
        let withdrawn = log_line(&logs, "other", "withdrawn");
        assert!(withdrawn.contains(r#""snapshots":1"#), "{withdrawn}");
        assert!(withdrawn.contains(r#""receipts":1"#), "{withdrawn}");
        assert_value_free(&logs);

        // A migration holding the registry lock fails the tick by category.
        let lock_key = RegistryLockKey::derive(served.service.registry.registry_id())
            .unwrap()
            .get();
        served
            .fixture
            .migration
            .execute("SELECT pg_advisory_lock($1)", &[&lock_key])
            .await
            .unwrap();
        let captured = registry_platform_testing::CapturedDiagnosticLogs::default();
        assert!(
            !served
                .service
                .retention_tick()
                .with_subscriber(captured.subscriber())
                .await
        );
        let logs = captured.text();
        assert_eq!(logs.lines().count(), 1, "{logs}");
        assert!(logs.contains(r#""level":"ERROR""#), "{logs}");
        assert!(logs.contains(r#""reason":"lock-timeout""#), "{logs}");
        served
            .fixture
            .migration
            .execute("SELECT pg_advisory_unlock($1)", &[&lock_key])
            .await
            .unwrap();
        served.fixture.cleanup().await;
    }

    #[tokio::test]
    async fn a_check_reports_each_grant_horizon_and_newest_publication() {
        let served = Served::new(Duration::from_secs(2)).await;
        served.publish_all().await;
        let other = bound_scope(&served.fixture, "other").await;
        served.fixture.cache(&other).await;
        // A withdrawn scope's rows are not what the projection serves.
        served
            .fixture
            .migration
            .batch_execute(
                "SELECT registry_internal.withdraw_external_projection(
                     projection_id,epoch,binding_digest,grant_digest)
                 FROM registry_internal.registry_external_projection_scopes
                 WHERE projection_id='other'",
            )
            .await
            .unwrap();
        let status = served.service.projection_status().await.ok().unwrap();
        assert_eq!(
            status
                .iter()
                .map(|projection| projection.projection.as_str())
                .collect::<Vec<_>>(),
            ["other", "projection"]
        );
        for projection in &status {
            assert_eq!(
                projection.grant_valid_until,
                served
                    .service
                    .sources
                    .binding(&projection.projection)
                    .unwrap()
                    .grant_valid_until()
                    .timestamp()
            );
            assert!(projection.indexed);
        }
        assert_eq!(status[0].newest_publication, None);
        let newest = status[1].newest_publication.unwrap();
        assert!(
            (Utc::now().timestamp() - newest).abs() <= 5,
            "{newest} is the publication time"
        );
        served.fixture.cleanup().await;
    }
}
