// SPDX-License-Identifier: Apache-2.0
//! Governed HTTP reads and bounded refresh of external views.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use registry_adapter_core::{ProjectionRecord, ProjectionRequest, ProjectionResult};
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
    ExternalQuery, ExternalQueryMode, ExternalViewError, ExternalViewRequest, ExternalViewService,
    RefreshMode,
};
use crate::api::ServiceFuture;
use crate::audit::{
    begin_pre_io_audit, profile_is_keyed, read_terminal_entry, PreIoAudit, PreIoAuditKind,
    ReadTerminalAudit, RegistryAudit, TerminalAudit, TerminalAuditOutcome,
};
use crate::cursor::CursorCodec;
use crate::external_source::{BoundExternalSource, ExternalSourceError, ExternalSourceService};
use crate::external_views::{
    ExternalCardinality, ExternalLinkPermissionSource, ExternalLinkSource, ExternalProjectionMode,
    ExternalProjectionSource, ExternalRecordTypeSource,
};
use crate::model::{CompiledEntity, CompiledRegistry, HttpMethod};

use super::cancellation::QueryCancellationGuard;
use super::external_label_acquisition::{LabelAcquisition, LabelAfter};
use super::external_projection::{
    self as store, AcceptedSnapshot, ProjectionGeneration, ProjectionRow, ProjectionScope,
    RefreshFailure, RefreshTicket, RetentionPermission,
};
use super::external_view_query::{
    self as indexed, ExternalAvailability, IndexedViewQuery, LabelScope, PageAfter, SortDirection,
};
use super::read::{strict_claim_context, ReadRelations};
use super::{
    begin_record_transaction, begin_registry_transaction, ClaimContext, ExpectedRegistryIdentity,
    GuardedTransaction, RegistryLockKey, RuntimePool,
};

type Result<T> = std::result::Result<T, ExternalViewError>;

pub(crate) struct PostgresExternalViewService {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit: RegistryAudit,
    cursors: Arc<CursorCodec>,
    sources: ExternalSourceService,
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

#[derive(Serialize, Deserialize)]
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
                    match timeout_at(Instant::now() + Duration::from_secs(5), self.purge_tick()).await {
                        Ok(Ok(())) => last_success.record(),
                        _ => tracing::error!("external projection retention tick failed"),
                    }
                }
            }
        }
    }

    async fn purge_tick(&self) -> Result<()> {
        const BATCH: u32 = 1000;
        let mut session = self.session().await?;
        for _ in 0..8 {
            let transaction = begin_registry_transaction(
                session.client(),
                self.lock_key,
                self.lock_timeout,
                &self.expected,
            )
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
            transaction
                .set_statement_budget(Duration::from_secs(2))
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            let (snapshots, receipts) = store::purge(&transaction, BATCH)
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            transaction
                .commit()
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            if snapshots < u64::from(BATCH) && receipts < u64::from(BATCH) {
                break;
            }
        }
        session.disarm();
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
        let key = RootKeys::new(plan)?
            .for_root(&transaction, root)
            .await?
            .ok_or(ExternalViewError::Concealed)?;
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
            self.acquire(request, plan, source_request, &fields, None, None)
                .await
                .ok()
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
            .ok_or(ExternalViewError::Concealed)?;
        let (status, records) = if current == key {
            self.live_records(request, plan, root, result)?
        } else {
            ("unavailable", Vec::new())
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
            Err(_)
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
            Err(_) if matches!(&request.query, ExternalQueryMode::Continue(_)) => {
                return Err(ExternalViewError::InvalidCursor);
            }
            Err(_) => return Err(ExternalViewError::Incomplete),
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
                Some(source) => self
                    .lock_scope(&transaction, source, label.projection.as_str())
                    .await
                    .ok()
                    .map(|(scope, generation)| {
                        (scope, generation, source.grant_valid_until().timestamp())
                    }),
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
            .map_err(|_| ExternalViewError::Unavailable)?;
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
        let entry = read_terminal_entry(
            self.audit.profile(),
            ReadTerminalAudit {
                terminal: TerminalAudit {
                    grant: request.context.grant_audit().cloned(),
                    outcome: if permitted {
                        TerminalAuditOutcome::Returned
                    } else {
                        TerminalAuditOutcome::Refused
                    },
                    method,
                    operation_id: operation.to_owned(),
                    entity_id: Some(plan.root.id.clone()),
                    action_id: None,
                    package_revision: self.expected.activation_id.clone(),
                    selected_access_profile: request.context.selected_profile().to_owned(),
                    purpose_present: request.context.purpose().is_some(),
                    principal_reference: request.context.principal().map(str::to_owned),
                    record_reference: request.root.map(|root| root.to_string()),
                    record_revision: None,
                    result_count: None,
                    field_set_reference: None,
                    correlation: request.correlation.clone(),
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
                json!([
                    boundary.field(),
                    format!("{:?}", boundary.operator()),
                    boundary.values()
                ])
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
        self.cursors
            .seal_external(&Continuation {
                binding,
                query,
                position,
                expires_at,
            })
            .map_err(|_| ExternalViewError::Unavailable)
    }
}

impl ExternalViewService for PostgresExternalViewService {
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
            timeout_at(request.deadline, self.run(request, Some(mode)))
                .await
                .map_err(|_| ExternalViewError::Unavailable)?
        })
    }
}

struct RefreshAuthority {
    pool: RuntimePool,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    scope: ProjectionScope,
    parent: Option<(ProjectionScope, ProjectionGeneration)>,
}

impl RefreshAuthority {
    async fn check(&self, deadline: Instant) -> std::result::Result<(), EvidenceHookError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| EvidenceHookError::Authority)?;
        let mut session = QueryCancellationGuard::new(self.pool.clone(), client);
        let transaction = begin_registry_transaction(
            session.client(),
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
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
        if let Some((parent, generation)) = &self.parent {
            let current = store::lock_generation(&transaction, parent)
                .await
                .map_err(|_| EvidenceHookError::Authority)?;
            if &current != generation {
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

    async fn page(
        &self,
        transaction: &GuardedTransaction<'_>,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<(Uuid, Option<String>)>> {
        // The row policy can make PostgreSQL underestimate the eligible
        // population. Prefer the existing primary-key order for this
        // bounded refresh transaction to avoid sorting the scope per page.
        transaction
            .transaction()
            .batch_execute("SET LOCAL enable_sort = off")
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        let rows = transaction
            .transaction()
            .query(
                &format!(
                    "{} WHERE ($1::uuid IS NULL OR {} > $1) ORDER BY {} LIMIT $2",
                    self.select, self.id, self.id
                ),
                &[&after, &i64::from(limit)],
            )
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

struct RefreshRows {
    rows: Vec<(Uuid, Option<String>)>,
    next: Option<RefreshAfter>,
    eligibility: String,
    supporting_until: Option<i64>,
}

struct RefreshWork {
    key: String,
    roots: BTreeSet<Uuid>,
    ticket: RefreshTicket,
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
        let mut by_key = BTreeMap::<String, BTreeSet<Uuid>>::new();
        let mut unavailable = 0usize;
        for (root, key) in &page.rows {
            if let Some(key) = key.as_ref().filter(|value| !value.is_empty()) {
                by_key.entry(key.clone()).or_default().insert(*root);
            } else {
                unavailable += 1;
            }
        }
        let keys = by_key.keys().cloned().collect::<Vec<_>>();
        let due = store::refresh_due_keys(
            &transaction,
            &scope,
            &keys,
            minimum_sequence,
            Utc::now().timestamp(),
        )
        .await
        .map_err(|_| ExternalViewError::Unavailable)?;
        let reused = keys.len() - due.len();
        let mut work = Vec::with_capacity(due.len());
        for (key, roots) in by_key {
            if !due.contains(&key) {
                continue;
            }
            let ticket = store::allocate_refresh(&transaction, &scope, &key)
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            work.push(RefreshWork { key, roots, ticket });
        }
        transaction
            .commit()
            .await
            .map_err(|_| ExternalViewError::Unavailable)?;
        session.disarm();
        drop(session);

        let mut published = 0usize;
        if !work.is_empty() {
            let authority = Arc::new(RefreshAuthority {
                pool: self.pool.clone(),
                expected: self.expected.clone(),
                lock_key: self.lock_key,
                lock_timeout: self.lock_timeout,
                scope: scope.clone(),
                parent: parent.clone(),
            });
            let outcomes = self
                .fetch_refresh(request, plan, &work, page.supporting_until, authority)
                .await;
            let mut session = self.session().await?;
            let transaction = self
                .transaction(&mut session, claims, request.deadline)
                .await?;
            let current =
                active_scope(&transaction, plan.source, plan.projection.id.as_str()).await?;
            if current.epoch != scope.epoch {
                return Err(ExternalViewError::Unavailable);
            }
            if let (Some(parent), Some((_, selected_generation))) = (&plan.label_parent, &parent) {
                let parent_is_current = self
                    .lock_scope(&transaction, parent.source, parent.projection.id.as_str())
                    .await
                    .is_ok_and(|(_, generation)| &generation == selected_generation);
                if !parent_is_current
                    || page
                        .supporting_until
                        .is_some_and(|cutoff| Utc::now().timestamp() >= cutoff)
                {
                    for work in &work {
                        store::fail_refresh(&transaction, &work.ticket, RefreshFailure::Abandoned)
                            .await
                            .map_err(|_| ExternalViewError::Unavailable)?;
                    }
                    transaction
                        .commit()
                        .await
                        .map_err(|_| ExternalViewError::Unavailable)?;
                    session.disarm();
                    return Err(ExternalViewError::Unavailable);
                }
            }
            for (work, result) in work.into_iter().zip(outcomes) {
                let accepted = match result {
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
                            Ok(store::Publication::Published | store::Publication::Replay) => true,
                            Ok(store::Publication::Ineligible)
                            | Err(store::ProjectionError::StaleRefresh) => {
                                store::fail_refresh(
                                    &transaction,
                                    &work.ticket,
                                    RefreshFailure::Abandoned,
                                )
                                .await
                                .map_err(|_| ExternalViewError::Unavailable)?;
                                false
                            }
                            Err(_) => return Err(ExternalViewError::Unavailable),
                        }
                    }
                    RefreshResult::Failed(failure) => {
                        store::fail_refresh(&transaction, &work.ticket, failure)
                            .await
                            .map_err(|_| ExternalViewError::Unavailable)?;
                        false
                    }
                };
                if accepted {
                    published += 1;
                } else {
                    unavailable += 1;
                }
            }
            transaction
                .commit()
                .await
                .map_err(|_| ExternalViewError::Unavailable)?;
            session.disarm();
        }
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
                            Some(Arc::clone(&authority)),
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
                            Some(Arc::clone(&authority)),
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
}

#[cfg(test)]
#[cfg(feature = "postgres-test")]
mod postgres_tests {
    use super::*;
    use crate::correlation::RequestCorrelation;
    use crate::postgres::external_projection::postgres_tests::{two_projection_project, Activated};

    fn service(registry: &CompiledRegistry, fixture: &Activated) -> PostgresExternalViewService {
        PostgresExternalViewService::new(
            fixture.pool.clone(),
            Arc::new(registry.clone()),
            fixture.expected.clone(),
            RegistryLockKey::derive(registry.registry_id()).unwrap(),
            Duration::from_secs(2),
            crate::audit::test_support::capturing(
                registry_platform_audit::AuditProfile::unkeyed_dev_only(),
            )
            .0,
            Arc::new(
                CursorCodec::new(
                    zeroize::Zeroizing::new(vec![7; 32]),
                    Duration::from_secs(60),
                )
                .unwrap(),
            ),
            crate::external_source::tests::indexed_service(&[
                ("projection", "binding", "grant", 60),
                ("other", "other-binding", "other-grant", 120),
            ]),
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
}
