// SPDX-License-Identifier: Apache-2.0
//! Durable refresh steps driven by an admitted worker, one bounded unit at a time.

use super::*;
use crate::api::external_views::{ExternalRefreshHint, HintAdmission};
use crate::api::{AuthorizedRequestContext, VerifiedRequestClaims};
use crate::audit::begin_statistics_pre_io_audit;
use crate::correlation::RequestCorrelation;
use crate::external_refresh_config::{
    ExternalRefreshResolution, ResolvedExternalRefreshProjection,
};
use queue::{ClaimedTarget, QueueError, Settlement, StepKind, SweepCheckpoint, WorkTarget};

const MAX_PENDING: i32 = 10_000;
const STEP: &str = "external-refresh-plan-step";
const HINT: &str = "external-refresh-plan-hint";

fn unavailable<T>(_: T) -> ExternalViewError {
    ExternalViewError::Unavailable
}

#[derive(Clone)]
pub(super) struct LeaseFence {
    id: Arc<str>,
    digest: Arc<str>,
    lease: queue::PlanLease,
    epochs: Vec<Uuid>,
}

impl LeaseFence {
    pub(super) async fn check(
        &self,
        transaction: &GuardedTransaction<'_>,
        targets: &[(i64, i64)],
    ) -> Result<()> {
        for epoch in &self.epochs {
            queue::guard_plan_lease(
                transaction,
                &self.id,
                &self.digest,
                Some(*epoch),
                self.lease,
                None,
            )
            .await
            .map_err(unavailable)?;
        }
        for target in targets {
            queue::guard_plan_lease(
                transaction,
                &self.id,
                &self.digest,
                None,
                self.lease,
                Some(*target),
            )
            .await
            .map_err(unavailable)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct AcquisitionAuthority {
    pub(super) claims: ClaimContext,
    fence: LeaseFence,
    page: Arc<RefreshRows>,
    keys: Vec<String>,
    targets: Vec<(i64, i64)>,
}

impl AcquisitionAuthority {
    pub(super) fn new(fence: &LeaseFence, claims: &ClaimContext, page: &RefreshRows) -> Self {
        Self {
            claims: claims.clone(),
            fence: fence.clone(),
            page: Arc::new(page.clone()),
            keys: Vec::new(),
            targets: Vec::new(),
        }
    }

    pub(super) fn for_work(&self, work: &[RefreshWork]) -> Self {
        Self {
            keys: work.iter().map(|item| item.key.clone()).collect(),
            targets: work
                .iter()
                .flat_map(|item| item.managed_targets.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            ..self.clone()
        }
    }

    pub(super) async fn check(&self, transaction: &GuardedTransaction<'_>) -> Result<()> {
        self.fence.check(transaction, &self.targets).await?;
        if !self
            .page
            .targeted_witnesses_current(transaction, &self.keys)
            .await?
        {
            return Err(ExternalViewError::Unavailable);
        }
        Ok(())
    }
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct StepReport {
    more_work: bool,
    processed: usize,
    published: usize,
    reused: usize,
    unavailable: usize,
    retried: usize,
    settled: usize,
    sweep_completed: bool,
    sweep_acquisition_failures: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedPosition {
    binding: String,
    after: RefreshAfter,
}

struct ManagedScopes {
    primary: ProjectionScope,
    labels: Option<ProjectionScope>,
}

#[derive(Default)]
struct TargetBatch {
    page: Option<RefreshRows>,
    selected: Vec<SelectedTarget>,
    required: BTreeSet<String>,
}

struct SelectedTarget {
    claimed: ClaimedTarget,
    keys: BTreeSet<String>,
    roots: BTreeSet<Uuid>,
    continuation: Option<String>,
}

impl TargetBatch {
    fn push(
        &mut self,
        mut rows: RefreshRows,
        target: ClaimedTarget,
        continuation: Option<String>,
    ) -> Result<()> {
        rows.rows.retain(|(_, key)| {
            key.as_ref()
                .is_some_and(|key| store::valid_key(key) && projection_token_valid(key))
        });
        let keys: BTreeSet<_> = rows
            .rows
            .iter()
            .filter_map(|(_, key)| key.clone())
            .collect();
        let roots = rows.rows.iter().map(|(root, _)| *root).collect();
        if matches!(&target.target, WorkTarget::SourceHint { .. }) {
            self.required.extend(keys.iter().cloned());
        }
        self.selected.push(SelectedTarget {
            claimed: target,
            keys,
            roots,
            continuation,
        });
        if let Some(page) = &mut self.page {
            if page.eligibility != rows.eligibility {
                return Err(ExternalViewError::Unavailable);
            }
            page.rows.extend(rows.rows);
            page.supporting.extend(rows.supporting);
            page.supporting_until = page
                .supporting_until
                .into_iter()
                .chain(rows.supporting_until)
                .min();
        } else {
            self.page = Some(rows);
        }
        Ok(())
    }
}

impl ManagedScopes {
    fn epochs(&self) -> impl Iterator<Item = Uuid> + '_ {
        std::iter::once(self.primary.epoch).chain(self.labels.iter().map(|scope| scope.epoch))
    }
}

impl PostgresExternalViewService {
    pub(crate) async fn configure_managed_refresh(
        &mut self,
        resolution: ExternalRefreshResolution,
        persist: bool,
    ) -> Result<()> {
        for (id, problem) in resolution.unavailable {
            tracing::warn!(plan = %id, path = %problem.path, code = problem.code,
                "external refresh plan is unavailable");
        }
        if !store::enabled(&self.registry) {
            return Ok(());
        }
        let mut session = self.session().await?;
        let transaction = self
            .managed_transaction(&mut session, Instant::now() + Duration::from_secs(30))
            .await?;
        let mut registrations = Vec::new();
        let mut available = BTreeMap::new();
        for (id, plan) in resolution.available {
            match self.managed_scopes(&transaction, &plan).await {
                Ok(scopes) => {
                    let many = self.registry.external_views().projections
                        [&scopes.primary.projection_id]
                        .cardinality
                        == ExternalCardinality::Many;
                    registrations.push(queue::PlanRegistration {
                        plan_id: id.clone(),
                        package_digest: self.expected.package_digest.clone(),
                        activation_id: self.expected.activation_uuid().map_err(unavailable)?,
                        authority_digest: plan.authority_digest.clone(),
                        root_entity_id: plan.target.root_record_type.clone(),
                        watched_fields: plan
                            .target
                            .row_boundary_fields
                            .iter()
                            .cloned()
                            .chain(std::iter::once(plan.target.from_field.clone()))
                            .collect(),
                        projection_epochs: scopes.epochs().collect(),
                        interval_seconds: i64::try_from(plan.interval.as_secs())
                            .map_err(unavailable)?,
                        page_size: i32::from(if many {
                            plan.page_size.min(10)
                        } else {
                            plan.page_size
                        }),
                        max_pending: MAX_PENDING,
                    });
                    available.insert(id, plan);
                }
                Err(ExternalViewError::ProjectionUnavailable(projection)) => {
                    tracing::warn!(plan = %id, %projection,
                        "external refresh plan has no active source binding");
                }
                Err(error) => return Err(error),
            }
        }
        if persist {
            queue::register_plans(&transaction, &registrations)
                .await
                .map_err(unavailable)?;
            transaction.commit().await.map_err(unavailable)?;
        } else {
            transaction.rollback().await.map_err(unavailable)?;
        }
        session.disarm();
        self.managed_refresh = available;
        Ok(())
    }

    async fn managed_transaction<'a>(
        &self,
        session: &'a mut QueryCancellationGuard,
        deadline: Instant,
    ) -> Result<GuardedTransaction<'a>> {
        let transaction = begin_registry_transaction(
            session.client(),
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(unavailable)?;
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(30));
        if budget < Duration::from_millis(1) {
            return Err(ExternalViewError::Unavailable);
        }
        transaction
            .set_statement_budget(budget)
            .await
            .map_err(unavailable)?;
        Ok(transaction)
    }

    pub(crate) async fn managed_refresh_status(
        &self,
    ) -> Result<Vec<crate::startup::ExternalRefreshPlanStatus>> {
        if self.managed_refresh.is_empty() {
            return Ok(Vec::new());
        }
        let mut session = self.session().await?;
        let transaction = self
            .managed_transaction(&mut session, Instant::now() + Duration::from_secs(10))
            .await?;
        let mut reports = Vec::with_capacity(self.managed_refresh.len());
        for (id, plan) in &self.managed_refresh {
            let state = queue::plan_status(&transaction, id, &plan.authority_digest)
                .await
                .map_err(unavailable)?;
            reports.push(crate::startup::ExternalRefreshPlanStatus {
                plan: id.clone(),
                registered: state.as_ref().is_some_and(|state| state.active),
                due: state.as_ref().is_some_and(|state| state.due),
                leased: state.as_ref().is_some_and(|state| state.leased),
                pending: state.as_ref().map_or(0, |state| state.pending),
                ready: state.as_ref().map_or(0, |state| state.ready),
                oldest_ready_age_seconds: state
                    .as_ref()
                    .and_then(|state| state.oldest_ready_age_seconds),
                last_attempt_at: state.as_ref().and_then(|state| state.last_attempt_at),
                last_completed_at: state.as_ref().and_then(|state| state.last_completed_at),
                last_outcome: state.and_then(|state| state.last_attempt_outcome),
            });
        }
        transaction.rollback().await.map_err(unavailable)?;
        session.disarm();
        Ok(reports)
    }

    async fn managed_scopes(
        &self,
        transaction: &GuardedTransaction<'_>,
        config: &ResolvedExternalRefreshPlan,
    ) -> Result<ManagedScopes> {
        let primary = self
            .configured_scope(transaction, &config.target.primary_projection)
            .await?;
        let labels = match &config.target.label_projection {
            Some(label) if config.refresh_labels => {
                Some(self.configured_scope(transaction, label).await?)
            }
            _ => None,
        };
        Ok(ManagedScopes { primary, labels })
    }

    async fn configured_scope(
        &self,
        transaction: &GuardedTransaction<'_>,
        projection: &ResolvedExternalRefreshProjection,
    ) -> Result<ProjectionScope> {
        let id = &projection.projection;
        let projection = self
            .registry
            .external_views()
            .projections
            .get(id)
            .ok_or(ExternalViewError::Unavailable)?;
        active_scope(transaction, self.bound_source(projection)?, id).await
    }

    pub(super) async fn run_hint(
        &self,
        id: &str,
        claims: VerifiedRequestClaims,
        correlation: RequestCorrelation,
        deadline: Instant,
        hint: ExternalRefreshHint,
    ) -> Result<HintAdmission> {
        let config = self
            .managed_refresh
            .get(id)
            .ok_or(ExternalViewError::Concealed)?;
        let context = AuthorizedRequestContext::new(
            claims.principal().map(str::to_owned),
            claims.purpose().map(str::to_owned),
            format!("external-refresh:{id}"),
            Vec::new(),
        )
        .with_audit_context(&claims);
        let attempt = begin_statistics_pre_io_audit(
            &self.audit,
            &self.expected,
            &context,
            PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method: HttpMethod::Post,
                operation_id: HINT,
                target_record: None,
                refusal_reason: None,
                correlation: &correlation,
            },
        )
        .await
        .map_err(unavailable)?;
        let result = self.store_hint(config, &claims, deadline, hint).await;
        if !attempt.is_answered() {
            self.terminal_for(
                &context,
                &correlation,
                None,
                None,
                HINT,
                HttpMethod::Post,
                matches!(result, Ok(HintAdmission::Accepted)),
            )
            .await?;
        }
        result
    }

    async fn store_hint(
        &self,
        config: &ResolvedExternalRefreshPlan,
        claims: &VerifiedRequestClaims,
        deadline: Instant,
        hint: ExternalRefreshHint,
    ) -> Result<HintAdmission> {
        // Only the authenticated client can replay its hint ID. The payload
        // receipt contains a keyed digest, so settled selectors are gone.
        let client = claims
            .requester_client()
            .ok_or(ExternalViewError::Concealed)?;
        let digest = |domain: &'static [u8], data: Value| {
            self.cursors
                .binding_digest(domain, &data)
                .map_err(unavailable)
        };
        let mut session = self.session().await?;
        let transaction = self.managed_transaction(&mut session, deadline).await?;
        let scopes = self.managed_scopes(&transaction, config).await?;
        let scope = std::iter::once(&scopes.primary)
            .chain(scopes.labels.as_ref())
            .find(|scope| scope.projection_id == hint.projection)
            .ok_or(ExternalViewError::Concealed)?;
        let notifier = digest(
            b"breg-external-refresh-notifier-v1",
            json!([
                config.id,
                config.authority_digest,
                client,
                scope.projection_id,
                scope.epoch
            ]),
        )?;
        let receipt = digest(
            b"breg-external-refresh-hint-v1",
            json!([notifier, hint.hint_id]),
        )?;
        let payload = digest(
            b"breg-external-refresh-hint-payload-v1",
            json!([hint.selector_scheme, hint.selector]),
        )?;
        let target =
            self.source_target_digest(scope.epoch, &hint.selector_scheme, &hint.selector)?;
        let expires_at = self.work_expiry(scope)?;
        let result = queue::enqueue_hint(
            &transaction,
            &config.id,
            &config.authority_digest,
            &notifier,
            &receipt,
            &payload,
            &target,
            scope.epoch,
            &hint.selector_scheme,
            &hint.selector,
            expires_at,
        )
        .await;
        let response = match result {
            Ok(_) => HintAdmission::Accepted,
            Err(QueueError::Conflict) => HintAdmission::Conflict,
            Err(QueueError::AtCapacity) => HintAdmission::AtCapacity,
            Err(error) => return Err(unavailable(error)),
        };
        transaction.commit().await.map_err(unavailable)?;
        session.disarm();
        Ok(response)
    }

    fn source_target_digest(&self, epoch: Uuid, scheme: &str, selector: &str) -> Result<String> {
        self.cursors
            .binding_digest(
                b"breg-external-refresh-source-target-v1",
                &json!([epoch, scheme, selector]),
            )
            .map_err(unavailable)
    }

    fn work_expiry(&self, scope: &ProjectionScope) -> Result<i64> {
        let projection = self
            .registry
            .external_views()
            .projections
            .get(&scope.projection_id)
            .ok_or(ExternalViewError::Unavailable)?;
        let source = self.bound_source(projection)?;
        let expiry = Utc::now()
            .timestamp()
            .saturating_add(scope.cache_ttl_seconds)
            .min(source.grant_valid_until().timestamp());
        if expiry <= Utc::now().timestamp() {
            return Err(ExternalViewError::Unavailable);
        }
        Ok(expiry)
    }

    pub(super) async fn run_managed_step(
        &self,
        id: &str,
        request: ExternalViewRequest,
        start_sweep: bool,
    ) -> Result<Value> {
        let config = self
            .managed_refresh
            .get(id)
            .ok_or(ExternalViewError::Concealed)?;
        let primary = self.plan(&request, Some(RefreshMode::Projection))?;
        let claims = strict_claim_context(&self.registry, &request.context, &primary.root.id)
            .map_err(unavailable)?;
        let attempt = begin_pre_io_audit(
            &self.audit,
            &self.expected,
            &claims,
            PreIoAudit {
                kind: PreIoAuditKind::Attempt,
                method: HttpMethod::Post,
                operation_id: STEP,
                target_record: None,
                refusal_reason: None,
                correlation: &request.correlation,
            },
        )
        .await
        .map_err(unavailable)?;
        let result = self
            .step(config, &request, &claims, &primary, start_sweep)
            .await;
        if !attempt.is_answered() {
            self.terminal(&request, &primary, STEP, HttpMethod::Post, result.is_ok())
                .await?;
        }
        serde_json::to_value(result?).map_err(unavailable)
    }

    async fn step(
        &self,
        config: &ResolvedExternalRefreshPlan,
        request: &ExternalViewRequest,
        claims: &ClaimContext,
        primary: &Plan<'_>,
        start_sweep: bool,
    ) -> Result<StepReport> {
        let labels = config
            .refresh_labels
            .then(|| self.plan(request, Some(RefreshMode::Labels)))
            .transpose()?;
        let mut session = self.session().await?;
        let transaction = self
            .managed_transaction(&mut session, request.deadline)
            .await?;
        let scopes = self.managed_scopes(&transaction, config).await?;
        if start_sweep
            && !queue::request_sweep(&transaction, &config.id, &config.authority_digest)
                .await
                .map_err(unavailable)?
        {
            return Err(ExternalViewError::Unavailable);
        }
        let Some(lease) = queue::claim_plan(
            &transaction,
            &config.id,
            &config.authority_digest,
            refresh_lease(request.deadline),
        )
        .await
        .map_err(unavailable)?
        else {
            transaction.commit().await.map_err(unavailable)?;
            session.disarm();
            return Ok(StepReport::default());
        };
        let fence = LeaseFence {
            id: config.id.as_str().into(),
            digest: config.authority_digest.as_str().into(),
            lease,
            epochs: scopes.epochs().collect(),
        };
        let mut state =
            queue::load_step_state(&transaction, &config.id, &config.authority_digest, lease)
                .await
                .map_err(unavailable)?;
        let targets = if state.next == StepKind::Targets {
            queue::claim_targets(&transaction, &config.id, lease)
                .await
                .map_err(unavailable)?
        } else {
            Vec::new()
        };
        transaction.commit().await.map_err(unavailable)?;
        session.disarm();
        drop(session);

        let mut report = StepReport::default();
        let outcome = if state.next == StepKind::Sweep && state.sweep_due {
            self.sweep_page(
                config,
                request,
                claims,
                primary,
                labels.as_ref(),
                &scopes,
                &fence,
                &mut state.checkpoint,
                &mut report,
            )
            .await?;
            match (
                state.checkpoint.completed,
                state.checkpoint.acquisition_failures,
            ) {
                (false, _) => "sweep-page",
                (true, 0) => "sweep-complete",
                (true, _) => "sweep-with-failures",
            }
        } else if !targets.is_empty() {
            self.target_batch(
                config,
                request,
                claims,
                primary,
                labels.as_ref(),
                &scopes,
                &fence,
                targets,
                &mut report,
            )
            .await?;
            "targets"
        } else {
            "idle"
        };

        let mut session = self.session().await?;
        let transaction = self
            .managed_transaction(&mut session, request.deadline)
            .await?;
        fence.check(&transaction, &[]).await?;
        queue::finish_step(
            &transaction,
            &config.id,
            &config.authority_digest,
            lease,
            state.next,
            &state.checkpoint,
            outcome,
        )
        .await
        .map_err(unavailable)?;
        report.more_work =
            queue::has_ready_work(&transaction, &config.id, &config.authority_digest)
                .await
                .map_err(unavailable)?;
        report.sweep_completed = state.checkpoint.completed;
        report.sweep_acquisition_failures = state.checkpoint.acquisition_failures;
        transaction.commit().await.map_err(unavailable)?;
        session.disarm();
        tracing::info!(
            plan = %config.id, outcome, processed = report.processed, published = report.published,
            reused = report.reused, retried = report.retried, settled = report.settled,
            sweep_acquisition_failures = report.sweep_acquisition_failures,
            "external refresh step completed"
        );
        Ok(report)
    }

    async fn label_parent_scope(
        &self,
        transaction: &GuardedTransaction<'_>,
        label: &Plan<'_>,
    ) -> Result<(ProjectionScope, ProjectionGeneration)> {
        let parent = label
            .label_parent
            .as_ref()
            .ok_or(ExternalViewError::Unavailable)?;
        self.lock_scope(transaction, parent.source, parent.projection.id.as_str())
            .await
    }

    #[allow(clippy::too_many_arguments)] // One page carries its bound plan, lease, scope and claim context.
    async fn sweep_page(
        &self,
        config: &ResolvedExternalRefreshPlan,
        request: &ExternalViewRequest,
        claims: &ClaimContext,
        primary: &Plan<'_>,
        labels: Option<&Plan<'_>>,
        scopes: &ManagedScopes,
        fence: &LeaseFence,
        checkpoint: &mut SweepCheckpoint,
        report: &mut StepReport,
    ) -> Result<()> {
        let mut session = self.session().await?;
        let transaction = self
            .transaction(&mut session, claims, request.deadline)
            .await?;
        fence.check(&transaction, &[]).await?;
        if checkpoint.phase == "complete" {
            *checkpoint = SweepCheckpoint {
                phase: "roots".to_owned(),
                baseline_sequence: 0,
                continuation: None,
                completed: false,
                acquisition_failures: 0,
            };
        }
        let (plan, scope, parent) = match checkpoint.phase.as_str() {
            "roots" => (primary, &scopes.primary, None),
            "labels" => {
                let label = labels.ok_or(ExternalViewError::Unavailable)?;
                (
                    label,
                    scopes
                        .labels
                        .as_ref()
                        .ok_or(ExternalViewError::Unavailable)?,
                    Some(self.label_parent_scope(&transaction, label).await?),
                )
            }
            _ => return Err(ExternalViewError::Unavailable),
        };
        active_scope(&transaction, plan.source, plan.projection.id.as_str()).await?;
        let mut after = None;
        if let Some(cursor) = &checkpoint.continuation {
            let binding = self.managed_position_binding(
                config,
                request,
                scope,
                parent.as_ref(),
                &checkpoint.phase,
                checkpoint.baseline_sequence,
            )?;
            match self.open_managed_position(cursor, &binding) {
                Ok(position) => after = Some(position),
                Err(_) => {
                    // A rotated cursor key or changed context discards the
                    // saved run. The next step starts under current authority.
                    tracing::warn!(plan = %config.id, "external refresh continuation reset");
                    checkpoint.phase = "complete".to_owned();
                    checkpoint.continuation = None;
                    transaction.commit().await.map_err(unavailable)?;
                    session.disarm();
                    return Ok(());
                }
            }
        }
        let proposed_baseline = if checkpoint.baseline_sequence == 0 {
            store::next_refresh_sequence(&transaction, scope)
                .await
                .map_err(unavailable)?
        } else {
            checkpoint.baseline_sequence
        };
        // Save the baseline before source I/O so replaying this position
        // reuses keys published before an interrupted page checkpoint.
        *checkpoint = queue::prepare_sweep(
            &transaction,
            &config.id,
            &config.authority_digest,
            fence.lease,
            proposed_baseline,
        )
        .await
        .map_err(unavailable)?;
        let page = self
            .refresh_rows(
                &transaction,
                request,
                plan,
                parent.as_ref(),
                after,
                config.page_size,
            )
            .await?;
        let (work, reused, invalid) = self
            .prepare_refresh(
                &transaction,
                request,
                plan,
                scope,
                &page,
                checkpoint.baseline_sequence,
                &BTreeSet::new(),
            )
            .await?;
        transaction.commit().await.map_err(unavailable)?;
        session.disarm();
        drop(session);

        let attempted = work.len();
        let tally = self
            .execute_refresh(
                request,
                plan,
                claims,
                scope,
                parent.as_ref(),
                &page,
                work,
                Some(fence),
            )
            .await?;
        report.processed = page.rows.len();
        report.published = tally.published;
        report.reused = reused;
        report.unavailable = invalid + attempted - tally.published;
        checkpoint.acquisition_failures +=
            i64::try_from(report.unavailable).map_err(unavailable)?;

        let mut session = self.session().await?;
        let transaction = self
            .managed_transaction(&mut session, request.deadline)
            .await?;
        fence.check(&transaction, &[]).await?;
        for (key, outcome) in tally.by_key {
            if outcome.failure().is_some_and(retryable) {
                let expires = self.work_expiry(scope)?;
                let ready_at = Utc::now().timestamp().saturating_add(15);
                if ready_at < expires {
                    let scheme = plan.projection.selector_scheme.as_str();
                    let target = self.source_target_digest(scope.epoch, scheme, &key)?;
                    queue::enqueue_sweep_retry(
                        &transaction,
                        &config.id,
                        &config.authority_digest,
                        fence.lease,
                        &target,
                        scope.epoch,
                        scheme,
                        &key,
                        1,
                        ready_at,
                        expires,
                    )
                    .await
                    .map_err(unavailable)?;
                    report.retried += 1;
                }
            }
        }
        if let Some(after) = page.next {
            let binding = self.managed_position_binding(
                config,
                request,
                scope,
                parent.as_ref(),
                &checkpoint.phase,
                checkpoint.baseline_sequence,
            )?;
            checkpoint.continuation = Some(self.seal_managed_position(binding, after)?);
        } else if checkpoint.phase == "roots" && labels.is_some() {
            checkpoint.phase = "labels".to_owned();
            checkpoint.baseline_sequence = 0;
            checkpoint.continuation = None;
        } else {
            checkpoint.phase = "complete".to_owned();
            checkpoint.continuation = None;
            checkpoint.completed = true;
        }
        transaction.commit().await.map_err(unavailable)?;
        session.disarm();
        Ok(())
    }

    fn managed_position_binding(
        &self,
        config: &ResolvedExternalRefreshPlan,
        request: &ExternalViewRequest,
        scope: &ProjectionScope,
        parent: Option<&(ProjectionScope, ProjectionGeneration)>,
        phase: &str,
        baseline: i64,
    ) -> Result<String> {
        let view = self.cursor_binding(
            request,
            scope,
            None,
            parent.map(|(_, generation)| *generation),
        )?;
        self.cursors
            .binding_digest(
                b"breg-external-refresh-position-v1",
                &json!([config.authority_digest, view, phase, baseline]),
            )
            .map_err(unavailable)
    }

    fn open_managed_position(&self, token: &str, binding: &str) -> Result<RefreshAfter> {
        let position: ManagedPosition = self
            .cursors
            .open_managed_refresh(token)
            .map_err(|_| ExternalViewError::InvalidCursor)?;
        if position.binding != binding {
            return Err(ExternalViewError::InvalidCursor);
        }
        Ok(position.after)
    }

    fn seal_managed_position(&self, binding: String, after: RefreshAfter) -> Result<String> {
        self.cursors
            .seal_managed_refresh(&ManagedPosition { binding, after })
            .map_err(unavailable)
    }

    #[allow(clippy::too_many_arguments)] // The batches share the same admitted, bounded step.
    async fn target_batch(
        &self,
        config: &ResolvedExternalRefreshPlan,
        request: &ExternalViewRequest,
        claims: &ClaimContext,
        primary: &Plan<'_>,
        labels: Option<&Plan<'_>>,
        scopes: &ManagedScopes,
        fence: &LeaseFence,
        targets: Vec<ClaimedTarget>,
        report: &mut StepReport,
    ) -> Result<()> {
        let mut session = self.session().await?;
        let transaction = self
            .transaction(&mut session, claims, request.deadline)
            .await?;
        fence.check(&transaction, &[]).await?;
        let parent = if let Some(labels) = labels {
            Some(self.label_parent_scope(&transaction, labels).await?)
        } else {
            None
        };
        let mut roots = TargetBatch::default();
        let mut related = TargetBatch::default();
        let limit = (usize::from(config.page_size) / targets.len().max(1)).max(1) as u16;
        report.processed = targets.len();
        for target in targets {
            if target.attempts > 4 || target.expires_at <= Utc::now().timestamp() {
                let reason = if target.attempts > 4 {
                    Settlement::AttemptsExhausted
                } else {
                    Settlement::Expired
                };
                if settle(&transaction, fence, &target, reason).await? {
                    report.settled += 1;
                }
                continue;
            }
            match &target.target {
                WorkTarget::LocalRecord { record_id } => {
                    let page = targeted::exact_root(&transaction, primary, *record_id).await?;
                    roots.push(page, target, None)?;
                }
                WorkTarget::SourceHint {
                    projection_epoch,
                    selector_scheme,
                    selector,
                } if *projection_epoch == scopes.primary.epoch
                    && selector_scheme == primary.projection.selector_scheme.as_str() =>
                {
                    let page = targeted::primary_selector(&transaction, primary, selector).await?;
                    roots.push(page, target, None)?;
                }
                WorkTarget::SourceHint {
                    projection_epoch,
                    selector_scheme,
                    selector,
                } if scopes
                    .labels
                    .as_ref()
                    .is_some_and(|scope| scope.epoch == *projection_epoch)
                    && labels.is_some_and(|plan| {
                        plan.projection.selector_scheme.as_str() == selector_scheme
                    }) =>
                {
                    let label = labels.ok_or(ExternalViewError::Unavailable)?;
                    let parent = parent.as_ref().ok_or(ExternalViewError::Unavailable)?;
                    let page = targeted::label_selector(
                        &transaction,
                        &self.registry,
                        request,
                        label,
                        parent,
                        selector,
                    )
                    .await?;
                    related.push(page, target, None)?;
                }
                WorkTarget::ParentLabels { record_id, after } if labels.is_some() => {
                    let label = labels.ok_or(ExternalViewError::Unavailable)?;
                    let scope = scopes
                        .labels
                        .as_ref()
                        .ok_or(ExternalViewError::Unavailable)?;
                    let parent = parent.as_ref().ok_or(ExternalViewError::Unavailable)?;
                    let binding = self.managed_position_binding(
                        config,
                        request,
                        scope,
                        Some(parent),
                        &format!("parent-labels:{record_id}"),
                        0,
                    )?;
                    let position = after
                        .as_deref()
                        .and_then(|token| self.open_managed_position(token, &binding).ok());
                    let member = match &position {
                        Some(RefreshAfter::Label {
                            root_id,
                            member_key,
                        }) if root_id == record_id => Some(member_key.as_str()),
                        _ => None,
                    };
                    let mut page = targeted::label_page_for_root(
                        &transaction,
                        &self.registry,
                        request,
                        label,
                        parent,
                        *record_id,
                        member,
                        limit,
                    )
                    .await?;
                    let continuation = page
                        .next
                        .take()
                        .map(|after| self.seal_managed_position(binding, after))
                        .transpose()?;
                    related.push(page, target, continuation)?;
                }
                _ => {
                    if settle(&transaction, fence, &target, Settlement::AuthorityChanged).await? {
                        report.settled += 1;
                    }
                }
            }
        }

        let primary_work = self
            .prepare_target_batch(&transaction, request, primary, &scopes.primary, &roots)
            .await?;
        let label_work = if let (Some(labels), Some(scope)) = (labels, &scopes.labels) {
            self.prepare_target_batch(&transaction, request, labels, scope, &related)
                .await?
        } else {
            (Vec::new(), 0)
        };
        transaction.commit().await.map_err(unavailable)?;
        session.disarm();
        drop(session);

        // Related work uses the selected parent snapshots. Finish it before
        // publishing a replacement parent from this same step.
        if let (Some(labels), Some(scope)) = (labels, &scopes.labels) {
            self.finish_target_batch(
                request,
                claims,
                labels,
                scope,
                parent.as_ref(),
                fence,
                related,
                label_work,
                None,
                report,
            )
            .await?;
        }
        self.finish_target_batch(
            request,
            claims,
            primary,
            &scopes.primary,
            None,
            fence,
            roots,
            primary_work,
            scopes.labels.as_ref(),
            report,
        )
        .await
    }

    async fn prepare_target_batch(
        &self,
        transaction: &GuardedTransaction<'_>,
        request: &ExternalViewRequest,
        plan: &Plan<'_>,
        scope: &ProjectionScope,
        batch: &TargetBatch,
    ) -> Result<(Vec<RefreshWork>, usize)> {
        let Some(page) = &batch.page else {
            return Ok((Vec::new(), 0));
        };
        let (mut work, reused, _) = self
            .prepare_refresh(transaction, request, plan, scope, page, 1, &batch.required)
            .await?;
        for item in &mut work {
            item.managed_targets = batch
                .selected
                .iter()
                .filter(|target| target.keys.contains(&item.key))
                .map(|target| (target.claimed.work_id, target.claimed.enqueue_generation))
                .collect();
        }
        Ok((work, reused))
    }

    #[allow(clippy::too_many_arguments)] // Settlement uses the exact batch and source scope just acquired.
    async fn finish_target_batch(
        &self,
        request: &ExternalViewRequest,
        claims: &ClaimContext,
        plan: &Plan<'_>,
        scope: &ProjectionScope,
        parent: Option<&(ProjectionScope, ProjectionGeneration)>,
        fence: &LeaseFence,
        batch: TargetBatch,
        (work, reused): (Vec<RefreshWork>, usize),
        enqueue_labels: Option<&ProjectionScope>,
        report: &mut StepReport,
    ) -> Result<()> {
        let Some(page) = batch.page else {
            return Ok(());
        };
        let attempted = work.len();
        let tally = self
            .execute_refresh(
                request,
                plan,
                claims,
                scope,
                parent,
                &page,
                work,
                Some(fence),
            )
            .await?;
        report.published += tally.published;
        report.reused += reused;
        report.unavailable += attempted - tally.published;

        let mut session = self.session().await?;
        let transaction = self
            .managed_transaction(&mut session, request.deadline)
            .await?;
        fence.check(&transaction, &[]).await?;
        for selected in batch.selected {
            let failures = selected.keys.iter().filter_map(|key| {
                tally
                    .by_key
                    .get(key)
                    .copied()
                    .and_then(RefreshOutcome::failure)
            });
            if failures.clone().any(retryable) {
                retry_or_settle(&transaction, fence, &selected.claimed, report).await?;
            } else {
                let outcome = if failures
                    .clone()
                    .any(|failure| failure == RefreshFailure::Denied)
                {
                    Settlement::Denied
                } else if failures
                    .clone()
                    .any(|failure| failure == RefreshFailure::RetentionRefused)
                {
                    Settlement::RetentionRefused
                } else if failures
                    .clone()
                    .any(|failure| failure == RefreshFailure::InvalidBinding)
                {
                    Settlement::AuthorityChanged
                } else if let Some(outcome) = selected.keys.iter().find_map(|key| {
                    tally
                        .by_key
                        .get(key)
                        .copied()
                        .and_then(RefreshOutcome::settlement)
                }) {
                    outcome
                } else if selected.keys.is_empty() {
                    Settlement::NoEligibleWitness
                } else {
                    Settlement::FreshReuse
                };
                if !settle(&transaction, fence, &selected.claimed, outcome).await? {
                    continue;
                }
                report.settled += 1;
                if matches!(outcome, Settlement::Published | Settlement::FreshReuse) {
                    if let Some(label_scope) = enqueue_labels {
                        let expires_at = self
                            .work_expiry(label_scope)?
                            .min(plan.grant_valid_until().timestamp());
                        for record_id in selected.roots {
                            queue::enqueue_internal_target(
                                &transaction,
                                &fence.id,
                                &fence.digest,
                                fence.lease,
                                &WorkTarget::ParentLabels {
                                    record_id,
                                    after: None,
                                },
                                expires_at,
                            )
                            .await
                            .map_err(unavailable)?;
                        }
                    }
                }
                if let (WorkTarget::ParentLabels { record_id, .. }, Some(after)) =
                    (selected.claimed.target, selected.continuation)
                {
                    if selected.claimed.expires_at > Utc::now().timestamp() {
                        queue::enqueue_internal_target(
                            &transaction,
                            &fence.id,
                            &fence.digest,
                            fence.lease,
                            &WorkTarget::ParentLabels {
                                record_id,
                                after: Some(after),
                            },
                            selected.claimed.expires_at,
                        )
                        .await
                        .map_err(unavailable)?;
                    }
                }
            }
        }
        transaction.commit().await.map_err(unavailable)?;
        session.disarm();
        Ok(())
    }
}

fn retryable(failure: RefreshFailure) -> bool {
    matches!(
        failure,
        RefreshFailure::Unavailable | RefreshFailure::Incomplete | RefreshFailure::Abandoned
    )
}

async fn settle(
    transaction: &GuardedTransaction<'_>,
    fence: &LeaseFence,
    claimed: &ClaimedTarget,
    reason: Settlement,
) -> Result<bool> {
    match queue::settle_target(transaction, &fence.id, fence.lease, claimed, reason).await {
        Ok(()) => Ok(true),
        // A concurrent enqueue leaves its newer generation pending.
        Err(QueueError::StaleLease) => Ok(false),
        Err(error) => Err(unavailable(error)),
    }
}

async fn retry_or_settle(
    transaction: &GuardedTransaction<'_>,
    fence: &LeaseFence,
    claimed: &ClaimedTarget,
    report: &mut StepReport,
) -> Result<()> {
    let delay = match claimed.attempts {
        1 => 15,
        2 => 30,
        3 => 60,
        _ => 0,
    };
    if delay == 0 || Utc::now().timestamp().saturating_add(delay) >= claimed.expires_at {
        let reason = if delay == 0 {
            Settlement::AttemptsExhausted
        } else {
            Settlement::Expired
        };
        if settle(transaction, fence, claimed, reason).await? {
            report.settled += 1;
        }
        return Ok(());
    }
    match queue::retry_target(
        transaction,
        &fence.id,
        fence.lease,
        claimed,
        Duration::from_secs(delay as u64),
    )
    .await
    {
        Ok(()) => report.retried += 1,
        Err(QueueError::StaleLease) => {}
        Err(error) => return Err(unavailable(error)),
    }
    Ok(())
}
