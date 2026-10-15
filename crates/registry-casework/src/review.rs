mod maintenance;
mod staffing;
use chrono::{DateTime, TimeDelta, Utc};
use deadpool_postgres::GenericClient;
use deadpool_postgres::Transaction;
use futures::{stream, StreamExt};
use registry_casework_core::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::{CaseworkService, PostgresStore, StoreError};

const MAXIMUM_REVIEW_FEED_PAGE: usize = 100;
const MAXIMUM_REVIEW_DRAFT_BYTES: usize = 16 * 1024;
const REVIEW_RETENTION_BATCH_SIZE: i64 = 100;

#[derive(Clone, Copy)]
enum ReviewTaskListView {
    Reviewer(Option<ReviewTaskOwnership>),
    Supervision(Option<Uuid>),
    OwnDecisions,
}

impl ReviewTaskListView {
    fn is_supervisory(self) -> bool {
        matches!(self, Self::Supervision(_))
    }

    fn ownership(self) -> Option<ReviewTaskOwnership> {
        match self {
            Self::Reviewer(ownership) => ownership,
            Self::Supervision(_) | Self::OwnDecisions => None,
        }
    }

    fn request_id(self) -> Option<Uuid> {
        match self {
            Self::Reviewer(_) | Self::OwnDecisions => None,
            Self::Supervision(request_id) => request_id,
        }
    }

    fn is_own_decisions(self) -> bool {
        matches!(self, Self::OwnDecisions)
    }

    fn needs_current_scan_scope(self) -> bool {
        self.request_id().is_some() || self.is_own_decisions()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewTaskScanContext<'a> {
    feed: &'static str,
    role: CaseworkRole,
    supervisory: bool,
    ownership: Option<ReviewTaskOwnership>,
    #[serde(skip_serializing_if = "Option::is_none")]
    own_decisions: Option<bool>,
    queue: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<Uuid>,
    source_profile: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewCreateOutcome {
    pub accepted: ReviewRequestAccepted,
    pub recovered: bool,
}

/// Keep one audit admission across exact recovery and a fresh submission.
enum ReviewRecovery {
    Fresh(Box<crate::audit::AuditOperation>),
    Recovered(Box<ReviewCreateOutcome>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewResultRead {
    Available(Box<ReviewResult>),
    Pending,
    Expired,
}

pub use registry_casework_core::ReviewTaskDecisionRequest;

#[derive(Clone, Debug)]
pub(crate) struct LeasedReviewCompletion {
    pub event: registry_casework_core::ReviewCompletion,
    pub destination_id: String,
    pub recipient_binding: String,
}

#[derive(Debug, Error)]
pub enum ReviewRuntimeError {
    #[error("the expected review policy binding does not match the active policy")]
    PolicyMismatch,
    #[error(
        "narrow the queue or exact subject query to complete it within the configured read budget"
    )]
    QueryTooBroad,
    #[error("the review resource was not found")]
    NotFound,
    #[error("the caller is not authorized for this review operation")]
    Forbidden,
    #[error("the retained submission has different canonical content")]
    SubmissionConflict,
    #[error("the retained review result has expired")]
    ResultExpired,
    #[error("the review task must be held by the caller")]
    TaskNotHeld,
    #[error("the caller initiated this review and its stage excludes them")]
    InitiatorExcluded,
    #[error("the review kind excludes its initiator, so the request must name one")]
    InitiatorRequired,
    #[error("the review resource revision changed")]
    RevisionConflict,
    #[error("the idempotency key was reused with different review input")]
    IdempotencyConflict,
    #[error("the retained idempotency response expired")]
    IdempotencyExpired,
    #[error("the review input is invalid")]
    Invalid,
    #[error(transparent)]
    Validation(ReviewValidationError),
    #[error("stored review state is invalid")]
    Corrupt,
    #[error("a source profile is required for source-context review work")]
    SourceProfileRequired,
    #[error("a source profile does not apply to submitted review work")]
    SourceProfileNotApplicable,
    #[error("the source is temporarily unavailable")]
    SourceUnavailable,
    #[error("the source response is invalid")]
    SourceInvalid,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<tokio_postgres::Error> for ReviewRuntimeError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Store(StoreError::Postgres(error))
    }
}

impl From<serde_json::Error> for ReviewRuntimeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Store(StoreError::Json(error))
    }
}

fn review_validation_error(error: ReviewDecisionValidationError) -> ReviewRuntimeError {
    match error {
        ReviewDecisionValidationError::Structured(error) => ReviewRuntimeError::Validation(error),
        ReviewDecisionValidationError::Policy(_) => ReviewRuntimeError::Corrupt,
    }
}

fn map_review_decision_error(error: ReviewDecisionError) -> ReviewRuntimeError {
    match error {
        ReviewDecisionError::TaskNotHeld | ReviewDecisionError::HolderMismatch => {
            ReviewRuntimeError::TaskNotHeld
        }
        ReviewDecisionError::InitiatorExcluded => ReviewRuntimeError::InitiatorExcluded,
        ReviewDecisionError::DuplicateReviewer
        | ReviewDecisionError::PreviousStageReviewerExcluded
        | ReviewDecisionError::ProfileNotEligible => ReviewRuntimeError::Forbidden,
        ReviewDecisionError::Validation(error) => review_validation_error(error),
        ReviewDecisionError::Policy(_) => ReviewRuntimeError::Corrupt,
        ReviewDecisionError::OutcomeNotAllowed { declared, .. } => ReviewRuntimeError::Validation(
            ReviewValidationError::new("$.outcome", ReviewValidationReason::OutcomeNotDeclared)
                .allowing(declared),
        ),
        _ => ReviewRuntimeError::Invalid,
    }
}

/// A stored clock the shared calendar refuses is corrupt state. The operator
/// log keeps the calendar's reason and the clock field it concerns.
fn clock_evaluation_error(clock: &ClockPolicy, error: ClockPolicyError) -> ReviewRuntimeError {
    tracing::error!(
        clock = clock.id(),
        reason = %error,
        "the active Casework policy has a clock the calendar cannot evaluate; correct the clock or its calendar and activate the policy again"
    );
    ReviewRuntimeError::Corrupt
}

#[derive(Clone)]
struct ProducerAdmission {
    producer: registry_casework_core::ReviewProducerPolicy,
}

/// A requester-role caller entitled to a request's requester-visible history.
enum RequesterReader {
    /// The admitted producer, bound to its exact identity.
    Producer(Box<registry_casework_core::ReviewProducerPolicy>),
    /// A person reading as the recorded initiator of a request admitted by
    /// one of these producers, each of which declares the caller's profile as
    /// its initiator profile.
    Initiator(std::collections::BTreeSet<String>),
}

#[derive(Clone)]
struct ReviewRequestRecord {
    request_id: Uuid,
    producer_id: String,
    producer_issuer: String,
    producer_subject: String,
    subject: SubjectBinding,
    requester_reference: String,
    policy: ReviewPolicyClosure,
    submission_digest: ContentDigest,
    lifecycle: ReviewRequestLifecycle,
    active_stage: Option<u16>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    result_available_until: Option<DateTime<Utc>>,
    result_erased_at: Option<DateTime<Utc>>,
    initiator: Option<IssuerPrincipal>,
    result_constraints: Option<Value>,
    context: Option<registry_casework_core::ReviewContext>,
}

impl CaseworkService {
    pub async fn erase_expired_reviews(&self) -> Result<u64, ReviewRuntimeError> {
        self.store.erase_expired_reviews_at(Utc::now()).await
    }

    pub async fn create_review_request(
        &self,
        actor: &ActorContext,
        request: ReviewCreateRequest,
        idempotency_key: &str,
    ) -> Result<ReviewCreateOutcome, ReviewRuntimeError> {
        request.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        let admission = self.producer_for_create(actor, &request)?;
        let digest = submission_digest(&admission.producer.id, &request.subject.source, &request)
            .map_err(|_| ReviewRuntimeError::Invalid)?;
        let audit = self
            .store
            .begin_audit(crate::audit::request_record(
                "review-request-created",
                Some(actor),
                &actor.profile_id,
                json!({}),
            ))
            .await?;
        let audit = match self
            .store
            .recover_review(
                &admission.producer,
                actor,
                &request,
                &digest,
                idempotency_key,
                audit,
            )
            .await?
        {
            ReviewRecovery::Recovered(recovered) => return Ok(*recovered),
            ReviewRecovery::Fresh(audit) => *audit,
        };
        self.store
            .create_review(
                &admission.producer,
                actor,
                request,
                &self.project,
                digest,
                idempotency_key,
                audit,
            )
            .await
    }

    pub async fn review_request(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
    ) -> Result<ReviewRequestView, ReviewRuntimeError> {
        let admission = self.producer_for_actor(actor)?;
        self.store
            .review_request(&admission.producer, request_id)
            .await
    }

    pub fn review_policy_descriptions(
        &self,
        actor: &ActorContext,
    ) -> Result<Vec<ReviewPolicyClosure>, ReviewRuntimeError> {
        let allowed = match actor.role {
            CaseworkRole::Requester => self.producer_for_actor(actor)?.producer.review_policies,
            CaseworkRole::Staff | CaseworkRole::Supervisor => self
                .project
                .review_policies
                .iter()
                .filter(|kind| {
                    kind.stages
                        .iter()
                        .any(|stage| stage.deciding_profiles.contains(&actor.profile_id))
                })
                .map(|kind| kind.id.clone())
                .collect(),
            CaseworkRole::Administrator => self
                .project
                .review_policies
                .iter()
                .map(|kind| kind.id.clone())
                .collect(),
        };
        self.project
            .review_policies
            .iter()
            .filter(|kind| allowed.contains(&kind.id))
            .map(|policy| {
                self.project
                    .compile_policy(&policy.id)
                    .map_err(|_| ReviewRuntimeError::Corrupt)
            })
            .collect()
    }

    pub fn review_policy_description(
        &self,
        actor: &ActorContext,
        kind_id: &str,
    ) -> Result<ReviewPolicyClosure, ReviewRuntimeError> {
        self.review_policy_descriptions(actor)?
            .into_iter()
            .find(|kind| kind.identity.id == kind_id)
            .ok_or(ReviewRuntimeError::NotFound)
    }

    pub async fn review_tasks(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        queue: Option<&str>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        self.review_tasks_with_ownership(
            actor,
            source_profile_id,
            token,
            queue,
            None,
            cursor,
            limit,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn review_tasks_with_ownership(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        queue: Option<&str>,
        ownership: Option<ReviewTaskOwnership>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        self.review_task_page(
            actor,
            source_profile_id,
            token,
            queue,
            ReviewTaskListView::Reviewer(ownership),
            cursor,
            limit,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn supervisory_review_tasks(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        queue: Option<&str>,
        request_id: Option<Uuid>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<SupervisoryReviewTaskPage, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        if actor.role != CaseworkRole::Supervisor {
            return Err(ReviewRuntimeError::Forbidden);
        }
        let page = self
            .review_task_page(
                actor,
                source_profile_id,
                token,
                queue,
                ReviewTaskListView::Supervision(request_id),
                cursor,
                limit,
            )
            .await?;
        let task_ids = page
            .items
            .iter()
            .map(|task| task.task_id)
            .collect::<Vec<_>>();
        // Recheck live supervision and retention when projecting the minimal
        // references. No reviewer content or policy is released by this route.
        let items = self
            .store
            .supervisory_review_task_rows(actor, queue, &task_ids)
            .await?;
        Ok(SupervisoryReviewTaskPage {
            items,
            next_cursor: page.next_cursor,
            status: page.status,
        })
    }

    pub async fn own_review_decisions(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        queue: Option<&str>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<OwnReviewDecisionPage, ReviewRuntimeError> {
        let page = self
            .review_task_page(
                actor,
                source_profile_id,
                token,
                queue,
                ReviewTaskListView::OwnDecisions,
                cursor,
                limit,
            )
            .await?;
        let ids = page
            .items
            .iter()
            .map(|task| task.task_id)
            .collect::<Vec<_>>();
        let items = self
            .store
            .own_review_decision_rows(actor, queue, &ids)
            .await?;
        Ok(OwnReviewDecisionPage {
            items,
            next_cursor: page.next_cursor,
            status: page.status,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn review_task_page(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        token: &str,
        queue: Option<&str>,
        view: ReviewTaskListView,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        if limit == 0 || limit > 100 {
            return Err(ReviewRuntimeError::Invalid);
        }
        let policy = &self.project.inbox;
        let started = Instant::now();
        let deadline = Duration::from_millis(policy.page_deadline_milliseconds);
        let deadline_at = tokio::time::Instant::now() + deadline;
        let cursor_context = serde_json::to_string(&ReviewTaskScanContext {
            feed: "review-task-scan/v1",
            role: actor.role,
            supervisory: view.is_supervisory(),
            ownership: view.ownership(),
            own_decisions: view.is_own_decisions().then_some(true),
            queue,
            request_id: view.request_id(),
            source_profile: source_profile_id,
        })?;
        let mut scan_cursor = cursor;
        let mut continuation_disclosed = true;
        if let Some(supplied) = cursor {
            // A budget continuation is an issued position, not disclosure of
            // its skipped task. Resolve it only in the issuing caller/query
            // context; every delivered row still needs fresh source checks.
            let issued = self
                .store
                .review_task_scan_cursor(actor, source_profile_id, &cursor_context, supplied)
                .await?;
            let anchor = issued.unwrap_or(supplied);
            self.store
                .review_task_cursor_position(actor, queue, view, anchor)
                .await?;
            if issued.is_none() {
                let preflight = async {
                    let record = self.store.review_request_for_task(anchor).await?;
                    self.preflight_review_inbox_source(&record, source_profile_id, token)
                        .await
                };
                // Preflight only the supplied task anchor, never every store
                // scan cursor. One fixed anchor allowance outside the candidate
                // budget lets even a one-read page advance, under its deadline.
                match tokio::time::timeout_at(deadline_at, preflight).await {
                    Ok(Ok(())) => {}
                    Ok(Err(
                        ReviewRuntimeError::Forbidden
                        | ReviewRuntimeError::NotFound
                        | ReviewRuntimeError::ResultExpired
                        | ReviewRuntimeError::SourceProfileRequired
                        | ReviewRuntimeError::SourceProfileNotApplicable,
                    )) => return Err(ReviewRuntimeError::ResultExpired),
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(ReviewRuntimeError::SourceUnavailable),
                }
                // Recheck even if the preflight used the remaining page time
                // and no candidate batch can run afterward.
                self.store
                    .review_task_cursor_position(actor, queue, view, anchor)
                    .await?;
            }
            scan_cursor = Some(anchor);
            continuation_disclosed = issued.is_none();
        }
        let mut items = Vec::with_capacity(limit + 1);
        let mut examined = 0usize;
        let mut source_reads = 0usize;
        let mut continuation = scan_cursor;
        let mut completed_preflights = 0usize;
        let mut budget_exhausted = false;
        let mut source_timed_out = false;
        let mut skipped_without_source_profile = false;
        while items.len() <= limit
            && examined < policy.maximum_candidate_scan
            && started.elapsed() < deadline
        {
            let batch_limit = (policy.maximum_candidate_scan - examined).min(100);
            let page = self
                .store
                .review_tasks(actor, queue, view, scan_cursor, batch_limit)
                .await?;
            let page_next_cursor = page.next_cursor;
            let page_length = page.items.len();
            let mut prepared = Vec::with_capacity(page_length);
            for task in page.items {
                let record = self.store.review_request_for_task(task.task_id).await?;
                let source_backed = matches!(
                    record.policy.context,
                    registry_casework_core::ReviewContextPolicy::CurrentSource { .. }
                );
                if source_backed && source_reads == policy.maximum_source_reads {
                    budget_exhausted = true;
                    break;
                }
                examined += 1;
                source_reads += usize::from(source_backed);
                prepared.push((task, record));
            }
            let prepared_length = prepared.len();
            let mut checks = stream::iter(prepared)
                .map(|(task, record)| async move {
                    let result = tokio::time::timeout_at(
                        deadline_at,
                        self.preflight_review_inbox_source(&record, source_profile_id, token),
                    )
                    .await;
                    (task, result)
                })
                .buffered(policy.maximum_concurrent_source_reads);
            while let Some((task, result)) = checks.next().await {
                let mut disclosed = false;
                match result {
                    Ok(Ok(())) => match self
                        .store
                        .review_task_by_activity(
                            actor,
                            task.task_id,
                            matches!(view, ReviewTaskListView::Reviewer(_)),
                            view.is_supervisory(),
                        )
                        .await
                    {
                        // Ownership and queue can change during source I/O.
                        // Recheck both before releasing the current row.
                        Ok(current)
                            if queue.is_none_or(|queue| current.queue == queue)
                                && (!view.is_own_decisions()
                                    || current.decision_receipt.is_some())
                                && review_task_matches_ownership(
                                    &current,
                                    actor,
                                    view.ownership(),
                                ) =>
                        {
                            items.push(current);
                            disclosed = true;
                        }
                        Ok(_) => {}
                        Err(
                            ReviewRuntimeError::Forbidden
                            | ReviewRuntimeError::NotFound
                            | ReviewRuntimeError::ResultExpired,
                        ) => {
                            // Losing one task does not conceal its siblings.
                            // Complete neutrally only if current scope is empty.
                            if view.needs_current_scan_scope()
                                && self
                                    .store
                                    .review_tasks(actor, queue, view, None, 1)
                                    .await?
                                    .items
                                    .is_empty()
                            {
                                return Ok(ReviewTaskPage {
                                    items: Vec::new(),
                                    next_cursor: None,
                                    status: PageStatus::Complete,
                                });
                            }
                        }
                        Err(error) => return Err(error),
                    },
                    Err(_) => {
                        if completed_preflights == 0 {
                            return Err(ReviewRuntimeError::SourceUnavailable);
                        }
                        budget_exhausted = true;
                        source_timed_out = true;
                        break;
                    }
                    Ok(Err(ReviewRuntimeError::SourceProfileRequired)) => {
                        skipped_without_source_profile = true;
                    }
                    Ok(Err(
                        ReviewRuntimeError::Forbidden
                        | ReviewRuntimeError::NotFound
                        | ReviewRuntimeError::SourceProfileNotApplicable,
                    )) => {
                        // Every task in an exact lookup has the same pinned
                        // request and source binding. A concealed request must
                        // look absent even when its tasks exceed the page budget.
                        if view.request_id().is_some() {
                            return Ok(ReviewTaskPage {
                                items: Vec::new(),
                                next_cursor: None,
                                status: PageStatus::Complete,
                            });
                        }
                    }
                    Ok(Err(error)) => return Err(error),
                }
                completed_preflights += 1;
                continuation = Some(task.task_id);
                continuation_disclosed = disclosed;
                if items.len() > limit {
                    break;
                }
            }
            drop(checks);
            if items.len() > limit {
                break;
            }
            if budget_exhausted || prepared_length < page_length {
                break;
            }
            let Some(next_cursor) = page_next_cursor else {
                continuation = None;
                break;
            };
            if scan_cursor == Some(next_cursor) {
                return Err(ReviewRuntimeError::Corrupt);
            }
            scan_cursor = Some(next_cursor);
            continuation = Some(next_cursor);
        }
        let full = items.len() > limit;
        let next_cursor = if full {
            Some(items[limit - 1].task_id)
        } else if budget_exhausted
            || examined >= policy.maximum_candidate_scan
            || started.elapsed() >= deadline
        {
            continuation
        } else {
            None
        };
        let next_cursor = match next_cursor {
            Some(anchor) if !full && !continuation_disclosed => {
                // A task can leave scope during source I/O without the whole
                // request disappearing. Do not checkpoint an invalid anchor or
                // infer an empty lookup from that task alone.
                let anchor_in_scope = if view.needs_current_scan_scope() {
                    match self
                        .store
                        .review_task_cursor_position(actor, queue, view, anchor)
                        .await
                    {
                        Ok(_) => true,
                        Err(ReviewRuntimeError::ResultExpired) => false,
                        Err(error) => return Err(error),
                    }
                } else {
                    true
                };
                if anchor_in_scope {
                    Some(
                        self.store
                            .issue_review_task_scan_cursor(
                                actor,
                                source_profile_id,
                                &cursor_context,
                                anchor,
                            )
                            .await?,
                    )
                } else {
                    // This bounded store-only check releases no unchecked row
                    // and spends no additional source reads.
                    if self
                        .store
                        .review_tasks(actor, queue, view, None, 1)
                        .await?
                        .items
                        .is_empty()
                    {
                        return Ok(ReviewTaskPage {
                            items: Vec::new(),
                            next_cursor: None,
                            status: PageStatus::Complete,
                        });
                    }
                    // Retain disclosed work and resume after its last current
                    // anchor, so candidates beyond the budget are not skipped.
                    // Without one, require a refetch instead of false absence.
                    let retained = items.last().ok_or(ReviewRuntimeError::ResultExpired)?;
                    self.store
                        .review_task_cursor_position(actor, queue, view, retained.task_id)
                        .await?;
                    Some(retained.task_id)
                }
            }
            cursor => cursor,
        };
        // A final empty page caused only by the absent Registry-Source-Profile
        // header is refused, so a first-time caller learns which header to
        // send. A page that lists anything keeps its submitted-context tasks,
        // and a page emptied by an exhausted budget keeps its continuation.
        if items.is_empty() && skipped_without_source_profile && next_cursor.is_none() {
            return Err(ReviewRuntimeError::SourceProfileRequired);
        }
        // A page that stopped before it filled says why, so a caller does not
        // read a short page as the end of the inbox.
        let status = if full || next_cursor.is_none() {
            PageStatus::Complete
        } else if source_timed_out {
            PageStatus::SourceUnavailable
        } else {
            PageStatus::BudgetExhausted
        };
        items.truncate(limit);
        Ok(ReviewTaskPage {
            items,
            next_cursor,
            status,
        })
    }

    pub async fn review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        match self
            .preflight_review_source(task_id, source_profile_id, token)
            .await
        {
            Err(
                ReviewRuntimeError::Forbidden
                | ReviewRuntimeError::NotFound
                | ReviewRuntimeError::ResultExpired,
            ) => {
                return Err(ReviewRuntimeError::NotFound);
            }
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        self.store.review_task(actor, task_id).await
    }

    pub async fn review_task_context(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<ReviewTaskContext, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        self.store.review_task(actor, task_id).await?;
        let record = self.store.review_request_for_task(task_id).await?;
        let context = match record.context.as_ref().ok_or(ReviewRuntimeError::Corrupt)? {
            ReviewContext::Submitted { snapshot } => {
                if source_profile_id.is_some() {
                    return Err(ReviewRuntimeError::SourceProfileNotApplicable);
                }
                ReviewTaskContextData::Submitted {
                    snapshot: snapshot.clone(),
                }
            }
            ReviewContext::CurrentSource { binding } => {
                let ReviewContextPolicy::CurrentSource { provider, contract } =
                    &record.policy.context
                else {
                    return Err(ReviewRuntimeError::Corrupt);
                };
                let profile = source_profile_id.ok_or(ReviewRuntimeError::SourceProfileRequired)?;
                let provider = self
                    .providers
                    .get(provider)
                    .ok_or(ReviewRuntimeError::SourceUnavailable)?;
                let identity = ReviewContextIdentity {
                    subject: record.subject.clone(),
                    contract: contract.clone(),
                };
                let view = tokio::time::timeout(
                    Duration::from_millis(
                        record.policy.dependencies.inbox.page_deadline_milliseconds,
                    ),
                    provider.human_display(HumanDisplayRequest {
                        identity: &identity,
                        source_profile_id: profile,
                        credential: EphemeralCredential::new(token),
                    }),
                )
                .await
                .map_err(|_| ReviewRuntimeError::SourceUnavailable)?
                .map_err(map_review_context_source_error)?;
                if view.identity != identity || !view.reviewable {
                    return Err(ReviewRuntimeError::NotFound);
                }
                record
                    .policy
                    .validate_display(&serde_json::to_value(&view.fields)?)
                    .map_err(|error| invalid_provider_display(&record.policy, error))?;
                ReviewTaskContextData::CurrentSource {
                    reference: binding.reference.clone(),
                    binding_status: ReviewSourceBindingStatus::Current,
                    projection: Some(ReviewSourceProjection {
                        binding: view.identity.subject,
                        display_reference: view.display_reference,
                        display: view.fields,
                    }),
                }
            }
        };
        self.store.review_task(actor, task_id).await?;
        Ok(ReviewTaskContext {
            task_id,
            request_id: record.request_id,
            subject: record.subject,
            requester_reference: record.requester_reference,
            policy: policy_binding(&record.policy),
            policy_closure: record.policy,
            result_constraints: record.result_constraints,
            context,
        })
    }

    pub async fn review_result(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
    ) -> Result<ReviewResultRead, ReviewRuntimeError> {
        let admission = self.producer_for_actor(actor)?;
        self.store
            .review_result(&admission.producer, request_id)
            .await
    }

    pub async fn review_result_feed(
        &self,
        actor: &ActorContext,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewResultFeedPage, ReviewRuntimeError> {
        if limit == 0 || limit > MAXIMUM_REVIEW_FEED_PAGE {
            return Err(ReviewRuntimeError::Invalid);
        }
        let admission = self.producer_for_actor(actor)?;
        self.store
            .review_result_feed(&admission.producer, cursor, limit)
            .await
    }

    pub async fn cancel_review_request(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        request: ReviewCancelRequest,
        idempotency_key: &str,
    ) -> Result<ReviewCancelResponse, ReviewRuntimeError> {
        request.check().map_err(|_| ReviewRuntimeError::Invalid)?;
        let admission = self.producer_for_actor(actor)?;
        if !admission
            .producer
            .source_namespaces
            .contains(&request.subject.source)
        {
            return Err(ReviewRuntimeError::Forbidden);
        }
        self.store
            .cancel_review(
                &admission.producer,
                actor,
                request_id,
                request,
                idempotency_key,
            )
            .await
    }

    pub async fn claim_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await?;
        self.store
            .claim_review_task(actor, task_id, expected_revision, idempotency_key)
            .await
    }

    pub async fn release_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        self.store
            .release_review_task(actor, task_id, expected_revision, idempotency_key)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn assign_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
        expected_revision: i64,
        request: AssignmentRequest,
        idempotency_key: &str,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await?;
        let membership_kinds = self.review_task_membership_kinds(task_id).await?;
        self.store
            .assign_review_task(
                actor,
                task_id,
                expected_revision,
                &request.assignee,
                request.reason.as_deref(),
                false,
                &membership_kinds,
                idempotency_key,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn delegate_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
        expected_revision: i64,
        request: DelegateRequest,
        idempotency_key: &str,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await?;
        let membership_kinds = self.review_task_membership_kinds(task_id).await?;
        self.store
            .assign_review_task(
                actor,
                task_id,
                expected_revision,
                &request.delegate,
                request.reason.as_deref(),
                true,
                &membership_kinds,
                idempotency_key,
            )
            .await
    }

    pub async fn review_task_draft(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<Option<ReviewTaskDraft>, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await?;
        self.store.review_task_draft(actor, task_id).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn save_review_task_draft(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
        expected_revision: i64,
        input: ReviewTaskDraftInput,
        idempotency_key: &str,
    ) -> Result<ReviewTaskDraft, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        input.check().map_err(ReviewRuntimeError::Validation)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await?;
        self.store
            .save_review_task_draft(
                actor,
                task_id,
                expected_revision,
                input.body,
                idempotency_key,
            )
            .await
    }

    pub async fn delete_review_task_draft(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<(), ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await?;
        self.store
            .delete_review_task_draft(actor, task_id, expected_revision, idempotency_key)
            .await
    }

    pub async fn review_history(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewHistoryPage, ReviewRuntimeError> {
        let requester = if actor.role == CaseworkRole::Requester {
            if source_profile_id.is_some() {
                return Err(ReviewRuntimeError::SourceProfileNotApplicable);
            }
            Some(self.requester_reader(actor)?)
        } else {
            require_human_reviewer(actor)?;
            None
        };
        let history = self
            .store
            .review_history(actor, request_id, requester.as_ref(), cursor, limit)
            .await?;
        if requester.is_none() {
            self.preflight_review_request_source(request_id, source_profile_id, token)
                .await?;
            self.store.recheck_review_access(actor, request_id).await?;
        }
        Ok(history)
    }

    pub async fn review_clocks(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<Vec<ReviewClockOccurrence>, ReviewRuntimeError> {
        let producer = if actor.role == CaseworkRole::Requester {
            if source_profile_id.is_some() {
                return Err(ReviewRuntimeError::SourceProfileNotApplicable);
            }
            Some(self.producer_for_actor(actor)?.producer)
        } else {
            require_human_reviewer(actor)?;
            None
        };
        let clocks = self
            .store
            .review_clocks(actor, request_id, producer.as_ref())
            .await?;
        if producer.is_none() {
            self.preflight_review_request_source(request_id, source_profile_id, token)
                .await?;
            self.store.recheck_review_access(actor, request_id).await?;
        }
        Ok(clocks)
    }

    pub async fn review_accountability(
        &self,
        actor: &ActorContext,
        event_id: Uuid,
    ) -> Result<ReviewAccountabilityRecord, ReviewRuntimeError> {
        if actor.role != CaseworkRole::Supervisor {
            return Err(ReviewRuntimeError::Forbidden);
        }
        self.store.review_accountability(actor, event_id).await
    }

    pub async fn add_review_note(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
        request: ReviewNoteRequest,
        idempotency_key: &str,
    ) -> Result<ReviewHistoryEntry, ReviewRuntimeError> {
        let producer = if actor.role == CaseworkRole::Requester {
            if source_profile_id.is_some() {
                return Err(ReviewRuntimeError::SourceProfileNotApplicable);
            }
            let producer = self.producer_for_actor(actor)?.producer;
            if request.audience != ReviewHistoryAudience::Requester {
                return Err(ReviewRuntimeError::Forbidden);
            }
            Some(producer)
        } else {
            require_human_reviewer(actor)?;
            None
        };
        if producer.is_none() {
            self.preflight_review_request_source(request_id, source_profile_id, token)
                .await?;
        }
        self.store
            .add_review_note(
                actor,
                request_id,
                producer.as_ref(),
                request,
                idempotency_key,
            )
            .await
    }

    async fn review_task_membership_kinds(
        &self,
        task_id: Uuid,
    ) -> Result<Vec<String>, ReviewRuntimeError> {
        self.store.review_task_membership_kinds(task_id).await
    }

    pub async fn reconcile_review_absences(
        &self,
        maximum: usize,
    ) -> Result<usize, ReviewRuntimeError> {
        let candidates = self.store.review_absence_candidates(maximum).await?;
        let mut changed = 0;
        for task_id in candidates {
            let membership_kinds = self.review_task_membership_kinds(task_id).await?;
            changed += self
                .store
                .reconcile_review_task_absence(task_id, &membership_kinds)
                .await?;
        }
        Ok(changed)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn decide_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        request: ReviewTaskDecisionRequest,
        source_profile_id: Option<&str>,
        token: &str,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTransition, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        request
            .decision
            .check_input()
            .map_err(ReviewRuntimeError::Validation)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await?;
        self.store
            .decide_review_task(
                actor,
                task_id,
                request.decision,
                expected_revision,
                idempotency_key,
            )
            .await
    }

    async fn preflight_review_source(
        &self,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<(), ReviewRuntimeError> {
        let record = self.store.review_request_for_task(task_id).await?;
        ensure_review_result_retained(&record)?;
        self.preflight_review_record_source(&record, source_profile_id, token)
            .await
    }

    async fn preflight_review_request_source(
        &self,
        request_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<(), ReviewRuntimeError> {
        let record = self.store.review_request_record(request_id).await?;
        self.preflight_review_record_source(&record, source_profile_id, token)
            .await
    }

    async fn preflight_review_record_source(
        &self,
        record: &ReviewRequestRecord,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<(), ReviewRuntimeError> {
        match &record.policy.context {
            ReviewContextPolicy::Submitted => {
                if source_profile_id.is_some() {
                    Err(ReviewRuntimeError::SourceProfileNotApplicable)
                } else {
                    Ok(())
                }
            }
            ReviewContextPolicy::CurrentSource { provider, contract } => {
                let profile = source_profile_id.ok_or(ReviewRuntimeError::SourceProfileRequired)?;
                let provider = self
                    .providers
                    .get(provider)
                    .ok_or(ReviewRuntimeError::SourceUnavailable)?;
                let identity = ReviewContextIdentity {
                    subject: record.subject.clone(),
                    contract: contract.clone(),
                };
                let deadline = tokio::time::Instant::now()
                    + Duration::from_millis(
                        record.policy.dependencies.inbox.page_deadline_milliseconds,
                    );
                let view = tokio::time::timeout_at(
                    deadline,
                    provider.human_display(HumanDisplayRequest {
                        identity: &identity,
                        source_profile_id: profile,
                        credential: EphemeralCredential::new(token),
                    }),
                )
                .await
                .map_err(|_| ReviewRuntimeError::SourceUnavailable)?
                .map_err(map_review_source_error)?;
                if view.identity != identity || !view.reviewable {
                    return Err(ReviewRuntimeError::NotFound);
                }
                record
                    .policy
                    .validate_display(&serde_json::to_value(&view.fields)?)
                    .map_err(|error| invalid_provider_display(&record.policy, error))?;
                let status = tokio::time::timeout_at(deadline, provider.service_status(&identity))
                    .await
                    .map_err(|_| ReviewRuntimeError::SourceUnavailable)?
                    .map_err(map_review_source_error)?;
                if status.identity != identity || !status.reviewable {
                    return Err(ReviewRuntimeError::NotFound);
                }
                Ok(())
            }
        }
    }

    async fn preflight_review_inbox_source(
        &self,
        record: &ReviewRequestRecord,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<(), ReviewRuntimeError> {
        // The inbox is a unified queue: a supplied source profile declares
        // the caller's source visibility, it does not select a context
        // strategy, so submitted-context candidates are admitted beside
        // source-backed ones. The exact single-task routes keep refusing the
        // mismatched profile.
        if matches!(
            record.policy.context,
            registry_casework_core::ReviewContextPolicy::Submitted
        ) {
            return Ok(());
        }
        self.preflight_review_record_source(record, source_profile_id, token)
            .await
    }

    fn producer_for_create(
        &self,
        actor: &ActorContext,
        request: &ReviewCreateRequest,
    ) -> Result<ProducerAdmission, ReviewRuntimeError> {
        let admission = self.producer_for_actor(actor)?;
        if !admission
            .producer
            .review_policies
            .contains(&request.policy.id)
            || !admission
                .producer
                .source_namespaces
                .contains(&request.subject.source)
            || request.subject.source != request.subject.source.trim()
        {
            return Err(ReviewRuntimeError::Forbidden);
        }
        Ok(admission)
    }

    fn producer_for_actor(
        &self,
        actor: &ActorContext,
    ) -> Result<ProducerAdmission, ReviewRuntimeError> {
        if actor.role != registry_casework_core::CaseworkRole::Requester {
            return Err(ReviewRuntimeError::Forbidden);
        }
        self.project
            .trusted_producers
            .iter()
            .find(|producer| {
                producer.profile == actor.profile_id
                    && producer.issuer == actor.principal.issuer
                    && producer.subject == actor.principal.subject
            })
            .cloned()
            .map(|producer| ProducerAdmission { producer })
            .ok_or(ReviewRuntimeError::Forbidden)
    }

    /// The producer itself, or else a person whose profile some producer
    /// declares as its initiator profile. Which request that person may read
    /// is decided against the stored initiator, not here.
    fn requester_reader(
        &self,
        actor: &ActorContext,
    ) -> Result<RequesterReader, ReviewRuntimeError> {
        match self.producer_for_actor(actor) {
            Ok(admission) => return Ok(RequesterReader::Producer(Box::new(admission.producer))),
            Err(ReviewRuntimeError::Forbidden) => {}
            Err(error) => return Err(error),
        }
        let producers = self
            .project
            .trusted_producers
            .iter()
            .filter(|producer| producer.initiator_profile.as_ref() == Some(&actor.profile_id))
            .map(|producer| producer.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if producers.is_empty() {
            return Err(ReviewRuntimeError::Forbidden);
        }
        Ok(RequesterReader::Initiator(producers))
    }
}

impl PostgresStore {
    async fn review_task_scan_cursor(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        context: &str,
        cursor: Uuid,
    ) -> Result<Option<Uuid>, ReviewRuntimeError> {
        let client = self.client().await?;
        // An existing token never falls back to task-anchor interpretation,
        // including when its caller, query context or expiry no longer matches.
        let row = client
            .query_opt(
                "SELECT last_task_id,
                        issuer=$2 AND subject=$3 AND casework_profile_id=$4
                        AND source_profile_id=$5 AND context=$6 AND expires_at>now()
                 FROM casework_review_cursors WHERE cursor_id=$1",
                &[
                    &cursor,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &actor.profile_id,
                    &source_profile_id.unwrap_or_default(),
                    &context,
                ],
            )
            .await?;
        match row {
            None => Ok(None),
            Some(row) if row.get::<_, bool>(1) => row
                .get::<_, Option<Uuid>>(0)
                .map(Some)
                .ok_or(ReviewRuntimeError::ResultExpired),
            Some(_) => Err(ReviewRuntimeError::ResultExpired),
        }
    }

    async fn issue_review_task_scan_cursor(
        &self,
        actor: &ActorContext,
        source_profile_id: Option<&str>,
        context: &str,
        task_id: Uuid,
    ) -> Result<Uuid, ReviewRuntimeError> {
        let cursor = Uuid::new_v4();
        let client = self.client().await?;
        // Reuse the existing expiring position store and cleanup. Lock only
        // the request, in retention's order, so erasure cannot miss a checkpoint
        // concurrently issued for a task it removes. No source authority is saved.
        let row = client
            .query_opt(
                "INSERT INTO casework_review_cursors(
                     cursor_id,issuer,subject,casework_profile_id,source_profile_id,
                     context,last_task_id,expires_at)
                 SELECT $1,$2,$3,$4,$5,$6,t.task_id,
                        LEAST(now()+interval '15 minutes',r.result_available_until)
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 WHERE t.task_id=$7 AND r.result_erased_at IS NULL
                   AND (r.lifecycle='reviewing' OR r.result_available_until>now())
                 FOR SHARE OF r
                 RETURNING cursor_id",
                &[
                    &cursor,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &actor.profile_id,
                    &source_profile_id.unwrap_or_default(),
                    &context,
                    &task_id,
                ],
            )
            .await?
            .ok_or(ReviewRuntimeError::ResultExpired)?;
        Ok(row.get(0))
    }

    async fn review_task_cursor_position(
        &self,
        actor: &ActorContext,
        queue: Option<&str>,
        view: ReviewTaskListView,
        task_id: Uuid,
    ) -> Result<(DateTime<Utc>, Uuid), ReviewRuntimeError> {
        if queue.is_some_and(str::is_empty) {
            return Err(ReviewRuntimeError::Invalid);
        }
        if view.is_own_decisions() {
            let rows = self
                .own_review_decision_rows(actor, queue, &[task_id])
                .await?;
            let row = rows.first().ok_or(ReviewRuntimeError::ResultExpired)?;
            return Ok((row.decision_receipt.decided_at, task_id));
        }
        let membership = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator | CaseworkRole::Requester => {
                return Err(ReviewRuntimeError::Forbidden)
            }
        };
        // The UUID names an immutable scan position, not a claim about the
        // anchor's current state or holder. Current authorization still applies.
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT t.created_at,t.task_id
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 JOIN casework_queue_service q ON q.queue_id=t.queue_id
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE t.task_id=$1
                   AND r.result_erased_at IS NULL
                   AND (r.lifecycle='reviewing' OR r.result_available_until>now())
                   AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4
                   AND ($5::text IS NULL OR t.queue_id=$5)
                   AND ($7 OR ((r.policy_snapshot->'stages'->t.stage_index->'decidingProfiles') ? $6))
                   AND ($8::uuid IS NULL OR t.request_id=$8)",
                &[
                    &task_id,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                    &queue,
                    &actor.profile_id,
                    &view.is_supervisory(),
                    &view.request_id(),
                ],
            )
            .await?
            .ok_or(ReviewRuntimeError::ResultExpired)?;
        Ok((row.get(0), row.get(1)))
    }

    async fn review_tasks(
        &self,
        actor: &ActorContext,
        queue: Option<&str>,
        view: ReviewTaskListView,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        self.review_tasks_filtered(actor, queue, view, cursor, limit, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn review_tasks_filtered(
        &self,
        actor: &ActorContext,
        queue: Option<&str>,
        view: ReviewTaskListView,
        cursor: Option<Uuid>,
        limit: usize,
        subject: Option<&SubjectBinding>,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        if limit == 0 || limit > 100 || queue.is_some_and(str::is_empty) {
            return Err(ReviewRuntimeError::Invalid);
        }
        if view.is_own_decisions() {
            return self.own_review_tasks(actor, queue, cursor, limit).await;
        }
        let membership = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator | CaseworkRole::Requester => {
                return Err(ReviewRuntimeError::Forbidden)
            }
        };
        let supervisory = view.is_supervisory();
        let ownership = match view.ownership() {
            None => None,
            Some(ReviewTaskOwnership::AssignedToMe) => Some("assigned-to-me"),
            Some(ReviewTaskOwnership::Unclaimed) => Some("unclaimed"),
        };
        let (cursor_created_at, cursor_task_id) = match cursor {
            Some(task_id) => {
                let (created_at, task_id) = self
                    .review_task_cursor_position(actor, queue, view, task_id)
                    .await?;
                (Some(created_at), Some(task_id))
            }
            None => (None, None),
        };
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT t.task_id,t.request_id,t.stage_index,t.stage_id,t.queue_id,t.state,
                        t.holder_issuer,t.holder_subject,t.revision,r.policy_snapshot,
                        r.subject_source,r.subject_type,r.subject_id,r.subject_version,r.subject_digest,r.requester_reference,t.deadline_at,t.created_at,t.staffing_diagnostic
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 JOIN casework_queue_service q ON q.queue_id=t.queue_id
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE r.result_erased_at IS NULL
                   AND (r.lifecycle='reviewing' OR r.result_available_until>now())
                   AND ($9 OR (r.lifecycle='reviewing' AND t.stage_index=r.active_stage_index
                               AND t.state IN ('open','claimed')))
                   AND m.issuer=$1 AND m.subject=$2 AND m.membership_kind=$3
                   AND ($4::text IS NULL OR t.queue_id=$4)
                   AND ($5::timestamptz IS NULL OR (t.created_at,t.task_id)>($5,$6))
                   AND ($9 OR ((r.policy_snapshot->'stages'->t.stage_index->'decidingProfiles') ? $8))
                   AND ($10::text IS NULL
                        OR ($10='unclaimed' AND t.state='open')
                        OR ($10='assigned-to-me' AND t.state='claimed'
                            AND t.holder_issuer=$1 AND t.holder_subject=$2))
                   AND ($11::uuid IS NULL OR t.request_id=$11)
                   AND ($12::text IS NULL OR (r.subject_source=$12 AND r.subject_type=$13
                        AND r.subject_id=$14 AND r.subject_version=$15 AND r.subject_digest=$16))
                 ORDER BY t.created_at,t.task_id LIMIT $7",
                &[
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                    &queue,
                    &cursor_created_at,
                    &cursor_task_id,
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

    async fn own_review_tasks(
        &self,
        actor: &ActorContext,
        queue: Option<&str>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        let membership = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            _ => return Err(ReviewRuntimeError::Forbidden),
        };
        let position = match cursor {
            Some(id) => Some(
                self.review_task_cursor_position(
                    actor,
                    queue,
                    ReviewTaskListView::OwnDecisions,
                    id,
                )
                .await?,
            ),
            None => None,
        };
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT t.task_id,t.request_id,t.stage_index,t.stage_id,t.queue_id,t.state,
                    t.holder_issuer,t.holder_subject,t.revision,r.policy_snapshot,
                        r.subject_source,r.subject_type,r.subject_id,r.subject_version,r.subject_digest,r.requester_reference,t.deadline_at,t.created_at,t.staffing_diagnostic
             FROM casework_review_decisions d
             JOIN casework_review_tasks t ON t.task_id=d.task_id
             JOIN casework_review_requests r ON r.request_id=t.request_id
             WHERE d.actor_issuer=$1 AND d.actor_subject=$2 AND t.state='decided'
               AND r.result_erased_at IS NULL
               AND (r.lifecycle='reviewing' OR r.result_available_until>now())
               AND EXISTS (SELECT 1 FROM casework_queue_service q
                   JOIN casework_memberships m ON m.team_id=q.team_id
                   WHERE q.queue_id=t.queue_id AND m.issuer=$1 AND m.subject=$2
                     AND m.membership_kind=$3)
               AND ($4::text IS NULL OR t.queue_id=$4)
               AND ($5::timestamptz IS NULL OR (d.decided_at,t.task_id)<($5,$6))
               AND ((r.policy_snapshot->'stages'->t.stage_index->'decidingProfiles') ? $8)
             ORDER BY d.decided_at DESC,t.task_id DESC LIMIT $7",
                &[
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                    &queue,
                    &position.map(|p| p.0),
                    &position.map(|p| p.1),
                    &i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?,
                    &actor.profile_id,
                ],
            )
            .await?;
        let mut items = rows
            .into_iter()
            .map(|row| {
                let policy = serde_json::from_value::<ReviewPolicyClosure>(row.get(9))?;
                reviewer_task_from_row(&row, &policy)
            })
            .collect::<Result<Vec<_>, ReviewRuntimeError>>()?;
        let next_cursor = (items.len() > limit).then(|| items[limit - 1].task_id);
        items.truncate(limit);
        Ok(ReviewTaskPage {
            items,
            next_cursor,
            status: PageStatus::Complete,
        })
    }

    async fn own_review_decision_rows(
        &self,
        actor: &ActorContext,
        queue: Option<&str>,
        ids: &[Uuid],
    ) -> Result<Vec<OwnReviewDecision>, ReviewRuntimeError> {
        let membership = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            _ => return Err(ReviewRuntimeError::Forbidden),
        };
        let client = self.client().await?;
        client
            .query(
                "SELECT t.task_id,t.request_id,t.queue_id,r.requester_reference,
                    d.decision,d.outcome,d.decided_at,r.policy_snapshot
             FROM casework_review_decisions d
             JOIN casework_review_tasks t ON t.task_id=d.task_id
             JOIN casework_review_requests r ON r.request_id=t.request_id
             WHERE t.task_id=ANY($1) AND d.actor_issuer=$2 AND d.actor_subject=$3
               AND t.state='decided' AND r.result_erased_at IS NULL
               AND (r.lifecycle='reviewing' OR r.result_available_until>now())
               AND EXISTS (SELECT 1 FROM casework_queue_service q
                   JOIN casework_memberships m ON m.team_id=q.team_id
                   WHERE q.queue_id=t.queue_id AND m.issuer=$2 AND m.subject=$3
                     AND m.membership_kind=$4)
               AND ($5::text IS NULL OR t.queue_id=$5)
               AND ((r.policy_snapshot->'stages'->t.stage_index->'decidingProfiles') ? $6)
             ORDER BY array_position($1::uuid[],t.task_id)",
                &[
                    &ids,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                    &queue,
                    &actor.profile_id,
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                let policy: ReviewPolicyClosure = serde_json::from_value(row.get(7))?;
                Ok(OwnReviewDecision {
                    task_id: row.get(0),
                    request_id: row.get(1),
                    queue: row.get(2),
                    requester_reference: row.get(3),
                    decision_receipt: review_decision_receipt(
                        &policy,
                        &row.get::<_, String>(4),
                        row.get(5),
                        row.get(6),
                    )?,
                })
            })
            .collect()
    }

    async fn supervisory_review_task_rows(
        &self,
        actor: &ActorContext,
        queue: Option<&str>,
        task_ids: &[Uuid],
    ) -> Result<Vec<SupervisoryReviewTask>, ReviewRuntimeError> {
        let client = self.client().await?;
        client
            .query(
                "SELECT t.task_id,t.request_id,t.queue_id,t.revision,t.state,a.event_id,t.staffing_diagnostic
             FROM casework_review_tasks t
             JOIN casework_review_requests r ON r.request_id=t.request_id
             JOIN casework_queue_service q ON q.queue_id=t.queue_id
             JOIN casework_memberships m ON m.team_id=q.team_id
             LEFT JOIN casework_review_accountability a ON a.task_id=t.task_id
                 AND (r.lifecycle='reviewing' OR a.retained_until>now())
             WHERE t.task_id=ANY($1) AND m.issuer=$2 AND m.subject=$3
               AND m.membership_kind='supervisor'
               AND ($4::text IS NULL OR t.queue_id=$4)
               AND r.result_erased_at IS NULL
               AND (r.lifecycle='reviewing' OR r.result_available_until>now())
             ORDER BY array_position($1::uuid[],t.task_id)",
                &[
                    &task_ids,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &queue,
                ],
            )
            .await?
            .into_iter()
            .map(|row| {
                Ok(SupervisoryReviewTask {
                    task_id: row.get(0),
                    request_id: row.get(1),
                    queue: row.get(2),
                    revision: row.get(3),
                    state: match row.get::<_, String>(4).as_str() {
                        "open" => SupervisoryReviewTaskState::Open,
                        "claimed" => SupervisoryReviewTaskState::Held,
                        "decided" | "closed" => SupervisoryReviewTaskState::Decided,
                        _ => return Err(ReviewRuntimeError::Corrupt),
                    },
                    staffing_diagnostic: staffing_diagnostic_from_row(&row)?,
                    accountability_event_id: row.get(5),
                })
            })
            .collect()
    }

    async fn review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        self.review_task_by_activity(actor, task_id, false, false)
            .await
    }

    async fn review_task_by_activity(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        active_only: bool,
        supervisory: bool,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        let membership = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator | CaseworkRole::Requester => {
                return Err(ReviewRuntimeError::Forbidden)
            }
        };
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT t.task_id,t.request_id,t.stage_index,t.stage_id,t.queue_id,t.state,
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
                 WHERE t.task_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4
                   AND (NOT $5 OR (r.lifecycle='reviewing'
                       AND t.stage_index=r.active_stage_index
                       AND t.state IN ('open','claimed')))",
                &[
                    &task_id,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                    &active_only,
                ],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        if row.get::<_, String>(10) != "reviewing"
            && (row.get::<_, Option<DateTime<Utc>>>(12).is_some()
                || row
                    .get::<_, Option<DateTime<Utc>>>(11)
                    .is_none_or(|available_until| available_until <= Utc::now()))
        {
            return Err(ReviewRuntimeError::ResultExpired);
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
            return Err(ReviewRuntimeError::NotFound);
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
        Ok(task)
    }

    async fn review_absence_candidates(
        &self,
        maximum: usize,
    ) -> Result<Vec<Uuid>, ReviewRuntimeError> {
        let client = self.client().await?;
        let maximum = i64::try_from(maximum.min(100)).map_err(|_| ReviewRuntimeError::Invalid)?;
        Ok(client
            .query(
                "SELECT task_id FROM casework_review_tasks
                 WHERE state IN ('open','claimed') AND assignment_owner_issuer IS NOT NULL
                 ORDER BY updated_at,task_id LIMIT $1",
                &[&maximum],
            )
            .await?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }

    async fn reconcile_review_task_absence(
        &self,
        task_id: Uuid,
        membership_kinds: &[String],
    ) -> Result<usize, ReviewRuntimeError> {
        let now = Utc::now();
        let mut audit = self.begin_background_audit().await?;
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
        let row = transaction
            .query_one(
                "SELECT stage_index,queue_id,state,holder_issuer,holder_subject,
                        assignment_owner_issuer,assignment_owner_subject,assignment_kind,revision
                 FROM casework_review_tasks WHERE task_id=$1 FOR UPDATE",
                &[&task_id],
            )
            .await?;
        let stage_index =
            u16::try_from(row.get::<_, i32>(0)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        if record.lifecycle != ReviewRequestLifecycle::Reviewing
            || record.active_stage != Some(stage_index)
        {
            audit.commit(transaction).await?;
            return Ok(0);
        }
        let owner = match (
            row.get::<_, Option<String>>(5),
            row.get::<_, Option<String>>(6),
        ) {
            (Some(issuer), Some(subject)) => IssuerPrincipal { issuer, subject },
            (None, None) => {
                audit.commit(transaction).await?;
                return Ok(0);
            }
            _ => return Err(ReviewRuntimeError::Corrupt),
        };
        let current = match (
            row.get::<_, Option<String>>(3),
            row.get::<_, Option<String>>(4),
        ) {
            (Some(issuer), Some(subject)) => Some(IssuerPrincipal { issuer, subject }),
            (None, None) => None,
            _ => return Err(ReviewRuntimeError::Corrupt),
        };
        let absences = active_review_absences(&transaction, &owner, now).await?;
        let cover = resolve_absence_cover(&owner, now, &absences)
            .map_err(|_| ReviewRuntimeError::Corrupt)?;
        let stage = record
            .policy
            .stages
            .get(usize::from(stage_index))
            .ok_or(ReviewRuntimeError::Corrupt)?;
        let eligible = ensure_review_identity_eligible(
            &transaction,
            &record,
            stage,
            stage_index,
            &cover.person,
            &row.get::<_, String>(1),
            membership_kinds,
        )
        .await
        .is_ok();
        let desired = eligible.then_some(cover.person);
        let assignment_kind = if cover.absence_ids.is_empty() {
            match row.get::<_, Option<String>>(7).as_deref() {
                Some("claim") => "claim",
                Some("delegation") => "delegation",
                _ => "nomination",
            }
        } else {
            "absence-cover"
        };
        if current == desired
            && row.get::<_, String>(2) == if eligible { "claimed" } else { "open" }
        {
            transaction
                .execute(
                    "UPDATE casework_review_tasks SET updated_at=$2 WHERE task_id=$1",
                    &[&task_id, &now],
                )
                .await?;
            audit.commit(transaction).await?;
            return Ok(0);
        }
        transaction
            .execute(
                "UPDATE casework_review_tasks SET state=$2,holder_issuer=$3,holder_subject=$4,
                    assignment_kind=$5,assignment_absence_ids=$6,staffing_diagnostic=$7,
                    revision=revision+1,updated_at=$8 WHERE task_id=$1",
                &[
                    &task_id,
                    &if eligible { "claimed" } else { "open" },
                    &desired.as_ref().map(|person| &person.issuer),
                    &desired.as_ref().map(|person| &person.subject),
                    &eligible.then_some(assignment_kind),
                    &cover.absence_ids,
                    &(!eligible).then_some("no-cover-available"),
                    &now,
                ],
            )
            .await
            .map_err(map_reviewer_conflict)?;
        let event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,'task-absence-reconciled',NULL,$4,$5)",
                &[
                    &event_id,
                    &request_id,
                    &task_id,
                    &json!({
                        "assignmentKind": assignment_kind,
                        "staffingBlocked": !eligible,
                        "absenceCount": cover.absence_ids.len(),
                    }),
                    &now,
                ],
            )
            .await?;
        audit.record(event_id, crate::audit::request_record(
            "task-absence-reconciled", None, "system:absences",
            json!({"reviewRequestId":request_id,"reviewTaskId":task_id,"taskRevision":row.get::<_,i64>(8)+1}),
        ))?;
        audit.commit(transaction).await?;
        Ok(1)
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn lease_review_completions_for_test(
        &self,
        limit: usize,
        lease_until: DateTime<Utc>,
    ) -> Result<Vec<registry_casework_core::ReviewCompletion>, ReviewRuntimeError> {
        Ok(self
            .lease_review_completions(limit, lease_until)
            .await?
            .into_iter()
            .map(|delivery| delivery.event)
            .collect())
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn finish_review_completion_for_test(
        &self,
        event_id: Uuid,
        delivered: bool,
        maximum_attempts: u32,
        retry_at: DateTime<Utc>,
    ) -> Result<(), ReviewRuntimeError> {
        self.finish_review_completion(event_id, delivered, maximum_attempts, retry_at)
            .await
    }

    #[cfg(feature = "postgres-test")]
    pub(crate) async fn lease_review_completions(
        &self,
        limit: usize,
        lease_until: DateTime<Utc>,
    ) -> Result<Vec<LeasedReviewCompletion>, ReviewRuntimeError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let rows = transaction
            .query(
                "WITH due AS (
                    SELECT event_id FROM casework_review_completion_outbox
                    WHERE retained_until>now() AND next_attempt_at<=now()
                      AND (state='pending' OR (state='leased' AND lease_until<=now()))
                    ORDER BY next_attempt_at,event_id LIMIT $1 FOR UPDATE SKIP LOCKED
                 ), leased AS (
                    UPDATE casework_review_completion_outbox o
                    SET state='leased',lease_until=$2,attempt_count=attempt_count+1
                    FROM due WHERE o.event_id=due.event_id
                    RETURNING o.event_id,o.destination_id,o.recipient_binding,o.attempt_count
                 )
                 SELECT l.event_id,e.request_id,e.result_id,e.completed_at,
                        l.destination_id,l.recipient_binding
                 FROM leased l JOIN casework_review_terminal_events e ON e.event_id=l.event_id",
                &[
                    &i64::try_from(limit.min(100)).map_err(|_| ReviewRuntimeError::Invalid)?,
                    &lease_until,
                ],
            )
            .await?;
        transaction.commit().await?;
        rows.into_iter()
            .map(|row| {
                Ok(LeasedReviewCompletion {
                    event: registry_casework_core::ReviewCompletion {
                        event_type: registry_casework_core::ReviewCompletionType::ReviewCompleted,
                        event_id: row.get(0),
                        request_id: row.get(1),
                        result_id: row.get(2),
                        completed_at: row.get(3),
                    },
                    destination_id: row.get(4),
                    recipient_binding: row.get(5),
                })
            })
            .collect()
    }

    #[cfg(feature = "postgres-test")]
    pub(crate) async fn finish_review_completion(
        &self,
        event_id: Uuid,
        delivered: bool,
        maximum_attempts: u32,
        retry_at: DateTime<Utc>,
    ) -> Result<(), ReviewRuntimeError> {
        let client = self.client().await?;
        if delivered {
            client
                .execute(
                    "UPDATE casework_review_completion_outbox
                     SET state='delivered',delivered_at=now(),lease_until=NULL,last_failure_class=NULL
                     WHERE event_id=$1 AND state='leased'",
                    &[&event_id],
                )
                .await?;
        } else {
            client
                .execute(
                    "UPDATE casework_review_completion_outbox
                     SET state=CASE WHEN attempt_count >= $2 OR $3>=retained_until
                                    THEN 'exhausted' ELSE 'pending' END,
                         next_attempt_at=LEAST($3,retained_until - interval '1 microsecond'),
                         lease_until=NULL,last_failure_class='delivery_failed'
                     WHERE event_id=$1 AND state='leased'",
                    &[
                        &event_id,
                        &i32::try_from(maximum_attempts)
                            .map_err(|_| ReviewRuntimeError::Invalid)?,
                        &retry_at,
                    ],
                )
                .await?;
        }
        Ok(())
    }

    async fn review_request_for_task(
        &self,
        task_id: Uuid,
    ) -> Result<ReviewRequestRecord, ReviewRuntimeError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                &request_query(
                    "request_id=(SELECT request_id FROM casework_review_tasks WHERE task_id=$1)",
                ),
                &[&task_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        request_from_row(&row)
    }

    async fn review_request_record(
        &self,
        request_id: Uuid,
    ) -> Result<ReviewRequestRecord, ReviewRuntimeError> {
        let client = self.client().await?;
        load_request_by_id(&client, request_id, false).await
    }

    async fn review_task_membership_kinds(
        &self,
        task_id: Uuid,
    ) -> Result<Vec<String>, ReviewRuntimeError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT t.stage_index,r.policy_snapshot
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 WHERE t.task_id=$1",
                &[&task_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        let stage_index =
            usize::try_from(row.get::<_, i32>(0)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        let policy: ReviewPolicyClosure = serde_json::from_value(row.get(1))?;
        let stage = policy
            .stages
            .get(stage_index)
            .ok_or(ReviewRuntimeError::Corrupt)?;
        let kinds = policy
            .dependencies
            .access_profiles
            .iter()
            .filter(|profile| stage.deciding_profiles.contains(&profile.id))
            .filter_map(|profile| match profile.role {
                CaseworkRole::Staff => Some("staff".to_owned()),
                CaseworkRole::Supervisor => Some("supervisor".to_owned()),
                CaseworkRole::Administrator | CaseworkRole::Requester => None,
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if kinds.is_empty() {
            return Err(ReviewRuntimeError::Corrupt);
        }
        Ok(kinds)
    }

    #[allow(clippy::too_many_arguments)]
    async fn recover_review(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        actor: &ActorContext,
        request: &ReviewCreateRequest,
        digest: &ContentDigest,
        idempotency_key: &str,
        mut audit: crate::audit::AuditOperation,
    ) -> Result<ReviewRecovery, ReviewRuntimeError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let resource = format!("review-producer:{}", producer.id);
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.create",
            &resource,
            idempotency_key,
            digest.as_str(),
        )
        .await?
        {
            let accepted = serde_json::from_value(response)?;
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return Ok(ReviewRecovery::Recovered(Box::new(ReviewCreateOutcome {
                accepted,
                recovered: true,
            })));
        }
        let binding_digest = review_submission_binding_digest(&producer.id, request);
        let reservation = transaction
            .query_opt(
                "SELECT submission_digest,request_id,recovery_deadline
                 FROM casework_review_submission_reservations
                 WHERE binding_digest=$1",
                &[&binding_digest],
            )
            .await?;
        let Some(reservation) = reservation else {
            transaction.commit().await?;
            return Ok(ReviewRecovery::Fresh(Box::new(audit)));
        };
        if reservation.get::<_, String>(0) != digest.as_str() {
            return Err(ReviewRuntimeError::SubmissionConflict);
        }
        if reservation.get::<_, DateTime<Utc>>(2) <= Utc::now() {
            return Err(ReviewRuntimeError::ResultExpired);
        }
        let Some(request_id) = reservation.get::<_, Option<Uuid>>(1) else {
            transaction.commit().await?;
            return Ok(ReviewRecovery::Fresh(Box::new(audit)));
        };
        let record = load_request(&transaction, producer, request_id, true).await?;
        if record
            .result_available_until
            .is_some_and(|available_until| available_until <= Utc::now())
        {
            return Err(ReviewRuntimeError::ResultExpired);
        }
        let accepted = accepted(&record);
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.create",
            &resource,
            idempotency_key,
            digest.as_str(),
            &serde_json::to_value(&accepted)?,
        )
        .await?;
        audit.record_outcome(crate::audit::AuditOutcome::Replayed);
        audit.commit(transaction).await?;
        Ok(ReviewRecovery::Recovered(Box::new(ReviewCreateOutcome {
            accepted,
            recovered: true,
        })))
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_review(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        actor: &ActorContext,
        request: ReviewCreateRequest,
        project: &CaseworkProject,
        digest: ContentDigest,
        idempotency_key: &str,
        mut audit: crate::audit::AuditOperation,
    ) -> Result<ReviewCreateOutcome, ReviewRuntimeError> {
        let now = Utc::now();
        let recovery_deadline = now + TimeDelta::days(i64::from(producer.recovery_days));
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let resource = format!("review-producer:{}", producer.id);
        let binding_digest = review_submission_binding_digest(&producer.id, &request);
        let subject_lock = format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            producer.id,
            request.subject.source,
            request.subject.subject_type,
            request.subject.id,
            request.policy.id
        );
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&subject_lock],
            )
            .await?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.create",
            &resource,
            idempotency_key,
            digest.as_str(),
        )
        .await?
        {
            let accepted = serde_json::from_value(response)?;
            audit.record_outcome(crate::audit::AuditOutcome::Replayed);
            audit.commit(transaction).await?;
            return Ok(ReviewCreateOutcome {
                accepted,
                recovered: true,
            });
        }
        let reservation = transaction
            .query_opt(
                "SELECT submission_digest,request_id,recovery_deadline
                 FROM casework_review_submission_reservations
                 WHERE binding_digest=$1
                 FOR UPDATE",
                &[&binding_digest],
            )
            .await?;
        if let Some(reservation) = reservation {
            let retained_digest: String = reservation.get(0);
            if retained_digest != digest.as_str() {
                return Err(ReviewRuntimeError::SubmissionConflict);
            }
            if reservation.get::<_, DateTime<Utc>>(2) <= now {
                return Err(ReviewRuntimeError::ResultExpired);
            }
            if let Some(request_id) = reservation.get::<_, Option<Uuid>>(1) {
                let record = load_request(&transaction, producer, request_id, true).await?;
                if record
                    .result_available_until
                    .is_some_and(|available_until| available_until <= now)
                {
                    return Err(ReviewRuntimeError::ResultExpired);
                }
                let accepted = accepted(&record);
                insert_review_idempotency(
                    &transaction,
                    request_id,
                    actor,
                    "review.create",
                    &resource,
                    idempotency_key,
                    digest.as_str(),
                    &serde_json::to_value(&accepted)?,
                )
                .await?;
                audit.record_outcome(crate::audit::AuditOutcome::Replayed);
                audit.commit(transaction).await?;
                return Ok(ReviewCreateOutcome {
                    accepted,
                    recovered: true,
                });
            }

            // A reservation is committed only together with its accepted request.
            return Err(ReviewRuntimeError::Corrupt);
        }
        // Resolve only fresh submissions while holding the subject lock. The
        // concrete policy and response are committed with the original selector digest.
        let policy = project
            .review_policies
            .iter()
            .find(|policy| policy.id == request.policy.id)
            .ok_or(ReviewRuntimeError::Forbidden)?;
        let snapshot = project
            .compile_policy(&policy.id)
            .map_err(|_| ReviewRuntimeError::Corrupt)?;
        if !request.policy.matches(&policy_binding(&snapshot)) {
            return Err(ReviewRuntimeError::PolicyMismatch);
        }
        let requires_initiator = snapshot.stages.iter().any(|stage| stage.exclude_initiator);
        // A producer with no trusted initiator issuer submits only kinds that
        // exclude nobody, so an initiator it names is not recorded: storing it
        // would let that unverified person read the request's history.
        let initiator = match (
            request.initiator.as_ref(),
            producer.trusted_initiator_issuer.as_deref(),
        ) {
            (Some(initiator), Some(issuer)) if initiator.issuer == issuer => Some(initiator),
            (Some(_), None) if !requires_initiator => None,
            (None, _) if requires_initiator => return Err(ReviewRuntimeError::InitiatorRequired),
            (None, _) => None,
            _ => return Err(ReviewRuntimeError::Invalid),
        };
        match (&snapshot.context, &request.context) {
            (
                registry_casework_core::ReviewContextPolicy::Submitted,
                registry_casework_core::ReviewContext::Submitted { snapshot: display },
            ) => snapshot
                .validate_display(display)
                .map_err(review_validation_error)?,
            (
                registry_casework_core::ReviewContextPolicy::CurrentSource { .. },
                registry_casework_core::ReviewContext::CurrentSource { .. },
            ) => {
                let provider = snapshot
                    .dependencies
                    .context_provider
                    .as_ref()
                    .ok_or(ReviewRuntimeError::Corrupt)?;
                if request.subject.source != provider.source_namespace {
                    return Err(ReviewRuntimeError::Forbidden);
                }
            }
            _ => return Err(ReviewRuntimeError::Invalid),
        }
        if let Some(constraints) = &request.result_constraints {
            snapshot
                .validate_result_constraints(constraints)
                .map_err(review_validation_error)?;
        }
        let initiator = initiator.map(|person| IssuerPrincipal {
            issuer: person.issuer.clone(),
            subject: person.subject.clone(),
        });
        let clocks = snapshot
            .clocks
            .iter()
            .map(|clock_id| {
                let clock = snapshot
                    .dependencies
                    .clocks
                    .iter()
                    .find(|clock| clock.id() == clock_id)
                    .cloned()
                    .ok_or(ReviewRuntimeError::Corrupt)?;
                let calendar = match &clock {
                    ClockPolicy::Subject { .. } => None,
                    ClockPolicy::Activity { calendar, .. } => Some(
                        snapshot
                            .dependencies
                            .calendars
                            .iter()
                            .find(|candidate| candidate.id == *calendar)
                            .cloned()
                            .ok_or(ReviewRuntimeError::Corrupt)?,
                    ),
                };
                Ok::<_, ReviewRuntimeError>((clock, calendar))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let policy = snapshot;
        let retained_until = now
            + TimeDelta::days(i64::from(
                producer
                    .recovery_days
                    .max(policy.retention.accountability_days),
            ));
        transaction
            .execute(
                "INSERT INTO casework_review_submission_reservations(
                    binding_digest,producer_id,source_namespace,subject_source,subject_type,subject_id,
                    subject_version,policy_id,submission_digest,request_id,recovery_deadline,
                    retained_until,created_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10,$11,$12)",
                &[
                    &binding_digest,
                    &producer.id,
                    &request.subject.source,
                    &request.subject.source,
                    &request.subject.subject_type,
                    &request.subject.id,
                    &request.subject.version,
                    &request.policy.id,
                    &digest.as_str(),
                    &recovery_deadline,
                    &retained_until,
                    &now,
                ],
            )
            .await?;
        let superseded = transaction
            .query(
                "SELECT request_id FROM casework_review_requests
                 WHERE producer_id=$1 AND producer_issuer=$2 AND producer_subject=$3
                   AND subject_source=$4 AND subject_type=$5
                   AND subject_id=$6 AND policy_id=$7 AND lifecycle='reviewing'
                 ORDER BY request_id FOR UPDATE",
                &[
                    &producer.id,
                    &producer.issuer,
                    &producer.subject,
                    &request.subject.source,
                    &request.subject.subject_type,
                    &request.subject.id,
                    &request.policy.id,
                ],
            )
            .await?;
        for row in superseded {
            let prior_id: Uuid = row.get(0);
            let prior = load_request(&transaction, producer, prior_id, true).await?;
            settle_review(
                &transaction,
                &prior,
                ReviewResultStatus::Superseded,
                None,
                None,
                None,
                now,
            )
            .await?;
            transaction
                .execute(
                    "INSERT INTO casework_review_history(
                        event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                     VALUES($1,$2,NULL,'review-superseded',NULL,'{}'::jsonb,$3)",
                    &[&Uuid::new_v4(), &prior_id, &now],
                )
                .await?;
        }

        let request_id = Uuid::new_v4();
        let policy_json = serde_json::to_value(&policy)?;
        let (context_strategy, context) = match &request.context {
            registry_casework_core::ReviewContext::Submitted { snapshot } => {
                ("submitted", snapshot.clone())
            }
            registry_casework_core::ReviewContext::CurrentSource { binding } => (
                "current-source",
                serde_json::to_value(binding).map_err(|_| ReviewRuntimeError::Invalid)?,
            ),
        };
        let initiator_issuer = initiator.as_ref().map(|person| person.issuer.as_str());
        let initiator_subject = initiator.as_ref().map(|person| person.subject.as_str());
        let completion_destination = producer
            .completion
            .as_ref()
            .map(|completion| completion.destination_id.as_str());
        let completion_recipient_binding = producer
            .completion
            .as_ref()
            .map(|completion| completion.recipient_binding.as_str());
        transaction
            .execute(
                "INSERT INTO casework_review_requests(
                    request_id,producer_id,producer_issuer,producer_subject,source_namespace,
                    subject_source,subject_type,subject_id,subject_version,subject_digest,
                    requester_reference,initiator_issuer,initiator_subject,context_strategy,
                    context,result_constraints,
                    policy_id,policy_version,policy_digest,policy_snapshot,submission_digest,
                    completion_destination,completion_recipient_binding,lifecycle,
                    active_stage_index,revision,created_at,updated_at,terminal_at,
                    result_available_until,accountability_retained_until)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                        $19,$20,$21,$22,$23,'reviewing',0,1,$24,$24,NULL,NULL,NULL)",
                &[
                    &request_id,
                    &producer.id,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &request.subject.source,
                    &request.subject.source,
                    &request.subject.subject_type,
                    &request.subject.id,
                    &request.subject.version,
                    &request.subject.digest.as_str(),
                    &request.requester_reference,
                    &initiator_issuer,
                    &initiator_subject,
                    &context_strategy,
                    &context,
                    &request.result_constraints,
                    &policy.identity.id,
                    &policy.identity.version,
                    &policy.identity.digest.as_str(),
                    &policy_json,
                    &digest.as_str(),
                    &completion_destination,
                    &completion_recipient_binding,
                    &now,
                ],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_review_submission_reservations SET request_id=$1
                 WHERE binding_digest=$2",
                &[&request_id, &binding_digest],
            )
            .await?;
        let tasks =
            insert_stage_tasks(&transaction, &self.providers, request_id, &policy, 0, now).await?;
        insert_initial_review_clocks(
            &transaction,
            request_id,
            &request.subject,
            &policy.identity.id,
            &clocks,
            &tasks,
            now,
        )
        .await?;
        let completion = producer.completion.as_ref().map(|completion| {
            json!({
                "destinationId": completion.destination_id,
                "recipientBinding": completion.recipient_binding,
            })
        });
        transaction
            .execute(
                "INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES
                    ($1,$2,NULL,'review-created',NULL,$3,$5),
                    ($4,$2,NULL,'request-created',NULL,'{}'::jsonb,$5)",
                &[
                    &Uuid::new_v4(),
                    &request_id,
                    &json!({"completion": completion}),
                    &Uuid::new_v4(),
                    &now,
                ],
            )
            .await?;
        let accepted = ReviewRequestAccepted {
            request_id,
            subject: request.subject.clone(),
            policy: policy_binding(&policy),
            submission_digest: digest.clone(),
        };
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.create",
            &resource,
            idempotency_key,
            digest.as_str(),
            &serde_json::to_value(&accepted)?,
        )
        .await?;
        // Collect only event identities from this transaction, including any
        // superseded request. Source context and private history stay in storage.
        for event in transaction
            .query(
                "SELECT event_id,request_id,task_id,kind FROM casework_review_history
             WHERE xmin=pg_current_xact_id()::xid ORDER BY event_id",
                &[],
            )
            .await?
        {
            let event_id: Uuid = event.get(0);
            let mut identifiers = json!({"reviewRequestId":event.get::<_,Uuid>(1)});
            if let Some(task_id) = event.get::<_, Option<Uuid>>(2) {
                identifiers["reviewTaskId"] = json!(task_id);
            }
            audit.record(
                event_id,
                crate::audit::request_record(
                    &event.get::<_, String>(3),
                    Some(actor),
                    &actor.profile_id,
                    identifiers,
                ),
            )?;
        }
        audit.commit(transaction).await?;
        Ok(ReviewCreateOutcome {
            accepted,
            recovered: false,
        })
    }

    async fn review_request(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        request_id: Uuid,
    ) -> Result<ReviewRequestView, ReviewRuntimeError> {
        let client = self.client().await?;
        let record = load_request_client(&client, producer, request_id).await?;
        ensure_review_result_retained(&record)?;
        Ok(request_view(&record))
    }

    async fn recheck_review_access(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
    ) -> Result<(), ReviewRuntimeError> {
        let client = self.client().await?;
        let record = load_request_by_id(&client, request_id, false).await?;
        ensure_review_result_retained(&record)?;
        ensure_review_reviewer_access(&client, &record, actor, None, false).await
    }

    async fn review_result(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        request_id: Uuid,
    ) -> Result<ReviewResultRead, ReviewRuntimeError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let record = load_request(&transaction, producer, request_id, true).await?;
        if record.lifecycle == ReviewRequestLifecycle::Reviewing {
            transaction.commit().await?;
            return Ok(ReviewResultRead::Pending);
        }
        if ensure_review_result_retained(&record).is_err() {
            transaction.commit().await?;
            return Ok(ReviewResultRead::Expired);
        }
        let result = load_result(&transaction, &record).await?;
        transaction.commit().await?;
        Ok(ReviewResultRead::Available(Box::new(result)))
    }

    async fn review_result_feed(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewResultFeedPage, ReviewRuntimeError> {
        let client = self.client().await?;
        let position = if let Some(cursor) = cursor {
            Some(
                client
                    .query_opt(
                        "SELECT e.feed_position FROM casework_review_terminal_events e
                         JOIN casework_review_requests r USING(request_id)
                         WHERE e.producer_id=$1 AND r.producer_issuer=$2
                           AND r.producer_subject=$3 AND e.event_id=$4
                           AND e.retained_until>now()",
                        &[&producer.id, &producer.issuer, &producer.subject, &cursor],
                    )
                    .await?
                    .ok_or(ReviewRuntimeError::ResultExpired)?,
            )
        } else {
            None
        };
        let rows = if let Some(position) = position {
            client
                .query(
                    "SELECT e.event_id,e.request_id,e.result_id,e.completed_at
                     FROM casework_review_terminal_events e
                     JOIN casework_review_requests r USING(request_id)
                     WHERE e.producer_id=$1 AND r.producer_issuer=$2
                       AND r.producer_subject=$3 AND e.retained_until>now()
                       AND e.feed_position>$4
                     ORDER BY e.feed_position LIMIT $5",
                    &[
                        &producer.id,
                        &producer.issuer,
                        &producer.subject,
                        &position.get::<_, i64>(0),
                        &i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?,
                    ],
                )
                .await?
        } else {
            client
                .query(
                    "SELECT e.event_id,e.request_id,e.result_id,e.completed_at
                     FROM casework_review_terminal_events e
                     JOIN casework_review_requests r USING(request_id)
                     WHERE e.producer_id=$1 AND r.producer_issuer=$2
                       AND r.producer_subject=$3 AND e.retained_until>now()
                     ORDER BY e.feed_position LIMIT $4",
                    &[
                        &producer.id,
                        &producer.issuer,
                        &producer.subject,
                        &i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?,
                    ],
                )
                .await?
        };
        let next_cursor = (rows.len() > limit).then(|| rows[limit - 1].get::<_, Uuid>(0));
        let items = rows
            .into_iter()
            .take(limit)
            .map(|row| ReviewResultFeedEntry {
                event_id: row.get(0),
                request_id: row.get(1),
                result_id: row.get(2),
                completed_at: row.get(3),
            })
            .collect();
        Ok(ReviewResultFeedPage { items, next_cursor })
    }

    async fn cancel_review(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        actor: &ActorContext,
        request_id: Uuid,
        request: ReviewCancelRequest,
        idempotency_key: &str,
    ) -> Result<ReviewCancelResponse, ReviewRuntimeError> {
        let now = Utc::now();
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "review-cancelled",
                Some(actor),
                &actor.profile_id,
                json!({}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let record = load_request(&transaction, producer, request_id, true).await?;
        let resource = format!("review-request:{request_id}");
        let request_hash = review_request_hash(&request)?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.cancel",
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
        if record.subject != request.subject {
            return Err(ReviewRuntimeError::NotFound);
        }
        if record.lifecycle != ReviewRequestLifecycle::Reviewing {
            if record
                .result_available_until
                .is_none_or(|available_until| available_until <= now)
            {
                return Err(ReviewRuntimeError::ResultExpired);
            }
            let result = load_result(&transaction, &record).await?;
            let response = ReviewCancelResponse::AlreadyTerminal { result };
            insert_review_idempotency(
                &transaction,
                request_id,
                actor,
                "review.cancel",
                &resource,
                idempotency_key,
                &request_hash,
                &serde_json::to_value(&response)?,
            )
            .await?;
            audit.record_outcome(crate::audit::AuditOutcome::Unchanged);
            audit.commit(transaction).await?;
            return Ok(response);
        }
        let result = settle_review(
            &transaction,
            &record,
            ReviewResultStatus::Cancelled,
            None,
            None,
            None,
            now,
        )
        .await?;
        let cancel_event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,NULL,'review-cancelled',NULL,$3,$4)",
                &[
                    &cancel_event_id,
                    &request_id,
                    &json!({"reason": request.reason}),
                    &now,
                ],
            )
            .await?;
        // The cancellation is audited like every other mutation once the
        // transaction commits. The record stays minimal: the private reason
        // never leaves the review history row.
        audit.record(
            cancel_event_id,
            json!({
                "event": "casework.review-cancelled",
                "eventId": cancel_event_id,
                "reviewRequestId": request_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
                "resultId": result.result_id,
            }),
        )?;
        let response = ReviewCancelResponse::Cancelled { result };
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.cancel",
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&response)?,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(response)
    }

    async fn claim_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        let now = Utc::now();
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "task-claimed",
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
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(expected_revision, "claim"))?;
        ensure_review_mutation_actor_authorized(&transaction, &record, actor, task_id).await?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.task.claim",
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
        if record.lifecycle != ReviewRequestLifecycle::Reviewing {
            return Err(ReviewRuntimeError::NotFound);
        }
        let row = transaction
            .query_opt(
                "SELECT stage_index,stage_id,queue_id,state,holder_issuer,holder_subject,revision
                 FROM casework_review_tasks WHERE task_id=$1 AND request_id=$2 FOR UPDATE",
                &[&task_id, &request_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        let revision = row.get::<_, i64>(6);
        if revision != expected_revision {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        let stage_index =
            u16::try_from(row.get::<_, i32>(0)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        if record.active_stage != Some(stage_index) {
            return Err(ReviewRuntimeError::NotFound);
        }
        let stage = record
            .policy
            .stages
            .get(usize::from(stage_index))
            .ok_or(ReviewRuntimeError::Corrupt)?;
        if !stage.deciding_profiles.contains(&actor.profile_id) {
            return Err(ReviewRuntimeError::Forbidden);
        }
        ensure_actor_serves_review_queue(&transaction, actor, &row.get::<_, String>(2)).await?;
        if stage.exclude_initiator && record.initiator.as_ref() == Some(&actor.principal) {
            return Err(ReviewRuntimeError::InitiatorExcluded);
        }
        if transaction
            .query_opt(
                "SELECT 1 FROM casework_review_decisions
                 WHERE request_id=$1 AND actor_issuer=$2 AND actor_subject=$3
                   AND (stage_index=$4 OR ($5 AND stage_index<$4)) LIMIT 1",
                &[
                    &request_id,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &i32::from(stage_index),
                    &stage.exclude_previous_stage_reviewers,
                ],
            )
            .await?
            .is_some()
        {
            return Err(ReviewRuntimeError::Forbidden);
        }
        if !active_review_absences(&transaction, &actor.principal, now)
            .await?
            .is_empty()
        {
            return Err(ReviewRuntimeError::Forbidden);
        }
        let state: String = row.get(3);
        let held_by_caller = state == "claimed"
            && row.get::<_, Option<String>>(4).as_deref() == Some(actor.principal.issuer.as_str())
            && row.get::<_, Option<String>>(5).as_deref() == Some(actor.principal.subject.as_str());
        if state == "open" || held_by_caller {
            // A retried claim by the current holder under a fresh idempotency
            // key (a client that lost its first response) is still a real
            // transition: every successful claim advances the revision by
            // exactly one, the invariant the maintained client enforces on
            // the response. The claimant becomes the assignment owner, so any
            // assigner recorded by an earlier nomination is cleared rather
            // than left attributing the self-claim to a supervisor.
            transaction
                .execute(
                    "UPDATE casework_review_tasks
                     SET state='claimed',holder_issuer=$2,holder_subject=$3,
                         assignment_kind='claim',assignment_owner_issuer=$2,
                         assignment_owner_subject=$3,assigned_by_issuer=NULL,
                         assigned_by_subject=NULL,assignment_absence_ids='{}',
                         staffing_diagnostic=NULL,revision=revision+1,updated_at=$4
                     WHERE task_id=$1",
                    &[
                        &task_id,
                        &actor.principal.issuer,
                        &actor.principal.subject,
                        &now,
                    ],
                )
                .await
                .map_err(map_reviewer_conflict)?;
        } else if state == "claimed" {
            return Err(ReviewRuntimeError::TaskNotHeld);
        } else {
            return Err(ReviewRuntimeError::NotFound);
        }
        let metadata = transaction
            .query_one(
                "SELECT deadline_at,created_at,staffing_diagnostic,state FROM casework_review_tasks WHERE task_id=$1",
                &[&task_id],
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
            revision: revision + 1,
            eligible_profiles: stage.deciding_profiles.clone(),
            state: ReviewTaskState::Held {
                holder: actor.principal.clone(),
            },
            staffing_diagnostic: staffing_diagnostic_from_row(&metadata)?,
            decided_by_caller: None,
            decision_receipt: None,
        };
        let claim_event_id = Uuid::new_v4();
        {
            let actor_ref = actor_reference(&actor.principal);
            transaction
                .execute(
                    "INSERT INTO casework_review_history(
                        event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                     VALUES($1,$2,$3,'task-claimed',$4,$5,$6)",
                    &[
                        &claim_event_id,
                        &request_id,
                        &task_id,
                        &actor_ref,
                        &json!({
                            "assignmentKind": "claim",
                            "targetRef": &actor_ref,
                            "staffingBlocked": false,
                        }),
                        &now,
                    ],
                )
                .await?;
        }
        // The claim is audited like every other mutation once the transaction
        // commits. The record stays minimal: review history is erased at result
        // expiry, so only who took responsibility survives in the audit
        // journal.
        audit.record(
            claim_event_id,
            json!({
                "event": "casework.task-claimed",
                "eventId": claim_event_id,
                "reviewRequestId": request_id,
                "reviewTaskId": task_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
            }),
        )?;
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.task.claim",
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&task)?,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(task)
    }

    #[allow(clippy::too_many_arguments)]
    async fn assign_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        expected_revision: i64,
        target: &IssuerPrincipal,
        reason: Option<&str>,
        delegate: bool,
        membership_kinds: &[String],
        idempotency_key: &str,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        if reason.is_some_and(|value| {
            value.is_empty() || value.len() > 2_000 || value.chars().any(char::is_control)
        }) {
            return Err(ReviewRuntimeError::Invalid);
        }
        let now = Utc::now();
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                if delegate {
                    "task-delegated"
                } else {
                    "task-assigned"
                },
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
        let task_queue = transaction
            .query_opt(
                "SELECT queue_id FROM casework_review_tasks
                 WHERE task_id=$1 AND request_id=$2",
                &[&task_id, &request_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?
            .get::<_, String>(0);
        let operation = if delegate {
            "review.task.delegate"
        } else {
            "review.task.assign"
        };
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(
            expected_revision,
            target,
            reason,
            delegate,
            membership_kinds,
        ))?;
        if delegate {
            ensure_review_mutation_actor_authorized(&transaction, &record, actor, task_id).await?;
        } else {
            if actor.role != CaseworkRole::Supervisor {
                return Err(ReviewRuntimeError::Forbidden);
            }
            ensure_actor_serves_review_queue(&transaction, actor, &task_queue).await?;
        }
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            operation,
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
        if record.lifecycle != ReviewRequestLifecycle::Reviewing {
            return Err(ReviewRuntimeError::NotFound);
        }
        let row = transaction
            .query_opt(
                "SELECT stage_index,stage_id,queue_id,state,holder_issuer,holder_subject,revision
                 FROM casework_review_tasks WHERE task_id=$1 AND request_id=$2 FOR UPDATE",
                &[&task_id, &request_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        let stage_index =
            u16::try_from(row.get::<_, i32>(0)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        if record.active_stage != Some(stage_index)
            || row.get::<_, i64>(6) != expected_revision
            || !matches!(row.get::<_, String>(3).as_str(), "open" | "claimed")
        {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        let stage = record
            .policy
            .stages
            .get(usize::from(stage_index))
            .ok_or(ReviewRuntimeError::Corrupt)?;
        if delegate && !stage.deciding_profiles.contains(&actor.profile_id) {
            return Err(ReviewRuntimeError::Forbidden);
        }
        if !delegate && actor.role != CaseworkRole::Supervisor {
            return Err(ReviewRuntimeError::Forbidden);
        }
        let holder = match (
            row.get::<_, Option<String>>(4),
            row.get::<_, Option<String>>(5),
        ) {
            (Some(issuer), Some(subject)) => Some(IssuerPrincipal { issuer, subject }),
            (None, None) => None,
            _ => return Err(ReviewRuntimeError::Corrupt),
        };
        let queue = row.get::<_, String>(2);
        if delegate {
            if holder.as_ref() != Some(&actor.principal) {
                return Err(ReviewRuntimeError::Forbidden);
            }
            ensure_actor_serves_review_queue(&transaction, actor, &queue).await?;
        } else if transaction
            .query_opt(
                "SELECT 1 FROM casework_queue_service q
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3
                   AND m.membership_kind='supervisor' FOR KEY SHARE OF q,m",
                &[&queue, &actor.principal.issuer, &actor.principal.subject],
            )
            .await?
            .is_none()
        {
            return Err(ReviewRuntimeError::Forbidden);
        }
        ensure_review_identity_eligible(
            &transaction,
            &record,
            stage,
            stage_index,
            target,
            &queue,
            membership_kinds,
        )
        .await?;
        let absences = active_review_absences(&transaction, target, now).await?;
        let cover = resolve_absence_cover(target, now, &absences)
            .map_err(|_| ReviewRuntimeError::Corrupt)?;
        let effective = cover.person;
        let eligible = ensure_review_identity_eligible(
            &transaction,
            &record,
            stage,
            stage_index,
            &effective,
            &queue,
            membership_kinds,
        )
        .await
        .is_ok();
        let assignment_kind = if cover.absence_ids.is_empty() {
            if delegate {
                "delegation"
            } else {
                "nomination"
            }
        } else {
            "absence-cover"
        };
        let next_revision = expected_revision + 1;
        transaction
            .execute(
                "UPDATE casework_review_tasks
                 SET state=$2,holder_issuer=$3,holder_subject=$4,assignment_kind=$5,
                     assignment_owner_issuer=$6,assignment_owner_subject=$7,
                     assigned_by_issuer=$8,assigned_by_subject=$9,assignment_absence_ids=$10,
                     staffing_diagnostic=$11,revision=$12,updated_at=$13
                 WHERE task_id=$1",
                &[
                    &task_id,
                    &if eligible { "claimed" } else { "open" },
                    &eligible.then_some(&effective.issuer),
                    &eligible.then_some(&effective.subject),
                    &eligible.then_some(assignment_kind),
                    &target.issuer,
                    &target.subject,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &cover.absence_ids,
                    &(!eligible).then_some("no-cover-available"),
                    &next_revision,
                    &now,
                ],
            )
            .await
            .map_err(map_reviewer_conflict)?;
        let actor_ref = actor_reference(&actor.principal);
        let target_ref = actor_reference(target);
        let assignment_event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &assignment_event_id,
                    &request_id,
                    &task_id,
                    &if delegate {
                        "task-delegated"
                    } else {
                        "task-assigned"
                    },
                    &actor_ref,
                    &json!({
                        "assignmentKind": assignment_kind,
                        "targetRef": target_ref,
                        "reason": reason,
                        "staffingBlocked": !eligible,
                    }),
                    &now,
                ],
            )
            .await?;
        // The ownership transfer is audited like every other mutation once
        // the transaction commits. The record stays minimal:
        // the private reason never leaves the review history row, and only who
        // transferred responsibility to whom survives result expiry.
        audit.record(
            assignment_event_id,
            json!({
                "event": if delegate {
                    "casework.task-delegated"
                } else {
                    "casework.task-assigned"
                },
                "eventId": assignment_event_id,
                "reviewRequestId": request_id,
                "reviewTaskId": task_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
                "target": {
                    "issuer": target.issuer,
                    "subject": target.subject,
                },
            }),
        )?;
        let metadata = transaction
            .query_one(
                "SELECT deadline_at,created_at,staffing_diagnostic,state FROM casework_review_tasks WHERE task_id=$1",
                &[&task_id],
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
            queue,
            revision: next_revision,
            eligible_profiles: stage.deciding_profiles.clone(),
            state: if eligible {
                ReviewTaskState::Held { holder: effective }
            } else {
                ReviewTaskState::Open
            },
            staffing_diagnostic: staffing_diagnostic_from_row(&metadata)?,
            decided_by_caller: None,
            decision_receipt: None,
        };
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            operation,
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&task)?,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(task)
    }

    async fn review_task_draft(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
    ) -> Result<Option<ReviewTaskDraft>, ReviewRuntimeError> {
        let client = self.client().await?;
        let request_id = client
            .query_opt(
                "SELECT request_id FROM casework_review_tasks WHERE task_id=$1",
                &[&task_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?
            .get::<_, Uuid>(0);
        let record = load_request_by_id(&client, request_id, false).await?;
        ensure_review_result_retained(&record)?;
        ensure_review_reviewer_access(&client, &record, actor, Some(task_id), false).await?;
        let row = client
            .query_opt(
                "SELECT body,revision,updated_at FROM casework_review_task_drafts
                 WHERE task_id=$1 AND actor_issuer=$2 AND actor_subject=$3",
                &[&task_id, &actor.principal.issuer, &actor.principal.subject],
            )
            .await?;
        Ok(row.map(|row| ReviewTaskDraft {
            task_id,
            author: actor.principal.clone(),
            body: row.get(0),
            revision: row.get(1),
            updated_at: row.get(2),
        }))
    }

    async fn save_review_task_draft(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        expected_revision: i64,
        body: Value,
        idempotency_key: &str,
    ) -> Result<ReviewTaskDraft, ReviewRuntimeError> {
        if !registry_platform_canonical_json::canonicalize_json(&body)
            .is_ok_and(|canonical| canonical.len() <= MAXIMUM_REVIEW_DRAFT_BYTES)
        {
            return Err(ReviewRuntimeError::Invalid);
        }
        let now = Utc::now();
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
        let row = transaction
            .query_opt(
                "SELECT request_id,state,holder_issuer,holder_subject,revision
                 FROM casework_review_tasks WHERE task_id=$1 FOR UPDATE",
                &[&task_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        ensure_review_reviewer_access(&transaction, &record, actor, Some(task_id), true).await?;
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(expected_revision, &body))?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.task.draft.save",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        {
            transaction.commit().await?;
            return serde_json::from_value(response).map_err(ReviewRuntimeError::from);
        }
        if row.get::<_, String>(1) != "claimed"
            || row.get::<_, Option<String>>(2).as_deref() != Some(actor.principal.issuer.as_str())
            || row.get::<_, Option<String>>(3).as_deref() != Some(actor.principal.subject.as_str())
        {
            return Err(ReviewRuntimeError::TaskNotHeld);
        }
        if row.get::<_, i64>(4) != expected_revision {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        let draft_revision = transaction
            .query_opt(
                "SELECT revision FROM casework_review_task_drafts
                 WHERE task_id=$1 AND actor_issuer=$2 AND actor_subject=$3 FOR UPDATE",
                &[&task_id, &actor.principal.issuer, &actor.principal.subject],
            )
            .await?
            .map_or(1_i64, |row| row.get::<_, i64>(0) + 1);
        transaction
            .execute(
                "INSERT INTO casework_review_task_drafts(
                    task_id,actor_issuer,actor_subject,body,revision,updated_at)
                 VALUES($1,$2,$3,$4,$5,$6)
                 ON CONFLICT(task_id,actor_issuer,actor_subject) DO UPDATE SET body=EXCLUDED.body,
                    revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at",
                &[
                    &task_id,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &body,
                    &draft_revision,
                    &now,
                ],
            )
            .await?;
        transaction
            .execute(
                "UPDATE casework_review_tasks SET revision=revision+1,updated_at=$2
                 WHERE task_id=$1",
                &[&task_id, &now],
            )
            .await?;
        let draft = ReviewTaskDraft {
            task_id,
            author: actor.principal.clone(),
            body,
            revision: draft_revision,
            updated_at: now,
        };
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,'task-draft-saved',$4,$5,$6)",
                &[
                    &Uuid::new_v4(),
                    &request_id,
                    &task_id,
                    &actor_reference(&actor.principal),
                    &json!({"draftRevision": draft_revision}),
                    &now,
                ],
            )
            .await?;
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.task.draft.save",
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&draft)?,
        )
        .await?;
        transaction.commit().await?;
        Ok(draft)
    }

    async fn delete_review_task_draft(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<(), ReviewRuntimeError> {
        let now = Utc::now();
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
        let row = transaction
            .query_opt(
                "SELECT request_id,state,holder_issuer,holder_subject,revision
                 FROM casework_review_tasks WHERE task_id=$1 FOR UPDATE",
                &[&task_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        ensure_review_reviewer_access(&transaction, &record, actor, Some(task_id), true).await?;
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(expected_revision, "delete-draft"))?;
        if review_idempotent_response(
            &transaction,
            actor,
            "review.task.draft.delete",
            &resource,
            idempotency_key,
            &request_hash,
        )
        .await?
        .is_some()
        {
            transaction.commit().await?;
            return Ok(());
        }
        if row.get::<_, String>(1) != "claimed"
            || row.get::<_, Option<String>>(2).as_deref() != Some(actor.principal.issuer.as_str())
            || row.get::<_, Option<String>>(3).as_deref() != Some(actor.principal.subject.as_str())
        {
            return Err(ReviewRuntimeError::TaskNotHeld);
        }
        if row.get::<_, i64>(4) != expected_revision {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        if transaction
            .execute(
                "DELETE FROM casework_review_task_drafts
                 WHERE task_id=$1 AND actor_issuer=$2 AND actor_subject=$3",
                &[&task_id, &actor.principal.issuer, &actor.principal.subject],
            )
            .await?
            != 1
        {
            return Err(ReviewRuntimeError::NotFound);
        }
        transaction
            .execute(
                "UPDATE casework_review_tasks SET revision=revision+1,updated_at=$2
                 WHERE task_id=$1",
                &[&task_id, &now],
            )
            .await?;
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.task.draft.delete",
            &resource,
            idempotency_key,
            &request_hash,
            &Value::Null,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn review_history(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        requester: Option<&RequesterReader>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewHistoryPage, ReviewRuntimeError> {
        let client = self.client().await?;
        let record = load_request_by_id(&client, request_id, false).await?;
        // Access is decided before the retention boundary: whether a settled
        // review's result window has closed is only for callers entitled to
        // the review to learn.
        match requester {
            Some(RequesterReader::Producer(producer)) => {
                ensure_review_producer_access(&record, producer)?;
            }
            Some(RequesterReader::Initiator(producers)) => {
                ensure_review_initiator_access(&record, producers, actor)?;
            }
            None => ensure_review_reviewer_access(&client, &record, actor, None, false).await?,
        }
        ensure_review_result_retained(&record)?;
        if limit == 0 || limit > 100 {
            return Err(ReviewRuntimeError::Invalid);
        }
        let cursor_anchor = if let Some(cursor) = cursor {
            Some(
                client
                    .query_opt(
                        "SELECT occurred_at,event_id FROM casework_review_history
                         WHERE request_id=$1 AND event_id=$2 AND (
                            NOT $3 OR kind IN ('request-created','stage-advanced','review-settled','review-cancelled')
                            OR (kind='note' AND detail->>'audience'='requester')
                         )",
                        &[&request_id, &cursor, &requester.is_some()],
                    )
                    .await?
                    .map(|row| (row.get::<_, DateTime<Utc>>(0), row.get::<_, Uuid>(1)))
                    .ok_or(ReviewRuntimeError::ResultExpired)?,
            )
        } else {
            None
        };
        let cursor_occurred_at = cursor_anchor.as_ref().map(|anchor| anchor.0);
        let cursor_event_id = cursor_anchor.as_ref().map(|anchor| anchor.1);
        let query_limit = i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?;
        let rows = client
            .query(
                "SELECT event_id,request_id,task_id,kind,actor_ref,detail,occurred_at
                 FROM casework_review_history
                 WHERE request_id=$1 AND (
                    NOT $2 OR kind IN ('request-created','stage-advanced','review-settled','review-cancelled')
                    OR (kind='note' AND detail->>'audience'='requester')
                 )
                 AND ($3::timestamptz IS NULL OR (occurred_at,event_id)>($3,$4))
                 ORDER BY occurred_at,event_id LIMIT $5",
                &[
                    &request_id,
                    &requester.is_some(),
                    &cursor_occurred_at,
                    &cursor_event_id,
                    &query_limit,
                ],
            )
            .await?;
        let mut items = rows
            .into_iter()
            .map(|row| ReviewHistoryEntry {
                event_id: row.get(0),
                request_id: row.get(1),
                task_id: row.get(2),
                kind: row.get(3),
                actor_ref: row.get(4),
                detail: row.get(5),
                occurred_at: row.get(6),
            })
            .collect::<Vec<_>>();
        let next_cursor = (items.len() > limit).then(|| items[limit - 1].event_id);
        items.truncate(limit);
        Ok(ReviewHistoryPage { items, next_cursor })
    }

    async fn review_clocks(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        producer: Option<&registry_casework_core::ReviewProducerPolicy>,
    ) -> Result<Vec<ReviewClockOccurrence>, ReviewRuntimeError> {
        let client = self.client().await?;
        let record = load_request_by_id(&client, request_id, false).await?;
        // Access before retention, as in review_history: the expiry of a
        // result window must not be disclosed to callers outside the review.
        if let Some(producer) = producer {
            ensure_review_producer_access(&record, producer)?;
        } else {
            ensure_review_reviewer_access(&client, &record, actor, None, false).await?;
        }
        ensure_review_result_retained(&record)?;
        client
            .query(
                "SELECT o.clock_occurrence_id,o.clock_id,o.request_id,o.scope,o.subject_source,
                        o.subject_type,o.subject_id,o.task_id,t.stage_id,o.state,
                        o.policy_digest,o.anchor_at,o.due_at,o.at_risk_at,o.completed_at
                 FROM casework_review_clock_occurrences o
                 LEFT JOIN casework_review_tasks t ON t.task_id=o.task_id
                 WHERE o.request_id=$1 ORDER BY o.clock_id,o.scope,o.clock_occurrence_id",
                &[&request_id],
            )
            .await?
            .into_iter()
            .map(|row| review_clock_from_row(&row))
            .collect()
    }

    async fn review_accountability(
        &self,
        actor: &ActorContext,
        event_id: Uuid,
    ) -> Result<ReviewAccountabilityRecord, ReviewRuntimeError> {
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "review-accountability-read",
                Some(actor),
                &actor.profile_id,
                json!({"accountabilityEventId": event_id}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT a.event_id,a.request_id,a.task_id,a.actor_ref,a.actor_issuer,
                        a.actor_subject,a.profile_id,a.decision,a.private_reason,a.result_digest,
                        a.occurred_at,a.retained_until,a.outcome,r.policy_snapshot
                 FROM casework_review_accountability a
                 JOIN casework_queue_service q ON q.queue_id=a.queue_id
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 JOIN casework_review_requests r ON r.request_id=a.request_id
                 WHERE a.event_id=$1 AND m.issuer=$2 AND m.subject=$3
                   AND m.membership_kind='supervisor'
                   AND (r.lifecycle='reviewing' OR a.retained_until>now())
                 FOR KEY SHARE OF q,m",
                &[&event_id, &actor.principal.issuer, &actor.principal.subject],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        let decision: String = row.get(7);
        let outcome: Option<String> = row.get(12);
        let policy: ReviewPolicyClosure = serde_json::from_value(row.get(13))?;
        let decision_receipt = if decision == "approve" || outcome.is_some() {
            Some(review_decision_receipt(
                &policy,
                &decision,
                outcome,
                row.get(10),
            )?)
        } else {
            None
        };
        let record = ReviewAccountabilityRecord {
            event_id: row.get(0),
            request_id: row.get(1),
            task_id: row.get(2),
            actor_ref: row.get(3),
            actor: IssuerPrincipal {
                issuer: row.get(4),
                subject: row.get(5),
            },
            profile_id: row.get(6),
            decision,
            decision_receipt,
            private_reason: row.get(8),
            result_digest: row.get(9),
            occurred_at: row.get(10),
            retained_until: row.get(11),
        };
        let read_event_id = Uuid::new_v4();
        audit.record(
            read_event_id,
            json!({
                "event": "casework.review-accountability-read",
                "eventId": read_event_id,
                "accountabilityEventId": record.event_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
            }),
        )?;
        audit.commit(transaction).await?;
        Ok(record)
    }

    async fn add_review_note(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        producer: Option<&registry_casework_core::ReviewProducerPolicy>,
        request: ReviewNoteRequest,
        idempotency_key: &str,
    ) -> Result<ReviewHistoryEntry, ReviewRuntimeError> {
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "review-note-added",
                Some(actor),
                &actor.profile_id,
                json!({"reviewRequestId": request_id}),
            ))
            .await?;
        if request.note.trim().is_empty()
            || request.note.len() > 2_000
            || request.note.chars().any(char::is_control)
        {
            return Err(ReviewRuntimeError::Invalid);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let record = load_request_by_id(&transaction, request_id, true).await?;
        if let Some(producer) = producer {
            ensure_review_producer_access(&record, producer)?;
        } else {
            ensure_review_reviewer_access(&transaction, &record, actor, None, true).await?;
        }
        let now = Utc::now();
        if record
            .result_available_until
            .is_some_and(|available_until| available_until <= now)
        {
            return Err(ReviewRuntimeError::ResultExpired);
        }
        let resource = format!("review-request:{request_id}");
        let request_hash = review_request_hash(&request)?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.note.add",
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
        let entry = ReviewHistoryEntry {
            event_id: Uuid::new_v4(),
            request_id,
            task_id: None,
            kind: "note".to_owned(),
            actor_ref: Some(actor_reference(&actor.principal)),
            detail: json!({
                "audience": match request.audience {
                    ReviewHistoryAudience::Reviewers => "reviewers",
                    ReviewHistoryAudience::Requester => "requester",
                },
                "note": request.note,
            }),
            occurred_at: now,
        };
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,NULL,$3,$4,$5,$6)",
                &[
                    &entry.event_id,
                    &request_id,
                    &entry.kind,
                    &entry.actor_ref,
                    &entry.detail,
                    &now,
                ],
            )
            .await?;
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.note.add",
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&entry)?,
        )
        .await?;
        // The note's text and audience stay in the review history; the audit
        // record names only who added a note and which history event it is.
        audit.record(
            entry.event_id,
            json!({
                "event": "casework.review-note-added",
                "eventId": entry.event_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
            }),
        )?;
        audit.commit(transaction).await?;
        Ok(entry)
    }

    async fn release_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTask, ReviewRuntimeError> {
        let now = Utc::now();
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "task-released",
                Some(actor),
                &actor.profile_id,
                json!({}),
            ))
            .await?;
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT t.request_id,t.stage_index,t.stage_id,t.queue_id,t.state,
                        t.holder_issuer,t.holder_subject,t.revision,r.lifecycle,r.policy_snapshot
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 WHERE t.task_id=$1 FOR UPDATE OF r,t",
                &[&task_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        let request_id = row.get::<_, Uuid>(0);
        let record = load_request_by_id(&transaction, request_id, true).await?;
        ensure_review_mutation_actor_authorized(&transaction, &record, actor, task_id).await?;
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(expected_revision, "release"))?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.task.release",
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
        if row.get::<_, String>(8) != "reviewing" || row.get::<_, i64>(7) != expected_revision {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        if row.get::<_, String>(4) != "claimed"
            || row.get::<_, Option<String>>(5).as_deref() != Some(actor.principal.issuer.as_str())
            || row.get::<_, Option<String>>(6).as_deref() != Some(actor.principal.subject.as_str())
        {
            return Err(ReviewRuntimeError::TaskNotHeld);
        }
        let policy: ReviewPolicyClosure = serde_json::from_value(row.get(9))?;
        let stage_index =
            u16::try_from(row.get::<_, i32>(1)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        let stage = policy
            .stages
            .get(usize::from(stage_index))
            .ok_or(ReviewRuntimeError::Corrupt)?;
        transaction
            .execute(
                "UPDATE casework_review_tasks
                 SET state='open',holder_issuer=NULL,holder_subject=NULL,assignment_kind=NULL,
                     assignment_owner_issuer=NULL,assignment_owner_subject=NULL,
                     assigned_by_issuer=NULL,assigned_by_subject=NULL,
                     assignment_absence_ids='{}',staffing_diagnostic=NULL,
                     revision=revision+1,updated_at=$2 WHERE task_id=$1",
                &[&task_id, &now],
            )
            .await?;
        let metadata = transaction
            .query_one(
                "SELECT deadline_at,created_at,staffing_diagnostic,state FROM casework_review_tasks WHERE task_id=$1",
                &[&task_id],
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
            stage_id: row.get(2),
            queue: row.get(3),
            revision: expected_revision + 1,
            eligible_profiles: stage.deciding_profiles.clone(),
            state: ReviewTaskState::Open,
            staffing_diagnostic: staffing_diagnostic_from_row(&metadata)?,
            decided_by_caller: None,
            decision_receipt: None,
        };
        let actor_ref = actor_reference(&actor.principal);
        let release_event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,'task-released',$4,$5,$6)",
                &[
                    &release_event_id,
                    &request_id,
                    &task_id,
                    &actor_ref,
                    &json!({
                        "assignmentKind": "release",
                        "previousHolderRef": &actor_ref,
                    }),
                    &now,
                ],
            )
            .await?;
        // The release is audited like every other mutation once the
        // transaction commits. The record stays minimal: only
        // who gave up responsibility survives result expiry.
        audit.record(
            release_event_id,
            json!({
                "event": "casework.task-released",
                "eventId": release_event_id,
                "reviewRequestId": request_id,
                "reviewTaskId": task_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
            }),
        )?;
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.task.release",
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&task)?,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(task)
    }

    async fn decide_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        decision_kind: DecisionKind,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTransition, ReviewRuntimeError> {
        let now = Utc::now();
        let mut audit = self
            .begin_audit(crate::audit::request_record(
                "review-decided",
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
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(expected_revision, &decision_kind))?;
        ensure_review_mutation_actor_authorized(&transaction, &record, actor, task_id).await?;
        if let Some(response) = review_idempotent_response(
            &transaction,
            actor,
            "review.task.decide",
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
        if record.lifecycle != ReviewRequestLifecycle::Reviewing {
            return Err(ReviewRuntimeError::NotFound);
        }
        let task_row = transaction
            .query_opt(
                "SELECT stage_index,stage_id,queue_id,state,holder_issuer,holder_subject,revision
                 FROM casework_review_tasks WHERE task_id=$1 AND request_id=$2 FOR UPDATE",
                &[&task_id, &request_id],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        if task_row.get::<_, i64>(6) != expected_revision {
            return Err(ReviewRuntimeError::RevisionConflict);
        }
        let stage_index =
            u16::try_from(task_row.get::<_, i32>(0)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        let stage = record
            .policy
            .stages
            .get(usize::from(stage_index))
            .ok_or(ReviewRuntimeError::Corrupt)?;
        ensure_actor_serves_review_queue(&transaction, actor, &task_row.get::<_, String>(2))
            .await?;
        let metadata = transaction
            .query_one(
                "SELECT deadline_at,created_at,staffing_diagnostic,state FROM casework_review_tasks WHERE task_id=$1",
                &[&task_id],
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
            stage_id: task_row.get(1),
            queue: task_row.get(2),
            revision: expected_revision,
            eligible_profiles: stage.deciding_profiles.clone(),
            state: match task_row.get::<_, String>(3).as_str() {
                "open" => ReviewTaskState::Open,
                "claimed" => ReviewTaskState::Held {
                    holder: IssuerPrincipal {
                        issuer: task_row
                            .get::<_, Option<String>>(4)
                            .ok_or(ReviewRuntimeError::Corrupt)?,
                        subject: task_row
                            .get::<_, Option<String>>(5)
                            .ok_or(ReviewRuntimeError::Corrupt)?,
                    },
                },
                "decided" | "closed" => ReviewTaskState::Decided,
                _ => return Err(ReviewRuntimeError::Corrupt),
            },
            staffing_diagnostic: staffing_diagnostic_from_row(&metadata)?,
            decided_by_caller: None,
            decision_receipt: None,
        };
        check_task_holder(&task.state, &actor.principal).map_err(map_review_decision_error)?;
        let mut progress = ReviewProgress::new(
            request_id,
            record.initiator.clone(),
            record.result_constraints.clone(),
            &record.policy,
        )
        .map_err(|_| ReviewRuntimeError::Corrupt)?;
        progress.active_stage = record.active_stage.ok_or(ReviewRuntimeError::Corrupt)?;
        progress.decisions = load_decisions(&transaction, request_id).await?;
        let decision = Decision {
            task_id,
            request_id,
            stage_id: task.stage_id.clone(),
            reviewer: actor.principal.clone(),
            profile_id: actor.profile_id.clone(),
            decision: decision_kind,
        };
        let transition =
            record_review_decision(&record.policy, &mut progress, &task, decision.clone())
                .map_err(map_review_decision_error)?;
        let (decision_name, outcome, result, reason, public_reason) =
            decision_columns(&decision.decision);
        let decision_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_decisions(
                    decision_id,request_id,task_id,stage_index,actor_issuer,actor_subject,
                    profile_id,decision,outcome,result,private_reason,public_reason,decided_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
                &[
                    &decision_id,
                    &request_id,
                    &task_id,
                    &i32::from(stage_index),
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &actor.profile_id,
                    &decision_name,
                    &outcome,
                    &result,
                    &reason,
                    &public_reason,
                    &now,
                ],
            )
            .await
            .map_err(map_reviewer_conflict)?;
        transaction
            .execute(
                "UPDATE casework_review_tasks
                 SET state='decided',staffing_diagnostic=NULL,settled_at=$2,revision=revision+1,updated_at=$2
                 WHERE task_id=$1",
                &[&task_id, &now],
            )
            .await?;
        let actor_ref = actor_reference(&actor.principal);
        let result_digest = result
            .as_ref()
            .map(registry_platform_canonical_json::canonicalize_json)
            .transpose()
            .map_err(|_| ReviewRuntimeError::Invalid)?
            .map(|bytes| ContentDigest::for_bytes(&bytes).to_string());
        let accountability_until =
            now + TimeDelta::days(i64::from(record.policy.retention.accountability_days));
        let accountability_event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_accountability(
                    event_id,request_id,task_id,queue_id,actor_ref,actor_issuer,actor_subject,
                    profile_id,decision,private_reason,result_digest,occurred_at,retained_until,outcome)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
                &[
                    &accountability_event_id,
                    &request_id,
                    &task_id,
                    &task.queue,
                    &actor_ref,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &actor.profile_id,
                    &decision_name,
                    &reason,
                    &result_digest,
                    &now,
                    &accountability_until,
                    &outcome,
                ],
            )
            .await?;
        match &transition {
            ReviewTransition::Recorded { .. } => {
                transaction
                    .execute(
                        "UPDATE casework_review_requests SET revision=revision+1,updated_at=$2
                         WHERE request_id=$1",
                        &[&request_id, &now],
                    )
                    .await?;
            }
            ReviewTransition::StageAdvanced { .. } => {
                transaction
                    .execute(
                        "UPDATE casework_review_tasks
                         SET state='closed',staffing_diagnostic=NULL,settled_at=COALESCE(settled_at,$3),updated_at=$3,
                             revision=revision+1
                         WHERE request_id=$1 AND stage_index=$2 AND state IN ('open','claimed')",
                        &[&request_id, &i32::from(stage_index), &now],
                    )
                    .await?;
                transaction
                    .execute(
                        "UPDATE casework_review_clock_occurrences
                         SET state='completed',completed_at=$3,next_action_at=NULL,updated_at=$3
                         WHERE request_id=$1 AND task_id IN (
                             SELECT task_id FROM casework_review_tasks
                             WHERE request_id=$1 AND stage_index=$2
                         ) AND scope='activity' AND state NOT IN ('completed','cancelled')",
                        &[&request_id, &i32::from(stage_index), &now],
                    )
                    .await?;
                let next_stage = progress.active_stage;
                let tasks = insert_stage_tasks(
                    &transaction,
                    &self.providers,
                    request_id,
                    &record.policy,
                    next_stage,
                    now,
                )
                .await?;
                insert_advanced_review_activity_clocks(
                    &transaction,
                    request_id,
                    &record.subject,
                    &record.policy.clocks,
                    &tasks,
                    now,
                )
                .await?;
                transaction
                    .execute(
                        "UPDATE casework_review_requests
                         SET active_stage_index=$2,revision=revision+1,updated_at=$3
                         WHERE request_id=$1",
                        &[&request_id, &i32::from(next_stage), &now],
                    )
                    .await?;
                transaction
                    .execute(
                        "INSERT INTO casework_review_history(
                            event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                         VALUES($1,$2,NULL,'stage-advanced',NULL,$3,$4)",
                        &[
                            &Uuid::new_v4(),
                            &request_id,
                            &json!({"stageIndex": next_stage}),
                            &now,
                        ],
                    )
                    .await?;
            }
            ReviewTransition::Settled { settlement } => {
                let (status, outcome, public_reason, result) = settlement_columns(settlement);
                settle_review(
                    &transaction,
                    &record,
                    status,
                    outcome,
                    public_reason,
                    result,
                    now,
                )
                .await?;
            }
        }
        let decision_event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,'review-decided',$4,$5,$6)",
                &[
                    &decision_event_id,
                    &request_id,
                    &task_id,
                    &actor_ref,
                    &json!({
                        "decision": decision_name,
                        "transition": transition_kind(&transition),
                        "accountabilityEventId": accountability_event_id,
                    }),
                    &now,
                ],
            )
            .await?;
        // The decision is the strongest accountability event this service
        // emits, so it is audited like every other mutation once the
        // transaction commits. The record stays minimal: the
        // private reason and the structured result never leave the
        // protected accountability row. The public reason is released only
        // with the producer's ReviewResult, so the journal records that one
        // was given and never its text.
        audit.record(
            decision_event_id,
            json!({
                "event": "casework.review-decided",
                "eventId": decision_event_id,
                "reviewRequestId": request_id,
                "reviewTaskId": task_id,
                "actor": {
                    "issuer": actor.principal.issuer,
                    "subject": actor.principal.subject,
                },
                "profileId": actor.profile_id,
                "decision": decision_name,
                "transition": transition_kind(&transition),
                "accountabilityEventId": accountability_event_id,
                "publicReasonGiven": public_reason.is_some(),
            }),
        )?;
        insert_review_idempotency(
            &transaction,
            request_id,
            actor,
            "review.task.decide",
            &resource,
            idempotency_key,
            &request_hash,
            &serde_json::to_value(&transition)?,
        )
        .await?;
        audit.commit(transaction).await?;
        Ok(transition)
    }
}

async fn insert_stage_tasks(
    tx: &Transaction<'_>,
    providers: &std::collections::BTreeMap<String, std::sync::Arc<dyn ReviewContextProvider>>,
    request_id: Uuid,
    policy: &ReviewPolicyClosure,
    stage_index: u16,
    now: DateTime<Utc>,
) -> Result<Vec<(Uuid, String)>, ReviewRuntimeError> {
    let stage = policy
        .stages
        .get(usize::from(stage_index))
        .ok_or(ReviewRuntimeError::Corrupt)?;
    let record = load_request_by_id(tx, request_id, false).await?;
    let rules = policy
        .routing
        .iter()
        .filter(|rule| rule.when.stage.as_ref().is_none_or(|id| id == &stage.id))
        .cloned()
        .collect::<Vec<_>>();
    let fields = rules
        .iter()
        .flat_map(|rule| rule.when.fields.keys().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut tasks = Vec::new();
    for slot in 0..stage.required_approvals {
        let task_id = Uuid::new_v4();
        let values = if fields.is_empty() {
            std::collections::BTreeMap::new()
        } else {
            match (&policy.context, record.context.as_ref()) {
                (ReviewContextPolicy::Submitted, Some(ReviewContext::Submitted { snapshot })) => {
                    fields
                        .iter()
                        .filter_map(|field| {
                            snapshot
                                .get(field)
                                .cloned()
                                .map(|value| (field.clone(), value))
                        })
                        .collect()
                }
                (
                    ReviewContextPolicy::CurrentSource { provider, contract },
                    Some(ReviewContext::CurrentSource { .. }),
                ) => {
                    let provider = providers
                        .get(provider)
                        .ok_or(ReviewRuntimeError::SourceUnavailable)?;
                    let expected = ServiceContextRequest {
                        identity: ReviewContextIdentity {
                            subject: record.subject.clone(),
                            contract: contract.clone(),
                        },
                        request_id,
                        task_id,
                        task_revision: 1,
                        policy: policy_binding(policy),
                        purpose: "review-task-routing".to_owned(),
                        fields: fields.clone(),
                    };
                    let observed = tokio::time::timeout(
                        Duration::from_millis(policy.dependencies.inbox.page_deadline_milliseconds),
                        provider.routing_context(&expected),
                    )
                    .await
                    .map_err(|_| ReviewRuntimeError::SourceUnavailable)?
                    .map_err(map_review_source_error)?;
                    observed.check(&expected).map_err(map_review_source_error)?;
                    if !observed.reviewable {
                        return Err(ReviewRuntimeError::Forbidden);
                    }
                    observed.fields
                }
                _ => return Err(ReviewRuntimeError::Corrupt),
            }
        };
        let metadata = RoutingSourceMetadata {
            stages: policy.stages.iter().map(|s| s.id.clone()).collect(),
            fields: fields
                .iter()
                .map(|field| {
                    Ok(RoutingFieldDescriptor {
                        field: field.clone(),
                        api_name: field.clone(),
                        schema: policy
                            .display_schema
                            .get("properties")
                            .and_then(|props| props.get(field))
                            .cloned()
                            .ok_or(ReviewRuntimeError::Corrupt)?,
                    })
                })
                .collect::<Result<Vec<_>, ReviewRuntimeError>>()?,
        };
        let routing = evaluate_routing(
            &stage.queue,
            &fields,
            &rules,
            &metadata,
            &RoutingContext {
                activity: RoutingActivity::Review,
                stage: Some(stage.id.clone()),
                fields: values,
            },
        )
        .map_err(|_| ReviewRuntimeError::SourceInvalid)?;
        tx.execute("INSERT INTO casework_review_tasks(task_id,request_id,stage_index,stage_id,slot,queue_id,state,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'open',1,$7,$7)",&[&task_id,&request_id,&i32::from(stage_index),&stage.id,&i32::from(slot),&routing.queue,&now]).await?;
        tasks.push((task_id, stage.id.clone()));
    }
    Ok(tasks)
}

/// The clock a review clock occurrence stored when it started.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewClockDefinition {
    clock: ClockPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    calendar: Option<CalendarPolicy>,
}

fn next_review_clock_action(
    reminders: &[ReminderOccurrence],
    steps: &[StepOccurrence],
    completed: &std::collections::BTreeSet<(String, String)>,
) -> Option<DateTime<Utc>> {
    reminders
        .iter()
        .filter(|effect| !completed.contains(&("reminder".to_owned(), effect.id.clone())))
        .map(|effect| effect.at)
        .chain(
            steps
                .iter()
                .filter(|effect| !completed.contains(&("step".to_owned(), effect.id.clone())))
                .map(|effect| effect.at),
        )
        .min()
}

// Inserts a fresh subject-scope clock occurrence, anchored at `now` with a
// full deadline computed from the current policy. Shared by the
// no-prior-occurrence path and the path that erases an occurrence bound to a
// round already past its result_available_until, so both start the new
// subject clock the same way.
#[allow(clippy::too_many_arguments)]
async fn insert_fresh_subject_clock_occurrence(
    transaction: &Transaction<'_>,
    request_id: Uuid,
    subject: &SubjectBinding,
    correlation_key: &str,
    clock_id: &str,
    digest: &str,
    document: &serde_json::Value,
    now: DateTime<Utc>,
    due_at: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    transaction
        .execute(
            "INSERT INTO casework_review_clock_occurrences(
                clock_occurrence_id,clock_id,scope,correlation_key,
                subject_source,subject_type,subject_id,request_id,policy_digest,
                policy,state,anchor_at,due_at,created_at,updated_at)
             VALUES($1,$2,'subject',$3,$4,$5,$6,$7,$8,$9,'running',$10,$11,$10,$10)",
            &[
                &Uuid::new_v4(),
                &clock_id,
                &correlation_key,
                &subject.source,
                &subject.subject_type,
                &subject.id,
                &request_id,
                &digest,
                document,
                &now,
                &due_at,
            ],
        )
        .await?;
    Ok(())
}

async fn insert_initial_review_clocks(
    tx: &Transaction<'_>,
    request_id: Uuid,
    subject: &SubjectBinding,
    review_policy_id: &str,
    clocks: &[(ClockPolicy, Option<CalendarPolicy>)],
    tasks: &[(Uuid, String)],
    now: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    for (clock, calendar) in clocks {
        let definition = ReviewClockDefinition {
            clock: clock.clone(),
            calendar: calendar.clone(),
        };
        match clock {
            ClockPolicy::Subject { after, .. } => {
                let seconds =
                    parse_elapsed_seconds(&after.elapsed).ok_or(ReviewRuntimeError::Corrupt)?;
                let document = serde_json::to_value(&definition)?;
                let digest = review_request_hash(&document)?;
                let correlation = format!("review-policy:{review_policy_id}:{request_id}");
                insert_fresh_subject_clock_occurrence(
                    tx,
                    request_id,
                    subject,
                    &correlation,
                    clock.id(),
                    &digest,
                    &document,
                    now,
                    now + TimeDelta::seconds(seconds),
                )
                .await?;
            }
            ClockPolicy::Activity { .. } => {
                for (task_id, stage_id) in tasks {
                    insert_review_activity_clock(
                        tx,
                        request_id,
                        subject,
                        task_id,
                        stage_id,
                        &definition,
                        now,
                    )
                    .await?;
                }
            }
        }
    }
    refresh_review_deadlines(tx, request_id).await?;
    Ok(())
}

async fn insert_advanced_review_activity_clocks(
    transaction: &Transaction<'_>,
    request_id: Uuid,
    subject: &SubjectBinding,
    clock_ids: &[String],
    tasks: &[(Uuid, String)],
    now: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    for clock_id in clock_ids {
        let Some(row) = transaction
            .query_opt(
                "SELECT policy FROM casework_review_clock_occurrences
                 WHERE subject_source=$1 AND subject_type=$2 AND subject_id=$3 AND clock_id=$4
                   AND request_id=$5
                 ORDER BY created_at LIMIT 1",
                &[
                    &subject.source,
                    &subject.subject_type,
                    &subject.id,
                    &clock_id,
                    &request_id,
                ],
            )
            .await?
        else {
            continue;
        };
        let definition: ReviewClockDefinition = serde_json::from_value(row.get(0))?;
        if !matches!(definition.clock, ClockPolicy::Activity { .. }) {
            continue;
        }
        for (task_id, stage_id) in tasks {
            insert_review_activity_clock(
                transaction,
                request_id,
                subject,
                task_id,
                stage_id,
                &definition,
                now,
            )
            .await?;
        }
    }
    refresh_review_deadlines(transaction, request_id).await?;
    Ok(())
}

async fn insert_review_activity_clock(
    transaction: &Transaction<'_>,
    request_id: Uuid,
    subject: &SubjectBinding,
    task_id: &Uuid,
    stage_id: &str,
    definition: &ReviewClockDefinition,
    now: DateTime<Utc>,
) -> Result<(), ReviewRuntimeError> {
    let document = serde_json::to_value(definition)?;
    let digest = review_request_hash(&document)?;
    let correlation = format!("{task_id}:{stage_id}");
    let (state, holiday_document, due_at, at_risk_at, reminders, steps, next_action_at) =
        if let Some(calendar) = definition.calendar.as_ref() {
            let holiday = transaction
                .query_opt(
                    "SELECT document FROM casework_holiday_sets WHERE holiday_set=$1
                 ORDER BY revision DESC LIMIT 1",
                    &[&calendar.holiday_set],
                )
                .await?;
            if let Some(holiday) = holiday {
                let holiday: HolidaySetDocument = serde_json::from_value(holiday.get(0))?;
                let evaluated = registry_casework_core::evaluate_activity_clock(
                    &definition.clock,
                    calendar,
                    &holiday,
                    now,
                )
                .map_err(|error| clock_evaluation_error(&definition.clock, error))?;
                let next_action_at = next_review_clock_action(
                    &evaluated.reminders,
                    &evaluated.steps,
                    &std::collections::BTreeSet::new(),
                );
                (
                    "running",
                    Some(holiday),
                    Some(evaluated.due_at),
                    evaluated.at_risk_at,
                    evaluated.reminders,
                    evaluated.steps,
                    next_action_at,
                )
            } else {
                (
                    "source-facts-missing",
                    None,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    None,
                )
            }
        } else {
            return Err(ReviewRuntimeError::Corrupt);
        };
    transaction
        .execute(
            "INSERT INTO casework_review_clock_occurrences(
                clock_occurrence_id,clock_id,scope,correlation_key,subject_source,
                subject_type,subject_id,request_id,task_id,policy_digest,policy,state,
                anchor_at,due_at,at_risk_at,holiday_document,reminders,steps,next_action_at,
                created_at,updated_at)
             VALUES($1,$2,'activity',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
                    $18,$12,$12)
             ON CONFLICT DO NOTHING",
            &[
                &Uuid::new_v4(),
                &definition.clock.id(),
                &correlation,
                &subject.source,
                &subject.subject_type,
                &subject.id,
                &request_id,
                &task_id,
                &digest,
                &document,
                &state,
                &now,
                &due_at,
                &at_risk_at,
                &holiday_document
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()?,
                &serde_json::to_value(&reminders)?,
                &serde_json::to_value(&steps)?,
                &next_action_at,
            ],
        )
        .await?;
    Ok(())
}

async fn settle_review(
    transaction: &Transaction<'_>,
    record: &ReviewRequestRecord,
    status: ReviewResultStatus,
    outcome: Option<String>,
    public_reason: Option<String>,
    result: Option<Value>,
    now: DateTime<Utc>,
) -> Result<ReviewResult, ReviewRuntimeError> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            &[&record.producer_id],
        )
        .await?;
    let result_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let available_until = now + TimeDelta::days(i64::from(record.policy.retention.terminal_days));
    let accountability_until =
        now + TimeDelta::days(i64::from(record.policy.retention.accountability_days));
    let retained_until = available_until;
    let status_name = result_status_name(status);
    transaction
        .execute(
            "UPDATE casework_review_accountability
             SET retained_until=$2 WHERE request_id=$1",
            &[&record.request_id, &accountability_until],
        )
        .await?;
    transaction
        .execute(
            "UPDATE casework_review_submission_reservations
             SET retained_until=$2 WHERE request_id=$1",
            &[&record.request_id, &accountability_until],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO casework_review_results(
                result_id,request_id,status,outcome,public_reason,result,completed_at,available_until)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &result_id,
                &record.request_id,
                &status_name,
                &outcome,
                &public_reason,
                &result,
                &now,
                &available_until,
            ],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO casework_review_terminal_events(
                event_id,request_id,result_id,producer_id,completed_at,retained_until)
             VALUES($1,$2,$3,$4,$5,$6)",
            &[
                &event_id,
                &record.request_id,
                &result_id,
                &record.producer_id,
                &now,
                &retained_until,
            ],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO casework_review_history(
                event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
             VALUES($1,$2,NULL,'review-settled',NULL,$3,$4)",
            &[
                &Uuid::new_v4(),
                &record.request_id,
                &json!({"status": status_name}),
                &now,
            ],
        )
        .await?;
    let completion = transaction
        .query_one(
            "SELECT completion_destination,completion_recipient_binding
             FROM casework_review_requests WHERE request_id=$1",
            &[&record.request_id],
        )
        .await?;
    let destination = completion.get::<_, Option<String>>(0);
    let recipient = completion.get::<_, Option<String>>(1);
    match (destination, recipient) {
        (Some(destination), Some(recipient)) => {
            transaction
                .execute(
                    "INSERT INTO casework_review_completion_outbox(
                    event_id,request_id,destination_id,recipient_binding,state,attempt_count,
                    next_attempt_at,retained_until)
                 VALUES($1,$2,$3,$4,'pending',0,$5,$6)",
                    &[
                        &event_id,
                        &record.request_id,
                        &destination,
                        &recipient,
                        &now,
                        &retained_until,
                    ],
                )
                .await?;
        }
        (None, None) => {}
        _ => return Err(ReviewRuntimeError::Corrupt),
    }
    transaction
        .execute(
            "UPDATE casework_review_tasks
             SET state='closed',staffing_diagnostic=NULL,settled_at=COALESCE(settled_at,$2),updated_at=$2,
                 revision=revision+1
             WHERE request_id=$1 AND state IN ('open','claimed')",
            &[&record.request_id, &now],
        )
        .await?;
    let lifecycle = result_status_name(status);
    transaction
        .execute(
            "UPDATE casework_review_requests
             SET lifecycle=$2,active_stage_index=NULL,revision=revision+1,updated_at=$3,
                 terminal_at=$3,result_available_until=$4,accountability_retained_until=$5
             WHERE request_id=$1 AND lifecycle='reviewing'",
            &[
                &record.request_id,
                &lifecycle,
                &now,
                &available_until,
                &accountability_until,
            ],
        )
        .await?;
    let clock_state = if matches!(
        status,
        ReviewResultStatus::Cancelled | ReviewResultStatus::Superseded
    ) {
        "cancelled"
    } else {
        "completed"
    };
    transaction.execute("UPDATE casework_review_clock_occurrences SET state=$2,completed_at=CASE WHEN $2='completed' THEN $3::timestamptz ELSE NULL END,paused_at=NULL,next_action_at=NULL,updated_at=$3 WHERE request_id=$1 AND state NOT IN('completed','cancelled')",&[&record.request_id,&clock_state,&now]).await?;

    let response = ReviewResult {
        result_id,
        request_id: record.request_id,
        subject: record.subject.clone(),
        policy: policy_binding(&record.policy),
        submission_digest: record.submission_digest.clone(),
        status,
        outcome,
        public_reason,
        result,
        completed_at: now,
        available_until,
    };
    response.check().map_err(|_| ReviewRuntimeError::Corrupt)?;
    Ok(response)
}

async fn load_request(
    transaction: &Transaction<'_>,
    producer: &registry_casework_core::ReviewProducerPolicy,
    request_id: Uuid,
    for_update: bool,
) -> Result<ReviewRequestRecord, ReviewRuntimeError> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let query = format!(
        "{}{}",
        request_query("producer_id=$1 AND request_id=$2"),
        suffix
    );
    let row = transaction
        .query_opt(&query, &[&producer.id, &request_id])
        .await?
        .ok_or(ReviewRuntimeError::NotFound)?;
    let record = request_from_row(&row)?;
    ensure_review_producer_access(&record, producer)?;
    Ok(record)
}

async fn load_request_by_id(
    transaction: &impl GenericClient,
    request_id: Uuid,
    for_update: bool,
) -> Result<ReviewRequestRecord, ReviewRuntimeError> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let query = format!("{}{}", request_query("request_id=$1"), suffix);
    let row = transaction
        .query_opt(&query, &[&request_id])
        .await?
        .ok_or(ReviewRuntimeError::NotFound)?;
    request_from_row(&row)
}

async fn load_request_client(
    client: &deadpool_postgres::Client,
    producer: &registry_casework_core::ReviewProducerPolicy,
    request_id: Uuid,
) -> Result<ReviewRequestRecord, ReviewRuntimeError> {
    let row = client
        .query_opt(
            &request_query("producer_id=$1 AND request_id=$2"),
            &[&producer.id, &request_id],
        )
        .await?
        .ok_or(ReviewRuntimeError::NotFound)?;
    let record = request_from_row(&row)?;
    ensure_review_producer_access(&record, producer)?;
    Ok(record)
}

fn request_query(predicate: &str) -> String {
    format!(
        "SELECT request_id,producer_id,subject_source,subject_type,subject_id,subject_version,
                subject_digest,requester_reference,policy_snapshot,submission_digest,lifecycle,
                active_stage_index,created_at,updated_at,result_available_until,
                initiator_issuer,initiator_subject,result_constraints,context_strategy,context,
                result_erased_at,producer_issuer,producer_subject
         FROM casework_review_requests WHERE {predicate}"
    )
}

fn request_from_row(row: &Row) -> Result<ReviewRequestRecord, ReviewRuntimeError> {
    let lifecycle = parse_lifecycle(&row.get::<_, String>(10))?;
    let policy: ReviewPolicyClosure = serde_json::from_value(row.get(8))?;
    policy.verify().map_err(|_| ReviewRuntimeError::Corrupt)?;
    let result_available_until = row.get::<_, Option<DateTime<Utc>>>(14);
    let result_erased_at = row.get::<_, Option<DateTime<Utc>>>(20);
    let context_strategy = row.get::<_, String>(18);
    let context_value = row.get::<_, Value>(19);
    let context_erased = context_value
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
        && lifecycle != ReviewRequestLifecycle::Reviewing
        && (result_erased_at.is_some()
            || result_available_until.is_some_and(|until| until <= Utc::now()));
    let context = if context_erased {
        None
    } else {
        match context_strategy.as_str() {
            "submitted" => Some(registry_casework_core::ReviewContext::Submitted {
                snapshot: context_value,
            }),
            "current-source" => Some(registry_casework_core::ReviewContext::CurrentSource {
                binding: serde_json::from_value::<SourceContextBinding>(context_value)?,
            }),
            _ => return Err(ReviewRuntimeError::Corrupt),
        }
    };
    Ok(ReviewRequestRecord {
        request_id: row.get(0),
        producer_id: row.get(1),
        producer_issuer: row.get(21),
        producer_subject: row.get(22),
        subject: SubjectBinding {
            source: row.get(2),
            subject_type: row.get(3),
            id: row.get(4),
            version: row.get(5),
            digest: ContentDigest::parse(&row.get::<_, String>(6))
                .map_err(|_| ReviewRuntimeError::Corrupt)?,
        },
        requester_reference: row.get(7),
        policy,
        submission_digest: ContentDigest::parse(&row.get::<_, String>(9))
            .map_err(|_| ReviewRuntimeError::Corrupt)?,
        lifecycle,
        active_stage: row
            .get::<_, Option<i32>>(11)
            .map(u16::try_from)
            .transpose()
            .map_err(|_| ReviewRuntimeError::Corrupt)?,
        created_at: row.get(12),
        updated_at: row.get(13),
        result_available_until,
        result_erased_at,
        initiator: match (
            row.get::<_, Option<String>>(15),
            row.get::<_, Option<String>>(16),
        ) {
            (Some(issuer), Some(subject)) => Some(IssuerPrincipal { issuer, subject }),
            (None, None) => None,
            _ => return Err(ReviewRuntimeError::Corrupt),
        },
        result_constraints: row.get(17),
        context,
    })
}

/// A person reads a request only as its exact recorded initiator, and only
/// when the producer that admitted it declares the caller's profile. After
/// erasure the stored initiator is a tombstone of that same identity, so the
/// person still learns that the result expired and nobody else does.
fn ensure_review_initiator_access(
    record: &ReviewRequestRecord,
    producers: &std::collections::BTreeSet<String>,
    actor: &ActorContext,
) -> Result<(), ReviewRuntimeError> {
    let expected = if record.result_erased_at.is_some() {
        let tombstone = review_initiator_tombstone(
            record.request_id,
            &actor.principal.issuer,
            &actor.principal.subject,
        );
        IssuerPrincipal {
            issuer: tombstone.clone(),
            subject: tombstone,
        }
    } else {
        actor.principal.clone()
    };
    if producers.contains(&record.producer_id) && record.initiator.as_ref() == Some(&expected) {
        Ok(())
    } else {
        Err(ReviewRuntimeError::NotFound)
    }
}

fn ensure_review_producer_access(
    record: &ReviewRequestRecord,
    producer: &registry_casework_core::ReviewProducerPolicy,
) -> Result<(), ReviewRuntimeError> {
    let identity_matches = if record.result_erased_at.is_some() {
        let tombstone = review_producer_tombstone(
            record.request_id,
            &producer.id,
            &producer.issuer,
            &producer.subject,
        );
        record.producer_issuer == tombstone && record.producer_subject == tombstone
    } else {
        record.producer_issuer == producer.issuer && record.producer_subject == producer.subject
    };
    if record.producer_id == producer.id && identity_matches {
        Ok(())
    } else {
        Err(ReviewRuntimeError::NotFound)
    }
}

fn review_task_matches_ownership(
    task: &ReviewTask,
    actor: &ActorContext,
    ownership: Option<ReviewTaskOwnership>,
) -> bool {
    match ownership {
        None => true,
        Some(ReviewTaskOwnership::Unclaimed) => task.state == ReviewTaskState::Open,
        Some(ReviewTaskOwnership::AssignedToMe) => matches!(
            &task.state, ReviewTaskState::Held { holder } if holder == &actor.principal
        ),
    }
}

fn review_task_state(
    state: &str,
    holder_issuer: Option<String>,
    holder_subject: Option<String>,
) -> Result<ReviewTaskState, ReviewRuntimeError> {
    match state {
        "open" => Ok(ReviewTaskState::Open),
        "claimed" => Ok(ReviewTaskState::Held {
            holder: IssuerPrincipal {
                issuer: holder_issuer.ok_or(ReviewRuntimeError::Corrupt)?,
                subject: holder_subject.ok_or(ReviewRuntimeError::Corrupt)?,
            },
        }),
        "decided" | "closed" => Ok(ReviewTaskState::Decided),
        _ => Err(ReviewRuntimeError::Corrupt),
    }
}

fn staffing_diagnostic_from_row(
    row: &Row,
) -> Result<Option<StaffingDiagnostic>, ReviewRuntimeError> {
    // Older runtime versions could retain this notice after task closure.
    // It describes current unheld work, never a held or terminal task.
    if row.get::<_, String>("state") != "open" {
        return Ok(None);
    }
    match row
        .get::<_, Option<String>>("staffing_diagnostic")
        .as_deref()
    {
        None => Ok(None),
        Some("no-cover-available") => Ok(Some(StaffingDiagnostic::NoCoverAvailable)),
        Some(_) => Err(ReviewRuntimeError::Corrupt),
    }
}

fn reviewer_task_from_row(
    row: &Row,
    policy: &ReviewPolicyClosure,
) -> Result<ReviewTask, ReviewRuntimeError> {
    let stage_index =
        u16::try_from(row.get::<_, i32>(2)).map_err(|_| ReviewRuntimeError::Corrupt)?;
    let stage = policy
        .stages
        .get(usize::from(stage_index))
        .ok_or(ReviewRuntimeError::Corrupt)?;
    let state = review_task_state(&row.get::<_, String>(5), row.get(6), row.get(7))?;
    Ok(ReviewTask {
        subject: SubjectBinding {
            source: row.get("subject_source"),
            subject_type: row.get("subject_type"),
            id: row.get("subject_id"),
            version: row.get("subject_version"),
            digest: ContentDigest::parse(&row.get::<_, String>("subject_digest"))
                .map_err(|_| ReviewRuntimeError::Corrupt)?,
        },
        requester_reference: row.get("requester_reference"),
        deadline_at: row.get("deadline_at"),
        created_at: row.get("created_at"),
        display_reference: None,
        task_id: row.get(0),
        request_id: row.get(1),
        stage_index,
        stage_id: row.get(3),
        queue: row.get(4),
        revision: row.get(8),
        eligible_profiles: stage.deciding_profiles.clone(),
        state,
        staffing_diagnostic: staffing_diagnostic_from_row(row)?,
        decided_by_caller: None,
        decision_receipt: None,
    })
}

async fn load_result(
    transaction: &Transaction<'_>,
    record: &ReviewRequestRecord,
) -> Result<ReviewResult, ReviewRuntimeError> {
    let row = transaction
        .query_opt(
            "SELECT result_id,status,outcome,result,completed_at,available_until,public_reason
             FROM casework_review_results WHERE request_id=$1",
            &[&record.request_id],
        )
        .await?
        .ok_or(ReviewRuntimeError::Corrupt)?;
    result_from_row(&row, record)
}

fn result_from_row(
    row: &Row,
    record: &ReviewRequestRecord,
) -> Result<ReviewResult, ReviewRuntimeError> {
    let result = ReviewResult {
        result_id: row.get(0),
        request_id: record.request_id,
        subject: record.subject.clone(),
        policy: policy_binding(&record.policy),
        submission_digest: record.submission_digest.clone(),
        status: parse_result_status(&row.get::<_, String>(1))?,
        outcome: row.get(2),
        public_reason: row.get(6),
        result: row.get(3),
        completed_at: row.get(4),
        available_until: row.get(5),
    };
    result.check().map_err(|_| ReviewRuntimeError::Corrupt)?;
    Ok(result)
}

async fn load_decisions(
    transaction: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Vec<Decision>, ReviewRuntimeError> {
    transaction
        .query(
            "SELECT d.task_id,t.stage_id,d.actor_issuer,d.actor_subject,d.profile_id,d.decision,
                    d.outcome,d.result,d.private_reason,d.public_reason
             FROM casework_review_decisions d
             JOIN casework_review_tasks t ON t.task_id=d.task_id
             WHERE d.request_id=$1 ORDER BY d.decided_at,d.decision_id",
            &[&request_id],
        )
        .await?
        .into_iter()
        .map(|row| {
            let decision = match row.get::<_, String>(5).as_str() {
                "approve" => DecisionKind::Approve {
                    outcome: row
                        .get::<_, Option<String>>(6)
                        .ok_or(ReviewRuntimeError::Corrupt)?,
                    public_reason: row.get(9),
                },
                "reject" => DecisionKind::Reject {
                    outcome: row
                        .get::<_, Option<String>>(6)
                        .ok_or(ReviewRuntimeError::Corrupt)?,
                    reason: row.get::<_, Option<String>>(8),
                    public_reason: row.get(9),
                    result: row.get(7),
                },
                "changes-requested" => DecisionKind::ChangesRequested {
                    outcome: row
                        .get::<_, Option<String>>(6)
                        .ok_or(ReviewRuntimeError::Corrupt)?,
                    reason: row.get::<_, Option<String>>(8),
                    public_reason: row.get(9),
                    result: row.get(7),
                },
                "answer" => DecisionKind::Answer {
                    outcome: row
                        .get::<_, Option<String>>(6)
                        .ok_or(ReviewRuntimeError::Corrupt)?,
                    reason: row.get(8),
                    public_reason: row.get(9),
                    result: row.get(7),
                },
                _ => return Err(ReviewRuntimeError::Corrupt),
            };
            Ok(Decision {
                task_id: row.get(0),
                request_id,
                stage_id: row.get(1),
                reviewer: IssuerPrincipal {
                    issuer: row.get(2),
                    subject: row.get(3),
                },
                profile_id: row.get(4),
                decision,
            })
        })
        .collect()
}

async fn ensure_review_identity_eligible(
    transaction: &Transaction<'_>,
    record: &ReviewRequestRecord,
    stage: &ReviewStagePolicy,
    stage_index: u16,
    person: &IssuerPrincipal,
    queue: &str,
    membership_kinds: &[String],
) -> Result<(), ReviewRuntimeError> {
    if stage.exclude_initiator && record.initiator.as_ref() == Some(person) {
        return Err(ReviewRuntimeError::Forbidden);
    }
    if transaction
        .query_opt(
            "SELECT 1 FROM casework_review_decisions
             WHERE request_id=$1 AND actor_issuer=$2 AND actor_subject=$3
               AND (stage_index=$4 OR ($5 AND stage_index<$4)) LIMIT 1",
            &[
                &record.request_id,
                &person.issuer,
                &person.subject,
                &i32::from(stage_index),
                &stage.exclude_previous_stage_reviewers,
            ],
        )
        .await?
        .is_some()
    {
        return Err(ReviewRuntimeError::Forbidden);
    }
    if transaction
        .query_opt(
            "SELECT 1 FROM casework_queue_service q
             JOIN casework_memberships m ON m.team_id=q.team_id
             WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3
               AND m.membership_kind=ANY($4) FOR KEY SHARE OF q,m",
            &[&queue, &person.issuer, &person.subject, &membership_kinds],
        )
        .await?
        .is_none()
    {
        return Err(ReviewRuntimeError::Forbidden);
    }
    Ok(())
}

async fn ensure_actor_serves_review_queue(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    queue: &str,
) -> Result<(), ReviewRuntimeError> {
    let membership_kind = match actor.role {
        CaseworkRole::Staff => "staff",
        CaseworkRole::Supervisor => "supervisor",
        CaseworkRole::Administrator | CaseworkRole::Requester => {
            return Err(ReviewRuntimeError::Forbidden);
        }
    };
    if transaction
        .query_opt(
            "SELECT 1 FROM casework_queue_service q
             JOIN casework_memberships m ON m.team_id=q.team_id
             WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3
               AND m.membership_kind=$4 FOR KEY SHARE OF q,m",
            &[
                &queue,
                &actor.principal.issuer,
                &actor.principal.subject,
                &membership_kind,
            ],
        )
        .await?
        .is_none()
    {
        return Err(ReviewRuntimeError::Forbidden);
    }
    Ok(())
}

async fn active_review_absences(
    transaction: &Transaction<'_>,
    person: &IssuerPrincipal,
    now: DateTime<Utc>,
) -> Result<Vec<AbsenceRecord>, ReviewRuntimeError> {
    let rows = transaction
        .query(
            "WITH RECURSIVE chain(
                absence_id,person_issuer,person_subject,starts_at,ends_at,
                cover_issuer,cover_subject,revision,depth
             ) AS (
                SELECT absence_id,person_issuer,person_subject,starts_at,ends_at,
                       cover_issuer,cover_subject,revision,1
                FROM casework_absences
                WHERE person_issuer=$1 AND person_subject=$2 AND starts_at<=$3 AND $3<ends_at
                UNION ALL
                SELECT a.absence_id,a.person_issuer,a.person_subject,a.starts_at,a.ends_at,
                       a.cover_issuer,a.cover_subject,a.revision,c.depth+1
                FROM casework_absences a JOIN chain c
                  ON a.person_issuer=c.cover_issuer AND a.person_subject=c.cover_subject
                WHERE a.starts_at<=$3 AND $3<a.ends_at AND c.depth<101
             )
             SELECT absence_id,person_issuer,person_subject,starts_at,ends_at,
                    cover_issuer,cover_subject,revision,depth
             FROM chain ORDER BY depth,starts_at,absence_id LIMIT 102",
            &[&person.issuer, &person.subject, &now],
        )
        .await?;
    if rows.len() > 101 || rows.iter().any(|row| row.get::<_, i32>(8) >= 101) {
        return Err(ReviewRuntimeError::Corrupt);
    }
    rows.into_iter()
        .map(|row| {
            Ok(AbsenceRecord {
                absence_id: row.get(0),
                person: IssuerPrincipal {
                    issuer: row.get(1),
                    subject: row.get(2),
                },
                from: row.get(3),
                until: row.get(4),
                cover: IssuerPrincipal {
                    issuer: row.get(5),
                    subject: row.get(6),
                },
                revision: row.get(7),
            })
        })
        .collect()
}

fn accepted(record: &ReviewRequestRecord) -> ReviewRequestAccepted {
    ReviewRequestAccepted {
        request_id: record.request_id,
        subject: record.subject.clone(),
        policy: policy_binding(&record.policy),
        submission_digest: record.submission_digest.clone(),
    }
}

fn request_view(record: &ReviewRequestRecord) -> ReviewRequestView {
    ReviewRequestView {
        request_id: record.request_id,
        subject: record.subject.clone(),
        policy: policy_binding(&record.policy),
        submission_digest: record.submission_digest.clone(),
        requester_reference: record.requester_reference.clone(),
        lifecycle: record.lifecycle,
        active_stage: record
            .active_stage
            .and_then(|index| record.policy.stages.get(usize::from(index)))
            .map(|stage| stage.id.clone()),
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn review_decision_receipt(
    policy: &ReviewPolicyClosure,
    decision: &str,
    outcome: Option<String>,
    decided_at: DateTime<Utc>,
) -> Result<ReviewDecisionReceipt, ReviewRuntimeError> {
    let decision = match decision {
        "approve" if outcome.is_some() => ReviewDecisionType::Approve,
        "reject" if outcome.is_some() => ReviewDecisionType::Reject,
        "changes-requested" if outcome.is_some() => ReviewDecisionType::ChangesRequested,
        "answer" if outcome.is_some() => ReviewDecisionType::Answer,
        _ => return Err(ReviewRuntimeError::Corrupt),
    };
    let outcome_label = outcome
        .as_ref()
        .map(|id| {
            policy
                .outcomes
                .iter()
                .find(|configured| &configured.id == id)
                .map(|configured| configured.label.clone())
                .ok_or(ReviewRuntimeError::Corrupt)
        })
        .transpose()?;
    Ok(ReviewDecisionReceipt {
        policy: policy_binding(policy),
        decision,
        outcome,
        outcome_label,
        decided_at,
    })
}

fn policy_binding(policy: &ReviewPolicyClosure) -> PolicyBinding {
    PolicyBinding {
        id: policy.identity.id.clone(),
        version: policy.identity.version.clone(),
        digest: policy.identity.digest.clone(),
    }
}

// The review clock driver and the review preflight gate on the same source
// facts: an authoritative observation is usable only while it still describes
// the pinned occurrence the request was created against and the source
// reports live work. Superseded and cancelled occurrences refuse the
// operation, and a still-synchronizing occurrence refuses it because the
// source has not finished publishing the work. A completed occurrence stays
// reviewable, because Casework's bounded retention intentionally accepts
// fresh reviews for settled proposals and the source's pinned correlation,
// not this gate, refuses their results.

fn review_submission_binding_digest(producer_id: &str, request: &ReviewCreateRequest) -> String {
    ContentDigest::for_bytes(
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            producer_id,
            request.subject.source,
            request.subject.subject_type,
            request.subject.id,
            request.subject.version,
            request.policy.id
        )
        .as_bytes(),
    )
    .to_string()
}

fn review_producer_tombstone(
    request_id: Uuid,
    producer_id: &str,
    issuer: &str,
    subject: &str,
) -> String {
    review_identity_tombstone(
        b"registry-casework-review-producer-tombstone/v1\0",
        request_id,
        &[producer_id, issuer, subject],
    )
}

fn review_initiator_tombstone(request_id: Uuid, issuer: &str, subject: &str) -> String {
    review_identity_tombstone(
        b"registry-casework-review-initiator-tombstone/v1\0",
        request_id,
        &[issuer, subject],
    )
}

fn review_identity_tombstone(domain: &[u8], request_id: Uuid, values: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(request_id.as_bytes());
    for value in values {
        hash.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(value.as_bytes());
    }
    let digest = hash.finalize();
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn parse_lifecycle(value: &str) -> Result<ReviewRequestLifecycle, ReviewRuntimeError> {
    match value {
        "reviewing" => Ok(ReviewRequestLifecycle::Reviewing),
        "approved" => Ok(ReviewRequestLifecycle::Approved),
        "rejected" => Ok(ReviewRequestLifecycle::Rejected),
        "changes-requested" => Ok(ReviewRequestLifecycle::ChangesRequested),
        "answered" => Ok(ReviewRequestLifecycle::Answered),
        "cancelled" => Ok(ReviewRequestLifecycle::Cancelled),
        "superseded" => Ok(ReviewRequestLifecycle::Superseded),
        _ => Err(ReviewRuntimeError::Corrupt),
    }
}

fn parse_result_status(value: &str) -> Result<ReviewResultStatus, ReviewRuntimeError> {
    match value {
        "approved" => Ok(ReviewResultStatus::Approved),
        "rejected" => Ok(ReviewResultStatus::Rejected),
        "changes-requested" => Ok(ReviewResultStatus::ChangesRequested),
        "answered" => Ok(ReviewResultStatus::Answered),
        "cancelled" => Ok(ReviewResultStatus::Cancelled),
        "superseded" => Ok(ReviewResultStatus::Superseded),
        _ => Err(ReviewRuntimeError::Corrupt),
    }
}

fn result_status_name(value: ReviewResultStatus) -> &'static str {
    match value {
        ReviewResultStatus::Approved => "approved",
        ReviewResultStatus::Rejected => "rejected",
        ReviewResultStatus::ChangesRequested => "changes-requested",
        ReviewResultStatus::Answered => "answered",
        ReviewResultStatus::Cancelled => "cancelled",
        ReviewResultStatus::Superseded => "superseded",
    }
}

/// The stored columns of a decision: its name, outcome, structured result,
/// private reason, and public reason.
type DecisionColumns = (
    &'static str,
    Option<String>,
    Option<Value>,
    Option<String>,
    Option<String>,
);

fn decision_columns(decision: &DecisionKind) -> DecisionColumns {
    match decision {
        DecisionKind::Approve {
            outcome,
            public_reason,
        } => (
            "approve",
            Some(outcome.clone()),
            None,
            None,
            public_reason.clone(),
        ),
        DecisionKind::Reject {
            outcome,
            reason,
            public_reason,
            result,
        } => (
            "reject",
            Some(outcome.clone()),
            result.clone(),
            reason.clone(),
            public_reason.clone(),
        ),
        DecisionKind::ChangesRequested {
            outcome,
            reason,
            public_reason,
            result,
        } => (
            "changes-requested",
            Some(outcome.clone()),
            result.clone(),
            reason.clone(),
            public_reason.clone(),
        ),
        DecisionKind::Answer {
            outcome,
            reason,
            public_reason,
            result,
        } => (
            "answer",
            Some(outcome.clone()),
            result.clone(),
            reason.clone(),
            public_reason.clone(),
        ),
    }
}

fn settlement_columns(
    settlement: &ReviewSettlement,
) -> (
    ReviewResultStatus,
    Option<String>,
    Option<String>,
    Option<Value>,
) {
    match settlement {
        ReviewSettlement::Approved {
            outcome,
            public_reason,
        } => (
            ReviewResultStatus::Approved,
            Some(outcome.clone()),
            public_reason.clone(),
            None,
        ),
        ReviewSettlement::Rejected {
            outcome,
            public_reason,
            result,
        } => (
            ReviewResultStatus::Rejected,
            Some(outcome.clone()),
            public_reason.clone(),
            result.clone(),
        ),
        ReviewSettlement::ChangesRequested {
            outcome,
            public_reason,
            result,
        } => (
            ReviewResultStatus::ChangesRequested,
            Some(outcome.clone()),
            public_reason.clone(),
            result.clone(),
        ),
        ReviewSettlement::Answered {
            outcome,
            public_reason,
            result,
        } => (
            ReviewResultStatus::Answered,
            Some(outcome.clone()),
            public_reason.clone(),
            result.clone(),
        ),
    }
}

fn transition_kind(transition: &ReviewTransition) -> &'static str {
    match transition {
        ReviewTransition::Recorded { .. } => "recorded",
        ReviewTransition::StageAdvanced { .. } => "stage-advanced",
        ReviewTransition::Settled { settlement } => match settlement {
            ReviewSettlement::Approved { .. } => "approved",
            ReviewSettlement::Rejected { .. } => "rejected",
            ReviewSettlement::ChangesRequested { .. } => "changes-requested",
            ReviewSettlement::Answered { .. } => "answered",
        },
    }
}

fn require_human_reviewer(actor: &ActorContext) -> Result<(), ReviewRuntimeError> {
    matches!(
        actor.role,
        registry_casework_core::CaseworkRole::Staff
            | registry_casework_core::CaseworkRole::Supervisor
    )
    .then_some(())
    .ok_or(ReviewRuntimeError::Forbidden)
}

fn ensure_review_result_retained(record: &ReviewRequestRecord) -> Result<(), ReviewRuntimeError> {
    if record.lifecycle != ReviewRequestLifecycle::Reviewing
        && (record.result_erased_at.is_some()
            || record
                .result_available_until
                .is_none_or(|available_until| available_until <= Utc::now()))
    {
        return Err(ReviewRuntimeError::ResultExpired);
    }
    Ok(())
}

async fn ensure_review_reviewer_access(
    client: &impl GenericClient,
    record: &ReviewRequestRecord,
    actor: &ActorContext,
    task_id: Option<Uuid>,
    lock_membership: bool,
) -> Result<(), ReviewRuntimeError> {
    let membership = match actor.role {
        CaseworkRole::Staff => "staff",
        CaseworkRole::Supervisor => "supervisor",
        CaseworkRole::Administrator | CaseworkRole::Requester => {
            return Err(ReviewRuntimeError::Forbidden);
        }
    };
    let eligible_stages = record
        .policy
        .stages
        .iter()
        .enumerate()
        .filter(|(_, stage)| stage.deciding_profiles.contains(&actor.profile_id))
        .map(|(index, _)| i32::try_from(index).map_err(|_| ReviewRuntimeError::Corrupt))
        .collect::<Result<Vec<_>, _>>()?;
    if eligible_stages.is_empty() {
        return Err(ReviewRuntimeError::NotFound);
    }
    let lock = if lock_membership {
        " FOR KEY SHARE OF m,q,t"
    } else {
        ""
    };
    let query = format!(
        "SELECT 1 FROM casework_review_tasks t
         JOIN casework_queue_service q ON q.queue_id=t.queue_id
         JOIN casework_memberships m ON m.team_id=q.team_id
         WHERE t.request_id=$1 AND t.stage_index=ANY($2)
           AND m.issuer=$3 AND m.subject=$4 AND m.membership_kind=$5
           AND ($6::uuid IS NULL OR t.task_id=$6) LIMIT 1{lock}"
    );
    client
        .query_opt(
            &query,
            &[
                &record.request_id,
                &eligible_stages,
                &actor.principal.issuer,
                &actor.principal.subject,
                &membership,
                &task_id,
            ],
        )
        .await?
        .ok_or(ReviewRuntimeError::NotFound)?;
    Ok(())
}

async fn ensure_review_mutation_actor_authorized(
    transaction: &impl GenericClient,
    record: &ReviewRequestRecord,
    actor: &ActorContext,
    task_id: Uuid,
) -> Result<(), ReviewRuntimeError> {
    match ensure_review_reviewer_access(transaction, record, actor, Some(task_id), true).await {
        Err(ReviewRuntimeError::NotFound) => Err(ReviewRuntimeError::Forbidden),
        result => result,
    }
}

fn review_clock_from_row(row: &Row) -> Result<ReviewClockOccurrence, ReviewRuntimeError> {
    let correlation = match row.get::<_, String>(3).as_str() {
        "subject" => ReviewClockCorrelation::Subject {
            source: row.get(4),
            subject_type: row.get(5),
            id: row.get(6),
        },
        "activity" => ReviewClockCorrelation::Activity {
            task_id: row
                .get::<_, Option<Uuid>>(7)
                .ok_or(ReviewRuntimeError::Corrupt)?,
            stage_id: row
                .get::<_, Option<String>>(8)
                .ok_or(ReviewRuntimeError::Corrupt)?,
        },
        _ => return Err(ReviewRuntimeError::Corrupt),
    };
    let state = match row.get::<_, String>(9).as_str() {
        "running" => ReviewClockState::Running,
        "paused" => ReviewClockState::Paused,
        "completed" => ReviewClockState::Completed,
        "cancelled" => ReviewClockState::Cancelled,
        "source-facts-missing" => ReviewClockState::SourceFactsMissing,
        _ => return Err(ReviewRuntimeError::Corrupt),
    };
    Ok(ReviewClockOccurrence {
        clock_occurrence_id: row.get(0),
        clock_id: row.get(1),
        request_id: row.get(2),
        correlation,
        state,
        policy_digest: ContentDigest::parse(&row.get::<_, String>(10))
            .map_err(|_| ReviewRuntimeError::Corrupt)?,
        anchor_at: row.get(11),
        due_at: row.get(12),
        at_risk_at: row.get(13),
        completed_at: row.get(14),
    })
}

pub(crate) fn actor_reference(actor: &IssuerPrincipal) -> String {
    let mut hash = Sha256::new();
    hash.update(actor.issuer.as_bytes());
    hash.update([0]);
    hash.update(actor.subject.as_bytes());
    let digest = hash.finalize();
    format!(
        "actor_{}",
        digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn map_reviewer_conflict(error: tokio_postgres::Error) -> ReviewRuntimeError {
    if error
        .as_db_error()
        .is_some_and(|error| error.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
    {
        ReviewRuntimeError::Forbidden
    } else {
        ReviewRuntimeError::Store(StoreError::Postgres(error))
    }
}

fn map_review_source_error(error: ReviewContextError) -> ReviewRuntimeError {
    match error {
        ReviewContextError::Unavailable => ReviewRuntimeError::SourceUnavailable,
        ReviewContextError::Invalid | ReviewContextError::Unsupported => {
            ReviewRuntimeError::SourceInvalid
        }
        _ => ReviewRuntimeError::NotFound,
    }
}

fn map_review_context_source_error(error: ReviewContextError) -> ReviewRuntimeError {
    match error {
        ReviewContextError::Concealed
        | ReviewContextError::Denied
        | ReviewContextError::BindingMoved
        | ReviewContextError::ContractChanged => ReviewRuntimeError::NotFound,
        other => map_review_source_error(other),
    }
}

fn review_request_hash<T: Serialize>(value: &T) -> Result<String, ReviewRuntimeError> {
    let value = serde_json::to_value(value)?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| ReviewRuntimeError::Invalid)?;
    Ok(ContentDigest::for_bytes(&bytes).to_string())
}

async fn review_idempotent_response(
    transaction: &Transaction<'_>,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    request_hash: &str,
) -> Result<Option<Value>, ReviewRuntimeError> {
    if key.is_empty() || key.len() > 256 {
        return Err(ReviewRuntimeError::Invalid);
    }
    let row = transaction
        .query_opt(
            "SELECT request_hash,response FROM casework_idempotency
             WHERE issuer=$1 AND subject=$2 AND profile_id=$3 AND operation=$4
               AND resource=$5 AND idempotency_key=$6 FOR UPDATE",
            &[
                &actor.principal.issuer,
                &actor.principal.subject,
                &actor.profile_id,
                &operation,
                &resource,
                &key,
            ],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != request_hash {
        return Err(ReviewRuntimeError::IdempotencyConflict);
    }
    row.get::<_, Option<Value>>(1)
        .ok_or(ReviewRuntimeError::IdempotencyExpired)
        .map(Some)
}

#[allow(clippy::too_many_arguments)]
async fn insert_review_idempotency(
    transaction: &Transaction<'_>,
    review_request_id: Uuid,
    actor: &ActorContext,
    operation: &str,
    resource: &str,
    key: &str,
    request_hash: &str,
    response: &Value,
) -> Result<(), ReviewRuntimeError> {
    transaction
        .execute(
            "INSERT INTO casework_idempotency(
                issuer,subject,profile_id,operation,resource,idempotency_key,
                request_hash,response,created_at,review_request_id)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &actor.principal.issuer,
                &actor.principal.subject,
                &actor.profile_id,
                &operation,
                &resource,
                &key,
                &request_hash,
                &response,
                &Utc::now(),
                &review_request_id,
            ],
        )
        .await
        .map_err(|error| {
            if error.as_db_error().is_some_and(|error| {
                error.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION
            }) {
                ReviewRuntimeError::IdempotencyConflict
            } else {
                ReviewRuntimeError::Store(StoreError::Postgres(error))
            }
        })?;
    Ok(())
}

impl CaseworkService {
    pub(crate) async fn preflight_review_grant_human(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile: Option<&str>,
        token: &str,
    ) -> Result<(), crate::ServiceError> {
        self.review_task(actor, task_id, source_profile, token)
            .await
            .map(|_| ())
            .map_err(review_service_error)
    }
    pub(crate) async fn review_grant_fields(
        &self,
        task_id: Uuid,
        revision: i64,
        fields: &[String],
    ) -> Result<std::collections::BTreeMap<String, Value>, crate::ServiceError> {
        let record = self
            .store
            .review_request_for_task(task_id)
            .await
            .map_err(review_service_error)?;
        match (&record.policy.context, record.context.as_ref()) {
            (ReviewContextPolicy::Submitted, Some(ReviewContext::Submitted { snapshot })) => fields
                .iter()
                .map(|field| {
                    snapshot
                        .get(field)
                        .cloned()
                        .map(|value| (field.clone(), value))
                        .ok_or(crate::ServiceError::Forbidden)
                })
                .collect(),
            (
                ReviewContextPolicy::CurrentSource { provider, contract },
                Some(ReviewContext::CurrentSource { .. }),
            ) => {
                let provider = self
                    .providers
                    .get(provider)
                    .ok_or(crate::ServiceError::Context(
                        ReviewContextError::Unavailable,
                    ))?;
                if fields.is_empty() {
                    let expected = ReviewContextIdentity {
                        subject: record.subject.clone(),
                        contract: contract.clone(),
                    };
                    let observed = tokio::time::timeout(
                        Duration::from_millis(
                            record.policy.dependencies.inbox.page_deadline_milliseconds,
                        ),
                        provider.service_status(&expected),
                    )
                    .await
                    .map_err(|_| crate::ServiceError::Context(ReviewContextError::Unavailable))??;
                    if observed.identity != expected {
                        return Err(ReviewContextError::Invalid.into());
                    }
                    if !observed.reviewable {
                        return Err(crate::ServiceError::Forbidden);
                    }
                    return Ok(Default::default());
                }
                let expected = ServiceContextRequest {
                    identity: ReviewContextIdentity {
                        subject: record.subject.clone(),
                        contract: contract.clone(),
                    },
                    request_id: record.request_id,
                    task_id,
                    task_revision: revision,
                    policy: policy_binding(&record.policy),
                    purpose: "task-grant-recheck".to_owned(),
                    fields: fields.to_vec(),
                };
                let observed = tokio::time::timeout(
                    Duration::from_millis(
                        record.policy.dependencies.inbox.page_deadline_milliseconds,
                    ),
                    provider.task_grant_context(&expected),
                )
                .await
                .map_err(|_| crate::ServiceError::Context(ReviewContextError::Unavailable))??;
                observed.check(&expected)?;
                if !observed.reviewable {
                    return Err(crate::ServiceError::Forbidden);
                }
                Ok(observed.fields)
            }
            _ => Err(crate::ServiceError::Store(StoreError::Corrupt)),
        }
    }
}
fn review_service_error(error: ReviewRuntimeError) -> crate::ServiceError {
    match error {
        ReviewRuntimeError::Store(error) => error.into(),
        ReviewRuntimeError::SourceUnavailable => ReviewContextError::Unavailable.into(),
        ReviewRuntimeError::SourceInvalid => ReviewContextError::Invalid.into(),
        ReviewRuntimeError::NotFound | ReviewRuntimeError::ResultExpired => {
            crate::ServiceError::NotFound
        }
        ReviewRuntimeError::RevisionConflict => StoreError::Conflict.into(),
        _ => crate::ServiceError::Forbidden,
    }
}

async fn refresh_review_deadlines(
    tx: &Transaction<'_>,
    request_id: Uuid,
) -> Result<(), ReviewRuntimeError> {
    tx.execute("UPDATE casework_review_tasks t SET deadline_at=(SELECT min(c.due_at) FROM casework_review_clock_occurrences c WHERE c.request_id=t.request_id AND (c.task_id=t.task_id OR c.scope='subject') AND c.state IN('running','source-facts-missing')) WHERE t.request_id=$1 AND t.state IN('open','claimed')",&[&request_id]).await?;
    Ok(())
}

fn invalid_provider_display(
    policy: &ReviewPolicyClosure,
    error: ReviewDecisionValidationError,
) -> ReviewRuntimeError {
    let ReviewDecisionValidationError::Structured(error) = error else {
        return ReviewRuntimeError::Corrupt;
    };
    let reason = serde_json::to_value(error.reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "invalid".into());
    tracing::warn!(review_policy=%policy.identity.id,validation_reason=%reason,"Casework context provider returned invalid display");
    ReviewRuntimeError::SourceInvalid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_references_are_stable_and_issuer_qualified() {
        let first = IssuerPrincipal {
            issuer: "https://issuer-a.example".to_owned(),
            subject: "person".to_owned(),
        };
        let second = IssuerPrincipal {
            issuer: "https://issuer-b.example".to_owned(),
            subject: "person".to_owned(),
        };
        assert_eq!(actor_reference(&first), actor_reference(&first));
        assert_ne!(actor_reference(&first), actor_reference(&second));
        assert!(!actor_reference(&first).contains("person"));
    }
}
