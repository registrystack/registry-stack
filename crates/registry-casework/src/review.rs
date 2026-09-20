use chrono::{DateTime, TimeDelta, Utc};
use deadpool_postgres::GenericClient;
use registry_casework_core::{
    evaluate_activity_clock, record_review_decision, resolve_absence_cover, submission_digest,
    AbsenceRecord, ActorContext, AssignmentRequest, CalendarPolicy, CaseworkRole, ClockPolicy,
    ContentDigest, DelegateRequest, EphemeralCredential, HolidaySetDocument, IssuerPrincipal,
    PolicyBinding, ReminderOccurrence, ReviewAccountabilityRecord, ReviewCancelRequest,
    ReviewCancelResponse, ReviewClockCorrelation, ReviewClockOccurrence, ReviewClockState,
    ReviewCreateRequest, ReviewHistoryAudience, ReviewHistoryEntry, ReviewHistoryPage,
    ReviewKindPolicySnapshot, ReviewNoteRequest, ReviewProgress, ReviewRequestAccepted,
    ReviewRequestLifecycle, ReviewRequestView, ReviewResult, ReviewResultFeedEntry,
    ReviewResultFeedPage, ReviewResultStatus, ReviewSettlement, ReviewSourceBindingStatus,
    ReviewSourceProjection, ReviewStagePolicy, ReviewTaskContext, ReviewTaskContextData,
    ReviewTaskDraft, ReviewTaskDraftInput, ReviewTaskPage, ReviewTransition, ReviewerDecision,
    ReviewerDecisionKind, ReviewerTask, ReviewerTaskState, SourceAdapterError,
    SourceContextBinding, StepOccurrence, SubjectBinding, SubjectRef,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::{CaseworkService, PostgresStore, StoreError};

const MAXIMUM_REVIEW_FEED_PAGE: usize = 100;
const MAXIMUM_REVIEW_DRAFT_BYTES: usize = 16 * 1024;
const REVIEW_RETENTION_BATCH_SIZE: i64 = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewCreateOutcome {
    pub accepted: ReviewRequestAccepted,
    pub recovered: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewResultRead {
    Available(Box<ReviewResult>),
    Pending,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskDecisionRequest {
    pub decision: ReviewerDecisionKind,
}

#[derive(Clone, Debug)]
pub(crate) struct LeasedReviewCompletion {
    pub event: registry_casework_core::ReviewCompletion,
    pub destination_id: String,
    pub recipient_binding: String,
}

#[derive(Debug, Error)]
pub enum ReviewRuntimeError {
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
    #[error("the review resource revision changed")]
    RevisionConflict,
    #[error("the idempotency key was reused with different review input")]
    IdempotencyConflict,
    #[error("the retained idempotency response expired")]
    IdempotencyExpired,
    #[error("the review input is invalid")]
    Invalid,
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

#[derive(Clone)]
struct ProducerAdmission {
    producer: registry_casework_core::ReviewProducerPolicy,
}

#[derive(Clone)]
struct ReviewRequestRecord {
    request_id: Uuid,
    producer_id: String,
    subject: SubjectBinding,
    requester_reference: String,
    policy: ReviewKindPolicySnapshot,
    submission_digest: ContentDigest,
    lifecycle: ReviewRequestLifecycle,
    active_stage: Option<u16>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    result_available_until: Option<DateTime<Utc>>,
    initiator: Option<IssuerPrincipal>,
    result_constraints: Option<Value>,
    context: Option<registry_casework_core::ReviewContext>,
}

impl CaseworkService {
    pub async fn erase_expired_reviews(&self) -> Result<u64, ReviewRuntimeError> {
        self.store.erase_expired_reviews_at(Utc::now()).await
    }

    pub async fn process_due_review_clocks(
        &self,
        maximum: usize,
    ) -> Result<usize, ReviewRuntimeError> {
        let candidates = self.store.due_review_clock_tasks(maximum).await?;
        let mut verified = Vec::with_capacity(candidates.len());
        for task_id in candidates {
            let record = self.store.review_request_for_task(task_id).await?;
            let current =
                match record.policy.context_strategy {
                    registry_casework_core::ReviewContextStrategy::Submitted => true,
                    registry_casework_core::ReviewContextStrategy::Source => {
                        let subject = SubjectRef {
                            source_id: record.subject.source.clone(),
                            kind: record.subject.subject_type.clone(),
                            id: record.subject.id.clone(),
                        };
                        match self.adapters.get(&subject.source_id) {
                            Some(adapter) => adapter.read_authoritative(&subject).await.is_ok_and(
                                |observation| {
                                    observation.subject == subject
                                    && observation.binding.version == record.subject.version
                                    && observation.binding.integrity.as_deref()
                                        == Some(record.subject.digest.as_str())
                                    && observation.state.is_active()
                                    && observation.state
                                        != registry_casework_core::OccurrenceState::Synchronizing
                                },
                            ),
                            None => false,
                        }
                    }
                };
            if current {
                verified.push(task_id);
            } else {
                self.store.defer_review_clock_task(task_id).await?;
            }
        }
        self.store
            .process_due_review_clocks(maximum, &verified)
            .await
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
        if let Some(recovered) = self
            .store
            .recover_review(
                &admission.producer.id,
                actor,
                &request,
                &digest,
                idempotency_key,
            )
            .await?
        {
            return Ok(recovered);
        }
        let policy = self
            .project
            .review_kinds
            .iter()
            .find(|policy| policy.id == request.kind)
            .ok_or(ReviewRuntimeError::Forbidden)?;
        let snapshot = policy.snapshot().map_err(|_| ReviewRuntimeError::Corrupt)?;
        let requires_initiator = snapshot.stages.iter().any(|stage| stage.exclude_initiator);
        match (
            request.initiator.as_ref(),
            admission.producer.trusted_initiator_issuer.as_deref(),
        ) {
            (Some(initiator), Some(issuer)) if initiator.issuer == issuer => {}
            (None, _) if !requires_initiator => {}
            _ => return Err(ReviewRuntimeError::Invalid),
        }
        match (&snapshot.context_strategy, &request.context) {
            (
                registry_casework_core::ReviewContextStrategy::Submitted,
                registry_casework_core::ReviewContext::Submitted { snapshot: display },
            ) => snapshot
                .validate_display(display)
                .map_err(|_| ReviewRuntimeError::Invalid)?,
            (
                registry_casework_core::ReviewContextStrategy::Source,
                registry_casework_core::ReviewContext::Source { .. },
            ) => {}
            _ => return Err(ReviewRuntimeError::Invalid),
        }
        if let Some(constraints) = &request.result_constraints {
            snapshot
                .validate_result_constraints(constraints)
                .map_err(|_| ReviewRuntimeError::Invalid)?;
        }
        let initiator = request.initiator.as_ref().map(|person| IssuerPrincipal {
            issuer: person.issuer.clone(),
            subject: person.subject.clone(),
        });
        let clocks = snapshot
            .clocks
            .iter()
            .map(|clock_id| {
                let clock = self
                    .project
                    .clocks
                    .iter()
                    .find(|clock| clock.id() == clock_id)
                    .cloned()
                    .ok_or(ReviewRuntimeError::Corrupt)?;
                let calendar = match &clock {
                    ClockPolicy::Subject { .. } => None,
                    ClockPolicy::Activity { calendar, .. } => Some(
                        self.project
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
        self.store
            .create_review(
                &admission.producer,
                actor,
                request,
                initiator,
                snapshot,
                clocks,
                digest,
                idempotency_key,
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
            .review_request(&admission.producer.id, request_id)
            .await
    }

    pub fn review_kind_descriptions(
        &self,
        actor: &ActorContext,
    ) -> Result<Vec<ReviewKindPolicySnapshot>, ReviewRuntimeError> {
        let allowed = match actor.role {
            CaseworkRole::Requester => self.producer_for_actor(actor)?.producer.kinds,
            CaseworkRole::Staff | CaseworkRole::Supervisor => self
                .project
                .review_kinds
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
                .review_kinds
                .iter()
                .map(|kind| kind.id.clone())
                .collect(),
        };
        self.project
            .review_kinds
            .iter()
            .filter(|kind| allowed.contains(&kind.id))
            .map(|kind| kind.snapshot().map_err(|_| ReviewRuntimeError::Corrupt))
            .collect()
    }

    pub fn review_kind_description(
        &self,
        actor: &ActorContext,
        kind_id: &str,
    ) -> Result<ReviewKindPolicySnapshot, ReviewRuntimeError> {
        self.review_kind_descriptions(actor)?
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
        require_human_reviewer(actor)?;
        if limit == 0 || limit > 100 {
            return Err(ReviewRuntimeError::Invalid);
        }
        let mut scan_cursor = cursor;
        let mut items = Vec::with_capacity(limit + 1);
        let mut examined = 0usize;
        let mut continuation = None;
        while items.len() <= limit && examined < 1_000 {
            let page = self
                .store
                .review_tasks(actor, queue, scan_cursor, 100)
                .await?;
            examined += page.items.len();
            for task in page.items {
                match self
                    .preflight_review_source(task.task_id, source_profile_id, token)
                    .await
                {
                    Ok(()) => {
                        items.push(task);
                        if items.len() > limit {
                            break;
                        }
                    }
                    Err(
                        ReviewRuntimeError::Forbidden
                        | ReviewRuntimeError::NotFound
                        | ReviewRuntimeError::SourceProfileRequired
                        | ReviewRuntimeError::SourceProfileNotApplicable,
                    ) => {}
                    Err(error) => return Err(error),
                }
            }
            let Some(next_cursor) = page.next_cursor else {
                continuation = None;
                break;
            };
            if scan_cursor == Some(next_cursor) {
                return Err(ReviewRuntimeError::Corrupt);
            }
            scan_cursor = Some(next_cursor);
            continuation = Some(next_cursor);
        }
        let next_cursor = if items.len() > limit {
            Some(items[limit - 1].task_id)
        } else if examined >= 1_000 {
            continuation
        } else {
            None
        };
        items.truncate(limit);
        Ok(ReviewTaskPage { items, next_cursor })
    }

    pub async fn review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        source_profile_id: Option<&str>,
        token: &str,
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
        require_human_reviewer(actor)?;
        self.preflight_review_source(task_id, source_profile_id, token)
            .await
            .map_err(|_| ReviewRuntimeError::NotFound)?;
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
            registry_casework_core::ReviewContext::Submitted { snapshot } => {
                if source_profile_id.is_some() {
                    return Err(ReviewRuntimeError::SourceProfileNotApplicable);
                }
                ReviewTaskContextData::Submitted {
                    snapshot: snapshot.clone(),
                }
            }
            registry_casework_core::ReviewContext::Source { binding } => {
                let source_profile_id =
                    source_profile_id.ok_or(ReviewRuntimeError::SourceProfileRequired)?;
                let subject = SubjectRef {
                    source_id: record.subject.source.clone(),
                    kind: record.subject.subject_type.clone(),
                    id: record.subject.id.clone(),
                };
                let adapter = self
                    .adapters
                    .get(&subject.source_id)
                    .ok_or(ReviewRuntimeError::SourceInvalid)?;
                let view = adapter
                    .read_for_caller(&subject, source_profile_id, EphemeralCredential::new(token))
                    .await
                    .map_err(map_review_context_source_error)?;
                if view.subject != subject {
                    return Err(ReviewRuntimeError::SourceInvalid);
                }
                let current = view.binding.version == record.subject.version
                    && view.binding.integrity.as_deref() == Some(record.subject.digest.as_str());
                if current {
                    record
                        .policy
                        .validate_display(
                            &serde_json::to_value(&view.disclosed)
                                .map_err(|_| ReviewRuntimeError::SourceInvalid)?,
                        )
                        .map_err(|_| ReviewRuntimeError::SourceInvalid)?;
                }
                ReviewTaskContextData::Source {
                    reference: binding.reference.clone(),
                    binding_status: if current {
                        ReviewSourceBindingStatus::Current
                    } else {
                        ReviewSourceBindingStatus::BindingChanged
                    },
                    projection: current.then_some(ReviewSourceProjection {
                        binding: view.binding,
                        display_reference: view.display_reference,
                        display: view.disclosed,
                    }),
                }
            }
        };
        // A current team membership is required both before and after source I/O. This avoids
        // holding a database transaction across the remote read without releasing context after
        // authority was revoked while that read was in flight.
        self.store.review_task(actor, task_id).await?;
        Ok(ReviewTaskContext {
            task_id,
            request_id: record.request_id,
            subject: record.subject,
            requester_reference: record.requester_reference,
            policy: policy_binding(&record.policy),
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
            .review_result(&admission.producer.id, request_id)
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
            .review_result_feed(&admission.producer.id, cursor, limit)
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
                &admission.producer.id,
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
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
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
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
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
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
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
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
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
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewHistoryPage, ReviewRuntimeError> {
        let producer_id = if actor.role == CaseworkRole::Requester {
            Some(self.producer_for_actor(actor)?.producer.id)
        } else {
            require_human_reviewer(actor)?;
            None
        };
        self.store
            .review_history(actor, request_id, producer_id.as_deref(), cursor, limit)
            .await
    }

    pub async fn review_clocks(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
    ) -> Result<Vec<ReviewClockOccurrence>, ReviewRuntimeError> {
        let producer_id = if actor.role == CaseworkRole::Requester {
            Some(self.producer_for_actor(actor)?.producer.id)
        } else {
            require_human_reviewer(actor)?;
            None
        };
        self.store
            .review_clocks(actor, request_id, producer_id.as_deref())
            .await
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
        request: ReviewNoteRequest,
        idempotency_key: &str,
    ) -> Result<ReviewHistoryEntry, ReviewRuntimeError> {
        let producer_id = if actor.role == CaseworkRole::Requester {
            let producer_id = self.producer_for_actor(actor)?.producer.id;
            if request.audience != ReviewHistoryAudience::Requester {
                return Err(ReviewRuntimeError::Forbidden);
            }
            Some(producer_id)
        } else {
            require_human_reviewer(actor)?;
            None
        };
        self.store
            .add_review_note(
                actor,
                request_id,
                producer_id.as_deref(),
                request,
                idempotency_key,
            )
            .await
    }

    async fn review_task_membership_kinds(
        &self,
        task_id: Uuid,
    ) -> Result<Vec<String>, ReviewRuntimeError> {
        let record = self.store.review_request_for_task(task_id).await?;
        let stage = record
            .active_stage
            .and_then(|index| record.policy.stages.get(usize::from(index)))
            .ok_or(ReviewRuntimeError::NotFound)?;
        let mut kinds = stage
            .deciding_profiles
            .iter()
            .filter_map(|profile_id| {
                self.project
                    .access_profiles
                    .iter()
                    .find(|profile| profile.id == *profile_id)
                    .and_then(|profile| match profile.role {
                        CaseworkRole::Staff => Some("staff".to_owned()),
                        CaseworkRole::Supervisor => Some("supervisor".to_owned()),
                        CaseworkRole::Administrator | CaseworkRole::Requester => None,
                    })
            })
            .collect::<Vec<_>>();
        kinds.sort();
        kinds.dedup();
        (!kinds.is_empty())
            .then_some(kinds)
            .ok_or(ReviewRuntimeError::Corrupt)
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
        match record.policy.context_strategy {
            registry_casework_core::ReviewContextStrategy::Submitted => {
                if source_profile_id.is_some() {
                    return Err(ReviewRuntimeError::SourceProfileNotApplicable);
                }
                Ok(())
            }
            registry_casework_core::ReviewContextStrategy::Source => {
                let source_profile_id =
                    source_profile_id.ok_or(ReviewRuntimeError::SourceProfileRequired)?;
                let subject = SubjectRef {
                    source_id: record.subject.source.clone(),
                    kind: record.subject.subject_type.clone(),
                    id: record.subject.id.clone(),
                };
                let adapter = self
                    .adapters
                    .get(&subject.source_id)
                    .ok_or(ReviewRuntimeError::SourceInvalid)?;
                let view = adapter
                    .read_for_caller(&subject, source_profile_id, EphemeralCredential::new(token))
                    .await
                    .map_err(map_review_source_error)?;
                if view.subject != subject
                    || view.binding.version != record.subject.version
                    || view.binding.integrity.as_deref() != Some(record.subject.digest.as_str())
                {
                    return Err(ReviewRuntimeError::Forbidden);
                }
                record
                    .policy
                    .validate_display(&serde_json::to_value(&view.disclosed)?)
                    .map_err(|_| ReviewRuntimeError::Forbidden)?;
                Ok(())
            }
        }
    }

    fn producer_for_create(
        &self,
        actor: &ActorContext,
        request: &ReviewCreateRequest,
    ) -> Result<ProducerAdmission, ReviewRuntimeError> {
        let admission = self.producer_for_actor(actor)?;
        if !admission.producer.kinds.contains(&request.kind)
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
            .review_producers
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
}

impl PostgresStore {
    async fn due_review_clock_tasks(
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
                    AND (state='source_facts_missing'
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

    async fn defer_review_clock_task(&self, task_id: Uuid) -> Result<(), ReviewRuntimeError> {
        let client = self.client().await?;
        client
            .execute(
                "UPDATE casework_review_clock_occurrences
                    SET next_action_at=CASE WHEN state='running'
                            THEN transaction_timestamp()+interval '30 seconds'
                            ELSE next_action_at END,
                        updated_at=transaction_timestamp()
                  WHERE task_id=$1 AND scope='activity'
                    AND (state='source_facts_missing'
                         OR (state='running' AND next_action_at<=now()))",
                &[&task_id],
            )
            .await?;
        Ok(())
    }

    async fn process_due_review_clocks(
        &self,
        maximum: usize,
        verified_tasks: &[Uuid],
    ) -> Result<usize, ReviewRuntimeError> {
        if verified_tasks.is_empty() {
            return Ok(0);
        }
        let limit =
            i64::try_from(maximum.clamp(1, 100)).map_err(|_| ReviewRuntimeError::Invalid)?;
        let now = Utc::now();
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let rows = transaction
            .query(
                "SELECT clock_occurrence_id,request_id,task_id
                 FROM casework_review_clock_occurrences
                 WHERE scope='activity'
                   AND task_id=ANY($2)
                   AND (state='source_facts_missing'
                        OR (state='running' AND next_action_at<=now()))
                 ORDER BY COALESCE(next_action_at,updated_at),clock_occurrence_id
                 LIMIT $1",
                &[&limit, &verified_tasks],
            )
            .await?;
        let mut applied = 0usize;
        for row in rows {
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
                       AND (state='source_facts_missing'
                            OR (state='running' AND next_action_at<=$2))
                     FOR UPDATE",
                    &[&occurrence_id, &now],
                )
                .await?
            else {
                continue;
            };
            let definition: ReviewClockDefinition = serde_json::from_value(occurrence.get(0))?;
            let state: String = occurrence.get(1);
            let anchor_at: DateTime<Utc> = occurrence.get(2);
            let (_holiday_document, reminders, steps): (
                HolidaySetDocument,
                Vec<ReminderOccurrence>,
                Vec<StepOccurrence>,
            ) = if state == "source_facts_missing" {
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
                            "UPDATE casework_review_clock_occurrences SET updated_at=$2
                             WHERE clock_occurrence_id=$1 AND state='source_facts_missing'",
                            &[&occurrence_id, &now],
                        )
                        .await?;
                    continue;
                };
                let holiday: HolidaySetDocument = serde_json::from_value(holiday_row.get(0))?;
                let evaluated =
                    evaluate_activity_clock(&definition.clock, calendar, &holiday, anchor_at)
                        .map_err(|_| ReviewRuntimeError::Corrupt)?;
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
                         WHERE clock_occurrence_id=$1 AND state='source_facts_missing'",
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
                             VALUES($1,$2,$3,'clock_reminder',NULL,$4,$5)",
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
                    applied += 1;
                }
            }
            let mut prior_queue: String = task.get(1);
            for step in steps.iter().filter(|effect| effect.at <= now) {
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
                             VALUES($1,$2,$3,'clock_step_applied',NULL,$4,$5)",
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
            transaction
                .execute(
                    "UPDATE casework_review_clock_occurrences
                     SET next_action_at=$2,updated_at=$3
                     WHERE clock_occurrence_id=$1 AND state='running'",
                    &[&occurrence_id, &next_action_at, &now],
                )
                .await?;
        }
        transaction.commit().await?;
        Ok(applied)
    }

    async fn review_tasks(
        &self,
        actor: &ActorContext,
        queue: Option<&str>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewTaskPage, ReviewRuntimeError> {
        if limit == 0 || limit > 100 || queue.is_some_and(str::is_empty) {
            return Err(ReviewRuntimeError::Invalid);
        }
        let membership = match actor.role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator | CaseworkRole::Requester => {
                return Err(ReviewRuntimeError::Forbidden)
            }
        };
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT t.task_id,t.request_id,t.stage_index,t.stage_id,t.queue_id,t.state,
                        t.holder_issuer,t.holder_subject,t.revision,r.policy_snapshot
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 JOIN casework_queue_service q ON q.queue_id=t.queue_id
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE r.lifecycle='reviewing' AND t.stage_index=r.active_stage_index
                   AND t.state IN ('open','claimed')
                   AND m.issuer=$1 AND m.subject=$2 AND m.membership_kind=$3
                   AND ($4::text IS NULL OR t.queue_id=$4)
                   AND ($5::uuid IS NULL OR (t.created_at,t.task_id)>(
                        SELECT c.created_at,c.task_id FROM casework_review_tasks c WHERE c.task_id=$5
                   ))
                   AND ((r.policy_snapshot->'stages'->t.stage_index->'decidingProfiles') ? $7)
                 ORDER BY t.created_at,t.task_id LIMIT $6",
                &[
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                    &queue,
                    &cursor,
                    &i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?,
                    &actor.profile_id,
                ],
            )
            .await?;
        let mut items = rows
            .into_iter()
            .map(|row| {
                let policy = serde_json::from_value::<ReviewKindPolicySnapshot>(row.get(9))?;
                reviewer_task_from_row(&row, &policy)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = (items.len() > limit).then(|| items[limit - 1].task_id);
        items.truncate(limit);
        Ok(ReviewTaskPage { items, next_cursor })
    }

    async fn review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
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
                        t.holder_issuer,t.holder_subject,t.revision,r.policy_snapshot
                 FROM casework_review_tasks t
                 JOIN casework_review_requests r ON r.request_id=t.request_id
                 JOIN casework_queue_service q ON q.queue_id=t.queue_id
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE t.task_id=$1 AND m.issuer=$2 AND m.subject=$3 AND m.membership_kind=$4",
                &[
                    &task_id,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership,
                ],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        let policy: ReviewKindPolicySnapshot = serde_json::from_value(row.get(9))?;
        let stage_index =
            u16::try_from(row.get::<_, i32>(2)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        if policy
            .stages
            .get(usize::from(stage_index))
            .is_none_or(|stage| !stage.deciding_profiles.contains(&actor.profile_id))
        {
            return Err(ReviewRuntimeError::NotFound);
        }
        reviewer_task_from_row(&row, &policy)
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
                        assignment_owner_issuer,assignment_owner_subject,assignment_kind
                 FROM casework_review_tasks WHERE task_id=$1 FOR UPDATE",
                &[&task_id],
            )
            .await?;
        let stage_index =
            u16::try_from(row.get::<_, i32>(0)).map_err(|_| ReviewRuntimeError::Corrupt)?;
        if record.lifecycle != ReviewRequestLifecycle::Reviewing
            || record.active_stage != Some(stage_index)
        {
            transaction.commit().await?;
            return Ok(0);
        }
        let owner = match (
            row.get::<_, Option<String>>(5),
            row.get::<_, Option<String>>(6),
        ) {
            (Some(issuer), Some(subject)) => IssuerPrincipal { issuer, subject },
            (None, None) => {
                transaction.commit().await?;
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
            "absence_cover"
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
            transaction.commit().await?;
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
                    &(!eligible).then_some("no_cover_available"),
                    &now,
                ],
            )
            .await
            .map_err(map_reviewer_conflict)?;
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,'task_absence_reconciled',NULL,$4,$5)",
                &[
                    &Uuid::new_v4(),
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
        transaction.commit().await?;
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

    async fn erase_expired_reviews_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, ReviewRuntimeError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let selected = transaction
            .query(
                "SELECT request_id FROM casework_review_requests
                 WHERE (result_available_until<=$1 AND result_erased_at IS NULL)
                    OR accountability_retained_until<=$1
                 ORDER BY request_id LIMIT $2 FOR UPDATE SKIP LOCKED",
                &[&now, &REVIEW_RETENTION_BATCH_SIZE],
            )
            .await?
            .into_iter()
            .map(|row| row.get::<_, Uuid>(0))
            .collect::<Vec<_>>();
        transaction
            .execute(
                "DELETE FROM casework_review_accountability
                 WHERE request_id=ANY($2) AND retained_until<=$1",
                &[&now, &selected],
            )
            .await?;
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
                 SET context='{}'::jsonb,result_constraints=NULL
                 WHERE request_id=ANY($2) AND result_available_until<=$1
                   AND (context<>'{}'::jsonb OR result_constraints IS NOT NULL)",
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
                "UPDATE casework_review_requests
                 SET result_erased_at=COALESCE(result_erased_at,$1)
                 WHERE request_id=ANY($2) AND result_available_until<=$1",
                &[&now, &selected],
            )
            .await?;
        // Subject clocks intentionally span review rounds by moving their request binding to the
        // latest round. Delete only occurrences still bound to an expired accountability record;
        // a continued subject clock is therefore retained with its active round.
        transaction
            .execute(
                "DELETE FROM casework_review_clock_occurrences c USING casework_review_requests r
                 WHERE c.request_id=r.request_id AND r.request_id=ANY($2)
                   AND r.accountability_retained_until<=$1",
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
        transaction
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
        transaction.commit().await?;
        Ok(erased)
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

    async fn recover_review(
        &self,
        producer_id: &str,
        actor: &ActorContext,
        request: &ReviewCreateRequest,
        digest: &ContentDigest,
        idempotency_key: &str,
    ) -> Result<Option<ReviewCreateOutcome>, ReviewRuntimeError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let resource = format!("review-producer:{producer_id}");
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
            transaction.commit().await?;
            return Ok(Some(ReviewCreateOutcome {
                accepted: serde_json::from_value(response)?,
                recovered: true,
            }));
        }
        let reservation = transaction
            .query_opt(
                "SELECT submission_digest,request_id,recovery_deadline
                 FROM casework_review_submission_reservations
                 WHERE producer_id=$1 AND source_namespace=$2 AND subject_source=$2
                   AND subject_type=$3 AND subject_id=$4 AND subject_version=$5 AND policy_id=$6",
                &[
                    &producer_id,
                    &request.subject.source,
                    &request.subject.subject_type,
                    &request.subject.id,
                    &request.subject.version,
                    &request.kind,
                ],
            )
            .await?;
        let Some(reservation) = reservation else {
            transaction.commit().await?;
            return Ok(None);
        };
        if reservation.get::<_, String>(0) != digest.as_str() {
            return Err(ReviewRuntimeError::SubmissionConflict);
        }
        if reservation.get::<_, DateTime<Utc>>(2) <= Utc::now() {
            return Err(ReviewRuntimeError::ResultExpired);
        }
        let Some(request_id) = reservation.get::<_, Option<Uuid>>(1) else {
            transaction.commit().await?;
            return Ok(None);
        };
        let record = load_request(&transaction, producer_id, request_id, true).await?;
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
        transaction.commit().await?;
        Ok(Some(ReviewCreateOutcome {
            accepted,
            recovered: true,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_review(
        &self,
        producer: &registry_casework_core::ReviewProducerPolicy,
        actor: &ActorContext,
        request: ReviewCreateRequest,
        initiator: Option<IssuerPrincipal>,
        policy: ReviewKindPolicySnapshot,
        clocks: Vec<(ClockPolicy, Option<CalendarPolicy>)>,
        digest: ContentDigest,
        idempotency_key: &str,
    ) -> Result<ReviewCreateOutcome, ReviewRuntimeError> {
        let now = Utc::now();
        let recovery_deadline = now + TimeDelta::days(i64::from(producer.recovery_days));
        let retained_until = now
            + TimeDelta::days(i64::from(
                producer
                    .recovery_days
                    .max(policy.retention.accountability_days),
            ));
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let resource = format!("review-producer:{}", producer.id);
        let subject_lock = format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            producer.id,
            request.subject.source,
            request.subject.subject_type,
            request.subject.id,
            request.kind
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
            transaction.commit().await?;
            return Ok(ReviewCreateOutcome {
                accepted: serde_json::from_value(response)?,
                recovered: true,
            });
        }
        transaction
            .execute(
                "INSERT INTO casework_review_submission_reservations(
                    producer_id,source_namespace,subject_source,subject_type,subject_id,
                    subject_version,policy_id,submission_digest,request_id,recovery_deadline,
                    retained_until,created_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9,$10,$11)
                 ON CONFLICT DO NOTHING",
                &[
                    &producer.id,
                    &request.subject.source,
                    &request.subject.source,
                    &request.subject.subject_type,
                    &request.subject.id,
                    &request.subject.version,
                    &request.kind,
                    &digest.as_str(),
                    &recovery_deadline,
                    &retained_until,
                    &now,
                ],
            )
            .await?;
        let reservation = transaction
            .query_one(
                "SELECT submission_digest,request_id,recovery_deadline
                 FROM casework_review_submission_reservations
                 WHERE producer_id=$1 AND source_namespace=$2 AND subject_source=$3
                   AND subject_type=$4 AND subject_id=$5 AND subject_version=$6 AND policy_id=$7
                 FOR UPDATE",
                &[
                    &producer.id,
                    &request.subject.source,
                    &request.subject.source,
                    &request.subject.subject_type,
                    &request.subject.id,
                    &request.subject.version,
                    &request.kind,
                ],
            )
            .await?;
        let retained_digest: String = reservation.get(0);
        if retained_digest != digest.as_str() {
            return Err(ReviewRuntimeError::SubmissionConflict);
        }
        if reservation.get::<_, DateTime<Utc>>(2) <= now {
            return Err(ReviewRuntimeError::ResultExpired);
        }
        if let Some(request_id) = reservation.get::<_, Option<Uuid>>(1) {
            let record = load_request(&transaction, &producer.id, request_id, true).await?;
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
            transaction.commit().await?;
            return Ok(ReviewCreateOutcome {
                accepted,
                recovered: true,
            });
        }

        let superseded = transaction
            .query(
                "SELECT request_id FROM casework_review_requests
                 WHERE producer_id=$1 AND subject_source=$2 AND subject_type=$3
                   AND subject_id=$4 AND policy_id=$5 AND lifecycle='reviewing'
                 ORDER BY request_id FOR UPDATE",
                &[
                    &producer.id,
                    &request.subject.source,
                    &request.subject.subject_type,
                    &request.subject.id,
                    &request.kind,
                ],
            )
            .await?;
        for row in superseded {
            let prior_id: Uuid = row.get(0);
            let prior = load_request(&transaction, &producer.id, prior_id, true).await?;
            settle_review(
                &transaction,
                &prior,
                ReviewResultStatus::Superseded,
                None,
                None,
                now,
            )
            .await?;
            transaction
                .execute(
                    "INSERT INTO casework_review_history(
                        event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                     VALUES($1,$2,NULL,'review_superseded',NULL,'{}'::jsonb,$3)",
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
            registry_casework_core::ReviewContext::Source { binding } => (
                "source",
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
                 WHERE producer_id=$2 AND source_namespace=$3 AND subject_source=$3
                   AND subject_type=$4 AND subject_id=$5 AND subject_version=$6 AND policy_id=$7",
                &[
                    &request_id,
                    &producer.id,
                    &request.subject.source,
                    &request.subject.subject_type,
                    &request.subject.id,
                    &request.subject.version,
                    &request.kind,
                ],
            )
            .await?;
        let tasks = insert_stage_tasks(&transaction, request_id, &policy, 0, now).await?;
        insert_initial_review_clocks(
            &transaction,
            request_id,
            &request.subject,
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
                    ($1,$2,NULL,'review_created',NULL,$3,$5),
                    ($4,$2,NULL,'request_created',NULL,'{}'::jsonb,$5)",
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
        transaction.commit().await?;
        Ok(ReviewCreateOutcome {
            accepted,
            recovered: false,
        })
    }

    async fn review_request(
        &self,
        producer_id: &str,
        request_id: Uuid,
    ) -> Result<ReviewRequestView, ReviewRuntimeError> {
        let client = self.client().await?;
        let record = load_request_client(&client, producer_id, request_id).await?;
        Ok(request_view(&record))
    }

    async fn review_result(
        &self,
        producer_id: &str,
        request_id: Uuid,
    ) -> Result<ReviewResultRead, ReviewRuntimeError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let record = load_request(&transaction, producer_id, request_id, true).await?;
        if record.lifecycle == ReviewRequestLifecycle::Reviewing {
            transaction.commit().await?;
            return Ok(ReviewResultRead::Pending);
        }
        if record
            .result_available_until
            .is_none_or(|available_until| available_until <= Utc::now())
        {
            transaction.commit().await?;
            return Ok(ReviewResultRead::Expired);
        }
        let result = load_result(&transaction, &record).await?;
        transaction.commit().await?;
        Ok(ReviewResultRead::Available(Box::new(result)))
    }

    async fn review_result_feed(
        &self,
        producer_id: &str,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewResultFeedPage, ReviewRuntimeError> {
        let client = self.client().await?;
        let position = if let Some(cursor) = cursor {
            Some(
                client
                    .query_opt(
                        "SELECT feed_position FROM casework_review_terminal_events
                         WHERE producer_id=$1 AND event_id=$2 AND retained_until>now()",
                        &[&producer_id, &cursor],
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
                    "SELECT event_id,request_id,result_id,completed_at
                     FROM casework_review_terminal_events
                     WHERE producer_id=$1 AND retained_until>now()
                       AND feed_position>$2
                     ORDER BY feed_position LIMIT $3",
                    &[
                        &producer_id,
                        &position.get::<_, i64>(0),
                        &i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?,
                    ],
                )
                .await?
        } else {
            client
                .query(
                    "SELECT event_id,request_id,result_id,completed_at
                     FROM casework_review_terminal_events
                     WHERE producer_id=$1 AND retained_until>now()
                     ORDER BY feed_position LIMIT $2",
                    &[
                        &producer_id,
                        &i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?,
                    ],
                )
                .await?
        };
        let next_cursor =
            (rows.len() > limit).then(|| rows[limit - 1].get::<_, Uuid>(0).to_string());
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
        producer_id: &str,
        actor: &ActorContext,
        request_id: Uuid,
        request: ReviewCancelRequest,
        idempotency_key: &str,
    ) -> Result<ReviewCancelResponse, ReviewRuntimeError> {
        let now = Utc::now();
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let record = load_request(&transaction, producer_id, request_id, true).await?;
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
            transaction.commit().await?;
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
            transaction.commit().await?;
            return Ok(response);
        }
        let result = settle_review(
            &transaction,
            &record,
            ReviewResultStatus::Cancelled,
            None,
            None,
            now,
        )
        .await?;
        transaction
            .execute(
                "INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,NULL,'review_cancelled',NULL,$3,$4)",
                &[
                    &Uuid::new_v4(),
                    &request_id,
                    &json!({"reason": request.reason}),
                    &now,
                ],
            )
            .await?;
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
        transaction.commit().await?;
        Ok(response)
    }

    async fn claim_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
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
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(expected_revision, "claim"))?;
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
            transaction.commit().await?;
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
            return Err(ReviewRuntimeError::Forbidden);
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
        match state.as_str() {
            "open" => {
                transaction
                    .execute(
                        "UPDATE casework_review_tasks
                         SET state='claimed',holder_issuer=$2,holder_subject=$3,
                             assignment_kind='claim',assignment_owner_issuer=$2,
                             assignment_owner_subject=$3,assignment_absence_ids='{}',
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
            }
            "claimed"
                if row.get::<_, Option<String>>(4).as_deref()
                    == Some(actor.principal.issuer.as_str())
                    && row.get::<_, Option<String>>(5).as_deref()
                        == Some(actor.principal.subject.as_str()) => {}
            "claimed" => return Err(ReviewRuntimeError::TaskNotHeld),
            _ => return Err(ReviewRuntimeError::NotFound),
        }
        let task = ReviewerTask {
            task_id,
            request_id,
            stage_index,
            stage_id: row.get(1),
            queue: row.get(2),
            revision: revision + i64::from(state == "open"),
            eligible_profiles: stage.deciding_profiles.clone(),
            state: ReviewerTaskState::Held {
                holder: actor.principal.clone(),
            },
        };
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
        transaction.commit().await?;
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
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
        if reason.is_some_and(|value| {
            value.is_empty() || value.len() > 2_000 || value.chars().any(char::is_control)
        }) {
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
            transaction.commit().await?;
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
        let holder = match (
            row.get::<_, Option<String>>(4),
            row.get::<_, Option<String>>(5),
        ) {
            (Some(issuer), Some(subject)) => Some(IssuerPrincipal { issuer, subject }),
            (None, None) => None,
            _ => return Err(ReviewRuntimeError::Corrupt),
        };
        let actor_controls_queue = transaction
            .query_opt(
                "SELECT 1 FROM casework_queue_service q
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3
                   AND m.membership_kind='supervisor' FOR KEY SHARE OF q,m",
                &[
                    &row.get::<_, String>(2),
                    &actor.principal.issuer,
                    &actor.principal.subject,
                ],
            )
            .await?
            .is_some();
        let actor_currently_eligible = transaction
            .query_opt(
                "SELECT 1 FROM casework_queue_service q
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE q.queue_id=$1 AND m.issuer=$2 AND m.subject=$3
                   AND m.membership_kind=ANY($4) FOR KEY SHARE OF q,m",
                &[
                    &row.get::<_, String>(2),
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &membership_kinds,
                ],
            )
            .await?
            .is_some();
        if (delegate && (holder.as_ref() != Some(&actor.principal) || !actor_currently_eligible))
            || (!delegate && !actor_controls_queue)
        {
            return Err(ReviewRuntimeError::Forbidden);
        }
        ensure_review_identity_eligible(
            &transaction,
            &record,
            stage,
            stage_index,
            target,
            &row.get::<_, String>(2),
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
            &row.get::<_, String>(2),
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
            "absence_cover"
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
                    &(!eligible).then_some("no_cover_available"),
                    &next_revision,
                    &now,
                ],
            )
            .await
            .map_err(map_reviewer_conflict)?;
        let actor_ref = actor_reference(&actor.principal);
        let target_ref = actor_reference(target);
        transaction
            .execute(
                "INSERT INTO casework_review_history(
                    event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &Uuid::new_v4(),
                    &request_id,
                    &task_id,
                    &if delegate {
                        "task_delegated"
                    } else {
                        "task_assigned"
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
        let task = ReviewerTask {
            task_id,
            request_id,
            stage_index,
            stage_id: row.get(1),
            queue: row.get(2),
            revision: next_revision,
            eligible_profiles: stage.deciding_profiles.clone(),
            state: if eligible {
                ReviewerTaskState::Held { holder: effective }
            } else {
                ReviewerTaskState::Open
            },
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
        transaction.commit().await?;
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
                 VALUES($1,$2,$3,'task_draft_saved',$4,$5,$6)",
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
        producer_id: Option<&str>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<ReviewHistoryPage, ReviewRuntimeError> {
        let client = self.client().await?;
        let record = load_request_by_id(&client, request_id, false).await?;
        if let Some(producer_id) = producer_id {
            client
                .query_opt(
                    "SELECT 1 FROM casework_review_requests
                     WHERE request_id=$1 AND producer_id=$2",
                    &[&request_id, &producer_id],
                )
                .await?
                .ok_or(ReviewRuntimeError::NotFound)?;
        } else {
            ensure_review_reviewer_access(&client, &record, actor, None, false).await?;
        }
        if limit == 0 || limit > 100 {
            return Err(ReviewRuntimeError::Invalid);
        }
        let query_limit = i64::try_from(limit + 1).map_err(|_| ReviewRuntimeError::Invalid)?;
        let rows = client
            .query(
                "SELECT event_id,request_id,task_id,kind,actor_ref,detail,occurred_at
                 FROM casework_review_history
                 WHERE request_id=$1 AND (
                    NOT $2 OR kind IN ('request_created','stage_advanced','review_settled','review_cancelled')
                    OR (kind='note' AND detail->>'audience'='requester')
                 )
                 AND ($3::uuid IS NULL OR (occurred_at,event_id)>(
                    SELECT occurred_at,event_id FROM casework_review_history
                    WHERE request_id=$1 AND event_id=$3
                 ))
                 ORDER BY occurred_at,event_id LIMIT $4",
                &[&request_id, &producer_id.is_some(), &cursor, &query_limit],
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
        producer_id: Option<&str>,
    ) -> Result<Vec<ReviewClockOccurrence>, ReviewRuntimeError> {
        let client = self.client().await?;
        let record = load_request_by_id(&client, request_id, false).await?;
        if let Some(producer_id) = producer_id {
            if client
                .query_opt(
                    "SELECT 1 FROM casework_review_requests
                     WHERE request_id=$1 AND producer_id=$2",
                    &[&request_id, &producer_id],
                )
                .await?
                .is_none()
            {
                return Err(ReviewRuntimeError::NotFound);
            }
        } else {
            ensure_review_reviewer_access(&client, &record, actor, None, false).await?;
        }
        client
            .query(
                "SELECT o.clock_occurrence_id,o.clock_id,o.scope,o.subject_source,
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
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT a.event_id,a.request_id,a.task_id,a.actor_ref,a.actor_issuer,
                        a.actor_subject,a.profile_id,a.decision,a.private_reason,a.result_digest,
                        a.occurred_at,a.retained_until
                 FROM casework_review_accountability a
                 JOIN casework_review_tasks t ON t.task_id=a.task_id
                 JOIN casework_queue_service q ON q.queue_id=t.queue_id
                 JOIN casework_memberships m ON m.team_id=q.team_id
                 WHERE a.event_id=$1 AND m.issuer=$2 AND m.subject=$3
                   AND m.membership_kind='supervisor' AND a.retained_until>now()
                 FOR KEY SHARE OF q,m",
                &[&event_id, &actor.principal.issuer, &actor.principal.subject],
            )
            .await?
            .ok_or(ReviewRuntimeError::NotFound)?;
        let record = ReviewAccountabilityRecord {
            event_id: row.get(0),
            request_id: row.get(1),
            task_id: row
                .get::<_, Option<Uuid>>(2)
                .ok_or(ReviewRuntimeError::Corrupt)?,
            actor_ref: row.get(3),
            actor: IssuerPrincipal {
                issuer: row.get(4),
                subject: row.get(5),
            },
            profile_id: row.get(6),
            decision: row.get(7),
            private_reason: row.get(8),
            result_digest: row.get(9),
            occurred_at: row.get(10),
            retained_until: row.get(11),
        };
        let read_event_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES($1,$2)",
                &[
                    &read_event_id,
                    &json!({
                        "event": "casework.review_accountability_read",
                        "eventId": read_event_id,
                        "accountabilityEventId": record.event_id,
                        "actor": {
                            "issuer": actor.principal.issuer,
                            "subject": actor.principal.subject,
                        },
                        "profileId": actor.profile_id,
                    }),
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(record)
    }

    async fn add_review_note(
        &self,
        actor: &ActorContext,
        request_id: Uuid,
        producer_id: Option<&str>,
        request: ReviewNoteRequest,
        idempotency_key: &str,
    ) -> Result<ReviewHistoryEntry, ReviewRuntimeError> {
        if request.note.trim().is_empty()
            || request.note.len() > 2_000
            || request.note.chars().any(char::is_control)
        {
            return Err(ReviewRuntimeError::Invalid);
        }
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        let record = load_request_by_id(&transaction, request_id, true).await?;
        if let Some(producer_id) = producer_id {
            transaction
                .query_opt(
                    "SELECT 1 FROM casework_review_requests
                     WHERE request_id=$1 AND producer_id=$2",
                    &[&request_id, &producer_id],
                )
                .await?
                .ok_or(ReviewRuntimeError::NotFound)?;
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
            transaction.commit().await?;
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
        transaction.commit().await?;
        Ok(entry)
    }

    async fn release_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewerTask, ReviewRuntimeError> {
        let now = Utc::now();
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
            transaction.commit().await?;
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
        let policy: ReviewKindPolicySnapshot = serde_json::from_value(row.get(9))?;
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
                     revision=revision+1,updated_at=$2 WHERE task_id=$1",
                &[&task_id, &now],
            )
            .await?;
        let request_id = row.get(0);
        let task = ReviewerTask {
            task_id,
            request_id,
            stage_index,
            stage_id: row.get(2),
            queue: row.get(3),
            revision: expected_revision + 1,
            eligible_profiles: stage.deciding_profiles.clone(),
            state: ReviewerTaskState::Open,
        };
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
        transaction.commit().await?;
        Ok(task)
    }

    async fn decide_review_task(
        &self,
        actor: &ActorContext,
        task_id: Uuid,
        decision_kind: ReviewerDecisionKind,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<ReviewTransition, ReviewRuntimeError> {
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
        let resource = format!("review-task:{task_id}");
        let request_hash = review_request_hash(&(expected_revision, &decision_kind))?;
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
            transaction.commit().await?;
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
        let task = ReviewerTask {
            task_id,
            request_id,
            stage_index,
            stage_id: task_row.get(1),
            queue: task_row.get(2),
            revision: expected_revision,
            eligible_profiles: stage.deciding_profiles.clone(),
            state: match task_row.get::<_, String>(3).as_str() {
                "open" => ReviewerTaskState::Open,
                "claimed" => ReviewerTaskState::Held {
                    holder: IssuerPrincipal {
                        issuer: task_row
                            .get::<_, Option<String>>(4)
                            .ok_or(ReviewRuntimeError::Corrupt)?,
                        subject: task_row
                            .get::<_, Option<String>>(5)
                            .ok_or(ReviewRuntimeError::Corrupt)?,
                    },
                },
                "decided" | "closed" => ReviewerTaskState::Decided,
                _ => return Err(ReviewRuntimeError::Corrupt),
            },
        };
        let mut progress = ReviewProgress::new(
            request_id,
            record.initiator.clone(),
            record.result_constraints.clone(),
            &record.policy,
        )
        .map_err(|_| ReviewRuntimeError::Corrupt)?;
        progress.active_stage = record.active_stage.ok_or(ReviewRuntimeError::Corrupt)?;
        progress.decisions = load_decisions(&transaction, request_id).await?;
        let decision = ReviewerDecision {
            task_id,
            request_id,
            stage_id: task.stage_id.clone(),
            reviewer: actor.principal.clone(),
            profile_id: actor.profile_id.clone(),
            decision: decision_kind,
        };
        let transition =
            record_review_decision(&record.policy, &mut progress, &task, decision.clone())
                .map_err(|error| match error {
                    registry_casework_core::ReviewDecisionError::TaskNotHeld
                    | registry_casework_core::ReviewDecisionError::HolderMismatch => {
                        ReviewRuntimeError::TaskNotHeld
                    }
                    registry_casework_core::ReviewDecisionError::DuplicateReviewer
                    | registry_casework_core::ReviewDecisionError::InitiatorExcluded
                    | registry_casework_core::ReviewDecisionError::PreviousStageReviewerExcluded
                    | registry_casework_core::ReviewDecisionError::ProfileNotEligible => {
                        ReviewRuntimeError::Forbidden
                    }
                    _ => ReviewRuntimeError::Invalid,
                })?;
        let (decision_name, outcome, result, reason) = decision_columns(&decision.decision);
        let decision_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_decisions(
                    decision_id,request_id,task_id,stage_index,actor_issuer,actor_subject,
                    profile_id,decision,outcome,result,private_reason,decided_at)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
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
                    &now,
                ],
            )
            .await
            .map_err(map_reviewer_conflict)?;
        transaction
            .execute(
                "UPDATE casework_review_tasks
                 SET state='decided',settled_at=$2,revision=revision+1,updated_at=$2
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
                    event_id,request_id,task_id,actor_ref,actor_issuer,actor_subject,profile_id,
                    decision,private_reason,result_digest,occurred_at,retained_until)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                &[
                    &accountability_event_id,
                    &request_id,
                    &task_id,
                    &actor_ref,
                    &actor.principal.issuer,
                    &actor.principal.subject,
                    &actor.profile_id,
                    &decision_name,
                    &reason,
                    &result_digest,
                    &now,
                    &accountability_until,
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
                         SET state='closed',settled_at=COALESCE(settled_at,$3),updated_at=$3,
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
                let tasks =
                    insert_stage_tasks(&transaction, request_id, &record.policy, next_stage, now)
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
                         VALUES($1,$2,NULL,'stage_advanced',NULL,$3,$4)",
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
                let (status, outcome, result) = settlement_columns(settlement);
                settle_review(&transaction, &record, status, outcome, result, now).await?;
            }
        }
        transaction
            .execute(
                "INSERT INTO casework_review_history(event_id,request_id,task_id,kind,actor_ref,detail,occurred_at)
                 VALUES($1,$2,$3,'review_decided',$4,$5,$6)",
                &[
                    &Uuid::new_v4(),
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
        transaction.commit().await?;
        Ok(transition)
    }
}

async fn insert_stage_tasks(
    transaction: &Transaction<'_>,
    request_id: Uuid,
    policy: &ReviewKindPolicySnapshot,
    stage_index: u16,
    now: DateTime<Utc>,
) -> Result<Vec<(Uuid, String)>, ReviewRuntimeError> {
    let stage = policy
        .stages
        .get(usize::from(stage_index))
        .ok_or(ReviewRuntimeError::Corrupt)?;
    let mut tasks = Vec::with_capacity(usize::from(stage.required_approvals));
    for slot in 0..stage.required_approvals {
        let task_id = Uuid::new_v4();
        transaction
            .execute(
                "INSERT INTO casework_review_tasks(
                    task_id,request_id,stage_index,stage_id,slot,queue_id,state,revision,
                    created_at,updated_at)
                 VALUES($1,$2,$3,$4,$5,$6,'open',1,$7,$7)",
                &[
                    &task_id,
                    &request_id,
                    &i32::from(stage_index),
                    &stage.id,
                    &i32::from(slot),
                    &stage.queue,
                    &now,
                ],
            )
            .await?;
        tasks.push((task_id, stage.id.clone()));
    }
    Ok(tasks)
}

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

async fn insert_initial_review_clocks(
    transaction: &Transaction<'_>,
    request_id: Uuid,
    subject: &SubjectBinding,
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
                let seconds = registry_casework_core::parse_elapsed_seconds(&after.elapsed)
                    .ok_or(ReviewRuntimeError::Corrupt)?;
                let document = serde_json::to_value(&definition)?;
                let digest = review_request_hash(&document)?;
                let due_at = now + TimeDelta::seconds(seconds);
                let existing = transaction
                    .query_opt(
                        "SELECT clock_occurrence_id,state,paused_at FROM casework_review_clock_occurrences
                         WHERE subject_source=$1 AND subject_type=$2 AND subject_id=$3
                           AND clock_id=$4 AND scope='subject' AND correlation_key='subject'
                         FOR UPDATE",
                        &[&subject.source, &subject.subject_type, &subject.id, &clock.id()],
                    )
                    .await?;
                if let Some(existing) = existing {
                    let id: Uuid = existing.get(0);
                    let state: String = existing.get(1);
                    if state == "paused" {
                        transaction
                            .execute(
                                "UPDATE casework_review_clock_occurrences
                                 SET request_id=$2,state='running',
                                     due_at=due_at+($3-paused_at),
                                     paused_seconds=paused_seconds+GREATEST(0,EXTRACT(EPOCH FROM ($3-paused_at))::bigint),
                                     paused_at=NULL,updated_at=$3
                                 WHERE clock_occurrence_id=$1",
                                &[&id, &request_id, &now],
                            )
                            .await?;
                    } else if state == "running" {
                        transaction
                            .execute(
                                "UPDATE casework_review_clock_occurrences
                                 SET request_id=$2,updated_at=$3 WHERE clock_occurrence_id=$1",
                                &[&id, &request_id, &now],
                            )
                            .await?;
                    }
                } else {
                    transaction
                        .execute(
                            "INSERT INTO casework_review_clock_occurrences(
                                clock_occurrence_id,clock_id,scope,correlation_key,
                                subject_source,subject_type,subject_id,request_id,policy_digest,
                                policy,state,anchor_at,due_at,created_at,updated_at)
                             VALUES($1,$2,'subject','subject',$3,$4,$5,$6,$7,$8,'running',$9,$10,$9,$9)",
                            &[
                                &Uuid::new_v4(),
                                &clock.id(),
                                &subject.source,
                                &subject.subject_type,
                                &subject.id,
                                &request_id,
                                &digest,
                                &document,
                                &now,
                                &due_at,
                            ],
                        )
                        .await?;
                }
            }
            ClockPolicy::Activity { .. } => {
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
        }
    }
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
                .map_err(|_| ReviewRuntimeError::Corrupt)?;
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
                    "source_facts_missing",
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
                result_id,request_id,status,outcome,result,completed_at,available_until)
             VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[
                &result_id,
                &record.request_id,
                &status_name,
                &outcome,
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
             VALUES($1,$2,NULL,'review_settled',NULL,$3,$4)",
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
             SET state='closed',settled_at=COALESCE(settled_at,$2),updated_at=$2,
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
    match status {
        ReviewResultStatus::ChangesRequested => {
            transaction
                .execute(
                    "UPDATE casework_review_clock_occurrences
                     SET state='paused',paused_at=$2,next_action_at=NULL,updated_at=$2
                     WHERE request_id=$1 AND scope='subject' AND state='running'",
                    &[&record.request_id, &now],
                )
                .await?;
            transaction
                .execute(
                    "UPDATE casework_review_clock_occurrences
                     SET state='completed',completed_at=$2,next_action_at=NULL,updated_at=$2
                     WHERE request_id=$1 AND scope='activity'
                       AND state NOT IN ('completed','cancelled')",
                    &[&record.request_id, &now],
                )
                .await?;
        }
        ReviewResultStatus::Approved
        | ReviewResultStatus::Rejected
        | ReviewResultStatus::Answered => {
            transaction
                .execute(
                    "UPDATE casework_review_clock_occurrences
                     SET state='completed',completed_at=$2,paused_at=NULL,next_action_at=NULL,
                         updated_at=$2
                     WHERE request_id=$1 AND state NOT IN ('completed','cancelled')",
                    &[&record.request_id, &now],
                )
                .await?;
        }
        ReviewResultStatus::Superseded => {
            transaction
                .execute(
                    "UPDATE casework_review_clock_occurrences
                     SET state='cancelled',paused_at=NULL,next_action_at=NULL,updated_at=$2
                     WHERE request_id=$1 AND scope='activity'
                       AND state NOT IN ('completed','cancelled')",
                    &[&record.request_id, &now],
                )
                .await?;
        }
        ReviewResultStatus::Cancelled => {
            transaction
                .execute(
                    "UPDATE casework_review_clock_occurrences
                     SET state='cancelled',paused_at=NULL,next_action_at=NULL,updated_at=$2
                     WHERE request_id=$1 AND state NOT IN ('completed','cancelled')",
                    &[&record.request_id, &now],
                )
                .await?;
        }
    }
    let response = ReviewResult {
        result_id,
        request_id: record.request_id,
        subject: record.subject.clone(),
        policy: policy_binding(&record.policy),
        submission_digest: record.submission_digest.clone(),
        status,
        outcome,
        result,
        completed_at: now,
        available_until,
    };
    response.check().map_err(|_| ReviewRuntimeError::Corrupt)?;
    Ok(response)
}

async fn load_request(
    transaction: &Transaction<'_>,
    producer_id: &str,
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
        .query_opt(&query, &[&producer_id, &request_id])
        .await?
        .ok_or(ReviewRuntimeError::NotFound)?;
    request_from_row(&row)
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
    producer_id: &str,
    request_id: Uuid,
) -> Result<ReviewRequestRecord, ReviewRuntimeError> {
    let row = client
        .query_opt(
            &request_query("producer_id=$1 AND request_id=$2"),
            &[&producer_id, &request_id],
        )
        .await?
        .ok_or(ReviewRuntimeError::NotFound)?;
    request_from_row(&row)
}

fn request_query(predicate: &str) -> String {
    format!(
        "SELECT request_id,producer_id,subject_source,subject_type,subject_id,subject_version,
                subject_digest,requester_reference,policy_snapshot,submission_digest,lifecycle,
                active_stage_index,created_at,updated_at,result_available_until,
                initiator_issuer,initiator_subject,result_constraints,context_strategy,context
         FROM casework_review_requests WHERE {predicate}"
    )
}

fn request_from_row(row: &Row) -> Result<ReviewRequestRecord, ReviewRuntimeError> {
    let lifecycle = parse_lifecycle(&row.get::<_, String>(10))?;
    let policy: ReviewKindPolicySnapshot = serde_json::from_value(row.get(8))?;
    policy.verify().map_err(|_| ReviewRuntimeError::Corrupt)?;
    let result_available_until = row.get::<_, Option<DateTime<Utc>>>(14);
    let context_strategy = row.get::<_, String>(18);
    let context_value = row.get::<_, Value>(19);
    let context_erased = context_value
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
        && lifecycle != ReviewRequestLifecycle::Reviewing
        && result_available_until.is_some_and(|until| until <= Utc::now());
    let context = if context_erased {
        None
    } else {
        match context_strategy.as_str() {
            "submitted" => Some(registry_casework_core::ReviewContext::Submitted {
                snapshot: context_value,
            }),
            "source" => Some(registry_casework_core::ReviewContext::Source {
                binding: serde_json::from_value::<SourceContextBinding>(context_value)?,
            }),
            _ => return Err(ReviewRuntimeError::Corrupt),
        }
    };
    Ok(ReviewRequestRecord {
        request_id: row.get(0),
        producer_id: row.get(1),
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

fn reviewer_task_from_row(
    row: &Row,
    policy: &ReviewKindPolicySnapshot,
) -> Result<ReviewerTask, ReviewRuntimeError> {
    let stage_index =
        u16::try_from(row.get::<_, i32>(2)).map_err(|_| ReviewRuntimeError::Corrupt)?;
    let stage = policy
        .stages
        .get(usize::from(stage_index))
        .ok_or(ReviewRuntimeError::Corrupt)?;
    let state = match row.get::<_, String>(5).as_str() {
        "open" => ReviewerTaskState::Open,
        "claimed" => ReviewerTaskState::Held {
            holder: IssuerPrincipal {
                issuer: row
                    .get::<_, Option<String>>(6)
                    .ok_or(ReviewRuntimeError::Corrupt)?,
                subject: row
                    .get::<_, Option<String>>(7)
                    .ok_or(ReviewRuntimeError::Corrupt)?,
            },
        },
        "decided" | "closed" => ReviewerTaskState::Decided,
        _ => return Err(ReviewRuntimeError::Corrupt),
    };
    Ok(ReviewerTask {
        task_id: row.get(0),
        request_id: row.get(1),
        stage_index,
        stage_id: row.get(3),
        queue: row.get(4),
        revision: row.get(8),
        eligible_profiles: stage.deciding_profiles.clone(),
        state,
    })
}

async fn load_result(
    transaction: &Transaction<'_>,
    record: &ReviewRequestRecord,
) -> Result<ReviewResult, ReviewRuntimeError> {
    let row = transaction
        .query_opt(
            "SELECT result_id,status,outcome,result,completed_at,available_until
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
) -> Result<Vec<ReviewerDecision>, ReviewRuntimeError> {
    transaction
        .query(
            "SELECT d.task_id,t.stage_id,d.actor_issuer,d.actor_subject,d.profile_id,d.decision,
                    d.outcome,d.result,d.private_reason
             FROM casework_review_decisions d
             JOIN casework_review_tasks t ON t.task_id=d.task_id
             WHERE d.request_id=$1 ORDER BY d.decided_at,d.decision_id",
            &[&request_id],
        )
        .await?
        .into_iter()
        .map(|row| {
            let decision = match row.get::<_, String>(5).as_str() {
                "approve" => ReviewerDecisionKind::Approve,
                "reject" => ReviewerDecisionKind::Reject {
                    outcome: row
                        .get::<_, Option<String>>(6)
                        .ok_or(ReviewRuntimeError::Corrupt)?,
                    reason: row.get::<_, Option<String>>(8),
                    result: row.get(7),
                },
                "changes_requested" => ReviewerDecisionKind::ChangesRequested {
                    outcome: row
                        .get::<_, Option<String>>(6)
                        .ok_or(ReviewRuntimeError::Corrupt)?,
                    reason: row.get::<_, Option<String>>(8),
                    result: row.get(7),
                },
                "answer" => ReviewerDecisionKind::Answer {
                    outcome: row
                        .get::<_, Option<String>>(6)
                        .ok_or(ReviewRuntimeError::Corrupt)?,
                    reason: row.get(8),
                    result: row.get(7),
                },
                _ => return Err(ReviewRuntimeError::Corrupt),
            };
            Ok(ReviewerDecision {
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

fn policy_binding(policy: &ReviewKindPolicySnapshot) -> PolicyBinding {
    PolicyBinding {
        id: policy.identity.id.clone(),
        version: policy.identity.version.clone(),
        digest: policy.identity.digest.clone(),
    }
}

fn parse_lifecycle(value: &str) -> Result<ReviewRequestLifecycle, ReviewRuntimeError> {
    match value {
        "reviewing" => Ok(ReviewRequestLifecycle::Reviewing),
        "approved" => Ok(ReviewRequestLifecycle::Approved),
        "rejected" => Ok(ReviewRequestLifecycle::Rejected),
        "changes_requested" => Ok(ReviewRequestLifecycle::ChangesRequested),
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
        "changes_requested" => Ok(ReviewResultStatus::ChangesRequested),
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
        ReviewResultStatus::ChangesRequested => "changes_requested",
        ReviewResultStatus::Answered => "answered",
        ReviewResultStatus::Cancelled => "cancelled",
        ReviewResultStatus::Superseded => "superseded",
    }
}

fn decision_columns(
    decision: &ReviewerDecisionKind,
) -> (&'static str, Option<String>, Option<Value>, Option<String>) {
    match decision {
        ReviewerDecisionKind::Approve => ("approve", None, None, None),
        ReviewerDecisionKind::Reject {
            outcome,
            reason,
            result,
        } => (
            "reject",
            Some(outcome.clone()),
            result.clone(),
            reason.clone(),
        ),
        ReviewerDecisionKind::ChangesRequested {
            outcome,
            reason,
            result,
        } => (
            "changes_requested",
            Some(outcome.clone()),
            result.clone(),
            reason.clone(),
        ),
        ReviewerDecisionKind::Answer {
            outcome,
            reason,
            result,
        } => (
            "answer",
            Some(outcome.clone()),
            result.clone(),
            reason.clone(),
        ),
    }
}

fn settlement_columns(
    settlement: &ReviewSettlement,
) -> (ReviewResultStatus, Option<String>, Option<Value>) {
    match settlement {
        ReviewSettlement::Approved => (ReviewResultStatus::Approved, None, None),
        ReviewSettlement::Rejected { outcome, result } => (
            ReviewResultStatus::Rejected,
            Some(outcome.clone()),
            result.clone(),
        ),
        ReviewSettlement::ChangesRequested { outcome, result } => (
            ReviewResultStatus::ChangesRequested,
            Some(outcome.clone()),
            result.clone(),
        ),
        ReviewSettlement::Answered { outcome, result } => (
            ReviewResultStatus::Answered,
            Some(outcome.clone()),
            result.clone(),
        ),
    }
}

fn transition_kind(transition: &ReviewTransition) -> &'static str {
    match transition {
        ReviewTransition::Recorded { .. } => "recorded",
        ReviewTransition::StageAdvanced { .. } => "stage_advanced",
        ReviewTransition::Settled { settlement } => match settlement {
            ReviewSettlement::Approved => "approved",
            ReviewSettlement::Rejected { .. } => "rejected",
            ReviewSettlement::ChangesRequested { .. } => "changes_requested",
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
        " FOR KEY SHARE OF m,q"
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

fn review_clock_from_row(row: &Row) -> Result<ReviewClockOccurrence, ReviewRuntimeError> {
    let correlation = match row.get::<_, String>(2).as_str() {
        "subject" => ReviewClockCorrelation::Subject {
            source: row.get(3),
            subject_type: row.get(4),
            id: row.get(5),
        },
        "activity" => ReviewClockCorrelation::Activity {
            task_id: row
                .get::<_, Option<Uuid>>(6)
                .ok_or(ReviewRuntimeError::Corrupt)?,
            stage_id: row
                .get::<_, Option<String>>(7)
                .ok_or(ReviewRuntimeError::Corrupt)?,
        },
        _ => return Err(ReviewRuntimeError::Corrupt),
    };
    let state = match row.get::<_, String>(8).as_str() {
        "running" => ReviewClockState::Running,
        "paused" => ReviewClockState::Paused,
        "completed" => ReviewClockState::Completed,
        "cancelled" => ReviewClockState::Cancelled,
        "source_facts_missing" => ReviewClockState::SourceFactsMissing,
        _ => return Err(ReviewRuntimeError::Corrupt),
    };
    Ok(ReviewClockOccurrence {
        clock_occurrence_id: row.get(0),
        clock_id: row.get(1),
        correlation,
        state,
        policy_digest: ContentDigest::parse(&row.get::<_, String>(9))
            .map_err(|_| ReviewRuntimeError::Corrupt)?,
        anchor_at: row.get(10),
        due_at: row.get(11),
        at_risk_at: row.get(12),
        completed_at: row.get(13),
    })
}

fn actor_reference(actor: &IssuerPrincipal) -> String {
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

fn map_review_source_error(error: SourceAdapterError) -> ReviewRuntimeError {
    match error {
        SourceAdapterError::Unavailable | SourceAdapterError::Uncertain => {
            ReviewRuntimeError::SourceUnavailable
        }
        SourceAdapterError::Invalid => ReviewRuntimeError::SourceInvalid,
        SourceAdapterError::Concealed
        | SourceAdapterError::Denied
        | SourceAdapterError::RequestRejected
        | SourceAdapterError::RecordMissing
        | SourceAdapterError::ReviewerNotAuthorized
        | SourceAdapterError::ActionNotOffered
        | SourceAdapterError::BindingMoved
        | SourceAdapterError::ReasonUnsupported => ReviewRuntimeError::Forbidden,
    }
}

fn map_review_context_source_error(error: SourceAdapterError) -> ReviewRuntimeError {
    match error {
        SourceAdapterError::Concealed
        | SourceAdapterError::Denied
        | SourceAdapterError::RecordMissing
        | SourceAdapterError::ReviewerNotAuthorized
        | SourceAdapterError::BindingMoved => ReviewRuntimeError::NotFound,
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
