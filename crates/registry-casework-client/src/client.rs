use registry_casework_core::DirectoryTeamUpdateRequest;
use std::fmt;

use registry_casework_core::{
    AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery, AssignmentRequest,
    BootstrapDirectoryRequest, DelegateRequest, Description, DirectoryResponse,
    DirectoryTargetPage, DirectoryTargetsQuery, HolidaySetDocument, HolidaySetRevisionInput,
    OwnReviewDecisionPage, PageStatus, ReviewAccountabilityRecord, ReviewCancelRequest,
    ReviewCancelResponse, ReviewCaseloadApplyRequest, ReviewCaseloadMoveRequest,
    ReviewCaseloadPreview, ReviewCaseloadResult, ReviewClockOccurrence,
    ReviewClockRecomputeApplyRequest, ReviewClockRecomputePreview, ReviewClockRecomputeRequest,
    ReviewClockRecomputeResult, ReviewContextPolicy, ReviewCreateRequest, ReviewHistoryAudience,
    ReviewHistoryEntry, ReviewHistoryPage, ReviewNoteRequest, ReviewPolicyClosure,
    ReviewRequestAccepted, ReviewRequestView, ReviewResultFeedPage, ReviewSourceBindingStatus,
    ReviewStaffingQuery, ReviewTask, ReviewTaskContext, ReviewTaskContextData, ReviewTaskDraft,
    ReviewTaskDraftInput, ReviewTaskPage, ReviewTaskState, ReviewValidationError,
    ReviewValidationReason, SupervisoryReviewTaskPage, CASEWORK_PROBLEM_TYPE_BASE,
    CASEWORK_PROFILE_HEADER, DIRECTORY_TARGETS_PATH, IDEMPOTENCY_KEY_HEADER,
    MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES, MAXIMUM_CASEWORK_PROFILE_BYTES, SOURCE_PROFILE_HEADER,
    VALIDATION_ALLOWED_HEADER, VALIDATION_PATH_HEADER, VALIDATION_REASON_HEADER,
};
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, classify_keyed_attempt, read_failure_kind, retry_keyed_mutation,
    send_failure_kind, KeyedMutationAttempt, OutboundOptions, RetryAfter, ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, url::append_path_segments, validate_response_headers,
};
use registry_review_client::{
    ReviewAuth as ProducerReviewAuth, ReviewClient as ProducerReviewClient,
    ReviewClientConfig as ProducerReviewClientConfig,
    ReviewResultResponse as ProducerReviewResultResponse, ReviewResultsQuery,
    MAXIMUM_REVIEW_RESPONSE_BYTES,
};
use reqwest::header::{HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use reqwest::{Method, RequestBuilder, Response, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    CaseworkAuth, CaseworkClientConfig, CaseworkClientError, CaseworkComplete, CaseworkProblemCode,
    CaseworkProtocolFailure, ReviewPageQuery, ReviewResultResponse, ReviewTaskDecisionRequest,
    SupervisoryReviewTaskQuery,
};

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;
const MAXIMUM_CURSOR_BYTES: usize = 4096;
const MAXIMUM_PAGE_SIZE: usize = 100;
const MAXIMUM_ABSENCES_PAGE_SIZE: usize = 1000;
const MAXIMUM_REVIEW_IDENTITY_BYTES: usize = 64;
const MAXIMUM_REVIEW_RECEIPT_OUTCOME_BYTES: usize = 128;
const ORIGINAL_ATTEMPT_HEADER: &str = "registry-casework-attempt";

pub struct CaseworkClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    max_response_bytes: u64,
    max_mutation_retries: u8,
    review: ProducerReviewClient,
}

impl fmt::Debug for CaseworkClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaseworkClient")
            .field("base_url", &"<validated service URL>")
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_mutation_retries", &self.max_mutation_retries)
            .finish_non_exhaustive()
    }
}

impl CaseworkClient {
    pub fn new(config: CaseworkClientConfig) -> Result<Self, CaseworkClientError> {
        let mut review_config = ProducerReviewClientConfig::new(config.base_url.clone())
            .with_request_timeout(config.request_timeout)
            .with_connect_timeout(config.connect_timeout)
            .with_max_response_bytes(config.max_response_bytes.min(MAXIMUM_REVIEW_RESPONSE_BYTES));
        if let Some(user_agent) = &config.user_agent {
            review_config = review_config.with_user_agent(user_agent.clone());
        }
        if let Some(certificates) = &config.trusted_root_certificates {
            review_config = review_config.with_trusted_root_certificates(certificates.clone());
        }
        let review =
            ProducerReviewClient::new(review_config).map_err(CaseworkClientError::from_review)?;
        let base_url = config.validate()?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| CaseworkClientError::configuration("the HTTP client could not be built"))?;
        Ok(Self {
            http,
            base_url,
            max_response_bytes: config.max_response_bytes,
            max_mutation_retries: config.max_mutation_retries,
            review,
        })
    }

    pub async fn description(
        &self,
        auth: CaseworkAuth<'_>,
    ) -> Result<CaseworkComplete<Description>, CaseworkClientError> {
        self.get_json(&auth, &["v1", "casework"], &[]).await
    }

    pub async fn create_or_recover_review_request(
        &self,
        auth: CaseworkAuth<'_>,
        idempotency_key: &str,
        request: &ReviewCreateRequest,
        expected_submission_digest: &registry_casework_core::SubmissionDigest,
    ) -> Result<CaseworkComplete<ReviewRequestAccepted>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.review
            .create_or_recover_request(
                ProducerReviewAuth::new(auth.token, auth.profile),
                idempotency_key,
                request,
                expected_submission_digest,
            )
            .await
            .map(CaseworkComplete::from)
            .map_err(CaseworkClientError::from_review)
    }

    pub async fn review_request(
        &self,
        auth: CaseworkAuth<'_>,
        request_id: Uuid,
    ) -> Result<CaseworkComplete<ReviewRequestView>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.review
            .request(
                ProducerReviewAuth::new(auth.token, auth.profile),
                request_id,
            )
            .await
            .map(CaseworkComplete::from)
            .map_err(CaseworkClientError::from_review)
    }

    pub async fn review_result(
        &self,
        auth: CaseworkAuth<'_>,
        expected: &ReviewRequestAccepted,
    ) -> Result<ReviewResultResponse, CaseworkClientError> {
        self.review_result_observation(auth, expected).await.outcome
    }

    pub async fn review_result_observation(
        &self,
        auth: CaseworkAuth<'_>,
        expected: &ReviewRequestAccepted,
    ) -> crate::ReviewResultObservation {
        if let Err(error) = reject_source_profile(&auth) {
            return crate::ReviewResultObservation {
                outcome: Err(error),
                retry_after: RetryAfter::Absent,
            };
        }
        let observation = self
            .review
            .result_observation(ProducerReviewAuth::new(auth.token, auth.profile), expected)
            .await;
        let outcome = observation
            .outcome
            .map_err(CaseworkClientError::from_review)
            .map(|response| match response {
                ProducerReviewResultResponse::Available(complete) => {
                    ReviewResultResponse::Available(Box::new(CaseworkComplete::from(*complete)))
                }
                ProducerReviewResultResponse::Pending { trace_id } => {
                    ReviewResultResponse::Pending { trace_id }
                }
                ProducerReviewResultResponse::ConcealedOrUnknown { trace_id } => {
                    ReviewResultResponse::ConcealedOrUnknown { trace_id }
                }
                ProducerReviewResultResponse::Expired { trace_id } => {
                    ReviewResultResponse::Expired { trace_id }
                }
            });
        crate::ReviewResultObservation {
            outcome,
            retry_after: observation.retry_after,
        }
    }

    pub async fn review_results(
        &self,
        auth: CaseworkAuth<'_>,
        query: &ReviewPageQuery,
    ) -> Result<CaseworkComplete<ReviewResultFeedPage>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.review
            .requester_results(
                ProducerReviewAuth::new(auth.token, auth.profile),
                &ReviewResultsQuery {
                    cursor: query.cursor,
                    limit: query.limit,
                },
            )
            .await
            .map(CaseworkComplete::from)
            .map_err(CaseworkClientError::from_review)
    }

    pub async fn cancel_review_request(
        &self,
        auth: CaseworkAuth<'_>,
        expected: &ReviewRequestAccepted,
        idempotency_key: &str,
        cancellation: &ReviewCancelRequest,
    ) -> Result<CaseworkComplete<ReviewCancelResponse>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.review
            .cancel_request(
                ProducerReviewAuth::new(auth.token, auth.profile),
                expected,
                idempotency_key,
                cancellation,
            )
            .await
            .map(CaseworkComplete::from)
            .map_err(CaseworkClientError::from_review)
    }

    pub async fn review_policies(
        &self,
        auth: CaseworkAuth<'_>,
    ) -> Result<CaseworkComplete<Vec<ReviewPolicyClosure>>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        let complete: CaseworkComplete<Vec<ReviewPolicyClosure>> = self
            .get_json(&auth, &["v1", "review-policies"], &[])
            .await?;
        if complete
            .value
            .iter()
            .any(|snapshot| snapshot.verify().is_err())
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn review_policy(
        &self,
        auth: CaseworkAuth<'_>,
        policy_id: &str,
    ) -> Result<CaseworkComplete<ReviewPolicyClosure>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        validate_identifier(policy_id, "the review policy identifier is invalid")?;
        let complete: CaseworkComplete<ReviewPolicyClosure> = self
            .get_json(&auth, &["v1", "review-policies", policy_id], &[])
            .await?;
        if complete.value.identity.id != policy_id || complete.value.verify().is_err() {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn review_tasks(
        &self,
        auth: CaseworkAuth<'_>,
        query: &ReviewStaffingQuery,
    ) -> Result<CaseworkComplete<ReviewTaskPage>, CaseworkClientError> {
        query.check().map_err(|_| {
            CaseworkClientError::invalid_request("the review task query is invalid")
        })?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-tasks"])?)
                .query(query),
            &auth,
        )?;
        let complete: CaseworkComplete<ReviewTaskPage> =
            self.send_json(request, StatusCode::OK).await?;
        if !valid_staffing_page(&complete.value.items, query)
            || invalid_page_cursor(complete.value.status, complete.value.next_cursor)
            || complete.value.items.iter().any(|task| {
                !staffing_task_matches(task, query, auth.profile)
                    || task.decided_by_caller.is_some()
                    || task.decision_receipt.is_some()
                    || !review_task_matches_ownership(&task.state, query.ownership)
                    || query
                        .queue
                        .as_ref()
                        .is_some_and(|queue| &task.queue != queue)
                    || !task
                        .eligible_profiles
                        .iter()
                        .any(|profile| profile == auth.profile)
            })
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn own_review_decisions(
        &self,
        auth: CaseworkAuth<'_>,
        query: &crate::OwnReviewDecisionQuery,
    ) -> Result<CaseworkComplete<OwnReviewDecisionPage>, CaseworkClientError> {
        if let Some(queue) = &query.queue {
            validate_identifier(queue, "the review queue identifier is invalid")?;
        }
        validate_review_page(query.cursor, query.limit)?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-tasks", "own-decisions"])?)
                .query(query),
            &auth,
        )?;
        let complete: CaseworkComplete<OwnReviewDecisionPage> =
            self.send_json(request, StatusCode::OK).await?;
        if page_exceeds_limit(complete.value.items.len(), query.limit)
            || invalid_page_cursor(complete.value.status, complete.value.next_cursor)
            || complete.value.items.iter().any(|row| {
                query
                    .queue
                    .as_ref()
                    .is_some_and(|queue| &row.queue != queue)
                    || row.requester_reference.trim().is_empty()
                    || row.requester_reference.len() > 256
                    || row.requester_reference.chars().any(char::is_control)
                    || !valid_decision_receipt(&row.decision_receipt)
            })
            || complete.value.items.windows(2).any(|rows| {
                (rows[0].decision_receipt.decided_at, rows[0].task_id)
                    <= (rows[1].decision_receipt.decided_at, rows[1].task_id)
            })
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn supervisory_review_tasks(
        &self,
        auth: CaseworkAuth<'_>,
        query: &SupervisoryReviewTaskQuery,
    ) -> Result<CaseworkComplete<SupervisoryReviewTaskPage>, CaseworkClientError> {
        if let Some(queue) = &query.queue {
            validate_identifier(queue, "the review queue identifier is invalid")?;
        }
        validate_review_page(query.cursor, query.limit)?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-tasks", "supervision"])?)
                .query(query),
            &auth,
        )?;
        let complete: CaseworkComplete<SupervisoryReviewTaskPage> =
            self.send_json(request, StatusCode::OK).await?;
        if page_exceeds_limit(complete.value.items.len(), query.limit)
            || invalid_page_cursor(complete.value.status, complete.value.next_cursor)
            || complete.value.items.iter().any(|task| {
                query
                    .queue
                    .as_ref()
                    .is_some_and(|queue| &task.queue != queue)
                    || query
                        .request_id
                        .is_some_and(|request_id| task.request_id != request_id)
            })
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
    ) -> Result<CaseworkComplete<ReviewTask>, CaseworkClientError> {
        let complete = self
            .get_json(&auth, &["v1", "review-tasks", &task_id.to_string()], &[])
            .await?;
        require_review_task_id(complete, task_id, StatusCode::OK)
    }

    pub async fn review_task_context(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
    ) -> Result<CaseworkComplete<ReviewTaskContext>, CaseworkClientError> {
        let complete: CaseworkComplete<ReviewTaskContext> = self
            .get_json(
                &auth,
                &["v1", "review-tasks", &task_id.to_string(), "context"],
                &[],
            )
            .await?;
        let snapshot = &complete.value.policy_closure;
        if snapshot.verify().is_err()
            || complete.value.task_id != task_id
            || snapshot.identity.id != complete.value.policy.id
            || snapshot.identity.version != complete.value.policy.version
            || snapshot.identity.digest != complete.value.policy.digest
            || !review_task_context_matches_policy(&complete.value)
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn preview_review_task_templates(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskTemplatePreviews>, CaseworkClientError>
    {
        self.get_json(
            &auth,
            &["v1", "review-tasks", &task_id.to_string(), "task-templates"],
            &[],
        )
        .await
    }

    pub async fn list_review_task_grants(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskGrantList>, CaseworkClientError> {
        self.get_json(
            &auth,
            &["v1", "review-tasks", &task_id.to_string(), "task-grants"],
            &[],
        )
        .await
    }

    pub async fn approve_review_task_grant(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        approval: &registry_casework_core::TaskApprovalRequest,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskGrantView>, CaseworkClientError> {
        let complete: CaseworkComplete<registry_casework_core::TaskGrantView> = self
            .mutate(
                &auth,
                &["v1", "review-tasks", &task_id.to_string(), "task-grants"],
                expected_revision,
                idempotency_key,
                approval,
            )
            .await?;
        if complete.value.template_id != approval.template_id
            || complete.value.template_version != approval.template_version
            || complete.value.invalidated
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn revoke_review_task_grant(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        grant_id: Uuid,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskGrantRevocation>, CaseworkClientError>
    {
        reject_source_profile(&auth)?;
        let url = self.url(&[
            "v1",
            "review-tasks",
            &task_id.to_string(),
            "task-grants",
            &grant_id.to_string(),
            "revoke",
        ])?;
        let complete: CaseworkComplete<registry_casework_core::TaskGrantRevocation> = self
            .send_json(self.authorized(self.http.post(url), &auth)?, StatusCode::OK)
            .await?;
        if complete.value.id != grant_id || !complete.value.invalidated {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn claim_review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<CaseworkComplete<ReviewTask>, CaseworkClientError> {
        self.review_task_empty_mutation(
            auth,
            task_id,
            ReviewTaskTransition::Claim,
            expected_revision,
            idempotency_key,
            StatusCode::OK,
        )
        .await
    }

    pub async fn release_review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<CaseworkComplete<ReviewTask>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.review_task_empty_mutation(
            auth,
            task_id,
            ReviewTaskTransition::Release,
            expected_revision,
            idempotency_key,
            StatusCode::OK,
        )
        .await
    }

    pub async fn assign_review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        assignment: &AssignmentRequest,
    ) -> Result<CaseworkComplete<ReviewTask>, CaseworkClientError> {
        let complete = self
            .mutate(
                &auth,
                &["v1", "review-tasks", &task_id.to_string(), "assign"],
                expected_revision,
                idempotency_key,
                assignment,
            )
            .await?;
        require_review_task_transition(
            complete,
            task_id,
            ReviewTaskTransition::Assign,
            expected_revision,
            StatusCode::OK,
        )
    }

    pub async fn delegate_review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        delegation: &DelegateRequest,
    ) -> Result<CaseworkComplete<ReviewTask>, CaseworkClientError> {
        let complete = self
            .mutate(
                &auth,
                &["v1", "review-tasks", &task_id.to_string(), "delegate"],
                expected_revision,
                idempotency_key,
                delegation,
            )
            .await?;
        require_review_task_transition(
            complete,
            task_id,
            ReviewTaskTransition::Delegate,
            expected_revision,
            StatusCode::OK,
        )
    }

    pub async fn review_task_draft(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
    ) -> Result<CaseworkComplete<Option<ReviewTaskDraft>>, CaseworkClientError> {
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-tasks", &task_id.to_string(), "draft"])?),
            &auth,
        )?;
        let response = self.send(request).await?;
        let status = response.status();
        let trace_id = response_trace(status, response.headers())?;
        match status {
            StatusCode::OK => {
                if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
                    return Err(protocol(
                        status,
                        CaseworkProtocolFailure::MediaType,
                        Some(trace_id),
                    ));
                }
                let body = read_bounded(response, self.max_response_bytes)
                    .await
                    .map_err(|error| CaseworkClientError::Transport {
                        kind: read_failure_kind(&error),
                    })?;
                let value: ReviewTaskDraft = decode_response_json(&body).map_err(|_| {
                    protocol(
                        status,
                        CaseworkProtocolFailure::Body,
                        Some(trace_id.clone()),
                    )
                })?;
                if value.task_id != task_id {
                    return Err(protocol(
                        status,
                        CaseworkProtocolFailure::Body,
                        Some(trace_id),
                    ));
                }
                Ok(CaseworkComplete {
                    value: Some(value),
                    trace_id,
                })
            }
            StatusCode::NOT_FOUND => {
                // An empty 404 is the absent draft; a problem-bearing 404
                // names the refusal that kept the draft from being read.
                if exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
                    return Err(self.problem_or_status(response).await);
                }
                require_empty_response(response, status, &trace_id).await?;
                Ok(CaseworkComplete {
                    value: None,
                    trace_id,
                })
            }
            _ => Err(self.problem_or_status(response).await),
        }
    }

    pub async fn save_review_task_draft(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        draft: &ReviewTaskDraftInput,
    ) -> Result<CaseworkComplete<ReviewTaskDraft>, CaseworkClientError> {
        draft.check().map_err(|_| {
            CaseworkClientError::invalid_request("the private decision draft is invalid")
        })?;
        let complete: CaseworkComplete<ReviewTaskDraft> = self
            .mutate_with_method(
                &auth,
                Method::PUT,
                &["v1", "review-tasks", &task_id.to_string(), "draft"],
                expected_revision,
                idempotency_key,
                draft,
            )
            .await?;
        if complete.value.task_id != task_id
            || complete.value.revision < 1
            || complete.value.body != draft.body
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn delete_review_task_draft(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
        validate_mutation(expected_revision, idempotency_key)?;
        let request = self.mutation_headers(
            self.authorized(
                self.http.delete(self.url(&[
                    "v1",
                    "review-tasks",
                    &task_id.to_string(),
                    "draft",
                ])?),
                &auth,
            )?,
            expected_revision,
            idempotency_key,
        )?;
        self.send_keyed_empty(request, StatusCode::NO_CONTENT).await
    }

    pub async fn decide_review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        decision: &ReviewTaskDecisionRequest,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
        decision
            .decision
            .check_input()
            .map_err(|_| CaseworkClientError::invalid_request("the review decision is invalid"))?;
        validate_mutation(expected_revision, idempotency_key)?;
        let request = self.mutation_headers(
            self.authorized(
                self.http
                    .post(self.url(&["v1", "review-tasks", &task_id.to_string(), "decisions"])?)
                    .json(decision),
                &auth,
            )?,
            expected_revision,
            idempotency_key,
        )?;
        self.send_keyed_empty(request, StatusCode::NO_CONTENT).await
    }

    pub async fn review_history(
        &self,
        auth: CaseworkAuth<'_>,
        request_id: Uuid,
        query: &ReviewPageQuery,
    ) -> Result<CaseworkComplete<ReviewHistoryPage>, CaseworkClientError> {
        validate_review_page(query.cursor, query.limit)?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-requests", &request_id.to_string(), "history"])?)
                .query(query),
            &auth,
        )?;
        let complete = self.send_json(request, StatusCode::OK).await?;
        if !valid_review_history_page(&complete.value, request_id) {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn add_review_note(
        &self,
        auth: CaseworkAuth<'_>,
        request_id: Uuid,
        idempotency_key: &str,
        note: &ReviewNoteRequest,
    ) -> Result<CaseworkComplete<ReviewHistoryEntry>, CaseworkClientError> {
        validate_idempotency_key(idempotency_key)?;
        let request = self
            .authorized(
                self.http
                    .post(self.url(&["v1", "review-requests", &request_id.to_string(), "notes"])?)
                    .json(note),
                &auth,
            )?
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                idempotency_key,
            );
        let complete: CaseworkComplete<ReviewHistoryEntry> =
            self.send_keyed_json(request, StatusCode::OK).await?;
        let audience = match note.audience {
            ReviewHistoryAudience::Reviewers => "reviewers",
            ReviewHistoryAudience::Requester => "requester",
        };
        if complete.value.request_id != request_id
            || complete.value.kind != "note"
            || complete.value.task_id.is_some()
            || complete.value.detail != json!({"audience": audience, "note": note.note})
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn review_clocks(
        &self,
        auth: CaseworkAuth<'_>,
        request_id: Uuid,
    ) -> Result<CaseworkComplete<Vec<ReviewClockOccurrence>>, CaseworkClientError> {
        let complete: CaseworkComplete<Vec<ReviewClockOccurrence>> = self
            .get_json(
                &auth,
                &["v1", "review-requests", &request_id.to_string(), "clocks"],
                &[],
            )
            .await?;
        if complete
            .value
            .iter()
            .any(|occurrence| occurrence.request_id != request_id)
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn review_accountability(
        &self,
        auth: CaseworkAuth<'_>,
        event_id: Uuid,
    ) -> Result<CaseworkComplete<ReviewAccountabilityRecord>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        let complete: CaseworkComplete<ReviewAccountabilityRecord> = self
            .get_json(
                &auth,
                &["v1", "review-accountability", &event_id.to_string()],
                &[],
            )
            .await?;
        if complete.value.event_id != event_id
            || complete
                .value
                .decision_receipt
                .as_ref()
                .is_some_and(|receipt| {
                    !valid_decision_receipt(receipt)
                        || receipt.decided_at != complete.value.occurred_at
                        || match receipt.decision {
                            registry_casework_core::ReviewDecisionType::Approve => "approve",
                            registry_casework_core::ReviewDecisionType::Reject => "reject",
                            registry_casework_core::ReviewDecisionType::ChangesRequested => {
                                "changes-requested"
                            }
                            registry_casework_core::ReviewDecisionType::Answer => "answer",
                        } != complete.value.decision
                })
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    async fn review_task_empty_mutation(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        transition: ReviewTaskTransition,
        expected_revision: i64,
        idempotency_key: &str,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<ReviewTask>, CaseworkClientError> {
        validate_mutation(expected_revision, idempotency_key)?;
        let request = self.authorized(
            self.http.post(self.url(&[
                "v1",
                "review-tasks",
                &task_id.to_string(),
                transition.path_segment(),
            ])?),
            &auth,
        )?;
        let request = self.mutation_headers(request, expected_revision, idempotency_key)?;
        let complete: CaseworkComplete<ReviewTask> =
            self.send_keyed_json(request, expected_status).await?;
        require_review_task_transition(
            complete,
            task_id,
            transition,
            expected_revision,
            expected_status,
        )
    }

    /// Obtain an assertion using this agent's short-lived bootstrap token.
    /// No human or source profile header is sent and no credential is retained.
    pub async fn task_assertion(
        &self,
        token: &crate::BearerToken,
        grant_id: Uuid,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskAssertionResponse>, CaseworkClientError>
    {
        let url = self.task_assertion_endpoint(grant_id)?;
        let request = self
            .http
            .post(url)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE);
        self.send_json(request, StatusCode::OK).await
    }

    /// The exact fixed authority route for this grant. A host may pass this
    /// descriptor to the shared remote exchange provider while Casework keeps
    /// ownership of its route and response contract.
    pub fn task_assertion_endpoint(&self, grant_id: Uuid) -> Result<url::Url, CaseworkClientError> {
        self.url(&["v1", "task-grants", &grant_id.to_string(), "assertion"])
    }

    /// Perform a fresh check using the service token registered for the resource.
    pub async fn task_grant_status(
        &self,
        token: &crate::BearerToken,
        grant_id: Uuid,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskGrantStatus>, CaseworkClientError>
    {
        let url = self.url(&["v1", "task-grants", &grant_id.to_string(), "status"])?;
        let request = self
            .http
            .get(url)
            .header(AUTHORIZATION, token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE);
        self.send_json(request, StatusCode::OK).await
    }

    /// Return the first visible eligible task in the requested ordering.
    pub async fn next_review_task(
        &self,
        auth: CaseworkAuth<'_>,
        query: &ReviewStaffingQuery,
    ) -> Result<CaseworkComplete<Option<ReviewTask>>, CaseworkClientError> {
        query.check().map_err(|_| {
            CaseworkClientError::invalid_request("the review task query is invalid")
        })?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-tasks", "next"])?)
                .query(query),
            &auth,
        )?;
        let complete: CaseworkComplete<Option<ReviewTask>> =
            self.send_json(request, StatusCode::OK).await?;
        if complete.value.as_ref().is_some_and(|task| {
            !staffing_task_matches(task, query, auth.profile)
                || !review_task_matches_ownership(
                    &task.state,
                    Some(
                        query
                            .ownership
                            .unwrap_or(registry_casework_core::ReviewTaskOwnership::Unclaimed),
                    ),
                )
                || task.decided_by_caller.is_some()
                || task.decision_receipt.is_some()
                || query
                    .queue
                    .as_ref()
                    .is_some_and(|queue| &task.queue != queue)
        }) {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    /// Bounded holdings under the caller's current disclosure and staffing authority.
    pub async fn review_task_holdings(
        &self,
        auth: CaseworkAuth<'_>,
        query: &ReviewStaffingQuery,
    ) -> Result<CaseworkComplete<ReviewTaskPage>, CaseworkClientError> {
        query.check().map_err(|_| {
            CaseworkClientError::invalid_request("the review task query is invalid")
        })?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-tasks", "holdings"])?)
                .query(query),
            &auth,
        )?;
        let complete: CaseworkComplete<ReviewTaskPage> =
            self.send_json(request, StatusCode::OK).await?;
        if !valid_staffing_page(&complete.value.items, query)
            || invalid_page_cursor(complete.value.status, complete.value.next_cursor)
            || complete.value.items.iter().any(|task| {
                !staffing_task_matches(task, query, auth.profile)
                    || !matches!(task.state, ReviewTaskState::Held { .. })
                    || task.decided_by_caller.is_some()
                    || task.decision_receipt.is_some()
            })
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn directory(
        &self,
        auth: CaseworkAuth<'_>,
    ) -> Result<CaseworkComplete<DirectoryResponse>, CaseworkClientError> {
        self.get_json(&auth, &["v1", "directory"], &[]).await
    }

    pub async fn directory_targets(
        &self,
        auth: CaseworkAuth<'_>,
        query: &DirectoryTargetsQuery,
    ) -> Result<CaseworkComplete<DirectoryTargetPage>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        query.check().map_err(|_| {
            CaseworkClientError::invalid_request("the directory target query is invalid")
        })?;
        validate_page(query.cursor.as_deref(), query.limit)?;
        let url = self.url_from_constant(DIRECTORY_TARGETS_PATH)?;
        let request = self.authorized(self.http.get(url).query(query), &auth)?;
        let complete: CaseworkComplete<DirectoryTargetPage> =
            self.send_json(request, StatusCode::OK).await?;
        if page_stopped_without_cursor(complete.value.status, complete.value.next_cursor.is_some())
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn bootstrap_directory(
        &self,
        auth: CaseworkAuth<'_>,
        expected_revision: i64,
        idempotency_key: &str,
        bootstrap: &BootstrapDirectoryRequest,
    ) -> Result<CaseworkComplete<DirectoryResponse>, CaseworkClientError> {
        self.mutate(
            &auth,
            &["v1", "directory", "bootstrap"],
            expected_revision,
            idempotency_key,
            bootstrap,
        )
        .await
    }

    pub async fn absences(
        &self,
        auth: CaseworkAuth<'_>,
    ) -> Result<CaseworkComplete<AbsenceList>, CaseworkClientError> {
        self.absences_page(auth, &AbsencesQuery::default()).await
    }

    pub async fn absences_page(
        &self,
        auth: CaseworkAuth<'_>,
        query: &AbsencesQuery,
    ) -> Result<CaseworkComplete<AbsenceList>, CaseworkClientError> {
        validate_page_with_max(
            query.cursor.as_deref(),
            query.limit,
            MAXIMUM_ABSENCES_PAGE_SIZE,
        )?;
        let url = self.url(&["v1", "directory", "absences"])?;
        let request = self.authorized(self.http.get(url).query(query), &auth)?;
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn create_absence(
        &self,
        auth: CaseworkAuth<'_>,
        expected_directory_revision: i64,
        idempotency_key: &str,
        input: &AbsenceInput,
    ) -> Result<CaseworkComplete<AbsenceRecord>, CaseworkClientError> {
        validate_mutation(expected_directory_revision, idempotency_key)?;
        let request = self.mutation_headers(
            self.authorized(
                self.http
                    .post(self.url(&["v1", "directory", "absences"])?)
                    .json(input),
                &auth,
            )?,
            expected_directory_revision,
            idempotency_key,
        )?;
        self.send_keyed_json(request, StatusCode::CREATED).await
    }

    pub async fn update_absence(
        &self,
        auth: CaseworkAuth<'_>,
        absence_id: Uuid,
        expected_directory_revision: i64,
        idempotency_key: &str,
        input: &AbsenceInput,
    ) -> Result<CaseworkComplete<AbsenceRecord>, CaseworkClientError> {
        self.mutate_with_method(
            &auth,
            Method::PUT,
            &["v1", "directory", "absences", &absence_id.to_string()],
            expected_directory_revision,
            idempotency_key,
            input,
        )
        .await
    }

    pub async fn delete_absence(
        &self,
        auth: CaseworkAuth<'_>,
        absence_id: Uuid,
        expected_directory_revision: i64,
        idempotency_key: &str,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
        validate_mutation(expected_directory_revision, idempotency_key)?;
        let request = self.mutation_headers(
            self.authorized(
                self.http.delete(self.url(&[
                    "v1",
                    "directory",
                    "absences",
                    &absence_id.to_string(),
                ])?),
                &auth,
            )?,
            expected_directory_revision,
            idempotency_key,
        )?;
        self.send_keyed_empty(request, StatusCode::NO_CONTENT).await
    }

    pub async fn preview_caseload_move(
        &self,
        auth: CaseworkAuth<'_>,
        movement: &ReviewCaseloadMoveRequest,
    ) -> Result<CaseworkComplete<ReviewCaseloadPreview>, CaseworkClientError> {
        movement
            .check()
            .map_err(|_| CaseworkClientError::invalid_request("the caseload move is invalid"))?;
        let request = self.authorized(
            self.http
                .post(self.url(&["v1", "directory", "caseload", "preview"])?)
                .json(movement),
            &auth,
        )?;
        let complete: CaseworkComplete<ReviewCaseloadPreview> =
            self.send_json(request, StatusCode::OK).await?;
        if complete.value.preview_id.is_nil()
            || complete.value.directory_revision < 0
            || !valid_staffing_tasks(
                complete
                    .value
                    .tasks
                    .iter()
                    .map(|task| (task.task_id, task.revision)),
            )
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn apply_caseload_move(
        &self,
        auth: CaseworkAuth<'_>,
        idempotency_key: &str,
        input: &ReviewCaseloadApplyRequest,
    ) -> Result<CaseworkComplete<ReviewCaseloadResult>, CaseworkClientError> {
        validate_idempotency_key(idempotency_key)?;
        input
            .check()
            .map_err(|_| CaseworkClientError::invalid_request("the caseload preview is invalid"))?;
        let request = self
            .authorized(
                self.http
                    .post(self.url(&["v1", "directory", "caseload", "apply"])?)
                    .json(input),
                &auth,
            )?
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                idempotency_key,
            );
        let complete: CaseworkComplete<ReviewCaseloadResult> =
            self.send_keyed_json(request, StatusCode::OK).await?;
        if !valid_staffing_tasks(
            complete
                .value
                .moved
                .iter()
                .map(|task| (task.task_id, task.revision)),
        ) {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn update_directory_team(
        &self,
        auth: CaseworkAuth<'_>,
        team_id: &str,
        expected_directory_revision: i64,
        idempotency_key: &str,
        request: &DirectoryTeamUpdateRequest,
    ) -> Result<CaseworkComplete<DirectoryResponse>, CaseworkClientError> {
        self.mutate_with_method(
            &auth,
            Method::PUT,
            &["v1", "directory", "teams", team_id],
            expected_directory_revision,
            idempotency_key,
            request,
        )
        .await
    }

    pub async fn holiday_revision(
        &self,
        auth: CaseworkAuth<'_>,
        holiday_set: &str,
        revision: u64,
    ) -> Result<CaseworkComplete<HolidaySetDocument>, CaseworkClientError> {
        self.get_json(
            &auth,
            &[
                "v1",
                "directory",
                "holidays",
                holiday_set,
                "revisions",
                &revision.to_string(),
            ],
            &[],
        )
        .await
    }

    pub async fn create_holiday_revision(
        &self,
        auth: CaseworkAuth<'_>,
        idempotency_key: &str,
        input: &HolidaySetRevisionInput,
    ) -> Result<CaseworkComplete<HolidaySetDocument>, CaseworkClientError> {
        validate_idempotency_key(idempotency_key)?;
        let request = self
            .authorized(
                self.http
                    .post(self.url(&["v1", "directory", "holidays"])?)
                    .json(input),
                &auth,
            )?
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                idempotency_key,
            );
        self.send_keyed_json(request, StatusCode::CREATED).await
    }

    pub async fn preview_clock_recompute(
        &self,
        auth: CaseworkAuth<'_>,
        input: &ReviewClockRecomputeRequest,
    ) -> Result<CaseworkComplete<ReviewClockRecomputePreview>, CaseworkClientError> {
        input.check().map_err(|_| {
            CaseworkClientError::invalid_request("the clock recompute request is invalid")
        })?;
        let request = self.authorized(
            self.http
                .post(self.url(&["v1", "directory", "clocks", "recompute", "preview"])?)
                .json(input),
            &auth,
        )?;
        let complete: CaseworkComplete<ReviewClockRecomputePreview> =
            self.send_json(request, StatusCode::OK).await?;
        let actual: std::collections::BTreeSet<_> = complete
            .value
            .tasks
            .iter()
            .map(|task| task.task_id)
            .collect();
        let expected: std::collections::BTreeSet<_> = input.task_ids.iter().copied().collect();
        if complete.value.preview_id.is_nil()
            || complete.value.directory_revision < 0
            || actual != expected
            || !valid_staffing_tasks(
                complete
                    .value
                    .tasks
                    .iter()
                    .map(|task| (task.task_id, task.revision)),
            )
        {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn apply_clock_recompute(
        &self,
        auth: CaseworkAuth<'_>,
        idempotency_key: &str,
        input: &ReviewClockRecomputeApplyRequest,
    ) -> Result<CaseworkComplete<ReviewClockRecomputeResult>, CaseworkClientError> {
        validate_idempotency_key(idempotency_key)?;
        input.check().map_err(|_| {
            CaseworkClientError::invalid_request("the clock recompute preview is invalid")
        })?;
        let request = self
            .authorized(
                self.http
                    .post(self.url(&["v1", "directory", "clocks", "recompute", "apply"])?)
                    .json(input),
                &auth,
            )?
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                idempotency_key,
            );
        let complete: CaseworkComplete<ReviewClockRecomputeResult> =
            self.send_keyed_json(request, StatusCode::OK).await?;
        if !valid_staffing_tasks(
            complete
                .value
                .tasks
                .iter()
                .map(|task| (task.task_id, task.revision)),
        ) {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        auth: &CaseworkAuth<'_>,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<CaseworkComplete<T>, CaseworkClientError> {
        let request = self.authorized(self.http.get(self.url(segments)?).query(query), auth)?;
        self.send_json(request, StatusCode::OK).await
    }

    async fn mutate<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        auth: &CaseworkAuth<'_>,
        segments: &[&str],
        expected_revision: i64,
        idempotency_key: &str,
        body: &B,
    ) -> Result<CaseworkComplete<T>, CaseworkClientError> {
        self.mutate_with_method(
            auth,
            Method::POST,
            segments,
            expected_revision,
            idempotency_key,
            body,
        )
        .await
    }

    async fn mutate_with_method<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        auth: &CaseworkAuth<'_>,
        method: Method,
        segments: &[&str],
        expected_revision: i64,
        idempotency_key: &str,
        body: &B,
    ) -> Result<CaseworkComplete<T>, CaseworkClientError> {
        validate_mutation(expected_revision, idempotency_key)?;
        let request = self.http.request(method, self.url(segments)?).json(body);
        let request = self.mutation_headers(
            self.authorized(request, auth)?,
            expected_revision,
            idempotency_key,
        )?;
        self.send_keyed_json(request, StatusCode::OK).await
    }

    fn authorized(
        &self,
        request: RequestBuilder,
        auth: &CaseworkAuth<'_>,
    ) -> Result<RequestBuilder, CaseworkClientError> {
        validate_identifier(auth.profile, "the selected Casework profile is invalid")?;
        let profile = HeaderValue::from_str(auth.profile).map_err(|_| {
            CaseworkClientError::invalid_request("the selected Casework profile is invalid")
        })?;
        let mut request = request
            .header(AUTHORIZATION, auth.token.authorization_header_value())
            .header(HeaderName::from_static(CASEWORK_PROFILE_HEADER), profile)
            .header(ACCEPT, JSON_MEDIA_TYPE);
        if let Some(source_profile) = auth.source_profile {
            validate_identifier(source_profile, "the selected source profile is invalid")?;
            request = request.header(
                HeaderName::from_static(SOURCE_PROFILE_HEADER),
                HeaderValue::from_str(source_profile).map_err(|_| {
                    CaseworkClientError::invalid_request("the selected source profile is invalid")
                })?,
            );
        }
        Ok(request)
    }

    fn mutation_headers(
        &self,
        request: RequestBuilder,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<RequestBuilder, CaseworkClientError> {
        self.mutation_headers_value(
            request,
            &format!("\"{expected_revision}\""),
            idempotency_key,
        )
    }

    fn mutation_headers_value(
        &self,
        request: RequestBuilder,
        expected_revision: &str,
        idempotency_key: &str,
    ) -> Result<RequestBuilder, CaseworkClientError> {
        let if_match = HeaderValue::from_str(expected_revision)
            .map_err(|_| CaseworkClientError::invalid_request("the item revision is invalid"))?;
        let key = HeaderValue::from_str(idempotency_key)
            .map_err(|_| CaseworkClientError::invalid_request("the idempotency key is invalid"))?;
        Ok(request
            .header(IF_MATCH, if_match)
            .header(HeaderName::from_static(IDEMPOTENCY_KEY_HEADER), key))
    }

    fn url(&self, segments: &[&str]) -> Result<Url, CaseworkClientError> {
        append_path_segments(self.base_url.as_url(), segments)
            .map_err(|_| CaseworkClientError::invalid_request("a route identifier is invalid"))
    }

    fn url_from_constant(&self, path: &str) -> Result<Url, CaseworkClientError> {
        let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        self.url(&segments)
    }

    /// Send one idempotency-keyed mutation, resending the identical request
    /// under the same key while its outcome stays unknown, at most the
    /// configured number of times.
    async fn send_keyed_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<T>, CaseworkClientError> {
        let request = &request;
        retry_keyed_mutation(self.max_mutation_retries, || async move {
            let Some(attempt) = request.try_clone() else {
                return KeyedMutationAttempt::Settled(Err(CaseworkClientError::invalid_request(
                    "the request could not be prepared for sending",
                )));
            };
            let response = match self.send(attempt).await {
                Ok(response) => response,
                Err(error) => return keyed_attempt(Err(error), None, RetryAfter::Absent),
            };
            let status = response.status();
            let retry_after = RetryAfter::from_headers(response.headers());
            keyed_attempt(
                self.json_answer(response, expected_status).await,
                Some(status),
                retry_after,
            )
        })
        .await
    }

    /// Send one idempotency-keyed mutation answered without a body, under the
    /// same resend rule as [`Self::send_keyed_json`].
    async fn send_keyed_empty(
        &self,
        request: RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
        let request = &request;
        retry_keyed_mutation(self.max_mutation_retries, || async move {
            let Some(attempt) = request.try_clone() else {
                return KeyedMutationAttempt::Settled(Err(CaseworkClientError::invalid_request(
                    "the request could not be prepared for sending",
                )));
            };
            let response = match self.send(attempt).await {
                Ok(response) => response,
                Err(error) => return keyed_attempt(Err(error), None, RetryAfter::Absent),
            };
            let status = response.status();
            let retry_after = RetryAfter::from_headers(response.headers());
            keyed_attempt(
                self.empty_answer(response, expected_status).await,
                Some(status),
                retry_after,
            )
        })
        .await
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<T>, CaseworkClientError> {
        let response = self.send(request).await?;
        self.json_answer(response, expected_status).await
    }

    async fn json_answer<T: DeserializeOwned>(
        &self,
        response: Response,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<T>, CaseworkClientError> {
        let status = response.status();
        if status != expected_status {
            return Err(self.problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
            return Err(protocol(
                status,
                CaseworkProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let body = read_bounded(response, self.max_response_bytes)
            .await
            .map_err(|error| CaseworkClientError::Transport {
                kind: read_failure_kind(&error),
            })?;
        let value = decode_response_json(&body).map_err(|_| {
            protocol(
                status,
                CaseworkProtocolFailure::Body,
                Some(trace_id.clone()),
            )
        })?;
        Ok(CaseworkComplete { value, trace_id })
    }

    async fn empty_answer(
        &self,
        response: Response,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
        let status = response.status();
        if status != expected_status {
            return Err(self.problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        let body =
            read_bounded(response, 1)
                .await
                .map_err(|error| CaseworkClientError::Transport {
                    kind: read_failure_kind(&error),
                })?;
        if !body.is_empty() {
            return Err(protocol(
                status,
                CaseworkProtocolFailure::Body,
                Some(trace_id),
            ));
        }
        Ok(CaseworkComplete {
            value: (),
            trace_id,
        })
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response, CaseworkClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| CaseworkClientError::Transport {
                kind: send_failure_kind(&error),
            })?;
        validate_response_headers(response.headers()).map_err(|_| {
            protocol(
                response.status(),
                CaseworkProtocolFailure::HeaderBounds,
                None,
            )
        })?;
        Ok(response)
    }

    async fn problem_or_status(&self, response: Response) -> CaseworkClientError {
        let status = response.status();
        let trace_id = response_trace(status, response.headers()).ok();
        let original_attempt_values: Vec<HeaderValue> = response
            .headers()
            .get_all(ORIGINAL_ATTEMPT_HEADER)
            .iter()
            .cloned()
            .collect();
        let validation_path_values: Vec<HeaderValue> = response
            .headers()
            .get_all(VALIDATION_PATH_HEADER)
            .iter()
            .cloned()
            .collect();
        let validation_reason_values: Vec<HeaderValue> = response
            .headers()
            .get_all(VALIDATION_REASON_HEADER)
            .iter()
            .cloned()
            .collect();
        let validation_allowed_values: Vec<HeaderValue> = response
            .headers()
            .get_all(VALIDATION_ALLOWED_HEADER)
            .iter()
            .cloned()
            .collect();
        if !exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
            return protocol(status, CaseworkProtocolFailure::Status, trace_id);
        }
        let body = match read_bounded(response, MAXIMUM_PROBLEM_BYTES).await {
            Ok(value) => value,
            Err(error) => {
                return CaseworkClientError::Transport {
                    kind: read_failure_kind(&error),
                }
            }
        };
        let document = match ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES as usize) {
            Ok(value) => value,
            Err(_) => return protocol(status, CaseworkProtocolFailure::Problem, trace_id),
        };
        if document.status != status.as_u16()
            || trace_id.as_deref() != Some(document.trace_id.as_str())
        {
            return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
        }
        let code = CaseworkProblemCode::parse(&document.code);
        let expected_text = code.expected_text();
        if document.type_uri
            != format!(
                "{CASEWORK_PROBLEM_TYPE_BASE}{}",
                code.code().replace('.', "/")
            )
            || code
                .expected_status()
                .is_some_and(|expected| expected != status.as_u16())
            || expected_text
                .is_some_and(|(title, detail)| document.title != title || document.detail != detail)
        {
            return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
        }
        if !original_attempt_values.is_empty() {
            return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
        }
        let validation = match (
            validation_path_values.as_slice(),
            validation_reason_values.as_slice(),
        ) {
            ([], []) => None,
            ([path], [reason]) if code == CaseworkProblemCode::RequestInvalid => {
                let (Ok(path), Ok(reason)) = (path.to_str(), reason.to_str()) else {
                    return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
                };
                if path.is_empty() || path.len() > 256 {
                    return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
                }
                let Some(reason) = review_validation_reason(reason) else {
                    return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
                };
                let allowed = match validation_allowed_values.as_slice() {
                    [] => Vec::new(),
                    [allowed] => match allowed.to_str().ok().and_then(validation_allowed) {
                        Some(allowed) => allowed,
                        None => {
                            return protocol(status, CaseworkProtocolFailure::Problem, trace_id)
                        }
                    },
                    _ => return protocol(status, CaseworkProtocolFailure::Problem, trace_id),
                };
                Some(ReviewValidationError {
                    path: path.to_owned(),
                    reason,
                    allowed: allowed.into_boxed_slice(),
                })
            }
            _ => return protocol(status, CaseworkProtocolFailure::Problem, trace_id),
        };
        if validation.is_none() && !validation_allowed_values.is_empty() {
            return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
        }
        CaseworkClientError::Problem {
            status: status.as_u16(),
            code,
            detail: expected_text.map(|(_, detail)| detail.to_owned()),
            trace_id,
            validation,
        }
    }
}

/// Reads the comma-separated declared identifiers of a validation refusal:
/// one to sixteen review policy identifiers.
fn validation_allowed(value: &str) -> Option<Vec<String>> {
    let allowed: Vec<String> = value.split(',').map(str::to_owned).collect();
    let identifier = |value: &String| {
        let bytes = value.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 64
            && bytes[0].is_ascii_lowercase()
            && bytes[1..].iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
            })
    };
    (allowed.len() <= 16 && allowed.iter().all(identifier)).then_some(allowed)
}

fn decode_response_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ()> {
    let value = registry_platform_canonical_json::parse_json_strict(body).map_err(|_| ())?;
    serde_json::from_value(value).map_err(|_| ())
}

fn require_review_task_id(
    complete: CaseworkComplete<ReviewTask>,
    expected_task_id: Uuid,
    status: StatusCode,
) -> Result<CaseworkComplete<ReviewTask>, CaseworkClientError> {
    // Caller decision details belong to a single decided-task read, and only
    // the deciding principal receives the bounded receipt.
    if complete.value.task_id != expected_task_id
        || complete.value.decided_by_caller.is_some()
            != matches!(complete.value.state, ReviewTaskState::Decided)
        || complete.value.decision_receipt.is_some()
            != (complete.value.decided_by_caller == Some(true))
        || complete
            .value
            .decision_receipt
            .as_ref()
            .is_some_and(|receipt| !valid_decision_receipt(receipt))
    {
        return Err(protocol(
            status,
            CaseworkProtocolFailure::Body,
            Some(complete.trace_id),
        ));
    }
    Ok(complete)
}

fn valid_decision_receipt(receipt: &registry_casework_core::ReviewDecisionReceipt) -> bool {
    let id = receipt.policy.id.as_bytes();
    let valid_policy_id = !id.is_empty()
        && id.len() <= MAXIMUM_REVIEW_IDENTITY_BYTES
        && id[0].is_ascii_lowercase()
        && id[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    let valid_policy_version = !receipt.policy.version.is_empty()
        && receipt.policy.version.len() <= MAXIMUM_REVIEW_IDENTITY_BYTES
        && receipt
            .policy
            .version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    // Every decision names the declared outcome it settles with.
    let outcome = &receipt.outcome;
    let valid_outcome = !outcome.trim().is_empty()
        && outcome.len() <= MAXIMUM_REVIEW_RECEIPT_OUTCOME_BYTES
        && outcome.chars().all(|character| !character.is_control());
    valid_policy_id
        && valid_policy_version
        && valid_outcome
        && receipt.outcome_label.as_ref().is_none_or(|label| {
            !label.trim().is_empty()
                && label.len() <= 120
                && label.chars().all(|character| !character.is_control())
        })
}

fn review_task_matches_ownership(
    state: &ReviewTaskState,
    ownership: Option<registry_casework_core::ReviewTaskOwnership>,
) -> bool {
    match ownership {
        None => matches!(state, ReviewTaskState::Open | ReviewTaskState::Held { .. }),
        Some(registry_casework_core::ReviewTaskOwnership::AssignedToMe) => {
            matches!(state, ReviewTaskState::Held { .. })
        }
        Some(registry_casework_core::ReviewTaskOwnership::Unclaimed) => {
            *state == ReviewTaskState::Open
        }
    }
}

fn valid_staffing_page(tasks: &[ReviewTask], query: &ReviewStaffingQuery) -> bool {
    if page_exceeds_limit(tasks.len(), query.limit)
        || tasks
            .iter()
            .map(|task| task.task_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != tasks.len()
    {
        return false;
    }
    tasks.windows(2).all(|pair| {
        use registry_casework_core::ReviewTaskSort;
        let (left, right) = (&pair[0], &pair[1]);
        let primary = match query.sort {
            ReviewTaskSort::Due => match (left.deadline_at, right.deadline_at) {
                (Some(left), Some(right)) => left.cmp(&right),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            },
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
                )),
            ReviewTaskSort::Reference => {
                match (&left.display_reference, &right.display_reference) {
                    (Some(left), Some(right)) => left.cmp(right),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            }
        };
        primary
            .then_with(|| left.created_at.cmp(&right.created_at))
            .then_with(|| left.task_id.cmp(&right.task_id))
            .is_le()
    })
}

fn staffing_task_matches(task: &ReviewTask, query: &ReviewStaffingQuery, profile: &str) -> bool {
    task.revision > 0
        && !task.task_id.is_nil()
        && query
            .queue
            .as_ref()
            .is_none_or(|queue| queue == &task.queue)
        && query.subject().is_ok_and(|subject| {
            subject
                .as_ref()
                .is_none_or(|subject| subject == &task.subject)
        })
        && query
            .reference
            .as_ref()
            .is_none_or(|reference| task.display_reference.as_ref() == Some(reference))
        && task
            .eligible_profiles
            .iter()
            .any(|eligible| eligible == profile)
}

fn valid_staffing_tasks(tasks: impl Iterator<Item = (Uuid, i64)>) -> bool {
    let mut ids = std::collections::BTreeSet::new();
    for (id, revision) in tasks {
        if id.is_nil() || revision <= 0 || !ids.insert(id) || ids.len() > MAXIMUM_PAGE_SIZE {
            return false;
        }
    }
    true
}

fn page_exceeds_limit(item_count: usize, requested_limit: Option<usize>) -> bool {
    item_count > requested_limit.unwrap_or(MAXIMUM_PAGE_SIZE)
}

/// A page that stopped early must carry the position to resume from; without
/// one the caller can only restart and repeat the same partial page.
fn page_stopped_without_cursor(status: PageStatus, has_cursor: bool) -> bool {
    status != PageStatus::Complete && !has_cursor
}

/// A UUID-cursored page must say where to resume when it stopped early, and
/// Casework never issues the nil identifier as a cursor.
fn invalid_page_cursor(status: PageStatus, cursor: Option<Uuid>) -> bool {
    page_stopped_without_cursor(status, cursor.is_some()) || cursor.is_some_and(|c| c.is_nil())
}

/// A successful mutation response must show the transition it was asked to
/// perform, not only the task it names: the revision advances by exactly one
/// and the state is a legal successor for that mutation.
fn require_review_task_transition(
    complete: CaseworkComplete<ReviewTask>,
    expected_task_id: Uuid,
    transition: ReviewTaskTransition,
    expected_revision: i64,
    status: StatusCode,
) -> Result<CaseworkComplete<ReviewTask>, CaseworkClientError> {
    if complete.value.task_id != expected_task_id
        || complete.value.decided_by_caller.is_some()
        || complete.value.decision_receipt.is_some()
        || !transition.completed(&complete.value, expected_revision)
    {
        return Err(protocol(
            status,
            CaseworkProtocolFailure::Body,
            Some(complete.trace_id),
        ));
    }
    Ok(complete)
}

#[derive(Clone, Copy, Debug)]
enum ReviewTaskTransition {
    Claim,
    Release,
    Assign,
    Delegate,
}

impl ReviewTaskTransition {
    fn path_segment(self) -> &'static str {
        match self {
            ReviewTaskTransition::Claim => "claim",
            ReviewTaskTransition::Release => "release",
            ReviewTaskTransition::Assign => "assign",
            ReviewTaskTransition::Delegate => "delegate",
        }
    }

    fn completed(self, task: &ReviewTask, expected_revision: i64) -> bool {
        expected_revision.checked_add(1) == Some(task.revision)
            && match self {
                ReviewTaskTransition::Claim => {
                    matches!(task.state, ReviewTaskState::Held { .. })
                }
                ReviewTaskTransition::Release => task.state == ReviewTaskState::Open,
                // Assignment and delegation settle the task on the requested
                // cover when one is eligible and leave it open otherwise, so
                // either successor state proves the mutation; the revision
                // bump rules out an untouched row.
                ReviewTaskTransition::Assign | ReviewTaskTransition::Delegate => matches!(
                    task.state,
                    ReviewTaskState::Open | ReviewTaskState::Held { .. }
                ),
            }
    }
}

/// The returned context must be the one the pinned policy closure describes:
/// the context mode matches, a submitted snapshot satisfies the policy's
/// display schema, and a source binding change never still carries the
/// superseded projection. A binding reported current must carry that same
/// pinned occurrence's projection: version and integrity match the caller's
/// subject binding, and the display satisfies the policy's display schema.
fn review_task_context_matches_policy(value: &ReviewTaskContext) -> bool {
    match (&value.context, &value.policy_closure.context) {
        (ReviewTaskContextData::Submitted { snapshot }, ReviewContextPolicy::Submitted) => {
            value.policy_closure.validate_display(snapshot).is_ok()
        }
        (
            ReviewTaskContextData::CurrentSource {
                binding_status,
                projection,
                ..
            },
            ReviewContextPolicy::CurrentSource { .. },
        ) => match (*binding_status, projection) {
            (ReviewSourceBindingStatus::BindingChanged, None) => true,
            (
                ReviewSourceBindingStatus::Current,
                Some(registry_casework_core::ReviewSourceProjection {
                    binding, display, ..
                }),
            ) => {
                binding == &value.subject
                    && serde_json::to_value(display).is_ok_and(|display| {
                        value.policy_closure.validate_display(&display).is_ok()
                    })
            }
            _ => false,
        },
        _ => false,
    }
}

fn valid_review_history_page(value: &ReviewHistoryPage, expected_request_id: Uuid) -> bool {
    value.items.len() <= MAXIMUM_PAGE_SIZE
        && value
            .items
            .iter()
            .all(|entry| entry.request_id == expected_request_id)
        // The runtime constructs a present cursor from the final returned
        // event, so a page naming any other value would skip events on the
        // next request.
        && value
            .next_cursor
            .is_none_or(|cursor| value.items.last().is_some_and(|last| last.event_id == cursor))
}

fn review_validation_reason(value: &str) -> Option<ReviewValidationReason> {
    Some(match value {
        "policy-not-allowed" => ReviewValidationReason::PolicyNotAllowed,
        "reference-invalid" => ReviewValidationReason::ReferenceInvalid,
        "object-required" => ReviewValidationReason::ObjectRequired,
        "maximum-bytes-exceeded" => ReviewValidationReason::MaximumBytesExceeded,
        "maximum-depth-exceeded" => ReviewValidationReason::MaximumDepthExceeded,
        "schema-mismatch" => ReviewValidationReason::SchemaMismatch,
        "outcome-not-declared" => ReviewValidationReason::OutcomeNotDeclared,
        "reason-required" => ReviewValidationReason::ReasonRequired,
        "text-invalid" => ReviewValidationReason::TextInvalid,
        "result-not-declared" => ReviewValidationReason::ResultNotDeclared,
        "result-required" => ReviewValidationReason::ResultRequired,
        "field-not-declared" => ReviewValidationReason::FieldNotDeclared,
        "constraint-invalid" => ReviewValidationReason::ConstraintInvalid,
        "constraint-violated" => ReviewValidationReason::ConstraintViolated,
        "public-reason-required" => ReviewValidationReason::PublicReasonRequired,
        "public-reason-not-declared" => ReviewValidationReason::PublicReasonNotDeclared,
        "approval-outcome-differs" => ReviewValidationReason::ApprovalOutcomeDiffers,
        _ => return None,
    })
}

/// Classify one attempt of a keyed mutation for the shared retry loop, with
/// the shared rule. Any unknown outcome on a 5xx answer is resent, whatever
/// stage of decoding it reached.
fn keyed_attempt<T>(
    result: Result<T, CaseworkClientError>,
    status: Option<StatusCode>,
    retry_after: RetryAfter,
) -> KeyedMutationAttempt<T, CaseworkClientError> {
    classify_keyed_attempt(
        result,
        status,
        retry_after,
        CaseworkClientError::is_outcome_unknown,
        CaseworkClientError::resend_may_settle,
    )
}

fn response_trace(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<String, CaseworkClientError> {
    response_trace_id(headers)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| protocol(status, CaseworkProtocolFailure::TraceContext, None))
}

fn exact_media_type(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!((values.next(), values.next()), (Some(value), None) if value.as_bytes() == expected.as_bytes())
}

fn protocol(
    status: StatusCode,
    failure: CaseworkProtocolFailure,
    trace_id: Option<String>,
) -> CaseworkClientError {
    CaseworkClientError::Protocol {
        status: status.as_u16(),
        failure,
        trace_id,
    }
}

fn validate_identifier(value: &str, reason: &'static str) -> Result<(), CaseworkClientError> {
    if value.is_empty()
        || value.len() > MAXIMUM_CASEWORK_PROFILE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(CaseworkClientError::invalid_request(reason));
    }
    Ok(())
}

fn reject_source_profile(auth: &CaseworkAuth<'_>) -> Result<(), CaseworkClientError> {
    if auth.source_profile.is_some() {
        return Err(CaseworkClientError::invalid_request(
            "this operation does not accept a source profile",
        ));
    }
    Ok(())
}

fn validate_mutation(
    expected_revision: i64,
    idempotency_key: &str,
) -> Result<(), CaseworkClientError> {
    if expected_revision < 0 {
        return Err(CaseworkClientError::invalid_request(
            "the expected revision is invalid",
        ));
    }
    validate_idempotency_key(idempotency_key)
}

fn validate_idempotency_key(idempotency_key: &str) -> Result<(), CaseworkClientError> {
    if idempotency_key.is_empty()
        || idempotency_key.len() > MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES
        || !idempotency_key.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(CaseworkClientError::invalid_request(
            "the idempotency key is invalid",
        ));
    }
    Ok(())
}

fn validate_page(cursor: Option<&str>, limit: Option<usize>) -> Result<(), CaseworkClientError> {
    validate_page_with_max(cursor, limit, MAXIMUM_PAGE_SIZE)
}

fn validate_review_page(
    cursor: Option<Uuid>,
    limit: Option<usize>,
) -> Result<(), CaseworkClientError> {
    if limit.is_some_and(|value| value == 0 || value > MAXIMUM_PAGE_SIZE) {
        return Err(CaseworkClientError::invalid_request(
            "the page size is outside the accepted range",
        ));
    }
    if cursor.is_some_and(|cursor| cursor.is_nil()) {
        return Err(CaseworkClientError::invalid_request(
            "the page cursor must be a nextCursor Casework returned",
        ));
    }
    Ok(())
}

async fn require_empty_response(
    response: Response,
    status: StatusCode,
    trace_id: &str,
) -> Result<(), CaseworkClientError> {
    if response.headers().contains_key(CONTENT_TYPE) {
        return Err(protocol(
            status,
            CaseworkProtocolFailure::MediaType,
            Some(trace_id.to_owned()),
        ));
    }
    let body = read_bounded(response, 1)
        .await
        .map_err(|error| CaseworkClientError::Transport {
            kind: read_failure_kind(&error),
        })?;
    if !body.is_empty() {
        return Err(protocol(
            status,
            CaseworkProtocolFailure::Body,
            Some(trace_id.to_owned()),
        ));
    }
    Ok(())
}

fn validate_page_with_max(
    cursor: Option<&str>,
    limit: Option<usize>,
    maximum_page_size: usize,
) -> Result<(), CaseworkClientError> {
    if cursor.is_some_and(|value| value.is_empty() || value.len() > MAXIMUM_CURSOR_BYTES) {
        return Err(CaseworkClientError::invalid_request(
            "the cursor is invalid",
        ));
    }
    if limit.is_some_and(|value| value == 0 || value > maximum_page_size) {
        return Err(CaseworkClientError::invalid_request(
            "the page size is outside the accepted range",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token_and_profile() {
        let token = crate::BearerToken::new("secret-token").expect("token");
        let auth = CaseworkAuth::new(&token, "sensitive-profile");
        let debug = format!("{auth:?}");
        assert!(!debug.contains("secret-token"));
        assert!(!debug.contains("sensitive-profile"));
    }

    #[test]
    fn mutation_inputs_are_bounded_before_io() {
        assert!(validate_mutation(-1, "key").is_err());
        assert!(validate_mutation(1, "").is_err());
        assert!(validate_mutation(1, "line\nbreak").is_err());
    }

    #[test]
    fn request_bounds_match_the_service_contract() {
        assert!(validate_page(None, Some(100)).is_ok());
        assert!(validate_page(None, Some(101)).is_err());
        assert!(validate_identifier(&"x".repeat(128), "profile").is_ok());
        assert!(validate_identifier(&"x".repeat(129), "profile").is_err());
        assert!(validate_idempotency_key(&"x".repeat(128)).is_ok());
        assert!(validate_idempotency_key(&"x".repeat(129)).is_err());
    }

    #[test]
    fn decision_receipts_enforce_the_decision_outcome_shape() {
        use registry_casework_core::{
            ContentDigest, PolicyBinding, ReviewDecisionReceipt, ReviewDecisionType,
        };

        let receipt = |decision, outcome| ReviewDecisionReceipt {
            outcome_label: None,
            policy: PolicyBinding {
                id: "review".to_owned(),
                version: "1".to_owned(),
                digest: ContentDigest::for_bytes(b"review"),
            },
            decision,
            outcome,
            decided_at: chrono::Utc::now(),
        };
        assert!(valid_decision_receipt(&receipt(
            ReviewDecisionType::Approve,
            "approved".to_owned()
        )));
        assert!(valid_decision_receipt(&receipt(
            ReviewDecisionType::Reject,
            "declined".to_owned()
        )));
        assert!(!valid_decision_receipt(&receipt(
            ReviewDecisionType::Answer,
            String::new()
        )));
        assert!(!valid_decision_receipt(&receipt(
            ReviewDecisionType::Reject,
            " \n".to_owned()
        )));
        let mut invalid_policy = receipt(ReviewDecisionType::Reject, "declined".to_owned());
        invalid_policy.policy.id = "Invalid_Policy".to_owned();
        assert!(!valid_decision_receipt(&invalid_policy));
        invalid_policy.policy.id = "review".to_owned();
        invalid_policy.policy.version = "x".repeat(MAXIMUM_REVIEW_IDENTITY_BYTES + 1);
        assert!(!valid_decision_receipt(&invalid_policy));
        let mut labelled = receipt(ReviewDecisionType::Answer, "confirm".to_owned());
        labelled.outcome_label = Some("Confirm".to_owned());
        assert!(valid_decision_receipt(&labelled));
        for invalid_label in ["".to_owned(), " \n".to_owned(), "x".repeat(121)] {
            labelled.outcome_label = Some(invalid_label);
            assert!(!valid_decision_receipt(&labelled));
        }
        let mut approval = receipt(ReviewDecisionType::Approve, "approved".to_owned());
        approval.outcome_label = Some("Approved".to_owned());
        assert!(valid_decision_receipt(&approval));
    }

    #[test]
    fn discovery_filters_require_matching_state_and_requested_page_bound() {
        use registry_casework_core::{IssuerPrincipal, ReviewTaskOwnership};

        let held = ReviewTaskState::Held {
            holder: IssuerPrincipal {
                issuer: "https://issuer.example.test".to_owned(),
                subject: "reviewer".to_owned(),
            },
        };
        assert!(review_task_matches_ownership(
            &held,
            Some(ReviewTaskOwnership::AssignedToMe)
        ));
        assert!(!review_task_matches_ownership(
            &ReviewTaskState::Open,
            Some(ReviewTaskOwnership::AssignedToMe)
        ));
        assert!(review_task_matches_ownership(
            &ReviewTaskState::Open,
            Some(ReviewTaskOwnership::Unclaimed)
        ));
        assert!(!review_task_matches_ownership(
            &ReviewTaskState::Decided,
            Some(ReviewTaskOwnership::Unclaimed)
        ));
        assert!(!review_task_matches_ownership(
            &ReviewTaskState::Decided,
            None
        ));
        assert!(page_exceeds_limit(2, Some(1)));
        assert!(!page_exceeds_limit(1, Some(1)));
        assert!(page_exceeds_limit(MAXIMUM_PAGE_SIZE + 1, None));
    }

    #[test]
    fn history_pages_bind_a_present_cursor_to_the_final_returned_event() {
        let request_id = Uuid::new_v4();
        let entry = |event_id: Uuid| ReviewHistoryEntry {
            event_id,
            request_id,
            task_id: None,
            kind: "note".to_owned(),
            actor_ref: None,
            detail: serde_json::json!({}),
            occurred_at: chrono::Utc::now(),
        };
        let first = entry(Uuid::new_v4());
        let last = entry(Uuid::new_v4());
        assert!(valid_review_history_page(
            &ReviewHistoryPage {
                items: vec![first.clone(), last.clone()],
                next_cursor: Some(last.event_id),
            },
            request_id
        ));
        assert!(valid_review_history_page(
            &ReviewHistoryPage {
                items: vec![first],
                next_cursor: None,
            },
            request_id
        ));
        // The runtime builds the cursor from the final returned event, so any
        // other value would skip events on the next request.
        assert!(!valid_review_history_page(
            &ReviewHistoryPage {
                items: vec![last],
                next_cursor: Some(Uuid::new_v4()),
            },
            request_id
        ));
        assert!(!valid_review_history_page(
            &ReviewHistoryPage {
                items: Vec::new(),
                next_cursor: Some(Uuid::new_v4()),
            },
            request_id
        ));
    }

    /// The client reads the validation reason header in the spelling the
    /// runtime writes; the previous spelling is an unknown word.
    #[test]
    fn every_validation_reason_is_read_in_kebab_case_only() {
        let reasons = [
            (
                "policy-not-allowed",
                ReviewValidationReason::PolicyNotAllowed,
            ),
            (
                "reference-invalid",
                ReviewValidationReason::ReferenceInvalid,
            ),
            ("object-required", ReviewValidationReason::ObjectRequired),
            (
                "maximum-bytes-exceeded",
                ReviewValidationReason::MaximumBytesExceeded,
            ),
            (
                "maximum-depth-exceeded",
                ReviewValidationReason::MaximumDepthExceeded,
            ),
            ("schema-mismatch", ReviewValidationReason::SchemaMismatch),
            (
                "outcome-not-declared",
                ReviewValidationReason::OutcomeNotDeclared,
            ),
            ("reason-required", ReviewValidationReason::ReasonRequired),
            ("text-invalid", ReviewValidationReason::TextInvalid),
            (
                "result-not-declared",
                ReviewValidationReason::ResultNotDeclared,
            ),
            ("result-required", ReviewValidationReason::ResultRequired),
            (
                "field-not-declared",
                ReviewValidationReason::FieldNotDeclared,
            ),
            (
                "constraint-invalid",
                ReviewValidationReason::ConstraintInvalid,
            ),
            (
                "constraint-violated",
                ReviewValidationReason::ConstraintViolated,
            ),
            (
                "public-reason-required",
                ReviewValidationReason::PublicReasonRequired,
            ),
            (
                "public-reason-not-declared",
                ReviewValidationReason::PublicReasonNotDeclared,
            ),
            (
                "approval-outcome-differs",
                ReviewValidationReason::ApprovalOutcomeDiffers,
            ),
        ];
        for (word, reason) in reasons {
            assert_eq!(review_validation_reason(word), Some(reason), "{word}");
            assert_eq!(serde_json::to_value(reason).expect("reason"), word);
            assert_eq!(
                review_validation_reason(&word.replace('-', "_")),
                None,
                "{word}"
            );
        }
    }
}
