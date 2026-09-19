use registry_casework_core::DirectoryTeamUpdateRequest;
use std::fmt;

use registry_casework_core::{
    AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery, AssignmentRequest,
    BootstrapDirectoryRequest, CaseloadApplyRequest, CaseloadItemResult, CaseloadMoveRequest,
    CaseloadPreviewPage, CaseloadPreviewQuery, CaseworkAction, ClaimRequest, ClockOccurrenceView,
    ClockRecomputeApplyRequest, ClockRecomputePreview, ClockRecomputeRequest, ClockRecomputeResult,
    DecideRequest, DelegateRequest, Description, DirectoryResponse, DirectoryTargetPage,
    DirectoryTargetsQuery, DraftResponse, HistoryPage, HoldingsPage, HoldingsQuery,
    HolidaySetDocument, HolidaySetRevisionInput, ListWorkItemsQuery, MutationResponse,
    NextWorkItemQuery, RecoverAttemptRequest, ReleaseRequest, ReviewAccountabilityRecord,
    ReviewCancelRequest, ReviewCancelResponse, ReviewCreateRequest, ReviewHistoryEntry,
    ReviewHistoryPage, ReviewKindPolicySnapshot, ReviewNoteRequest, ReviewRequestAccepted,
    ReviewRequestView, ReviewResult, ReviewResultFeedPage, ReviewTaskContext, ReviewTaskDraft,
    ReviewTaskDraftInput, ReviewTaskPage, ReviewValidationError, ReviewValidationReason,
    ReviewerTask, SaveDraftRequest, WorkItem, WorkItemPage, CASEWORK_PROBLEM_TYPE_BASE,
    CASEWORK_PROFILE_HEADER, DIRECTORY_TARGETS_PATH, HOLDINGS_PATH, IDEMPOTENCY_KEY_HEADER,
    MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES, MAXIMUM_CASEWORK_PROFILE_BYTES, NEXT_WORK_ITEM_PATH,
    SOURCE_PROFILE_HEADER, VALIDATION_PATH_HEADER, VALIDATION_REASON_HEADER, WORK_ITEMS_PATH,
};
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, OutboundOptions, ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, url::append_path_segments, validate_response_headers,
};
use reqwest::header::{HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use reqwest::{Method, RequestBuilder, Response, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    CaseworkAuth, CaseworkClientConfig, CaseworkClientError, CaseworkComplete, CaseworkProblemCode,
    CaseworkProtocolFailure, ReviewPageQuery, ReviewResultResponse, ReviewTaskDecisionRequest,
    ReviewTaskQuery, WorkItemHistoryQuery,
};

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;
const MAXIMUM_CURSOR_BYTES: usize = 4096;
const MAXIMUM_PAGE_SIZE: usize = 100;
const MAXIMUM_ABSENCES_PAGE_SIZE: usize = 1000;
const ORIGINAL_ATTEMPT_HEADER: &str = "registry-casework-attempt";

pub struct CaseworkClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    max_response_bytes: u64,
}

impl fmt::Debug for CaseworkClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaseworkClient")
            .field("base_url", &"<validated service URL>")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl CaseworkClient {
    pub fn new(config: CaseworkClientConfig) -> Result<Self, CaseworkClientError> {
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
        request
            .check()
            .map_err(|_| CaseworkClientError::invalid_request("the review request is invalid"))?;
        validate_idempotency_key(idempotency_key)?;
        let outgoing = self
            .authorized(
                self.http
                    .post(self.url(&["v1", "review-requests"])?)
                    .json(request),
                &auth,
            )?
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                idempotency_key,
            );
        let complete: CaseworkComplete<ReviewRequestAccepted> =
            self.send_json(outgoing, StatusCode::CREATED).await?;
        if complete.value.subject != request.subject
            || &complete.value.submission_digest != expected_submission_digest
        {
            return Err(protocol(
                StatusCode::CREATED,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn review_request(
        &self,
        auth: CaseworkAuth<'_>,
        request_id: Uuid,
    ) -> Result<CaseworkComplete<ReviewRequestView>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        let complete: CaseworkComplete<ReviewRequestView> = self
            .get_json(
                &auth,
                &["v1", "review-requests", &request_id.to_string()],
                &[],
            )
            .await?;
        if complete.value.request_id != request_id {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(complete.trace_id),
            ));
        }
        Ok(complete)
    }

    pub async fn review_result(
        &self,
        auth: CaseworkAuth<'_>,
        expected: &ReviewRequestAccepted,
    ) -> Result<ReviewResultResponse, CaseworkClientError> {
        reject_source_profile(&auth)?;
        let request = self.authorized(
            self.http.get(self.url(&[
                "v1",
                "review-requests",
                &expected.request_id.to_string(),
                "result",
            ])?),
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
                let value: ReviewResult = serde_json::from_slice(&body).map_err(|_| {
                    protocol(
                        status,
                        CaseworkProtocolFailure::Body,
                        Some(trace_id.clone()),
                    )
                })?;
                if value.check().is_err()
                    || value.request_id != expected.request_id
                    || value.subject != expected.subject
                    || value.policy != expected.policy
                    || value.submission_digest != expected.submission_digest
                {
                    return Err(protocol(
                        status,
                        CaseworkProtocolFailure::Body,
                        Some(trace_id),
                    ));
                }
                Ok(ReviewResultResponse::Available(Box::new(
                    CaseworkComplete { value, trace_id },
                )))
            }
            StatusCode::ACCEPTED | StatusCode::NOT_FOUND | StatusCode::GONE => {
                require_empty_response(response, status, &trace_id).await?;
                Ok(match status {
                    StatusCode::ACCEPTED => ReviewResultResponse::Pending { trace_id },
                    StatusCode::NOT_FOUND => ReviewResultResponse::ConcealedOrUnknown { trace_id },
                    StatusCode::GONE => ReviewResultResponse::Expired { trace_id },
                    _ => unreachable!(),
                })
            }
            _ => Err(self.problem_or_status(response).await),
        }
    }

    pub async fn review_results(
        &self,
        auth: CaseworkAuth<'_>,
        query: &ReviewPageQuery,
    ) -> Result<CaseworkComplete<ReviewResultFeedPage>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        validate_review_page(query.limit)?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-results"])?)
                .query(query),
            &auth,
        )?;
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn cancel_review_request(
        &self,
        auth: CaseworkAuth<'_>,
        request_id: Uuid,
        idempotency_key: &str,
        cancellation: &ReviewCancelRequest,
    ) -> Result<CaseworkComplete<ReviewCancelResponse>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        cancellation
            .check()
            .map_err(|_| CaseworkClientError::invalid_request("the cancellation is invalid"))?;
        validate_idempotency_key(idempotency_key)?;
        let request = self
            .authorized(
                self.http
                    .post(self.url(&[
                        "v1",
                        "review-requests",
                        &request_id.to_string(),
                        "cancel",
                    ])?)
                    .json(cancellation),
                &auth,
            )?
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                idempotency_key,
            );
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn review_kinds(
        &self,
        auth: CaseworkAuth<'_>,
    ) -> Result<CaseworkComplete<Vec<ReviewKindPolicySnapshot>>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.get_json(&auth, &["v1", "review-kinds"], &[]).await
    }

    pub async fn review_kind(
        &self,
        auth: CaseworkAuth<'_>,
        kind_id: &str,
    ) -> Result<CaseworkComplete<ReviewKindPolicySnapshot>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        validate_identifier(kind_id, "the review kind identifier is invalid")?;
        self.get_json(&auth, &["v1", "review-kinds", kind_id], &[])
            .await
    }

    pub async fn review_tasks(
        &self,
        auth: CaseworkAuth<'_>,
        query: &ReviewTaskQuery,
    ) -> Result<CaseworkComplete<ReviewTaskPage>, CaseworkClientError> {
        if let Some(queue) = &query.queue {
            validate_identifier(queue, "the review queue identifier is invalid")?;
        }
        validate_review_page(query.limit)?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-tasks"])?)
                .query(query),
            &auth,
        )?;
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
    ) -> Result<CaseworkComplete<ReviewerTask>, CaseworkClientError> {
        self.get_json(&auth, &["v1", "review-tasks", &task_id.to_string()], &[])
            .await
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
        if complete.value.task_id != task_id {
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
    ) -> Result<CaseworkComplete<ReviewerTask>, CaseworkClientError> {
        self.review_task_empty_mutation(
            auth,
            task_id,
            "claim",
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
    ) -> Result<CaseworkComplete<ReviewerTask>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.review_task_empty_mutation(
            auth,
            task_id,
            "release",
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
    ) -> Result<CaseworkComplete<ReviewerTask>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.mutate(
            &auth,
            &["v1", "review-tasks", &task_id.to_string(), "assign"],
            expected_revision,
            idempotency_key,
            assignment,
        )
        .await
    }

    pub async fn delegate_review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        delegation: &DelegateRequest,
    ) -> Result<CaseworkComplete<ReviewerTask>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.mutate(
            &auth,
            &["v1", "review-tasks", &task_id.to_string(), "delegate"],
            expected_revision,
            idempotency_key,
            delegation,
        )
        .await
    }

    pub async fn review_task_draft(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
    ) -> Result<CaseworkComplete<Option<ReviewTaskDraft>>, CaseworkClientError> {
        reject_source_profile(&auth)?;
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
                let value = serde_json::from_slice(&body).map_err(|_| {
                    protocol(
                        status,
                        CaseworkProtocolFailure::Body,
                        Some(trace_id.clone()),
                    )
                })?;
                Ok(CaseworkComplete {
                    value: Some(value),
                    trace_id,
                })
            }
            StatusCode::NOT_FOUND => {
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
        reject_source_profile(&auth)?;
        self.mutate_with_method(
            &auth,
            Method::PUT,
            &["v1", "review-tasks", &task_id.to_string(), "draft"],
            expected_revision,
            idempotency_key,
            draft,
        )
        .await
    }

    pub async fn delete_review_task_draft(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
        reject_source_profile(&auth)?;
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
        self.send_empty(request, StatusCode::NO_CONTENT).await
    }

    pub async fn decide_review_task(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        decision: &ReviewTaskDecisionRequest,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
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
        self.send_empty(request, StatusCode::NO_CONTENT).await
    }

    pub async fn review_history(
        &self,
        auth: CaseworkAuth<'_>,
        request_id: Uuid,
        query: &ReviewPageQuery,
    ) -> Result<CaseworkComplete<ReviewHistoryPage>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        validate_review_page(query.limit)?;
        let request = self.authorized(
            self.http
                .get(self.url(&["v1", "review-requests", &request_id.to_string(), "history"])?)
                .query(query),
            &auth,
        )?;
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn add_review_note(
        &self,
        auth: CaseworkAuth<'_>,
        request_id: Uuid,
        idempotency_key: &str,
        note: &ReviewNoteRequest,
    ) -> Result<CaseworkComplete<ReviewHistoryEntry>, CaseworkClientError> {
        reject_source_profile(&auth)?;
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
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn review_accountability(
        &self,
        auth: CaseworkAuth<'_>,
        event_id: Uuid,
    ) -> Result<CaseworkComplete<ReviewAccountabilityRecord>, CaseworkClientError> {
        reject_source_profile(&auth)?;
        self.get_json(
            &auth,
            &["v1", "review-accountability", &event_id.to_string()],
            &[],
        )
        .await
    }

    async fn review_task_empty_mutation(
        &self,
        auth: CaseworkAuth<'_>,
        task_id: Uuid,
        operation: &str,
        expected_revision: i64,
        idempotency_key: &str,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<ReviewerTask>, CaseworkClientError> {
        validate_mutation(expected_revision, idempotency_key)?;
        let request = self.authorized(
            self.http
                .post(self.url(&["v1", "review-tasks", &task_id.to_string(), operation])?),
            &auth,
        )?;
        let request = self.mutation_headers(request, expected_revision, idempotency_key)?;
        self.send_json(request, expected_status).await
    }

    pub async fn list_work_items(
        &self,
        auth: CaseworkAuth<'_>,
        query: &ListWorkItemsQuery,
    ) -> Result<CaseworkComplete<WorkItemPage>, CaseworkClientError> {
        require_source_profile(&auth)?;
        query
            .subject()
            .map_err(|_| CaseworkClientError::invalid_request("the subject selector is invalid"))?;
        query.reference().map_err(|_| {
            CaseworkClientError::invalid_request("the display reference is invalid")
        })?;
        validate_page(query.cursor.as_deref(), query.limit)?;
        let url = self.url_from_constant(WORK_ITEMS_PATH)?;
        let request = self.authorized(self.http.get(url).query(query), &auth)?;
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn next_work_item(
        &self,
        auth: CaseworkAuth<'_>,
        query: &NextWorkItemQuery,
    ) -> Result<CaseworkComplete<WorkItemPage>, CaseworkClientError> {
        require_source_profile(&auth)?;
        if let Some(queue) = query.queue.as_deref() {
            validate_identifier(queue, "the queue identifier is invalid")?;
        }
        validate_page(query.cursor.as_deref(), None)?;
        let url = self.url_from_constant(NEXT_WORK_ITEM_PATH)?;
        let request = self.authorized(self.http.get(url).query(query), &auth)?;
        let page: CaseworkComplete<WorkItemPage> = self.send_json(request, StatusCode::OK).await?;
        if page.value.items.len() > 1 {
            return Err(protocol(
                StatusCode::OK,
                CaseworkProtocolFailure::Body,
                Some(page.trace_id),
            ));
        }
        Ok(page)
    }

    pub async fn get_work_item(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
    ) -> Result<CaseworkComplete<WorkItem>, CaseworkClientError> {
        require_source_profile(&auth)?;
        self.get_json(&auth, &["v1", "work-items", &item_id.to_string()], &[])
            .await
    }

    pub async fn preview_task_templates(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskTemplatePreviews>, CaseworkClientError>
    {
        require_source_profile(&auth)?;
        self.get_json(
            &auth,
            &["v1", "work-items", &item_id.to_string(), "task-templates"],
            &[],
        )
        .await
    }

    pub async fn list_task_grants(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskGrantList>, CaseworkClientError> {
        require_source_profile(&auth)?;
        self.get_json(
            &auth,
            &["v1", "work-items", &item_id.to_string(), "task-grants"],
            &[],
        )
        .await
    }

    pub async fn approve_task_grant(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        approval: &registry_casework_core::TaskApprovalRequest,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskGrantView>, CaseworkClientError> {
        require_source_profile(&auth)?;
        self.mutate(
            &auth,
            &["v1", "work-items", &item_id.to_string(), "task-grants"],
            expected_revision,
            idempotency_key,
            approval,
        )
        .await
    }

    pub async fn revoke_task_grant(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        grant_id: Uuid,
    ) -> Result<CaseworkComplete<registry_casework_core::TaskGrantRevocation>, CaseworkClientError>
    {
        require_source_profile(&auth)?;
        let url = self.url(&[
            "v1",
            "work-items",
            &item_id.to_string(),
            "task-grants",
            &grant_id.to_string(),
            "revoke",
        ])?;
        self.send_json(self.authorized(self.http.post(url), &auth)?, StatusCode::OK)
            .await
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

    pub async fn claim_work_item(
        &self,
        auth: CaseworkAuth<'_>,
        action: &CaseworkAction,
        idempotency_key: &str,
    ) -> Result<CaseworkComplete<MutationResponse>, CaseworkClientError> {
        require_source_profile(&auth)?;
        self.mutate_action(
            &auth,
            action,
            "claim",
            "claim",
            idempotency_key,
            &ClaimRequest {},
        )
        .await
    }

    pub async fn release_work_item(
        &self,
        auth: CaseworkAuth<'_>,
        action: &CaseworkAction,
        idempotency_key: &str,
    ) -> Result<CaseworkComplete<MutationResponse>, CaseworkClientError> {
        require_source_profile(&auth)?;
        self.mutate_action(
            &auth,
            action,
            "release",
            "release",
            idempotency_key,
            &ReleaseRequest {},
        )
        .await
    }

    pub async fn get_draft(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
    ) -> Result<CaseworkComplete<DraftResponse>, CaseworkClientError> {
        require_source_profile(&auth)?;
        self.get_json(
            &auth,
            &["v1", "work-items", &item_id.to_string(), "draft"],
            &[],
        )
        .await
    }

    pub async fn save_draft(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        draft: &SaveDraftRequest,
    ) -> Result<CaseworkComplete<DraftResponse>, CaseworkClientError> {
        require_source_profile(&auth)?;
        self.mutate_with_method(
            &auth,
            Method::PUT,
            &["v1", "work-items", &item_id.to_string(), "draft"],
            expected_revision,
            idempotency_key,
            draft,
        )
        .await
    }

    pub async fn delete_draft(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
        require_source_profile(&auth)?;
        validate_mutation(expected_revision, idempotency_key)?;
        let url = self.url(&["v1", "work-items", &item_id.to_string(), "draft"])?;
        let request = self.mutation_headers(
            self.authorized(self.http.delete(url), &auth)?,
            expected_revision,
            idempotency_key,
        )?;
        self.send_empty(request, StatusCode::NO_CONTENT).await
    }

    pub async fn decide_work_item(
        &self,
        auth: CaseworkAuth<'_>,
        action: &CaseworkAction,
        idempotency_key: &str,
        decision: &DecideRequest,
    ) -> Result<CaseworkComplete<MutationResponse>, CaseworkClientError> {
        require_source_profile(&auth)?;
        if action.operation != decision.operation.as_str() {
            return Err(CaseworkClientError::invalid_request(
                "the offered action does not match the decision",
            ));
        }
        self.mutate_action(
            &auth,
            action,
            decision.operation.as_str(),
            "decisions",
            idempotency_key,
            decision,
        )
        .await
    }

    pub async fn recover_decision(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        attempt_id: Uuid,
        recovery: &RecoverAttemptRequest,
    ) -> Result<CaseworkComplete<MutationResponse>, CaseworkClientError> {
        require_source_profile(&auth)?;
        let url = self.url(&[
            "v1",
            "work-items",
            &item_id.to_string(),
            "attempts",
            &attempt_id.to_string(),
            "recover",
        ])?;
        let request = self.authorized(self.http.post(url).json(recovery), &auth)?;
        self.send_json(request, StatusCode::OK).await
    }

    /// Recover the exact prepared decision identified by the original key.
    ///
    /// This form remains usable when the response that contained the generated
    /// attempt identifier was lost. The service binds the lookup to the
    /// authenticated actor, selected profiles, work item, and idempotency key.
    pub async fn recover_decision_by_key(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        idempotency_key: &str,
        recovery: &RecoverAttemptRequest,
    ) -> Result<CaseworkComplete<MutationResponse>, CaseworkClientError> {
        require_source_profile(&auth)?;
        validate_idempotency_key(idempotency_key)?;
        let url = self.url(&[
            "v1",
            "work-items",
            &item_id.to_string(),
            "attempts",
            "recover",
        ])?;
        let request = self
            .authorized(self.http.post(url).json(recovery), &auth)?
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                HeaderValue::from_str(idempotency_key).map_err(|_| {
                    CaseworkClientError::invalid_request("the idempotency key is invalid")
                })?,
            );
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn work_item_history(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        query: &WorkItemHistoryQuery,
    ) -> Result<CaseworkComplete<HistoryPage>, CaseworkClientError> {
        require_source_profile(&auth)?;
        validate_page(query.cursor.as_deref(), query.limit)?;
        let url = self.url(&["v1", "work-items", &item_id.to_string(), "history"])?;
        let request = self.authorized(self.http.get(url).query(query), &auth)?;
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn holdings(
        &self,
        auth: CaseworkAuth<'_>,
        query: &HoldingsQuery,
    ) -> Result<CaseworkComplete<HoldingsPage>, CaseworkClientError> {
        require_source_profile(&auth)?;
        validate_page(query.cursor.as_deref(), query.limit)?;
        let url = self.url_from_constant(HOLDINGS_PATH)?;
        let request = self.authorized(self.http.get(url).query(query), &auth)?;
        self.send_json(request, StatusCode::OK).await
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
        self.send_json(request, StatusCode::OK).await
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
        self.send_json(request, StatusCode::CREATED).await
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
        self.send_empty(request, StatusCode::NO_CONTENT).await
    }

    pub async fn assign_work_item(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        request: &AssignmentRequest,
    ) -> Result<CaseworkComplete<MutationResponse>, CaseworkClientError> {
        self.mutate(
            &auth,
            &["v1", "work-items", &item_id.to_string(), "assign"],
            expected_revision,
            idempotency_key,
            request,
        )
        .await
    }

    pub async fn delegate_work_item(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
        expected_revision: i64,
        idempotency_key: &str,
        request: &DelegateRequest,
    ) -> Result<CaseworkComplete<MutationResponse>, CaseworkClientError> {
        self.mutate(
            &auth,
            &["v1", "work-items", &item_id.to_string(), "delegate"],
            expected_revision,
            idempotency_key,
            request,
        )
        .await
    }

    pub async fn preview_caseload_move(
        &self,
        auth: CaseworkAuth<'_>,
        movement: &CaseloadMoveRequest,
        query: &CaseloadPreviewQuery,
    ) -> Result<CaseworkComplete<CaseloadPreviewPage>, CaseworkClientError> {
        validate_page(query.cursor.as_deref(), query.limit)?;
        let request = self.authorized(
            self.http
                .post(self.url(&["v1", "directory", "caseload", "preview"])?)
                .query(query)
                .json(movement),
            &auth,
        )?;
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn apply_caseload_move(
        &self,
        auth: CaseworkAuth<'_>,
        idempotency_key: &str,
        request: &CaseloadApplyRequest,
    ) -> Result<CaseworkComplete<Vec<CaseloadItemResult>>, CaseworkClientError> {
        validate_idempotency_key(idempotency_key)?;
        if request.items.is_empty()
            || request.items.len() > 100
            || request.items.iter().any(|item| item.expected_revision <= 0)
            || request
                .items
                .iter()
                .map(|item| item.item_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != request.items.len()
        {
            return Err(CaseworkClientError::invalid_request(
                "select between 1 and 100 distinct caseload items with positive revisions",
            ));
        }
        let request = self
            .authorized(
                self.http
                    .post(self.url(&["v1", "directory", "caseload", "apply"])?)
                    .json(request),
                &auth,
            )?
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                idempotency_key,
            );
        self.send_json(request, StatusCode::OK).await
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

    pub async fn work_item_clocks(
        &self,
        auth: CaseworkAuth<'_>,
        item_id: Uuid,
    ) -> Result<CaseworkComplete<Vec<ClockOccurrenceView>>, CaseworkClientError> {
        require_source_profile(&auth)?;
        self.get_json(
            &auth,
            &["v1", "work-items", &item_id.to_string(), "clocks"],
            &[],
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
        self.send_json(request, StatusCode::CREATED).await
    }

    pub async fn preview_clock_recompute(
        &self,
        auth: CaseworkAuth<'_>,
        input: &ClockRecomputeRequest,
    ) -> Result<CaseworkComplete<ClockRecomputePreview>, CaseworkClientError> {
        let request = self.authorized(
            self.http
                .post(self.url(&["v1", "directory", "clocks", "recompute", "preview"])?)
                .json(input),
            &auth,
        )?;
        self.send_json(request, StatusCode::OK).await
    }

    pub async fn apply_clock_recompute(
        &self,
        auth: CaseworkAuth<'_>,
        idempotency_key: &str,
        input: &ClockRecomputeApplyRequest,
    ) -> Result<CaseworkComplete<ClockRecomputeResult>, CaseworkClientError> {
        validate_idempotency_key(idempotency_key)?;
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
        self.send_json(request, StatusCode::OK).await
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

    async fn mutate_action<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        auth: &CaseworkAuth<'_>,
        action: &CaseworkAction,
        expected_operation: &str,
        path_suffix: &str,
        idempotency_key: &str,
        body: &B,
    ) -> Result<CaseworkComplete<T>, CaseworkClientError> {
        if action.operation != expected_operation {
            return Err(CaseworkClientError::invalid_request(
                "the offered Casework action has the wrong operation",
            ));
        }
        validate_idempotency_key(idempotency_key)?;
        validate_if_match(&action.if_match)?;
        let segments = action_segments(&action.href, path_suffix)?;
        let request = self.http.post(self.url(&segments)?).json(body);
        let request = self.mutation_headers_value(
            self.authorized(request, auth)?,
            &action.if_match,
            idempotency_key,
        )?;
        self.send_json(request, StatusCode::OK).await
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
        self.send_json(request, StatusCode::OK).await
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

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<T>, CaseworkClientError> {
        let response = self.send(request).await?;
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
        let value = serde_json::from_slice(&body).map_err(|_| {
            protocol(
                status,
                CaseworkProtocolFailure::Body,
                Some(trace_id.clone()),
            )
        })?;
        Ok(CaseworkComplete { value, trace_id })
    }

    async fn send_empty(
        &self,
        request: RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<CaseworkComplete<()>, CaseworkClientError> {
        let response = self.send(request).await?;
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
        let original_attempt_id = match (&code, original_attempt_values.as_slice()) {
            (CaseworkProblemCode::WorkItemRecoveryPending, [value]) => {
                let Ok(text) = value.to_str() else {
                    return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
                };
                let Ok(attempt_id) = Uuid::parse_str(text) else {
                    return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
                };
                if attempt_id.hyphenated().to_string() != text {
                    return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
                }
                Some(attempt_id)
            }
            (CaseworkProblemCode::WorkItemRecoveryPending, []) => None,
            (_, [_, ..]) => {
                return protocol(status, CaseworkProtocolFailure::Problem, trace_id);
            }
            (_, []) => None,
        };
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
                Some(ReviewValidationError {
                    path: path.to_owned(),
                    reason,
                })
            }
            _ => return protocol(status, CaseworkProtocolFailure::Problem, trace_id),
        };
        CaseworkClientError::Problem {
            status: status.as_u16(),
            code,
            detail: expected_text.map(|(_, detail)| detail.to_owned()),
            trace_id,
            original_attempt_id,
            validation,
        }
    }
}

fn review_validation_reason(value: &str) -> Option<ReviewValidationReason> {
    Some(match value {
        "kind_not_allowed" => ReviewValidationReason::KindNotAllowed,
        "reference_invalid" => ReviewValidationReason::ReferenceInvalid,
        "object_required" => ReviewValidationReason::ObjectRequired,
        "maximum_bytes_exceeded" => ReviewValidationReason::MaximumBytesExceeded,
        "maximum_depth_exceeded" => ReviewValidationReason::MaximumDepthExceeded,
        "schema_mismatch" => ReviewValidationReason::SchemaMismatch,
        "outcome_not_declared" => ReviewValidationReason::OutcomeNotDeclared,
        "reason_required" => ReviewValidationReason::ReasonRequired,
        "text_invalid" => ReviewValidationReason::TextInvalid,
        "result_not_declared" => ReviewValidationReason::ResultNotDeclared,
        "result_required" => ReviewValidationReason::ResultRequired,
        "field_not_declared" => ReviewValidationReason::FieldNotDeclared,
        "constraint_invalid" => ReviewValidationReason::ConstraintInvalid,
        "constraint_violated" => ReviewValidationReason::ConstraintViolated,
        _ => return None,
    })
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

fn require_source_profile(auth: &CaseworkAuth<'_>) -> Result<(), CaseworkClientError> {
    if auth.source_profile.is_none() {
        return Err(CaseworkClientError::invalid_request(
            "this operation requires an explicit source profile",
        ));
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

fn validate_if_match(value: &str) -> Result<(), CaseworkClientError> {
    let revision = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.parse::<i64>().ok());
    if revision.is_none_or(|value| value < 0) {
        return Err(CaseworkClientError::invalid_request(
            "the offered action revision is invalid",
        ));
    }
    Ok(())
}

fn action_segments<'a>(
    href: &'a str,
    expected_operation: &str,
) -> Result<Vec<&'a str>, CaseworkClientError> {
    if !href.starts_with('/') || href.contains(['?', '#']) {
        return Err(CaseworkClientError::invalid_request(
            "the offered Casework action route is invalid",
        ));
    }
    let segments = href.trim_start_matches('/').split('/').collect::<Vec<_>>();
    let valid = segments.len() == 4
        && segments[0] == "v1"
        && segments[1] == "work-items"
        && Uuid::parse_str(segments[2]).is_ok()
        && segments[3] == expected_operation;
    if !valid {
        return Err(CaseworkClientError::invalid_request(
            "the offered Casework action route is invalid",
        ));
    }
    Ok(segments)
}

fn validate_page(cursor: Option<&str>, limit: Option<usize>) -> Result<(), CaseworkClientError> {
    validate_page_with_max(cursor, limit, MAXIMUM_PAGE_SIZE)
}

fn validate_review_page(limit: Option<usize>) -> Result<(), CaseworkClientError> {
    if limit.is_some_and(|value| value == 0 || value > MAXIMUM_PAGE_SIZE) {
        return Err(CaseworkClientError::invalid_request(
            "the page size is outside the accepted range",
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
}
