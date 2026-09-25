use registry_casework_core::DirectoryTeamUpdateRequest;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use registry_casework_core::{
    AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery, AssignmentRequest, AttemptPath,
    BootstrapDirectoryRequest, CaseloadApplyRequest, CaseloadItemResult, CaseloadMoveRequest,
    CaseloadPreviewPage, CaseloadPreviewQuery, CaseworkProject, CaseworkRole, ClockOccurrenceView,
    ClockRecomputeApplyRequest, ClockRecomputePreview, ClockRecomputeRequest, ClockRecomputeResult,
    DecideRequest, DelegateRequest, Description, DirectoryResponse, DirectoryTargetPage,
    DirectoryTargetsQuery, DraftResponse, EventRequest, HistoryPage, HoldingsQuery,
    HolidaySetDocument, HolidaySetRevisionInput, ListWorkItemsQuery, MutationResponse,
    NextWorkItemQuery, QueueRecord, RecoverAttemptRequest, ReviewAccountabilityRecord,
    ReviewCancelRequest, ReviewCreateRequest, ReviewHistoryEntry, ReviewHistoryPage,
    ReviewKindPolicySnapshot, ReviewNoteRequest, ReviewPageQuery, ReviewRequestView,
    ReviewResultFeedPage, ReviewTaskContext, ReviewTaskDraft, ReviewTaskDraftInput, ReviewTaskPage,
    ReviewValidationError, ReviewValidationReason, ReviewerTask, SaveDraftRequest,
    ATTEMPT_REFERENCE_HEADER, CASEWORK_PROFILE_HEADER, IDEMPOTENCY_KEY_HEADER, IF_MATCH_HEADER,
    MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES, MAXIMUM_CASEWORK_PROFILE_BYTES, SOURCE_PROFILE_HEADER,
    VALIDATION_PATH_HEADER, VALIDATION_REASON_HEADER,
};
use registry_platform_authcommon::parse_bearer_token;
use registry_platform_httpsec::{
    request_body_limit_default, security_headers, CspBuilder, ProblemBody, TraceContext,
};
use uuid::Uuid;

use crate::problem::ProblemCode;
use crate::{
    AuthenticationError, CaseworkAuthenticator, CaseworkService, ReviewResultRead,
    ReviewRuntimeError, ReviewTaskDecisionRequest, ServiceError, StoreError,
};

tokio::task_local! {
    static REQUEST_TRACE: TraceContext;
}

const MAXIMUM_PAGE_SIZE: usize = 100;

#[derive(Clone)]
pub struct HttpState {
    pub service: CaseworkService,
    pub authenticator: Arc<CaseworkAuthenticator>,
    pub project: Arc<CaseworkProject>,
}

pub fn router(state: HttpState) -> Router {
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/casework", get(description))
        .route("/.well-known/jwks.json", get(task_jwks))
        .route(
            "/v1/work-items/{item_id}/task-templates",
            get(preview_task_templates),
        )
        .route(
            "/v1/work-items/{item_id}/task-grants",
            get(list_task_grants).post(approve_task_grant),
        )
        .route(
            "/v1/work-items/{item_id}/task-grants/{grant_id}/revoke",
            post(revoke_task_grant),
        )
        .route("/v1/task-grants/{grant_id}/assertion", post(task_assertion))
        .route("/v1/task-grants/{grant_id}/status", get(task_status))
        .route("/v1/review-requests", post(create_review_request))
        .route("/v1/review-kinds", get(review_kind_descriptions))
        .route("/v1/review-kinds/{kind_id}", get(review_kind_description))
        .route("/v1/review-results", get(review_result_feed))
        .route("/v1/review-tasks", get(review_tasks))
        .route("/v1/review-tasks/{task_id}", get(get_review_task))
        .route(
            "/v1/review-tasks/{task_id}/context",
            get(get_review_task_context),
        )
        .route(
            "/v1/review-tasks/{task_id}/task-templates",
            get(preview_review_task_templates),
        )
        .route(
            "/v1/review-tasks/{task_id}/task-grants",
            get(list_review_task_grants).post(approve_review_task_grant),
        )
        .route(
            "/v1/review-tasks/{task_id}/task-grants/{grant_id}/revoke",
            post(revoke_review_task_grant),
        )
        .route("/v1/review-requests/{request_id}", get(get_review_request))
        .route(
            "/v1/review-requests/{request_id}/result",
            get(get_review_result),
        )
        .route(
            "/v1/review-requests/{request_id}/cancel",
            post(cancel_review_request),
        )
        .route("/v1/review-tasks/{task_id}/claim", post(claim_review_task))
        .route(
            "/v1/review-tasks/{task_id}/assign",
            post(assign_review_task),
        )
        .route(
            "/v1/review-tasks/{task_id}/delegate",
            post(delegate_review_task),
        )
        .route(
            "/v1/review-tasks/{task_id}/release",
            post(release_review_task),
        )
        .route(
            "/v1/review-tasks/{task_id}/draft",
            get(get_review_task_draft)
                .put(save_review_task_draft)
                .delete(delete_review_task_draft),
        )
        .route(
            "/v1/review-tasks/{task_id}/decisions",
            post(decide_review_task),
        )
        .route(
            "/v1/review-requests/{request_id}/history",
            get(review_history),
        )
        .route(
            "/v1/review-requests/{request_id}/clocks",
            get(review_clocks),
        )
        .route(
            "/v1/review-requests/{request_id}/notes",
            post(add_review_note),
        )
        .route(
            "/v1/review-accountability/{event_id}",
            get(review_accountability),
        )
        .route("/v1/work-items", get(list_items))
        .route("/v1/work-items/next", get(next_item))
        .route("/v1/work-items/{item_id}", get(get_item))
        .route("/v1/work-items/{item_id}/clocks", get(work_item_clocks))
        .route("/v1/work-items/{item_id}/claim", post(claim))
        .route("/v1/work-items/{item_id}/release", post(release))
        .route("/v1/work-items/{item_id}/assign", post(assign_item))
        .route("/v1/work-items/{item_id}/delegate", post(delegate_item))
        .route(
            "/v1/work-items/{item_id}/draft",
            get(get_draft).put(save_draft).delete(delete_draft),
        )
        .route("/v1/work-items/{item_id}/decisions", post(decide))
        .route(
            "/v1/work-items/{item_id}/attempts/recover",
            post(recover_by_key),
        )
        .route(
            "/v1/work-items/{item_id}/attempts/{attempt_id}/recover",
            post(recover),
        )
        .route("/v1/work-items/{item_id}/history", get(history))
        .route("/v1/holdings", get(holdings))
        .route("/v1/directory", get(directory))
        .route("/v1/directory/targets", get(directory_targets))
        .route(
            "/v1/directory/teams/{team_id}",
            axum::routing::put(update_directory_team),
        )
        .route("/v1/directory/bootstrap", post(bootstrap))
        .route("/v1/directory/holidays", post(create_holiday_revision))
        .route(
            "/v1/directory/holidays/{id}/revisions/{revision}",
            get(holiday_revision),
        )
        .route(
            "/v1/directory/clocks/recompute/preview",
            post(preview_clock_recompute),
        )
        .route(
            "/v1/directory/clocks/recompute/apply",
            post(apply_clock_recompute),
        )
        .route("/v1/directory/absences", get(absences).post(create_absence))
        .route(
            "/v1/directory/absences/{absence_id}",
            axum::routing::put(update_absence).delete(delete_absence),
        )
        .route(
            "/v1/directory/caseload/preview",
            post(preview_caseload_move),
        )
        .route("/v1/directory/caseload/apply", post(apply_caseload_move))
        .route("/events/sources/{source_id}", post(source_event));
    http_edge(app).with_state(state)
}

fn http_edge<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .fallback(route_not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(request_body_limit_default())
        .layer(middleware::from_fn(http_boundary))
        .layer(security_headers(CspBuilder::restrictive()).without_hsts())
}

async fn http_boundary(request: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let trace = TraceContext::from_headers(request.headers());
    let mut response = REQUEST_TRACE
        .scope(trace.clone(), async move {
            normalize_framework_rejection(next.run(request).await)
        })
        .await;
    trace.apply(response.headers_mut());
    response.headers_mut().insert(
        CACHE_CONTROL,
        "no-store"
            .parse()
            .expect("the no-store policy is a valid header value"),
    );
    response
}

fn normalize_framework_rejection(response: Response) -> Response {
    let is_problem = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        == Some("application/problem+json");
    if is_problem {
        return response;
    }
    let problem = match response.status() {
        StatusCode::BAD_REQUEST => Some(ProblemCode::RequestInvalid),
        StatusCode::PAYLOAD_TOO_LARGE => Some(ProblemCode::RequestBodyTooLarge),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => Some(ProblemCode::RequestUnsupportedMediaType),
        StatusCode::UNPROCESSABLE_ENTITY => Some(ProblemCode::RequestUnprocessable),
        _ => None,
    };
    problem.map_or(response, |problem| problem_response(problem, None, None))
}

async fn route_not_found() -> Response {
    problem_response(ProblemCode::RequestNotFound, None, None)
}

async fn method_not_allowed() -> Response {
    problem_response(ProblemCode::RequestMethodNotAllowed, None, None)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<HttpState>) -> Result<StatusCode, HttpError> {
    if state.service.ready().await.is_ok() {
        Ok(StatusCode::OK)
    } else {
        Err(HttpError::ServiceUnavailable)
    }
}

async fn description(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Description>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(Description {
        project_id: state.project.casework.id.clone(),
        policy_version: state.project.casework.version.clone(),
        queues: state
            .project
            .queues
            .iter()
            .map(|queue| QueueRecord {
                id: queue.id.clone(),
                label: queue.label.clone(),
            })
            .collect(),
        sources: if actor.role == CaseworkRole::Requester {
            Vec::new()
        } else {
            state.project.sources.clone()
        },
        calendars: if actor.role == CaseworkRole::Requester {
            Vec::new()
        } else {
            state.project.calendars.clone()
        },
        clocks: if actor.role == CaseworkRole::Requester {
            Vec::new()
        } else {
            state.project.clocks.clone()
        },
    }))
}

async fn create_review_request(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<ReviewCreateRequest>,
) -> Result<Response, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    let outcome = state
        .service
        .create_review_request(&actor, request, idempotency_key(&headers)?)
        .await
        .map_err(HttpError::from)?;
    let status = if outcome.recovered {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(outcome.accepted)).into_response())
}

async fn review_kind_descriptions(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ReviewKindPolicySnapshot>>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(state.service.review_kind_descriptions(&actor)?))
}

async fn review_kind_description(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(kind_id): Path<String>,
) -> Result<Json<ReviewKindPolicySnapshot>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state.service.review_kind_description(&actor, &kind_id)?,
    ))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewTaskQuery {
    queue: Option<String>,
    cursor: Option<Uuid>,
    limit: Option<usize>,
}

async fn review_tasks(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ReviewTaskQuery>,
) -> Result<Json<ReviewTaskPage>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_tasks(
                &actor,
                source_profile_id,
                token,
                query.queue.as_deref(),
                query.cursor,
                page_limit(&state, query.limit)?,
            )
            .await?,
    ))
}

async fn get_review_task(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
) -> Result<Json<ReviewerTask>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_task(&actor, task_id, source_profile_id, token)
            .await?,
    ))
}

async fn get_review_task_context(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
) -> Result<Json<ReviewTaskContext>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_task_context(&actor, task_id, source_profile_id, token)
            .await?,
    ))
}

async fn get_review_request(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
) -> Result<Json<ReviewRequestView>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_request(&actor, request_id)
            .await
            .map_err(HttpError::from)?,
    ))
}

async fn get_review_result(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
) -> Result<Response, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    match state.service.review_result(&actor, request_id).await {
        Ok(ReviewResultRead::Available(result)) => Ok(Json(result).into_response()),
        Ok(ReviewResultRead::Pending) => Ok(StatusCode::ACCEPTED.into_response()),
        Ok(ReviewResultRead::Expired) => Ok(StatusCode::GONE.into_response()),
        Err(ReviewRuntimeError::NotFound) => Ok(StatusCode::NOT_FOUND.into_response()),
        Err(error) => Err(HttpError::from(error)),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewFeedQuery {
    cursor: Option<Uuid>,
    limit: Option<usize>,
}

async fn review_result_feed(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ReviewFeedQuery>,
) -> Result<Json<ReviewResultFeedPage>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_result_feed(&actor, query.cursor, query.limit.unwrap_or(25))
            .await
            .map_err(HttpError::from)?,
    ))
}

async fn cancel_review_request(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
    Json(request): Json<ReviewCancelRequest>,
) -> Result<Response, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .cancel_review_request(&actor, request_id, request, idempotency_key(&headers)?)
            .await
            .map_err(HttpError::from)?,
    )
    .into_response())
}

async fn claim_review_task(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, HttpError> {
    if !body.is_empty() {
        return Err(HttpError::Invalid);
    }
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .claim_review_task(
                &actor,
                task_id,
                source_profile_id,
                token,
                if_match(&headers)?,
                idempotency_key(&headers)?,
            )
            .await
            .map_err(HttpError::from)?,
    )
    .into_response())
}

async fn assign_review_task(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
    Json(request): Json<AssignmentRequest>,
) -> Result<Json<ReviewerTask>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .assign_review_task(
                &actor,
                task_id,
                source_profile_id,
                token,
                if_match(&headers)?,
                request,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
}

async fn delegate_review_task(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
    Json(request): Json<DelegateRequest>,
) -> Result<Json<ReviewerTask>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .delegate_review_task(
                &actor,
                task_id,
                source_profile_id,
                token,
                if_match(&headers)?,
                request,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
}

async fn get_review_task_draft(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
) -> Result<Response, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    match state
        .service
        .review_task_draft(&actor, task_id, source_profile_id, token)
        .await?
    {
        Some(draft) => Ok(Json(draft).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn save_review_task_draft(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
    Json(input): Json<ReviewTaskDraftInput>,
) -> Result<Json<ReviewTaskDraft>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .save_review_task_draft(
                &actor,
                task_id,
                source_profile_id,
                token,
                if_match(&headers)?,
                input,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
}

async fn delete_review_task_draft(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
) -> Result<StatusCode, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    state
        .service
        .delete_review_task_draft(
            &actor,
            task_id,
            source_profile_id,
            token,
            if_match(&headers)?,
            idempotency_key(&headers)?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewHistoryQuery {
    cursor: Option<Uuid>,
    limit: Option<usize>,
}

async fn review_history(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
    Query(query): Query<ReviewHistoryQuery>,
) -> Result<Json<ReviewHistoryPage>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_history(
                &actor,
                request_id,
                source_profile_id,
                token,
                query.cursor,
                query.limit.unwrap_or(25),
            )
            .await?,
    ))
}

async fn review_clocks(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
) -> Result<Json<Vec<registry_casework_core::ReviewClockOccurrence>>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_clocks(&actor, request_id, source_profile_id, token)
            .await?,
    ))
}

async fn add_review_note(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
    Json(request): Json<ReviewNoteRequest>,
) -> Result<Json<ReviewHistoryEntry>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .add_review_note(
                &actor,
                request_id,
                source_profile_id,
                token,
                request,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
}

async fn review_accountability(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(event_id): Path<Uuid>,
) -> Result<Json<ReviewAccountabilityRecord>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_accountability(&actor, event_id)
            .await?,
    ))
}

async fn release_review_task(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, HttpError> {
    reject_source_profile(&headers)?;
    if !body.is_empty() {
        return Err(HttpError::Invalid);
    }
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .release_review_task(
                &actor,
                task_id,
                if_match(&headers)?,
                idempotency_key(&headers)?,
            )
            .await
            .map_err(HttpError::from)?,
    )
    .into_response())
}

async fn decide_review_task(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
    Json(request): Json<ReviewTaskDecisionRequest>,
) -> Result<StatusCode, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    state
        .service
        .decide_review_task(
            &actor,
            task_id,
            request,
            source_profile_id,
            token,
            if_match(&headers)?,
            idempotency_key(&headers)?,
        )
        .await
        .map_err(HttpError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_items(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ListWorkItemsQuery>,
) -> Result<Json<registry_casework_core::WorkItemPage>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let source_profile = source_profile(&headers)?;
    let limit = page_limit(&state, query.limit)?;
    let subject = query.subject().map_err(|_| HttpError::Invalid)?;
    let reference = query.reference().map_err(|_| HttpError::Invalid)?;
    if reference.is_some()
        && !state.service.project.sources.iter().any(|source| {
            source.requests.iter().any(|request| {
                request.display_reference.is_some()
                    && query
                        .queue
                        .as_deref()
                        .is_none_or(|queue| request.queue == queue)
            })
        })
    {
        return Err(HttpError::Invalid);
    }
    let page = state
        .service
        .inbox_for_view_query(
            &actor,
            source_profile,
            token,
            query.view,
            limit,
            query.queue.as_deref(),
            subject.as_ref(),
            reference,
            query.sort,
            query.cursor.as_deref(),
        )
        .await?;
    Ok(Json(page))
}

async fn next_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<NextWorkItemQuery>,
) -> Result<Response, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let source_profile = source_profile(&headers)?;
    let page = state
        .service
        .next_item(
            &actor,
            source_profile,
            token,
            query.queue.as_deref(),
            query.cursor.as_deref(),
        )
        .await?;
    Ok(Json(page).into_response())
}

async fn get_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<registry_casework_core::WorkItem>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let item = state
        .service
        .open_source_item(&actor, item_id, source_profile(&headers)?, token)
        .await?;
    Ok(Json(item))
}

async fn claim(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<MutationResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let expected_revision = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let item = state
        .service
        .claim_source_item(
            &actor,
            item_id,
            expected_revision,
            source_profile(&headers)?,
            key,
            token,
        )
        .await
        .map_err(HttpError::from_source_event)?;
    Ok(Json(MutationResponse {
        item,
        attempt: None,
    }))
}

async fn release(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<MutationResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let expected_revision = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let item = state
        .service
        .release_source_item(
            &actor,
            item_id,
            expected_revision,
            source_profile(&headers)?,
            key,
            token,
        )
        .await?;
    Ok(Json(MutationResponse {
        item,
        attempt: None,
    }))
}

async fn get_draft(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<DraftResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let draft = state
        .service
        .source_draft(&actor, item_id, source_profile(&headers)?, token)
        .await?;
    Ok(Json(DraftResponse { draft }))
}

async fn save_draft(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<SaveDraftRequest>,
) -> Result<Json<DraftResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let source_profile = source_profile(&headers)?;
    let expected_revision = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let draft = state
        .service
        .save_source_draft(
            &actor,
            item_id,
            expected_revision,
            source_profile,
            &request.binding,
            &request.reason,
            &request.flagged_fields,
            key,
            token,
        )
        .await?;
    Ok(Json(DraftResponse { draft }))
}

async fn delete_draft(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<StatusCode, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let source_profile = source_profile(&headers)?;
    let expected_revision = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    state
        .service
        .delete_source_draft(
            &actor,
            item_id,
            expected_revision,
            source_profile,
            key,
            token,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn decide(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<DecideRequest>,
) -> Result<Json<MutationResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let selected_source_profile = source_profile(&headers)?;
    if request.source_profile_id != selected_source_profile {
        return Err(HttpError::Invalid);
    }
    let response = state
        .service
        .decide_mutation(
            &actor,
            item_id,
            if_match_allow_zero(&headers)?,
            selected_source_profile,
            request.operation,
            request.reason.as_deref(),
            &request.flagged_fields,
            &request.displayed_binding,
            idempotency_key(&headers)?,
            token,
        )
        .await?;
    Ok(Json(response))
}

async fn recover(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(path): Path<AttemptPath>,
    Json(request): Json<RecoverAttemptRequest>,
) -> Result<Json<MutationResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let selected_source_profile = source_profile(&headers)?;
    if request.source_profile_id != selected_source_profile {
        return Err(HttpError::Invalid);
    }
    let response = state
        .service
        .recover_mutation(
            &actor,
            path.item_id,
            path.attempt_id,
            selected_source_profile,
            token,
        )
        .await?;
    Ok(Json(response))
}

async fn recover_by_key(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<RecoverAttemptRequest>,
) -> Result<Json<MutationResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let selected_source_profile = source_profile(&headers)?;
    if request.source_profile_id != selected_source_profile {
        return Err(HttpError::Invalid);
    }
    let response = state
        .service
        .recover_mutation_by_key(
            &actor,
            item_id,
            selected_source_profile,
            idempotency_key(&headers)?,
            token,
        )
        .await?;
    Ok(Json(response))
}

async fn history(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Query(query): Query<ReviewPageQuery>,
) -> Result<Json<HistoryPage>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .source_history(
                &actor,
                item_id,
                source_profile(&headers)?,
                token,
                page_limit(&state, query.limit)?,
                query.cursor.as_deref(),
            )
            .await?,
    ))
}

async fn holdings(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<HoldingsQuery>,
) -> Result<Json<registry_casework_core::HoldingsPage>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let page = state
        .service
        .caller_visible_holdings(
            &actor,
            source_profile(&headers)?,
            token,
            page_limit(&state, query.limit)?,
            query.cursor.as_deref(),
        )
        .await?;
    Ok(Json(page))
}

async fn directory(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<DirectoryResponse>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    let (revision, teams) = state.service.store().directory(&actor).await?;
    Ok(Json(DirectoryResponse { revision, teams }))
}

async fn directory_targets(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<DirectoryTargetsQuery>,
) -> Result<Json<DirectoryTargetPage>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    query.check().map_err(|_| HttpError::Invalid)?;
    let person = query.person();
    Ok(Json(
        state
            .service
            .directory_targets(
                &actor,
                query.purpose,
                query.queue.as_deref(),
                person.as_ref(),
                page_limit(&state, query.limit)?,
                query.cursor.as_deref(),
            )
            .await?,
    ))
}

async fn update_directory_team(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(team_id): Path<String>,
    Json(request): Json<DirectoryTeamUpdateRequest>,
) -> Result<Json<DirectoryResponse>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    state
        .service
        .update_directory_team(
            &actor,
            if_match_allow_zero(&headers)?,
            &team_id,
            &request,
            idempotency_key(&headers)?,
        )
        .await?;
    let (revision, teams) = state.service.store().directory(&actor).await?;
    Ok(Json(DirectoryResponse { revision, teams }))
}

async fn bootstrap(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<BootstrapDirectoryRequest>,
) -> Result<Json<DirectoryResponse>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    state
        .service
        .bootstrap_directory(
            &actor,
            if_match_allow_zero(&headers)?,
            &request,
            idempotency_key(&headers)?,
        )
        .await?;
    let (revision, teams) = state.service.store().directory(&actor).await?;
    Ok(Json(DirectoryResponse { revision, teams }))
}

async fn work_item_clocks(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<Vec<ClockOccurrenceView>>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .work_item_clocks(&actor, item_id, source_profile(&headers)?, token)
            .await?,
    ))
}

async fn create_holiday_revision(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(input): Json<HolidaySetRevisionInput>,
) -> Result<(StatusCode, Json<HolidaySetDocument>), HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    state
        .service
        .create_holiday_revision(&actor, &input.document, idempotency_key(&headers)?)
        .await?;
    Ok((StatusCode::CREATED, Json(input.document)))
}

async fn holiday_revision(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((id, revision)): Path<(String, u64)>,
) -> Result<Json<HolidaySetDocument>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .holiday_revision(&actor, &id, revision)
            .await?,
    ))
}

async fn preview_clock_recompute(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(input): Json<ClockRecomputeRequest>,
) -> Result<Json<ClockRecomputePreview>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .preview_clock_recompute(&actor, &input)
            .await?,
    ))
}

async fn apply_clock_recompute(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(input): Json<ClockRecomputeApplyRequest>,
) -> Result<Json<ClockRecomputeResult>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .apply_clock_recompute(&actor, input.preview_id, idempotency_key(&headers)?)
            .await
            .map_err(|error| match error {
                ServiceError::Store(StoreError::CursorExpired) => {
                    HttpError::ClockRecomputePreviewExpired
                }
                other => HttpError::from(other),
            })?,
    ))
}

async fn absences(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<AbsencesQuery>,
) -> Result<Json<AbsenceList>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .absences_page(
                &actor,
                query.limit.unwrap_or(1_000),
                query.cursor.as_deref(),
            )
            .await?,
    ))
}

async fn create_absence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(input): Json<AbsenceInput>,
) -> Result<(StatusCode, Json<AbsenceRecord>), HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    let absence = state
        .service
        .create_absence(
            &actor,
            if_match_allow_zero(&headers)?,
            &input,
            idempotency_key(&headers)?,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(absence)))
}

async fn update_absence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(absence_id): Path<Uuid>,
    Json(input): Json<AbsenceInput>,
) -> Result<Json<AbsenceRecord>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .update_absence(
                &actor,
                absence_id,
                if_match(&headers)?,
                &input,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
}

async fn delete_absence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(absence_id): Path<Uuid>,
) -> Result<StatusCode, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    state
        .service
        .delete_absence(
            &actor,
            absence_id,
            if_match(&headers)?,
            idempotency_key(&headers)?,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn assign_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<AssignmentRequest>,
) -> Result<Json<MutationResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let item = state
        .service
        .assign_item(
            &actor,
            source_profile_optional(&headers)?,
            token,
            item_id,
            if_match(&headers)?,
            &request,
            idempotency_key(&headers)?,
        )
        .await?;
    Ok(Json(MutationResponse {
        item,
        attempt: None,
    }))
}

async fn delegate_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<DelegateRequest>,
) -> Result<Json<MutationResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let item = state
        .service
        .delegate_item(
            &actor,
            source_profile_optional(&headers)?,
            token,
            item_id,
            if_match(&headers)?,
            &request,
            idempotency_key(&headers)?,
        )
        .await?;
    Ok(Json(MutationResponse {
        item,
        attempt: None,
    }))
}

async fn preview_caseload_move(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<CaseloadPreviewQuery>,
    Json(movement): Json<CaseloadMoveRequest>,
) -> Result<Json<CaseloadPreviewPage>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .preview_caseload_move(
                &actor,
                source_profile_optional(&headers)?,
                token,
                &movement,
                page_limit(&state, query.limit)?,
                query.cursor.as_deref(),
            )
            .await?,
    ))
}

async fn apply_caseload_move(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<CaseloadApplyRequest>,
) -> Result<Json<Vec<CaseloadItemResult>>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .apply_caseload_move(
                &actor,
                source_profile_optional(&headers)?,
                token,
                &request,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
}

async fn source_event(
    State(state): State<HttpState>,
    Path(source_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, HttpError> {
    let headers = headers
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                .map_err(|_| HttpError::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    state
        .service
        .receive_event(
            &source_id,
            EventRequest {
                headers,
                body: body.to_vec(),
            },
        )
        .await
        .map_err(HttpError::from_source_event)?;
    Ok(StatusCode::ACCEPTED)
}

async fn task_jwks(State(state): State<HttpState>) -> Result<Json<serde_json::Value>, HttpError> {
    Ok(Json(state.service.task_jwks()?))
}
async fn preview_task_templates(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item): Path<Uuid>,
) -> Result<Json<registry_casework_core::TaskTemplatePreviews>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .preview_tasks(&actor, item, source_profile(&headers)?, token)
            .await?,
    ))
}
async fn approve_task_grant(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item): Path<Uuid>,
    Json(request): Json<registry_casework_core::TaskApprovalRequest>,
) -> Result<Json<registry_casework_core::TaskGrantView>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .approve_task(
                &actor,
                item,
                if_match(&headers)?,
                source_profile(&headers)?,
                idempotency_key(&headers)?,
                token,
                request,
            )
            .await?,
    ))
}
async fn list_task_grants(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item): Path<Uuid>,
) -> Result<Json<registry_casework_core::TaskGrantList>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .list_tasks(&actor, item, source_profile(&headers)?, token)
            .await?,
    ))
}
async fn revoke_task_grant(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((item, grant)): Path<(Uuid, Uuid)>,
    body: Bytes,
) -> Result<Json<registry_casework_core::TaskGrantRevocation>, HttpError> {
    if !body.is_empty() {
        return Err(HttpError::Invalid);
    }
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(state.service.revoke_task(&actor, item, grant).await?))
}
async fn preview_review_task_templates(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
) -> Result<Json<registry_casework_core::TaskTemplatePreviews>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .preview_review_task_templates(&actor, task_id, source_profile(&headers)?, token)
            .await?,
    ))
}
async fn approve_review_task_grant(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
    Json(request): Json<registry_casework_core::TaskApprovalRequest>,
) -> Result<Json<registry_casework_core::TaskGrantView>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .approve_review_task(
                &actor,
                task_id,
                if_match(&headers)?,
                source_profile(&headers)?,
                idempotency_key(&headers)?,
                token,
                request,
            )
            .await?,
    ))
}
async fn list_review_task_grants(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
) -> Result<Json<registry_casework_core::TaskGrantList>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .list_review_task_grants(&actor, task_id, source_profile(&headers)?, token)
            .await?,
    ))
}
async fn revoke_review_task_grant(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((task_id, grant_id)): Path<(Uuid, Uuid)>,
    body: Bytes,
) -> Result<Json<registry_casework_core::TaskGrantRevocation>, HttpError> {
    if !body.is_empty() {
        return Err(HttpError::Invalid);
    }
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .revoke_review_task_grant(&actor, task_id, grant_id)
            .await?,
    ))
}
async fn task_client(
    state: &HttpState,
    headers: &HeaderMap,
    scope: &str,
    kind: registry_platform_oidc::ActorKind,
) -> Result<registry_platform_oidc::VerifiedToken, HttpError> {
    if headers.contains_key(CASEWORK_PROFILE_HEADER) || headers.contains_key(SOURCE_PROFILE_HEADER)
    {
        return Err(HttpError::AuthenticationRefused);
    }
    let raw = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(HttpError::AuthenticationRefused)?;
    let token = parse_bearer_token(raw).map_err(|_| HttpError::AuthenticationRefused)?;
    state
        .authenticator
        .authenticate_task_client(token, scope, kind)
        .await
        .map_err(|_| HttpError::AuthenticationRefused)
}
async fn task_assertion(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(grant): Path<Uuid>,
    body: Bytes,
) -> Result<Json<registry_casework_core::TaskAssertionResponse>, HttpError> {
    if !body.is_empty() {
        return Err(HttpError::Invalid);
    }
    let client = task_client(
        &state,
        &headers,
        "casework:grants:assert",
        registry_platform_oidc::ActorKind::Agent,
    )
    .await?;
    Ok(Json(state.service.task_assertion(grant, &client).await?))
}
async fn task_status(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(grant): Path<Uuid>,
) -> Result<Json<registry_casework_core::TaskGrantStatus>, HttpError> {
    let client = task_client(
        &state,
        &headers,
        "casework:grants:status",
        registry_platform_oidc::ActorKind::Service,
    )
    .await?;
    Ok(Json(state.service.task_status(grant, &client).await?))
}

async fn authenticate<'a>(
    state: &HttpState,
    headers: &'a HeaderMap,
) -> Result<(registry_casework_core::ActorContext, &'a str), HttpError> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(HttpError::AuthenticationRefused)?;
    let token = parse_bearer_token(authorization).map_err(|_| HttpError::AuthenticationRefused)?;
    let profile = profile_header(headers, CASEWORK_PROFILE_HEADER)?;
    let actor = state
        .authenticator
        .authenticate(token, profile)
        .await
        .map_err(|error| match error {
            AuthenticationError::Refused => HttpError::AuthenticationRefused,
            AuthenticationError::Profile => HttpError::ProfileNotAuthorized,
            AuthenticationError::NotHuman => HttpError::ProfileNotHuman,
            AuthenticationError::Claims => HttpError::AuthenticationRefused,
        })?;
    Ok((actor, token))
}

fn source_profile(headers: &HeaderMap) -> Result<&str, HttpError> {
    if !headers.contains_key(SOURCE_PROFILE_HEADER) {
        return Err(HttpError::SourceProfileRequired);
    }
    profile_header(headers, SOURCE_PROFILE_HEADER)
}

fn source_profile_optional(headers: &HeaderMap) -> Result<Option<&str>, HttpError> {
    headers
        .contains_key(SOURCE_PROFILE_HEADER)
        .then(|| source_profile(headers))
        .transpose()
}

fn reject_source_profile(headers: &HeaderMap) -> Result<(), HttpError> {
    if headers.contains_key(SOURCE_PROFILE_HEADER) {
        return Err(HttpError::SourceProfileNotApplicable);
    }
    Ok(())
}

fn page_limit(state: &HttpState, requested: Option<usize>) -> Result<usize, HttpError> {
    let limit = requested.unwrap_or(state.service.inbox_policy().default_page_size);
    (1..=MAXIMUM_PAGE_SIZE)
        .contains(&limit)
        .then_some(limit)
        .ok_or(HttpError::Invalid)
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, HttpError> {
    let value = header(headers, IDEMPOTENCY_KEY_HEADER)?;
    if value.len() > MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(HttpError::Invalid);
    }
    Ok(value)
}

fn profile_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, HttpError> {
    let value = header(headers, name)?;
    if value.len() > MAXIMUM_CASEWORK_PROFILE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(HttpError::Invalid);
    }
    Ok(value)
}

fn header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, HttpError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or(HttpError::Invalid)
}

fn if_match(headers: &HeaderMap) -> Result<i64, HttpError> {
    if_match_with_minimum(headers, 1)
}

fn if_match_allow_zero(headers: &HeaderMap) -> Result<i64, HttpError> {
    if_match_with_minimum(headers, 0)
}

fn if_match_with_minimum(headers: &HeaderMap, minimum: i64) -> Result<i64, HttpError> {
    let value = headers
        .get(IF_MATCH_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or(HttpError::PreconditionRequired)?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(HttpError::Invalid)?;
    value
        .parse()
        .ok()
        .filter(|value| *value >= minimum)
        .ok_or(HttpError::Invalid)
}

#[derive(Debug)]
pub enum HttpError {
    ClockRecomputePreviewExpired,
    Absence(registry_casework_core::AbsenceError),
    AuthenticationRefused,
    CursorExpired,
    CursorInvalid,
    IdempotencyExpired,
    ProfileNotAuthorized,
    ProfileNotHuman,
    Forbidden,
    NotFound,
    PreconditionFailed,
    PreconditionRequired,
    ProposalChanged,
    Superseded,
    AlreadyClaimed,
    NotHolder,
    RecoveryPending(Option<Uuid>),
    IdempotencyKeyReused,
    NotOffered,
    Invalid,
    ServiceUnavailable,
    SourceNotFound,
    SourceProfileNotApplicable,
    SourceProfileRequired,
    SourceBadGateway,
    ReasonUnsupported,
    ReviewInitiatorExcluded,
    ReviewInitiatorRequired,
    ReviewResultExpired,
    ReviewSubmissionConflict,
    ReviewTaskNotHeld,
    SourceRecordMissing,
    SourceRequestRejected,
    SourceReviewerNotAuthorized,
    SourceSignatureInvalid,
    SourceUnavailable(Option<Uuid>),
    Internal,
    Validation(ReviewValidationError),
}

impl From<StoreError> for HttpError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Absence(error) => Self::Absence(error),
            StoreError::CursorExpired => Self::CursorExpired,
            StoreError::CursorInvalid => Self::CursorInvalid,
            StoreError::IdempotencyExpired => Self::IdempotencyExpired,
            StoreError::NotFound => Self::NotFound,
            StoreError::Forbidden => Self::Forbidden,
            StoreError::Conflict => Self::PreconditionFailed,
            StoreError::StaleGeneration => Self::Superseded,
            StoreError::AlreadyClaimed => Self::AlreadyClaimed,
            StoreError::NotHolder => Self::NotHolder,
            StoreError::IdempotencyConflict => Self::IdempotencyKeyReused,
            StoreError::AttemptPending => Self::RecoveryPending(None),
            StoreError::Invalid => Self::Invalid,
            StoreError::ReviewValidation(validation) => Self::Validation(validation),
            StoreError::Unavailable | StoreError::AuditUnavailable | StoreError::Postgres(_) => {
                Self::ServiceUnavailable
            }
            StoreError::Configuration
            | StoreError::SecretConfiguration(_)
            | StoreError::Corrupt
            | StoreError::SchemaNewer { .. }
            | StoreError::HostedWorkWouldBeDropped { .. }
            | StoreError::UnpublishedAuditWouldBeDropped { .. }
            | StoreError::Json(_) => Self::Internal,
        }
    }
}

impl From<ServiceError> for HttpError {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::Configuration => Self::Internal,
            ServiceError::Source => Self::SourceNotFound,
            ServiceError::SourceProtocol => Self::SourceBadGateway,
            ServiceError::Store(error) => error.into(),
            ServiceError::NotFound => Self::NotFound,
            ServiceError::Forbidden => Self::Forbidden,
            ServiceError::ReviewValidation(validation) => Self::Validation(validation),
            ServiceError::BindingMoved => Self::ProposalChanged,
            ServiceError::UncertainAttempt(attempt_id) => Self::RecoveryPending(Some(attempt_id)),
            ServiceError::PostWriteSourceUnavailable(attempt_id) => {
                Self::SourceUnavailable(Some(attempt_id))
            }
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::Unavailable) => {
                Self::SourceUnavailable(None)
            }
            ServiceError::Adapter(
                registry_casework_core::SourceAdapterError::Concealed
                | registry_casework_core::SourceAdapterError::Denied,
            ) => Self::NotFound,
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::BindingMoved) => {
                Self::ProposalChanged
            }
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::RequestRejected) => {
                Self::SourceRequestRejected
            }
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::RecordMissing) => {
                Self::SourceRecordMissing
            }
            ServiceError::Adapter(
                registry_casework_core::SourceAdapterError::ReviewerNotAuthorized,
            ) => Self::SourceReviewerNotAuthorized,
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::ActionNotOffered) => {
                Self::NotOffered
            }
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::Uncertain) => {
                Self::RecoveryPending(None)
            }
            ServiceError::Adapter(
                registry_casework_core::SourceAdapterError::ReasonUnsupported,
            ) => Self::ReasonUnsupported,
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::Invalid) => {
                Self::SourceBadGateway
            }
        }
    }
}

impl From<ReviewRuntimeError> for HttpError {
    fn from(error: ReviewRuntimeError) -> Self {
        match error {
            ReviewRuntimeError::NotFound => Self::NotFound,
            ReviewRuntimeError::Forbidden => Self::Forbidden,
            ReviewRuntimeError::SubmissionConflict => Self::ReviewSubmissionConflict,
            ReviewRuntimeError::ResultExpired => Self::ReviewResultExpired,
            ReviewRuntimeError::TaskNotHeld => Self::ReviewTaskNotHeld,
            ReviewRuntimeError::InitiatorExcluded => Self::ReviewInitiatorExcluded,
            ReviewRuntimeError::InitiatorRequired => Self::ReviewInitiatorRequired,
            ReviewRuntimeError::SourceProfileRequired => Self::SourceProfileRequired,
            ReviewRuntimeError::SourceProfileNotApplicable => Self::SourceProfileNotApplicable,
            ReviewRuntimeError::SourceUnavailable => {
                tracing::warn!(
                    "Casework review preflight timed out waiting on a bound source read"
                );
                Self::SourceUnavailable(None)
            }
            ReviewRuntimeError::SourceInvalid => Self::SourceBadGateway,
            ReviewRuntimeError::RevisionConflict => Self::PreconditionFailed,
            ReviewRuntimeError::IdempotencyConflict => Self::IdempotencyKeyReused,
            ReviewRuntimeError::IdempotencyExpired => Self::IdempotencyExpired,
            ReviewRuntimeError::Invalid => Self::Invalid,
            ReviewRuntimeError::Validation(validation) => Self::Validation(validation),
            ReviewRuntimeError::Corrupt => Self::Internal,
            ReviewRuntimeError::Store(error) => error.into(),
        }
    }
}

impl HttpError {
    fn from_source_event(error: ServiceError) -> Self {
        match error {
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::Invalid) => {
                Self::SourceSignatureInvalid
            }
            other => other.into(),
        }
    }

    fn problem(&self) -> ProblemCode {
        match self {
            Self::ClockRecomputePreviewExpired => ProblemCode::ClockRecomputePreviewExpired,
            Self::AuthenticationRefused => ProblemCode::AuthenticationRefused,
            Self::CursorExpired => ProblemCode::CursorExpired,
            Self::CursorInvalid => ProblemCode::CursorInvalid,
            Self::IdempotencyExpired => ProblemCode::IdempotencyExpired,
            Self::ProfileNotAuthorized => ProblemCode::ProfileNotAuthorized,
            Self::ProfileNotHuman => ProblemCode::ProfileNotHuman,
            Self::Forbidden => ProblemCode::OperationNotAuthorized,
            Self::NotFound => ProblemCode::WorkItemNotVisible,
            Self::PreconditionFailed => ProblemCode::PreconditionFailed,
            Self::PreconditionRequired => ProblemCode::PreconditionRequired,
            Self::ProposalChanged => ProblemCode::WorkItemProposalChanged,
            Self::Superseded => ProblemCode::WorkItemSuperseded,
            Self::AlreadyClaimed => ProblemCode::WorkItemAlreadyClaimed,
            Self::NotHolder => ProblemCode::WorkItemNotHolder,
            Self::RecoveryPending(_) => ProblemCode::WorkItemRecoveryPending,
            Self::IdempotencyKeyReused => ProblemCode::IdempotencyKeyReused,
            Self::NotOffered => ProblemCode::WorkItemNotOffered,
            Self::Invalid => ProblemCode::RequestInvalid,
            Self::ServiceUnavailable => ProblemCode::ServiceUnavailable,
            Self::SourceNotFound => ProblemCode::SourceNotFound,
            Self::SourceProfileNotApplicable => ProblemCode::SourceProfileNotApplicable,
            Self::SourceProfileRequired => ProblemCode::SourceProfileRequired,
            Self::SourceBadGateway => ProblemCode::SourceBadGateway,
            Self::ReasonUnsupported => ProblemCode::RequestReasonUnsupported,
            Self::ReviewInitiatorExcluded => ProblemCode::ReviewInitiatorExcluded,
            Self::ReviewInitiatorRequired => ProblemCode::ReviewInitiatorRequired,
            Self::ReviewResultExpired => ProblemCode::ReviewResultExpired,
            Self::ReviewSubmissionConflict => ProblemCode::ReviewSubmissionConflict,
            Self::ReviewTaskNotHeld => ProblemCode::ReviewTaskNotHeld,
            Self::SourceRecordMissing => ProblemCode::SourceRecordMissing,
            Self::SourceRequestRejected => ProblemCode::RequestSourceRejected,
            Self::SourceReviewerNotAuthorized => ProblemCode::SourceReviewerNotAuthorized,
            Self::SourceSignatureInvalid => ProblemCode::SourceSignatureInvalid,
            Self::SourceUnavailable(_) => ProblemCode::WorkItemSourceUnavailable,
            Self::Internal => ProblemCode::RuntimeFailure,
            Self::Validation(_) => ProblemCode::RequestInvalid,
            Self::Absence(error) => match error {
                registry_casework_core::AbsenceError::InvalidPeriod => {
                    ProblemCode::AbsenceInvalidPeriod
                }
                registry_casework_core::AbsenceError::SelfCover => ProblemCode::AbsenceSelfCover,
                registry_casework_core::AbsenceError::OverlappingPeriod => {
                    ProblemCode::AbsenceOverlap
                }
                registry_casework_core::AbsenceError::CoverCycle => ProblemCode::AbsenceCoverCycle,
            },
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let attempt_reference = match &self {
            Self::RecoveryPending(attempt_id) => *attempt_id,
            Self::SourceUnavailable(attempt_id) => *attempt_id,
            _ => None,
        };
        let validation = match &self {
            Self::Validation(validation) => Some(validation),
            _ => None,
        };
        problem_response(self.problem(), attempt_reference, validation)
    }
}

fn problem_response(
    problem: ProblemCode,
    attempt_reference: Option<Uuid>,
    validation: Option<&ReviewValidationError>,
) -> Response {
    let trace = REQUEST_TRACE
        .try_with(Clone::clone)
        .unwrap_or_else(|_| TraceContext::server_created());
    let status = problem.status();
    let body = ProblemBody {
        type_uri: problem.type_uri(),
        title: problem.title(),
        status: status.as_u16(),
        detail: problem.detail(),
        code: problem.code(),
        trace_id: trace.trace_id.clone(),
    };
    let mut response = (
        status,
        [(CONTENT_TYPE, "application/problem+json")],
        Json(body),
    )
        .into_response();
    trace.apply(response.headers_mut());
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            "Bearer"
                .parse()
                .expect("the bearer challenge is a valid header value"),
        );
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response.headers_mut().insert(
            RETRY_AFTER,
            "5".parse()
                .expect("the retry interval is a valid header value"),
        );
    }
    if let Some(attempt_id) = attempt_reference {
        response.headers_mut().insert(
            ATTEMPT_REFERENCE_HEADER,
            attempt_id
                .to_string()
                .parse()
                .expect("UUIDs are valid bounded header values"),
        );
    }
    if let Some(validation) = validation {
        response.headers_mut().insert(
            VALIDATION_PATH_HEADER,
            validation
                .path
                .parse()
                .expect("bounded JSON paths are valid header values"),
        );
        response.headers_mut().insert(
            VALIDATION_REASON_HEADER,
            review_validation_reason(validation.reason)
                .parse()
                .expect("validation reasons are valid header values"),
        );
    }
    response
}

fn review_validation_reason(reason: ReviewValidationReason) -> &'static str {
    match reason {
        ReviewValidationReason::KindNotAllowed => "kind_not_allowed",
        ReviewValidationReason::ReferenceInvalid => "reference_invalid",
        ReviewValidationReason::ObjectRequired => "object_required",
        ReviewValidationReason::MaximumBytesExceeded => "maximum_bytes_exceeded",
        ReviewValidationReason::MaximumDepthExceeded => "maximum_depth_exceeded",
        ReviewValidationReason::SchemaMismatch => "schema_mismatch",
        ReviewValidationReason::OutcomeNotDeclared => "outcome_not_declared",
        ReviewValidationReason::ReasonRequired => "reason_required",
        ReviewValidationReason::TextInvalid => "text_invalid",
        ReviewValidationReason::ResultNotDeclared => "result_not_declared",
        ReviewValidationReason::ResultRequired => "result_required",
        ReviewValidationReason::FieldNotDeclared => "field_not_declared",
        ReviewValidationReason::ConstraintInvalid => "constraint_invalid",
        ReviewValidationReason::ConstraintViolated => "constraint_violated",
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::body::{to_bytes, Body};
    use axum::extract::{Path, State};
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde::Deserialize;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;

    const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        value: String,
    }

    async fn json_route(Path(_id): Path<Uuid>, Json(input): Json<Input>) -> StatusCode {
        let _ = input.value;
        StatusCode::NO_CONTENT
    }

    async fn bounded_header_route(
        State(calls): State<Arc<AtomicUsize>>,
        headers: HeaderMap,
    ) -> Result<StatusCode, HttpError> {
        profile_header(&headers, CASEWORK_PROFILE_HEADER)?;
        source_profile(&headers)?;
        idempotency_key(&headers)?;
        calls.fetch_add(1, Ordering::Relaxed);
        Ok(StatusCode::NO_CONTENT)
    }

    fn edge_fixture() -> Router {
        http_edge(Router::new().route("/json/{id}", post(json_route)))
    }

    #[test]
    fn unsupported_source_reason_is_a_client_problem_without_hiding_bad_gateway() {
        let unsupported = HttpError::from(ServiceError::Adapter(
            registry_casework_core::SourceAdapterError::ReasonUnsupported,
        ));
        assert_eq!(unsupported.problem(), ProblemCode::RequestReasonUnsupported);
        assert_eq!(
            unsupported.problem().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(unsupported.problem().detail().contains("reason"));

        let malformed = HttpError::from(ServiceError::Adapter(
            registry_casework_core::SourceAdapterError::Invalid,
        ));
        assert_eq!(malformed.problem(), ProblemCode::SourceBadGateway);
        assert_eq!(malformed.problem().status(), StatusCode::BAD_GATEWAY);
    }

    #[derive(Clone, Default)]
    struct CapturedOperationalLogs(Arc<Mutex<Vec<u8>>>);

    impl CapturedOperationalLogs {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("operational log buffer").clone())
                .expect("operational logs are UTF-8")
        }
    }

    impl io::Write for CapturedOperationalLogs {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| io::Error::other("operational log buffer poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedOperationalLogs {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn a_review_source_timeout_is_reported_as_source_unavailable_and_logged() {
        let writer = CapturedOperationalLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(writer.clone())
            .finish();
        let mapped = tracing::subscriber::with_default(subscriber, || {
            HttpError::from(ReviewRuntimeError::SourceUnavailable)
        });

        assert_eq!(mapped.problem(), ProblemCode::WorkItemSourceUnavailable);
        assert_eq!(mapped.problem().status(), StatusCode::SERVICE_UNAVAILABLE);

        let output = writer.text();
        let logged: serde_json::Value =
            serde_json::from_str(output.lines().next().expect("a log line was written"))
                .expect("captured log line is JSON");
        assert_eq!(logged["level"], "WARN");
    }

    #[tokio::test]
    async fn http_edge_returns_closed_problems_with_request_trace_and_security_headers() {
        let id = Uuid::nil();
        let cases = [
            (
                Request::builder()
                    .method("GET")
                    .uri("/missing")
                    .body(Body::empty())
                    .expect("fallback request"),
                ProblemCode::RequestNotFound,
            ),
            (
                Request::builder()
                    .method("GET")
                    .uri(format!("/json/{id}"))
                    .body(Body::empty())
                    .expect("method request"),
                ProblemCode::RequestMethodNotAllowed,
            ),
            (
                Request::builder()
                    .method("POST")
                    .uri("/json/not-a-uuid")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":"ok"}"#))
                    .expect("path request"),
                ProblemCode::RequestInvalid,
            ),
            (
                Request::builder()
                    .method("POST")
                    .uri(format!("/json/{id}"))
                    .header(CONTENT_TYPE, "text/plain")
                    .body(Body::from(r#"{"value":"ok"}"#))
                    .expect("media request"),
                ProblemCode::RequestUnsupportedMediaType,
            ),
            (
                Request::builder()
                    .method("POST")
                    .uri(format!("/json/{id}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":1}"#))
                    .expect("shape request"),
                ProblemCode::RequestUnprocessable,
            ),
            (
                Request::builder()
                    .method("POST")
                    .uri(format!("/json/{id}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![b'x'; 1024 * 1024 + 1]))
                    .expect("large request"),
                ProblemCode::RequestBodyTooLarge,
            ),
        ];

        for (mut request, expected) in cases {
            request
                .headers_mut()
                .insert("traceparent", TRACEPARENT.parse().expect("trace header"));
            let response = edge_fixture()
                .oneshot(request)
                .await
                .expect("edge response");
            assert_eq!(response.status(), expected.status(), "{expected}");
            assert_eq!(
                response
                    .headers()
                    .get(CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store"),
                "{expected}"
            );
            assert!(response.headers().contains_key("content-security-policy"));
            assert!(response.headers().contains_key("x-content-type-options"));
            assert!(!response
                .headers()
                .contains_key("access-control-allow-origin"));
            assert!(!response.headers().contains_key("strict-transport-security"));
            assert_eq!(
                response
                    .headers()
                    .get("traceparent")
                    .and_then(|value| value.to_str().ok()),
                Some(TRACEPARENT),
                "{expected}"
            );
            let body = to_bytes(response.into_body(), 16 * 1024)
                .await
                .expect("bounded problem");
            let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem JSON");
            assert_eq!(problem["code"], expected.code(), "{expected}");
            assert_eq!(
                problem["type"],
                format!(
                    "{}{}",
                    registry_casework_core::CASEWORK_PROBLEM_TYPE_BASE,
                    expected.code().replace('.', "/")
                ),
                "{expected}"
            );
            assert_eq!(
                problem["traceId"], "0123456789abcdef0123456789abcdef",
                "{expected}"
            );
        }
    }

    #[tokio::test]
    async fn authentication_and_outage_problems_carry_recovery_headers() {
        let app = http_edge(
            Router::new()
                .route(
                    "/authentication",
                    axum::routing::get(|| async {
                        Err::<StatusCode, _>(HttpError::AuthenticationRefused)
                    }),
                )
                .route(
                    "/outage",
                    axum::routing::get(|| async {
                        Err::<StatusCode, _>(HttpError::ServiceUnavailable)
                    }),
                ),
        );
        let authentication = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/authentication")
                    .body(Body::empty())
                    .expect("authentication request"),
            )
            .await
            .expect("authentication response");
        assert_eq!(authentication.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            authentication
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );
        let outage = app
            .oneshot(
                Request::builder()
                    .uri("/outage")
                    .body(Body::empty())
                    .expect("outage request"),
            )
            .await
            .expect("outage response");
        assert_eq!(outage.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            outage
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
    }

    #[tokio::test]
    async fn invalid_bounded_headers_are_rejected_before_handler_work() {
        for (name, value) in [
            (
                CASEWORK_PROFILE_HEADER,
                "x".repeat(MAXIMUM_CASEWORK_PROFILE_BYTES + 1),
            ),
            (SOURCE_PROFILE_HEADER, "invalid/profile".to_owned()),
            (
                IDEMPOTENCY_KEY_HEADER,
                "x".repeat(MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES + 1),
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let app = http_edge(
                Router::new()
                    .route("/headers", post(bounded_header_route))
                    .with_state(Arc::clone(&calls)),
            );
            let mut request = Request::builder()
                .method("POST")
                .uri("/headers")
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer")
                .header(IDEMPOTENCY_KEY_HEADER, "attempt-1")
                .body(Body::empty())
                .expect("bounded header request");
            request.headers_mut().insert(
                name,
                value
                    .parse()
                    .expect("fixture header value is syntactically valid"),
            );
            let response = app.oneshot(request).await.expect("bounded header response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
            let body = to_bytes(response.into_body(), 16 * 1024)
                .await
                .expect("bounded problem");
            let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem JSON");
            assert_eq!(
                problem["code"],
                ProblemCode::RequestInvalid.code(),
                "{name}"
            );
            assert_eq!(calls.load(Ordering::Relaxed), 0, "{name}");
        }
    }
}
