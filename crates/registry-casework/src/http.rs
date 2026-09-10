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
    AttemptPath, BootstrapDirectoryRequest, CaseworkProject, CaseworkRole, DecideRequest,
    Description, DirectoryResponse, DraftResponse, EventRequest, HistoryPage, HoldingsQuery,
    HostedAccountabilityRecord, HostedCancelRequest, HostedCreateRequest, HostedDecisionRequest,
    HostedHistoryPage, HostedNotePage, HostedNoteRequest, HostedPageQuery, HostedTerminalPage,
    HostedTerminalQuery, HostedTerminalResult, HostedValidationError, HostedValidationReason,
    ListWorkItemsQuery, MutationResponse, NextWorkItemQuery, Page, PageStatus, QueueRecord,
    RecoverAttemptRequest, RequesterHostedItem, SaveDraftRequest, ATTEMPT_REFERENCE_HEADER,
    CASEWORK_PROFILE_HEADER, IDEMPOTENCY_KEY_HEADER, IF_MATCH_HEADER,
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
    AuthenticationError, CaseworkAuthenticator, CaseworkService, ServiceError, StoreError,
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
    http_edge(
        Router::new()
            .route("/health", get(health))
            .route("/ready", get(ready))
            .route("/v1/casework", get(description))
            .route("/v1/hosted-items", post(create_hosted_item))
            .route("/v1/hosted-items/terminal", get(hosted_terminal_items))
            .route("/v1/hosted-items/{item_id}", get(get_hosted_item))
            .route(
                "/v1/hosted-items/{item_id}/notes",
                get(requester_hosted_notes).post(add_hosted_note),
            )
            .route(
                "/v1/hosted-items/{item_id}/cancel",
                post(cancel_hosted_item),
            )
            .route(
                "/v1/hosted-accountability/{event_id}",
                get(hosted_accountability),
            )
            .route("/v1/work-items", get(list_items))
            .route("/v1/work-items/next", get(next_item))
            .route("/v1/work-items/{item_id}", get(get_item))
            .route("/v1/work-items/{item_id}/claim", post(claim))
            .route("/v1/work-items/{item_id}/release", post(release))
            .route(
                "/v1/work-items/{item_id}/draft",
                get(get_draft).put(save_draft).delete(delete_draft),
            )
            .route("/v1/work-items/{item_id}/decisions", post(decide))
            .route(
                "/v1/work-items/{item_id}/hosted-decisions",
                post(decide_hosted_item),
            )
            .route(
                "/v1/work-items/{item_id}/attempts/recover",
                post(recover_by_key),
            )
            .route(
                "/v1/work-items/{item_id}/attempts/{attempt_id}/recover",
                post(recover),
            )
            .route("/v1/work-items/{item_id}/history", get(history))
            .route(
                "/v1/work-items/{item_id}/hosted-history",
                get(hosted_staff_history),
            )
            .route("/v1/holdings", get(holdings))
            .route("/v1/directory", get(directory))
            .route("/v1/directory/bootstrap", post(bootstrap))
            .route("/events/sources/{source_id}", post(source_event)),
    )
    .with_state(state)
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
    if state.service.store().ready().await.is_ok() {
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
    let selected_profile = state
        .project
        .access_profiles
        .iter()
        .find(|profile| profile.id == actor.profile_id)
        .ok_or(HttpError::ProfileNotAuthorized)?;
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
        hosted_kinds: state
            .project
            .hosted_kinds
            .iter()
            .filter(|kind| match actor.role {
                CaseworkRole::Requester => selected_profile.kinds.contains(&kind.id),
                CaseworkRole::Staff | CaseworkRole::Supervisor => {
                    kind.deciding_profiles.contains(&actor.profile_id)
                }
                CaseworkRole::Administrator => true,
            })
            .cloned()
            .collect(),
    }))
}

async fn create_hosted_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<HostedCreateRequest>,
) -> Result<(StatusCode, Json<RequesterHostedItem>), HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    let item = state
        .service
        .hosted_create(&actor, &request, idempotency_key(&headers)?)
        .await?;
    Ok((StatusCode::CREATED, Json(item)))
}

async fn get_hosted_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<RequesterHostedItem>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state.service.hosted_requester_item(&actor, item_id).await?,
    ))
}

async fn add_hosted_note(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<HostedNoteRequest>,
) -> Result<Json<RequesterHostedItem>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .hosted_note(
                &actor,
                item_id,
                if_match(&headers)?,
                &request,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
}

async fn requester_hosted_notes(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Query(query): Query<HostedPageQuery>,
) -> Result<Json<HostedNotePage>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .hosted_requester_notes(
                &actor,
                item_id,
                page_limit(&state, query.limit)?,
                query.cursor.as_deref(),
            )
            .await?,
    ))
}

async fn hosted_accountability(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(event_id): Path<Uuid>,
) -> Result<Json<HostedAccountabilityRecord>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .hosted_accountability_record(&actor, event_id)
            .await?,
    ))
}

async fn cancel_hosted_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<HostedCancelRequest>,
) -> Result<Json<HostedTerminalResult>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .hosted_cancel(
                &actor,
                item_id,
                if_match(&headers)?,
                &request,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
}

async fn hosted_terminal_items(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<HostedTerminalQuery>,
) -> Result<Json<HostedTerminalPage>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .hosted_terminal_page(
                &actor,
                page_limit(&state, query.limit)?,
                crate::HOSTED_TERMINAL_CURSOR_CONTEXT,
                query.cursor.as_deref(),
            )
            .await?,
    ))
}

async fn list_items(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ListWorkItemsQuery>,
) -> Result<Json<registry_casework_core::WorkItemPage>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let source_profile = source_profile_optional(&headers)?;
    let cursor_context = format!(
        "list:{:?}:{}",
        query.view,
        query.queue.as_deref().unwrap_or("")
    );
    let limit = page_limit(&state, query.limit)?;
    let page = if let Some(source_profile) = source_profile {
        state
            .service
            .inbox_for_view(
                &actor,
                source_profile,
                token,
                query.view,
                limit,
                &cursor_context,
                query.cursor.as_deref(),
            )
            .await?
    } else {
        state
            .service
            .hosted_staff_inbox(
                &actor,
                limit,
                crate::HOSTED_STAFF_INBOX_CURSOR_CONTEXT,
                query.cursor.as_deref(),
            )
            .await?
    };
    Ok(Json(page))
}

async fn next_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<NextWorkItemQuery>,
) -> Result<Response, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let source_profile = source_profile(&headers)?;
    let item = state
        .service
        .next_item(
            &actor,
            source_profile,
            token,
            query.queue.as_deref(),
            query.cursor.as_deref(),
        )
        .await;
    if let Ok(item) = item {
        Ok(Json(item).into_response())
    } else {
        match item {
            Err(ServiceError::NotFound) => Ok(StatusCode::NO_CONTENT.into_response()),
            Err(error) => Err(error.into()),
            Ok(_) => unreachable!(),
        }
    }
}

async fn get_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<registry_casework_core::WorkItem>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let item = if let Some(source_profile) = source_profile_optional(&headers)? {
        let item = state
            .service
            .caller_item(&actor, item_id, source_profile, token)
            .await?
            .0;
        state.service.store().record_opened(&actor, item_id).await?;
        item
    } else {
        state.service.hosted_work_item(&actor, item_id).await?
    };
    Ok(Json(item))
}

async fn hosted_staff_history(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Query(query): Query<HostedPageQuery>,
) -> Result<Json<HostedHistoryPage>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .hosted_staff_history(
                &actor,
                item_id,
                page_limit(&state, query.limit)?,
                query.cursor.as_deref(),
            )
            .await?,
    ))
}

async fn claim(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<MutationResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    let expected_revision = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let item = if let Some(source_profile) = source_profile_optional(&headers)? {
        state
            .service
            .caller_item(&actor, item_id, source_profile, token)
            .await
            .map_err(HttpError::from_source_event)?;
        state
            .service
            .store()
            .claim(&actor, item_id, expected_revision, key)
            .await?
    } else {
        state
            .service
            .hosted_claim(&actor, item_id, expected_revision, key)
            .await?
    };
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
    let item = if let Some(source_profile) = source_profile_optional(&headers)? {
        state
            .service
            .caller_item(&actor, item_id, source_profile, token)
            .await?;
        state
            .service
            .store()
            .release(&actor, item_id, expected_revision, key)
            .await?
    } else {
        state
            .service
            .hosted_release(&actor, item_id, expected_revision, key)
            .await?
    };
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
    state
        .service
        .caller_item(&actor, item_id, source_profile(&headers)?, token)
        .await?;
    let draft = state
        .service
        .store()
        .read_draft(&actor, item_id)
        .await?
        .ok_or(HttpError::NotFound)?;
    Ok(Json(DraftResponse { draft }))
}

async fn save_draft(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<SaveDraftRequest>,
) -> Result<Json<DraftResponse>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    state
        .service
        .caller_item(&actor, item_id, source_profile(&headers)?, token)
        .await?;
    let draft = state
        .service
        .store()
        .save_draft(
            &actor,
            item_id,
            if_match(&headers)?,
            &request.binding,
            &request.reason,
            &request.flagged_fields,
            idempotency_key(&headers)?,
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
    state
        .service
        .caller_item(&actor, item_id, source_profile(&headers)?, token)
        .await?;
    state
        .service
        .store()
        .delete_draft(
            &actor,
            item_id,
            if_match(&headers)?,
            idempotency_key(&headers)?,
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
    let (attempt, _) = state
        .service
        .decide(
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
    let item = state.service.store().item(item_id).await?;
    Ok(Json(MutationResponse {
        item,
        attempt: Some(attempt),
    }))
}

async fn decide_hosted_item(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
    Json(request): Json<HostedDecisionRequest>,
) -> Result<Json<HostedTerminalResult>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .hosted_decide(
                &actor,
                item_id,
                if_match(&headers)?,
                &request,
                idempotency_key(&headers)?,
            )
            .await?,
    ))
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
    let (attempt, _) = state
        .service
        .recover(
            &actor,
            path.item_id,
            path.attempt_id,
            selected_source_profile,
            token,
        )
        .await?;
    let item = state.service.store().item(path.item_id).await?;
    Ok(Json(MutationResponse {
        item,
        attempt: Some(attempt),
    }))
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
    let (attempt, _) = state
        .service
        .recover_by_key(
            &actor,
            item_id,
            selected_source_profile,
            idempotency_key(&headers)?,
            token,
        )
        .await?;
    let item = state.service.store().item(item_id).await?;
    Ok(Json(MutationResponse {
        item,
        attempt: Some(attempt),
    }))
}

async fn history(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(item_id): Path<Uuid>,
) -> Result<Json<HistoryPage>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    state
        .service
        .caller_item(&actor, item_id, source_profile(&headers)?, token)
        .await?;
    let items = state.service.store().history(&actor, item_id, 100).await?;
    Ok(Json(Page {
        items,
        next_cursor: None,
        status: PageStatus::Complete,
    }))
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

async fn bootstrap(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<BootstrapDirectoryRequest>,
) -> Result<Json<DirectoryResponse>, HttpError> {
    let (actor, _) = authenticate(&state, &headers).await?;
    state
        .service
        .store()
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
        return Err(HttpError::Invalid);
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
    SourceBadGateway,
    SourceSignatureInvalid,
    SourceUnavailable,
    Internal,
    Validation(HostedValidationError),
}

impl From<StoreError> for HttpError {
    fn from(error: StoreError) -> Self {
        match error {
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
            StoreError::Unavailable | StoreError::Postgres(_) => Self::ServiceUnavailable,
            StoreError::Configuration | StoreError::Corrupt | StoreError::Json(_) => Self::Internal,
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
            ServiceError::HostedValidation(validation) => Self::Validation(validation),
            ServiceError::BindingMoved => Self::ProposalChanged,
            ServiceError::UncertainAttempt(attempt_id) => Self::RecoveryPending(Some(attempt_id)),
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::Unavailable) => {
                Self::SourceUnavailable
            }
            ServiceError::Adapter(
                registry_casework_core::SourceAdapterError::Concealed
                | registry_casework_core::SourceAdapterError::Denied,
            ) => Self::NotFound,
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::BindingMoved) => {
                Self::ProposalChanged
            }
            ServiceError::Adapter(
                registry_casework_core::SourceAdapterError::DefinitiveRefusal,
            ) => Self::NotOffered,
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::Uncertain) => {
                Self::RecoveryPending(None)
            }
            ServiceError::Adapter(registry_casework_core::SourceAdapterError::Invalid) => {
                Self::SourceBadGateway
            }
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
            Self::SourceBadGateway => ProblemCode::SourceBadGateway,
            Self::SourceSignatureInvalid => ProblemCode::SourceSignatureInvalid,
            Self::SourceUnavailable => ProblemCode::WorkItemSourceUnavailable,
            Self::Internal => ProblemCode::RuntimeFailure,
            Self::Validation(_) => ProblemCode::RequestInvalid,
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let attempt_reference = match &self {
            Self::RecoveryPending(attempt_id) => *attempt_id,
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
    validation: Option<&HostedValidationError>,
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
            hosted_validation_reason(validation.reason)
                .parse()
                .expect("validation reasons are valid header values"),
        );
    }
    response
}

fn hosted_validation_reason(reason: HostedValidationReason) -> &'static str {
    match reason {
        HostedValidationReason::KindNotAllowed => "kind_not_allowed",
        HostedValidationReason::ReferenceInvalid => "reference_invalid",
        HostedValidationReason::ObjectRequired => "object_required",
        HostedValidationReason::MaximumBytesExceeded => "maximum_bytes_exceeded",
        HostedValidationReason::MaximumDepthExceeded => "maximum_depth_exceeded",
        HostedValidationReason::SchemaMismatch => "schema_mismatch",
        HostedValidationReason::OutcomeNotDeclared => "outcome_not_declared",
        HostedValidationReason::ReasonRequired => "reason_required",
        HostedValidationReason::TextInvalid => "text_invalid",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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
