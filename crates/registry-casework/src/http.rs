use registry_casework_core::DirectoryTeamUpdateRequest;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use registry_casework_core::*;
use registry_platform_authcommon::parse_bearer_token;
use registry_platform_httpsec::{
    request_body_limit_default, security_headers, CspBuilder, ProblemBody, TraceContext,
};
use serde_json::error::Category;
use uuid::Uuid;

use crate::problem::ProblemCode;
use crate::{
    AuthenticationError, CaseworkAuthenticator, CaseworkService, ReviewResultRead,
    ReviewRuntimeError, ReviewTaskDecisionRequest, ServiceError, StoreError,
};

tokio::task_local! {
    static REQUEST_TRACE: TraceContext;
    static REQUEST_CONTRACT: HttpContract;
}

#[derive(Clone, Copy, Default)]
enum HttpContract {
    #[default]
    Casework,
    Review,
}

impl HttpContract {
    fn current() -> Self {
        REQUEST_CONTRACT
            .try_with(|contract| *contract)
            .unwrap_or_default()
    }

    fn profile_header(self) -> &'static str {
        match self {
            Self::Casework => CASEWORK_PROFILE_HEADER,
            Self::Review => REVIEW_PROFILE_HEADER,
        }
    }

    fn validation_headers(self) -> (&'static str, &'static str) {
        match self {
            Self::Casework => (VALIDATION_PATH_HEADER, VALIDATION_REASON_HEADER),
            Self::Review => (
                REVIEW_VALIDATION_PATH_HEADER,
                REVIEW_VALIDATION_REASON_HEADER,
            ),
        }
    }
}

const MAXIMUM_PAGE_SIZE: usize = 100;
const MAXIMUM_ABSENCE_PAGE_SIZE: usize = 1_000;

#[derive(Clone)]
pub struct HttpState {
    pub service: CaseworkService,
    pub authenticator: Arc<CaseworkAuthenticator>,
    pub project: Arc<CaseworkProject>,
}

pub fn router(state: HttpState) -> Router {
    let review = Router::new()
        .route("/v1/review-requests", post(create_review_request))
        .route("/v1/review-results", get(review_result_feed))
        .route("/v1/review-requests/{request_id}", get(get_review_request))
        .route(
            "/v1/review-requests/{request_id}/result",
            get(get_review_result),
        )
        .route(
            "/v1/review-requests/{request_id}/cancel",
            post(cancel_review_request),
        );
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/casework", get(description))
        .route("/.well-known/jwks.json", get(task_jwks))
        .route("/v1/task-grants/{grant_id}/assertion", post(task_assertion))
        .route("/v1/task-grants/{grant_id}/status", get(task_status))
        .route("/v1/review-policies", get(review_policy_descriptions))
        .route(
            "/v1/review-policies/{policy_id}",
            get(review_policy_description),
        )
        .route("/v1/review-tasks", get(review_tasks))
        .route("/v1/review-tasks/next", get(next_review_task))
        .route("/v1/review-tasks/holdings", get(review_task_holdings))
        .route("/v1/review-tasks/own-decisions", get(own_review_decisions))
        .route(
            "/v1/review-tasks/supervision",
            get(supervisory_review_tasks),
        )
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
        .route("/v1/directory/caseload/apply", post(apply_caseload_move));
    http_edge(app)
        .merge(contract_edge(review, HttpContract::Review))
        .with_state(state)
}

fn http_edge<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    contract_edge(router.fallback(route_not_found), HttpContract::Casework)
}

fn contract_edge<S>(router: Router<S>, contract: HttpContract) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .method_not_allowed_fallback(method_not_allowed)
        .layer(request_body_limit_default())
        .layer(middleware::from_fn(move |request, next| {
            http_boundary(contract, request, next)
        }))
        .layer(security_headers(CspBuilder::restrictive()).without_hsts())
}

async fn http_boundary(
    contract: HttpContract,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let trace = TraceContext::from_headers(request.headers());
    let mut response = REQUEST_TRACE
        .scope(trace.clone(), async move {
            REQUEST_CONTRACT
                .scope(contract, async move {
                    normalize_framework_rejection(next.run(request).await)
                })
                .await
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

/// A JSON request body parsed with the workspace's strict parser, so a
/// duplicate object member at any depth is refused instead of letting the
/// last occurrence win. The router's body limit bounds the bytes first.
///
/// The rejection classes match axum's `Json`: a missing or non-JSON content
/// type is 415, a body over the limit is 413, malformed JSON is 400
/// `request.invalid`, and a document that does not match the closed request
/// type is 422 `request.unprocessable`. A duplicate member falls in the
/// latter class, as serde already refused a duplicated typed field.
struct StrictJson<T>(T);

impl<T, S> FromRequest<S> for StrictJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !json_content_type(request.headers()) {
            return Err(problem_response(
                ProblemCode::RequestUnsupportedMediaType,
                None,
                None,
            ));
        }
        let bytes = Bytes::from_request(request, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let value = registry_platform_canonical_json::parse_json_strict(&bytes).map_err(|_| {
            // The strict parser can refuse an inexact integer before it
            // reaches a later syntax error, so malformedness is decided by a
            // plain syntax pass over the same bounded bytes.
            let malformed = serde_json::from_slice::<serde::de::IgnoredAny>(&bytes)
                .is_err_and(|error| matches!(error.classify(), Category::Syntax | Category::Eof));
            problem_response(
                if malformed {
                    ProblemCode::RequestInvalid
                } else {
                    ProblemCode::RequestUnprocessable
                },
                None,
                None,
            )
        })?;
        serde_path_to_error::deserialize(value)
            .map(Self)
            .map_err(|error| shape_rejection(&error))
    }
}

/// The longest member name echoed back in a shape refusal.
const MAXIMUM_SHAPE_MEMBER_BYTES: usize = 64;

/// The 422 for a document that does not match the closed request type. It
/// names the failing JSON path and the closed `schema-mismatch` category in the
/// validation headers, never the submitted value. A member name is client text,
/// so the path stops at the last segment that is not a short identifier.
fn shape_rejection(error: &serde_path_to_error::Error<serde_json::Error>) -> Response {
    let mut path = String::from("$");
    let mut named = true;
    for segment in error.path().iter() {
        match segment {
            serde_path_to_error::Segment::Seq { index } => path.push_str(&format!(".{index}")),
            serde_path_to_error::Segment::Map { key } => named = push_member(&mut path, key),
            serde_path_to_error::Segment::Enum { .. } | serde_path_to_error::Segment::Unknown => {}
        }
        if !named {
            break;
        }
    }
    // The path tracker names an undeclared member of a plain object but stops
    // at the object holding one inside an internally tagged enum, so the member
    // is also read from the error text when the path does not already end in it.
    if named {
        if let Some(member) = unknown_member(&error.inner().to_string()) {
            if path.rsplit('.').next() != Some(member) {
                push_member(&mut path, member);
            }
        }
    }
    let validation = ReviewValidationError::new(path, ReviewValidationReason::SchemaMismatch);
    problem_response(ProblemCode::RequestUnprocessable, None, Some(&validation))
}

/// Appends `.name` when it is a short identifier; reports whether it was.
fn push_member(path: &mut String, name: &str) -> bool {
    let safe = !name.is_empty()
        && name.len() <= MAXIMUM_SHAPE_MEMBER_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if safe {
        path.push('.');
        path.push_str(name);
    }
    safe
}

/// The member serde names in an "unknown field `name`, expected ..." message.
fn unknown_member(message: &str) -> Option<&str> {
    let rest = message.strip_prefix("unknown field `")?;
    rest.split_once('`').map(|(name, _)| name)
}

/// `application/json` or an `application/*+json` media type with well-formed
/// parameters, as axum's `Json` extractor accepts. The whole value must parse
/// as a media type, so a malformed parameter or subtype is refused.
fn json_content_type(headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let mut segments = value.split(';');
    let essence = segments.next().unwrap_or_default().trim();
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    let subtype = subtype.to_ascii_lowercase();
    media_token(kind)
        && media_token(&subtype)
        && kind.eq_ignore_ascii_case("application")
        && (subtype == "json" || subtype.ends_with("+json"))
        && segments.all(|parameter| {
            parameter
                .trim()
                .split_once('=')
                .is_some_and(|(name, value)| {
                    media_token(name) && (media_token(value) || quoted_string(value))
                })
        })
}

/// An RFC 9110 token.
fn media_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// An RFC 9110 quoted-string without control characters.
fn quoted_string(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return false;
    };
    let mut escaped = false;
    inner.chars().all(|character| {
        if escaped {
            escaped = false;
            return !character.is_control() || character == '\t';
        }
        match character {
            '\\' => {
                escaped = true;
                true
            }
            '"' => false,
            character => !character.is_control() || character == '\t',
        }
    }) && !escaped
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
        project_id: state.project.project.id.to_string(),
        policy_version: state.project.project.version.clone(),
        queues: state
            .project
            .queues
            .iter()
            .map(|queue| QueueRecord {
                id: queue.id.clone(),
                label: queue.label.clone(),
            })
            .collect(),
        review_policies: state
            .project
            .review_policies
            .iter()
            .filter(|policy| {
                state
                    .service
                    .review_policy_description(&actor, &policy.id)
                    .is_ok()
            })
            .cloned()
            .collect(),
        context_providers: if actor.role == CaseworkRole::Requester {
            Vec::new()
        } else {
            state.project.context_providers.clone()
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
    StrictJson(request): StrictJson<ReviewCreateRequest>,
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
    Ok((
        status,
        [(REVIEW_PRODUCER_HEADER, outcome.producer_id)],
        Json(outcome.accepted),
    )
        .into_response())
}

async fn review_policy_descriptions(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ReviewPolicyClosure>>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(state.service.review_policy_descriptions(&actor)?))
}

async fn review_policy_description(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(policy_id): Path<String>,
) -> Result<Json<ReviewPolicyClosure>, HttpError> {
    reject_source_profile(&headers)?;
    let (actor, _) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_policy_description(&actor, &policy_id)?,
    ))
}

async fn review_tasks(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ReviewStaffingQuery>,
) -> Result<Json<ReviewTaskPage>, HttpError> {
    page_limit(&state, query.limit)?;
    let source = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .review_staffing_tasks(&actor, source, token, query)
            .await?,
    ))
}
async fn next_review_task(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(mut query): Query<ReviewStaffingQuery>,
) -> Result<Json<Option<ReviewTask>>, HttpError> {
    page_limit(&state, query.limit)?;
    let source = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    // The next task is always the first of the due ordering, so a list cursor
    // never moves it.
    query.sort = ReviewTaskSort::Due;
    query.cursor = None;
    query.limit = Some(1);
    query.ownership = Some(query.ownership.unwrap_or(ReviewTaskOwnership::Unclaimed));
    Ok(Json(
        state
            .service
            .review_staffing_tasks(&actor, source, token, query)
            .await?
            .items
            .into_iter()
            .next(),
    ))
}
async fn review_task_holdings(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(mut query): Query<ReviewStaffingQuery>,
) -> Result<Json<ReviewTaskPage>, HttpError> {
    page_limit(&state, query.limit)?;
    let source = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    query.ownership = Some(ReviewTaskOwnership::AssignedToMe);
    Ok(Json(
        state
            .service
            .review_staffing_tasks(&actor, source, token, query)
            .await?,
    ))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnReviewDecisionQuery {
    queue: Option<String>,
    cursor: Option<Uuid>,
    limit: Option<usize>,
}

async fn own_review_decisions(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<OwnReviewDecisionQuery>,
) -> Result<Json<OwnReviewDecisionPage>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .own_review_decisions(
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

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SupervisoryReviewTaskQuery {
    queue: Option<String>,
    request_id: Option<Uuid>,
    cursor: Option<Uuid>,
    limit: Option<usize>,
}

async fn supervisory_review_tasks(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<SupervisoryReviewTaskQuery>,
) -> Result<Json<SupervisoryReviewTaskPage>, HttpError> {
    let source_profile_id = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .supervisory_review_tasks(
                &actor,
                source_profile_id,
                token,
                query.queue.as_deref(),
                query.request_id,
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
) -> Result<Json<ReviewTask>, HttpError> {
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
            .review_result_feed(&actor, query.cursor, page_limit(&state, query.limit)?)
            .await
            .map_err(HttpError::from)?,
    ))
}

async fn cancel_review_request(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
    StrictJson(request): StrictJson<ReviewCancelRequest>,
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
    StrictJson(request): StrictJson<AssignmentRequest>,
) -> Result<Json<ReviewTask>, HttpError> {
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
    StrictJson(request): StrictJson<DelegateRequest>,
) -> Result<Json<ReviewTask>, HttpError> {
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
    StrictJson(input): StrictJson<ReviewTaskDraftInput>,
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
                page_limit(&state, query.limit)?,
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
    StrictJson(request): StrictJson<ReviewNoteRequest>,
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
    StrictJson(request): StrictJson<ReviewTaskDecisionRequest>,
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
    StrictJson(request): StrictJson<DirectoryTeamUpdateRequest>,
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
    StrictJson(request): StrictJson<BootstrapDirectoryRequest>,
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

async fn create_holiday_revision(
    State(state): State<HttpState>,
    headers: HeaderMap,
    StrictJson(input): StrictJson<HolidaySetRevisionInput>,
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
    StrictJson(request): StrictJson<ReviewClockRecomputeRequest>,
) -> Result<Json<ReviewClockRecomputePreview>, HttpError> {
    let source = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .preview_review_clock_recompute(&actor, source, token, request)
            .await?,
    ))
}

async fn apply_clock_recompute(
    State(state): State<HttpState>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<ReviewClockRecomputeApplyRequest>,
) -> Result<Json<ReviewClockRecomputeResult>, HttpError> {
    let source = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .apply_review_clock_recompute(&actor, source, token, request)
            .await?,
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
                bounded_limit(
                    query.limit,
                    MAXIMUM_ABSENCE_PAGE_SIZE,
                    MAXIMUM_ABSENCE_PAGE_SIZE,
                )?,
                query.cursor.as_deref(),
            )
            .await?,
    ))
}

async fn create_absence(
    State(state): State<HttpState>,
    headers: HeaderMap,
    StrictJson(input): StrictJson<AbsenceInput>,
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
    StrictJson(input): StrictJson<AbsenceInput>,
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

async fn preview_caseload_move(
    State(state): State<HttpState>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<ReviewCaseloadMoveRequest>,
) -> Result<Json<ReviewCaseloadPreview>, HttpError> {
    let source = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .preview_review_caseload(&actor, source, token, request)
            .await?,
    ))
}

async fn apply_caseload_move(
    State(state): State<HttpState>,
    headers: HeaderMap,
    StrictJson(request): StrictJson<ReviewCaseloadApplyRequest>,
) -> Result<Json<ReviewCaseloadResult>, HttpError> {
    let source = source_profile_optional(&headers)?;
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .apply_review_caseload(&actor, source, token, request)
            .await?,
    ))
}

async fn task_jwks(State(state): State<HttpState>) -> Result<Json<serde_json::Value>, HttpError> {
    Ok(Json(state.service.task_jwks()?))
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
            .preview_review_task_templates(
                &actor,
                task_id,
                source_profile_optional(&headers)?,
                token,
            )
            .await?,
    ))
}
async fn approve_review_task_grant(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(task_id): Path<Uuid>,
    StrictJson(request): StrictJson<registry_casework_core::TaskApprovalRequest>,
) -> Result<Json<registry_casework_core::TaskGrantView>, HttpError> {
    let (actor, token) = authenticate(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .approve_review_task(
                &actor,
                task_id,
                if_match(&headers)?,
                source_profile_optional(&headers)?,
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
            .list_review_task_grants(&actor, task_id, source_profile_optional(&headers)?, token)
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
        .ok_or_else(|| header_authentication_refused(state))?;
    let token = parse_bearer_token(raw).map_err(|_| header_authentication_refused(state))?;
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
        .ok_or_else(|| header_authentication_refused(state))?;
    let token =
        parse_bearer_token(authorization).map_err(|_| header_authentication_refused(state))?;
    let profile = profile_header(headers, HttpContract::current().profile_header())?;
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

fn header_authentication_refused(state: &HttpState) -> HttpError {
    state.authenticator.record_header_refusal();
    HttpError::AuthenticationRefused
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
    bounded_limit(
        requested,
        state.service.inbox_policy().default_page_size,
        MAXIMUM_PAGE_SIZE,
    )
}

/// A `limit` of zero or a value above the route's maximum (100, or 1000 on
/// the directory absence list) is refused with the closed problem whose
/// detail names the parameter and each accepted range.
fn bounded_limit(
    requested: Option<usize>,
    default: usize,
    maximum: usize,
) -> Result<usize, HttpError> {
    let limit = requested.unwrap_or(default);
    (1..=maximum)
        .contains(&limit)
        .then_some(limit)
        .ok_or(HttpError::LimitOutOfRange)
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
    ProfileNotAuthorized,
    ProfileNotHuman,
    Forbidden,
    NotFound,
    PreconditionFailed,
    PreconditionRequired,
    IdempotencyKeyReused,
    IdempotencyExpired,
    Invalid,
    LimitOutOfRange,
    ServiceUnavailable,
    SourceProfileNotApplicable,
    SourceProfileRequired,
    SourceBadGateway,
    SourceVersionMismatch,
    SourceVersionUnavailable,
    ReviewDistinctApproverRequired,
    ReviewInitiatorExcluded,
    ReviewInitiatorRequired,
    ReviewResultExpired,
    ReviewSubmissionConflict,
    ReviewTaskNotHeld,
    ReviewPolicyMismatch,
    ReviewQueryTooBroad,
    CursorInvalid,
    CursorExpired,
    Absence(AbsenceError),
    Internal,
    Validation(ReviewValidationError),
}
impl From<StoreError> for HttpError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Absence(e) => Self::Absence(e),
            StoreError::CursorExpired => Self::CursorExpired,
            StoreError::CursorInvalid => Self::CursorInvalid,
            StoreError::IdempotencyExpired => Self::IdempotencyExpired,
            StoreError::NotFound => Self::NotFound,
            StoreError::Forbidden => Self::Forbidden,
            StoreError::Conflict => Self::PreconditionFailed,
            StoreError::AlreadyClaimed | StoreError::NotHolder => Self::ReviewTaskNotHeld,
            StoreError::IdempotencyConflict => Self::IdempotencyKeyReused,
            StoreError::Invalid => Self::Invalid,
            StoreError::ReviewValidation(e) => Self::Validation(e),
            StoreError::Unavailable
            | StoreError::AuditUnavailable
            | StoreError::Postgres(_)
            | StoreError::SchemaNotCurrent { .. }
            | StoreError::LedgerUnreadable { .. } => Self::ServiceUnavailable,
            _ => Self::Internal,
        }
    }
}
impl From<ServiceError> for HttpError {
    fn from(e: ServiceError) -> Self {
        match e {
            ServiceError::Store(e) => e.into(),
            ServiceError::NotFound => Self::NotFound,
            ServiceError::Forbidden => Self::Forbidden,
            ServiceError::ReviewValidation(e) => Self::Validation(e),
            ServiceError::Configuration => Self::Internal,
            ServiceError::Context(ReviewContextError::VersionMismatch) => {
                Self::SourceVersionMismatch
            }
            ServiceError::Context(ReviewContextError::VersionUnavailable) => {
                Self::SourceVersionUnavailable
            }
            ServiceError::Context(ReviewContextError::Unavailable) => Self::ServiceUnavailable,
            ServiceError::Context(
                ReviewContextError::Invalid | ReviewContextError::Unsupported,
            ) => Self::SourceBadGateway,
            ServiceError::Context(_) => Self::NotFound,
        }
    }
}
impl From<ReviewRuntimeError> for HttpError {
    fn from(e: ReviewRuntimeError) -> Self {
        match e {
            ReviewRuntimeError::NotFound => Self::NotFound,
            ReviewRuntimeError::Forbidden => Self::Forbidden,
            ReviewRuntimeError::SubmissionConflict => Self::ReviewSubmissionConflict,
            ReviewRuntimeError::ResultExpired => Self::ReviewResultExpired,
            ReviewRuntimeError::TaskNotHeld => Self::ReviewTaskNotHeld,
            ReviewRuntimeError::DistinctApproverRequired => Self::ReviewDistinctApproverRequired,
            ReviewRuntimeError::InitiatorExcluded => Self::ReviewInitiatorExcluded,
            ReviewRuntimeError::InitiatorRequired => Self::ReviewInitiatorRequired,
            ReviewRuntimeError::SourceProfileRequired => Self::SourceProfileRequired,
            ReviewRuntimeError::SourceProfileNotApplicable => Self::SourceProfileNotApplicable,
            ReviewRuntimeError::SourceUnavailable => {
                tracing::warn!("Casework review context provider unavailable");
                Self::ServiceUnavailable
            }
            ReviewRuntimeError::SourceInvalid => Self::SourceBadGateway,
            ReviewRuntimeError::SourceVersionMismatch => Self::SourceVersionMismatch,
            ReviewRuntimeError::SourceVersionUnavailable => Self::SourceVersionUnavailable,
            ReviewRuntimeError::RevisionConflict => Self::PreconditionFailed,
            ReviewRuntimeError::IdempotencyConflict => Self::IdempotencyKeyReused,
            ReviewRuntimeError::IdempotencyExpired => Self::IdempotencyExpired,
            ReviewRuntimeError::Invalid => Self::Invalid,
            ReviewRuntimeError::Validation(e) => Self::Validation(e),
            ReviewRuntimeError::Corrupt => Self::Internal,
            ReviewRuntimeError::PolicyMismatch => Self::ReviewPolicyMismatch,
            ReviewRuntimeError::QueryTooBroad => Self::ReviewQueryTooBroad,
            ReviewRuntimeError::Store(e) => e.into(),
        }
    }
}
impl HttpError {
    fn problem(&self) -> ProblemCode {
        match self {
            Self::AuthenticationRefused => ProblemCode::AuthenticationRefused,
            Self::ProfileNotAuthorized => ProblemCode::ProfileNotAuthorized,
            Self::ProfileNotHuman => ProblemCode::ProfileNotHuman,
            Self::Forbidden => ProblemCode::OperationNotAuthorized,
            Self::NotFound => ProblemCode::RequestNotFound,
            Self::PreconditionFailed => ProblemCode::PreconditionFailed,
            Self::PreconditionRequired => ProblemCode::PreconditionRequired,
            Self::IdempotencyKeyReused => ProblemCode::IdempotencyKeyReused,
            Self::IdempotencyExpired => ProblemCode::IdempotencyExpired,
            Self::Invalid | Self::Validation(_) => ProblemCode::RequestInvalid,
            Self::LimitOutOfRange => ProblemCode::RequestLimitOutOfRange,
            Self::ServiceUnavailable => ProblemCode::ServiceUnavailable,
            Self::SourceProfileNotApplicable => ProblemCode::SourceProfileNotApplicable,
            Self::SourceProfileRequired => ProblemCode::SourceProfileRequired,
            Self::SourceBadGateway => ProblemCode::SourceBadGateway,
            Self::SourceVersionMismatch => ProblemCode::SourceVersionMismatch,
            Self::SourceVersionUnavailable => ProblemCode::SourceVersionUnavailable,
            Self::ReviewDistinctApproverRequired => ProblemCode::ReviewDistinctApproverRequired,
            Self::ReviewInitiatorExcluded => ProblemCode::ReviewInitiatorExcluded,
            Self::ReviewInitiatorRequired => ProblemCode::ReviewInitiatorRequired,
            Self::ReviewResultExpired => ProblemCode::ReviewResultExpired,
            Self::ReviewSubmissionConflict => ProblemCode::ReviewSubmissionConflict,
            Self::ReviewTaskNotHeld => ProblemCode::ReviewTaskNotHeld,
            Self::ReviewPolicyMismatch => ProblemCode::ReviewPolicyMismatch,
            Self::ReviewQueryTooBroad => ProblemCode::ReviewQueryTooBroad,
            Self::CursorInvalid => ProblemCode::CursorInvalid,
            Self::CursorExpired => ProblemCode::CursorExpired,
            Self::Internal => ProblemCode::RuntimeFailure,
            Self::Absence(e) => match e {
                AbsenceError::InvalidPeriod => ProblemCode::AbsenceInvalidPeriod,
                AbsenceError::SelfCover => ProblemCode::AbsenceSelfCover,
                AbsenceError::OverlappingPeriod => ProblemCode::AbsenceOverlap,
                AbsenceError::CoverCycle => ProblemCode::AbsenceCoverCycle,
            },
        }
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let validation = match &self {
            Self::Validation(v) => Some(v),
            _ => None,
        };
        problem_response(self.problem(), None, validation)
    }
}

fn problem_response(
    problem: ProblemCode,
    _attempt_reference: Option<Uuid>,
    validation: Option<&ReviewValidationError>,
) -> Response {
    let trace = REQUEST_TRACE
        .try_with(Clone::clone)
        .unwrap_or_else(|_| TraceContext::server_created());
    let status = problem.status();
    let body = ProblemBody {
        type_uri: format!(
            "{}{}",
            CASEWORK_PROBLEM_TYPE_BASE,
            problem.code().replace('.', "/")
        ),
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
    if let Some(validation) = validation {
        let (path_header, reason_header) = HttpContract::current().validation_headers();
        response.headers_mut().insert(
            path_header,
            validation
                .path
                .parse()
                .expect("bounded JSON paths are valid header values"),
        );
        response.headers_mut().insert(
            reason_header,
            review_validation_reason(validation.reason)
                .parse()
                .expect("validation reasons are valid header values"),
        );
        // Only a human decision names allowed outcomes: the declared ones, or
        // the one an earlier approval in the stage chose. Both are policy
        // identifiers the reviewer already reads from the review policy.
        if !validation.allowed.is_empty() {
            response.headers_mut().insert(
                VALIDATION_ALLOWED_HEADER,
                validation
                    .allowed
                    .join(",")
                    .parse()
                    .expect("declared identifiers are valid header values"),
            );
        }
    }
    response
}

fn review_validation_reason(reason: ReviewValidationReason) -> &'static str {
    match reason {
        ReviewValidationReason::PolicyNotAllowed => "policy-not-allowed",
        ReviewValidationReason::ReferenceInvalid => "reference-invalid",
        ReviewValidationReason::ObjectRequired => "object-required",
        ReviewValidationReason::MaximumBytesExceeded => "maximum-bytes-exceeded",
        ReviewValidationReason::MaximumDepthExceeded => "maximum-depth-exceeded",
        ReviewValidationReason::SchemaMismatch => "schema-mismatch",
        ReviewValidationReason::OutcomeNotDeclared => "outcome-not-declared",
        ReviewValidationReason::ReasonRequired => "reason-required",
        ReviewValidationReason::TextInvalid => "text-invalid",
        ReviewValidationReason::ResultNotDeclared => "result-not-declared",
        ReviewValidationReason::ResultRequired => "result-required",
        ReviewValidationReason::FieldNotDeclared => "field-not-declared",
        ReviewValidationReason::ConstraintInvalid => "constraint-invalid",
        ReviewValidationReason::ConstraintViolated => "constraint-violated",
        ReviewValidationReason::PublicReasonRequired => "public-reason-required",
        ReviewValidationReason::PublicReasonNotDeclared => "public-reason-not-declared",
        ReviewValidationReason::ApprovalOutcomeDiffers => "approval-outcome-differs",
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
    use axum::Router;
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

    async fn json_route(Path(_id): Path<Uuid>, StrictJson(input): StrictJson<Input>) -> StatusCode {
        let _ = input.value;
        StatusCode::NO_CONTENT
    }

    async fn bounded_header_route(
        State(calls): State<Arc<AtomicUsize>>,
        headers: HeaderMap,
    ) -> Result<StatusCode, HttpError> {
        profile_header(&headers, CASEWORK_PROFILE_HEADER)?;
        source_profile_optional(&headers)?;
        idempotency_key(&headers)?;
        calls.fetch_add(1, Ordering::Relaxed);
        Ok(StatusCode::NO_CONTENT)
    }

    fn edge_fixture() -> Router {
        http_edge(Router::new().route("/json/{id}", post(json_route)))
    }

    #[tokio::test]
    async fn review_and_staff_routes_select_only_their_own_profile_contract() {
        async fn selected_profile(headers: HeaderMap) -> Result<Json<String>, HttpError> {
            Ok(Json(
                profile_header(&headers, HttpContract::current().profile_header())?.to_owned(),
            ))
        }
        let app =
            http_edge(Router::new().route("/staff", post(selected_profile))).merge(contract_edge(
                Router::new().route("/review", post(selected_profile)),
                HttpContract::Review,
            ));
        for (path, selected, other, base) in [
            (
                "/review",
                REVIEW_PROFILE_HEADER,
                CASEWORK_PROFILE_HEADER,
                CASEWORK_PROBLEM_TYPE_BASE,
            ),
            (
                "/staff",
                CASEWORK_PROFILE_HEADER,
                REVIEW_PROFILE_HEADER,
                CASEWORK_PROBLEM_TYPE_BASE,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header(selected, "expected")
                        .header(other, "ignored")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                to_bytes(response.into_body(), 1024).await.unwrap(),
                "\"expected\""
            );
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header(other, "ignored")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let problem: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            assert_eq!(problem["type"], format!("{base}request/invalid"));
        }
    }

    #[tokio::test]
    async fn review_contract_covers_framework_and_validation_failures() {
        let app = contract_edge(
            Router::new().route("/json/{id}", post(json_route)).route(
                "/validation",
                post(|| async {
                    Err::<StatusCode, _>(HttpError::Validation(ReviewValidationError::new(
                        "$.policy",
                        ReviewValidationReason::PolicyNotAllowed,
                    )))
                }),
            ),
            HttpContract::Review,
        );
        for (method, path, media, body, expected) in [
            (
                "GET",
                "/json/00000000-0000-0000-0000-000000000000",
                "application/json",
                Vec::new(),
                ProblemCode::RequestMethodNotAllowed,
            ),
            (
                "POST",
                "/json/invalid",
                "application/json",
                b"{}".to_vec(),
                ProblemCode::RequestInvalid,
            ),
            (
                "POST",
                "/json/00000000-0000-0000-0000-000000000000",
                "text/plain",
                b"{}".to_vec(),
                ProblemCode::RequestUnsupportedMediaType,
            ),
            (
                "POST",
                "/json/00000000-0000-0000-0000-000000000000",
                "application/json",
                vec![b'x'; 1024 * 1024 + 1],
                ProblemCode::RequestBodyTooLarge,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header(CONTENT_TYPE, media)
                        .header("traceparent", TRACEPARENT)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected.status());
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            let problem: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            assert_eq!(
                problem["type"],
                format!(
                    "{CASEWORK_PROBLEM_TYPE_BASE}{}",
                    expected.code().replace('.', "/")
                )
            );
            assert_eq!(problem["traceId"], "0123456789abcdef0123456789abcdef");
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/validation")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers()[REVIEW_VALIDATION_PATH_HEADER],
            "$.policy"
        );
        assert_eq!(
            response.headers()[REVIEW_VALIDATION_REASON_HEADER],
            "policy-not-allowed"
        );
        assert!(!response.headers().contains_key(VALIDATION_PATH_HEADER));
        assert!(!response.headers().contains_key(VALIDATION_REASON_HEADER));
    }

    #[test]
    fn provider_failures_preserve_concealment_and_distinguish_invalid_responses() {
        let concealed = HttpError::from(ServiceError::Context(ReviewContextError::Concealed));
        assert_eq!(concealed.problem(), ProblemCode::RequestNotFound);
        let malformed = HttpError::from(ServiceError::Context(ReviewContextError::Invalid));
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

        assert_eq!(mapped.problem(), ProblemCode::ServiceUnavailable);
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
            (
                Request::builder()
                    .method("POST")
                    .uri(format!("/json/{id}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":"ok""#))
                    .expect("syntax request"),
                ProblemCode::RequestInvalid,
            ),
            (
                Request::builder()
                    .method("POST")
                    .uri(format!("/json/{id}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":9007199254740993x}"#))
                    .expect("malformed inexact integer request"),
                ProblemCode::RequestInvalid,
            ),
            (
                Request::builder()
                    .method("POST")
                    .uri(format!("/json/{id}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":9007199254740993}"#))
                    .expect("inexact integer request"),
                ProblemCode::RequestUnprocessable,
            ),
            (
                Request::builder()
                    .method("POST")
                    .uri(format!("/json/{id}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":"ok","value":"smuggled"}"#))
                    .expect("duplicate member request"),
                ProblemCode::RequestUnprocessable,
            ),
            (
                Request::builder()
                    .method("POST")
                    .uri(format!("/json/{id}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"value":"ok","nested":[{"a":1,"a":2}]}"#))
                    .expect("nested duplicate member request"),
                ProblemCode::RequestUnprocessable,
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
    async fn strict_json_accepts_one_unambiguous_document_in_a_json_media_type() {
        let id = Uuid::nil();
        for content_type in [
            "application/json",
            "application/json; charset=utf-8",
            "Application/JSON",
            "application/merge-patch+json",
            "application/json;charset=\"utf-8\"",
        ] {
            let response = edge_fixture()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/json/{id}"))
                        .header(CONTENT_TYPE, content_type)
                        .body(Body::from(r#"{"value":"ok"}"#))
                        .expect("valid request"),
                )
                .await
                .expect("edge response");
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{content_type}");
        }
        for content_type in [
            None,
            Some("text/json"),
            Some("application/jsonx"),
            Some("application/json; charset"),
            Some("application/not a type+json"),
            Some("application/json; =utf-8"),
            Some("application/json; charset=\"utf-8"),
        ] {
            let mut request = Request::builder().method("POST").uri(format!("/json/{id}"));
            if let Some(content_type) = content_type {
                request = request.header(CONTENT_TYPE, content_type);
            }
            let response = edge_fixture()
                .oneshot(
                    request
                        .body(Body::from(r#"{"value":"ok"}"#))
                        .expect("media request"),
                )
                .await
                .expect("edge response");
            assert_eq!(
                response.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{content_type:?}"
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

    async fn decision_route(
        StrictJson(request): StrictJson<ReviewTaskDecisionRequest>,
    ) -> StatusCode {
        let _ = request;
        StatusCode::NO_CONTENT
    }

    async fn refused_shape(body: &str) -> (Response, serde_json::Value) {
        let response = http_edge(Router::new().route("/decision", post(decision_route)))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/decision")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_owned()))
                    .expect("decision request"),
            )
            .await
            .expect("bounded shape response");
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, 16 * 1024).await.expect("bounded problem");
        let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("problem JSON");
        (Response::from_parts(parts, Body::empty()), problem)
    }

    /// A member the closed request type does not declare is named by path, so
    /// the client sees which field was refused rather than a generic 422.
    #[tokio::test]
    async fn an_undeclared_member_is_refused_with_its_json_path() {
        let (response, problem) = refused_shape(
            r#"{"decision":{"type":"approve","outcome":"approved","reason":"private words"}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(problem["code"], ProblemCode::RequestUnprocessable.code());
        let headers = response.headers();
        assert_eq!(headers[VALIDATION_PATH_HEADER], "$.decision.reason");
        assert_eq!(headers[VALIDATION_REASON_HEADER], "schema-mismatch");
        assert!(!problem.to_string().contains("private words"));
        assert!(!format!("{headers:?}").contains("private words"));

        let (response, _) = refused_shape(r#"{"decision":{"type":"approve"},"extra":1}"#).await;
        assert_eq!(response.headers()[VALIDATION_PATH_HEADER], "$.extra");
    }

    /// A member name is client-chosen text, so a name that is not a short
    /// identifier is never echoed: the path stops at its parent.
    #[tokio::test]
    async fn an_unsafe_member_name_is_not_echoed() {
        let (response, _) = refused_shape(
            r#"{"decision":{"type":"approve","outcome":"approved","pri vate;words":"x"}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response.headers()[VALIDATION_PATH_HEADER], "$.decision");
        assert!(!format!("{:?}", response.headers()).contains("pri vate"));

        let long = "a".repeat(80);
        let (response, _) = refused_shape(&format!(r#"{{"{long}":1}}"#)).await;
        assert_eq!(response.headers()[VALIDATION_PATH_HEADER], "$");
    }

    /// A wrongly typed member is refused with the deepest path the parser can
    /// attribute and no submitted value; inside a tagged decision that is the
    /// decision itself.
    #[tokio::test]
    async fn a_mistyped_member_is_refused_without_its_value() {
        let (response, problem) = refused_shape(
            r#"{"decision":{"type":"approve","outcome":"approved","publicReason":7}}"#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(problem["code"], ProblemCode::RequestUnprocessable.code());
        assert_eq!(response.headers()[VALIDATION_PATH_HEADER], "$.decision");
        assert_eq!(
            response.headers()[VALIDATION_REASON_HEADER],
            "schema-mismatch"
        );
    }

    /// An outcome refusal lists the declared outcomes the reviewer may send,
    /// so the fix is in the response.
    #[test]
    fn an_outcome_refusal_lists_the_declared_outcomes() {
        let response = HttpError::Validation(
            ReviewValidationError::new("$.outcome", ReviewValidationReason::OutcomeNotDeclared)
                .allowing(vec!["approved".to_owned(), "approved-with-note".to_owned()]),
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let headers = response.headers();
        assert_eq!(headers[VALIDATION_PATH_HEADER], "$.outcome");
        assert_eq!(headers[VALIDATION_REASON_HEADER], "outcome-not-declared");
        assert_eq!(
            headers[VALIDATION_ALLOWED_HEADER],
            "approved,approved-with-note"
        );
        let other = HttpError::Validation(ReviewValidationError::new(
            "$.reason",
            ReviewValidationReason::ReasonRequired,
        ))
        .into_response();
        assert!(other.headers().get(VALIDATION_ALLOWED_HEADER).is_none());
    }

    /// The validation reason header carries the word the SDK type
    /// serializes to, so a reader of either sees one spelling.
    #[test]
    fn every_validation_reason_header_is_the_kebab_case_word_of_its_type() {
        let reasons = [
            ReviewValidationReason::PolicyNotAllowed,
            ReviewValidationReason::ReferenceInvalid,
            ReviewValidationReason::ObjectRequired,
            ReviewValidationReason::MaximumBytesExceeded,
            ReviewValidationReason::MaximumDepthExceeded,
            ReviewValidationReason::SchemaMismatch,
            ReviewValidationReason::OutcomeNotDeclared,
            ReviewValidationReason::ReasonRequired,
            ReviewValidationReason::TextInvalid,
            ReviewValidationReason::ResultNotDeclared,
            ReviewValidationReason::ResultRequired,
            ReviewValidationReason::FieldNotDeclared,
            ReviewValidationReason::ConstraintInvalid,
            ReviewValidationReason::ConstraintViolated,
            ReviewValidationReason::PublicReasonRequired,
            ReviewValidationReason::PublicReasonNotDeclared,
            ReviewValidationReason::ApprovalOutcomeDiffers,
        ];
        for reason in reasons {
            let word = review_validation_reason(reason);
            assert_eq!(serde_json::to_value(reason).expect("reason"), word);
            assert!(
                word.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
                "{word}"
            );
        }
    }
}
