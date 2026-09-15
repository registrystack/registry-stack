// SPDX-License-Identifier: Apache-2.0

//! The HTTP surface: the pinned routes, the request boundary, and the one
//! problem rendering every refusal flows through.
//!
//! Every refusal leaves this edge as one problem shape: a code from the closed
//! vocabulary — the product refusals (authentication, authorization,
//! admission, idempotency, cursors, availability) and the `request.*` family
//! carrying the request-edge rejections (a route that does not exist, a
//! method the route refuses, a body too large or not JSON) — under the
//! Scheduling problem base, with the answering request's trace id. No shared
//! platform problem prefix exists in the Registry Stack catalog, so the edge
//! codes live in this product's own vocabulary exactly as Casework's do.
//!
//! Mutations answer through the service's commitment verdict. A minted
//! commitment answers with the route's success status and its document. A
//! replayed idempotency key answers as the stored attempt first did: a
//! success receipt projects through the same document, a refusal receipt
//! re-renders its pinned problem under the answering request's trace, and a
//! release's empty receipt answers as an empty 204 again.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use registry_platform_authcommon::parse_bearer_token;
use registry_platform_httpsec::{
    request_body_limit_default, security_headers, CspBuilder, ProblemBody, TraceContext,
};
use registry_scheduling_core::{
    type_uri, AdmissionRequest, CancelAppointmentRequest, CreateAppointmentRequest, ProblemCode,
    RescheduleAppointmentRequest, APPOINTMENTS_PATH, AVAILABILITY_EXPLAIN_PATH, AVAILABILITY_PATH,
    HOLDS_PATH, IDEMPOTENCY_KEY_HEADER, LOCATIONS_PATH, MAXIMUM_IDEMPOTENCY_KEY_BYTES,
    OFFERINGS_PATH, RESOURCES_PATH, SCHEDULING_PATH, SERVICES_PATH,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::auth::{AuthenticationError, SchedulingAuthenticator};
use crate::service::{Caller, CommitmentAnswer, SchedulingService, ServiceError};
use crate::store::PostgresStore;

tokio::task_local! {
    static REQUEST_TRACE: TraceContext;
}

#[derive(Clone)]
pub struct HttpState {
    pub service: Arc<SchedulingService>,
    pub authenticator: Arc<SchedulingAuthenticator>,
    pub store: PostgresStore,
}

const HOLD_ROUTE: &str = "/v1/holds/{hold_id}";
const APPOINTMENT_ROUTE: &str = "/v1/appointments/{appointment_id}";
const APPOINTMENT_RESCHEDULE_ROUTE: &str = "/v1/appointments/{appointment_id}/reschedule";
const APPOINTMENT_CANCEL_ROUTE: &str = "/v1/appointments/{appointment_id}/cancel";
const APPOINTMENT_HISTORY_ROUTE: &str = "/v1/appointments/{appointment_id}/history";

pub fn router(state: HttpState) -> Router {
    http_edge(
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .route(SCHEDULING_PATH, get(scheduling))
            .route(SERVICES_PATH, get(list_services))
            .route(OFFERINGS_PATH, get(list_offerings))
            .route(RESOURCES_PATH, get(list_resources))
            .route(LOCATIONS_PATH, get(list_locations))
            .route(AVAILABILITY_PATH, get(availability))
            .route(AVAILABILITY_EXPLAIN_PATH, get(explain))
            .route(HOLDS_PATH, post(create_hold))
            .route(HOLD_ROUTE, delete(release_hold))
            .route(APPOINTMENTS_PATH, post(create_appointment))
            .route(APPOINTMENT_ROUTE, get(get_appointment))
            .route(APPOINTMENT_RESCHEDULE_ROUTE, post(reschedule_appointment))
            .route(APPOINTMENT_CANCEL_ROUTE, post(cancel_appointment))
            .route(APPOINTMENT_HISTORY_ROUTE, get(appointment_history)),
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

/// Framework rejections carry axum's own bodies, which no Scheduling caller
/// was promised. The statuses are kept; the body becomes the vocabulary's
/// `request.*` problem for that status, so every answer still reads as one
/// problem shape.
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
    problem.map_or(response, problem_response)
}

async fn route_not_found() -> Response {
    problem_response(ProblemCode::RequestNotFound)
}

async fn method_not_allowed() -> Response {
    problem_response(ProblemCode::RequestMethodNotAllowed)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn readyz(State(state): State<HttpState>) -> Result<StatusCode, HttpError> {
    if state.store.ready().await.is_ok() {
        Ok(StatusCode::OK)
    } else {
        Err(HttpError(ProblemCode::ServiceUnavailable))
    }
}

async fn scheduling(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<registry_scheduling_core::SchedulingServiceDocument>, HttpError> {
    authenticate_read(&state, &headers).await?;
    Ok(Json(state.service.scheduling()))
}

async fn list_services(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(page): Query<ListingQuery>,
) -> Result<
    Json<registry_scheduling_core::PageDocument<registry_scheduling_core::ServiceDocument>>,
    HttpError,
> {
    authenticate_read(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .list_services(page.cursor.as_deref(), page.limit, Utc::now())
            .await?,
    ))
}

async fn list_offerings(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(page): Query<ListingQuery>,
) -> Result<
    Json<registry_scheduling_core::PageDocument<registry_scheduling_core::OfferingDocument>>,
    HttpError,
> {
    authenticate_read(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .list_offerings(page.cursor.as_deref(), page.limit, Utc::now())
            .await?,
    ))
}

async fn list_resources(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(page): Query<ListingQuery>,
) -> Result<
    Json<registry_scheduling_core::PageDocument<registry_scheduling_core::ResourceDocument>>,
    HttpError,
> {
    authenticate_read(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .list_resources(page.cursor.as_deref(), page.limit, Utc::now())
            .await?,
    ))
}

async fn list_locations(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(page): Query<ListingQuery>,
) -> Result<
    Json<registry_scheduling_core::PageDocument<registry_scheduling_core::LocationDocument>>,
    HttpError,
> {
    authenticate_read(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .list_locations(page.cursor.as_deref(), page.limit, Utc::now())
            .await?,
    ))
}

async fn availability(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<AvailabilityQuery>,
) -> Result<
    Json<registry_scheduling_core::PageDocument<registry_scheduling_core::AvailabilityEntry>>,
    HttpError,
> {
    authenticate_read(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .availability(
                &query.offering,
                query.start,
                query.end,
                query.cursor.as_deref(),
                query.limit,
                Utc::now(),
            )
            .await?,
    ))
}

async fn explain(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ExplainQuery>,
) -> Result<Json<registry_scheduling_core::ExplainDocument>, HttpError> {
    authenticate_explain(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .explain(&query.offering, query.start, Utc::now())
            .await?,
    ))
}

async fn create_hold(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionRequest>,
) -> Result<Response, HttpError> {
    let caller = authenticate_mutate(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let answer = state
        .service
        .create_hold(&caller, key, &request, Utc::now())
        .await?;
    Ok(match answer {
        CommitmentAnswer::Minted(hold) => (StatusCode::CREATED, Json(hold)).into_response(),
        CommitmentAnswer::Replay {
            status_code,
            receipt,
        } => replay_response(status_code, receipt),
    })
}

async fn release_hold(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(hold_id): Path<Uuid>,
) -> Result<Response, HttpError> {
    let caller = authenticate_mutate(&state, &headers).await?;
    let answer = state
        .service
        .release_hold(&caller, hold_id, Utc::now())
        .await?;
    Ok(match answer {
        CommitmentAnswer::Minted(()) => StatusCode::NO_CONTENT.into_response(),
        CommitmentAnswer::Replay {
            status_code,
            receipt,
        } => replay_response(status_code, receipt),
    })
}

async fn create_appointment(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<CreateAppointmentRequest>,
) -> Result<Response, HttpError> {
    let caller = authenticate_mutate(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let answer = state
        .service
        .create_appointment(&caller, key, &request, Utc::now())
        .await?;
    Ok(match answer {
        CommitmentAnswer::Minted(appointment) => {
            (StatusCode::CREATED, Json(appointment)).into_response()
        }
        CommitmentAnswer::Replay {
            status_code,
            receipt,
        } => replay_response(status_code, receipt),
    })
}

async fn get_appointment(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(appointment_id): Path<Uuid>,
) -> Result<Json<registry_scheduling_core::AppointmentDocument>, HttpError> {
    let caller = authenticate_read(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .get_appointment(&caller, appointment_id)
            .await?,
    ))
}

async fn reschedule_appointment(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(appointment_id): Path<Uuid>,
    Json(request): Json<RescheduleAppointmentRequest>,
) -> Result<Response, HttpError> {
    let caller = authenticate_mutate(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let answer = state
        .service
        .reschedule_appointment(&caller, appointment_id, key, &request, Utc::now())
        .await?;
    Ok(match answer {
        CommitmentAnswer::Minted(appointment) => {
            (StatusCode::OK, Json(appointment)).into_response()
        }
        CommitmentAnswer::Replay {
            status_code,
            receipt,
        } => replay_response(status_code, receipt),
    })
}

async fn cancel_appointment(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(appointment_id): Path<Uuid>,
    Json(request): Json<CancelAppointmentRequest>,
) -> Result<Response, HttpError> {
    let caller = authenticate_mutate(&state, &headers).await?;
    let key = idempotency_key(&headers)?;
    let answer = state
        .service
        .cancel_appointment(&caller, appointment_id, key, &request, Utc::now())
        .await?;
    Ok(match answer {
        CommitmentAnswer::Minted(appointment) => {
            (StatusCode::OK, Json(appointment)).into_response()
        }
        CommitmentAnswer::Replay {
            status_code,
            receipt,
        } => replay_response(status_code, receipt),
    })
}

async fn appointment_history(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(appointment_id): Path<Uuid>,
    Query(page): Query<ListingQuery>,
) -> Result<
    Json<
        registry_scheduling_core::PageDocument<
            registry_scheduling_core::AppointmentHistoryEntryDocument,
        >,
    >,
    HttpError,
> {
    let caller = authenticate_read(&state, &headers).await?;
    Ok(Json(
        state
            .service
            .appointment_history(
                &caller,
                appointment_id,
                page.cursor.as_deref(),
                page.limit,
                Utc::now(),
            )
            .await?,
    ))
}

#[derive(Debug, Default, Deserialize)]
struct ListingQuery {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AvailabilityQuery {
    offering: String,
    #[serde(default)]
    start: Option<DateTime<Utc>>,
    #[serde(default)]
    end: Option<DateTime<Utc>>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ExplainQuery {
    offering: String,
    start: DateTime<Utc>,
}

async fn authenticate_read(state: &HttpState, headers: &HeaderMap) -> Result<Caller, HttpError> {
    let token = bearer_token(headers)?;
    state
        .authenticator
        .authenticate_read(token)
        .await
        .map_err(authentication_problem)
}

async fn authenticate_explain(state: &HttpState, headers: &HeaderMap) -> Result<Caller, HttpError> {
    let token = bearer_token(headers)?;
    state
        .authenticator
        .authenticate_explain(token)
        .await
        .map_err(authentication_problem)
}

async fn authenticate_mutate(state: &HttpState, headers: &HeaderMap) -> Result<Caller, HttpError> {
    let token = bearer_token(headers)?;
    state
        .authenticator
        .authenticate_mutate(token)
        .await
        .map_err(authentication_problem)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, HttpError> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(HttpError(ProblemCode::AuthenticationRefused))?;
    parse_bearer_token(authorization).map_err(|_| HttpError(ProblemCode::AuthenticationRefused))
}

fn authentication_problem(error: AuthenticationError) -> HttpError {
    match error {
        AuthenticationError::Refused | AuthenticationError::Claims => {
            HttpError(ProblemCode::AuthenticationRefused)
        }
        AuthenticationError::Profile => HttpError(ProblemCode::ProfileNotAuthorized),
        // The verifier reached no verdict, so the credential is not what is
        // wrong. Answering 401 here would challenge a caller holding a good
        // token and invite it to rotate one during an outage that is ours;
        // `service.unavailable` carries `Retry-After` instead.
        AuthenticationError::Unavailable => HttpError(ProblemCode::ServiceUnavailable),
    }
}

/// The idempotency key every mutating command carries: present, bounded, and
/// graphical, so it can never smuggle a header-breaking byte.
fn idempotency_key(headers: &HeaderMap) -> Result<&str, HttpError> {
    let value = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or(HttpError(ProblemCode::RequestInvalid))?;
    if value.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(HttpError(ProblemCode::RequestInvalid));
    }
    Ok(value)
}

/// One refusal from the closed vocabulary, as an HTTP answer: every product
/// decision and every request-edge rejection renders through the same pinned
/// document.
#[derive(Debug)]
pub struct HttpError(pub ProblemCode);

impl From<ServiceError> for HttpError {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::Problem(problem) => Self(problem),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        problem_response(self.0)
    }
}

fn current_trace() -> TraceContext {
    REQUEST_TRACE
        .try_with(Clone::clone)
        .unwrap_or_else(|_| TraceContext::server_created())
}

/// Render one problem: the pinned code, title, status, and detail
/// from the closed vocabulary, under the answering request's trace.
fn problem_response(problem: ProblemCode) -> Response {
    let trace = current_trace();
    let status = problem.http_status();
    let body = ProblemBody {
        type_uri: type_uri(problem.code()),
        title: problem.title(),
        status,
        detail: problem.detail(),
        code: problem.code(),
        trace_id: trace.trace_id.clone(),
    };
    finish_problem(status, body, &trace)
}

fn finish_problem(status: u16, body: ProblemBody, trace: &TraceContext) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
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
    response
}

/// Answer a replayed idempotency key exactly as the stored attempt first
/// answered. A release's empty receipt answers as an empty 204 again. A
/// refusal receipt carries its problem without a trace id, so it re-renders
/// from its pinned code under the answering request's trace — the first
/// answer's words, this answer's correlation. A receipt in no known shape is
/// corrupt stored state: the caller learns nothing from it.
fn replay_response(status_code: u16, receipt: Value) -> Response {
    if receipt.is_null() {
        return StatusCode::NO_CONTENT.into_response();
    }
    let Some(code) = receipt
        .get("problem")
        .and_then(|problem| problem.get("code"))
        .and_then(Value::as_str)
    else {
        tracing::error!("a stored attempt receipt carries no recognizable problem");
        return problem_response(ProblemCode::ServiceUnavailable);
    };
    match ProblemCode::from_code(code) {
        Some(problem) => {
            if problem.http_status() != status_code {
                tracing::warn!(
                    stored = status_code,
                    pinned = problem.http_status(),
                    "a stored attempt receipt disagrees with its pinned status"
                );
            }
            problem_response(problem)
        }
        None => {
            tracing::error!(code, "a stored attempt receipt carries an unknown code");
            problem_response(ProblemCode::ServiceUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::header::IntoHeaderName;
    use axum::http::Request;
    use tower::ServiceExt;

    const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
    const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";

    fn traced_request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("traceparent", TRACEPARENT)
            .body(Body::empty())
            .expect("a traced test request")
    }

    /// Drive one in-process request to its answer; an infallible router
    /// always answers.
    async fn send(router: Router, request: Request<Body>) -> Response {
        router
            .oneshot(request)
            .await
            .expect("an in-process request always answers")
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a bounded test body");
        serde_json::from_slice(&bytes).expect("a JSON test body")
    }

    /// The edge under test, without a service behind it: the boundary layers
    /// and the fallbacks are the surface these tests pin.
    fn edge_router() -> Router {
        async fn echo(Json(_): Json<CancelAppointmentRequest>) -> StatusCode {
            StatusCode::OK
        }
        http_edge(Router::new().route("/v1/echo", post(echo)))
    }

    #[tokio::test]
    async fn an_unknown_route_answers_the_pinned_problem_under_the_callers_trace() {
        let response = send(edge_router(), traced_request("GET", "/v1/nothing")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        assert_eq!(response.headers().get("traceparent").unwrap(), TRACEPARENT);
        let body = body_json(response).await;
        assert_eq!(
            body["type"],
            "https://id.registrystack.org/problems/registry-scheduling/request/not-found"
        );
        assert_eq!(body["title"], "Route not found");
        assert_eq!(body["status"], 404);
        assert_eq!(body["detail"], "The requested route does not exist.");
        assert_eq!(body["code"], "request.not-found");
        assert_eq!(body["traceId"], TRACE_ID);
    }

    #[tokio::test]
    async fn a_known_route_with_a_foreign_method_is_method_not_allowed() {
        let response = send(edge_router(), traced_request("POST", "/v1/nothing")).await;
        // The method fallback wins over the route fallback for a path no
        // route claims at all.
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = send(edge_router(), traced_request("GET", "/v1/echo")).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = body_json(response).await;
        assert_eq!(body["code"], "request.method-not-allowed");
        assert_eq!(body["status"], 405);
    }

    #[tokio::test]
    async fn framework_rejections_normalize_to_request_problems() {
        // Malformed JSON is a 400, a type mismatch a 422, and a non-JSON
        // content type a 415: three framework answers, one problem vocabulary.
        let malformed = Request::builder()
            .method("POST")
            .uri("/v1/echo")
            .header("content-type", "application/json")
            .body(Body::from("this is not json"))
            .unwrap();
        let response = send(edge_router(), malformed).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert_eq!(body["code"], "request.invalid");

        let mismatched = Request::builder()
            .method("POST")
            .uri("/v1/echo")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"observedRevision": "not a number"}"#))
            .unwrap();
        let response = send(edge_router(), mismatched).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(response).await;
        assert_eq!(body["code"], "request.unprocessable");

        let wrong_media = Request::builder()
            .method("POST")
            .uri("/v1/echo")
            .header("content-type", "text/plain")
            .body(Body::from(r#"{"x":1}"#))
            .unwrap();
        let response = send(edge_router(), wrong_media).await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body = body_json(response).await;
        assert_eq!(body["code"], "request.unsupported-media-type");
    }

    #[tokio::test]
    async fn answers_carry_no_store_and_the_callers_trace() {
        let response = send(
            edge_router(),
            Request::builder()
                .method("POST")
                .uri("/v1/echo")
                .header("traceparent", TRACEPARENT)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"observedRevision": 1}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        // The answering traceparent keeps the caller's trace id under a fresh
        // server span id: pin the trace id segment, not the whole header.
        let answered = response
            .headers()
            .get("traceparent")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(&answered[3..35], TRACE_ID);
    }

    #[test]
    fn every_problem_of_the_closed_vocabulary_renders_its_pinned_document() {
        for problem in ProblemCode::ALL {
            let response = problem_response(*problem);
            let status = StatusCode::from_u16(problem.http_status()).unwrap();
            assert_eq!(response.status(), status, "the code {}", problem.code());
        }
    }

    #[tokio::test]
    async fn product_problems_carry_the_vocabulary_dialect() {
        let trace = TraceContext::from_headers(&{
            let mut headers = HeaderMap::new();
            headers.insert(
                "traceparent",
                TRACEPARENT.parse().expect("a valid traceparent"),
            );
            headers
        });
        let response = REQUEST_TRACE
            .scope(trace.clone(), async {
                problem_response(ProblemCode::CapacityExhausted)
            })
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = body_json(response).await;
        assert_eq!(body["type"], type_uri("capacity.exhausted"));
        assert_eq!(body["title"], "Capacity exhausted");
        assert_eq!(body["status"], 409);
        assert_eq!(body["detail"], ProblemCode::CapacityExhausted.detail());
        assert_eq!(body["code"], "capacity.exhausted");
        assert_eq!(
            body["traceId"],
            serde_json::to_value(&trace.trace_id).unwrap()
        );
    }

    #[tokio::test]
    async fn an_unauthenticated_problem_challenges_for_a_bearer() {
        let response = REQUEST_TRACE
            .scope(TraceContext::server_created(), async {
                problem_response(ProblemCode::AuthenticationRefused)
            })
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");
    }

    #[tokio::test]
    async fn an_unavailable_problem_names_a_retry_interval() {
        let response = REQUEST_TRACE
            .scope(TraceContext::server_created(), async {
                problem_response(ProblemCode::ServiceUnavailable)
            })
            .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "5");
    }

    #[tokio::test]
    async fn a_verifier_that_cannot_answer_is_unavailable_not_a_challenge() {
        // A 401 tells a caller its credential is wrong. When the issuer's key
        // material cannot be reached, nothing has been learned about the
        // credential, so the caller is told to come back instead of being sent
        // to rotate a working token.
        let problem = authentication_problem(AuthenticationError::Unavailable);
        assert!(matches!(
            problem,
            HttpError(ProblemCode::ServiceUnavailable)
        ));
        let response = REQUEST_TRACE
            .scope(TraceContext::server_created(), async {
                problem_response(problem.0)
            })
            .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "5");
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
        let body = body_json(response).await;
        assert_eq!(body["code"], "service.unavailable");
    }

    #[test]
    fn a_refused_credential_still_answers_a_challenge() {
        for refusal in [AuthenticationError::Refused, AuthenticationError::Claims] {
            assert!(matches!(
                authentication_problem(refusal),
                HttpError(ProblemCode::AuthenticationRefused)
            ));
        }
        assert!(matches!(
            authentication_problem(AuthenticationError::Profile),
            HttpError(ProblemCode::ProfileNotAuthorized)
        ));
    }

    fn stored_refusal(problem: ProblemCode) -> Value {
        // The receipt shape the service records under a caller's refused
        // idempotency key: the pinned problem, deliberately without a trace.
        serde_json::json!({
            "problem": {
                "type": type_uri(problem.code()),
                "title": problem.title(),
                "status": problem.http_status(),
                "detail": problem.detail(),
                "code": problem.code(),
            }
        })
    }

    #[tokio::test]
    async fn a_replayed_refusal_re_renders_its_pinned_code_under_the_current_trace() {
        let trace = TraceContext::from_headers(&{
            let mut headers = HeaderMap::new();
            headers.insert(
                "traceparent",
                TRACEPARENT.parse().expect("a valid traceparent"),
            );
            headers
        });
        let response = REQUEST_TRACE
            .scope(trace.clone(), async {
                replay_response(409, stored_refusal(ProblemCode::CapacityExhausted))
            })
            .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = body_json(response).await;
        assert_eq!(body["code"], "capacity.exhausted");
        assert_eq!(body["status"], 409);
        assert_eq!(
            body["traceId"],
            serde_json::to_value(&trace.trace_id).unwrap()
        );
    }

    #[tokio::test]
    async fn a_replayed_release_answers_an_empty_204_again() {
        let response = REQUEST_TRACE
            .scope(TraceContext::server_created(), async {
                replay_response(204, Value::Null)
            })
            .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let bytes = to_bytes(response.into_body(), 1 << 10).await.unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn a_receipt_in_no_known_shape_is_never_shown_to_the_caller() {
        let response = REQUEST_TRACE
            .scope(TraceContext::server_created(), async {
                replay_response(409, serde_json::json!({"surprise": true}))
            })
            .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(response).await;
        assert_eq!(body["code"], "service.unavailable");
    }

    fn headers_with<K: IntoHeaderName>(key: K, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(key, value.parse().expect("a valid header value"));
        headers
    }

    #[test]
    fn the_idempotency_key_is_present_bounded_and_graphical() {
        assert!(matches!(
            idempotency_key(&HeaderMap::new()),
            Err(HttpError(ProblemCode::RequestInvalid))
        ));
        assert!(matches!(
            idempotency_key(&headers_with(IDEMPOTENCY_KEY_HEADER, "")),
            Err(HttpError(ProblemCode::RequestInvalid))
        ));
        assert!(matches!(
            idempotency_key(&headers_with(IDEMPOTENCY_KEY_HEADER, "a key with spaces")),
            Err(HttpError(ProblemCode::RequestInvalid))
        ));
        let oversized = "k".repeat(MAXIMUM_IDEMPOTENCY_KEY_BYTES + 1);
        assert!(matches!(
            idempotency_key(&headers_with(IDEMPOTENCY_KEY_HEADER, &oversized)),
            Err(HttpError(ProblemCode::RequestInvalid))
        ));
        assert_eq!(
            idempotency_key(&headers_with(IDEMPOTENCY_KEY_HEADER, "hold-7")).unwrap(),
            "hold-7"
        );
    }

    #[test]
    fn the_item_routes_sit_on_the_pinned_collection_paths() {
        assert!(HOLD_ROUTE.starts_with(HOLDS_PATH));
        assert!(APPOINTMENT_ROUTE.starts_with(APPOINTMENTS_PATH));
        assert!(APPOINTMENT_RESCHEDULE_ROUTE.starts_with(APPOINTMENTS_PATH));
        assert!(APPOINTMENT_CANCEL_ROUTE.starts_with(APPOINTMENTS_PATH));
        assert!(APPOINTMENT_HISTORY_ROUTE.starts_with(APPOINTMENTS_PATH));
    }

    #[test]
    fn a_bearer_header_is_parsed_and_anything_else_is_a_refusal() {
        assert_eq!(
            bearer_token(&headers_with(AUTHORIZATION, "Bearer fixture-secret")).unwrap(),
            "fixture-secret"
        );
        assert!(matches!(
            bearer_token(&headers_with(AUTHORIZATION, "Basic dXNlcjpwYXNz")),
            Err(HttpError(ProblemCode::AuthenticationRefused))
        ));
        assert!(matches!(
            bearer_token(&HeaderMap::new()),
            Err(HttpError(ProblemCode::AuthenticationRefused))
        ));
    }
}
