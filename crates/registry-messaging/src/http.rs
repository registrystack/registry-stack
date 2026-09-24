// SPDX-License-Identifier: Apache-2.0

//! The HTTP surface: the pinned routes, the request boundary, and the one
//! problem rendering every refusal flows through.
//!
//! Every refusal leaves this edge as one problem shape: a code from the
//! closed vocabulary in `registry-messaging-core`, under the Messaging
//! problem base, with the answering request's trace id. Framework rejections
//! keep their status and take the vocabulary's `request.*` body.
//!
//! The public listener serves `/health`, `/ready`, and the `/v1` routes.
//! `/metrics` is served only by [`metrics_router`], on the operator-private
//! metrics listener.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use registry_messaging_core::{
    check_message_visibility, type_uri, Caller, CallerIdentity, ProblemCode, HEALTH_PATH,
    MESSAGE_PATH, METRICS_PATH, READY_PATH,
};
use registry_platform_authcommon::parse_bearer_token;
use registry_platform_httpsec::{
    request_body_limit_default, security_headers, CspBuilder, ProblemBody, TraceContext,
};

use crate::auth::{AuthenticationError, MessagingAuthenticator};
use crate::metrics::{count_requests, serve_metrics, Metrics};
use crate::store::PostgresStore;

tokio::task_local! {
    static REQUEST_TRACE: TraceContext;
}

/// What `/ready` asks before it answers.
#[derive(Clone, Debug)]
pub enum Readiness {
    /// The store answers and carries the expected schema.
    Store(PostgresStore),
    /// A fixed answer, for tests of the HTTP surface without a database.
    #[cfg(test)]
    Fixed(bool),
}

impl Readiness {
    async fn is_ready(&self) -> bool {
        match self {
            Self::Store(store) => match store.ready().await {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(error = %error, "the Messaging store is not ready");
                    false
                }
            },
            #[cfg(test)]
            Self::Fixed(ready) => *ready,
        }
    }
}

#[derive(Clone)]
pub struct HttpState {
    pub authenticator: Arc<MessagingAuthenticator>,
    pub readiness: Readiness,
    pub metrics: Arc<Metrics>,
}

/// One operation of the public HTTP contract. The router and the generated
/// OpenAPI document both read this table, so neither can publish a route the
/// other does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    pub method: &'static str,
    pub path: &'static str,
    pub operation_id: &'static str,
    pub summary: &'static str,
    /// Whether the operation requires a bearer access token.
    pub authenticated: bool,
    /// The success status, answered with an empty body.
    pub success_status: u16,
    /// Every problem the operation can answer with.
    pub problems: &'static [ProblemCode],
}

/// The problems every operation can answer at the request edge.
const EDGE_PROBLEMS: [ProblemCode; 2] = [
    ProblemCode::RequestMethodNotAllowed,
    ProblemCode::ServiceUnavailable,
];

pub const OPERATIONS: &[Operation] = &[
    Operation {
        method: "get",
        path: HEALTH_PATH,
        operation_id: "getHealth",
        summary: "Report that the process is serving.",
        authenticated: false,
        success_status: 200,
        problems: &[ProblemCode::RequestMethodNotAllowed],
    },
    Operation {
        method: "get",
        path: READY_PATH,
        operation_id: "getReady",
        summary: "Report that the store answers with the expected schema.",
        authenticated: false,
        success_status: 200,
        problems: &EDGE_PROBLEMS,
    },
    Operation {
        method: "get",
        path: MESSAGE_PATH,
        operation_id: "getMessage",
        summary: "Read the status of a message the caller submitted, or any message for an \
                  operator. A message the caller may not see answers exactly like one that does \
                  not exist.",
        authenticated: true,
        success_status: 200,
        problems: &[
            ProblemCode::AuthenticationRefused,
            ProblemCode::ProfileNotAuthorized,
            ProblemCode::MessageNotVisible,
            ProblemCode::RequestMethodNotAllowed,
            ProblemCode::ServiceUnavailable,
        ],
    },
];

pub fn router(state: HttpState) -> Router {
    let metrics = Arc::clone(&state.metrics);
    http_edge(
        Router::new()
            .route(HEALTH_PATH, get(health))
            .route(READY_PATH, get(ready))
            .route(MESSAGE_PATH, get(get_message))
            .with_state(state)
            .layer(middleware::from_fn_with_state(metrics, count_requests)),
    )
}

/// The operator-private router the metrics listener serves.
pub fn metrics_router(metrics: Arc<Metrics>) -> Router {
    http_edge(
        Router::new()
            .route(METRICS_PATH, get(serve_metrics))
            .with_state(metrics),
    )
}

fn http_edge(router: Router) -> Router {
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

/// Framework rejections carry axum's own bodies, which no Messaging caller
/// was promised. The statuses are kept; the body becomes the vocabulary's
/// `request.*` problem for that status.
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

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<HttpState>) -> Result<StatusCode, HttpError> {
    if state.readiness.is_ready().await {
        Ok(StatusCode::OK)
    } else {
        Err(HttpError(ProblemCode::ServiceUnavailable))
    }
}

async fn get_message(
    State(state): State<HttpState>,
    Path(message_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, HttpError> {
    let caller = authenticate(&state, &headers).await?;
    let submitter = submitter_of(&message_id);
    check_message_visibility(&caller, submitter.as_ref()).map_err(HttpError)?;
    Ok(StatusCode::OK)
}

/// The identity that submitted a message. This version records no message,
/// so every lookup finds none and every read answers `message.not-visible`.
fn submitter_of(_message_id: &str) -> Option<CallerIdentity> {
    None
}

async fn authenticate(state: &HttpState, headers: &HeaderMap) -> Result<Caller, HttpError> {
    let result = match bearer_token(headers) {
        Some(token) => state.authenticator.authenticate(token).await,
        None => Err(AuthenticationError::Refused),
    };
    result.map_err(|error| {
        state.metrics.record_authentication_refusal(error);
        authentication_problem(error)
    })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let authorization = headers.get(AUTHORIZATION)?.to_str().ok()?;
    parse_bearer_token(authorization).ok()
}

fn authentication_problem(error: AuthenticationError) -> HttpError {
    match error {
        AuthenticationError::Refused | AuthenticationError::Claims => {
            HttpError(ProblemCode::AuthenticationRefused)
        }
        AuthenticationError::Profile => HttpError(ProblemCode::ProfileNotAuthorized),
        // The verifier reached no verdict, so the credential is not what is
        // wrong. `service.unavailable` carries `Retry-After` instead of a
        // challenge that would send the caller rotating a good token.
        AuthenticationError::Unavailable => HttpError(ProblemCode::ServiceUnavailable),
    }
}

pub struct HttpError(pub ProblemCode);

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

/// Render one problem: the pinned code, title, status, and detail from the
/// closed vocabulary, under the answering request's trace.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{
        authenticator, authenticator_over, operator_claims, sender_claims, token,
        token_signed_with, UNPROFILED_CLIENT,
    };
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use registry_messaging_core::ProblemDocument;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
    use serde_json::json;
    use tower::ServiceExt as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn state_with(authenticator: MessagingAuthenticator, ready: bool) -> HttpState {
        HttpState {
            authenticator: Arc::new(authenticator),
            readiness: Readiness::Fixed(ready),
            metrics: Arc::new(Metrics::default()),
        }
    }

    fn app() -> (Router, Arc<Metrics>) {
        let state = state_with(authenticator(), true);
        let metrics = Arc::clone(&state.metrics);
        (router(state), metrics)
    }

    async fn call(app: Router, method: &str, uri: &str, bearer: Option<&str>) -> Response {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(bearer) = bearer {
            request = request.header(AUTHORIZATION, format!("Bearer {bearer}"));
        }
        app.oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn problem(response: Response) -> ProblemDocument {
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Assert the response is exactly the pinned problem and hand back its
    /// headers.
    async fn expect_problem(response: Response, expected: ProblemCode) -> HeaderMap {
        assert_eq!(response.status().as_u16(), expected.http_status());
        let headers = response.headers().clone();
        let document = problem(response).await;
        assert_eq!(document.problem(), Some(expected));
        assert!(!document.trace_id.is_empty());
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        headers
    }

    #[tokio::test]
    async fn health_and_ready_answer_without_a_credential() {
        let (app, _) = app();
        let response = call(app.clone(), "GET", HEALTH_PATH, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        let response = call(app, "GET", READY_PATH, None).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ready_answers_unavailable_when_the_store_is_not_ready() {
        let app = router(state_with(authenticator(), false));
        let headers = expect_problem(
            call(app, "GET", READY_PATH, None).await,
            ProblemCode::ServiceUnavailable,
        )
        .await;
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "5");
    }

    #[tokio::test]
    async fn metrics_are_not_served_on_the_public_listener() {
        let (app, _) = app();
        expect_problem(
            call(app, "GET", METRICS_PATH, None).await,
            ProblemCode::RequestNotFound,
        )
        .await;
    }

    #[tokio::test]
    async fn the_metrics_listener_serves_counters_and_nothing_else() {
        let (app, metrics) = app();
        call(app, "GET", "/v1/messages/m-1", None).await;
        let metrics_app = metrics_router(metrics);
        let response = call(metrics_app.clone(), "GET", METRICS_PATH, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains("route=\"/v1/messages/{message_id}\""),
            "{text}"
        );
        assert!(text.contains("reason=\"refused\"} 1"), "{text}");
        assert!(!text.contains("m-1"));
        expect_problem(
            call(metrics_app, "GET", HEALTH_PATH, None).await,
            ProblemCode::RequestNotFound,
        )
        .await;
    }

    #[tokio::test]
    async fn a_missing_or_malformed_credential_is_challenged() {
        let (app, _) = app();
        let headers = expect_problem(
            call(app.clone(), "GET", "/v1/messages/m-1", None).await,
            ProblemCode::AuthenticationRefused,
        )
        .await;
        assert_eq!(headers.get(WWW_AUTHENTICATE).unwrap(), "Bearer");
        let request = Request::builder()
            .uri("/v1/messages/m-1")
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        expect_problem(
            app.oneshot(request).await.unwrap(),
            ProblemCode::AuthenticationRefused,
        )
        .await;
    }

    #[tokio::test]
    async fn a_forged_credential_is_challenged() {
        let (app, _) = app();
        let forged = token_signed_with(sender_claims(), b"another-secret-another-secret-another!");
        expect_problem(
            call(app, "GET", "/v1/messages/m-1", Some(&forged)).await,
            ProblemCode::AuthenticationRefused,
        )
        .await;
    }

    #[tokio::test]
    async fn a_credential_for_another_audience_is_challenged() {
        let (app, _) = app();
        let mut claims = sender_claims();
        claims["aud"] = json!("urn:elsewhere");
        expect_problem(
            call(app, "GET", "/v1/messages/m-1", Some(&token(claims))).await,
            ProblemCode::AuthenticationRefused,
        )
        .await;
    }

    #[tokio::test]
    async fn a_client_without_a_profile_or_scope_is_not_authorized() {
        let (app, _) = app();
        let mut unprofiled = sender_claims();
        unprofiled["azp"] = json!(UNPROFILED_CLIENT);
        expect_problem(
            call(
                app.clone(),
                "GET",
                "/v1/messages/m-1",
                Some(&token(unprofiled)),
            )
            .await,
            ProblemCode::ProfileNotAuthorized,
        )
        .await;
        let mut no_scope = sender_claims();
        no_scope["registry_scopes"] = json!("messaging:read");
        expect_problem(
            call(
                app.clone(),
                "GET",
                "/v1/messages/m-1",
                Some(&token(no_scope)),
            )
            .await,
            ProblemCode::ProfileNotAuthorized,
        )
        .await;
        let mut wrong_kind = sender_claims();
        wrong_kind["registry_actor_kind"] = json!("agent");
        expect_problem(
            call(app, "GET", "/v1/messages/m-1", Some(&token(wrong_kind))).await,
            ProblemCode::ProfileNotAuthorized,
        )
        .await;
    }

    #[tokio::test]
    async fn a_key_endpoint_outage_answers_unavailable_with_retry_after() {
        let issuer_keys = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&issuer_keys)
            .await;
        let during_outage = authenticator_over(Arc::new(JwksFetcher::new_with_fetch_url_policy(
            format!("{}/jwks.json", issuer_keys.uri()),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )));
        let app = router(state_with(during_outage, true));
        let headers = expect_problem(
            call(
                app,
                "GET",
                "/v1/messages/m-1",
                Some(&token(sender_claims())),
            )
            .await,
            ProblemCode::ServiceUnavailable,
        )
        .await;
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "5");
        assert!(headers.get(WWW_AUTHENTICATE).is_none());
    }

    #[tokio::test]
    async fn an_authenticated_caller_is_told_an_unknown_message_is_not_visible() {
        let (app, _) = app();
        for claims in [sender_claims(), operator_claims()] {
            expect_problem(
                call(app.clone(), "GET", "/v1/messages/m-1", Some(&token(claims))).await,
                ProblemCode::MessageNotVisible,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unknown_routes_and_methods_answer_as_problems() {
        let (app, _) = app();
        expect_problem(
            call(app.clone(), "GET", "/v1/unknown", None).await,
            ProblemCode::RequestNotFound,
        )
        .await;
        expect_problem(
            call(app, "POST", HEALTH_PATH, None).await,
            ProblemCode::RequestMethodNotAllowed,
        )
        .await;
    }

    #[test]
    fn the_operation_table_answers_only_catalogued_problems_and_unique_ids() {
        let mut ids = std::collections::BTreeSet::new();
        for operation in OPERATIONS {
            assert!(ids.insert(operation.operation_id));
            for problem in operation.problems {
                assert!(ProblemCode::ALL.contains(problem));
            }
            if operation.authenticated {
                assert!(operation
                    .problems
                    .contains(&ProblemCode::AuthenticationRefused));
                assert!(operation
                    .problems
                    .contains(&ProblemCode::ServiceUnavailable));
            }
        }
    }
}
