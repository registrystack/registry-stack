// SPDX-License-Identifier: Apache-2.0

//! The HTTP surface.
//!
//! The runtime answers `/health` and refuses every other request with a
//! problem from the closed vocabulary. Every response carries the request's
//! trace and `Cache-Control: no-store`.
//!
//! The document routes are assembled by `document_router`, which exists
//! only in test builds: the production listener serves no document route
//! until it verifies the caller's token.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use registry_documents_core::{type_uri, ProblemCode, HEALTH_PATH};
use registry_platform_httpsec::{
    request_body_limit_default, security_headers, CspBuilder, ProblemBody, TraceContext,
};

tokio::task_local! {
    static REQUEST_TRACE: TraceContext;
}

/// Every problem the HTTP surface can answer with.
pub const HTTP_PROBLEMS: &[ProblemCode] = ProblemCode::ALL;

/// The route that reserves a document.
pub const DOCUMENTS_PATH: &str = "/documents";
/// The route that reads one document.
pub const DOCUMENT_PATH: &str = "/documents/{documentId}";
/// The route that releases the content of one document version.
pub const DOCUMENT_CONTENT_PATH: &str = "/documents/{documentId}/versions/{versionId}/content";
/// The route an upload's content is sent to.
pub const UPLOAD_CONTENT_PATH: &str = "/uploads/{uploadId}/content";

/// The production surface: `/health` only.
pub fn router() -> Router {
    finish(Router::new().route(HEALTH_PATH, get(health)), Router::new())
}

/// Apply the shared fallbacks and boundary layers. `limited` routes take
/// the default request body limit; `unlimited` routes bound their own body.
fn finish(limited: Router, unlimited: Router) -> Router {
    limited
        .layer(request_body_limit_default())
        .merge(unlimited)
        .fallback(route_not_found)
        .method_not_allowed_fallback(method_not_allowed)
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

/// Framework rejections carry axum's own bodies, which no Document Store
/// caller was promised. The statuses are kept; the body becomes the
/// vocabulary's `request.*` problem for that status.
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

fn current_trace() -> TraceContext {
    REQUEST_TRACE
        .try_with(Clone::clone)
        .unwrap_or_else(|_| TraceContext::server_created())
}

/// Render one problem: the pinned code, title, status, and detail from the
/// closed vocabulary, under the answering request's trace.
pub(crate) fn problem_response(problem: ProblemCode) -> Response {
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
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response.headers_mut().insert(
            RETRY_AFTER,
            "5".parse()
                .expect("the retry interval is a valid header value"),
        );
    }
    response
}

#[cfg(any(test, feature = "postgres-test"))]
pub use documents::document_router;

/// The document routes, served only by test builds through a synthetic
/// actor source.
#[cfg(any(test, feature = "postgres-test"))]
mod documents {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::{Path, State};
    use axum::http::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post, put};
    use axum::{Json, Router};
    use registry_documents_core::{ProblemCode, ReserveDocumentRequest, HEALTH_PATH};
    use uuid::Uuid;

    use super::{
        finish, health, problem_response, DOCUMENTS_PATH, DOCUMENT_CONTENT_PATH, DOCUMENT_PATH,
        UPLOAD_CONTENT_PATH,
    };
    use crate::actor::{Actor, ActorSource};
    use crate::service::DocumentService;

    #[derive(Clone)]
    struct DocumentState {
        service: Arc<DocumentService>,
        actors: Arc<dyn ActorSource>,
    }

    impl DocumentState {
        /// The caller, or `request.not-found` so an unauthenticated caller
        /// learns nothing about which documents exist.
        fn actor(&self, headers: &HeaderMap) -> Result<Actor, ProblemCode> {
            self.actors
                .actor(headers)
                .ok_or(ProblemCode::RequestNotFound)
        }
    }

    fn identifier(text: &str) -> Result<Uuid, ProblemCode> {
        Uuid::parse_str(text).map_err(|_| ProblemCode::RequestNotFound)
    }

    fn answer(result: Result<Response, ProblemCode>) -> Response {
        result.unwrap_or_else(problem_response)
    }

    /// The health route and the document routes, acting for the callers
    /// `actors` names.
    pub fn document_router(service: Arc<DocumentService>, actors: Arc<dyn ActorSource>) -> Router {
        let state = DocumentState { service, actors };
        let limited = Router::new()
            .route(HEALTH_PATH, get(health))
            .route(DOCUMENTS_PATH, post(reserve))
            .route(DOCUMENT_PATH, get(read))
            .route(DOCUMENT_CONTENT_PATH, get(download))
            .with_state(state.clone());
        let unlimited = Router::new()
            .route(UPLOAD_CONTENT_PATH, put(upload))
            .with_state(state);
        finish(limited, unlimited)
    }

    async fn reserve(
        State(state): State<DocumentState>,
        headers: HeaderMap,
        Json(request): Json<ReserveDocumentRequest>,
    ) -> Response {
        answer(
            async {
                let actor = state.actor(&headers)?;
                let view = state.service.reserve(&actor, &request).await?;
                let location = format!("{DOCUMENTS_PATH}/{}", view.document.id);
                Ok((StatusCode::CREATED, [(LOCATION, location)], Json(view)).into_response())
            }
            .await,
        )
    }

    async fn read(
        State(state): State<DocumentState>,
        headers: HeaderMap,
        Path(document_id): Path<String>,
    ) -> Response {
        answer(
            async {
                let actor = state.actor(&headers)?;
                let view = state
                    .service
                    .read(&actor, identifier(&document_id)?)
                    .await?;
                Ok(Json(view).into_response())
            }
            .await,
        )
    }

    async fn upload(
        State(state): State<DocumentState>,
        headers: HeaderMap,
        Path(upload_id): Path<String>,
        body: Body,
    ) -> Response {
        answer(
            async {
                let actor = state.actor(&headers)?;
                let upload_id = identifier(&upload_id)?;
                let content_type = headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok());
                let content_length = headers
                    .get(CONTENT_LENGTH)
                    .map(|value| {
                        value
                            .to_str()
                            .ok()
                            .and_then(|text| text.parse::<u64>().ok())
                            .ok_or(ProblemCode::RequestInvalid)
                    })
                    .transpose()?;
                let view = state
                    .service
                    .put_content(
                        &actor,
                        upload_id,
                        content_type,
                        content_length,
                        body.into_data_stream(),
                    )
                    .await?;
                Ok(Json(view).into_response())
            }
            .await,
        )
    }

    async fn download(
        State(state): State<DocumentState>,
        headers: HeaderMap,
        Path((document_id, version_id)): Path<(String, String)>,
    ) -> Response {
        answer(
            async {
                let actor = state.actor(&headers)?;
                let content = state
                    .service
                    .download(&actor, identifier(&document_id)?, identifier(&version_id)?)
                    .await?;
                Ok((
                    StatusCode::OK,
                    [
                        (CONTENT_TYPE, content.media_type),
                        (CONTENT_LENGTH, content.bytes.len().to_string()),
                        (CONTENT_DISPOSITION, "attachment".to_owned()),
                    ],
                    content.bytes,
                )
                    .into_response())
            }
            .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderMap, Request};
    use registry_documents_core::ProblemDocument;
    use tower::ServiceExt as _;

    async fn call(method: &str, uri: &str, body: Body) -> Response {
        router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Assert the response is exactly the pinned problem and hand back its
    /// headers.
    async fn expect_problem(response: Response, expected: ProblemCode) -> HeaderMap {
        assert_eq!(response.status().as_u16(), expected.http_status());
        let headers = response.headers().clone();
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let document: ProblemDocument = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document.problem(), Some(expected));
        assert!(!document.trace_id.is_empty());
        headers
    }

    #[tokio::test]
    async fn health_answers_without_a_credential() {
        let response = call("GET", HEALTH_PATH, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    }

    #[tokio::test]
    async fn every_other_route_is_not_found() {
        for path in ["/", "/documents", "/ready", "/metrics", "/health/extra"] {
            expect_problem(
                call("GET", path, Body::empty()).await,
                ProblemCode::RequestNotFound,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn the_served_router_carries_no_document_route() {
        let id = "00000000-0000-4000-8000-000000000000";
        for (method, uri) in [
            ("POST", DOCUMENTS_PATH.to_owned()),
            ("GET", format!("/documents/{id}")),
            ("GET", format!("/documents/{id}/versions/{id}/content")),
            ("PUT", format!("/uploads/{id}/content")),
        ] {
            expect_problem(
                call(method, &uri, Body::from("%PDF")).await,
                ProblemCode::RequestNotFound,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn another_method_on_health_is_refused() {
        expect_problem(
            call("POST", HEALTH_PATH, Body::empty()).await,
            ProblemCode::RequestMethodNotAllowed,
        )
        .await;
    }

    #[tokio::test]
    async fn the_trace_is_echoed_on_a_refusal() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/documents")
                    .header(
                        "traceparent",
                        "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let headers = expect_problem(response, ProblemCode::RequestNotFound).await;
        assert!(headers.contains_key("traceparent"));
    }

    #[test]
    fn framework_rejections_become_request_problems() {
        for (status, expected) in [
            (StatusCode::BAD_REQUEST, ProblemCode::RequestInvalid),
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                ProblemCode::RequestBodyTooLarge,
            ),
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ProblemCode::RequestUnsupportedMediaType,
            ),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                ProblemCode::RequestUnprocessable,
            ),
        ] {
            let response = normalize_framework_rejection(status.into_response());
            assert_eq!(response.status().as_u16(), expected.http_status());
            assert_eq!(
                response.headers().get(CONTENT_TYPE).unwrap(),
                "application/problem+json"
            );
        }
    }

    #[test]
    fn service_unavailable_tells_the_caller_when_to_retry() {
        let response = problem_response(ProblemCode::ServiceUnavailable);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "5");
    }
}
