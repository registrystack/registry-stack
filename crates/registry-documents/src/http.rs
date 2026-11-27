// SPDX-License-Identifier: Apache-2.0

//! The HTTP surface.
//!
//! The runtime answers `/health` and `/ready` without a credential and the
//! document routes only after it verifies the caller's bearer token and
//! resolves it to one access profile. Every other request is refused with a
//! problem from the closed vocabulary. Every response carries the request's
//! trace and `Cache-Control: no-store`; a credential refusal carries
//! `WWW-Authenticate: Bearer`.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest as _, Path, Query, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION,
    RETRY_AFTER, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use registry_documents_core::{
    type_uri, Caller, IssueGrantRequest, ProblemCode, ReserveDocumentRequest, HEALTH_PATH,
    READY_PATH,
};
use registry_platform_authcommon::{
    parse_bearer_token, BearerParseError, DeclaredScope, FailedCheck, RefusalNote,
};
use registry_platform_httpsec::{
    normalize_framework_rejection, request_body_limit_default, security_headers, CspBuilder,
    FrameworkRejection, ProblemBody, TraceContext,
};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use uuid::Uuid;

use crate::audit::DocumentsAudit;
use crate::auth::{AuthenticationError, DocumentsAuthenticator};
use crate::metrics::{serve_metrics, MetricsState, METRICS_PATH};
use crate::service::{DocumentService, PageRequest, ServiceError};
use crate::store::PostgresStore;

tokio::task_local! {
    static REQUEST_TRACE: TraceContext;
}

/// Every problem the HTTP surface can answer with.
pub const HTTP_PROBLEMS: &[ProblemCode] = ProblemCode::ALL;

pub use registry_documents_core::{
    DOCUMENTS_PATH, DOCUMENT_CONTENT_PATH, DOCUMENT_ERASURE_PATH, DOCUMENT_GRANTS_PATH,
    DOCUMENT_PATH, GRANTS_PATH, GRANT_PATH, IDEMPOTENCY_KEY_HEADER, MAXIMUM_IDEMPOTENCY_KEY_BYTES,
    POLICIES_PATH, UPLOAD_CONTENT_PATH,
};

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

/// The operator-private router the metrics listener serves: the series, with
/// the queues sampled at each scrape. It shares the boundary layers and the
/// refusals of the serving router, and answers nothing else.
pub fn metrics_router(state: MetricsState) -> Router {
    finish(
        Router::new()
            .route(METRICS_PATH, get(serve_metrics))
            .with_state(state),
        Router::new(),
    )
}

async fn http_boundary(request: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let trace = TraceContext::from_headers(request.headers());
    let mut response = REQUEST_TRACE
        .scope(trace.clone(), async move {
            normalize_framework_rejection(next.run(request).await, framework_rejection_problem)
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
fn framework_rejection_problem(kind: FrameworkRejection) -> Response {
    problem_response(match kind {
        FrameworkRejection::Invalid => ProblemCode::RequestInvalid,
        FrameworkRejection::BodyTooLarge => ProblemCode::RequestBodyTooLarge,
        FrameworkRejection::UnsupportedMediaType => ProblemCode::RequestUnsupportedMediaType,
        FrameworkRejection::Unprocessable => ProblemCode::RequestUnprocessable,
    })
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

/// What `/ready` asks before it answers.
#[derive(Clone, Debug)]
pub enum Readiness {
    /// The audit destination can take an entry, and the store answers with
    /// the expected schema, its ledger naming active the package this
    /// runtime serves for its database id, and the runtime role's grants
    /// current. Once an operator applies another package, the runtime
    /// answers not ready until it is restarted onto it.
    Store {
        store: PostgresStore,
        database_id: String,
        package_digest: String,
        audit: DocumentsAudit,
    },
    /// A fixed answer, for tests of the HTTP surface without a database.
    #[cfg(test)]
    Fixed(bool),
}

impl Readiness {
    /// Ask `audit` instead, for a runtime whose routes write to it.
    #[cfg(feature = "postgres-test")]
    pub(crate) fn watch_audit(&mut self, audit: DocumentsAudit) {
        match self {
            Self::Store { audit: watched, .. } => *watched = audit,
            #[cfg(test)]
            Self::Fixed(_) => {}
        }
    }

    async fn is_ready(&self) -> bool {
        match self {
            Self::Store {
                store,
                database_id,
                package_digest,
                audit,
            } => {
                if !audit.ready().await {
                    tracing::warn!("the Document Store audit destination is not ready");
                    return false;
                }
                match crate::activation::check_runtime(store, database_id, package_digest).await {
                    Ok(_) => true,
                    Err(error) => {
                        tracing::warn!(error = %error, "the Document Store database is not ready");
                        false
                    }
                }
            }
            #[cfg(test)]
            Self::Fixed(ready) => *ready,
        }
    }
}

/// `200` with no body while ready; `service.unavailable` otherwise, which
/// names no cause. The log carries the cause.
async fn ready(State(readiness): State<Readiness>) -> Response {
    if readiness.is_ready().await {
        StatusCode::OK.into_response()
    } else {
        problem_response(ProblemCode::ServiceUnavailable)
    }
}

/// The readiness probe, over its own state.
fn readiness_router(readiness: Readiness) -> Router {
    Router::new()
        .route(READY_PATH, get(ready))
        .with_state(readiness)
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

/// What the document routes act with: the operations and the
/// authenticator every route resolves its caller through first.
#[derive(Clone, Debug)]
pub struct DocumentRoutes {
    pub service: Arc<DocumentService>,
    pub authenticator: Arc<DocumentsAuthenticator>,
    pub readiness: Readiness,
}

impl DocumentRoutes {
    /// The verified caller, before anything else of the request is read.
    /// A missing or refused credential is `authentication.refused`; a token
    /// that resolves to no access profile is `profile.not-authorized`.
    async fn caller(&self, headers: &HeaderMap) -> Result<Caller, Refusal> {
        let token = bearer_token(headers)?;
        let caller = self
            .authenticator
            .authenticate_declaring(token)
            .await
            .map_err(|refusal| Refusal {
                error: authentication_refusal(refusal.error),
                declared: refusal.declared,
            })?;
        self.service.admit().await?;
        Ok(caller)
    }
}

/// The bearer token of the request, or the refusal that names what is wrong
/// with its credential: none, another scheme, or a header that is not a
/// well-formed bearer credential.
fn bearer_token(headers: &HeaderMap) -> Result<&str, ServiceError> {
    let credential = |check| ServiceError::unauthenticated(check);
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| credential(FailedCheck::CredentialMissing))?
        .to_str()
        .map_err(|_| credential(FailedCheck::CredentialMalformed))?;
    parse_bearer_token(value).map_err(|error| match error {
        BearerParseError::InvalidScheme => credential(FailedCheck::CredentialMissing),
        _ => credential(FailedCheck::CredentialMalformed),
    })
}

/// How authentication's refusal answers: a credential or claims refusal is
/// `authentication.refused`, a profile refusal is `profile.not-authorized`,
/// and a verifier that cannot answer is `service.unavailable`.
fn authentication_refusal(error: AuthenticationError) -> ServiceError {
    match error {
        AuthenticationError::Refused(check) | AuthenticationError::Claims(check) => {
            ServiceError::unauthenticated(check)
        }
        AuthenticationError::Profile(check) => ServiceError::not_authorized(check),
        AuthenticationError::Unavailable => ServiceError::KeySourceUnavailable,
    }
}

/// The served surface: `/health`, `/ready`, and the document routes.
pub fn router(routes: DocumentRoutes) -> Router {
    let probes = Router::new()
        .route(HEALTH_PATH, get(health))
        .merge(readiness_router(routes.readiness.clone()));
    let limited = Router::new()
        .route(DOCUMENTS_PATH, post(reserve).get(list_documents))
        .route(DOCUMENT_PATH, get(read))
        .route(DOCUMENT_CONTENT_PATH, get(download))
        .route(DOCUMENT_GRANTS_PATH, post(issue_grant).get(document_grants))
        .route(GRANTS_PATH, get(received_grants))
        .route(GRANT_PATH, delete(revoke_grant))
        .route(DOCUMENT_ERASURE_PATH, post(request_erasure))
        .route(POLICIES_PATH, get(policies))
        .with_state(routes.clone())
        .merge(probes);
    let unlimited = Router::new()
        .route(UPLOAD_CONTENT_PATH, put(upload))
        .with_state(routes);
    finish(limited, unlimited)
}

/// An id in a path. One that is not an id names nothing, and the answer
/// does not say whether anything exists.
fn identifier(text: &str) -> Result<Uuid, ServiceError> {
    Uuid::parse_str(text).map_err(|_| ServiceError::concealed(FailedCheck::Visibility))
}

/// A failed operation, and the values the deployment declared about it when
/// it is a scope refusal. The values go to the operator's log line only.
pub(crate) struct Refusal {
    error: ServiceError,
    declared: Option<DeclaredScope>,
}

impl From<ServiceError> for Refusal {
    fn from(error: ServiceError) -> Self {
        Self {
            error,
            declared: None,
        }
    }
}

impl From<ProblemCode> for Refusal {
    fn from(problem: ProblemCode) -> Self {
        ServiceError::from(problem).into()
    }
}

fn answer(result: Result<Response, Refusal>) -> Response {
    result.unwrap_or_else(|refusal| {
        let mut response = refusal_response(refusal.error);
        if let Some(declared) = refusal.declared {
            response.extensions_mut().insert(declared);
        }
        response
    })
}

/// The remedy the log line of a scope refusal carries.
const SCOPE_REMEDY: &str = "issue the access profile's required scope to the client, or set authentication.oidc.scopeClaim to the claim the issuer emits";

/// Render the answer to a failed operation. A refusal of authority puts its
/// check in the response's extensions, which are never serialized, for the
/// layer that records it; the bytes of the answer are those of its problem.
pub(crate) fn refusal_response(error: ServiceError) -> Response {
    let mut response = problem_response(error.problem());
    if let Some(check) = error.failed_check() {
        let note = RefusalNote::new(check);
        let note = match check {
            FailedCheck::Scope => note.with_remedy(SCOPE_REMEDY),
            _ => note,
        };
        response.extensions_mut().insert(note);
    }
    response
}

/// The idempotency key a creating request carries: present, bounded, and
/// graphical, so it can never smuggle a header-breaking byte.
fn idempotency_key(headers: &HeaderMap) -> Result<&str, ProblemCode> {
    headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAXIMUM_IDEMPOTENCY_KEY_BYTES
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .ok_or(ProblemCode::RequestInvalid)
}

/// The whole body of `request`, under the default body limit the router
/// applies. A handler calls this only after it verifies the caller, so an
/// unauthenticated request is refused before any of its body is read.
async fn buffered(request: Request) -> Result<Bytes, ProblemCode> {
    Bytes::from_request(request, &())
        .await
        .map_err(|rejection| match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => ProblemCode::RequestBodyTooLarge,
            _ => ProblemCode::RequestInvalid,
        })
}

/// A JSON request body, read only after the caller is verified. A body
/// that is not JSON is `request.invalid`; JSON of the wrong shape is
/// `request.unprocessable`.
fn json_body<T: DeserializeOwned>(headers: &HeaderMap, body: &[u8]) -> Result<T, ProblemCode> {
    let is_json = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(ProblemCode::RequestUnsupportedMediaType);
    }
    serde_json::from_slice(body).map_err(|error| match error.classify() {
        serde_json::error::Category::Data => ProblemCode::RequestUnprocessable,
        _ => ProblemCode::RequestInvalid,
    })
}

/// The query of a list route: an optional cursor and page size, and
/// nothing else.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    cursor: Option<String>,
    limit: Option<String>,
}

fn page(uri: &Uri) -> Result<PageRequest, ProblemCode> {
    let Query(query) =
        Query::<PageQuery>::try_from_uri(uri).map_err(|_| ProblemCode::RequestInvalid)?;
    PageRequest::parse(query.cursor.as_deref(), query.limit.as_deref())
}

async fn reserve(State(routes): State<DocumentRoutes>, request: Request) -> Response {
    answer(
        async {
            let headers = request.headers().clone();
            let caller = routes.caller(&headers).await?;
            let key = idempotency_key(&headers)?;
            let request: ReserveDocumentRequest = json_body(&headers, &buffered(request).await?)?;
            let view = routes.service.reserve(&caller, key, &request).await?;
            let location = format!("{DOCUMENTS_PATH}/{}", view.document.id);
            Ok((StatusCode::CREATED, [(LOCATION, location)], Json(view)).into_response())
        }
        .await,
    )
}

async fn list_documents(
    State(routes): State<DocumentRoutes>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
            let page = page(&uri)?;
            Ok(Json(routes.service.list(&caller, &page).await?).into_response())
        }
        .await,
    )
}

async fn read(
    State(routes): State<DocumentRoutes>,
    headers: HeaderMap,
    Path(document_id): Path<String>,
) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
            let view = routes
                .service
                .read(&caller, identifier(&document_id)?)
                .await?;
            Ok(Json(view).into_response())
        }
        .await,
    )
}

async fn upload(
    State(routes): State<DocumentRoutes>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
    body: Body,
) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
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
            let outcome = routes
                .service
                .put_content(
                    &caller,
                    upload_id,
                    content_type,
                    content_length,
                    body.into_data_stream(),
                )
                .await?;
            Ok(Json(outcome.into_view()).into_response())
        }
        .await,
    )
}

async fn download(
    State(routes): State<DocumentRoutes>,
    headers: HeaderMap,
    Path((document_id, version_id)): Path<(String, String)>,
) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
            let content = routes
                .service
                .download(&caller, identifier(&document_id)?, identifier(&version_id)?)
                .await?;
            Ok((
                StatusCode::OK,
                [
                    (CONTENT_TYPE, content.media_type),
                    (CONTENT_LENGTH, content.length.to_string()),
                    (CONTENT_DISPOSITION, "attachment".to_owned()),
                ],
                Body::from_stream(content.body),
            )
                .into_response())
        }
        .await,
    )
}

async fn issue_grant(
    State(routes): State<DocumentRoutes>,
    Path(document_id): Path<String>,
    request: Request,
) -> Response {
    answer(
        async {
            let headers = request.headers().clone();
            let caller = routes.caller(&headers).await?;
            let document_id = identifier(&document_id)?;
            let key = idempotency_key(&headers)?;
            let request: IssueGrantRequest = json_body(&headers, &buffered(request).await?)?;
            let view = routes
                .service
                .issue_grant(&caller, key, document_id, &request)
                .await?;
            let location = format!("{GRANTS_PATH}/{}", view.id);
            Ok((StatusCode::CREATED, [(LOCATION, location)], Json(view)).into_response())
        }
        .await,
    )
}

async fn document_grants(
    State(routes): State<DocumentRoutes>,
    headers: HeaderMap,
    Path(document_id): Path<String>,
    uri: Uri,
) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
            let document_id = identifier(&document_id)?;
            let page = page(&uri)?;
            Ok(Json(
                routes
                    .service
                    .document_grants(&caller, document_id, &page)
                    .await?,
            )
            .into_response())
        }
        .await,
    )
}

async fn received_grants(
    State(routes): State<DocumentRoutes>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
            let page = page(&uri)?;
            Ok(Json(routes.service.received_grants(&caller, &page).await?).into_response())
        }
        .await,
    )
}

async fn revoke_grant(
    State(routes): State<DocumentRoutes>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
            let view = routes
                .service
                .revoke_grant(&caller, identifier(&grant_id)?)
                .await?;
            Ok(Json(view).into_response())
        }
        .await,
    )
}

async fn request_erasure(
    State(routes): State<DocumentRoutes>,
    headers: HeaderMap,
    Path(document_id): Path<String>,
) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
            let view = routes
                .service
                .request_erasure(&caller, identifier(&document_id)?)
                .await?;
            Ok(Json(view).into_response())
        }
        .await,
    )
}

async fn policies(State(routes): State<DocumentRoutes>, headers: HeaderMap) -> Response {
    answer(
        async {
            let caller = routes.caller(&headers).await?;
            Ok(Json(routes.service.placeable_policies(&caller)).into_response())
        }
        .await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{HeaderMap, Request};
    use registry_documents_core::ProblemDocument;
    use tower::ServiceExt as _;

    /// The boundary layers over the probes alone: what every route shares,
    /// without a database behind it.
    fn shell() -> Router {
        shell_answering_ready(true)
    }

    fn shell_answering_ready(ready: bool) -> Router {
        finish(
            Router::new()
                .route(HEALTH_PATH, get(health))
                .merge(readiness_router(Readiness::Fixed(ready))),
            Router::new(),
        )
    }

    async fn call(method: &str, uri: &str, body: Body) -> Response {
        shell()
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
    async fn ready_answers_without_a_credential_when_the_store_and_audit_are_ready() {
        let response = call("GET", READY_PATH, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        assert!(bytes.is_empty(), "the ready answer carries no body");
    }

    #[tokio::test]
    async fn ready_answers_unavailable_while_the_store_or_audit_is_not_ready() {
        let response = shell_answering_ready(false)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(READY_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let headers = expect_problem(response, ProblemCode::ServiceUnavailable).await;
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "5");
    }

    #[tokio::test]
    async fn another_method_on_ready_is_refused() {
        expect_problem(
            call("POST", READY_PATH, Body::empty()).await,
            ProblemCode::RequestMethodNotAllowed,
        )
        .await;
    }

    #[tokio::test]
    async fn every_other_route_is_not_found() {
        for path in ["/", "/ready/extra", "/metrics", "/health/extra"] {
            expect_problem(
                call("GET", path, Body::empty()).await,
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
        let response = shell()
            .oneshot(
                Request::builder()
                    .uri("/unknown")
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
            let response =
                normalize_framework_rejection(status.into_response(), framework_rejection_problem);
            assert_eq!(response.status().as_u16(), expected.http_status());
            assert_eq!(
                response.headers().get(CONTENT_TYPE).unwrap(),
                "application/problem+json"
            );
        }
    }

    #[test]
    fn a_credential_refusal_carries_the_bearer_challenge() {
        let response = problem_response(ProblemCode::AuthenticationRefused);
        assert_eq!(response.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");
        let response = problem_response(ProblemCode::ProfileNotAuthorized);
        assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    }

    fn authorization(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value.parse().unwrap());
        headers
    }

    #[test]
    fn a_credential_refusal_names_what_is_wrong_with_the_credential() {
        let check = |headers: &HeaderMap| bearer_token(headers).unwrap_err().failed_check();
        assert_eq!(
            check(&HeaderMap::new()),
            Some(FailedCheck::CredentialMissing)
        );
        assert_eq!(
            check(&authorization("Basic dXNlcjpwYXNz")),
            Some(FailedCheck::CredentialMissing)
        );
        for malformed in ["Bearer", "Bearer  token", "Bearer a b"] {
            assert_eq!(
                check(&authorization(malformed)),
                Some(FailedCheck::CredentialMalformed),
                "{malformed}"
            );
        }
        let mut unreadable = HeaderMap::new();
        unreadable.insert(AUTHORIZATION, b"Bearer \xff".as_slice().try_into().unwrap());
        assert_eq!(check(&unreadable), Some(FailedCheck::CredentialMalformed));
        assert_eq!(bearer_token(&authorization("bearer abc")), Ok("abc"));
    }

    #[test]
    fn a_refusal_answers_the_bytes_of_its_problem_and_carries_its_note_apart() {
        for (error, problem) in [
            (
                ServiceError::concealed(FailedCheck::Visibility),
                ProblemCode::ResourceNotFound,
            ),
            (
                ServiceError::not_authorized(FailedCheck::Scope),
                ProblemCode::ProfileNotAuthorized,
            ),
            (
                ServiceError::unauthenticated(FailedCheck::TokenSignature),
                ProblemCode::AuthenticationRefused,
            ),
            (
                ServiceError::KeySourceUnavailable,
                ProblemCode::ServiceUnavailable,
            ),
        ] {
            let response = refusal_response(error);
            let plain = problem_response(problem);
            assert_eq!(response.status(), plain.status());
            // Each answer is under its own server-created trace.
            for (name, value) in plain.headers() {
                if name != "traceparent" && name != "tracestate" {
                    assert_eq!(response.headers().get(name), Some(value), "{name}");
                }
            }
            let note = response.extensions().get::<RefusalNote>().unwrap();
            assert_eq!(Some(note.check), error.failed_check());
            assert_eq!(
                note.remedy.is_some(),
                note.check == FailedCheck::Scope,
                "only a scope refusal carries a remedy"
            );
        }
        let plain = refusal_response(ServiceError::from(ProblemCode::RequestInvalid));
        assert!(plain.extensions().get::<RefusalNote>().is_none());
    }

    #[test]
    fn a_path_id_that_is_not_an_id_names_nothing() {
        assert_eq!(
            identifier("not-a-uuid"),
            Err(ServiceError::concealed(FailedCheck::Visibility))
        );
        assert!(identifier(&Uuid::nil().to_string()).is_ok());
    }

    #[test]
    fn the_idempotency_key_is_present_bounded_and_graphical() {
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(IDEMPOTENCY_KEY_HEADER, value.parse().unwrap());
            headers
        };
        assert_eq!(
            idempotency_key(&HeaderMap::new()),
            Err(ProblemCode::RequestInvalid)
        );
        for refused in ["", "a key with spaces", &"k".repeat(129)] {
            assert_eq!(
                idempotency_key(&with(refused)),
                Err(ProblemCode::RequestInvalid),
                "{refused}"
            );
        }
        assert_eq!(
            idempotency_key(&with(&"k".repeat(128))),
            Ok("k".repeat(128).as_str())
        );
    }

    #[test]
    fn a_json_body_is_parsed_only_as_json() {
        let json = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, value.parse().unwrap());
            headers
        };
        let parsed: Result<serde_json::Value, _> =
            json_body(&json("application/json; charset=utf-8"), b"{}");
        assert!(parsed.is_ok());
        assert_eq!(
            json_body::<serde_json::Value>(&json("text/plain"), b"{}").unwrap_err(),
            ProblemCode::RequestUnsupportedMediaType
        );
        assert_eq!(
            json_body::<serde_json::Value>(&HeaderMap::new(), b"{}").unwrap_err(),
            ProblemCode::RequestUnsupportedMediaType
        );
        assert_eq!(
            json_body::<serde_json::Value>(&json("application/json"), b"{").unwrap_err(),
            ProblemCode::RequestInvalid
        );
        assert_eq!(
            json_body::<IssueGrantRequest>(&json("application/json"), b"{\"versionId\": 1}")
                .unwrap_err(),
            ProblemCode::RequestUnprocessable
        );
    }

    #[test]
    fn a_page_query_names_only_a_cursor_and_a_limit() {
        assert!(page(&"/v1/documents".parse().unwrap()).is_ok());
        assert_eq!(
            page(&"/v1/documents?limit=10".parse().unwrap())
                .unwrap()
                .limit,
            10
        );
        for refused in [
            "/v1/documents?limit=0",
            "/v1/documents?other=1",
            "/v1/documents?cursor=zz",
        ] {
            assert_eq!(
                page(&refused.parse().unwrap()).unwrap_err(),
                ProblemCode::RequestInvalid,
                "{refused}"
            );
        }
    }

    #[test]
    fn service_unavailable_tells_the_caller_when_to_retry() {
        let response = problem_response(ProblemCode::ServiceUnavailable);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "5");
    }
}
