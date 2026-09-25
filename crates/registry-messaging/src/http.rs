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
//!
//! The template preview route renders a template version from the active
//! package for a sender whose profile lists the template. It persists
//! nothing and journals metadata only: the profile, the principal's keyed
//! pseudonym, the template version and locale the package ships, and the
//! outcome. Template data and rendered parts never reach the journal.
//!
//! The submission route authenticates, requires the sender role and an
//! `Idempotency-Key`, and hands the body to [`crate::messages`], which
//! checks the closed shape, authorizes the sender profile and template,
//! renders at acceptance, and records the message. An acceptance is audited
//! through the outbox in the transaction that records it; a refusal after
//! authentication and a replayed receipt are journaled here, by metadata
//! only. The status and cancel routes answer the submitter and operator
//! profiles alone, and a message anyone else asks for answers exactly like
//! one that does not exist.
//!
//! The provider callback routes take no bearer token: the provider's
//! configured verifier authenticates each request, and [`crate::callbacks`]
//! reads and records it.

use std::sync::Arc;

use axum::extract::{FromRequest, Path, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use registry_messaging_core::{
    type_uri, AccessRole, Caller, ContentRefusal, MessageView, Package, ProblemCode,
    TemplatePreview, TemplatePreviewRequest, HEALTH_PATH, IDEMPOTENCY_KEY_HEADER, MESSAGES_PATH,
    MESSAGE_CANCEL_PATH, MESSAGE_PATH, METRICS_PATH, PROVIDER_CALLBACK_PATH,
    PROVIDER_CALLBACK_TOKEN_PATH, READY_PATH, TEMPLATE_PREVIEW_PATH,
};
use registry_platform_authcommon::parse_bearer_token;
use registry_platform_httpsec::{
    request_body_limit_default, security_headers, CspBuilder, ProblemBody, TraceContext,
};
use serde::Serialize;

use crate::audit::AuditJournal;
use crate::auth::{AuthenticationError, MessagingAuthenticator};
use crate::callbacks;
use crate::limits::{CallbackLimits, CallerLimits, LimitRefusal};
use crate::messages::{
    prepare_submission, valid_idempotency_key, MessageService, SubmissionAnswer, SubmissionRefusal,
    MESSAGE_REFUSED_EVENT, MESSAGE_REPLAYED_EVENT,
};
use crate::metrics::{count_requests, serve_metrics, LimitKind, Metrics, MetricsState};
use crate::providers::CallbackReceivers;
use crate::store::PostgresStore;

tokio::task_local! {
    static REQUEST_TRACE: TraceContext;
}

/// What `/ready` asks before it answers.
#[derive(Clone, Debug)]
pub enum Readiness {
    /// The store answers, carries the expected schema, and its package
    /// ledger still names active the package this runtime serves. Once an
    /// operator applies another package, the runtime answers not ready
    /// until it is restarted onto it.
    Store {
        store: PostgresStore,
        package_digest: String,
    },
    /// A fixed answer, for tests of the HTTP surface without a database.
    #[cfg(test)]
    Fixed(bool),
}

impl Readiness {
    async fn is_ready(&self) -> bool {
        match self {
            Self::Store {
                store,
                package_digest,
            } => {
                let active = match store.ready().await {
                    Ok(()) => store.active_package_digest().await,
                    Err(error) => Err(error),
                };
                match active {
                    Ok(Some(active)) if active == *package_digest => true,
                    Ok(_) => {
                        tracing::warn!(
                            "the Messaging package ledger names another package active; \
                             restart the runtime to serve it"
                        );
                        false
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "the Messaging store is not ready");
                        false
                    }
                }
            }
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
    /// The package the ledger names active.
    pub package: Arc<Package>,
    /// The request rate of each of the package's access profiles.
    pub limits: Arc<CallerLimits>,
    pub audit: Arc<AuditJournal>,
    /// The message store, absent only in tests of the HTTP surface without
    /// a database, where every route that needs it answers unavailable.
    pub messages: Option<Arc<MessageService>>,
    /// The callback receiver of each activated provider that declares
    /// `receipts: callback`, by provider id.
    pub callbacks: Arc<CallbackReceivers>,
    /// The rate the callback routes admit, charged before a callback is
    /// verified.
    pub callback_limits: Arc<CallbackLimits>,
}

/// The audited event for every preview an authenticated caller asked for.
pub const TEMPLATE_PREVIEWED_EVENT: &str = "messaging.template.previewed";

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
    /// The success status.
    pub success_status: u16,
    /// Whether the operation requires the `Idempotency-Key` header.
    pub idempotency_key: bool,
    /// The request body the operation takes.
    pub request_body: RequestBody,
    /// The component schema of the JSON success body, or `None` for an
    /// empty body.
    pub response_body: Option<&'static str>,
    /// Every problem the operation can answer with.
    pub problems: &'static [ProblemCode],
}

/// The request body of one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBody {
    None,
    /// A JSON body described by this component schema.
    Json(&'static str),
    /// A provider's delivery callback: whatever JSON or form body the
    /// provider sends, read only by that provider's receipt script.
    ProviderCallback,
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
        idempotency_key: false,
        request_body: RequestBody::None,
        response_body: None,
        problems: &[ProblemCode::RequestMethodNotAllowed],
    },
    Operation {
        method: "get",
        path: READY_PATH,
        operation_id: "getReady",
        summary: "Report that the store answers with the expected schema.",
        authenticated: false,
        success_status: 200,
        idempotency_key: false,
        request_body: RequestBody::None,
        response_body: None,
        problems: &EDGE_PROBLEMS,
    },
    Operation {
        method: "post",
        path: MESSAGES_PATH,
        operation_id: "submitMessage",
        summary: "Submit one message through a sender profile the caller's access profile lists, \
                  rendered from a template version at acceptance or, where the profile allows \
                  it, from direct content. The `Idempotency-Key` header is required: the same \
                  key and request answer the stored receipt again.",
        authenticated: true,
        success_status: 202,
        idempotency_key: true,
        request_body: RequestBody::Json("SubmitMessageRequest"),
        response_body: Some("MessageReceipt"),
        problems: &[
            ProblemCode::RequestInvalid,
            ProblemCode::AuthenticationRefused,
            ProblemCode::OperationNotAuthorized,
            ProblemCode::ProfileNotAuthorized,
            ProblemCode::TemplateNotFound,
            ProblemCode::RequestMethodNotAllowed,
            ProblemCode::IdempotencyKeyReused,
            ProblemCode::IdempotencyExpired,
            ProblemCode::RequestBodyTooLarge,
            ProblemCode::RequestUnsupportedMediaType,
            ProblemCode::RequestUnprocessable,
            ProblemCode::ContentInvalid,
            ProblemCode::ContentTooLarge,
            ProblemCode::ContentTooManySegments,
            ProblemCode::TemplateDataInvalid,
            ProblemCode::TemplateLocaleUnavailable,
            ProblemCode::TemplateRenderRefused,
            ProblemCode::RateLimitExceeded,
            ProblemCode::QuotaExceeded,
            ProblemCode::ServiceUnavailable,
        ],
    },
    Operation {
        method: "get",
        path: MESSAGE_PATH,
        operation_id: "getMessage",
        summary: "Read the status of a message the caller submitted, or any message for an \
                  operator. A message the caller may not see answers exactly like one that does \
                  not exist. The recipient is masked, and no part or template data is returned.",
        authenticated: true,
        success_status: 200,
        idempotency_key: false,
        request_body: RequestBody::None,
        response_body: Some("MessageView"),
        problems: &[
            ProblemCode::AuthenticationRefused,
            ProblemCode::ProfileNotAuthorized,
            ProblemCode::MessageNotVisible,
            ProblemCode::RequestMethodNotAllowed,
            ProblemCode::ServiceUnavailable,
        ],
    },
    Operation {
        method: "post",
        path: MESSAGE_CANCEL_PATH,
        operation_id: "cancelMessage",
        summary: "Cancel a queued message, including one waiting for a retry, the caller \
                  submitted, or any queued message for an operator. A message whose dispatch \
                  started or that reached a final state is refused.",
        authenticated: true,
        success_status: 200,
        idempotency_key: false,
        request_body: RequestBody::None,
        response_body: Some("MessageView"),
        problems: &[
            ProblemCode::AuthenticationRefused,
            ProblemCode::ProfileNotAuthorized,
            ProblemCode::MessageNotVisible,
            ProblemCode::RequestMethodNotAllowed,
            ProblemCode::MessageDispatchStarted,
            ProblemCode::MessageTerminal,
            ProblemCode::ServiceUnavailable,
        ],
    },
    Operation {
        method: "post",
        path: TEMPLATE_PREVIEW_PATH,
        operation_id: "previewTemplate",
        summary: "Render a template version of the active package with the given locale and \
                  data, for a sender whose profile lists the template. Nothing is persisted; \
                  the body is byte-identical to `messagingctl preview --format json`.",
        authenticated: true,
        success_status: 200,
        idempotency_key: false,
        request_body: RequestBody::Json("TemplatePreviewRequest"),
        response_body: Some("TemplatePreview"),
        problems: &[
            ProblemCode::RequestInvalid,
            ProblemCode::AuthenticationRefused,
            ProblemCode::OperationNotAuthorized,
            ProblemCode::ProfileNotAuthorized,
            ProblemCode::TemplateNotFound,
            ProblemCode::RequestMethodNotAllowed,
            ProblemCode::RequestBodyTooLarge,
            ProblemCode::RequestUnsupportedMediaType,
            ProblemCode::RequestUnprocessable,
            ProblemCode::TemplateDataInvalid,
            ProblemCode::TemplateLocaleUnavailable,
            ProblemCode::TemplateRenderRefused,
            ProblemCode::ServiceUnavailable,
        ],
    },
    Operation {
        method: "post",
        path: PROVIDER_CALLBACK_PATH,
        operation_id: "receiveProviderCallback",
        summary: "Take one delivery callback from a provider whose runtime configuration names \
                  an `hmac-sha1-url-form` or `hmac-sha256-body` callback verifier. The verifier, \
                  not a bearer token, authenticates the request; the provider package's receipt \
                  script reads it. A verified callback answers 204 whether or not its reference \
                  names a message, and a receipt never moves a message's report backwards.",
        authenticated: false,
        success_status: 204,
        idempotency_key: false,
        request_body: RequestBody::ProviderCallback,
        response_body: None,
        problems: &CALLBACK_PROBLEMS,
    },
    Operation {
        method: "post",
        path: PROVIDER_CALLBACK_TOKEN_PATH,
        operation_id: "receiveProviderCallbackWithToken",
        summary: "Take one delivery callback from a provider whose runtime configuration names \
                  a `path-token` callback verifier, with the secret token as the last path \
                  segment. Otherwise as `receiveProviderCallback`.",
        authenticated: false,
        success_status: 204,
        idempotency_key: false,
        request_body: RequestBody::ProviderCallback,
        response_body: None,
        problems: &CALLBACK_PROBLEMS,
    },
];

/// Every problem a provider callback can answer with. An unknown provider,
/// a verifier refusal, and a token on the wrong route all answer
/// `callback.unverified`, so the route does not reveal which providers
/// receive callbacks.
const CALLBACK_PROBLEMS: [ProblemCode; 7] = [
    ProblemCode::RequestInvalid,
    ProblemCode::CallbackUnverified,
    ProblemCode::RequestMethodNotAllowed,
    ProblemCode::RequestBodyTooLarge,
    ProblemCode::CallbackUnreadable,
    ProblemCode::RateLimitExceeded,
    ProblemCode::ServiceUnavailable,
];

pub fn router(state: HttpState) -> Router {
    let metrics = Arc::clone(&state.metrics);
    http_edge(
        Router::new()
            .route(HEALTH_PATH, get(health))
            .route(READY_PATH, get(ready))
            .route(MESSAGES_PATH, post(submit_message))
            .route(MESSAGE_PATH, get(get_message))
            .route(MESSAGE_CANCEL_PATH, post(cancel_message))
            .route(TEMPLATE_PREVIEW_PATH, post(preview_template))
            .route(PROVIDER_CALLBACK_PATH, post(callbacks::receive))
            .route(
                PROVIDER_CALLBACK_TOKEN_PATH,
                post(callbacks::receive_with_token),
            )
            .with_state(state)
            .layer(middleware::from_fn_with_state(metrics, count_requests)),
    )
}

/// The operator-private router the metrics listener serves: the counters,
/// and the dispatch queue sampled from `store` when there is one.
pub fn metrics_router(metrics: Arc<Metrics>, store: Option<PostgresStore>) -> Router {
    http_edge(
        Router::new()
            .route(METRICS_PATH, get(serve_metrics))
            .with_state(MetricsState { metrics, store }),
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

async fn submit_message(
    State(state): State<HttpState>,
    request: Request,
) -> Result<Response, HttpError> {
    let caller = authenticate(&state, request.headers()).await?;
    let result = match admit_submission(&state, &caller, request.headers()).await {
        Ok(key) => {
            let body = read_request_body(request).await?;
            accept_submission(&state, &caller, &key, &body).await
        }
        Err(refusal) => Err(refusal),
    };
    let record = match &result {
        Ok(answer) if !answer.replayed => None,
        Ok(answer) => Some(SubmissionRecord::replayed(&state, &caller, answer)?),
        Err(refusal) => {
            count_limit_refusal(&state.metrics, refusal.problem);
            Some(SubmissionRecord::refused(&state, &caller, refusal.problem)?)
        }
    };
    if let Some(record) = record {
        if let Err(error) = state.audit.append(record).await {
            tracing::error!(error = %error, "the Messaging audit journal refused a submission record");
            return Err(HttpError(ProblemCode::ServiceUnavailable));
        }
    }
    let answer = match result {
        Ok(answer) => answer,
        Err(refusal) => return Ok(refusal_response(refusal)),
    };
    let status = StatusCode::from_u16(answer.status).map_err(|_| {
        tracing::error!("a stored Messaging receipt carries an invalid status");
        HttpError(ProblemCode::ServiceUnavailable)
    })?;
    Ok((status, Json(answer.receipt)).into_response())
}

/// Count a refusal by the request rate or the daily limit under the limit
/// that refused.
fn count_limit_refusal(metrics: &Metrics, problem: ProblemCode) {
    match problem {
        ProblemCode::RateLimitExceeded => metrics.record_limit_refusal(LimitKind::Rate),
        ProblemCode::QuotaExceeded => metrics.record_limit_refusal(LimitKind::Daily),
        _ => {}
    }
}

/// Admit a submission before its body is read: require the sender role,
/// charge the caller's request rate, then validate the body-independent
/// headers.
async fn admit_submission(
    state: &HttpState,
    caller: &Caller,
    headers: &HeaderMap,
) -> Result<String, SubmissionRefusal> {
    if caller.role() != AccessRole::Sender {
        return Err(ProblemCode::OperationNotAuthorized.into());
    }
    check_caller_rate(state, caller).await?;
    if !is_json(headers) {
        return Err(ProblemCode::RequestUnsupportedMediaType.into());
    }
    let key = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .filter(|key| valid_idempotency_key(key.as_bytes()))
        .and_then(|key| key.to_str().ok())
        .ok_or(ProblemCode::RequestInvalid)?;
    Ok(key.to_owned())
}

/// Read and accept a submission after its caller passed admission. The daily
/// limit is counted when the submission is recorded.
async fn accept_submission(
    state: &HttpState,
    caller: &Caller,
    key: &str,
    body: &[u8],
) -> Result<SubmissionAnswer, SubmissionRefusal> {
    let submission = prepare_submission(&state.package, caller, body)?;
    message_service(state)?
        .submit(caller, key, &submission)
        .await
}

/// Charge one submission to the caller's access profile, keyed by the
/// caller's audit pseudonym.
async fn check_caller_rate(state: &HttpState, caller: &Caller) -> Result<(), SubmissionRefusal> {
    let pseudonym = state
        .audit
        .principal_pseudonym(&caller.identity)
        .map_err(|error| {
            tracing::error!(error = %error, "a Messaging principal pseudonym failed");
            ProblemCode::ServiceUnavailable
        })?;
    match state.limits.check(&caller.profile.id, &pseudonym).await {
        Ok(()) => Ok(()),
        Err(LimitRefusal::Exceeded { retry_after }) => Err(SubmissionRefusal {
            problem: ProblemCode::RateLimitExceeded,
            retry_after: Some(retry_after),
        }),
        Err(LimitRefusal::Unavailable) => {
            tracing::error!("the Messaging request-rate limiter could not decide");
            Err(ProblemCode::ServiceUnavailable.into())
        }
    }
}

/// The journal record of a refused or replayed submission. It names the
/// caller's profile and pseudonym and the outcome only: the body is the
/// caller's text until the package accepts it, and an acceptance is
/// recorded through the outbox instead.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmissionRecord {
    event: &'static str,
    access_profile: String,
    principal_pseudonym: String,
    package_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<&'static str>,
}

impl SubmissionRecord {
    fn new(state: &HttpState, caller: &Caller, event: &'static str) -> Result<Self, HttpError> {
        let principal_pseudonym =
            state
                .audit
                .principal_pseudonym(&caller.identity)
                .map_err(|error| {
                    tracing::error!(error = %error, "a Messaging principal pseudonym failed");
                    HttpError(ProblemCode::ServiceUnavailable)
                })?;
        Ok(Self {
            event,
            access_profile: caller.profile.id.clone(),
            principal_pseudonym,
            package_digest: state.package.digest().to_owned(),
            message_id: None,
            problem: None,
        })
    }

    fn refused(
        state: &HttpState,
        caller: &Caller,
        problem: ProblemCode,
    ) -> Result<Self, HttpError> {
        let mut record = Self::new(state, caller, MESSAGE_REFUSED_EVENT)?;
        record.problem = Some(problem.code());
        Ok(record)
    }

    fn replayed(
        state: &HttpState,
        caller: &Caller,
        answer: &SubmissionAnswer,
    ) -> Result<Self, HttpError> {
        let mut record = Self::new(state, caller, MESSAGE_REPLAYED_EVENT)?;
        record.message_id = Some(answer.message_id.to_string());
        Ok(record)
    }
}

async fn get_message(
    State(state): State<HttpState>,
    Path(message_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MessageView>, HttpError> {
    let caller = authenticate(&state, &headers).await?;
    let service = visible_service(&state, &message_id)?;
    let message = service
        .visible_message(&caller, &message_id)
        .await
        .map_err(HttpError)?;
    Ok(Json(message.view))
}

async fn cancel_message(
    State(state): State<HttpState>,
    Path(message_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MessageView>, HttpError> {
    let caller = authenticate(&state, &headers).await?;
    let service = visible_service(&state, &message_id)?;
    let view = service
        .cancel(&caller, &message_id)
        .await
        .map_err(HttpError)?;
    Ok(Json(view))
}

/// The message service for a route naming `message_id`. An identifier no
/// message can carry is not visible before the store is consulted.
fn visible_service<'a>(
    state: &'a HttpState,
    message_id: &str,
) -> Result<&'a MessageService, HttpError> {
    if uuid::Uuid::parse_str(message_id).is_err() {
        return Err(HttpError(ProblemCode::MessageNotVisible));
    }
    message_service(state).map_err(HttpError)
}

fn message_service(state: &HttpState) -> Result<&MessageService, ProblemCode> {
    state
        .messages
        .as_deref()
        .ok_or(ProblemCode::ServiceUnavailable)
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

/// The bytes of a preview document, shared by the preview route and
/// `messagingctl preview --format json` so both answer the same bytes.
pub fn preview_json(preview: &TemplatePreview) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(preview)
}

async fn preview_template(
    State(state): State<HttpState>,
    Path((template_id, version)): Path<(String, String)>,
    request: Request,
) -> Result<Response, HttpError> {
    let caller = authenticate(&state, request.headers()).await?;
    let headers = request.headers().clone();
    let body = read_request_body(request).await?;
    let outcome = render_preview(
        &state.package,
        &caller,
        &template_id,
        &version,
        &headers,
        &body,
    );
    let record = PreviewRecord::new(&state, &caller, &template_id, &version, &outcome)?;
    if let Err(error) = state.audit.append(record).await {
        tracing::error!(error = %error, "the Messaging audit journal refused a preview record");
        return Err(HttpError(ProblemCode::ServiceUnavailable));
    }
    let preview = outcome.result.map_err(HttpError)?;
    let body = preview_json(&preview).map_err(|error| {
        tracing::error!(error = %error, "a Messaging preview could not be serialized");
        HttpError(ProblemCode::ServiceUnavailable)
    })?;
    Ok((StatusCode::OK, [(CONTENT_TYPE, "application/json")], body).into_response())
}

/// Buffer the request only after the route's authentication or rate admission
/// has succeeded. This uses the same Axum extraction as the former handler
/// arguments, including the edge's configured body limit and rejection shape.
pub(crate) async fn read_request_body(request: Request) -> Result<axum::body::Bytes, HttpError> {
    axum::body::Bytes::from_request(request, &())
        .await
        .map_err(|rejection| {
            let problem = match rejection.into_response().status() {
                StatusCode::PAYLOAD_TOO_LARGE => ProblemCode::RequestBodyTooLarge,
                _ => ProblemCode::RequestInvalid,
            };
            HttpError(problem)
        })
}

/// A preview's result, with the locale the request named once the body
/// was read.
struct PreviewOutcome {
    locale: Option<String>,
    result: Result<TemplatePreview, ProblemCode>,
}

fn render_preview(
    package: &Package,
    caller: &Caller,
    template_id: &str,
    version: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> PreviewOutcome {
    let request = match preview_request(headers, body) {
        Ok(request) => request,
        Err(problem) => {
            return PreviewOutcome {
                locale: None,
                result: Err(problem),
            }
        }
    };
    let result = package
        .preview_for(caller, template_id, version, &request)
        .map_err(|refusal: ContentRefusal| refusal.problem());
    PreviewOutcome {
        locale: Some(request.locale),
        result,
    }
}

/// Read a preview body: JSON by media type, then JSON by syntax, then the
/// request's closed shape.
fn preview_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<TemplatePreviewRequest, ProblemCode> {
    if !is_json(headers) {
        return Err(ProblemCode::RequestUnsupportedMediaType);
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| ProblemCode::RequestInvalid)?;
    serde_json::from_value(value).map_err(|_| ProblemCode::RequestUnprocessable)
}

/// The journal record of one preview. It names the template version and
/// locale only when the active package ships them, so a caller cannot write
/// arbitrary text into the journal through the path or the body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewRecord {
    event: &'static str,
    access_profile: String,
    principal_pseudonym: String,
    package_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<PreviewedTemplate>,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewedTemplate {
    id: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    locale: Option<String>,
}

impl PreviewRecord {
    fn new(
        state: &HttpState,
        caller: &Caller,
        template_id: &str,
        version: &str,
        outcome: &PreviewOutcome,
    ) -> Result<Self, HttpError> {
        let principal_pseudonym =
            state
                .audit
                .principal_pseudonym(&caller.identity)
                .map_err(|error| {
                    tracing::error!(error = %error, "a Messaging principal pseudonym failed");
                    HttpError(ProblemCode::ServiceUnavailable)
                })?;
        let template =
            state
                .package
                .template(template_id, version)
                .map(|shipped| PreviewedTemplate {
                    id: shipped.id().to_owned(),
                    version: shipped.version().to_owned(),
                    locale: outcome
                        .locale
                        .as_deref()
                        .and_then(|locale| shipped.locales().find(|shipped| *shipped == locale))
                        .map(str::to_owned),
                });
        let (outcome, problem) = match &outcome.result {
            Ok(_) => ("rendered", None),
            Err(problem) => ("refused", Some(problem.code())),
        };
        Ok(Self {
            event: TEMPLATE_PREVIEWED_EVENT,
            access_profile: caller.profile.id.clone(),
            principal_pseudonym,
            package_digest: state.package.digest().to_owned(),
            template,
            outcome,
            problem,
        })
    }
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

/// Render a refused submission: its problem, with `Retry-After` in whole
/// seconds, never below one, when a limit says how long to wait.
fn refusal_response(refusal: SubmissionRefusal) -> Response {
    let mut response = problem_response(refusal.problem);
    if let Some(retry_after) = refusal.retry_after {
        response
            .headers_mut()
            .insert(RETRY_AFTER, retry_after_seconds(retry_after).into());
    }
    response
}

/// Render a request refused by a rate limit, with the wait it needs.
pub(crate) fn rate_limited_response(retry_after: std::time::Duration) -> Response {
    refusal_response(SubmissionRefusal {
        problem: ProblemCode::RateLimitExceeded,
        retry_after: Some(retry_after),
    })
}

/// Whole seconds to wait, rounded up and never below one.
fn retry_after_seconds(wait: std::time::Duration) -> u64 {
    let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    seconds.max(1)
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
    use crate::audit::tests::{memory_journal, MemorySink};
    use crate::auth::tests::{
        authenticator, authenticator_over, operator_claims, sender_claims, token,
        token_signed_with, UNPROFILED_CLIENT,
    };
    use crate::limits::{CALLBACK_BURST, CALLBACK_REQUESTS_PER_MINUTE};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use registry_messaging_core::ProblemDocument;
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
    use serde_json::json;
    use tower::ServiceExt as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn starter_package() -> Package {
        crate::package::load_package(&crate::package::tests::starter_root())
            .unwrap()
            .package
    }

    fn state_with(authenticator: MessagingAuthenticator, ready: bool) -> HttpState {
        state_over(authenticator, ready, memory_journal().1)
    }

    fn state_over(
        authenticator: MessagingAuthenticator,
        ready: bool,
        audit: AuditJournal,
    ) -> HttpState {
        let package = starter_package();
        HttpState {
            authenticator: Arc::new(authenticator),
            readiness: Readiness::Fixed(ready),
            metrics: Arc::new(Metrics::default()),
            limits: Arc::new(unmetered_limits(&package)),
            package: Arc::new(package),
            audit: Arc::new(audit),
            messages: None,
            callbacks: Arc::default(),
            callback_limits: Arc::new(
                CallbackLimits::new(CALLBACK_REQUESTS_PER_MINUTE, CALLBACK_BURST).unwrap(),
            ),
        }
    }

    /// Limits no test of another behavior reaches: the starter's burst of
    /// ten would refuse a test that sends more.
    fn unmetered_limits(package: &Package) -> CallerLimits {
        let profiles = package
            .access_profiles()
            .iter()
            .cloned()
            .map(|profile| registry_messaging_core::AccessProfile {
                requests_per_minute: 60_000,
                burst: 10_000,
                ..profile
            })
            .collect();
        CallerLimits::new(&registry_messaging_core::AccessProfiles::new(profiles).unwrap()).unwrap()
    }

    /// A router over the starter package and an in-memory journal the test
    /// can read.
    fn preview_app() -> (Router, Arc<MemorySink>) {
        let (sink, journal) = memory_journal();
        (router(state_over(authenticator(), true, journal)), sink)
    }

    const PREVIEW: &str = "/v1/templates/appointment-reminder/versions/1/preview";

    fn sample_request() -> serde_json::Value {
        json!({
            "locale": "fr",
            "data": {"name": "Ada Lovelace", "day": "2026-10-01", "office": "Central Registry Office"}
        })
    }

    async fn post(
        app: Router,
        uri: &str,
        bearer: Option<&str>,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> Response {
        let mut request = Request::builder().method("POST").uri(uri);
        if let Some(bearer) = bearer {
            request = request.header(AUTHORIZATION, format!("Bearer {bearer}"));
        }
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        app.oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    async fn post_json(
        app: Router,
        uri: &str,
        bearer: Option<&str>,
        body: &serde_json::Value,
    ) -> Response {
        post(
            app,
            uri,
            bearer,
            Some("application/json"),
            serde_json::to_vec(body).unwrap(),
        )
        .await
    }

    /// A body whose first bytes beyond the edge limit expose any attempt to
    /// poll it. The request deliberately carries no `Content-Length`, so the
    /// edge layer cannot reject it from headers alone.
    fn body_poll_canary() -> Vec<u8> {
        vec![b'a'; registry_platform_httpsec::DEFAULT_REQUEST_BODY_LIMIT_BYTES + 1]
    }

    fn journal(sink: &MemorySink) -> Vec<serde_json::Value> {
        sink.records.lock().unwrap().clone()
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
        let metrics_app = metrics_router(metrics, None);
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

    #[tokio::test]
    async fn a_preview_answers_the_bytes_the_cli_prints_and_journals_metadata_only() {
        let (app, sink) = preview_app();
        let response = post_json(
            app,
            PREVIEW,
            Some(&token(sender_claims())),
            &sample_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();

        let request: TemplatePreviewRequest = serde_json::from_value(sample_request()).unwrap();
        let expected = starter_package()
            .preview("appointment-reminder", "1", &request)
            .unwrap();
        assert_eq!(body.as_ref(), preview_json(&expected).unwrap().as_slice());
        let answered: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(answered["channel"], "email");
        assert!(answered["parts"]["subject"]
            .as_str()
            .unwrap()
            .contains("01/10/2026"));
        assert!(answered["parts"]["html"]
            .as_str()
            .unwrap()
            .contains("Ada Lovelace"));

        let records = journal(&sink);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["event"], TEMPLATE_PREVIEWED_EVENT);
        assert_eq!(record["accessProfile"], "case-notices");
        assert_eq!(record["outcome"], "rendered");
        assert_eq!(
            record["template"],
            json!({"id": "appointment-reminder", "version": "1", "locale": "fr"})
        );
        assert!(record.get("problem").is_none());
        let written = record.to_string();
        for leaked in [
            "Ada Lovelace",
            "Central Registry Office",
            "2026-10-01",
            "subject-1",
            "case-system",
        ] {
            assert!(
                !written.contains(leaked),
                "{leaked} reached the journal: {written}"
            );
        }
    }

    #[tokio::test]
    async fn a_preview_requires_a_credential_and_journals_nothing_without_one() {
        let (app, sink) = preview_app();
        let headers = expect_problem(
            post_json(app.clone(), PREVIEW, None, &sample_request()).await,
            ProblemCode::AuthenticationRefused,
        )
        .await;
        assert_eq!(headers.get(WWW_AUTHENTICATE).unwrap(), "Bearer");
        expect_problem(
            post(
                app.clone(),
                PREVIEW,
                None,
                Some("application/json"),
                body_poll_canary(),
            )
            .await,
            ProblemCode::AuthenticationRefused,
        )
        .await;
        let forged = token_signed_with(sender_claims(), b"another-secret-another-secret-another!");
        expect_problem(
            post_json(app.clone(), PREVIEW, Some(&forged), &sample_request()).await,
            ProblemCode::AuthenticationRefused,
        )
        .await;
        let mut unprofiled = sender_claims();
        unprofiled["azp"] = json!(UNPROFILED_CLIENT);
        expect_problem(
            post_json(app, PREVIEW, Some(&token(unprofiled)), &sample_request()).await,
            ProblemCode::ProfileNotAuthorized,
        )
        .await;
        assert!(journal(&sink).is_empty());
    }

    #[tokio::test]
    async fn a_preview_outside_the_callers_profile_is_refused_and_journaled() {
        let (app, sink) = preview_app();
        // An operator resolves to a profile but does not send.
        expect_problem(
            post_json(
                app.clone(),
                PREVIEW,
                Some(&token(operator_claims())),
                &sample_request(),
            )
            .await,
            ProblemCode::OperationNotAuthorized,
        )
        .await;
        // The package ships this template, but the sender's profile does not
        // list it.
        expect_problem(
            post_json(
                app.clone(),
                "/v1/templates/appointment-reminder-sms/versions/1/preview",
                Some(&token(sender_claims())),
                &json!({"locale": "en", "data": {}}),
            )
            .await,
            ProblemCode::ProfileNotAuthorized,
        )
        .await;
        // A template the package does not ship is refused on the profile
        // before its existence is consulted.
        expect_problem(
            post_json(
                app,
                "/v1/templates/unshipped/versions/1/preview",
                Some(&token(sender_claims())),
                &sample_request(),
            )
            .await,
            ProblemCode::ProfileNotAuthorized,
        )
        .await;
        let records = journal(&sink);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["accessProfile"], "operations");
        assert_eq!(records[0]["problem"], "operation.not-authorized");
        assert_eq!(
            records[1]["template"],
            json!({"id": "appointment-reminder-sms", "version": "1", "locale": "en"})
        );
        assert_eq!(records[1]["problem"], "profile.not-authorized");
        assert!(records[2].get("template").is_none(), "{}", records[2]);
    }

    #[tokio::test]
    async fn a_preview_refuses_each_malformed_request_with_its_problem() {
        let (app, sink) = preview_app();
        let sender = token(sender_claims());
        let cases: Vec<(&str, Option<&str>, Vec<u8>, ProblemCode)> = vec![
            (
                PREVIEW,
                None,
                b"{}".to_vec(),
                ProblemCode::RequestUnsupportedMediaType,
            ),
            (
                PREVIEW,
                Some("text/plain"),
                b"{}".to_vec(),
                ProblemCode::RequestUnsupportedMediaType,
            ),
            (
                PREVIEW,
                Some("application/json"),
                b"{".to_vec(),
                ProblemCode::RequestInvalid,
            ),
            (
                PREVIEW,
                Some("application/json"),
                br#"{"locale": "en"}"#.to_vec(),
                ProblemCode::RequestUnprocessable,
            ),
            (
                PREVIEW,
                Some("application/json"),
                b"[]".to_vec(),
                ProblemCode::RequestUnprocessable,
            ),
            (
                PREVIEW,
                Some("application/json; charset=utf-8"),
                br#"{"locale": "en", "data": {}, "extra": 1}"#.to_vec(),
                ProblemCode::RequestUnprocessable,
            ),
            (
                "/v1/templates/appointment-reminder/versions/2/preview",
                Some("application/json"),
                serde_json::to_vec(&sample_request()).unwrap(),
                ProblemCode::TemplateNotFound,
            ),
            (
                PREVIEW,
                Some("application/json"),
                br#"{"locale": "de", "data": {"name": "A", "day": "2026-10-01", "office": "B"}}"#
                    .to_vec(),
                ProblemCode::TemplateLocaleUnavailable,
            ),
            (
                PREVIEW,
                Some("application/json"),
                br#"{"locale": "en", "data": {"name": "A"}}"#.to_vec(),
                ProblemCode::TemplateDataInvalid,
            ),
        ];
        for (uri, content_type, body, expected) in cases {
            expect_problem(
                post(app.clone(), uri, Some(&sender), content_type, body).await,
                expected,
            )
            .await;
        }
        let records = journal(&sink);
        assert_eq!(records.len(), 9);
        // The undeclared locale is not written; the declared template is.
        assert_eq!(
            records[7]["template"],
            json!({"id": "appointment-reminder", "version": "1"})
        );
        assert_eq!(records[7]["problem"], "template.locale-unavailable");
        assert!(records[6].get("template").is_none());
        for record in &records {
            assert_eq!(record["outcome"], "refused");
        }
    }

    #[tokio::test]
    async fn a_preview_the_journal_cannot_record_is_not_answered() {
        let (app, sink) = preview_app();
        sink.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
        let headers = expect_problem(
            post_json(
                app,
                PREVIEW,
                Some(&token(sender_claims())),
                &sample_request(),
            )
            .await,
            ProblemCode::ServiceUnavailable,
        )
        .await;
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "5");
    }

    fn submission() -> serde_json::Value {
        json!({
            "senderProfile": "transactional",
            "to": {"email": "ada@example.org"},
            "template": {"id": "appointment-reminder", "version": "1"},
            "locale": "en",
            "data": {"name": "Ada Lovelace", "day": "2026-10-01", "office": "Central Registry Office"},
            "correlationId": "case-42"
        })
    }

    async fn submit(
        app: Router,
        bearer: &str,
        key: Option<&str>,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> Response {
        let mut request = Request::builder()
            .method("POST")
            .uri(MESSAGES_PATH)
            .header(AUTHORIZATION, format!("Bearer {bearer}"));
        if let Some(key) = key {
            request = request.header(IDEMPOTENCY_KEY_HEADER, key);
        }
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        app.oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    async fn submit_json(app: Router, bearer: &str, body: &serde_json::Value) -> Response {
        submit(
            app,
            bearer,
            Some("key-1"),
            Some("application/json"),
            serde_json::to_vec(body).unwrap(),
        )
        .await
    }

    /// No refusal record may carry what the caller wrote in the body.
    fn assert_no_submission_values(records: &[serde_json::Value]) {
        let written = serde_json::to_string(records).unwrap();
        for leaked in [
            "ada@example.org",
            "Ada Lovelace",
            "Central Registry Office",
            "case-42",
            "case-system-principal",
            "operator-1",
        ] {
            assert!(
                !written.contains(leaked),
                "{leaked} reached the journal: {written}"
            );
        }
    }

    #[tokio::test]
    async fn a_submission_authentication_refusal_does_not_poll_the_body() {
        let (app, sink) = preview_app();
        let request = Request::builder()
            .method("POST")
            .uri(MESSAGES_PATH)
            .header(IDEMPOTENCY_KEY_HEADER, "key-1")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body_poll_canary()))
            .unwrap();
        let headers = expect_problem(
            app.oneshot(request).await.unwrap(),
            ProblemCode::AuthenticationRefused,
        )
        .await;
        assert_eq!(headers.get(WWW_AUTHENTICATE).unwrap(), "Bearer");
        assert!(journal(&sink).is_empty());
    }

    #[tokio::test]
    async fn a_caller_past_its_profile_rate_is_refused_with_the_wait_needed() {
        let (sink, journal_handle) = memory_journal();
        let mut state = state_over(authenticator(), true, journal_handle);
        state.limits = Arc::new(CallerLimits::new(state.package.access_profiles()).unwrap());
        let metrics = Arc::clone(&state.metrics);
        let app = router(state);
        let sender = token(sender_claims());
        // The starter's `case-notices` profile admits a burst of ten; the
        // runtime here has no message store, so each admitted submission
        // is answered as unavailable after its rate was charged.
        for _ in 0..10 {
            expect_problem(
                submit_json(app.clone(), &sender, &submission()).await,
                ProblemCode::ServiceUnavailable,
            )
            .await;
        }
        // The rate refusal is decided without polling this over-limit body.
        // Before delayed collection, Axum extracted it first and answered 413.
        let headers = expect_problem(
            submit(
                app.clone(),
                &sender,
                Some("key-1"),
                Some("application/json"),
                body_poll_canary(),
            )
            .await,
            ProblemCode::RateLimitExceeded,
        )
        .await;
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "1");
        // The operator's own profile has its own budget, and the role
        // refusal comes before the rate is charged.
        expect_problem(
            submit_json(app, &token(operator_claims()), &submission()).await,
            ProblemCode::OperationNotAuthorized,
        )
        .await;
        let records = journal(&sink);
        let refused = records
            .iter()
            .find(|record| record["problem"] == "rate-limit.exceeded")
            .expect("the rate refusal is journaled");
        assert_eq!(refused["event"], MESSAGE_REFUSED_EVENT);
        assert_eq!(refused["accessProfile"], "case-notices");
        assert_no_submission_values(&records);
        let text = metrics.render(None);
        assert!(
            text.contains("messaging_limit_refusals_total{limit=\"rate\"} 1\n"),
            "{text}"
        );
        assert!(text.contains("messaging_limit_refusals_total{limit=\"daily\"} 0\n"));
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        use std::time::Duration;
        assert_eq!(retry_after_seconds(Duration::ZERO), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_seconds(Duration::from_secs(1)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(1_001)), 2);
        assert_eq!(retry_after_seconds(Duration::from_secs(3_600)), 3_600);
    }

    #[tokio::test]
    async fn only_the_sender_role_submits_and_only_through_what_its_profile_lists() {
        let (app, sink) = preview_app();
        let sender = token(sender_claims());
        expect_problem(
            submit_json(app.clone(), &token(operator_claims()), &submission()).await,
            ProblemCode::OperationNotAuthorized,
        )
        .await;
        let mut unlisted_profile = submission();
        unlisted_profile["senderProfile"] = json!("another-program");
        let mut unlisted_template = submission();
        unlisted_template["template"] = json!({"id": "unshipped", "version": "1"});
        let direct = json!({
            "senderProfile": "transactional",
            "to": {"email": "ada@example.org"},
            "content": {"subject": "Hello", "text": "Ada Lovelace"}
        });
        for body in [unlisted_profile, unlisted_template, direct] {
            expect_problem(
                submit_json(app.clone(), &sender, &body).await,
                ProblemCode::ProfileNotAuthorized,
            )
            .await;
        }
        let records = journal(&sink);
        assert_eq!(records.len(), 4);
        assert_eq!(records[0]["event"], MESSAGE_REFUSED_EVENT);
        assert_eq!(records[0]["accessProfile"], "operations");
        assert_eq!(records[0]["problem"], "operation.not-authorized");
        for record in &records[1..] {
            assert_eq!(record["accessProfile"], "case-notices");
            assert_eq!(record["problem"], "profile.not-authorized");
        }
        assert_no_submission_values(&records);
    }

    /// The idempotency key, the media type, the body, and the expected
    /// refusal of one malformed submission.
    type SubmissionCase<'a> = (Option<&'a str>, Option<&'a str>, Vec<u8>, ProblemCode);

    #[tokio::test]
    async fn a_submission_body_is_closed_and_needs_an_idempotency_key() {
        let (app, sink) = preview_app();
        let sender = token(sender_claims());
        let body = serde_json::to_vec(&submission()).unwrap();
        let mut provider_chosen = submission();
        provider_chosen["provider"] = json!("https://attacker.example");
        let mut credential_chosen = submission();
        credential_chosen["to"]["passwordRef"] = json!("secret:env/SMTP");
        let mut wrong_channel = submission();
        wrong_channel["to"] = json!({"phone": "+15551234567"});
        let mut bad_instant = submission();
        bad_instant["expiresAt"] = json!("tomorrow");
        let long_key = "k".repeat(129);
        let cases: Vec<SubmissionCase<'_>> = vec![
            (
                None,
                Some("application/json"),
                body.clone(),
                ProblemCode::RequestInvalid,
            ),
            (
                Some(""),
                Some("application/json"),
                body.clone(),
                ProblemCode::RequestInvalid,
            ),
            (
                Some("has space"),
                Some("application/json"),
                body.clone(),
                ProblemCode::RequestInvalid,
            ),
            (
                Some(&long_key),
                Some("application/json"),
                body.clone(),
                ProblemCode::RequestInvalid,
            ),
            (
                Some("key-1"),
                Some("text/plain"),
                body,
                ProblemCode::RequestUnsupportedMediaType,
            ),
            (
                Some("key-1"),
                None,
                b"{}".to_vec(),
                ProblemCode::RequestUnsupportedMediaType,
            ),
            (
                Some("key-1"),
                Some("application/json"),
                b"{".to_vec(),
                ProblemCode::RequestInvalid,
            ),
            (
                Some("key-1"),
                Some("application/json"),
                br#"{"a": 1, "a": 2}"#.to_vec(),
                ProblemCode::RequestInvalid,
            ),
            (
                Some("key-1"),
                Some("application/json"),
                b"[]".to_vec(),
                ProblemCode::RequestUnprocessable,
            ),
            (
                Some("key-1"),
                Some("application/json"),
                serde_json::to_vec(&provider_chosen).unwrap(),
                ProblemCode::RequestUnprocessable,
            ),
            (
                Some("key-1"),
                Some("application/json"),
                serde_json::to_vec(&credential_chosen).unwrap(),
                ProblemCode::RequestUnprocessable,
            ),
            (
                Some("key-1"),
                Some("application/json"),
                serde_json::to_vec(&wrong_channel).unwrap(),
                ProblemCode::RequestUnprocessable,
            ),
            (
                Some("key-1"),
                Some("application/json"),
                serde_json::to_vec(&bad_instant).unwrap(),
                ProblemCode::RequestUnprocessable,
            ),
        ];
        let count = cases.len();
        for (key, content_type, body, expected) in cases {
            expect_problem(
                submit(app.clone(), &sender, key, content_type, body).await,
                expected,
            )
            .await;
        }
        let records = journal(&sink);
        assert_eq!(records.len(), count);
        assert_no_submission_values(&records);
    }

    #[tokio::test]
    async fn a_submission_that_passes_every_check_needs_the_store() {
        let (app, sink) = preview_app();
        let headers = expect_problem(
            submit_json(app, &token(sender_claims()), &submission()).await,
            ProblemCode::ServiceUnavailable,
        )
        .await;
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "5");
        let records = journal(&sink);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["problem"], "service.unavailable");
        assert_no_submission_values(&records);
    }

    #[tokio::test]
    async fn a_submission_the_journal_cannot_record_is_not_answered() {
        let (app, sink) = preview_app();
        sink.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
        expect_problem(
            submit_json(app, &token(operator_claims()), &submission()).await,
            ProblemCode::ServiceUnavailable,
        )
        .await;
    }

    #[tokio::test]
    async fn a_message_route_reaches_the_store_only_for_an_identifier_a_message_can_carry() {
        let (app, _) = app();
        let sender = token(sender_claims());
        for (method, uri) in [
            ("GET", "/v1/messages/m-1"),
            ("POST", "/v1/messages/m-1/cancel"),
        ] {
            expect_problem(
                call(app.clone(), method, uri, Some(&sender)).await,
                ProblemCode::MessageNotVisible,
            )
            .await;
        }
        let id = uuid::Uuid::new_v4();
        for (method, uri) in [
            ("GET", format!("/v1/messages/{id}")),
            ("POST", format!("/v1/messages/{id}/cancel")),
        ] {
            expect_problem(
                call(app.clone(), method, &uri, Some(&sender)).await,
                ProblemCode::ServiceUnavailable,
            )
            .await;
        }
        expect_problem(
            call(app, "POST", "/v1/messages/m-1/cancel", None).await,
            ProblemCode::AuthenticationRefused,
        )
        .await;
    }

    const CALLBACK_TOKEN: &[u8] = b"callback-token-4f1b90";
    const CALLBACK_SECRET: &[u8] = b"callback-secret-8a3c55";

    /// A router whose `sms-gateway` receives callbacks through `verifier`,
    /// with no message store.
    fn callback_app(verifier: serde_json::Value) -> (Router, Arc<Metrics>) {
        let state = callback_state(verifier);
        let metrics = Arc::clone(&state.metrics);
        (router(state), metrics)
    }

    fn callback_state(verifier: serde_json::Value) -> HttpState {
        let mut state = state_with(authenticator(), true);
        state.callbacks = Arc::new(crate::providers::tests::callback_receivers(
            verifier,
            &[
                ("callback-token", CALLBACK_TOKEN),
                ("callback-secret", CALLBACK_SECRET),
            ],
        ));
        state
    }

    fn path_token_verifier() -> serde_json::Value {
        json!({"kind": "path-token", "tokenRef": "secret:file/callback-token"})
    }

    fn body_verifier() -> serde_json::Value {
        json!({
            "kind": "hmac-sha256-body",
            "header": "x-gateway-signature",
            "encoding": "hex",
            "secretRef": "secret:file/callback-secret"
        })
    }

    fn callbacks_counted(metrics: &Metrics, outcome: &str, count: u64) {
        let text = metrics.render(None);
        assert!(
            text.contains(&format!(
                "messaging_provider_callbacks_total{{outcome=\"{outcome}\"}} {count}\n"
            )),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_callback_for_a_provider_that_receives_none_is_unverified() {
        let (app, metrics) = callback_app(path_token_verifier());
        for uri in [
            "/v1/provider-callbacks/mail-relay",
            "/v1/provider-callbacks/no-such-provider",
            "/v1/provider-callbacks/no-such-provider/callback-token-4f1b90",
        ] {
            let headers = expect_problem(
                post(
                    app.clone(),
                    uri,
                    None,
                    Some("application/json"),
                    b"{}".to_vec(),
                )
                .await,
                ProblemCode::CallbackUnverified,
            )
            .await;
            assert!(headers.get(WWW_AUTHENTICATE).is_none());
        }
        callbacks_counted(&metrics, "unverified", 3);
    }

    #[tokio::test]
    async fn a_path_token_callback_verifies_only_on_the_token_route_with_its_token() {
        let (app, metrics) = callback_app(path_token_verifier());
        for uri in [
            "/v1/provider-callbacks/sms-gateway",
            "/v1/provider-callbacks/sms-gateway/callback-token-000000",
            "/v1/provider-callbacks/sms-gateway/callback-token-4f1b9",
        ] {
            expect_problem(
                post(
                    app.clone(),
                    uri,
                    None,
                    Some("application/json"),
                    b"{}".to_vec(),
                )
                .await,
                ProblemCode::CallbackUnverified,
            )
            .await;
        }
        callbacks_counted(&metrics, "unverified", 3);
        // The token verifies; with no store the callback cannot be recorded,
        // so the provider is told to retry.
        expect_problem(
            post(
                app,
                "/v1/provider-callbacks/sms-gateway/callback-token-4f1b90",
                None,
                Some("application/json"),
                b"{}".to_vec(),
            )
            .await,
            ProblemCode::ServiceUnavailable,
        )
        .await;
        callbacks_counted(&metrics, "unavailable", 1);
        let text = metrics.render(None);
        assert!(!text.contains("callback-token-4f1b90"), "{text}");
        assert!(text.contains("route=\"/v1/provider-callbacks/{provider_id}/{token}\""));
    }

    #[tokio::test]
    async fn a_body_signed_callback_refuses_a_token_route_and_a_forged_signature() {
        let (app, metrics) = callback_app(body_verifier());
        expect_problem(
            post(
                app.clone(),
                "/v1/provider-callbacks/sms-gateway/anything",
                None,
                Some("application/json"),
                b"{}".to_vec(),
            )
            .await,
            ProblemCode::CallbackUnverified,
        )
        .await;
        let body = br#"{"id":"gw-1","status":"delivered"}"#.to_vec();
        let forged = Request::builder()
            .method("POST")
            .uri("/v1/provider-callbacks/sms-gateway")
            .header(CONTENT_TYPE, "application/json")
            .header("x-gateway-signature", "00".repeat(32))
            .body(Body::from(body))
            .unwrap();
        expect_problem(
            app.oneshot(forged).await.unwrap(),
            ProblemCode::CallbackUnverified,
        )
        .await;
        callbacks_counted(&metrics, "unverified", 2);
    }

    #[tokio::test]
    async fn callbacks_past_the_rate_are_refused_before_they_are_verified() {
        let mut state = callback_state(path_token_verifier());
        state.callback_limits = Arc::new(CallbackLimits::new(60, 2).unwrap());
        let metrics = Arc::clone(&state.metrics);
        let app = router(state);
        for _ in 0..2 {
            expect_problem(
                post(
                    app.clone(),
                    "/v1/provider-callbacks/sms-gateway/callback-token-000000",
                    None,
                    Some("application/json"),
                    b"{}".to_vec(),
                )
                .await,
                ProblemCode::CallbackUnverified,
            )
            .await;
        }
        // The provider's budget is spent, so even its own token is refused
        // before it is checked, and the provider is told how long to wait.
        // The rate refusal is decided without polling this over-limit body.
        // Before delayed collection, Axum extracted it first and answered 413.
        let headers = expect_problem(
            post(
                app.clone(),
                "/v1/provider-callbacks/sms-gateway/callback-token-4f1b90",
                None,
                Some("application/json"),
                body_poll_canary(),
            )
            .await,
            ProblemCode::RateLimitExceeded,
        )
        .await;
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "1");
        callbacks_counted(&metrics, "unverified", 2);
        callbacks_counted(&metrics, "unavailable", 0);

        // Paths naming no receiving provider share one budget of their own
        // and are refused alike, so the refusal names no provider either.
        for uri in [
            "/v1/provider-callbacks/no-such-provider",
            "/v1/provider-callbacks/another-one/callback-token-4f1b90",
        ] {
            expect_problem(
                post(
                    app.clone(),
                    uri,
                    None,
                    Some("application/json"),
                    b"{}".to_vec(),
                )
                .await,
                ProblemCode::CallbackUnverified,
            )
            .await;
        }
        let headers = expect_problem(
            post(
                app,
                "/v1/provider-callbacks/mail-relay",
                None,
                Some("application/json"),
                b"{}".to_vec(),
            )
            .await,
            ProblemCode::RateLimitExceeded,
        )
        .await;
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "1");
        callbacks_counted(&metrics, "unverified", 4);
        let text = metrics.render(None);
        assert!(
            text.contains("messaging_limit_refusals_total{limit=\"callback\"} 2\n"),
            "{text}"
        );
        assert!(text.contains("messaging_limit_refusals_total{limit=\"rate\"} 0\n"));
    }

    #[tokio::test]
    async fn a_callback_body_over_the_edge_limit_is_refused() {
        let (app, _) = callback_app(path_token_verifier());
        expect_problem(
            post(
                app,
                "/v1/provider-callbacks/sms-gateway/callback-token-4f1b90",
                None,
                Some("application/json"),
                body_poll_canary(),
            )
            .await,
            ProblemCode::RequestBodyTooLarge,
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
