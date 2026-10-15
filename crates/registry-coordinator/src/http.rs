// SPDX-License-Identifier: Apache-2.0
//! Authenticated, bounded Coordinator service surface.
use crate::{
    access::{Action, Authenticator, Caller},
    deployment::{self, Workflows},
    metrics::AuthenticationRefusal,
    problem::{for_error, type_uri, ProblemCode},
    protocol::AdapterSet,
    runtime::RuntimeConfig,
    store::{RunListState, RunStatus, Store},
    CoordinatorError, Result,
};
use axum::{
    body::Bytes,
    extract::{
        rejection::{BytesRejection, JsonRejection, PathRejection, QueryRejection},
        DefaultBodyLimit, FromRequest, Path, Query, State,
    },
    http::{
        header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use registry_platform_httpsec::{ProblemBody, TraceContext};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};
use uuid::Uuid;

mod admission_contracts;

tokio::task_local! {
    static REQUEST_TRACE: TraceContext;
}

const BINDING_RECHECK_INTERVAL: Duration = Duration::from_secs(30);

// Only the deployment-wide live-binding scan is cached. Mutable activation,
// custody, audit and recovery gates remain fresh on every readiness request.
#[derive(Default)]
struct BindingReadiness(Mutex<Option<(Instant, bool)>>);

impl BindingReadiness {
    async fn check<F: Future<Output = Result<()>>>(&self, check: impl FnOnce() -> F) -> bool {
        // Coalesce concurrent probes into one inspection, including failures.
        let mut checked = self.0.lock().await;
        if let Some((until, ready)) = checked.as_ref() {
            if Instant::now() < *until {
                return *ready;
            }
        }
        let ready = check().await.is_ok();
        *checked = Some((Instant::now() + BINDING_RECHECK_INTERVAL, ready));
        ready
    }
}
#[derive(Clone)]
pub struct HttpState {
    pub store: Arc<Store>,
    pub recovery_only: bool,
    pub runtime: Arc<RuntimeConfig>,
    pub workflows: Arc<Workflows>,
    pub authenticator: Arc<Authenticator>,
    pub adapters: Arc<dyn AdapterSet>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Start {
    workflow: String,
    workflow_revision: String,
    input: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reason {
    reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    #[serde(default = "limit")]
    limit: u32,
    cursor: Option<String>,
    state: Option<RunListState>,
    attention: Option<bool>,
}
fn limit() -> u32 {
    20
}
pub fn router(state: HttpState) -> Router {
    let ready_state = state.clone();
    let ready_bindings = Arc::new(BindingReadiness::default());
    let routes = Router::new()
        .route("/health", get(|| async { Json(json!({"live":true})) }))
        .route(
            "/ready",
            get(move || ready(ready_state.clone(), ready_bindings.clone())),
        )
        .route("/v1/workflows/{workflow}", get(workflow_contract))
        .route("/v1/runs", post(start).get(list))
        .route("/v1/runs/{run}", get(status))
        .route("/v1/runs/{run}/inspect", get(inspect))
        .route("/v1/runs/{run}/retry-same", post(retry))
        .route("/v1/runs/{run}/cancel", post(cancel))
        .route("/v1/runs/{run}/reconcile", post(reconcile))
        .route("/v1/doctor", get(doctor))
        .route("/v1/restore-hold", post(hold))
        .route("/v1/release-restore-hold", post(release))
        .route("/v1/release-admission-hold", post(release_admission))
        .route("/v1/complete-execution-recovery", post(complete_execution))
        .route("/v1/retention", post(retain))
        .route(
            "/v1/events/{workflow}/{trigger}",
            post(crate::event_trigger::receive),
        )
        .route(
            registry_review_protocol::REVIEW_COMPLETIONS_PATH,
            post(review_completion),
        )
        .with_state(state);
    http_edge(routes)
}
fn http_edge(router: Router) -> Router {
    router
        .fallback(route_not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(131_072))
        .layer(registry_platform_httpsec::request_body_limit(131_072))
        .layer(middleware::from_fn(http_boundary))
        .layer(registry_platform_httpsec::security_headers(
            registry_platform_httpsec::CspBuilder::deny_by_default(),
        ))
}
async fn http_boundary(request: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let trace = TraceContext::from_headers(request.headers());
    let mut response = REQUEST_TRACE
        .scope(trace.clone(), async move {
            normalize_framework_rejection(next.run(request).await)
        })
        .await;
    trace.apply(response.headers_mut());
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
/// Framework rejections carry axum's own bodies, which no Coordinator caller
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
/// Answer an internal refusal as the public problem it maps to. A server-side
/// problem is logged by its internal code, a fixed category that carries no
/// request value, and by the trace its response carries; an internal code with
/// no problem is a defect and answers `runtime.failure`.
pub(crate) fn problem(error: CoordinatorError) -> Response {
    let trace = current_trace();
    let problem = for_error(&error.code).unwrap_or_else(|| {
        tracing::error!(
            code = %error.code,
            trace_id = %trace.trace_id,
            "an HTTP refusal has no problem code; answering runtime.failure"
        );
        ProblemCode::RuntimeFailure
    });
    if problem.http_status() >= 500 {
        tracing::warn!(
            code = %error.code,
            problem = problem.code(),
            trace_id = %trace.trace_id,
            "the service answered a server problem"
        );
    }
    problem_response(problem)
}
pub(crate) fn current_trace() -> TraceContext {
    REQUEST_TRACE
        .try_with(Clone::clone)
        .unwrap_or_else(|_| TraceContext::server_created())
}

#[cfg(test)]
mod problem_log_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_logged_server_problem_names_the_trace_its_response_carries() {
        for internal in ["store-unavailable", "no-such-internal-code"] {
            let captured = Captured::default();
            let writer = captured.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .finish();
            let trace = TraceContext::server_created();
            let response = tracing::subscriber::with_default(subscriber, || {
                REQUEST_TRACE.sync_scope(trace.clone(), || {
                    problem(CoordinatorError::new(internal, "synthetic"))
                })
            });
            assert!(response.status().is_server_error(), "{internal}");
            let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
            assert!(
                logged.contains(&format!("trace_id={}", trace.trace_id)),
                "{internal}: {logged}"
            );
        }
    }
}
/// Render one problem: the pinned code, title, status and detail from the
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
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("5"));
    }
    response
}
/// The verified caller, counting every refusal by its closed reason.
pub(crate) async fn caller(s: &HttpState, headers: &HeaderMap) -> Result<Caller> {
    let result = authenticated_caller(s, headers).await;
    if let Err(error) = &result {
        s.store
            .metrics()
            .record_authentication_refusal(AuthenticationRefusal::from_code(&error.code));
    }
    result
}
async fn authenticated_caller(s: &HttpState, headers: &HeaderMap) -> Result<Caller> {
    let token = single_header(headers, axum::http::header::AUTHORIZATION.as_str())
        .and_then(|value| registry_platform_authcommon::parse_bearer_token(value).ok())
        .ok_or_else(|| {
            CoordinatorError::new(
                "access.unauthenticated",
                "a verified access token is required",
            )
        })?;
    s.authenticator.authenticate(token).await
}
async fn ready(s: HttpState, bindings: Arc<BindingReadiness>) -> Response {
    if !s.recovery_only
        && deployment::check(&s.store, &s.runtime, s.workflows.digest())
            .await
            .is_ok()
        && s.store.is_ready().await.unwrap_or(false)
        && bindings
            .check(|| s.store.check_runtime_bindings(&s.runtime))
            .await
    {
        (StatusCode::OK, Json(json!({"ready":true}))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ready":false})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[tokio::test(start_paused = true)]
    async fn live_binding_readiness_refreshes_success_and_failure_at_the_fixed_deadline() {
        let cache = BindingReadiness::default();
        let calls = AtomicUsize::new(0);
        assert!(
            cache
                .check(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(()))
                })
                .await
        );
        tokio::time::advance(BINDING_RECHECK_INTERVAL - Duration::from_millis(1)).await;
        assert!(
            cache
                .check(|| async { panic!("successful inspection still valid") })
                .await
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(
            !cache
                .check(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Err(CoordinatorError::new(
                        "live-binding-conflict",
                        "test refusal",
                    )))
                })
                .await
        );
        assert!(
            !cache
                .check(|| async { panic!("failed inspection still cached") })
                .await
        );
        tokio::time::advance(BINDING_RECHECK_INTERVAL).await;
        assert!(
            cache
                .check(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(()))
                })
                .await
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn concurrent_readiness_probes_share_one_live_binding_inspection() {
        let cache = Arc::new(BindingReadiness::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let first = tokio::spawn({
            let (cache, calls, started, release) = (
                cache.clone(),
                calls.clone(),
                started.clone(),
                release.clone(),
            );
            async move {
                cache
                    .check(|| async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        release.notified().await;
                        Ok(())
                    })
                    .await
            }
        });
        started.notified().await;
        let mut others = tokio::task::JoinSet::new();
        for _ in 0..7 {
            let (cache, calls) = (cache.clone(), calls.clone());
            others.spawn(async move {
                cache
                    .check(|| async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
            });
        }
        release.notify_one();
        assert!(first.await.unwrap());
        while let Some(result) = others.join_next().await {
            assert!(result.unwrap());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod problem_tests {
    use super::*;

    #[test]
    fn admission_keys_require_one_bounded_printable_header_value() {
        for key in [
            "stable-key".to_owned(),
            "key with spaces,1".to_owned(),
            "k".repeat(256),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("idempotency-key", HeaderValue::from_str(&key).unwrap());
            assert_eq!(idempotency_key(&headers).unwrap(), key);
        }
        let long = "k".repeat(257);
        for keys in [
            vec![],
            vec![""],
            vec![long.as_str()],
            vec!["tab\tkey"],
            vec!["same", "same"],
            vec!["first", "second"],
            vec!["second", "first"],
        ] {
            let mut headers = HeaderMap::new();
            for key in keys {
                headers.append("idempotency-key", HeaderValue::from_str(key).unwrap());
            }
            assert_eq!(
                idempotency_key(&headers).unwrap_err().code,
                "start-key-invalid"
            );
        }
    }

    #[test]
    fn only_credential_refusal_returns_a_bearer_challenge() {
        for (code, status, challenge) in [
            (
                "access.unauthenticated",
                StatusCode::UNAUTHORIZED,
                Some("Bearer"),
            ),
            ("access.denied", StatusCode::FORBIDDEN, None),
            ("access.unavailable", StatusCode::SERVICE_UNAVAILABLE, None),
            ("store-unavailable", StatusCode::SERVICE_UNAVAILABLE, None),
            ("request.invalid", StatusCode::BAD_REQUEST, None),
        ] {
            let response = problem(CoordinatorError::new(code, "synthetic boundary refusal"));
            assert_eq!(response.status(), status);
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::WWW_AUTHENTICATE)
                    .map(|value| value.to_str().unwrap()),
                challenge
            );
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
    }

    async fn document(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn assert_problem(response: &Response, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/problem+json"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
    }

    #[tokio::test]
    async fn a_refusal_answers_a_namespaced_problem_document_with_its_pinned_status() {
        let response = problem(CoordinatorError::new(
            "access.unauthenticated",
            "synthetic refusal canary",
        ));
        assert_problem(&response, StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[axum::http::header::WWW_AUTHENTICATE],
            "Bearer"
        );
        let traceparent = response.headers()["traceparent"]
            .to_str()
            .unwrap()
            .to_owned();
        let body = document(response).await;
        let members: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            members,
            ["code", "detail", "status", "title", "traceId", "type"]
        );
        assert_eq!(
            body["type"],
            "https://id.registrystack.org/problems/registry-coordinator/authentication/refused"
        );
        assert_eq!(body["code"], "authentication.refused");
        assert_eq!(body["status"], 401);
        let trace = body["traceId"].as_str().unwrap();
        assert_eq!(trace.len(), 32);
        assert!(traceparent.contains(trace));
        assert!(!body.to_string().contains("canary"));
    }

    #[tokio::test]
    async fn internal_refusal_codes_answer_their_public_problem() {
        for (internal, status, public) in [
            ("access.denied", 403, "operation.not-authorized"),
            ("run-absent", 404, "run.not-visible"),
            ("workflow-absent", 404, "workflow.not-served"),
            ("start-conflict", 409, "idempotency.key-reused"),
            ("store-unavailable", 503, "service.unavailable"),
            (
                "request.content-type-invalid",
                415,
                "request.unsupported-media-type",
            ),
            ("list-limit-invalid", 400, "request.limit-out-of-range"),
            ("definition.cycle", 409, "definition.refused"),
            ("status-unavailable", 500, "runtime.failure"),
        ] {
            let response = problem(CoordinatorError::new(internal, "synthetic"));
            assert_problem(&response, StatusCode::from_u16(status).unwrap());
            assert!(response
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .is_none());
            let unavailable = status == 503;
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::RETRY_AFTER)
                    .is_some(),
                unavailable,
                "{internal}"
            );
            let body = document(response).await;
            assert_eq!(body["code"], public, "{internal}");
            assert_eq!(body["status"], status, "{internal}");
        }
    }

    #[tokio::test]
    async fn an_unmapped_internal_code_answers_a_runtime_failure() {
        // A binding, not a literal, so the source scan in `problem` does not
        // read this synthetic code as one the crate raises.
        let unmapped = "synthetic-unmapped";
        let response = problem(CoordinatorError::new(unmapped, "canary"));
        assert_problem(&response, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(document(response).await["code"], "runtime.failure");
    }

    #[tokio::test]
    async fn request_edge_rejections_answer_problem_documents_under_the_request_trace() {
        use tower::ServiceExt as _;
        let app = || {
            http_edge(Router::new().route(
                "/v1/echo",
                post(|body: BoundedBody| async move {
                    answer(request_body::<Value>(body).map(|_| json!({})))
                }),
            ))
        };
        let traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        for (method, uri, length, status, code) in [
            ("GET", "/v1/absent", None, 404, "request.not-found"),
            ("GET", "/v1/echo", None, 405, "request.method-not-allowed"),
            (
                "POST",
                "/v1/echo",
                Some(65_537),
                413,
                "request.body-too-large",
            ),
        ] {
            let mut request = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("traceparent", traceparent);
            let body = match length {
                Some(length) => {
                    request = request.header("content-type", "application/json");
                    axum::body::Body::from(vec![b' '; length])
                }
                None => axum::body::Body::empty(),
            };
            let response = app().oneshot(request.body(body).unwrap()).await.unwrap();
            assert_problem(&response, StatusCode::from_u16(status).unwrap());
            assert!(response.headers()["traceparent"]
                .to_str()
                .unwrap()
                .contains("0af7651916cd43dd8448eb211c80319c"));
            let body = document(response).await;
            assert_eq!(body["code"], code, "{method} {uri}");
            assert_eq!(body["status"], status);
            assert_eq!(body["traceId"], "0af7651916cd43dd8448eb211c80319c");
        }
    }

    #[test]
    fn openapi_documents_challenges_only_on_authenticated_route_401s() {
        let document = openapi();
        for operation in document["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|path| path.as_object().unwrap().values())
        {
            if operation.get("security").is_some() {
                let challenge = if operation["security"][0].get("eventSource").is_some() {
                    "Registry-Signature version=\"v1\""
                } else {
                    "Bearer"
                };
                assert_eq!(
                    operation["responses"]["401"]["headers"]["WWW-Authenticate"]["schema"]["const"],
                    challenge
                );
                for status in ["400", "403", "404", "503"] {
                    assert!(operation["responses"][status]["headers"]
                        .get("WWW-Authenticate")
                        .is_none());
                }
            }
        }
    }

    fn operations(document: &Value) -> impl Iterator<Item = (&String, &Value)> {
        document["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|path| path.as_object().unwrap().iter())
    }

    #[test]
    fn openapi_summarizes_every_operation_once() {
        let document = openapi();
        let mut seen = std::collections::BTreeSet::new();
        for (_, operation) in operations(&document) {
            let id = operation["operationId"].as_str().unwrap();
            let summary = operation["summary"].as_str().unwrap_or_default();
            assert!(!summary.is_empty(), "{id} has no summary");
            assert!(seen.insert(summary.to_owned()), "{id} repeats {summary}");
        }
    }

    #[test]
    fn openapi_answers_every_refusal_with_problems_of_its_own_status() {
        let document = openapi();
        for (_, operation) in operations(&document) {
            let id = operation["operationId"].as_str().unwrap();
            for (status, response) in operation["responses"].as_object().unwrap() {
                if status.starts_with('2') || ["live", "ready"].contains(&id) && status == "503" {
                    continue;
                }
                let schema = &response["content"]["application/problem+json"]["schema"];
                let expected = "#/components/schemas/Problem";
                assert_eq!(schema["allOf"][0]["$ref"], expected, "{id} {status}");
                let codes = schema["allOf"][1]["properties"]["code"]["enum"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{id} {status}"));
                assert!(!codes.is_empty(), "{id} {status}");
                for code in codes {
                    let problem = ProblemCode::from_code(code.as_str().unwrap()).unwrap();
                    assert_eq!(problem.http_status().to_string(), *status, "{id} {code}");
                }
                if status == "503" {
                    assert_eq!(
                        response["headers"]["Retry-After"]["schema"]["minimum"], 1,
                        "{id}"
                    );
                }
            }
        }
    }

    #[test]
    fn openapi_problem_schema_is_the_closed_vocabulary() {
        let document = openapi();
        let schema = &document["components"]["schemas"]["Problem"];
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["required"],
            json!(["type", "title", "status", "detail", "code", "traceId"])
        );
        let codes: Vec<&str> = ProblemCode::ALL.iter().map(|p| p.code()).collect();
        let types: Vec<String> = codes.iter().map(|code| type_uri(code)).collect();
        assert_eq!(schema["properties"]["code"]["enum"], json!(codes));
        assert_eq!(schema["properties"]["type"]["enum"], json!(types));
    }

    #[test]
    fn openapi_run_states_match_the_runtime_filter() {
        let document = openapi();
        let response = &document["components"]["schemas"]["RunStatus"]["properties"]["state"];
        let filter = document["paths"]["/v1/runs"]["get"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "state")
            .unwrap();
        assert_eq!(response, &filter["schema"]);
        let states = response["enum"].as_array().unwrap();
        assert_eq!(states.len(), 8);
        for value in states {
            let state: RunListState = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(&serde_json::to_value(state).unwrap(), value);
        }
    }

    #[test]
    fn every_problem_an_operation_can_answer_is_documented_on_one() {
        let document = openapi();
        let documented: std::collections::BTreeSet<ProblemCode> = operations(&document)
            .flat_map(|(_, operation)| operation["responses"].as_object().unwrap().values())
            .filter_map(|response| {
                response["content"]["application/problem+json"]["schema"]["allOf"][1]["properties"]
                    ["code"]["enum"]
                    .as_array()
            })
            .flatten()
            .map(|code| ProblemCode::from_code(code.as_str().unwrap()).unwrap())
            .collect();
        // An unrouted path belongs to no operation, and every handler takes
        // its own extractor rejections, so neither edge problem is listed.
        let unlisted = [
            ProblemCode::RequestNotFound,
            ProblemCode::RequestUnprocessable,
        ];
        for problem in ProblemCode::ALL {
            assert_eq!(
                documented.contains(problem),
                !unlisted.contains(problem),
                "{}",
                problem.code()
            );
        }
    }
}

#[cfg(test)]
mod list_query_tests {
    use super::*;

    #[test]
    fn the_run_list_query_defaults_to_twenty_and_accepts_cursor_and_closed_state() {
        let parse = |uri: &str| Query::<List>::try_from_uri(&uri.parse().unwrap());
        assert_eq!(parse("/v1/runs").unwrap().limit, 20);
        assert_eq!(parse("/v1/runs?limit=100").unwrap().limit, 100);
        let query = parse("/v1/runs?limit=20&cursor=next&state=attention&attention=true").unwrap();
        assert_eq!(query.cursor.as_deref(), Some("next"));
        assert_eq!(query.state, Some(RunListState::Attention));
        assert_eq!(query.attention, Some(true));
        for refused in [
            "/v1/runs?state=waiting",
            "/v1/runs?state=ATTENTION",
            "/v1/runs?attention=maybe",
        ] {
            assert!(parse(refused).is_err(), "{refused}");
        }
    }
}
pub(crate) type BoundedBody = std::result::Result<Bytes, BytesRejection>;
/// A body the size limit cut short is too large; any other unreadable body is
/// an invalid request.
fn bounded_bytes(body: BoundedBody) -> Result<Bytes> {
    body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            CoordinatorError::new(
                "request.body-too-large",
                "supply a JSON object of at most 65536 bytes",
            )
        } else {
            CoordinatorError::new("request.invalid", "supply a bounded JSON object")
        }
    })
    .and_then(|bytes| {
        if bytes.len() <= 65_536 {
            Ok(bytes)
        } else {
            Err(CoordinatorError::new(
                "request.body-too-large",
                "supply a JSON object of at most 65536 bytes",
            ))
        }
    })
}
fn request_body<T: DeserializeOwned>(body: BoundedBody) -> Result<T> {
    let bytes = bounded_bytes(body)?;
    let value = registry_platform_canonical_json::parse_json_strict(&bytes)
        .map_err(|_| CoordinatorError::new("request.invalid", "supply unambiguous bounded JSON"))?;
    serde_json::from_value(value).map_err(|_| {
        CoordinatorError::new("request.invalid", "supply the declared JSON object fields")
    })
}
// Preserve Axum's JSON media contract, but release its rejection only after
// caller authentication and action/ownership authorization have succeeded.
async fn json_body<T: DeserializeOwned>(headers: &HeaderMap, body: BoundedBody) -> Result<T> {
    let bytes = bounded_bytes(body)?;
    let mut request = axum::http::Request::new(axum::body::Body::from(bytes.clone()));
    *request.headers_mut() = headers.clone();
    if matches!(
        Json::<Value>::from_request(request, &()).await,
        Err(JsonRejection::MissingJsonContentType(_))
    ) {
        return Err(CoordinatorError::new(
            "request.content-type-invalid",
            "supply application/json or an application media type ending in +json",
        ));
    }
    request_body(Ok(bytes))
}
async fn workflow_contract(
    State(s): State<HttpState>,
    headers: HeaderMap,
    workflow: std::result::Result<Path<String>, PathRejection>,
) -> Response {
    answer(async {
        let c = caller(&s, &headers).await?;
        c.authorize(Action::Start, None)?;
        let Path(workflow) = workflow.map_err(|_| CoordinatorError::new("request.invalid", "supply one bounded workflow identifier"))?;
        c.authorize(Action::Start, Some(&workflow))?;
        let package = s.workflows.get(&workflow).ok_or_else(|| CoordinatorError::new("workflow-absent", "this deployment does not serve the named workflow"))?;
        deployment::check(&s.store, &s.runtime, s.workflows.digest()).await?;
        Ok(json!({"workflow":package.definition.workflow.id, "workflowRevision":package.definition.digest, "input":package.definition.workflow.input, "outcomes":package.definition.workflow.outcomes}))
    }.await)
}

pub(crate) fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

pub(crate) fn idempotency_key(headers: &HeaderMap) -> Result<&str> {
    single_header(headers, "idempotency-key")
        .filter(|key| !key.is_empty() && key.len() <= 256 && !key.chars().any(char::is_control))
        .ok_or_else(|| {
            CoordinatorError::new("start-key-invalid", "supply one bounded Idempotency-Key")
        })
}

async fn start(State(s): State<HttpState>, headers: HeaderMap, body: BoundedBody) -> Response {
    let result = async {
        let c = caller(&s, &headers).await?;
        c.authorize(Action::Start, None)?;
        let body: Start = json_body(&headers, body).await?;
        c.authorize(Action::Start, Some(&body.workflow))?;
        if registry_platform_yaml::Digest::new(&body.workflow_revision).is_err() {
            return Err(CoordinatorError::new(
                "request.invalid",
                "supply the computed workflow revision",
            ));
        }
        if s.recovery_only {
            return Err(CoordinatorError::new(
                "recovery-only",
                "admissions are disabled in recovery-only service mode",
            )
            .suggest("establish persistent recovery hold before resuming an ordinary service"));
        }
        let package = s.workflows.get(&body.workflow).ok_or_else(|| {
            CoordinatorError::new(
                "workflow-absent",
                "this deployment does not serve the named workflow",
            )
            .suggest("name a workflow whose package this deployment lists")
        })?;
        deployment::check(&s.store, &s.runtime, s.workflows.digest()).await?;
        let key = idempotency_key(&headers)?;
        let binding = s.runtime.binding_digest_for(&package.definition.workflow)?;
        let id = s
            .store
            .admit_runtime_owned(
                &package.definition,
                body.input,
                &c.actor,
                key,
                &binding,
                &s.runtime,
                &body.workflow_revision,
            )
            .await?;
        s.store.status_owned(id, &c.actor).await.and_then(|v| {
            serde_json::to_value(v)
                .map_err(|_| CoordinatorError::new("status-unavailable", "cannot encode status"))
        })
    }
    .await;
    answer(result)
}
type RunPath = std::result::Result<Path<String>, PathRejection>;
async fn run_caller(
    s: &HttpState,
    headers: &HeaderMap,
    run: RunPath,
    action: Action,
) -> Result<(Caller, RunStatus)> {
    let c = caller(s, headers).await?;
    let workflows = c.authorized_workflows(action)?;
    let Path(run) = run.map_err(|_| {
        CoordinatorError::new("request.invalid", "supply a bounded UUID run identifier")
    })?;
    // Business parsing follows authentication and action policy. Accept the
    // UUID text forms `Uuid::parse_str` reads (hyphenated, simple, braced and
    // URN), within their bound.
    let run = if run.len() <= 45 {
        Uuid::parse_str(&run).ok()
    } else {
        None
    }
    .ok_or_else(|| {
        CoordinatorError::new("request.invalid", "supply a bounded UUID run identifier")
    })?;
    let status = s
        .store
        .status_owned_for_workflows(run, &c.actor, workflows)
        .await?;
    Ok((c, status))
}
fn answer(result: Result<Value>) -> Response {
    match result {
        Ok(v) => {
            let mut r = Json(v).into_response();
            r.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        }
        Err(e) => problem(e),
    }
}
fn encode(value: impl serde::Serialize) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|_| CoordinatorError::new("status-unavailable", "cannot encode protected result"))
}
async fn status(State(s): State<HttpState>, headers: HeaderMap, run: RunPath) -> Response {
    answer(
        async {
            let (_, status) = run_caller(&s, &headers, run, Action::Status).await?;
            encode(status)
        }
        .await,
    )
}
async fn list(
    State(s): State<HttpState>,
    headers: HeaderMap,
    query: std::result::Result<Query<List>, QueryRejection>,
) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            let workflows = c.authorized_workflows(Action::Status)?;
            let Query(q) = query.map_err(|_| {
                CoordinatorError::new("request.invalid", "supply the declared bounded list query")
            })?;
            if !(1..=100).contains(&q.limit) {
                return Err(CoordinatorError::new(
                    "list-limit-invalid",
                    "limit must be between 1 and 100",
                ));
            }
            encode(
                s.store
                    .list_owned_page(
                        q.limit,
                        q.cursor.as_deref(),
                        q.state,
                        q.attention,
                        &c.actor,
                        workflows,
                    )
                    .await?,
            )
        }
        .await,
    )
}
async fn binding(s: &HttpState, run: Uuid, c: &Caller) -> Result<String> {
    let definition = s.store.definition_owned(run, &c.actor).await?;
    s.runtime.binding_digest_for(&definition.workflow)
}
async fn inspect(State(s): State<HttpState>, headers: HeaderMap, run: RunPath) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::Inspect).await?;
            let run = run.run_id;
            encode(
                s.store
                    .inspect_runtime_owned(run, &s.runtime, &c.actor)
                    .await?,
            )
        }
        .await,
    )
}
async fn retry(
    State(s): State<HttpState>,
    headers: HeaderMap,
    run: RunPath,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::RetrySame).await?;
            let run = run.run_id;
            let reason: Reason = json_body(&headers, body).await?;
            s.store
                .retry_same_owned(run, &binding(&s, run, &c).await?, &c.actor, &reason.reason)
                .await?;
            Ok(json!({"runId":run,"status":"retry-scheduled"}))
        }
        .await,
    )
}
async fn cancel(
    State(s): State<HttpState>,
    headers: HeaderMap,
    run: RunPath,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::Cancel).await?;
            let run = run.run_id;
            let reason: Reason = json_body(&headers, body).await?;
            encode(s.store.cancel_owned(run, &c.actor, &reason.reason).await?)
        }
        .await,
    )
}
async fn reconcile(
    State(s): State<HttpState>,
    headers: HeaderMap,
    run: RunPath,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::Reconcile).await?;
            let run = run.run_id;
            let reason: Reason = json_body(&headers, body).await?;
            encode(
                s.store
                    .reconcile_owned(
                        run,
                        &binding(&s, run, &c).await?,
                        &c.actor,
                        &reason.reason,
                        s.adapters.as_ref(),
                    )
                    .await?,
            )
        }
        .await,
    )
}
async fn doctor(State(s): State<HttpState>, headers: HeaderMap) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize_deployment(Action::Doctor)?;
            let active =
                deployment::check_serving(&s.store, &s.runtime, s.workflows.digest()).await;
            let status = s.store.doctor().await?;
            Ok(json!({"activationReady":active.is_ok(),"state":status}))
        }
        .await,
    )
}
async fn hold(State(s): State<HttpState>, headers: HeaderMap, body: BoundedBody) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize_deployment(Action::RestoreHold)?;
            let reason: Reason = json_body(&headers, body).await?;
            s.store.set_restore_hold(&c.actor, &reason.reason).await?;
            Ok(json!({"restoreHold":true}))
        }
        .await,
    )
}
async fn release(State(s): State<HttpState>, headers: HeaderMap, body: BoundedBody) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize_deployment(Action::ReleaseRestoreHold)?;
            let reason: Reason = json_body(&headers, body).await?;
            s.store
                .release_restore_hold(&c.actor, &reason.reason)
                .await?;
            Ok(json!({"restoreHold":false}))
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionRelease {
    recovery_reference: String,
    admission_history_complete: bool,
    prior_deployment_fenced: bool,
}
async fn release_admission(
    State(s): State<HttpState>,
    headers: HeaderMap,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize_deployment(Action::ReleaseAdmissionHold)?;
            let body: AdmissionRelease = json_body(&headers, body).await?;
            s.store
                .release_admission_hold(
                    &c.actor,
                    &body.recovery_reference,
                    body.admission_history_complete,
                    body.prior_deployment_fenced,
                )
                .await?;
            Ok(json!({"admissionsHold":false}))
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutionRecovery {
    recovery_reference: String,
    execution_history_complete: bool,
    prior_deployment_fenced: bool,
}
async fn complete_execution(
    State(s): State<HttpState>,
    headers: HeaderMap,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize_deployment(Action::CompleteExecutionRecovery)?;
            let body: ExecutionRecovery = json_body(&headers, body).await?;
            s.store
                .complete_execution_recovery(
                    &c.actor,
                    &body.recovery_reference,
                    body.execution_history_complete,
                    body.prior_deployment_fenced,
                )
                .await?;
            Ok(json!({"executionRecoveryReviewed":true}))
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Retain {
    before: chrono::DateTime<chrono::Utc>,
    limit: u32,
}
async fn retain(State(s): State<HttpState>, headers: HeaderMap, body: BoundedBody) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize_deployment(Action::Retain)?;
            let body: Retain = json_body(&headers, body).await?;
            let count = s
                .store
                .retain_terminal(body.before, body.limit, &c.actor)
                .await?;
            Ok(json!({"erased":count}))
        }
        .await,
    )
}
/// Casework's completion destination authenticates with the connection's
/// completion credential and recipient binding, never a caller access token.
async fn review_completion(
    State(s): State<HttpState>,
    headers: HeaderMap,
    body: BoundedBody,
) -> Response {
    crate::completion::receive_review_completion(
        &s.store,
        s.adapters.as_ref(),
        &headers,
        body.as_deref().ok(),
    )
    .await
}
/// Every problem an authenticated operation can answer: its caller is
/// verified and authorized against durable, audited state.
const AUTHENTICATED_PROBLEMS: [ProblemCode; 6] = [
    ProblemCode::AuthenticationRefused,
    ProblemCode::OperationNotAuthorized,
    ProblemCode::RequestMethodNotAllowed,
    ProblemCode::AuditResponseUnavailable,
    ProblemCode::ServiceUnavailable,
    ProblemCode::RuntimeFailure,
];
/// Every problem reading a JSON request body can answer.
const BODY_PROBLEMS: [ProblemCode; 3] = [
    ProblemCode::RequestInvalid,
    ProblemCode::RequestBodyTooLarge,
    ProblemCode::RequestUnsupportedMediaType,
];
/// Every problem resolving the `{run}` path segment can answer.
const RUN_PROBLEMS: [ProblemCode; 2] = [ProblemCode::RequestInvalid, ProblemCode::RunNotVisible];
/// Every problem a review completion sender can be answered with.
const REVIEW_COMPLETION_PROBLEMS: [ProblemCode; 6] = [
    ProblemCode::AuthenticationRefused,
    ProblemCode::RequestInvalid,
    ProblemCode::RequestBodyTooLarge,
    ProblemCode::RequestUnsupportedMediaType,
    ProblemCode::RequestMethodNotAllowed,
    ProblemCode::ServiceUnavailable,
];
/// The problem responses of one operation, one per status, each naming the
/// codes it carries.
fn problem_responses(problems: &[ProblemCode]) -> serde_json::Map<String, Value> {
    let mut by_status: std::collections::BTreeMap<u16, Vec<&str>> = Default::default();
    for problem in problems {
        let codes = by_status.entry(problem.http_status()).or_default();
        if !codes.contains(&problem.code()) {
            codes.push(problem.code());
        }
    }
    by_status
        .into_iter()
        .map(|(status, mut codes)| {
            codes.sort_unstable();
            let mut response = json!({
                "description": format!("A problem: {}.", codes.join(", ")),
                "content": {"application/problem+json": {"schema": {"allOf": [
                    {"$ref": "#/components/schemas/Problem"},
                    {"properties": {"code": {"enum": codes}}}
                ]}}}
            });
            match status {
                401 => {
                    response["headers"] = json!({"WWW-Authenticate":{
                        "description":"Bearer authentication challenge for missing or refused credentials.",
                        "schema":{"type":"string","const":"Bearer"}
                    }})
                }
                503 => {
                    response["headers"] = json!({"Retry-After":{
                        "description":"Whole seconds to wait before trying again.",
                        "schema":{"type":"integer","minimum":1}
                    }})
                }
                _ => {}
            }
            (status.to_string(), response)
        })
        .collect()
}
/// One documented operation: its path, method, operation identifier, request
/// schema, response schema and the problems it can answer.
type DocumentedOperation = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
    Vec<ProblemCode>,
);
/// The one-line summary the API reference shows as each operation's title.
fn summary(operation_id: &str) -> &'static str {
    match operation_id {
        "live" => "Liveness",
        "ready" => "Readiness",
        "workflowContract" => "Discover the active workflow revision and typed contract",
        "startRun" => "Start a run of a served workflow",
        "listRuns" => "List a page of caller-visible runs",
        "runStatus" => "Read one run's status",
        "inspectRun" => "Inspect a run's steps and recovery options",
        "retrySame" => "Retry a held step with the same command",
        "cancelRun" => "Cancel a run",
        "reconcileRun" => "Reconcile an uncertain step against its receipt",
        "doctor" => "Report deployment readiness and run state",
        "restoreHold" => "Place the restore hold",
        "releaseRestoreHold" => "Release the restore hold",
        "releaseAdmissionHold" => "Release the admission hold",
        "completeExecutionRecovery" => "Complete execution recovery after a restore",
        "retainTerminal" => "Erase the payloads of terminal runs",
        "receiveReviewCompletion" => "Receive a Casework review completion event",
        _ => "",
    }
}

pub fn openapi() -> Value {
    use ProblemCode as P;
    let run_state = json!({"type":"string","enum":["running","finished","failed","cancelled","cancelled-after-effect","expired","attention","cancel-requested"]});
    let run_param = json!({"name":"run","in":"path","required":true,"schema":{"type":"string","format":"uuid"}});
    let mut paths = serde_json::Map::new();
    let operations: [DocumentedOperation; 14] = [
        (
            "/v1/workflows/{workflow}",
            "get",
            "workflowContract",
            None,
            "WorkflowContract",
            vec![
                P::WorkflowNotServed,
                P::DeploymentRefused,
                P::DeploymentActivationChanged,
            ],
        ),
        (
            "/v1/runs",
            "get",
            "listRuns",
            None,
            "RunList",
            vec![P::RequestInvalid, P::RequestLimitOutOfRange],
        ),
        (
            "/v1/runs",
            "post",
            "startRun",
            Some("Start"),
            "RunStatus",
            [
                &BODY_PROBLEMS[..],
                &[
                    P::WorkflowNotServed,
                    P::AdmissionRecoveryOnly,
                    P::AdmissionHeld,
                    P::ExecutionHeld,
                    P::DeploymentRefused,
                    P::DeploymentActivationChanged,
                    P::DefinitionRefused,
                    P::BindingConflict,
                    P::BindingLiveConflict,
                    P::WorkflowRevisionMismatch,
                    P::IdempotencyKeyInvalid,
                    P::IdempotencyKeyReused,
                    P::InputInvalid,
                ],
            ]
            .concat(),
        ),
        (
            "/v1/runs/{run}",
            "get",
            "runStatus",
            None,
            "RunStatus",
            RUN_PROBLEMS.to_vec(),
        ),
        (
            "/v1/runs/{run}/inspect",
            "get",
            "inspectRun",
            None,
            "RunInspection",
            [
                &RUN_PROBLEMS[..],
                &[
                    P::RunPayloadErased,
                    P::BindingConflict,
                    P::DefinitionRefused,
                ],
            ]
            .concat(),
        ),
        (
            "/v1/runs/{run}/retry-same",
            "post",
            "retrySame",
            Some("Reason"),
            "RetryScheduled",
            [
                &BODY_PROBLEMS[..],
                &RUN_PROBLEMS[..],
                &[
                    P::RequestReasonInvalid,
                    P::RunPayloadErased,
                    P::BindingConflict,
                    P::DefinitionRefused,
                    P::RetryRefused,
                    P::RunDefinitionIncompatible,
                    P::ReceiptExpired,
                    P::EvaluationUncertain,
                ],
            ]
            .concat(),
        ),
        (
            "/v1/runs/{run}/cancel",
            "post",
            "cancelRun",
            Some("Reason"),
            "RunStatus",
            [
                &BODY_PROBLEMS[..],
                &RUN_PROBLEMS[..],
                &[P::RequestReasonInvalid],
            ]
            .concat(),
        ),
        (
            "/v1/runs/{run}/reconcile",
            "post",
            "reconcileRun",
            Some("Reason"),
            "RunInspection",
            [
                &BODY_PROBLEMS[..],
                &RUN_PROBLEMS[..],
                &[
                    P::RequestReasonInvalid,
                    P::RunPayloadErased,
                    P::BindingConflict,
                    P::DefinitionRefused,
                    P::ReconcileRefused,
                    P::ReconcileUnsupported,
                    P::ReconcileRaced,
                ],
            ]
            .concat(),
        ),
        ("/v1/doctor", "get", "doctor", None, "Doctor", vec![]),
        (
            "/v1/restore-hold",
            "post",
            "restoreHold",
            Some("Reason"),
            "Hold",
            [&BODY_PROBLEMS[..], &[P::RequestReasonInvalid]].concat(),
        ),
        (
            "/v1/release-restore-hold",
            "post",
            "releaseRestoreHold",
            Some("Reason"),
            "Hold",
            [
                &BODY_PROBLEMS[..],
                &[P::RequestReasonInvalid, P::RestoreUnresolved],
            ]
            .concat(),
        ),
        (
            "/v1/release-admission-hold",
            "post",
            "releaseAdmissionHold",
            Some("AdmissionRelease"),
            "AdmissionHold",
            [
                &BODY_PROBLEMS[..],
                &[P::RequestReasonInvalid, P::AdmissionHeld, P::ExecutionHeld],
            ]
            .concat(),
        ),
        (
            "/v1/complete-execution-recovery",
            "post",
            "completeExecutionRecovery",
            Some("ExecutionRecovery"),
            "ExecutionReviewed",
            [
                &BODY_PROBLEMS[..],
                &[
                    P::RequestReasonInvalid,
                    P::RestoreReviewRequired,
                    P::RestoreHoldRequired,
                    P::RestoreLeaseIncompatible,
                ],
            ]
            .concat(),
        ),
        (
            "/v1/retention",
            "post",
            "retainTerminal",
            Some("Retention"),
            "Erased",
            [&BODY_PROBLEMS[..], &[P::RequestRetentionInvalid]].concat(),
        ),
    ];
    for (path, method, id, request, response, problems) in operations {
        let mut responses = problem_responses(&[&AUTHENTICATED_PROBLEMS[..], &problems].concat());
        responses.insert(
            "200".into(),
            json!({"description":"Authorized result","content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{response}")}}}}),
        );
        let mut op = json!({"operationId":id,"summary":summary(id),"security":[{"bearer":[]}],"responses":responses});
        if path.contains("{run}") {
            op["parameters"] = json!([run_param.clone()]);
        }
        if path.contains("{workflow}") {
            op["parameters"] = json!([{"name":"workflow","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":64}}]);
        }
        if id == "listRuns" {
            op["parameters"] = json!([
                {"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":100,"default":20}},
                {"name":"cursor","in":"query","description":"Opaque nextCursor from the previous page. Keep state and attention filters unchanged; the current caller is authorized again on each page.","schema":{"type":"string","minLength":1,"maxLength":4096}},
                {"name":"state","in":"query","schema":run_state},
                {"name":"attention","in":"query","description":"True selects effective states attention and failed; false excludes both. Composes with state.","schema":{"type":"boolean"}}
            ]);
        }
        if id == "cancelRun" {
            op["description"] = json!("An authorized cancellation of a parked review wait with onCancel records durable intent and takes that authored path. A leased result read settles or expires before cleanup advances. Repeating cancellation preserves cleanup, reported by authoredCancelRequested. Other cancellation stops future calls where possible; it never reverses an accepted product effect.");
        }
        if id == "startRun" {
            op["parameters"] = json!([{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":256}}]);
        }
        if let Some(request) = request {
            op["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{request}")}}}});
        }
        paths.entry(path.to_owned()).or_insert_with(|| json!({}))[method] = op;
    }
    paths.insert(
        registry_review_protocol::REVIEW_COMPLETIONS_PATH.into(),
        json!({"post":{
            "operationId":"receiveReviewCompletion",
            "summary":summary("receiveReviewCompletion"),
            "description":"Casework's completion destination for a review producer connection reports that a review result exists. The event only wakes the step waiting on that request, which then reads the result with the connection's producer credential. Every authentic, well-formed event answers 204 whether or not a step waits on its request.",
            "security":[{"reviewCompletion":[]}],
            "parameters":[
                {"name":"Registry-Recipient-Binding","in":"header","required":true,"description":"The recipient binding configured for the connection's completion destination.","schema":{"type":"string","minLength":1}},
                {"name":"Idempotency-Key","in":"header","required":true,"description":"The event identifier.","schema":{"type":"string","format":"uuid"}}
            ],
            "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ReviewCompletion"}}}},
            "responses":{}
        }}),
    );
    let mut responses = problem_responses(&REVIEW_COMPLETION_PROBLEMS);
    responses.insert(
        "204".into(),
        json!({"description":"Authentic completion accepted"}),
    );
    paths[registry_review_protocol::REVIEW_COMPLETIONS_PATH]["post"]["responses"] =
        Value::Object(responses);
    for (path, key) in [("/health", "live"), ("/ready", "ready")] {
        let mut responses = problem_responses(&[ProblemCode::RequestMethodNotAllowed]);
        responses.insert("200".into(), json!({"description":"Health result","content":{"application/json":{"schema":{"type":"object","required":[key],"properties":{key:{"type":"boolean"}}}}}}));
        responses.insert(
            "503".into(),
            json!({"description":"Deployment unavailable or in recovery hold"}),
        );
        paths.insert(
            path.into(),
            json!({"get":{"operationId":key,"summary":summary(key),"responses":responses}}),
        );
    }
    let problem_codes: Vec<&str> = ProblemCode::ALL.iter().map(|p| p.code()).collect();
    let problem_types: Vec<String> = problem_codes.iter().map(|code| type_uri(code)).collect();
    let nullable_text = json!({"type":["string","null"]});
    let date = json!({"type":"string","format":"date-time"});
    let operation_ids: Vec<_> = crate::operations::descriptors()
        .iter()
        .map(|operation| operation.id)
        .collect();
    let status = json!({"type":"object","required":["runId","workflow","workflowRevision","bindingDigest","step","state","admittedAt","deadlineAt","uncertain","cancelRequested","authoredCancelRequested","restoreReviewRequired"],"properties":{"runId":{"type":"string","format":"uuid"},"workflow":{"type":"string"},"workflowRevision":{"type":"string"},"bindingDigest":{"type":"string"},"step":{"type":"string"},"state":run_state,"outcome":nullable_text,"output":{},"failureCode":nullable_text,"failurePath":nullable_text,"admittedAt":date,"deadlineAt":date,"nextDueAt":{"type":["string","null"],"format":"date-time"},"uncertain":{"type":"boolean"},"cancelRequested":{"type":"boolean","description":"Ordinary cancellation is irreversible and prevents later workflow effects; an uncertain evaluation may still have run at its provider."},"authoredCancelRequested":{"type":"boolean","description":"An authorized cancellation took a parked wait's authored onCancel path; cleanup on that path remains runnable."},"restoreReviewRequired":{"type":"boolean"}}});
    let mut schemas = json!({
      "WorkflowContract":{"type":"object","additionalProperties":false,"required":["workflow","workflowRevision","input","outcomes"],"properties":{"workflow":{"type":"string"},"workflowRevision":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},"input":{},"outcomes":{"type":"object","minProperties":1,"maxProperties":64}}},
      "Start":{"type":"object","additionalProperties":false,"required":["workflow","workflowRevision","input"],"properties":{"workflow":{"type":"string","minLength":1,"maxLength":64},"workflowRevision":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},"input":{}}},
      "Reason":{"type":"object","additionalProperties":false,"required":["reason"],"properties":{"reason":{"type":"string","minLength":1,"maxLength":256}}},
      "ExecutionRecovery":{"type":"object","additionalProperties":false,"required":["recoveryReference","executionHistoryComplete","priorDeploymentFenced"],"properties":{"recoveryReference":{"type":"string","minLength":1,"maxLength":256},"executionHistoryComplete":{"type":"boolean"},"priorDeploymentFenced":{"type":"boolean"}}},
      "ExecutionReviewed":{"type":"object","required":["executionRecoveryReviewed"],"properties":{"executionRecoveryReviewed":{"type":"boolean"}}},
      "AdmissionRelease":{"type":"object","additionalProperties":false,"required":["recoveryReference","admissionHistoryComplete","priorDeploymentFenced"],"properties":{"recoveryReference":{"type":"string","minLength":1,"maxLength":256},"admissionHistoryComplete":{"type":"boolean"},"priorDeploymentFenced":{"type":"boolean"}}},
      "AdmissionHold":{"type":"object","required":["admissionsHold"],"properties":{"admissionsHold":{"type":"boolean"}}},
      "Retention":{"type":"object","additionalProperties":false,"required":["before","limit"],"properties":{"before":{"type":"string","format":"date-time"},"limit":{"type":"integer","minimum":1,"maximum":100}}},
      "RunStatus":status,"RunList":{"type":"object","required":["runs"],"properties":{"runs":{"type":"array","maxItems":100,"items":{"$ref":"#/components/schemas/RunStatus"}},"nextCursor":{"type":"string","description":"Present when another page may exist; continue with the same filters."}}},
      "StepStatus":{"type":"object","required":["step","state","generation","attempt","commandPrepared","uncertain","receiptExpired"],"properties":{"step":{"type":"string"},"state":{"type":"string"},"generation":{"type":"integer"},"attempt":{"type":"integer"},"nextDueAt":{"type":["string","null"],"format":"date-time"},"leaseExpiresAt":{"type":["string","null"],"format":"date-time"},"commandPrepared":{"type":"boolean"},"uncertain":{"type":"boolean"},"receiptExpired":{"type":"boolean"},"failureCode":{"type":["string","null"]},"failurePath":{"type":["string","null"]}}},
      "OperationIdentity":{"type":"object","additionalProperties":false,"description":"Pinned public operation contract; does not establish current authority or receipt availability.","required":["id","version","product","effect","keyRequirement","requiresPreparation","recovery","readReceipt"],"properties":{"id":{"type":"string","enum":operation_ids},"version":{"type":"integer","minimum":1},"product":{"type":"string"},"effect":{"type":"string","enum":["read","mutation","evaluation"]},"keyRequirement":{"type":"string","enum":["none","required"]},"requiresPreparation":{"type":"boolean"},"recovery":{"type":"string","enum":["read-again","same-command-and-receipt","same-command","hold-after-dispatch"]},"readReceipt":{"type":"boolean"}}},
      "EffectStatus":{"type":"object","additionalProperties":false,"required":["step","operation","operationRevision","state"],"properties":{"step":{"type":"string"},"operation":{"$ref":"#/components/schemas/OperationIdentity"},"operationRevision":{"type":"string"},"state":{"type":"string","enum":["accepted","unknown"]}}},
      "WaitStatus":{"type":"object","additionalProperties":false,"required":["step","acceptedStep","completion","completionRevision","timeoutAt","nextObservationAt","notBefore","minimumIntervalSeconds","observations","observationLimit"],"properties":{"step":{"type":"string"},"acceptedStep":{"type":"string"},"completion":{"type":"string"},"completionRevision":{"type":"string"},"timeoutAt":date,"nextObservationAt":{"type":["string","null"],"format":"date-time"},"notBefore":date,"minimumIntervalSeconds":{"type":"integer","minimum":30,"maximum":86400},"observations":{"type":"integer","minimum":0},"observationLimit":{"type":"integer","minimum":1}}},
      "RunInspection":{"type":"object","required":["run","steps","effects","waits","recovery"],"properties":{"run":{"$ref":"#/components/schemas/RunStatus"},"steps":{"type":"array","items":{"$ref":"#/components/schemas/StepStatus"}},"effects":{"type":"array","items":{"$ref":"#/components/schemas/EffectStatus"}},"waits":{"type":"array","items":{"$ref":"#/components/schemas/WaitStatus"}},"recovery":{"type":"object","required":["retryAllowed"],"properties":{"retryAllowed":{"type":"boolean"},"reason":{"type":["string","null"]},"operation":{"$ref":"#/components/schemas/OperationIdentity"}}}}},
      "Doctor":{"type":"object","required":["activationReady","state"],"properties":{"activationReady":{"type":"boolean"},"state":{"type":"object","required":["databaseId","schemaVersion","restoreHold","auditReady","admissionsHold","restoreReviewRequired","states","uncertain","terminalPayloads","oldestTerminalPayloadAt"],"properties":{"databaseId":{"type":"string"},"schemaVersion":{"type":"integer"},"restoreHold":{"type":"boolean"},"auditReady":{"type":"boolean"},"admissionsHold":{"type":"boolean"},"restoreReviewRequired":{"type":"integer","minimum":0},"states":{"type":"object","additionalProperties":{"type":"integer"}},"uncertain":{"type":"integer"},"oldestDueAt":{"type":["string","null"],"format":"date-time"},"terminalPayloads":{"type":"integer","minimum":0},"oldestTerminalPayloadAt":{"type":["string","null"],"format":"date-time"}}}}},
      "RetryScheduled":{"type":"object","required":["runId","status"],"properties":{"runId":{"type":"string","format":"uuid"},"status":{"const":"retry-scheduled"}}},
      "Hold":{"type":"object","required":["restoreHold"],"properties":{"restoreHold":{"type":"boolean"}}},"Erased":{"type":"object","required":["erased"],"properties":{"erased":{"type":"integer","minimum":0}}},
      "Problem":{"type":"object","additionalProperties":false,"required":["type","title","status","detail","code","traceId"],"properties":{"type":{"type":"string","enum":problem_types},"title":{"type":"string"},"status":{"type":"integer"},"detail":{"type":"string"},"code":{"type":"string","enum":problem_codes},"traceId":{"type":"string"}}}
    });
    admission_contracts::extend(&mut paths, &mut schemas);
    json!({"openapi":"3.1.0","info":{"title":"Registry Coordinator","version":env!("CARGO_PKG_VERSION"),"description":"Registry Coordinator HTTP contract. Refusals use the closed problem vocabulary."},"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer","bearerFormat":"JWT"},"reviewCompletion":{"type":"http","scheme":"bearer","description":"The completion credential configured for a Casework review connection, presented with its recipient binding."},"eventSource":{"type":"apiKey","in":"header","name":"X-Registry-Signature","description":"The platform v1 HMAC delivery signature, bound to the canonical envelope, signed delivery headers, HTTP method and exact request target. The configured event source key is separate from caller bearer tokens."}},"schemas":schemas},"paths":paths})
}
