//! Native Evidence Version 1 HTTP boundary.
//!
//! Request admission, body collection, and concurrency queueing observe the
//! configured request timeout. Once [`EvidenceRuntime::evaluate`] starts, this
//! boundary deliberately does not wrap it in a cancelling timeout: evaluation
//! contains the durable access-audit, signing, and durable release-audit
//! critical section.

use std::{
    future::{Future, IntoFuture},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{
        header::{
            ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER, VARY,
        },
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    middleware::{from_fn, from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use registry_platform_crypto::parse_json_strict;
use registry_platform_httpsec::CspBuilder;
use serde::Serialize;
use tokio::{net::TcpListener, sync::Semaphore};

use crate::{
    config::{ListenerConfig, ResponseFormat},
    contracts::{request_contract_accepts, served_openapi_document},
    model::{request_nonce_is_canonical, EvidenceRequest, JwksDocument},
    observability::{self, operation_id, Metrics},
    problem::ProblemCode,
    runtime::{EvidenceRuntime, RuntimeFailure},
    EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_MEDIA_TYPE, EVIDENCE_UNSIGNED_MEDIA_TYPE,
};

const EVIDENCE_ROUTE: &str = "/v1/evidence";
const DEFINITIONS_ROUTE: &str = "/v1/evidence-definitions";
const HEALTH_ROUTE: &str = "/health";
const OPENAPI_ROUTE: &str = "/openapi.json";
const READY_ROUTE: &str = "/ready";
const JWKS_ROUTE: &str = "/.well-known/evidence/jwks.json";
const JWT_VC_ISSUER_ROUTE: &str = "/.well-known/jwt-vc-issuer";

/// Every route template this listener registers.
///
/// Operational telemetry labels requests with a member of this set or with a
/// single fixed unmatched label, so a caller cannot introduce a label value.
pub(crate) const ROUTE_TEMPLATES: [&str; 7] = [
    EVIDENCE_ROUTE,
    DEFINITIONS_ROUTE,
    HEALTH_ROUTE,
    OPENAPI_ROUTE,
    READY_ROUTE,
    JWKS_ROUTE,
    JWT_VC_ISSUER_ROUTE,
];

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const JWKS_MEDIA_TYPE: &str = "application/jwk-set+json";
const OPENAPI_MEDIA_TYPE: &str = "application/openapi+json";
const RETRY_AFTER_SECONDS: &str = "1";

#[derive(Clone)]
struct ServerState {
    runtime: Arc<EvidenceRuntime>,
    maximum_request_bytes: usize,
    request_timeout: Duration,
    request_slots: Arc<Semaphore>,
    evaluations: EvaluationTracker,
    #[cfg(test)]
    evaluation_time: Option<chrono::DateTime<chrono::Utc>>,
}

/// Build the complete Version 1 application from one immutable runtime.
#[cfg(test)]
pub(crate) fn build_app(runtime: Arc<EvidenceRuntime>) -> Router {
    build_app_with_tracker(runtime).0
}

#[cfg(test)]
pub(crate) fn build_app_at_for_test(
    runtime: Arc<EvidenceRuntime>,
    evaluation_time: chrono::DateTime<chrono::Utc>,
) -> Router {
    build_app_with_tracker_at(runtime, Some(evaluation_time)).0
}

/// Build the application together with the registry its observation layer
/// feeds, so a test can read the counters a request produced.
#[cfg(test)]
pub(crate) fn build_app_with_metrics(runtime: Arc<EvidenceRuntime>) -> (Router, Arc<Metrics>) {
    let (app, _evaluations, metrics) = build_app_with_tracker_at(runtime, None);
    (app, metrics)
}

fn build_app_with_tracker(
    runtime: Arc<EvidenceRuntime>,
) -> (Router, EvaluationTracker, Arc<Metrics>) {
    build_app_with_tracker_at(runtime, None)
}

fn build_app_with_tracker_at(
    runtime: Arc<EvidenceRuntime>,
    evaluation_time: Option<chrono::DateTime<chrono::Utc>>,
) -> (Router, EvaluationTracker, Arc<Metrics>) {
    #[cfg(not(test))]
    let _ = evaluation_time;
    let listener = &runtime.runtime_config().listener;
    let maximum_request_bytes = listener.maximum_request_bytes as usize;
    let request_timeout = Duration::from_millis(listener.request_timeout_milliseconds);
    let maximum_concurrent_requests = listener.maximum_concurrent_requests as usize;
    let evaluations = EvaluationTracker::default();
    let state = Arc::new(ServerState {
        runtime,
        maximum_request_bytes,
        request_timeout,
        request_slots: Arc::new(Semaphore::new(maximum_concurrent_requests)),
        evaluations: evaluations.clone(),
        #[cfg(test)]
        evaluation_time,
    });

    let routes = Router::new()
        .route(EVIDENCE_ROUTE, post(create_evidence))
        .route(DEFINITIONS_ROUTE, get(discover_evidence))
        .route(HEALTH_ROUTE, get(health))
        .route(OPENAPI_ROUTE, get(openapi))
        .route(READY_ROUTE, get(ready))
        .route(JWKS_ROUTE, get(jwks))
        .route(JWT_VC_ISSUER_ROUTE, get(jwt_vc_issuer_metadata))
        .fallback(unknown_route)
        .method_not_allowed_fallback(unknown_route)
        .with_state(state);
    let metrics = Arc::new(Metrics::default());
    (
        response_layers(routes, Arc::clone(&metrics)),
        evaluations,
        metrics,
    )
}

#[derive(Clone, Default)]
struct EvaluationTracker {
    inner: Arc<EvaluationTrackerInner>,
}

#[derive(Default)]
struct EvaluationTrackerInner {
    active: AtomicUsize,
    idle: tokio::sync::Notify,
}

impl EvaluationTracker {
    fn spawn<F, T>(&self, future: F) -> tokio::task::JoinHandle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.inner.active.fetch_add(1, Ordering::AcqRel);
        let guard = ActiveEvaluation {
            tracker: self.clone(),
        };
        tokio::spawn(async move {
            let _guard = guard;
            future.await
        })
    }

    async fn wait_idle(&self) {
        loop {
            let idle = self.inner.idle.notified();
            if self.inner.active.load(Ordering::Acquire) == 0 {
                return;
            }
            idle.await;
        }
    }
}

struct ActiveEvaluation {
    tracker: EvaluationTracker,
}

impl Drop for ActiveEvaluation {
    fn drop(&mut self) {
        if self.tracker.inner.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.inner.idle.notify_one();
        }
    }
}

fn response_layers(routes: Router, metrics: Arc<Metrics>) -> Router {
    routes
        .layer(from_fn(add_no_store))
        .layer(registry_platform_httpsec::corp_conditional())
        .layer(
            registry_platform_httpsec::security_headers(CspBuilder::restrictive()).without_hsts(),
        )
        // Outermost, so that every response including both fallbacks carries a
        // correlation identifier and produces exactly one operational record.
        .layer(from_fn_with_state(metrics, observability::observe))
}

/// Bind the configured private listener and serve until graceful shutdown.
pub async fn serve<F>(runtime: Arc<EvidenceRuntime>, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener_config = runtime.runtime_config().listener.clone();
    let metrics_config = runtime.runtime_config().metrics_listener.clone();
    let listener = bind(&listener_config.bind_host, listener_config.port).await?;
    let (app, evaluations, metrics) = build_app_with_tracker(runtime);

    // Both listeners are bound before either serves, so a misconfigured
    // metrics binding fails startup instead of leaving a service that reports
    // healthy while publishing no telemetry.
    let metrics_listener = match &metrics_config {
        Some(config) => Some(bind(&config.bind_host, config.port).await?),
        None => None,
    };
    let (stop_metrics, metrics_stopped) = tokio::sync::watch::channel(());
    let metrics_server = metrics_listener.map(|listener| {
        let mut stopped = metrics_stopped;
        tokio::spawn(async move {
            axum::serve(listener, observability::metrics_app(metrics))
                .with_graceful_shutdown(async move {
                    // A dropped sender also ends the wait, so the metrics
                    // listener cannot outlive a failed evidence listener.
                    let _ = stopped.changed().await;
                })
                .await
        })
    });

    let result = serve_listener(listener, app, &listener_config, async move {
        shutdown.await;
        drop(stop_metrics);
    })
    .await;
    if let Some(server) = metrics_server {
        let _ = server.await;
    }

    // A disconnected client can cause axum to drop its handler future. The
    // admitted evaluation itself is owned by a detached task, so the server
    // must explicitly drain those tasks before production shutdown returns.
    evaluations.wait_idle().await;
    result
}

async fn bind(bind_host: &str, port: u16) -> io::Result<TcpListener> {
    let ip = bind_host
        .parse::<IpAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    TcpListener::bind(SocketAddr::new(ip, port)).await
}

/// Serve a pre-bound listener and drain client-bound handlers on shutdown.
///
/// The grace duration is an operational target, not a cancellation boundary.
/// A request already inside runtime evaluation is allowed to complete even if
/// it exceeds that target, preserving the audit and signing invariants. The
/// production [`serve`] entry point additionally drains detached evaluations.
async fn serve_listener<F>(
    listener: TcpListener,
    app: Router,
    config: &ListenerConfig,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let grace = Duration::from_millis(config.shutdown_grace_milliseconds);
    let (shutdown_started_tx, shutdown_started_rx) = tokio::sync::oneshot::channel();
    let graceful = async move {
        shutdown.await;
        let _ = shutdown_started_tx.send(());
    };
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(graceful)
        .into_future();
    tokio::pin!(server);

    let grace_watch = async move {
        if shutdown_started_rx.await.is_ok() {
            tokio::time::sleep(grace).await;
            tracing::warn!(
                target: "registry_evidence::server",
                "graceful shutdown target elapsed; waiting for protected operations to finish"
            );
        }
        std::future::pending::<()>().await;
    };
    tokio::pin!(grace_watch);

    tokio::select! {
        result = &mut server => result,
        () = &mut grace_watch => unreachable!("shutdown grace watcher never completes"),
    }
}

#[cfg(test)]
pub(crate) async fn serve_listener_for_test<F>(
    runtime: Arc<EvidenceRuntime>,
    listener: TcpListener,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener_config = runtime.runtime_config().listener.clone();
    let (app, evaluations, _metrics) = build_app_with_tracker(runtime);
    let result = serve_listener(listener, app, &listener_config, shutdown).await;
    evaluations.wait_idle().await;
    result
}

/// Every `/v1/evidence` response varies on the negotiated `Accept` value.
async fn create_evidence(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let mut response = create_evidence_negotiated(state, request).await;
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Accept"));
    response
}

async fn create_evidence_negotiated(state: Arc<ServerState>, request: Request<Body>) -> Response {
    let operation = operation_id(request.extensions());
    let started = Instant::now();

    let access_token = match bearer_token(request.headers()) {
        Ok(token) => token.to_owned(),
        Err(code) => return problem_response(code, &operation),
    };
    // Strict media negotiation resolves the requested response format before
    // the body is read and long before credential acquisition or source
    // access. Selection creates no permission; the bundle and matched grant
    // decide authorization later.
    let format = match resolve_response_format(request.headers()) {
        Ok(format) => format,
        Err(code) => return problem_response(code, &operation),
    };
    if !has_exact_content_type(request.headers(), JSON_MEDIA_TYPE)
        || content_length_exceeds(request.headers(), state.maximum_request_bytes)
    {
        return problem_response(ProblemCode::MalformedRequest, &operation);
    }

    let admission_budget = match remaining(state.request_timeout, started) {
        Some(remaining) => remaining,
        None => return problem_response(ProblemCode::ServiceUnavailable, &operation),
    };
    let request_slot = match tokio::time::timeout(
        admission_budget,
        Arc::clone(&state.request_slots).acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) | Err(_) => {
            return problem_response(ProblemCode::ServiceUnavailable, &operation)
        }
    };

    let body_budget = match remaining(state.request_timeout, started) {
        Some(remaining) => remaining,
        None => return problem_response(ProblemCode::ServiceUnavailable, &operation),
    };
    let body = match tokio::time::timeout(
        body_budget,
        to_bytes(request.into_body(), state.maximum_request_bytes),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => return problem_response(ProblemCode::MalformedRequest, &operation),
        Err(_) => return problem_response(ProblemCode::ServiceUnavailable, &operation),
    };
    let evidence_request = match parse_evidence_request(&body) {
        Ok(request) => request,
        Err(code) => return problem_response(code, &operation),
    };

    // The tracker-owned task, rather than this client-bound handler, owns the
    // admitted concurrency permit and complete fail-closed evaluation. If the
    // client disconnects while the handler awaits the join handle, dropping
    // that handle detaches the task instead of cancelling its audit writes.
    let evaluation_operation = operation.clone();
    let runtime = Arc::clone(&state.runtime);
    let evaluations = state.evaluations.clone();
    #[cfg(test)]
    let evaluation_time = state.evaluation_time;
    let evaluation = evaluations.spawn(async move {
        let _request_slot = request_slot;
        #[cfg(test)]
        if let Some(evaluation_time) = evaluation_time {
            return runtime
                .evaluate_at_for_test(
                    &evaluation_operation,
                    &access_token,
                    &evidence_request,
                    format,
                    evaluation_time,
                )
                .await;
        }
        runtime
            .evaluate_with_format(
                &evaluation_operation,
                &access_token,
                &evidence_request,
                format,
            )
            .await
    });
    let result = match evaluation.await {
        Ok(result) => result,
        Err(_) => return problem_response(ProblemCode::ServiceUnavailable, &operation),
    };

    match result {
        // Release exactly the immutable bytes serialized before the durable
        // disclosure-release audit event, with their exact media type.
        Ok(released) => {
            let media_type = released.media_type();
            bytes_response(StatusCode::OK, media_type, released.into_bytes())
        }
        Err(failure) => runtime_failure_response(failure, &operation),
    }
}

/// Resolve the closed Version 1 `Accept` matrix. Missing, `*/*`, and the exact
/// signed media type select signed JWS; only the exact unsigned vendor media
/// type selects the unsigned envelope, and only the exact SD-JWT VC media type
/// selects that serialization. Duplicate, combined, parameterized, weighted, or
/// unknown negotiation is not acceptable.
fn resolve_response_format(headers: &HeaderMap) -> Result<ResponseFormat, ProblemCode> {
    let mut values = headers.get_all(ACCEPT).iter();
    let Some(value) = values.next() else {
        return Ok(ResponseFormat::SignedJws);
    };
    if values.next().is_some() {
        return Err(ProblemCode::ResponseFormatNotAcceptable);
    }
    match value.as_bytes() {
        b"*/*" => Ok(ResponseFormat::SignedJws),
        value if value == EVIDENCE_JWS_MEDIA_TYPE.as_bytes() => Ok(ResponseFormat::SignedJws),
        value if value == EVIDENCE_UNSIGNED_MEDIA_TYPE.as_bytes() => {
            Ok(ResponseFormat::UnsignedJson)
        }
        value if value == EVIDENCE_SD_JWT_VC_MEDIA_TYPE.as_bytes() => Ok(ResponseFormat::SdJwtVc),
        _ => Err(ProblemCode::ResponseFormatNotAcceptable),
    }
}

async fn discover_evidence(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let operation = operation_id(request.extensions());
    let started = Instant::now();
    let access_token = match bearer_token(request.headers()) {
        Ok(token) => token.to_owned(),
        Err(code) => return problem_response(code, &operation),
    };
    if request.uri().query().is_some() || content_length_exceeds(request.headers(), 0) {
        return problem_response(ProblemCode::MalformedRequest, &operation);
    }
    let admission_budget = match remaining(state.request_timeout, started) {
        Some(remaining) => remaining,
        None => return problem_response(ProblemCode::ServiceUnavailable, &operation),
    };
    let _request_slot = match tokio::time::timeout(
        admission_budget,
        Arc::clone(&state.request_slots).acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) | Err(_) => {
            return problem_response(ProblemCode::ServiceUnavailable, &operation)
        }
    };
    let body_budget = match remaining(state.request_timeout, started) {
        Some(remaining) => remaining,
        None => return problem_response(ProblemCode::ServiceUnavailable, &operation),
    };
    match tokio::time::timeout(body_budget, to_bytes(request.into_body(), 0)).await {
        Ok(Ok(body)) if body.is_empty() => {}
        Ok(Ok(_)) | Ok(Err(_)) => {
            return problem_response(ProblemCode::MalformedRequest, &operation)
        }
        Err(_) => return problem_response(ProblemCode::ServiceUnavailable, &operation),
    }
    let discovery_budget = match remaining(state.request_timeout, started) {
        Some(remaining) => remaining,
        None => return problem_response(ProblemCode::ServiceUnavailable, &operation),
    };
    match tokio::time::timeout(discovery_budget, state.runtime.discover(&access_token)).await {
        Ok(Ok(definitions)) => {
            match serialize_response(StatusCode::OK, JSON_MEDIA_TYPE, &definitions) {
                Some(response) => response,
                None => problem_response(ProblemCode::ServiceUnavailable, &operation),
            }
        }
        Ok(Err(failure)) => runtime_failure_response(failure, &operation),
        Err(_) => problem_response(ProblemCode::ServiceUnavailable, &operation),
    }
}

async fn health() -> Response {
    static_json_response(StatusCode::OK, r#"{"status":"ok"}"#)
}

/// Publish the generated public contract. The document is static release
/// material, so this route takes no credential and reaches no dependency.
async fn openapi(request: Request<Body>) -> Response {
    match served_openapi_document() {
        Some(document) => bytes_response(
            StatusCode::OK,
            OPENAPI_MEDIA_TYPE,
            document.as_bytes().to_vec(),
        ),
        None => problem_response(
            ProblemCode::ServiceUnavailable,
            &operation_id(request.extensions()),
        ),
    }
}

async fn ready(State(state): State<Arc<ServerState>>, request: Request<Body>) -> Response {
    let operation = operation_id(request.extensions());
    match tokio::time::timeout(state.request_timeout, state.runtime.ready()).await {
        Ok(true) => static_json_response(StatusCode::OK, r#"{"status":"ready"}"#),
        Ok(false) | Err(_) => problem_response(ProblemCode::ServiceUnavailable, &operation),
    }
}

async fn jwks(State(state): State<Arc<ServerState>>, request: Request<Body>) -> Response {
    let operation = operation_id(request.extensions());
    match serialize_response(StatusCode::OK, JWKS_MEDIA_TYPE, state.runtime.jwks()) {
        Some(response) => response,
        None => problem_response(ProblemCode::ServiceUnavailable, &operation),
    }
}

/// JWT VC Issuer Metadata. Discovery is not a trust anchor: it republishes the
/// same public keys under the provider identity the assertion already names.
/// Resolution is meaningful only when that identity is the HTTPS origin of the
/// deployment; a URN provider identity simply has no resolution path.
async fn jwt_vc_issuer_metadata(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
) -> Response {
    let operation = operation_id(request.extensions());
    let metadata = JwtVcIssuerMetadata {
        issuer: &state.runtime.bundle().config.service.provider_id,
        jwks: state.runtime.jwks(),
    };
    match serialize_response(StatusCode::OK, JSON_MEDIA_TYPE, &metadata) {
        Some(response) => response,
        None => problem_response(ProblemCode::ServiceUnavailable, &operation),
    }
}

#[derive(Serialize)]
struct JwtVcIssuerMetadata<'a> {
    issuer: &'a str,
    jwks: &'a JwksDocument,
}

async fn unknown_route(request: Request<Body>) -> Response {
    problem_response(
        ProblemCode::MalformedRequest,
        &operation_id(request.extensions()),
    )
}

async fn add_no_store(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn parse_evidence_request(bytes: &[u8]) -> Result<EvidenceRequest, ProblemCode> {
    let value = parse_json_strict(bytes).map_err(|_| ProblemCode::MalformedRequest)?;
    match request_contract_accepts(&value) {
        Ok(true) => {}
        Ok(false) => return Err(ProblemCode::MalformedRequest),
        Err(_) => return Err(ProblemCode::ServiceUnavailable),
    }
    let request: EvidenceRequest =
        serde_json::from_value(value).map_err(|_| ProblemCode::MalformedRequest)?;
    // The transport schema pins length and alphabet; canonicality of the
    // final base64url symbol is checked here, before authentication.
    if !request_nonce_is_canonical(&request.request_nonce) {
        return Err(ProblemCode::MalformedRequest);
    }
    Ok(request)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ProblemCode> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(ProblemCode::AuthenticationFailed)?;
    if values.next().is_some() {
        return Err(ProblemCode::AuthenticationFailed);
    }
    let value = value
        .to_str()
        .map_err(|_| ProblemCode::AuthenticationFailed)?;
    // The HTTP authentication grammar matches the scheme case-insensitively.
    // The single-header, single-space, and token-value rules stay exact.
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(ProblemCode::AuthenticationFailed)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b',')
    {
        return Err(ProblemCode::AuthenticationFailed);
    }
    Ok(token)
}

fn has_exact_content_type(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none() && value.as_bytes() == expected.as_bytes()
}

fn content_length_exceeds(headers: &HeaderMap, maximum: usize) -> bool {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return true;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_none_or(|length| length > maximum as u64)
}

fn remaining(limit: Duration, started: Instant) -> Option<Duration> {
    limit.checked_sub(started.elapsed())
}

fn runtime_failure_response(failure: RuntimeFailure, operation: &str) -> Response {
    problem_response(failure.problem(), operation)
}

fn problem_response(code: ProblemCode, operation: &str) -> Response {
    let body = code.body(operation);
    let mut response = serialize_response(code.status(), PROBLEM_MEDIA_TYPE, &body)
        .unwrap_or_else(|| empty_response(StatusCode::INTERNAL_SERVER_ERROR));
    // The observation layer reads the code from here rather than from the
    // response body, so the operational record names the same reviewed error
    // category the caller was given without reparsing public bytes.
    response.extensions_mut().insert(code);
    if code == ProblemCode::AuthenticationFailed {
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer"),
        );
    }
    if code == ProblemCode::RateLimited {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_SECONDS));
    }
    response
}

fn serialize_response<T: Serialize>(
    status: StatusCode,
    media_type: &'static str,
    value: &T,
) -> Option<Response> {
    let bytes = serde_json::to_vec(value).ok()?;
    Some(bytes_response(status, media_type, bytes))
}

fn static_json_response(status: StatusCode, body: &'static str) -> Response {
    bytes_response(status, JSON_MEDIA_TYPE, body.as_bytes().to_vec())
}

fn bytes_response(status: StatusCode, media_type: &'static str, bytes: Vec<u8>) -> Response {
    let mut response = (status, Body::from(bytes)).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(media_type));
    response
}

fn empty_response(status: StatusCode) -> Response {
    (status, Body::empty()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[test]
    fn authorization_requires_one_unambiguous_bearer_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer three.parts.value"),
        );
        assert_eq!(
            bearer_token(&headers).expect("single bearer accepted"),
            "three.parts.value"
        );

        // The authentication scheme is case-insensitive per the HTTP grammar.
        for scheme in ["bearer", "BEARER", "BeArEr"] {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("{scheme} three.parts.value"))
                    .expect("test header is valid"),
            );
            assert_eq!(
                bearer_token(&headers).expect("case-insensitive scheme accepted"),
                "three.parts.value"
            );
        }

        for invalid in [
            "Basic three.parts.value",
            "Bearer",
            "Bearer  three.parts.value",
            "Bearer three.parts.value ",
            "Bearer three.parts.value,other",
        ] {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(invalid).expect("test header is valid"),
            );
            assert_eq!(
                bearer_token(&headers),
                Err(ProblemCode::AuthenticationFailed)
            );
        }

        headers.clear();
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer first"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
        assert_eq!(
            bearer_token(&headers),
            Err(ProblemCode::AuthenticationFailed)
        );
    }

    const TEST_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn request_json_is_strict_and_closed() {
        let valid = br#"{
            "requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "requirement":"urn:example:requirement:v1",
            "purpose":"review",
            "subjects":[{
                "role":"subject",
                "selector":{"profile":"opaque-v1","values":{"opaque":"value"}}
            }]
        }"#;
        assert!(parse_evidence_request(valid).is_ok());
        for number in ["1.0", "1e0"] {
            let request = r#"{"requestNonce":"NONCE","requirement":"urn:example:requirement:v1","purpose":"p","subjects":[{"role":"subject","selector":{"profile":"opaque-v1","values":{"opaque":NUMBER}}}]}"#
                .replace("NONCE", TEST_NONCE)
                .replace("NUMBER", number);
            let parsed = parse_evidence_request(request.as_bytes())
                .expect("schema-valid integral JSON number is accepted");
            assert_eq!(
                parsed.subjects[0]
                    .selector
                    .values
                    .as_ref()
                    .and_then(|values| values.get("opaque")),
                Some(&crate::model::SelectorValue::Integer(1))
            );
        }
        assert_eq!(
            parse_evidence_request(
                br#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requirement":"a","requirement":"b","purpose":"p","subjects":[]}"#
            ),
            Err(ProblemCode::MalformedRequest)
        );
        assert_eq!(
            parse_evidence_request(
                br#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requirement":"a","purpose":"p","subjects":[],"query":"hidden"}"#
            ),
            Err(ProblemCode::MalformedRequest)
        );

        let base = r#"{"requestNonce":"NONCE","requirement":"urn:example:requirement:v1","purpose":"p","subjects":[{"role":"subject","selector":{"profile":"opaque-v1","values":{"opaque":"value"}}}]}"#;
        for invalid in [
            base.replace("\"requestNonce\":\"NONCE\",", ""),
            base.replace("NONCE", ""),
            base.replace("NONCE", &"A".repeat(42)),
            base.replace("NONCE", &"A".repeat(44)),
            base.replace("NONCE", &format!("{}=", "A".repeat(42))),
            base.replace("NONCE", &format!("{}+", "A".repeat(42))),
            base.replace("NONCE", &format!("{}B", "A".repeat(42))),
            format!(
                r#"{{"requestNonce":"{TEST_NONCE}","requestNonce":"{TEST_NONCE}","requirement":"urn:example:requirement:v1","purpose":"p","subjects":[{{"role":"subject","selector":{{"profile":"opaque-v1","values":{{"opaque":"value"}}}}}}]}}"#
            ),
        ] {
            assert_eq!(
                parse_evidence_request(invalid.as_bytes()),
                Err(ProblemCode::MalformedRequest),
                "{invalid}"
            );
        }

        for invalid in [
            br#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requirement":"not a URI","purpose":"p","subjects":[{"role":"subject","selector":{"profile":"opaque-v1","values":{"opaque":"value"}}}]}"#.as_slice(),
            br#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requirement":"urn:example:requirement:v1","purpose":"Uppercase","subjects":[{"role":"subject","selector":{"profile":"opaque-v1","values":{"opaque":"value"}}}]}"#.as_slice(),
            br#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requirement":"urn:example:requirement:v1","purpose":"p","subjects":[]}"#.as_slice(),
            br#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requirement":"urn:example:requirement:v1","purpose":"p","subjects":[{"role":"Uppercase","selector":{"profile":"opaque-v1","values":{"opaque":"value"}}}]}"#.as_slice(),
            br#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requirement":"urn:example:requirement:v1","purpose":"p","subjects":[{"role":"subject","selector":{"profile":"opaque-v1","values":{}}}]}"#.as_slice(),
            br#"{"requestNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","requirement":"urn:example:requirement:v1","purpose":"p","subjects":[{"role":"subject","selector":{"profile":"opaque-v1","values":{"opaque":9007199254740992}}}]}"#.as_slice(),
        ] {
            assert_eq!(
                parse_evidence_request(invalid),
                Err(ProblemCode::MalformedRequest)
            );
        }
    }

    #[test]
    fn accept_negotiation_matrix_is_closed_and_exact() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            resolve_response_format(&headers),
            Ok(ResponseFormat::SignedJws)
        );

        for (value, expected) in [
            ("*/*", ResponseFormat::SignedJws),
            ("application/jose+json", ResponseFormat::SignedJws),
            (
                "application/vnd.registrystack.evidence-unsigned+json",
                ResponseFormat::UnsignedJson,
            ),
        ] {
            headers.insert(ACCEPT, HeaderValue::from_static(value));
            assert_eq!(resolve_response_format(&headers), Ok(expected), "{value}");
        }

        for invalid in [
            "application/json",
            "application/jose+json, application/json",
            "application/jose+json;q=0.9",
            "application/vnd.registrystack.evidence-unsigned+json; charset=utf-8",
            "application/*",
            "*/*;q=1",
            " application/jose+json",
            "APPLICATION/JOSE+JSON",
        ] {
            headers.insert(
                ACCEPT,
                HeaderValue::from_str(invalid).expect("test header is valid"),
            );
            assert_eq!(
                resolve_response_format(&headers),
                Err(ProblemCode::ResponseFormatNotAcceptable),
                "{invalid}"
            );
        }

        headers.clear();
        headers.append(ACCEPT, HeaderValue::from_static("application/jose+json"));
        headers.append(ACCEPT, HeaderValue::from_static("application/jose+json"));
        assert_eq!(
            resolve_response_format(&headers),
            Err(ProblemCode::ResponseFormatNotAcceptable)
        );
    }

    #[tokio::test]
    async fn problem_responses_have_closed_media_and_challenge_headers() {
        let authentication = problem_response(
            ProblemCode::AuthenticationFailed,
            "01K1EVIDENCEOPERATION0000000",
        );
        assert_eq!(authentication.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            authentication.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static(PROBLEM_MEDIA_TYPE))
        );
        assert_eq!(
            authentication
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static("Bearer"))
        );

        let rate = problem_response(ProblemCode::RateLimited, "01K1EVIDENCEOPERATION0000000");
        assert_eq!(rate.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rate.headers().get(RETRY_AFTER),
            Some(&HeaderValue::from_static(RETRY_AFTER_SECONDS))
        );
    }

    #[test]
    fn operation_ids_meet_the_audit_contract() {
        // The public `operation` field is frozen to a 26-character Crockford
        // Base32 ULID by the generated problem schema (^[0-9A-HJKMNP-TV-Z]{26}$).
        // Pin the producer to that exact shape so a future change (for example
        // swapping ULID for a hyphenated UUID) fails loudly here instead of
        // silently breaking the frozen contract.
        let operation = operation_id(&axum::http::Extensions::new());
        assert_operation_contract(&operation);
    }

    fn assert_operation_contract(operation: &str) {
        const CROCKFORD_UPPER: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        assert_eq!(operation.len(), 26, "operation id is a 26-character ULID");
        assert!(
            operation
                .bytes()
                .all(|byte| CROCKFORD_UPPER.contains(&byte)),
            "operation id uses only Crockford Base32 uppercase symbols"
        );
        // 26 lies inside the frozen 16..=128 audit-operation length range.
        assert!(!operation.bytes().any(|byte| byte.is_ascii_whitespace()));
    }

    #[tokio::test]
    async fn response_layers_apply_no_store_and_security_headers_without_hsts() {
        let app = response_layers(
            Router::new().route("/probe", get(|| async { StatusCode::NO_CONTENT })),
            Arc::new(Metrics::default()),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .body(Body::empty())
                    .expect("test request builds"),
            )
            .await
            .expect("infallible router responds");

        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            response.headers().get("x-frame-options"),
            Some(&HeaderValue::from_static("DENY"))
        );
        assert!(response
            .headers()
            .get("strict-transport-security")
            .is_none());
        // The identifier the caller can quote back is produced by the boundary
        // itself, so it must meet the same frozen shape as the audit field.
        assert_operation_contract(
            response
                .headers()
                .get(crate::observability::CORRELATION_HEADER)
                .expect("every response carries a correlation identifier")
                .to_str()
                .expect("the correlation header is ASCII"),
        );
    }

    #[tokio::test]
    async fn evaluation_tracker_drains_a_detached_task_without_a_missed_wakeup() {
        let tracker = EvaluationTracker::default();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let detached = tracker.spawn(async move {
            let _ = blocked.await;
        });
        drop(detached);

        let waiter = tokio::spawn({
            let tracker = tracker.clone();
            async move { tracker.wait_idle().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        release.send(()).expect("detached task is still running");
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("detached task drains")
            .expect("drain waiter does not panic");
    }
}
