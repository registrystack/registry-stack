//! `registry-render serve`: the HTTP rendering API. One POST endpoint, one GET
//! discovery endpoint, a private listener, resource-token auth, bounded body,
//! supervised worker renders, an audit request entry accepted before every
//! render starts, and an audit response entry accepted before every render
//! response, refusals included, whatever refusal class they are.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path as RoutePath, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use registry_platform_authcommon::{
    parse_bearer_token, validate_api_key_entropy, MIN_API_KEY_ENTROPY_BYTES,
};
use registry_platform_canonical_json::parse_json_preserving_integers;
use registry_platform_httpsec::{request_body_limit, security_headers, CspBuilder};

use crate::audit::{RenderAudit, RenderAuditEvent};
use crate::bundle::Bundle;
use crate::problem::{ProblemKind, RenderProblem, PROBLEM_TYPE_BASE};
use crate::runtime;
use crate::worker::{self, WorkerRendered, WorkerRequest};

pub struct Service {
    bundle: Bundle,
    audit: RenderAudit,
    api_key: Vec<u8>,
    oidc: Option<registry_platform_oidc::TokenVerifier>,
    caller_fingerprint: String,
    limits: crate::runtime::LimitsRuntime,
    bundle_path: PathBuf,
    concurrency: Arc<tokio::sync::Semaphore>,
    max_concurrency: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RenderHttpRequest {
    #[serde(default)]
    locale: Option<String>,
    /// Required: the document's issuance claim; the world clock. Read as
    /// optional so the refusal can be the dedicated issued-at-missing
    /// problem rather than a generic body error.
    issued_at: Option<String>,
    data: serde_json::Value,
    #[serde(default)]
    assets: Option<BTreeMap<String, String>>,
}

pub fn serve(runtime_path: &Path) -> Result<i32, RenderProblem> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| RenderProblem::new(ProblemKind::Internal, format!("runtime: {err}")))?;
    runtime.block_on(serve_async(runtime_path))
}

async fn serve_async(runtime_path: &Path) -> Result<i32, RenderProblem> {
    init_tracing();
    let (runtime, config_id) = runtime::load(runtime_path)?;
    let oidc = crate::auth::verifier(&runtime).await?;
    let api_key = if oidc.is_none() {
        normalize_api_key(runtime::resolve_secret(
            &runtime,
            runtime
                .auth
                .api_key_ref
                .as_deref()
                .expect("validated key mode"),
        )?)?
    } else {
        Vec::new()
    };
    if oidc.is_none() && api_key.len() < MIN_API_KEY_ENTROPY_BYTES {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("caller API key must be at least {MIN_API_KEY_ENTROPY_BYTES} bytes"),
        ));
    }
    if oidc.is_none() {
        validate_api_key_entropy(&String::from_utf8_lossy(&api_key)).map_err(|err| {
            RenderProblem::new(
                ProblemKind::RuntimeInvalid,
                format!("API key rejected: {err}"),
            )
        })?;
    }
    // The address is settled before the steps with side effects (opening
    // the audit destination creates its directory), so a refused bind
    // leaves nothing half-made behind.
    let bind: SocketAddr = runtime.listener.bind.socket_addr();
    if !runtime.listener.bind_allowed() {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            "listener.bind is outside the declared private network exposure",
        ));
    }
    let bundle = runtime::load_package(&runtime)?;
    crate::check::check_labels(&bundle)?;
    let audit = RenderAudit::open(runtime.audit.destination()?).await?;
    let service = Arc::new(Service {
        caller_fingerprint: registry_platform_authcommon::fingerprint_api_key(
            &String::from_utf8_lossy(&api_key),
        ),
        bundle,
        audit,
        api_key,
        oidc,
        limits: runtime.limits.clone(),
        bundle_path: runtime.package.root.clone(),
        concurrency: Arc::new(tokio::sync::Semaphore::new(
            runtime.limits.concurrent_renders(),
        )),
        max_concurrency: runtime.limits.concurrent_renders(),
    });
    tracing::info!(
        renderer = crate::display_version(),
        bundle = %service.bundle.bundle_hash,
        config = %config_id,
        "registry-render serve starting"
    );
    let listener = tokio::net::TcpListener::bind(bind).await.map_err(|err| {
        RenderProblem::new(ProblemKind::RuntimeInvalid, format!("bind {bind}: {err}"))
    })?;
    let app = router(Arc::clone(&service)).layer(axum::middleware::from_fn(lifecycle_log));
    let grace = runtime.listener.shutdown_grace();
    let drain_service = Arc::clone(&service);
    // The stop signal is observed once and broadcast, so the drain and the
    // hard bound below race the same event.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
    // The handler is installed here, not inside the task: a failure must
    // refuse startup. Installing it in the task could only panic there,
    // which ends the task alone and would leave a server that treats
    // SIGTERM as an immediate exit with renders in flight.
    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|err| {
            RenderProblem::new(
                ProblemKind::Internal,
                format!("cannot install the SIGTERM handler: {err}"),
            )
        })?;
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        let _ = stop_tx.send(());
    });
    // Phase 1 — drain: the graceful-shutdown future holds the server open
    // until every render permit is back (up to grace), so renders in
    // flight finish before the listener stops accepting.
    let mut stop_for_drain = stop_rx.clone();
    let shutdown = async move {
        let _ = stop_for_drain.changed().await;
        let service = drain_service;
        let drained = tokio::time::timeout(grace, async {
            while service.concurrency.available_permits() < service.max_concurrency {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                grace_milliseconds = grace.as_millis(),
                "shutdown grace elapsed with renders in flight; moving to connection teardown"
            );
        }
    };
    // Phase 2 — bounded teardown: after the shutdown future resolves, axum
    // waits for open connections; that wait gets one more grace. Dropping
    // the serve future at the bound is what actually abandons stragglers —
    // their request futures drop, which kills their workers (kill_on_drop).
    let mut stop_for_bound = stop_rx;
    let bound = async move {
        let _ = stop_for_bound.changed().await;
        tokio::time::sleep(grace + grace).await;
    };
    let outcome = tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown) => Some(result),
        _ = bound => None,
    };
    match outcome {
        Some(Ok(())) => {}
        Some(Err(err)) => {
            return Err(RenderProblem::new(
                ProblemKind::Internal,
                format!("server: {err}"),
            ))
        }
        None => tracing::warn!(
            grace_milliseconds = grace.as_millis(),
            "shutdown window elapsed with connections still open; abandoning them (their workers are killed)"
        ),
    }
    tracing::info!("registry-render serve stopped");
    Ok(0)
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("registry_render=info"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn router(service: Arc<Service>) -> Router {
    // API routes authenticate before anything buffers the body. Inside
    // auth: the body ceiling refuses as an audited RFC 9457 problem (with
    // the tower stream limit as the backstop for chunked or under-declared
    // bodies). Health, ready, and the OpenAPI document stay anonymous.
    let api = Router::new()
        .route("/v1/documents", get(documents))
        // `any`, not `post`: a wrong method must answer with the problem
        // vocabulary (and an audit event), not axum's bare 405.
        .route("/v1/render/{type}", any(render_route))
        .layer(request_body_limit(service.limits.request_bytes()))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&service),
            refuse_oversized_bodies,
        ))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&service),
            require_bearer,
        ));
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/openapi.json", get(openapi))
        .merge(api)
        .fallback(not_found)
        .with_state(service)
        .layer(security_headers(CspBuilder::restrictive()))
}

/// Authentication as a layer: it runs before the handler (and so before
/// the body extractor buffers anything), and every refusal is audited as
/// one response entry, with caller-controlled fields bounded and
/// shape-checked first, because the audit log is append-only.
async fn require_bearer(
    State(service): State<Arc<Service>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let caller = match authorized(&service, request.headers()).await {
        Ok(caller) => caller,
        Err(error) => {
            use crate::auth::AuthenticationError;
            let kind = match error {
                AuthenticationError::Refused => ProblemKind::Unauthorized,
                AuthenticationError::Forbidden => ProblemKind::Forbidden,
                AuthenticationError::Unavailable => ProblemKind::AuthenticationUnavailable,
            };
            let problem = RenderProblem::new(kind, "Render access could not be authorized");
            let target = sanitize_route_target(request.uri().path());
            let correlation = correlation_id(request.headers());
            let trace = trace_id(request.headers());
            let event = RenderAuditEvent::refused(
                &target,
                &problem,
                "unknown",
                correlation.as_deref(),
                trace.as_deref(),
            );
            let envelope = crate::audit::correlation();
            if let Err(audit_problem) = service.audit.response(&envelope, event).await {
                return problem_response(&audit_problem, trace.as_deref());
            }
            return problem_response(&problem, trace.as_deref());
        }
    };
    request.extensions_mut().insert(Caller(caller));
    next.run(request).await
}

#[derive(Clone)]
struct Caller(String);

/// Post-auth body-framing refusal, before any body byte is read (a healthy
/// connection can still be answered here): a declared Content-Length beyond
/// the configured limit, or a chunked body at all — this fixed-size JSON API
/// has no chunked callers, and once a chunked stream trips the tower limit
/// mid-body the connection is broken and no response can be delivered at
/// all. Either refusal is an audited RFC 9457 problem. The tower stream
/// limit directly beneath this middleware remains the last-ditch backstop;
/// a mid-stream abort there closes the connection (documented residual).
async fn refuse_oversized_bodies(
    State(service): State<Arc<Service>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let limit = service.limits.request_bytes();
    let problem = if request.headers().get(header::TRANSFER_ENCODING).is_some() {
        Some(RenderProblem::new(
            ProblemKind::InvalidArgument,
            "request bodies must carry Content-Length; chunked transfer is not accepted",
        ))
    } else {
        request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|declared| declared > limit)
            .then(|| {
                RenderProblem::new(
                    ProblemKind::BodyTooLarge,
                    format!("request body exceeds the configured limit of {limit} bytes"),
                )
            })
    };
    let Some(problem) = problem else {
        return next.run(request).await;
    };
    let target = sanitize_route_target(request.uri().path());
    let correlation = correlation_id(request.headers());
    let event = RenderAuditEvent::refused(
        &target,
        &problem,
        &request
            .extensions()
            .get::<Caller>()
            .expect("auth middleware precedes body checks")
            .0,
        correlation.as_deref(),
        trace_id(request.headers()).as_deref(),
    );
    let envelope = crate::audit::correlation();
    if let Err(audit_problem) = service.audit.response(&envelope, event).await {
        tracing::error!(problem = %audit_problem, "413 audit append failed");
    }
    problem_response(&problem, trace_id(request.headers()).as_deref())
}

/// The audit event's document id for pre-auth refusals: the route's last
/// segment for render calls, the literal route for discovery, always
/// bounded and kebab-checked.
fn sanitize_route_target(path: &str) -> String {
    let raw = path.rsplit('/').next().unwrap_or("unknown");
    sanitize_document_type(raw)
}

/// One value-free lifecycle line per request: method class, route
/// template, status, latency, trace id — the operability contract.
async fn lifecycle_log(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let context = registry_platform_httpsec::TraceContext::from_headers(request.headers());
    context.apply(request.headers_mut());
    let method = operational_method(request.method());
    let template = route_template(request.uri().path());
    let started = std::time::Instant::now();
    let trace = trace_id(request.headers()).unwrap_or_else(|| "none".to_owned());
    let mut response = next.run(request).await;
    context.apply(response.headers_mut());
    tracing::info!(
        target: "registry_render::http",
        method,
        route = %template,
        status = response.status().as_u16(),
        latency_milliseconds = started.elapsed().as_millis() as u64,
        trace_id = %trace,
        "request completed"
    );
    response
}

fn operational_method(method: &axum::http::Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        _ => "OTHER",
    }
}

fn route_template(path: &str) -> &'static str {
    match path {
        "/health" => "/health",
        "/ready" => "/ready",
        "/openapi.json" => "/openapi.json",
        "/v1/documents" => "/v1/documents",
        p if p.starts_with("/v1/render/") => "/v1/render/{type}",
        _ => "other",
    }
}

/// HTTP callers receive fixed, value-free guidance. Operator diagnostics stay
/// with the local CLI and audit boundary; the problem code identifies recovery.
fn problem_response(problem: &RenderProblem, trace: Option<&str>) -> Response {
    let mut context = registry_platform_httpsec::TraceContext::server_created();
    if let Some(trace_id) =
        trace.and_then(|value| registry_platform_httpsec::TraceId::parse(value).ok())
    {
        context.trace_id = trace_id;
    }
    let body = registry_platform_httpsec::ProblemBody {
        type_uri: format!("{}/{}", PROBLEM_TYPE_BASE, problem.kind.slug()),
        title: problem.kind.slug(),
        status: problem.kind.http_status(),
        detail: match problem.kind {
            ProblemKind::Unauthorized => "Present a valid bearer credential for this Render resource.",
            ProblemKind::Forbidden => "Obtain a Render resource credential with the render:render scope.",
            ProblemKind::AuthenticationUnavailable => "Credential verification is unavailable; retry when the issuer keys are available.",
            ProblemKind::NotFound => "Use a route exposed by this Render adapter.",
            ProblemKind::InvalidArgument => "Check the request method, Content-Length, JSON body, and document type.",
            ProblemKind::BodyTooLarge => "Reduce the request body to the configured size limit.",
            ProblemKind::AuditFailed => "The audit destination is unavailable; contact the operator before retrying.",
            ProblemKind::RateLimited => "The renderer is at capacity; retry later.",
            _ => "The render request was refused; use the problem code and the operator diagnostics to correct it.",
        },
        code: problem.kind.http_code(),
        trace_id: context.trace_id.clone(),
    };
    let status = StatusCode::from_u16(body.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut value = serde_json::to_value(body).expect("fixed problem serializes");
    // JSON pointers are bounded structural diagnostics, never request values.
    if !problem.pointers.is_empty() {
        value["pointers"] = serde_json::json!(problem
            .pointers
            .iter()
            .take(32)
            .map(|pointer| pointer.chars().take(256).collect::<String>())
            .collect::<Vec<_>>());
    }
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if problem.kind == ProblemKind::Unauthorized {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    context.apply(response.headers_mut());
    response
}

async fn not_found(headers: HeaderMap) -> Response {
    problem_response(
        &RenderProblem::new(ProblemKind::NotFound, "route not found"),
        trace_id(&headers).as_deref(),
    )
}

async fn health(State(service): State<Arc<Service>>) -> Response {
    // Versions operators reconcile against, value-free.
    let body = serde_json::json!({
        "status": "ok",
        "bundleVersion": service.bundle.manifest.bundle_version,
        "bundleHash": service.bundle.bundle_hash,
        "rendererVersion": crate::display_version(),
        "typstPin": crate::TYPST_PIN,
    });
    Json(body).into_response()
}

async fn ready(State(service): State<Arc<Service>>) -> Response {
    let keys_ready = match &service.oidc {
        Some(verifier) => verifier.key_source().ensure_key_set().await.is_ok(),
        None => true,
    };
    if keys_ready && service.audit.ready().await {
        minimal_json(StatusCode::OK, "{\"status\":\"ready\"}")
    } else {
        minimal_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "{\"status\":\"not-ready\"}",
        )
    }
}

fn minimal_json(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

async fn openapi() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        crate::openapi::OPENAPI_JSON,
    )
        .into_response()
}

async fn documents(State(service): State<Arc<Service>>) -> Response {
    let documents: Vec<serde_json::Value> = service
        .bundle
        .documents
        .values()
        .map(|doc| {
            serde_json::json!({
                "id": doc.spec.id,
                "version": doc.spec.version,
                "entry": doc.spec.entry.to_string_lossy(),
                "labels": doc.spec.labels,
                "pdfStandard": doc.spec.pdf_standard.map(|s| s.to_string()),
                "schema": doc.spec.schema.as_ref().map(|p| p.to_string_lossy()),
            })
        })
        .collect();
    let body = serde_json::json!({
        "documents": documents,
        "bundleVersion": service.bundle.manifest.bundle_version,
        "bundleHash": service.bundle.bundle_hash,
        "rendererVersion": crate::display_version(),
        "typstPin": crate::TYPST_PIN,
    });
    Json(body).into_response()
}

/// Exactly one trailing line ending is trimmed from the caller API key (the
/// newline every editor and `echo` appends — the same normalization the
/// platform applies to fingerprint files). Anything beyond that is a startup
/// error: a silently mis-armed key would refuse every caller while `/health`
/// stays green.
fn normalize_api_key(raw: Vec<u8>) -> Result<Vec<u8>, RenderProblem> {
    let refuse = |detail: String| RenderProblem::new(ProblemKind::RuntimeInvalid, detail);
    let text = String::from_utf8(raw)
        .map_err(|_| refuse("caller API key must be ASCII text".to_owned()))?;
    let text = registry_platform_authcommon::trim_one_line_ending(text);
    if text.is_empty() {
        return Err(refuse("caller API key is empty".to_owned()));
    }
    if text.chars().any(char::is_whitespace) {
        return Err(refuse(
            "caller API key contains whitespace beyond one trailing line ending; fix the key file"
                .to_owned(),
        ));
    }
    Ok(text.into_bytes())
}

async fn authorized(
    service: &Service,
    headers: &HeaderMap,
) -> Result<String, crate::auth::AuthenticationError> {
    use crate::auth::AuthenticationError;
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(AuthenticationError::Refused)?;
    if values.next().is_some() {
        return Err(AuthenticationError::Refused);
    }
    let token = parse_bearer_token(value.to_str().map_err(|_| AuthenticationError::Refused)?)
        .map_err(|_| AuthenticationError::Refused)?;
    if let Some(verifier) = &service.oidc {
        return crate::auth::authenticate(verifier, token).await;
    }
    let expected = service.api_key.as_slice();
    let presented = token.as_bytes();
    (presented.len() == expected.len() && bool::from(presented.ct_eq(expected)))
        .then(|| service.caller_fingerprint.clone())
        .ok_or(AuthenticationError::Refused)
}

/// Caller-supplied trace id from a W3C traceparent header, fully
/// validated: exactly one header, `00-<32hex>-<16hex>-<2hex>`. Anything
/// else yields no trace id rather than a partially-trusted one.
fn trace_id(headers: &HeaderMap) -> Option<String> {
    let mut all = headers.get_all("traceparent").iter();
    let value = all.next()?.to_str().ok()?;
    if all.next().is_some() {
        return None;
    }
    let is_lower_hex = |text: &str| {
        text.len() == 32
            && text
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    };
    let mut parts = value.split('-');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("00"), Some(trace), Some(_span), Some(_flags), None) if is_lower_hex(trace) => {
            Some(trace.to_owned())
        }
        _ => None,
    }
}

fn correlation_id(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("idempotency-key")?.to_str().ok()?;
    let bounded: String = value.chars().take(128).collect();
    (!bounded.is_empty()).then_some(bounded)
}

async fn render_route(
    State(service): State<Arc<Service>>,
    RoutePath(document_type): RoutePath<String>,
    axum::Extension(Caller(caller)): axum::Extension<Caller>,
    headers: HeaderMap,
    method: Method,
    body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let document_type = sanitize_document_type(&document_type);
    let trace = trace_id(&headers);
    let correlation = correlation_id(&headers);
    // One server-drawn envelope correlation joins this call's request and
    // response entries; the caller's key is only echoed in the record.
    let envelope = crate::audit::correlation();

    if method != Method::POST {
        return refuse(
            &service,
            &document_type,
            RenderProblem::new(ProblemKind::InvalidArgument, "use POST"),
            &caller,
            &envelope,
            correlation.as_deref(),
            trace.as_deref(),
        )
        .await;
    }
    // The stream-side body limit (chunked or under-declared lengths) fails
    // the extraction here; it gets the same audited problem the declared
    // Content-Length path produces, never a plain-text 413.
    let body = match body {
        Ok(bytes) => bytes,
        Err(rejection) => {
            let problem = body_rejection_problem(&rejection);
            return refuse(
                &service,
                &document_type,
                problem,
                &caller,
                &envelope,
                correlation.as_deref(),
                trace.as_deref(),
            )
            .await;
        }
    };
    let (worker_request, document_version) = match prepare_render(&service, &document_type, &body) {
        Ok(prepared) => prepared,
        Err(problem) => {
            return refuse(
                &service,
                &document_type,
                problem,
                &caller,
                &envelope,
                correlation.as_deref(),
                trace.as_deref(),
            )
            .await;
        }
    };
    let started = RenderAuditEvent::started(
        &document_type,
        document_version,
        service.bundle.manifest.bundle_version,
        &service.bundle.bundle_hash,
        &caller,
        correlation.as_deref(),
        trace.as_deref(),
    );
    // The request entry is accepted before the render starts; a refused one
    // means the render never starts and no response entry follows. A call
    // dropped from here on writes its unfinished response.
    let _request = match service.audit.request(&envelope, started.clone()).await {
        Ok(request) => request,
        Err(audit_problem) => return problem_response(&audit_problem, trace.as_deref()),
    };
    // The answer is built before its response entry, so the entry records
    // the outcome the caller actually receives.
    let outcome = run_render(&service, worker_request)
        .await
        .and_then(|rendered| {
            let event = RenderAuditEvent {
                document_id: document_type.clone(),
                document_version: rendered.document_version,
                bundle_version: rendered.bundle_version,
                bundle_hash: rendered.bundle_hash.clone(),
                outcome: Some("rendered"),
                problem: None,
                pdf_sha256: Some(rendered.pdf_sha256.clone()),
                data_sha256: Some(rendered.data_sha256.clone()),
                caller,
                correlation_id: correlation.clone(),
                trace_id: trace.clone(),
                renderer_version: crate::display_version(),
                typst_pin: crate::TYPST_PIN.to_owned(),
            };
            Ok((event, respond_rendered(&headers, rendered)?))
        });
    let (event, outcome) = match outcome {
        Ok((event, response)) => (event, Ok(response)),
        Err(problem) => (started.refused_after_start(&problem), Err(problem)),
    };
    // The response entry is accepted before anything leaves: audit failure
    // fails closed and withholds the document.
    if let Err(audit_problem) = service.audit.response(&envelope, event).await {
        return problem_response(&audit_problem, trace.as_deref());
    }
    match outcome {
        Ok(mut response) => {
            if let Some(correlation) = correlation
                .as_ref()
                .and_then(|c| header::HeaderValue::from_str(c).ok())
            {
                response
                    .headers_mut()
                    .insert("idempotency-key", correlation);
            }
            response
        }
        Err(problem) => problem_response(&problem, trace.as_deref()),
    }
}

/// Refuse one render call before any render starts: audit the refusal as
/// one response entry (accepted before responding, failing closed), then
/// answer with the problem document.
async fn refuse(
    service: &Service,
    document_type: &str,
    problem: RenderProblem,
    caller: &str,
    envelope: &str,
    correlation: Option<&str>,
    trace: Option<&str>,
) -> Response {
    let event = RenderAuditEvent::refused(document_type, &problem, caller, correlation, trace);
    if let Err(audit_problem) = service.audit.response(envelope, event).await {
        return problem_response(&audit_problem, trace);
    }
    problem_response(&problem, trace)
}

/// Map a failed body extraction to the problem vocabulary: the tower
/// stream limit's rejection is the body ceiling; anything else is a
/// malformed request.
fn body_rejection_problem(rejection: &axum::extract::rejection::BytesRejection) -> RenderProblem {
    let text = rejection.body_text();
    if text.contains("length limit exceeded") {
        RenderProblem::new(
            ProblemKind::BodyTooLarge,
            "request body exceeds the configured limit (chunked or under-declared length)",
        )
    } else {
        RenderProblem::new(
            ProblemKind::InvalidArgument,
            format!("request body could not be read: {text}"),
        )
    }
}

/// Everything decided before a render starts: the request parses, carries
/// an issuance time, and names a document the bundle declares. Returns the
/// worker request and the document's declared version.
fn prepare_render(
    service: &Service,
    document_type: &str,
    body: &[u8],
) -> Result<(WorkerRequest, u32), RenderProblem> {
    let value = parse_json_preserving_integers(body).map_err(|err| {
        RenderProblem::new(ProblemKind::InvalidArgument, format!("request body: {err}"))
    })?;
    let request: RenderHttpRequest = serde_json::from_value(value).map_err(|err| {
        RenderProblem::new(ProblemKind::InvalidArgument, format!("request body: {err}"))
    })?;
    let Some(issued_at) = request.issued_at.filter(|s| !s.trim().is_empty()) else {
        return Err(RenderProblem::new(
            ProblemKind::IssuedAtMissing,
            "issuedAt is required; it is the document's issuance claim and the render clock",
        ));
    };
    if issued_at.trim().is_empty() {
        return Err(RenderProblem::new(
            ProblemKind::IssuedAtMissing,
            "issuedAt is required; it is the document's issuance claim and the render clock",
        ));
    }
    // Existence check; the worker re-loads and re-checks.
    let document_version = service.bundle.document(document_type)?.spec.version;
    let worker_request = WorkerRequest {
        bundle: service.bundle_path.clone(),
        document: document_type.to_owned(),
        locale: request.locale,
        data: request.data,
        assets: request.assets.unwrap_or_default(),
        issued_at,
        strict: false,
        require_package: true,
        max_output_bytes: service.limits.output_bytes(),
        memory_limit_bytes: 512 * 1024 * 1024,
    };
    Ok((worker_request, document_version))
}

/// Run one prepared render on a supervised worker, once a render slot is
/// free.
async fn run_render(
    service: &Service,
    worker_request: WorkerRequest,
) -> Result<WorkerRendered, RenderProblem> {
    let permit = service
        .concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| RenderProblem::new(ProblemKind::Internal, "concurrency latch closed"))?;
    let timeout = service.limits.render_timeout();
    let result = worker::supervise(worker_request, timeout).await;
    drop(permit);
    // The worker already rendered from one verified immutable snapshot. Its
    // package digest must also be the one serve started with, not merely
    // a different valid package installed during the request.
    match result {
        Ok(rendered) if rendered.bundle_hash != service.bundle.bundle_hash => {
            Err(RenderProblem::new(
                ProblemKind::BundleTampered,
                "the package changed under serve; refusing the render from a drifted package",
            ))
        }
        other => other,
    }
}

/// Route parameters are caller-controlled even before authentication, so
/// anything that reaches the audit log is bounded and shape-checked first:
/// the log is append-only and must not be a write oracle.
fn sanitize_document_type(raw: &str) -> String {
    const MAX: usize = 64;
    let bounded: String = raw.chars().take(MAX).collect();
    let valid = !bounded.is_empty()
        && bounded.len() <= MAX
        && bounded
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if valid {
        bounded
    } else {
        "invalid".to_owned()
    }
}

fn respond_rendered(
    headers: &HeaderMap,
    rendered: WorkerRendered,
) -> Result<Response, RenderProblem> {
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| {
            accept.contains("application/json") && !accept.contains("application/pdf")
        });
    if accepts_json {
        let body = serde_json::json!({
            "pdfBase64": rendered.pdf_base64,
            "pdfSha256": rendered.pdf_sha256,
            "dataSha256": rendered.data_sha256,
            "documentVersion": format!("{} v{}", rendered.document_id, rendered.document_version),
            "warnings": rendered.warnings,
        });
        return Ok(Json(body).into_response());
    }
    let pdf = base64::engine::general_purpose::STANDARD
        .decode(&rendered.pdf_base64)
        .map_err(|_| {
            RenderProblem::new(
                ProblemKind::Internal,
                "worker returned an undecodable PDF; refusing to serve an empty document",
            )
        })?;
    let mut response = (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/pdf"),
        )],
        pdf,
    )
        .into_response();
    let map = response.headers_mut();
    insert_header(map, "X-Registry-Pdf-Sha256", &rendered.pdf_sha256);
    insert_header(map, "X-Registry-Data-Sha256", &rendered.data_sha256);
    insert_header(
        map,
        "X-Registry-Warning-Count",
        &rendered.warnings.len().to_string(),
    );
    insert_header(
        map,
        "X-Registry-Document-Version",
        &format!("{} v{}", rendered.document_id, rendered.document_version),
    );
    Ok(response)
}

fn insert_header(map: &mut header::HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        header::HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        map.insert(name, value);
    }
}

/// `registry-render healthcheck`: one plain HTTP GET against /health.
pub fn healthcheck(runtime_path: &Path) -> Result<i32, RenderProblem> {
    let (runtime, _) = runtime::load(runtime_path)?;
    let address = runtime.listener.bind.socket_addr().to_string();
    let stream = std::net::TcpStream::connect(&address).map_err(|err| {
        RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("cannot connect to {address}: {err}"),
        )
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut stream = stream;
    use std::io::Write as _;
    write!(
        &mut stream,
        "GET /health HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|err| {
        RenderProblem::new(ProblemKind::RuntimeInvalid, format!("healthcheck: {err}"))
    })?;
    let mut response = String::new();
    std::io::Read::read_to_string(&mut stream, &mut response).ok();
    if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
        println!("healthy at {address}");
        Ok(0)
    } else {
        Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("health endpoint at {address} did not answer 200"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_responses_report_warning_count_without_warning_text() {
        for warnings in [vec![], vec!["canary warning\r\nprivate detail".to_owned()]] {
            let count = warnings.len().to_string();
            let rendered = WorkerRendered {
                document_id: "receipt".to_owned(),
                pdf_base64: base64::engine::general_purpose::STANDARD.encode(b"%PDF-test"),
                pdf_sha256: "a".repeat(64),
                data_sha256: "b".repeat(64),
                document_version: 1,
                bundle_version: 1,
                bundle_hash: "c".repeat(64),
                deps: vec![],
                warnings,
            };
            let response = respond_rendered(&HeaderMap::new(), rendered).unwrap();
            assert_eq!(response.headers()["x-registry-warning-count"], count);
            assert!(!format!("{:?}", response.headers()).contains("canary"));
        }
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use registry_platform_audit::AuditWriter;
    use tower::ServiceExt as _;

    const TEST_API_KEY: &str = "unit-key-0123456789abcdef0123456789abcdef";

    /// An in-memory audit destination handed to the production writer. It
    /// keeps every accepted line and refuses the Nth line (1-based) when
    /// asked to, after which the writer stops as it would on a failed file.
    #[derive(Clone)]
    struct AuditLines {
        accepted: Arc<Mutex<Vec<serde_json::Value>>>,
        written: Arc<AtomicUsize>,
        refuse_line: Option<usize>,
    }

    impl AuditLines {
        fn new(refuse_line: Option<usize>) -> Self {
            Self {
                accepted: Arc::new(Mutex::new(Vec::new())),
                written: Arc::new(AtomicUsize::new(0)),
                refuse_line,
            }
        }

        fn accepted(&self) -> Vec<serde_json::Value> {
            self.accepted.lock().expect("audit lines").clone()
        }
    }

    impl std::io::Write for AuditLines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let line = self.written.fetch_add(1, Ordering::SeqCst) + 1;
            if self.refuse_line == Some(line) {
                return Err(std::io::Error::other("audit destination refused the line"));
            }
            let entry = serde_json::from_slice(buf).expect("one JSON line per write");
            self.accepted.lock().expect("audit lines").push(entry);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A service over the packaged receipt bundle with `permits` render slots.
    /// Zero slots means a render can never start: any request that reaches
    /// the render step waits there forever.
    fn service(lines: &AuditLines, permits: usize) -> Arc<Service> {
        let bundle_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/render/bundles/receipt");
        let verified = registry_platform_config::package::verify_package(
            &bundle_path,
            &runtime::package_limits(),
            "registry-render package",
        )
        .expect("packaged receipt bundle");
        let bundle =
            Bundle::load_package(&bundle_path, &verified).expect("packaged receipt bundle");
        Arc::new(Service {
            bundle,
            audit: RenderAudit::new(AuditWriter::from_line_sink(Box::new(lines.clone()))),
            api_key: TEST_API_KEY.as_bytes().to_vec(),
            oidc: None,
            caller_fingerprint: "caller-fingerprint".to_owned(),
            limits: runtime::LimitsRuntime::default(),
            bundle_path,
            concurrency: Arc::new(tokio::sync::Semaphore::new(permits)),
            max_concurrency: permits,
        })
    }

    #[tokio::test]
    async fn oidc_router_accepts_resource_token_and_refuses_with_common_problem() {
        use axum::body::to_bytes;
        use tower::ServiceExt as _;
        let lines = AuditLines::new(None);
        let mut service = service(&lines, 1);
        Arc::get_mut(&mut service)
            .expect("fixture owns service")
            .oidc = Some(crate::auth::tests::test_verifier());
        for (overrides, status) in [
            (serde_json::json!({}), StatusCode::OK),
            (
                serde_json::json!({"aud":["urn:other","urn:render:test"],"registry_grant_id":"canary-unrelated"}),
                StatusCode::OK,
            ),
            (serde_json::json!({"scope":"other"}), StatusCode::FORBIDDEN),
            (
                serde_json::json!({"aud":"urn:other"}),
                StatusCode::UNAUTHORIZED,
            ),
            (serde_json::json!({"exp":1}), StatusCode::UNAUTHORIZED),
        ] {
            let app = router(Arc::clone(&service)).layer(axum::middleware::from_fn(lifecycle_log));
            let request = axum::http::Request::builder()
                .uri("/v1/documents")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", crate::auth::tests::token(overrides)),
                )
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), status);
            if status != StatusCode::OK {
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                if status == StatusCode::UNAUTHORIZED {
                    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
                } else {
                    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
                }
                let trace = registry_platform_httpsec::response_trace_id(response.headers())
                    .unwrap()
                    .to_owned();
                assert_eq!(
                    response.headers()[header::CONTENT_TYPE],
                    "application/problem+json"
                );
                let body = to_bytes(response.into_body(), 16384).await.unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["traceId"], trace.as_str());
                assert_eq!(
                    body["code"],
                    if status == StatusCode::UNAUTHORIZED {
                        "render.unauthorized"
                    } else {
                        "render.forbidden"
                    }
                );
                assert!(body["detail"]
                    .as_str()
                    .is_some_and(|detail| !detail.is_empty()));
                assert!(!String::from_utf8_lossy(&body.to_string().into_bytes())
                    .contains("canary-principal"));
            }
        }
    }

    #[tokio::test]
    async fn fallback_has_the_same_complete_safe_problem_envelope() {
        use axum::body::to_bytes;
        use tower::ServiceExt as _;
        let lines = AuditLines::new(None);
        let response = router(service(&lines, 1))
            .oneshot(
                axum::http::Request::builder()
                    .uri("/canary-unknown-route")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let trace = registry_platform_httpsec::response_trace_id(response.headers())
            .unwrap()
            .to_owned();
        let body = to_bytes(response.into_body(), 16384).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["detail"]
            .as_str()
            .is_some_and(|detail| !detail.is_empty()));
        assert_eq!(body["traceId"], trace.as_str());
        assert_eq!(body["code"], "render.not-found");
        assert!(!body.to_string().contains("canary-unknown-route"));
    }

    #[tokio::test]
    async fn issuer_outage_distinguishes_unavailable_from_refused_and_respects_cached_keys() {
        use axum::body::to_bytes;
        use std::sync::atomic::AtomicBool;
        let available = Arc::new(AtomicBool::new(false));
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/jwks", origin.local_addr().unwrap());
        let keys_app = Router::new()
            .route(
                "/jwks",
                get(|State(available): State<Arc<AtomicBool>>| async move {
                    if available.load(Ordering::SeqCst) {
                        Json(crate::auth::tests::test_jwks()).into_response()
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE.into_response()
                    }
                }),
            )
            .with_state(Arc::clone(&available));
        let keys_server = tokio::spawn(async move {
            axum::serve(origin, keys_app).await.unwrap();
        });
        let lines = AuditLines::new(None);
        let mut service = service(&lines, 1);
        let mut config = registry_platform_oidc::JwksFetcherConfig::defaults();
        config.cache_ttl = Duration::from_millis(1);
        config.refresh_cooldown = Duration::ZERO;
        config.outage_tolerance = Duration::from_secs(30);
        let fetch_policy = registry_platform_oidc::IssuerNetworkPolicy::new(&url, true)
            .unwrap()
            .declared_jwks_fetch_policy();
        Arc::get_mut(&mut service).unwrap().oidc =
            Some(crate::auth::tests::test_verifier_over(Arc::new(
                registry_platform_oidc::JwksFetcher::new_with_fetch_url_policy(
                    url,
                    config,
                    fetch_policy,
                ),
            )));
        let credential = crate::auth::tests::token(serde_json::json!({}));
        for (keys_available, status) in [
            (false, StatusCode::SERVICE_UNAVAILABLE),
            (true, StatusCode::OK),
            (false, StatusCode::OK),
        ] {
            available.store(keys_available, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(2)).await;
            for route in ["/ready", "/v1/documents"] {
                let request = axum::http::Request::builder()
                    .uri(route)
                    .header(header::AUTHORIZATION, format!("Bearer {credential}"))
                    .body(axum::body::Body::empty())
                    .unwrap();
                let response = router(Arc::clone(&service)).oneshot(request).await.unwrap();
                assert_eq!(
                    response.status(),
                    status,
                    "{route}, keys available: {keys_available}"
                );
                if route == "/v1/documents" && status == StatusCode::SERVICE_UNAVAILABLE {
                    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
                    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                    let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
                    let problem: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(problem["code"], "render.authentication-unavailable");
                    assert!(!problem.to_string().contains("canary-principal"));
                }
            }
        }
        keys_server.abort();
    }

    #[tokio::test]
    async fn oidc_audit_contains_only_the_canonical_credential_fingerprint() {
        let lines = AuditLines::new(None);
        let mut service = service(&lines, 1);
        Arc::get_mut(&mut service).unwrap().oidc = Some(crate::auth::tests::test_verifier());
        for id in ["canary-first", "canary-second"] {
            let credential = crate::auth::tests::token(serde_json::json!({"jti":id}));
            let request = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/v1/render/receipt")
                .header(header::AUTHORIZATION, format!("Bearer {credential}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, 11)
                .body(axum::body::Body::from(r#"{"data":{}}"#))
                .unwrap();
            let response = router(Arc::clone(&service)).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let records = lines.accepted.lock().unwrap();
            let record = records.last().expect("audited refusal").to_string();
            assert!(
                record.contains(&registry_platform_authcommon::fingerprint_api_key(
                    &credential
                ))
            );
            for protected in [
                &credential,
                "canary-principal",
                "issuer.example.test",
                "portal",
                id,
            ] {
                assert!(
                    !record.contains(protected),
                    "protected credential claims are absent"
                );
            }
        }
    }

    fn render_request(idempotency_key: Option<&str>) -> axum::extract::Request {
        let data = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/render/bundles/receipt/fixtures/data.json"),
        )
        .expect("receipt fixture");
        let body = format!(r#"{{"issuedAt":"2026-09-16T10:32:00Z","data":{data}}}"#);
        let mut builder = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/render/receipt")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_API_KEY}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, body.len());
        if let Some(key) = idempotency_key {
            builder = builder.header("idempotency-key", key);
        }
        builder.body(axum::body::Body::from(body)).expect("request")
    }

    #[tokio::test]
    async fn the_request_entry_is_accepted_before_the_render_starts() {
        let lines = AuditLines::new(None);
        let service = service(&lines, 0);
        let pending = tokio::time::timeout(
            Duration::from_millis(500),
            router(Arc::clone(&service)).oneshot(render_request(Some("effect-1234"))),
        )
        .await;
        assert!(
            pending.is_err(),
            "with no render slot free the request must be waiting at the render step"
        );
        service.audit.wait_for_detached_entries();
        let accepted = lines.accepted();
        // The call dropped while it waited for a render slot, as a canceled
        // request is: its request entry is paired with an unfinished
        // response, and nothing else was written.
        assert_eq!(accepted.len(), 2, "{accepted:?}");
        let entry = &accepted[0];
        assert_eq!(entry["schema"], crate::audit::AUDIT_SCHEMA);
        assert_eq!(entry["phase"], "request");
        let correlation = entry["correlation"].as_str().expect("correlation");
        assert_eq!(correlation.len(), 36, "a drawn correlation: {correlation}");
        assert_eq!(accepted[1]["phase"], "response");
        assert_eq!(accepted[1]["correlation"], correlation);
        assert_eq!(accepted[1]["record"]["outcome"], "unfinished");
        let record = &entry["record"];
        assert!(
            record.get("outcome").is_none(),
            "a request entry carries no outcome: {record}"
        );
        assert_eq!(record["documentId"], "receipt");
        assert_eq!(record["documentVersion"], 3);
        assert_eq!(
            record["bundleVersion"],
            service.bundle.manifest.bundle_version
        );
        assert_eq!(record["bundleHash"], service.bundle.bundle_hash.as_str());
        assert_eq!(record["caller"], "caller-fingerprint");
        assert_eq!(record["correlationId"], "effect-1234");
        assert_eq!(record["rendererVersion"], crate::display_version());
        assert_eq!(record["typstPin"], crate::TYPST_PIN);
    }

    #[tokio::test]
    async fn a_refused_request_entry_prevents_the_render() {
        let lines = AuditLines::new(Some(1));
        let service = service(&lines, 0);
        // Zero render slots: reaching the render step would wait forever, so
        // an answer inside the bound proves the render never started.
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            router(Arc::clone(&service)).oneshot(render_request(None)),
        )
        .await
        .expect("a refused request entry answers without waiting for a render slot")
        .expect("router");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("problem body");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("audit-failed"), "{text}");
        assert_eq!(
            lines.written.load(Ordering::SeqCst),
            1,
            "no response entry follows a refused request entry"
        );
        assert!(lines.accepted().is_empty());
    }

    #[tokio::test]
    async fn a_refusal_before_the_render_is_one_response_entry() {
        let lines = AuditLines::new(None);
        let service = service(&lines, 0);
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/render/receipt")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_API_KEY}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", "effect-5678")
            .body(axum::body::Body::from(r#"{"data":{}}"#))
            .expect("request");
        let response = router(service).oneshot(request).await.expect("router");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let accepted = lines.accepted();
        assert_eq!(accepted.len(), 1, "{accepted:?}");
        assert_eq!(accepted[0]["phase"], "response");
        assert_ne!(accepted[0]["correlation"], "effect-5678");
        assert_eq!(accepted[0]["record"]["correlationId"], "effect-5678");
        assert_eq!(accepted[0]["record"]["outcome"], "refused");
        assert_eq!(accepted[0]["record"]["problem"], "issued-at-missing");
    }

    #[tokio::test]
    async fn a_duplicate_member_nested_in_data_is_refused_before_rendering() {
        let lines = AuditLines::new(None);
        let service = service(&lines, 1);
        let data = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/render/bundles/receipt/fixtures/data.json"),
        )
        .expect("receipt fixture");
        let duplicated = data.replacen(
            "\"reference\":",
            "\"reference\":\"shadowed\",\"reference\":",
            1,
        );
        let body = format!(r#"{{"issuedAt":"2026-09-16T10:32:00Z","data":{duplicated}}}"#);
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/render/receipt")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_API_KEY}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .expect("request");

        let response = router(service).oneshot(request).await.expect("router");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("problem body");
        let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON problem body");
        assert_eq!(
            problem["type"],
            "https://render.registrystack.org/problems/invalid-argument"
        );
        assert_eq!(problem["title"], "invalid-argument");

        let accepted = lines.accepted();
        assert_eq!(accepted.len(), 1, "{accepted:?}");
        assert_eq!(accepted[0]["phase"], "response");
        assert_eq!(accepted[0]["record"]["outcome"], "refused");
        assert_eq!(accepted[0]["record"]["problem"], "invalid-argument");
    }

    #[tokio::test]
    async fn a_refusal_after_the_render_starts_keeps_the_render_identity() {
        let lines = AuditLines::new(None);
        let service = service(&lines, 1);
        // A closed latch fails the render step after the request entry.
        service.concurrency.close();
        let response = router(Arc::clone(&service))
            .oneshot(render_request(Some("effect-9012")))
            .await
            .expect("router");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let accepted = lines.accepted();
        assert_eq!(accepted.len(), 2, "{accepted:?}");
        let entry = &accepted[1];
        assert_eq!(entry["phase"], "response");
        assert_eq!(entry["correlation"], accepted[0]["correlation"]);
        let record = &entry["record"];
        assert_eq!(record["correlationId"], "effect-9012");
        assert_eq!(record["outcome"], "refused");
        assert_eq!(record["problem"], "internal");
        assert_eq!(record["documentId"], "receipt");
        assert_eq!(record["documentVersion"], 3);
        assert_eq!(
            record["bundleVersion"],
            service.bundle.manifest.bundle_version
        );
        assert_eq!(record["bundleHash"], service.bundle.bundle_hash.as_str());
    }

    #[test]
    fn the_envelope_correlation_is_always_drawn_by_the_server() {
        let drawn = crate::audit::correlation();
        assert_eq!(drawn.len(), 36, "a random UUID: {drawn}");
        assert_ne!(drawn, crate::audit::correlation());
    }

    /// Two calls that carry the same caller key still pair unambiguously:
    /// the key is the caller's own reference, never the journal's join.
    #[tokio::test]
    async fn concurrent_calls_sharing_an_idempotency_key_pair_their_own_entries() {
        let lines = AuditLines::new(None);
        let service = service(&lines, 2);
        let (first, second) = tokio::join!(
            router(Arc::clone(&service)).oneshot(render_request(Some("shared-key"))),
            router(Arc::clone(&service)).oneshot(render_request(Some("shared-key"))),
        );
        // Whatever each call's outcome, both reach the render step.
        assert_eq!(
            first.expect("router").status(),
            second.expect("router").status()
        );
        let accepted = lines.accepted();
        assert_eq!(accepted.len(), 4, "{accepted:?}");
        let mut correlations = std::collections::BTreeMap::<String, Vec<String>>::new();
        for entry in &accepted {
            assert_eq!(entry["record"]["correlationId"], "shared-key");
            correlations
                .entry(
                    entry["correlation"]
                        .as_str()
                        .expect("correlation")
                        .to_owned(),
                )
                .or_default()
                .push(entry["phase"].as_str().expect("phase").to_owned());
        }
        assert_eq!(
            correlations.len(),
            2,
            "one correlation per call: {correlations:?}"
        );
        for phases in correlations.values() {
            assert_eq!(phases, &["request", "response"]);
        }
    }
}
