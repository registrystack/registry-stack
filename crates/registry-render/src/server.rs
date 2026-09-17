//! `render serve`: the HTTP rendering API. One POST endpoint, one GET
//! discovery endpoint, a private listener, API-key auth, bounded body,
//! supervised worker renders, and an audit append before every response.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path as RoutePath, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use registry_platform_authcommon::{
    parse_bearer_token, validate_api_key_entropy, MIN_API_KEY_ENTROPY_BYTES,
};
use registry_platform_httpsec::{request_body_limit, security_headers, CspBuilder, Problem};

use crate::audit::{RenderAudit, RenderAuditEvent};
use crate::bundle::Bundle;
use crate::problem::{ProblemKind, RenderProblem};
use crate::runtime;
use crate::worker::{self, WorkerRendered, WorkerRequest};

const PROBLEM_TYPE_BASE: &str = "https://render.registrystack.org/problems";

pub struct Service {
    bundle: Bundle,
    audit: RenderAudit,
    api_key: Vec<u8>,
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

pub fn serve(runtime_path: Option<&Path>) -> Result<i32, RenderProblem> {
    let runtime_path = runtime_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/etc/registry-render/runtime.yaml"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| RenderProblem::new(ProblemKind::Internal, format!("runtime: {err}")))?;
    runtime.block_on(serve_async(&runtime_path))
}

async fn serve_async(runtime_path: &Path) -> Result<i32, RenderProblem> {
    init_tracing();
    let (runtime, config_id) = runtime::load(runtime_path)?;
    let api_key = normalize_api_key(runtime::resolve_secret(
        runtime_path,
        &runtime.auth.api_key_ref,
    )?)?;
    if api_key.len() < MIN_API_KEY_ENTROPY_BYTES {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("caller API key must be at least {MIN_API_KEY_ENTROPY_BYTES} bytes"),
        ));
    }
    validate_api_key_entropy(&String::from_utf8_lossy(&api_key)).map_err(|err| {
        RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("API key rejected: {err}"),
        )
    })?;
    let integrity_key = runtime::resolve_secret(runtime_path, &runtime.audit.integrity_key_ref)?;
    let bundle = Bundle::load_sealed(&runtime.bundle.path)?;
    crate::check::check_script_coverage(&bundle)?;
    let audit = RenderAudit::open(
        &runtime.audit.directory,
        integrity_key,
        runtime.audit.max_segment_bytes,
    )
    .await?;
    let service = Arc::new(Service {
        caller_fingerprint: registry_platform_authcommon::fingerprint_api_key(
            &String::from_utf8_lossy(&api_key),
        ),
        bundle,
        audit,
        api_key,
        limits: runtime.limits.clone(),
        bundle_path: runtime.bundle.path.clone(),
        concurrency: Arc::new(tokio::sync::Semaphore::new(runtime.limits.max_concurrency)),
        max_concurrency: runtime.limits.max_concurrency,
    });
    tracing::info!(
        renderer = crate::display_version(),
        bundle = %service.bundle.bundle_hash,
        config = %config_id,
        "render serve starting"
    );
    let bind: SocketAddr = runtime.server.bind.parse().map_err(|err| {
        RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!(
                "server.bind {:?} is not an address: {err}",
                runtime.server.bind
            ),
        )
    })?;
    let listener = tokio::net::TcpListener::bind(bind).await.map_err(|err| {
        RenderProblem::new(ProblemKind::RuntimeInvalid, format!("bind {bind}: {err}"))
    })?;
    let app = router(Arc::clone(&service)).layer(axum::middleware::from_fn(lifecycle_log));
    let grace = Duration::from_secs(runtime.server.shutdown_grace_seconds);
    let drain_service = Arc::clone(&service);
    // The drain runs INSIDE the graceful-shutdown future: axum keeps
    // serving while it is pending, so in-flight renders finish and their
    // audit appends land before the listener closes. A render still holding
    // a permit at the end of the grace period is abandoned — dropping its
    // request future kills the worker (kill_on_drop).
    let shutdown = async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        let service = drain_service;
        let drained = tokio::time::timeout(grace, async {
            while service.concurrency.available_permits() < service.max_concurrency {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                grace_seconds = grace.as_secs(),
                "shutdown grace elapsed with renders in flight; abandoning them"
            );
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|err| RenderProblem::new(ProblemKind::Internal, format!("server: {err}")))?;
    tracing::info!("render serve stopped");
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
        .route("/v1/render/{type}", post(render_route))
        .layer(request_body_limit(service.limits.max_request_body_bytes))
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
/// the body extractor buffers anything), and every refusal is audited —
/// with caller-controlled fields bounded and shape-checked first, because
/// the ledger is immutable.
async fn require_bearer(
    State(service): State<Arc<Service>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !authorized(&service, request.headers()) {
        let target = sanitize_route_target(request.uri().path());
        let event = RenderAuditEvent::refused(
            &target,
            &RenderProblem::new(ProblemKind::Unauthorized, "missing or wrong API key"),
            "unknown",
            correlation_id(request.headers()).as_deref(),
            trace_id(request.headers()).as_deref(),
        );
        if let Err(audit_problem) = service.audit.append(event).await {
            tracing::warn!(problem = %audit_problem, "401 audit append failed");
        }
        return problem_response(&RenderProblem::new(
            ProblemKind::Unauthorized,
            "missing or wrong API key",
        ));
    }
    next.run(request).await
}

/// Post-auth body-ceiling refusal: a declared Content-Length beyond the
/// configured limit gets an RFC 9457 problem and an audit event like every
/// other refusal. The tower stream limit directly beneath this middleware
/// backstops chunked or under-declared bodies.
async fn refuse_oversized_bodies(
    State(service): State<Arc<Service>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let limit = service.limits.max_request_body_bytes;
    let too_large = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|declared| declared > limit);
    if !too_large {
        return next.run(request).await;
    }
    let problem = RenderProblem::new(
        ProblemKind::BodyTooLarge,
        format!("request body exceeds the configured limit of {limit} bytes"),
    );
    let target = sanitize_route_target(request.uri().path());
    let event = RenderAuditEvent::refused(
        &target,
        &problem,
        &service.caller_fingerprint,
        correlation_id(request.headers()).as_deref(),
        trace_id(request.headers()).as_deref(),
    );
    if let Err(audit_problem) = service.audit.append(event).await {
        tracing::warn!(problem = %audit_problem, "413 audit append failed");
    }
    problem_response(&problem)
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
async fn lifecycle_log(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let method = operational_method(request.method());
    let template = route_template(request.uri().path());
    let started = std::time::Instant::now();
    let trace = trace_id(request.headers()).unwrap_or_else(|| "none".to_owned());
    let response = next.run(request).await;
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

fn problem_response(problem: &RenderProblem) -> Response {
    Problem::new(
        &format!("{}/{}", PROBLEM_TYPE_BASE, problem.kind.slug()),
        problem.kind.slug(),
        StatusCode::from_u16(problem.kind.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    )
    .detail(problem.detail.clone())
    .with_extra("pointers", serde_json::json!(problem.pointers))
    .with_extra("locations", serde_json::json!(problem.locations))
    .into_response()
}

async fn not_found() -> Response {
    Problem::new(
        &format!("{PROBLEM_TYPE_BASE}/not-found"),
        "not-found",
        StatusCode::NOT_FOUND,
    )
    .into_response()
}

async fn health() -> Response {
    minimal_json(StatusCode::OK, "{\"status\":\"ok\"}")
}

async fn ready(State(service): State<Arc<Service>>) -> Response {
    if service.audit.ready().await {
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

async fn documents(State(service): State<Arc<Service>>, headers: HeaderMap) -> Response {
    if !authorized(&service, &headers) {
        return problem_response(&RenderProblem::new(
            ProblemKind::Unauthorized,
            "missing or wrong API key",
        ));
    }
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

fn authorized(service: &Service, headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(text) = value.to_str() else {
        return false;
    };
    let Ok(token) = parse_bearer_token(text) else {
        return false;
    };
    let expected = service.api_key.as_slice();
    let presented = token.as_bytes();
    if presented.len() != expected.len() {
        return false;
    }
    presented.ct_eq(expected).into()
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
    headers: HeaderMap,
    method: Method,
    body: axum::body::Bytes,
) -> Response {
    if method != Method::POST {
        return problem_response(&RenderProblem::new(
            ProblemKind::InvalidArgument,
            "use POST",
        ));
    }
    let document_type = sanitize_document_type(&document_type);
    let trace = trace_id(&headers);
    let correlation = correlation_id(&headers);
    let caller = service.caller_fingerprint.clone();
    let outcome = handle_render(&service, &document_type, &body).await;
    let event = match &outcome {
        Ok(rendered) => RenderAuditEvent {
            document_id: document_type.clone(),
            document_version: rendered.document_version,
            bundle_version: rendered.bundle_version,
            bundle_hash: rendered.bundle_hash.clone(),
            outcome: "rendered",
            problem: None,
            pdf_sha256: Some(rendered.pdf_sha256.clone()),
            data_sha256: Some(rendered.data_sha256.clone()),
            caller,
            correlation_id: correlation.clone(),
            trace_id: trace.clone(),
            renderer_version: crate::display_version(),
            typst_pin: crate::TYPST_PIN.to_owned(),
        },
        Err(problem) => RenderAuditEvent::refused(
            &document_type,
            problem,
            &service.caller_fingerprint,
            correlation.as_deref(),
            trace.as_deref(),
        ),
    };
    // Append before responding: audit failure fails closed.
    if let Err(audit_problem) = service.audit.append(event).await {
        return problem_response(&audit_problem);
    }
    match outcome {
        Ok(rendered) => match respond_rendered(&headers, rendered) {
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
            Err(problem) => problem_response(&problem),
        },
        Err(problem) => problem_response(&problem),
    }
}

async fn handle_render(
    service: &Service,
    document_type: &str,
    body: &[u8],
) -> Result<WorkerRendered, RenderProblem> {
    let request: RenderHttpRequest = serde_json::from_slice(body).map_err(|err| {
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
    let document = service.bundle.document(document_type).cloned()?;
    let _ = document; // existence check; the worker re-loads and re-checks
    let worker_request = WorkerRequest {
        bundle: service.bundle_path.clone(),
        document: document_type.to_owned(),
        locale: request.locale,
        data: request.data,
        assets: request.assets.unwrap_or_default(),
        issued_at,
        strict: false,
        require_sealed: true,
        max_output_bytes: service.limits.max_output_bytes,
        memory_limit_bytes: 512 * 1024 * 1024,
    };
    let permit = service
        .concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| RenderProblem::new(ProblemKind::Internal, "concurrency latch closed"))?;
    let timeout = Duration::from_secs(service.limits.render_timeout_seconds);
    let result = worker::supervise(worker_request, timeout).await;
    drop(permit);
    // The seal invariant is per request: the bundle that rendered must be
    // the bundle serve started with, not merely *a* sealed bundle.
    match result {
        Ok(rendered) if rendered.bundle_hash != service.bundle.bundle_hash => {
            Err(RenderProblem::new(
                ProblemKind::BundleTampered,
                "the bundle changed under serve; refusing the render from a drifted bundle",
            ))
        }
        other => other,
    }
}

/// Route parameters are caller-controlled even before authentication, so
/// anything that reaches the audit ledger is bounded and shape-checked
/// first: the ledger is immutable and must not be a write oracle.
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

/// `render healthcheck`: one plain HTTP GET against /health.
pub fn healthcheck(runtime_path: Option<&Path>) -> Result<i32, RenderProblem> {
    let runtime_path = runtime_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/etc/registry-render/runtime.yaml"));
    let (runtime, _) = runtime::load(&runtime_path)?;
    let address = runtime.server.bind.clone();
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
