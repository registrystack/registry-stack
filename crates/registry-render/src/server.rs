//! `registry-render serve`: the HTTP rendering API. One POST endpoint, one GET
//! discovery endpoint, a private listener, resource-token auth, bounded body,
//! supervised worker renders, an audit request entry accepted before every
//! render starts, and an audit response entry accepted before every render
//! response, refusals included, whatever refusal class they are.
//!
//! With a `signing` block, a second POST endpoint, `/v1/seal/{type}`, renders
//! the same request and returns it sealed (PAdES). The route exists only
//! when the runtime file declares seals: without one it is not mounted, the
//! served OpenAPI document omits it, and `/ready` carries no `signing`
//! member, so a deployment that does not seal is unchanged. It requires the
//! `render:seal` scope, which `render:render` does not imply, and a client
//! the seal's `allowedClients` names; the legacy API key never seals.

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
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use registry_platform_authcommon::{
    parse_bearer_token, validate_api_key_entropy, BearerParseError, DeclaredScope, FailedCheck,
    RefusalNote, RefusalRecorder, MIN_API_KEY_ENTROPY_BYTES,
};
use registry_platform_canonical_json::parse_json_preserving_integers;
use registry_platform_config::{DeclaredPosture, PostureReport};
use registry_platform_httpsec::{request_body_limit, security_headers, CspBuilder};
use registry_platform_httputil::{validate_response_headers, PeerPolicy};

use crate::audit::{RenderAudit, RenderAuditEvent};
use crate::auth::{RENDER_SCOPE, SCOPE_CLAIM, SEAL_SCOPE};
use crate::bundle::Bundle;
use crate::hash::sha256_label;
use crate::metrics::{Metrics, Operation, METRICS_PATH};
use crate::problem::{ProblemKind, RenderProblem, PROBLEM_TYPE_BASE};
use crate::runtime;
use crate::seal::{Seal, SealedDocument, Seals};
use crate::worker::{self, WorkerRendered, WorkerRequest};

pub struct Service {
    posture: PostureReport,
    bundle: Bundle,
    audit: RenderAudit,
    api_key: Vec<u8>,
    oidc: Option<registry_platform_oidc::TokenVerifier>,
    caller_fingerprint: String,
    limits: crate::runtime::LimitsRuntime,
    bundle_path: PathBuf,
    concurrency: Arc<tokio::sync::Semaphore>,
    max_concurrency: usize,
    /// The loaded seals by seal id; empty without a `signing` block.
    seals: Seals,
    /// Places for seals in flight, as many as render slots: a seal releases
    /// its render slot before it signs and waits on the timestamp authority.
    seals_in_flight: Arc<tokio::sync::Semaphore>,
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

pub fn serve(runtime_path: &Path, declared: DeclaredPosture) -> Result<i32, RenderProblem> {
    mark_not_dumpable()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| RenderProblem::new(ProblemKind::Internal, format!("runtime: {err}")))?;
    runtime.block_on(serve_async(runtime_path, declared))
}

/// On Linux, marks the serving process non-dumpable before it reads any
/// secret: it writes no core dump, and another process running as the same
/// user, a compromised render worker included, cannot read its `/proc`
/// environment or memory or attach to it. A worker is a fresh executable and
/// does not inherit the mark.
#[cfg(target_os = "linux")]
pub(crate) fn mark_not_dumpable() -> Result<(), RenderProblem> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).map_err(
        |err| {
            RenderProblem::new(
                ProblemKind::Internal,
                format!("cannot mark the serving process non-dumpable: {err}"),
            )
        },
    )
}

/// Nothing to mark here. macOS has no `/proc`, but a same-user process reads
/// another process's arguments and environment through `KERN_PROCARGS2`,
/// and nothing here closes that: on macOS a worker that gained code
/// execution can read the serving process's environment.
#[cfg(not(target_os = "linux"))]
pub(crate) fn mark_not_dumpable() -> Result<(), RenderProblem> {
    Ok(())
}

pub(crate) async fn load_service(
    runtime_path: &Path,
    declared: DeclaredPosture,
) -> Result<(runtime::RenderRuntime, String, Arc<Service>), RenderProblem> {
    let (mut loaded, positions) = runtime::load_with_positions(runtime_path, declared)?;
    let runtime = loaded.config;
    let config_id = loaded.effective_digest;
    let oidc = crate::auth::verifier(&runtime).await?;
    let api_key = if oidc.is_none() {
        normalize_api_key(runtime::resolve_secret(
            &runtime,
            runtime
                .authentication
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
    if !runtime.listener.bind_allowed() {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            "listener.bind is outside the declared private network exposure",
        ));
    }
    if let Err(cause) = runtime.check_metrics_listener() {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!(
                "metricsListener.bind is refused: {cause}. {}",
                cause.remedy(runtime::METRICS_NETWORK_EXPOSURE_KEY)
            ),
        ));
    }
    let bundle = runtime::load_package(&runtime)?;
    crate::check::check_labels(&bundle)?;
    let diagnostics = runtime::record_seal_binding_posture(
        &runtime,
        &bundle.manifest,
        runtime_path,
        &mut loaded.posture,
    );
    for diagnostic in diagnostics {
        if diagnostic.severity == registry_platform_yaml::Severity::Error {
            return Err(RenderProblem::new(
                ProblemKind::RuntimeInvalid,
                "the bundle and runtime combination was refused",
            )
            .with_diagnostics(vec![diagnostic]));
        }
        tracing::warn!(code = %diagnostic.code, pointer = %diagnostic.path, "{}", diagnostic.message);
    }
    loaded.posture.log_startup();
    for warning in runtime::validate_seal_bindings(&runtime, &bundle.manifest)? {
        tracing::warn!(
            code = %warning.code,
            pointer = %warning.path,
            "{}",
            warning.message
        );
    }
    // Seals load before the audit opens: a refused chain or key leaves
    // nothing half-made behind. A document type whose PDF standard cannot
    // hold its seal's reserved signature space is refused here, before any
    // render could write a nonconformant file.
    let seals = crate::seal::load(&runtime, loaded.development.as_ref(), peer_policy(declared))
        .await
        .map_err(|problem| positions.place(problem))?;
    drop(positions);
    crate::seal::refuse_unsealable(&bundle, &seals)?;
    // Plain rendering starts whatever a seal's state; these lines are where
    // an operator learns a seal cannot sign, or soon cannot, without polling
    // `/ready`. Each names the seal id and a value-free reason only.
    let now = time::OffsetDateTime::now_utc();
    for (id, seal) in &seals {
        if !seal.allows_document_signing_purpose() {
            tracing::warn!(
                target: "registry_render::seal",
                seal_id = %id,
                "seal certificate purpose excludes document signing"
            );
        }
        match seal.availability(now) {
            Err(unavailable) => tracing::warn!(
                target: "registry_render::seal",
                seal_id = %id,
                reason = unavailable.reason(),
                "seal unavailable"
            ),
            Ok(()) if seal.expires_soon(now) => tracing::warn!(
                target: "registry_render::seal",
                seal_id = %id,
                "seal certificate expiring"
            ),
            Ok(()) => {}
        }
    }
    let audit = RenderAudit::open(runtime.audit.destination()?, declared.posture).await?;
    let service = Arc::new(Service {
        posture: loaded.posture,
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
        seals,
        seals_in_flight: Arc::new(tokio::sync::Semaphore::new(
            runtime.limits.concurrent_renders(),
        )),
    });
    Ok((runtime, config_id, service))
}

async fn serve_async(runtime_path: &Path, declared: DeclaredPosture) -> Result<i32, RenderProblem> {
    init_tracing();
    let (runtime, config_id, service) = load_service(runtime_path, declared).await?;
    let bind: SocketAddr = runtime.listener.bind.socket_addr();
    tracing::info!(
        renderer = crate::display_version(),
        bundle = %service.bundle.bundle_hash,
        config = %config_id,
        "registry-render serve starting"
    );
    let listener = tokio::net::TcpListener::bind(bind).await.map_err(|err| {
        RenderProblem::new(ProblemKind::RuntimeInvalid, format!("bind {bind}: {err}"))
    })?;
    let metrics = Arc::new(Metrics::default());
    // Both sockets bind before either serves, so a metrics address already
    // in use refuses startup rather than leaving a runtime nobody can scrape.
    let metrics_listener = match &runtime.metrics_listener {
        Some(metrics_listener) => {
            let metrics_bind = metrics_listener.bind.socket_addr();
            Some(
                tokio::net::TcpListener::bind(metrics_bind)
                    .await
                    .map_err(|err| {
                        RenderProblem::new(
                            ProblemKind::RuntimeInvalid,
                            format!("bind metrics listener {metrics_bind}: {err}"),
                        )
                    })?,
            )
        }
        None => None,
    };
    let app = public_app(Arc::clone(&service), &metrics);
    let grace = runtime.listener.shutdown_grace();
    let drain_service = Arc::clone(&service);
    // The stop signal is observed once and broadcast, so the drain and the
    // hard bound below race the same event.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
    // The handlers are installed here, not inside the task: a failure must
    // refuse startup. Installing them in the task could only fail there,
    // which would leave a server that treats SIGTERM as an immediate exit
    // with renders in flight.
    let stop_signal = stop_signal_after(registry_platform_httpsec::shutdown_signal)?;
    tokio::spawn(async move {
        stop_signal.await;
        let _ = stop_tx.send(());
    });
    // Phase 1 — drain: the graceful-shutdown future holds the server open
    // until every render permit and every seal place is back (up to grace),
    // so renders and seals in flight finish before the listener stops
    // accepting. A seal waiting on its timestamp authority holds no render
    // permit, only its seal place.
    let mut stop_for_drain = stop_rx.clone();
    let shutdown = async move {
        let _ = stop_for_drain.changed().await;
        let service = drain_service;
        let drained = tokio::time::timeout(grace, async {
            while service.concurrency.available_permits() < service.max_concurrency
                || service.seals_in_flight.available_permits() < service.max_concurrency
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                grace_milliseconds = grace.as_millis(),
                "shutdown grace elapsed with renders or seals in flight; moving to connection teardown"
            );
        }
    };
    // Phase 2 — bounded teardown: after the shutdown future resolves, axum
    // waits for open connections; that wait gets one more grace. Dropping
    // the serve future at the bound is what actually abandons stragglers —
    // their request futures drop, which kills their workers (kill_on_drop).
    let stop_for_bound_metrics = stop_rx.clone();
    let mut stop_for_bound = stop_rx;
    let bound = async move {
        let _ = stop_for_bound.changed().await;
        tokio::time::sleep(grace + grace).await;
    };
    // The metrics listener stops on the same signal. It holds no render, so
    // it needs no drain, and a scrape in flight is not worth a grace period.
    let metrics_server = metrics_listener.map(|listener| {
        let app = metrics_router(Arc::clone(&service), metrics);
        let mut stop_for_metrics = stop_for_bound_metrics;
        tokio::spawn(async move {
            // A listener that fails while the runtime serves is reported when
            // it fails, not at shutdown. The document listener keeps serving.
            if let Err(err) = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stop_for_metrics.changed().await;
                })
                .await
            {
                tracing::error!(error = %err, "the metrics listener failed");
            }
        })
    });
    let outcome = tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown) => Some(result),
        _ = bound => None,
    };
    if let Some(metrics_server) = metrics_server {
        match tokio::time::timeout(grace, metrics_server).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::error!(error = %err, "the metrics listener stopped unexpectedly");
            }
            Err(_) => tracing::warn!("the metrics listener did not stop within the grace"),
        }
    }
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

/// Install the stop-signal handlers (SIGTERM and Ctrl-C) with `install`. A
/// failure refuses startup, so the server is never left with no way to drain
/// on a stop request.
fn stop_signal_after<I, S>(install: I) -> Result<S, RenderProblem>
where
    I: FnOnce() -> std::io::Result<S>,
{
    install().map_err(|err| {
        RenderProblem::new(
            ProblemKind::Internal,
            format!("cannot install the stop signal handlers: {err}"),
        )
    })
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("registry_render=info"))
        .add_directive(
            "registry_platform_config::posture=info"
                .parse()
                .expect("posture log directive"),
        );
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

pub(crate) fn router(service: Arc<Service>) -> Router {
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
            require_render_bearer,
        ));
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/openapi.json", get(openapi))
        .merge(api);
    // The seal route exists only with seals: without a signing block it
    // falls to the not-found fallback like any other unknown route. Its scope
    // is its own layer, so neither route's scope reaches the other.
    if !service.seals.is_empty() {
        let seal_api = Router::new()
            .route("/v1/seal/{type}", any(seal_route))
            .layer(request_body_limit(service.limits.request_bytes()))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&service),
                refuse_oversized_bodies,
            ))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&service),
                require_seal_bearer,
            ));
        app = app.merge(seal_api);
    }
    let posture = service.posture.posture();
    app.fallback(not_found)
        .with_state(service)
        .layer(security_headers(CspBuilder::restrictive(), posture))
}

/// The public application: the router under the request log, the refusal
/// recording and the document counter.
fn public_app(service: Arc<Service>, metrics: &Arc<Metrics>) -> Router {
    router(service)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(metrics.refusal_recorder()),
            record_refusals,
        ))
        .layer(axum::middleware::from_fn(lifecycle_log))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(metrics),
            count_documents,
        ))
}

/// The caller guidance a credential without `render:seal` receives on the
/// seal route.
const SEAL_SCOPE_GUIDANCE: &str = "Obtain a Render resource credential with the render:seal scope.";
/// The caller guidance the legacy API key receives on the seal route.
const LEGACY_KEY_GUIDANCE: &str =
    "The legacy API key cannot seal; present an OIDC resource credential with the render:seal scope.";

async fn require_render_bearer(
    State(service): State<Arc<Service>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    require_bearer(service, request, next, RENDER_SCOPE).await
}

async fn require_seal_bearer(
    State(service): State<Arc<Service>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    require_bearer(service, request, next, SEAL_SCOPE).await
}

/// Authentication as a layer: it runs before the handler (and so before
/// the body extractor buffers anything), and every refusal is audited as
/// one response entry, with caller-controlled fields bounded and
/// shape-checked first, because the audit log is append-only. `scope` is
/// the one scope the route requires.
async fn require_bearer(
    service: Arc<Service>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
    scope: &'static str,
) -> Response {
    let caller = match authorized(&service, request.headers(), scope).await {
        Ok(caller) => caller,
        Err(error) => {
            use crate::auth::AuthenticationError;
            let check = error.failed_check();
            let (kind, caller) = match error {
                AuthenticationError::Refused(_) => {
                    (ProblemKind::Unauthorized, "unknown".to_owned())
                }
                AuthenticationError::Forbidden {
                    caller_fingerprint, ..
                } => (ProblemKind::Forbidden, caller_fingerprint),
                AuthenticationError::Unavailable => {
                    (ProblemKind::AuthenticationUnavailable, "unknown".to_owned())
                }
            };
            let mut problem = RenderProblem::new(kind, "Render access could not be authorized");
            if problem.kind == ProblemKind::Forbidden && scope == SEAL_SCOPE {
                problem = problem.with_public_detail(SEAL_SCOPE_GUIDANCE);
            }
            let (path, headers) = (request.uri().path(), request.headers());
            let mut response =
                refuse_access(&service, path, headers, &problem, &caller, check).await;
            if check == FailedCheck::Scope {
                response.extensions_mut().insert(declared_scope(scope));
            }
            return response;
        }
    };
    // The legacy API key never seals. The runtime already refuses a signing
    // block without OIDC, so this holds even if that check is bypassed.
    if scope == SEAL_SCOPE && service.oidc.is_none() {
        let problem = RenderProblem::new(ProblemKind::Forbidden, "the legacy API key cannot seal")
            .with_public_detail(LEGACY_KEY_GUIDANCE);
        let (path, headers) = (request.uri().path(), request.headers());
        return refuse_access(
            &service,
            path,
            headers,
            &problem,
            &caller.fingerprint,
            FailedCheck::Operation,
        )
        .await;
    }
    request.extensions_mut().insert(caller);
    next.run(request).await
}

/// Audit an access refusal as one response entry, then answer with it. The
/// answer carries the check that refused the caller for the recording layer.
async fn refuse_access(
    service: &Service,
    path: &str,
    headers: &HeaderMap,
    problem: &RenderProblem,
    caller: &str,
    check: FailedCheck,
) -> Response {
    let target = sanitize_route_target(path);
    let correlation = correlation_id(headers);
    let trace = trace_id(headers);
    let event = RenderAuditEvent::refused(
        &target,
        problem,
        caller,
        correlation.as_deref(),
        trace.as_deref(),
    );
    let envelope = crate::audit::correlation();
    if let Err(audit_problem) = service.audit.response(&envelope, event).await {
        return problem_response(&audit_problem, trace.as_deref());
    }
    refusal_response(problem, trace.as_deref(), check)
}

/// A refusal answer with the check that refused the caller in its response
/// extensions, which are never serialized.
fn refusal_response(problem: &RenderProblem, trace: Option<&str>, check: FailedCheck) -> Response {
    let mut response = problem_answer(problem, trace);
    response.extensions_mut().insert(RefusalNote::new(check));
    response
}

/// The values the operator declared for a scope refusal: the claim Render
/// reads scopes from and the scope the route requires. Nothing here comes
/// from the caller's token.
fn declared_scope(required_scope: &str) -> DeclaredScope {
    DeclaredScope::new(SCOPE_CLAIM).with_required_scope(required_scope)
}

/// Count each refusal answer under its check and write the admitted log line.
/// The trace id is the one the answer carries.
async fn record_refusals(
    State(refusals): State<Arc<RefusalRecorder>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let response = next.run(request).await;
    if let Some(note) = response.extensions().get::<RefusalNote>() {
        let declared = response.extensions().get::<DeclaredScope>();
        match registry_platform_httpsec::response_trace_id(response.headers()) {
            Ok(trace) => {
                registry_platform_authcommon::record_refusal!(
                    refusals,
                    *note,
                    trace_id = trace,
                    declared = declared
                );
            }
            Err(_) => {
                registry_platform_authcommon::record_refusal!(refusals, *note, declared = declared);
            }
        }
    }
    response
}

/// The verified caller of an API route.
#[derive(Clone)]
struct Caller {
    /// The credential fingerprint, the only caller value the audit records.
    fingerprint: String,
    /// The verified OIDC client, for a seal's `allowedClients`; never
    /// audited. `None` for the legacy API key or a token naming no client.
    client_id: Option<String>,
}

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
            .fingerprint,
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

/// Count every call to the render and seal routes under its status class.
async fn count_documents(
    State(metrics): State<Arc<Metrics>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let operation = match route_template(request.uri().path()) {
        "/v1/render/{type}" => Some(Operation::Render),
        "/v1/seal/{type}" => Some(Operation::Seal),
        _ => None,
    };
    let response = next.run(request).await;
    if let Some(operation) = operation {
        metrics.record_document(operation, response.status());
    }
    response
}

#[derive(Clone)]
struct MetricsState {
    metrics: Arc<Metrics>,
    service: Arc<Service>,
}

/// The operator-private router the metrics listener serves: the series, with
/// the seal certificate lifetimes read at each scrape.
pub fn metrics_router(service: Arc<Service>, metrics: Arc<Metrics>) -> Router {
    let posture = service.posture.posture();
    Router::new()
        .route(METRICS_PATH, get(serve_metrics))
        .with_state(MetricsState { metrics, service })
        .layer(security_headers(CspBuilder::restrictive(), posture))
}

async fn serve_metrics(State(state): State<MetricsState>) -> Response {
    let text = state.metrics.render(
        state.service.audit.write_failures(),
        &state.service.seals,
        time::OffsetDateTime::now_utc(),
    );
    (
        [(
            header::CONTENT_TYPE,
            registry_platform_metrics::CONTENT_TYPE,
        )],
        text,
    )
        .into_response()
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
        p if p.starts_with("/v1/seal/") => "/v1/seal/{type}",
        _ => "other",
    }
}

/// An answer that is not a refusal of the caller. A 401 or 403 goes through
/// `refusal_response` so it carries the check that refused the caller: a
/// refusal status that arrives here has no check to count, which a debug
/// build refuses outright and a release build logs.
fn problem_response(problem: &RenderProblem, trace: Option<&str>) -> Response {
    if matches!(problem.kind.http_status(), 401 | 403) {
        debug_assert!(false, "a refusal was built without its failed check");
        tracing::error!(
            code = problem.kind.http_code(),
            "a refusal was answered without its failed check"
        );
    }
    problem_answer(problem, trace)
}

/// HTTP callers receive fixed, value-free guidance. Operator diagnostics stay
/// with the local CLI and audit boundary; the problem code identifies recovery.
fn problem_answer(problem: &RenderProblem, trace: Option<&str>) -> Response {
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
        detail: problem.public_detail().unwrap_or(match problem.kind {
            ProblemKind::Unauthorized => "Present a valid bearer credential for this Render resource.",
            ProblemKind::Forbidden => "Obtain a Render resource credential with the render:render scope.",
            ProblemKind::AuthenticationUnavailable => "Credential verification is unavailable; retry when the issuer keys are available.",
            ProblemKind::NotFound => "Use a route exposed by this Render adapter.",
            ProblemKind::InvalidArgument => "Check the request method, Content-Length, JSON body, and document type.",
            ProblemKind::BodyTooLarge => "Reduce the request body to the configured size limit.",
            ProblemKind::AuditFailed => "The audit destination is unavailable; contact the operator before retrying.",
            ProblemKind::RateLimited => "The renderer is at capacity; retry later.",
            ProblemKind::SigningUnavailable => "Sealing is unavailable now; plain rendering is unaffected. Retry when /ready reports the seal ready.",
            ProblemKind::SealCertificateInvalid => "The seal certificate cannot sign now; contact the operator.",
            ProblemKind::TimestampFailed => "The timestamp authority did not timestamp the seal; no document was sealed.",
            ProblemKind::DocumentNotSealable => "This document type declares no seal; use the render route.",
            ProblemKind::SealClientNotAllowed => "This client is not allowed to use this document type's seal.",
            _ => "The request was refused; use the problem code and the operator diagnostics to correct it.",
        }),
        code: problem.kind.http_code(),
        trace_id: context.trace_id.clone(),
    };
    let status = StatusCode::from_u16(body.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut value = serde_json::to_value(body).expect("fixed problem serializes");
    // At most 32 pointers of 256 scalar values fit the client's 64 KiB problem
    // budget, including six-byte JSON escapes. They are structural diagnostics,
    // never request values.
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

/// The `/ready` body. `signing` is present only with seals: one member per
/// seal, ready or unavailable with a value-free reason. A seal never decides
/// the status code, so plain rendering stays ready while a seal cannot sign.
#[derive(Serialize)]
struct Readiness<'a> {
    #[serde(flatten)]
    posture: serde_json::Map<String, serde_json::Value>,
    status: &'static str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    signing: BTreeMap<&'a str, SealReadiness>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealReadiness {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    /// Present, `true`, for a seal under `assuranceProfile: local`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    test_only: bool,
}

async fn ready(State(service): State<Arc<Service>>) -> Response {
    let keys_ready = match &service.oidc {
        Some(verifier) => verifier.key_source().ensure_key_set().await.is_ok(),
        None => true,
    };
    let (status, code) = if keys_ready && service.audit.ready().await {
        ("ready", StatusCode::OK)
    } else {
        ("not-ready", StatusCode::SERVICE_UNAVAILABLE)
    };
    // Availability reads the certificate validity and the key provider's
    // readiness as the last finished probe left it; it never requests a
    // timestamp and never waits on the provider. A signer that said it is
    // not ready gets a probe in the background, within the seal's probe
    // limits, and a probe that succeeds shows on a later call.
    for seal in service.seals.values() {
        // Dropping the handle leaves the probe running.
        drop(seal.start_signer_probe());
    }
    let now = time::OffsetDateTime::now_utc();
    let signing = service
        .seals
        .iter()
        .map(|(id, seal)| {
            let readiness = match seal.availability(now) {
                Ok(()) => SealReadiness {
                    status: "ready",
                    reason: None,
                    test_only: seal.is_test_only(),
                },
                Err(unavailable) => SealReadiness {
                    status: "not-ready",
                    reason: Some(unavailable.reason()),
                    test_only: seal.is_test_only(),
                },
            };
            (id.as_str(), readiness)
        })
        .collect();
    let body = serde_json::to_string(&Readiness {
        status,
        signing,
        posture: service.posture.ready_member(),
    })
    .expect("the readiness body serializes");
    (
        code,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

async fn openapi(State(service): State<Arc<Service>>) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        crate::openapi::served(!service.seals.is_empty()),
    )
        .into_response()
}

async fn documents(State(service): State<Arc<Service>>) -> Response {
    let documents: Vec<serde_json::Value> = service
        .bundle
        .documents
        .values()
        .map(|doc| {
            let mut listed = serde_json::json!({
                "id": doc.spec.id,
                "version": doc.spec.version,
                "entry": doc.spec.entry.to_string_lossy(),
                "labels": doc.spec.labels,
                "pdfStandard": doc.spec.pdf_standard.map(|s| s.to_string()),
                "schema": doc.spec.schema.as_ref().map(|p| p.to_string_lossy()),
            });
            // The seal route takes this document type: it names a seal this
            // deployment serves.
            if let Some(seal) = doc
                .spec
                .seal
                .as_deref()
                .filter(|seal| service.seals.contains_key(*seal))
            {
                listed["seal"] = serde_json::Value::String(seal.to_owned());
            }
            listed
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
    scope: &str,
) -> Result<Caller, crate::auth::AuthenticationError> {
    use crate::auth::AuthenticationError;
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or(AuthenticationError::Refused(FailedCheck::CredentialMissing))?;
    if values.next().is_some() {
        return Err(AuthenticationError::Refused(
            FailedCheck::CredentialMalformed,
        ));
    }
    let malformed = || AuthenticationError::Refused(FailedCheck::CredentialMalformed);
    let token =
        parse_bearer_token(value.to_str().map_err(|_| malformed())?).map_err(
            |error| match error {
                BearerParseError::InvalidScheme => {
                    AuthenticationError::Refused(FailedCheck::CredentialMissing)
                }
                _ => malformed(),
            },
        )?;
    if let Some(verifier) = &service.oidc {
        let verified = crate::auth::authenticate(verifier, token, scope).await?;
        return Ok(Caller {
            fingerprint: verified.caller_fingerprint,
            client_id: verified.client_id,
        });
    }
    let expected = service.api_key.as_slice();
    let presented = token.as_bytes();
    (presented.len() == expected.len() && bool::from(presented.ct_eq(expected)))
        .then(|| Caller {
            fingerprint: service.caller_fingerprint.clone(),
            client_id: None,
        })
        .ok_or(AuthenticationError::Refused(FailedCheck::SharedSecret))
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
    axum::Extension(Caller {
        fingerprint: caller,
        ..
    }): axum::Extension<Caller>,
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
                reason: None,
                pdf_digest: Some(sha256_label(&rendered.pdf_sha256)),
                data_digest: Some(sha256_label(&rendered.data_sha256)),
                seal_id: None,
                test_only: false,
                document_digest: None,
                signed_file_digest: None,
                certificate_digest: None,
                timestamp_token_digest: None,
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

/// One call to the seal route: what every audit entry of the call repeats.
struct SealCall {
    document_type: String,
    /// The seal the document type names, once the type is known.
    seal_id: Option<String>,
    /// Whether that seal is test-only, once serve's seal is found.
    test_only: bool,
    caller: String,
    envelope: String,
    correlation: Option<String>,
    trace: Option<String>,
}

impl SealCall {
    /// Refuse the call before any render starts for a reason that is not a
    /// caller refusal: one response entry naming the seal when it is known,
    /// accepted before responding. A 401 or 403 goes through `refuse_checked`,
    /// so every refused caller carries the check that refused it.
    async fn refuse(&self, service: &Service, problem: RenderProblem) -> Response {
        debug_assert!(
            !matches!(problem.kind.http_status(), 401 | 403),
            "a refused caller is answered by refuse_checked"
        );
        match self.audit_refusal(service, &problem).await {
            Ok(()) => problem_response(&problem, self.trace.as_deref()),
            Err(answer) => answer,
        }
    }

    /// Refuse the call as `refuse` does, and record the check that refused
    /// the caller.
    async fn refuse_checked(
        &self,
        service: &Service,
        problem: RenderProblem,
        check: FailedCheck,
    ) -> Response {
        match self.audit_refusal(service, &problem).await {
            Ok(()) => refusal_response(&problem, self.trace.as_deref(), check),
            Err(answer) => answer,
        }
    }

    /// Write the refusal's response entry. When the audit write fails the
    /// answer is the audit failure.
    async fn audit_refusal(
        &self,
        service: &Service,
        problem: &RenderProblem,
    ) -> Result<(), Response> {
        let mut event = RenderAuditEvent::refused(
            &self.document_type,
            problem,
            &self.caller,
            self.correlation.as_deref(),
            self.trace.as_deref(),
        );
        if let Some(seal_id) = &self.seal_id {
            event = event.for_seal(seal_id, self.test_only);
        }
        service
            .audit
            .response(&self.envelope, event)
            .await
            .map_err(|audit_problem| problem_response(&audit_problem, self.trace.as_deref()))
    }
}

/// `POST /v1/seal/{type}`: the render route's request, rendered for a seal
/// and returned sealed. The checks before any render, in order: the method
/// and body, a document the bundle declares, a document whose type names a
/// seal, a client the seal allows, and a seal that can sign now.
async fn seal_route(
    State(service): State<Arc<Service>>,
    RoutePath(document_type): RoutePath<String>,
    axum::Extension(caller): axum::Extension<Caller>,
    headers: HeaderMap,
    method: Method,
    body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let document_type = sanitize_document_type(&document_type);
    let declared = service.bundle.document(&document_type).map(|document| {
        (
            document.spec.version,
            document.spec.seal.as_ref().map(|seal| seal.to_owned()),
        )
    });
    let mut call = SealCall {
        seal_id: declared.as_ref().ok().and_then(|(_, seal)| seal.clone()),
        test_only: false,
        document_type,
        caller: caller.fingerprint.clone(),
        envelope: crate::audit::correlation(),
        correlation: correlation_id(&headers),
        trace: trace_id(&headers),
    };
    if method != Method::POST {
        let problem = RenderProblem::new(ProblemKind::InvalidArgument, "use POST");
        return call.refuse(&service, problem).await;
    }
    let body = match body {
        Ok(bytes) => bytes,
        Err(rejection) => {
            return call
                .refuse(&service, body_rejection_problem(&rejection))
                .await
        }
    };
    if let Err(problem) = declared {
        return call.refuse(&service, problem).await;
    }
    let Some(seal_id) = call.seal_id.clone() else {
        let problem = RenderProblem::new(
            ProblemKind::DocumentNotSealable,
            format!("document type {} declares no seal", call.document_type),
        );
        return call.refuse(&service, problem).await;
    };
    // Startup refused a package naming a seal the runtime does not bind.
    let Some(seal) = service.seals.get(&seal_id).map(Arc::clone) else {
        call.seal_id = None;
        let problem = RenderProblem::new(
            ProblemKind::Internal,
            format!(
                "document type {} names a seal serve did not load",
                call.document_type
            ),
        );
        return call.refuse(&service, problem).await;
    };
    call.test_only = seal.is_test_only();
    if !caller
        .client_id
        .as_deref()
        .is_some_and(|client| seal.allows_client(client))
    {
        let problem = RenderProblem::new(
            ProblemKind::SealClientNotAllowed,
            format!("the verified client is not in signing.seals.{seal_id}.allowedClients"),
        );
        return call
            .refuse_checked(&service, problem, FailedCheck::RequesterClient)
            .await;
    }
    seal.recover_signer().await;
    // One clock reading decides availability and is the signing time.
    let now = time::OffsetDateTime::now_utc();
    if let Err(unavailable) = seal.availability(now) {
        return call.refuse(&service, unavailable.problem(&seal_id)).await;
    }
    let (mut worker_request, document_version) =
        match prepare_render(&service, &call.document_type, &body) {
            Ok(prepared) => prepared,
            Err(problem) => return call.refuse(&service, problem).await,
        };
    worker_request.seal = Some(seal.worker_seal());
    let started = RenderAuditEvent::started(
        &call.document_type,
        document_version,
        service.bundle.manifest.bundle_version,
        &service.bundle.bundle_hash,
        &call.caller,
        call.correlation.as_deref(),
        call.trace.as_deref(),
    )
    .for_seal(&seal_id, seal.is_test_only());
    // As on the render route: the request entry is accepted before the
    // render starts, and a call dropped from here on writes its unfinished
    // response.
    let _request = match service.audit.request(&call.envelope, started.clone()).await {
        Ok(request) => request,
        Err(audit_problem) => return problem_response(&audit_problem, call.trace.as_deref()),
    };
    let outcome = run_seal(&service, &seal, worker_request, now)
        .await
        .map(|(rendered, sealed)| {
            let event = RenderAuditEvent {
                document_version: rendered.document_version,
                bundle_version: rendered.bundle_version,
                bundle_hash: rendered.bundle_hash.clone(),
                outcome: Some("sealed"),
                data_digest: Some(sha256_label(&rendered.data_sha256)),
                document_digest: Some(sealed.document_digest.clone()),
                signed_file_digest: Some(sealed.signed_file_digest.clone()),
                certificate_digest: Some(sealed.certificate_digest.clone()),
                timestamp_token_digest: sealed
                    .timestamp
                    .as_ref()
                    .map(|timestamp| timestamp.token_digest.clone()),
                ..started.clone()
            };
            (event, respond_sealed(&headers, &seal, &rendered, sealed))
        });
    let (event, outcome) = match outcome {
        Ok((event, response)) => (event, Ok(response)),
        Err(problem) => {
            // The caller reads fixed guidance; the operator reads the
            // value-free reason here and in the audit.
            if let Some(reason) = problem.reason() {
                tracing::warn!(
                    target: "registry_render::seal",
                    seal_id = %seal_id,
                    problem = problem.kind.slug(),
                    reason,
                    "seal refused"
                );
            }
            (started.refused_after_start(&problem), Err(problem))
        }
    };
    // The response entry is accepted before anything leaves.
    if let Err(audit_problem) = service.audit.response(&call.envelope, event).await {
        return problem_response(&audit_problem, call.trace.as_deref());
    }
    match outcome {
        Ok(mut response) => {
            if let Some(correlation) = call
                .correlation
                .as_ref()
                .and_then(|c| header::HeaderValue::from_str(c).ok())
            {
                response
                    .headers_mut()
                    .insert("idempotency-key", correlation);
            }
            response
        }
        Err(problem) => problem_response(&problem, call.trace.as_deref()),
    }
}

/// What a sealed response repeats from the worker's render.
struct SealedRender {
    document_id: String,
    document_version: u32,
    bundle_version: u32,
    bundle_hash: String,
    data_sha256: String,
    warnings: Vec<String>,
}

/// Render the first revision on a supervised worker once a render slot is
/// free, release the slot, then prepare the field, sign, timestamp and embed
/// in this process, signed at `signing_time`. Preparing, signing and the
/// timestamp exchange never hold a render slot; the whole call holds one of
/// the service's places for seals in flight, and the preparation keeps it
/// until it ends even when the client has gone.
async fn run_seal(
    service: &Service,
    seal: &Seal,
    worker_request: WorkerRequest,
    signing_time: time::OffsetDateTime,
) -> Result<(SealedRender, SealedDocument), RenderProblem> {
    // A seal beyond the places is refused, not queued: the queue behind a
    // slow authority would otherwise grow without a bound.
    let in_flight = service
        .seals_in_flight
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            RenderProblem::new(
                ProblemKind::RateLimited,
                "every place for a seal in flight is taken; retry later",
            )
        })?;
    let permit = service
        .concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| RenderProblem::new(ProblemKind::Internal, "concurrency latch closed"))?;
    let timeout = service.limits.render_timeout();
    let result = worker::supervise(worker_request, timeout).await;
    drop(permit);
    let mut answer = from_served_package(result?, &service.bundle.bundle_hash)?;
    let first_revision = first_revision(
        &std::mem::take(&mut answer.pdf_base64),
        service.limits.output_bytes(),
    )?;
    let rendered = SealedRender {
        document_id: answer.document_id,
        document_version: answer.document_version,
        bundle_version: answer.bundle_version,
        bundle_hash: answer.bundle_hash,
        data_sha256: answer.data_sha256,
        warnings: answer.warnings,
    };
    let sealed = seal.seal(first_revision, signing_time, in_flight).await?;
    Ok((rendered, sealed))
}

/// The worker rendered from one verified immutable snapshot; its package
/// digest must also be the one serve started with, not merely a different
/// valid package installed during the request. This detects an honest
/// worker's drift: the digest is the worker's own report.
fn from_served_package(
    rendered: WorkerRendered,
    served_hash: &str,
) -> Result<WorkerRendered, RenderProblem> {
    if rendered.bundle_hash != served_hash {
        return Err(RenderProblem::new(
            ProblemKind::BundleTampered,
            "the package changed under serve; refusing the render from a drifted package",
        ));
    }
    Ok(rendered)
}

/// The first revision a worker answered for a seal, decoded and held to the
/// output limit before this process reads it as a PDF.
fn first_revision(pdf_base64: &str, limit: usize) -> Result<Vec<u8>, RenderProblem> {
    let pdf = base64::engine::general_purpose::STANDARD
        .decode(pdf_base64)
        .map_err(|_| {
            RenderProblem::new(
                ProblemKind::Internal,
                "worker returned an undecodable PDF; refusing to seal it",
            )
        })?;
    if pdf.len() > limit {
        return Err(RenderProblem::new(
            ProblemKind::OutputTooLarge,
            format!("rendered PDF is {} bytes; the limit is {limit}", pdf.len()),
        ));
    }
    Ok(pdf)
}

/// The sealed document in the representation the caller accepts, by the
/// render route's rule. JSON carries the signed file and the seal; the PDF
/// representation carries the same values in headers. Every digest is
/// labelled, `sha256:<hex>`. Neither carries a `pdfDigest`: a sealed file
/// has two, `documentDigest` over the first revision and `signedFileDigest`
/// over the whole file. Both carry the package's `packageDigest`, in the form
/// `package.expectedDigest` takes, so a client granted only `render:seal` can
/// pin the package without reading `/v1/documents`, and both say when the
/// seal is test-only, whether or not the template prints it.
fn respond_sealed(
    headers: &HeaderMap,
    seal: &Seal,
    rendered: &SealedRender,
    sealed: SealedDocument,
) -> Response {
    let document_version = format!("{} v{}", rendered.document_id, rendered.document_version);
    let data_digest = sha256_label(&rendered.data_sha256);
    let package_digest = sha256_label(&rendered.bundle_hash);
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| {
            accept.contains("application/json") && !accept.contains("application/pdf")
        });
    if accepts_json {
        let mut member = serde_json::json!({
            "id": seal.id(),
            "level": sealed.level.as_str(),
            "certificateDigest": sealed.certificate_digest,
        });
        if let Some(timestamp) = &sealed.timestamp {
            member["timestampedAt"] = serde_json::Value::String(timestamp.timestamped_at.clone());
        }
        if seal.is_test_only() {
            member["testOnly"] = serde_json::Value::Bool(true);
        }
        let body = serde_json::json!({
            "pdfBase64": base64::engine::general_purpose::STANDARD.encode(&sealed.pdf),
            "documentDigest": sealed.document_digest,
            "signedFileDigest": sealed.signed_file_digest,
            "dataDigest": data_digest,
            "documentVersion": document_version,
            "packageDigest": package_digest,
            "warnings": rendered.warnings,
            "seal": member,
        });
        return Json(body).into_response();
    }
    let mut response = (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/pdf"),
        )],
        sealed.pdf,
    )
        .into_response();
    let map = response.headers_mut();
    insert_header(map, "X-Registry-Document-Digest", &sealed.document_digest);
    insert_header(
        map,
        "X-Registry-Signed-File-Digest",
        &sealed.signed_file_digest,
    );
    insert_header(map, "X-Registry-Data-Digest", &data_digest);
    insert_header(
        map,
        "X-Registry-Warning-Count",
        &rendered.warnings.len().to_string(),
    );
    insert_header(map, "X-Registry-Document-Version", &document_version);
    insert_header(map, "X-Registry-Package-Digest", &package_digest);
    insert_header(map, "X-Registry-Seal-Id", seal.id());
    insert_header(map, "X-Registry-Seal-Level", sealed.level.as_str());
    if seal.is_test_only() {
        insert_header(map, "X-Registry-Seal-Test-Only", "true");
    }
    insert_header(
        map,
        "X-Registry-Certificate-Digest",
        &sealed.certificate_digest,
    );
    if let Some(timestamp) = &sealed.timestamp {
        insert_header(map, "X-Registry-Timestamped-At", &timestamp.timestamped_at);
    }
    response
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
        seal: None,
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
    from_served_package(result?, &service.bundle.bundle_hash)
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

/// The rendered document in the representation the caller accepts, with
/// the labelled `pdfDigest` and `dataDigest`; the PDF representation carries
/// them in headers.
fn respond_rendered(
    headers: &HeaderMap,
    rendered: WorkerRendered,
) -> Result<Response, RenderProblem> {
    let pdf_digest = sha256_label(&rendered.pdf_sha256);
    let data_digest = sha256_label(&rendered.data_sha256);
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| {
            accept.contains("application/json") && !accept.contains("application/pdf")
        });
    if accepts_json {
        let body = serde_json::json!({
            "pdfBase64": rendered.pdf_base64,
            "pdfDigest": pdf_digest,
            "dataDigest": data_digest,
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
    insert_header(map, "X-Registry-Pdf-Digest", &pdf_digest);
    insert_header(map, "X-Registry-Data-Digest", &data_digest);
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

fn peer_policy(declared: DeclaredPosture) -> PeerPolicy {
    match declared.posture {
        registry_platform_config::Posture::Development => PeerPolicy::AcceptDevelopmentPeer,
        registry_platform_config::Posture::Production => PeerPolicy::RefuseDevelopmentPeer,
    }
}

/// `registry-render healthcheck`: one plain HTTP GET against /health.
pub fn healthcheck(runtime_path: &Path, declared: DeclaredPosture) -> Result<i32, RenderProblem> {
    let (loaded, _) = runtime::load_with_positions(runtime_path, declared)?;
    let address = loaded.config.listener.bind.socket_addr();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| RenderProblem::new(ProblemKind::Internal, format!("runtime: {error}")))?;
    runtime.block_on(async {
        let timeout = Duration::from_secs(5);
        let client = registry_platform_httputil::client::build_client(
            registry_platform_httputil::client::OutboundOptions {
                request_timeout: timeout,
                connect_timeout: timeout,
                user_agent: Some("registry-render"),
                trusted_root_certificates: None,
            },
        )
        .map_err(|reason| RenderProblem::new(ProblemKind::Internal, reason))?;
        let response = client
            .get(healthcheck_url(address))
            .send()
            .await
            .map_err(|_| {
                RenderProblem::new(
                    ProblemKind::RuntimeInvalid,
                    format!("cannot reach the health endpoint at {address}"),
                )
            })?;
        validate_response_headers(response.headers(), peer_policy(declared))
            .map_err(|error| RenderProblem::new(ProblemKind::RuntimeInvalid, error.to_string()))?;
        if response.status() != StatusCode::OK {
            return Err(RenderProblem::new(
                ProblemKind::RuntimeInvalid,
                format!("health endpoint at {address} did not answer 200"),
            ));
        }
        println!("healthy at {address}");
        Ok(0)
    })
}

fn healthcheck_url(address: std::net::SocketAddr) -> String {
    let address = std::net::SocketAddr::new(address.ip(), address.port());
    format!("http://{address}/health")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthcheck_url_omits_the_numeric_ipv6_scope() {
        let bind: registry_platform_config::ListenerBind = "[fe80::1%2]:8080".parse().unwrap();
        assert_eq!(
            healthcheck_url(bind.socket_addr()),
            "http://[fe80::1]:8080/health"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn serving_marks_the_process_not_dumpable() {
        mark_not_dumpable().expect("prctl succeeds");
        assert_eq!(
            rustix::process::dumpable_behavior().expect("prctl reads"),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }

    #[test]
    fn a_stop_signal_install_failure_refuses_startup() {
        let problem = stop_signal_after(|| -> std::io::Result<std::future::Pending<()>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "install refused",
            ))
        })
        .expect_err("an install failure is an error, never a silent wait");
        assert_eq!(problem.kind, ProblemKind::Internal);
        assert!(
            problem.detail.contains("install refused"),
            "{}",
            problem.detail
        );
    }

    #[tokio::test]
    async fn an_installed_stop_signal_resolves_when_it_fires() {
        let signal = stop_signal_after(|| Ok(std::future::ready(()))).expect("installs");
        tokio::time::timeout(std::time::Duration::from_secs(5), signal)
            .await
            .expect("a fired signal resolves");
    }

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

    /// Both routes refuse an answer whose package digest is not the one
    /// serve started with; the seal route does so before it signs.
    #[test]
    fn an_answer_from_another_package_is_refused_as_tampered() {
        let answer = WorkerRendered {
            document_id: "receipt".to_owned(),
            pdf_base64: String::new(),
            pdf_sha256: "a".repeat(64),
            data_sha256: "b".repeat(64),
            document_version: 1,
            bundle_version: 1,
            bundle_hash: "c".repeat(64),
            deps: vec![],
            warnings: vec![],
        };
        let served = from_served_package(answer.clone(), &"c".repeat(64)).expect("served");
        assert_eq!(served.bundle_hash, answer.bundle_hash);
        let Err(problem) = from_served_package(answer, &"0".repeat(64)) else {
            panic!("an answer from another package was accepted");
        };
        assert_eq!(problem.kind, ProblemKind::BundleTampered);
    }

    /// The parent reads a seal's first revision as a PDF only once it is
    /// decoded and within the output limit.
    #[test]
    fn a_first_revision_is_held_to_the_output_limit() {
        let pdf = base64::engine::general_purpose::STANDARD.encode(b"%PDF-2.0 sixteen");
        assert_eq!(
            first_revision(&pdf, 16).expect("at the limit"),
            b"%PDF-2.0 sixteen"
        );
        let Err(problem) = first_revision(&pdf, 15) else {
            panic!("a first revision over the limit was accepted");
        };
        assert_eq!(problem.kind, ProblemKind::OutputTooLarge);
        assert_eq!(problem.detail, "rendered PDF is 16 bytes; the limit is 15");
        let Err(problem) = first_revision("not base64!", 1024) else {
            panic!("an undecodable answer was accepted");
        };
        assert_eq!(problem.kind, ProblemKind::Internal);
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
            posture: PostureReport::new(runtime::DEFAULT_POSTURE),
            audit: RenderAudit::new(AuditWriter::from_line_sink(
                Box::new(lines.clone()),
                registry_platform_config::Posture::Production,
            )),
            api_key: TEST_API_KEY.as_bytes().to_vec(),
            oidc: None,
            caller_fingerprint: "caller-fingerprint".to_owned(),
            limits: runtime::LimitsRuntime::default(),
            bundle_path,
            concurrency: Arc::new(tokio::sync::Semaphore::new(permits)),
            max_concurrency: permits,
            seals: Seals::new(),
            seals_in_flight: Arc::new(tokio::sync::Semaphore::new(permits)),
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

    /// The request log takes its route and trace id from these two helpers:
    /// however long the caller's path or traceparent, the logged values are
    /// a fixed template and at most a 32-character trace id.
    #[test]
    fn the_request_log_takes_a_route_template_and_a_parsed_trace_id() {
        let long = "x".repeat(10_000);
        assert_eq!(
            route_template(&format!("/v1/render/{long}")),
            "/v1/render/{type}"
        );
        assert_eq!(
            route_template(&format!("/v1/seal/{long}")),
            "/v1/seal/{type}"
        );
        assert_eq!(route_template(&format!("/{long}")), "other");
        let trace = "1234567890abcdef1234567890abcdef";
        let hex = "a".repeat(10_000);
        let traceparent = |value: String| {
            let mut headers = HeaderMap::new();
            headers.insert("traceparent", HeaderValue::from_str(&value).unwrap());
            headers
        };
        assert_eq!(
            trace_id(&traceparent(format!("00-{trace}-{long}-01"))).as_deref(),
            Some(trace)
        );
        assert_eq!(
            trace_id(&traceparent(format!("00-{trace}{hex}-1234567890abcdef-01"))),
            None
        );
        assert_eq!(
            trace_id(&traceparent(format!("00-{hex}-1234567890abcdef-01"))),
            None
        );
    }

    #[tokio::test]
    async fn maximum_pointer_problem_fits_the_serving_client_budget() {
        for character in ["😀", "\u{001f}"] {
            let pointer = format!("/{}", character.repeat(512));
            let problem = RenderProblem::new(ProblemKind::DataInvalid, "local diagnostic")
                .with_pointers(vec![pointer; 64]);
            let response = problem_response(&problem, None);
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            assert!(bytes.len() > 16 * 1024);
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let pointers = body["pointers"].as_array().unwrap();
            assert_eq!(pointers.len(), 32);
            assert!(pointers
                .iter()
                .all(|pointer| pointer.as_str().unwrap().chars().count() == 256));
        }
    }

    #[tokio::test]
    async fn scope_refusals_keep_verified_credential_fingerprints() {
        let lines = AuditLines::new(None);
        let mut service = service(&lines, 1);
        Arc::get_mut(&mut service).unwrap().oidc = Some(crate::auth::tests::test_verifier());
        let credential = crate::auth::tests::token(serde_json::json!({"scope":"other"}));
        for (token, status, caller) in [
            (
                credential.clone(),
                StatusCode::FORBIDDEN,
                registry_platform_authcommon::fingerprint_api_key(&credential),
            ),
            (
                credential.clone(),
                StatusCode::FORBIDDEN,
                registry_platform_authcommon::fingerprint_api_key(&credential),
            ),
            (
                crate::auth::tests::token(serde_json::json!({"aud":"urn:other"})),
                StatusCode::UNAUTHORIZED,
                "unknown".to_owned(),
            ),
        ] {
            let response = router(Arc::clone(&service))
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/v1/documents")
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            let records = lines.accepted.lock().unwrap();
            let record = &records.last().expect("audited refusal")["record"];
            assert_eq!(record["caller"], caller);
            assert!(!record.to_string().contains(&token));
        }
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

    /// The series the metrics listener serves for `service` after `metrics`
    /// counted whatever the test sent through the counting layer.
    async fn scraped(service: &Arc<Service>, metrics: &Arc<Metrics>) -> String {
        let response = metrics_router(Arc::clone(service), Arc::clone(metrics))
            .oneshot(
                axum::http::Request::get("/metrics")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("metrics body");
        String::from_utf8(body.to_vec()).expect("text exposition")
    }

    #[tokio::test]
    async fn a_failed_audit_write_is_counted_and_the_call_is_a_failed_render() {
        let lines = AuditLines::new(Some(1));
        let service = service(&lines, 1);
        let metrics = Arc::new(Metrics::default());
        let app = router(Arc::clone(&service)).layer(axum::middleware::from_fn_with_state(
            Arc::clone(&metrics),
            count_documents,
        ));
        let response = app.oneshot(render_request(None)).await.expect("router");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let text = scraped(&service, &metrics).await;
        assert!(
            text.contains("\nrender_audit_write_failures_total 1\n"),
            "{text}"
        );
        assert!(
            text.contains("render_documents_total{operation=\"render\",result=\"failed\"} 1"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn only_the_document_routes_are_counted_and_the_listener_serves_nothing_else() {
        let lines = AuditLines::new(None);
        let service = service(&lines, 1);
        let metrics = Arc::new(Metrics::default());
        let app = router(Arc::clone(&service)).layer(axum::middleware::from_fn_with_state(
            Arc::clone(&metrics),
            count_documents,
        ));
        let health = app
            .clone()
            .oneshot(
                axum::http::Request::get("/health")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(health.status(), StatusCode::OK);
        let unauthenticated = app
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::POST)
                    .uri("/v1/render/receipt")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert!(unauthenticated.status().is_client_error());
        let text = scraped(&service, &metrics).await;
        assert!(
            text.contains("render_documents_total{operation=\"render\",result=\"refused\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("render_documents_total{operation=\"render\",result=\"ok\"} 0"),
            "{text}"
        );
        let elsewhere = metrics_router(Arc::clone(&service), metrics)
            .oneshot(
                axum::http::Request::get("/health")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(elsewhere.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn each_loaded_seal_reports_its_certificate_lifetime() {
        use registry_platform_crypto::document_signature::test_support::TestPki;
        use registry_platform_crypto::SigningAlgorithm;
        let lines = AuditLines::new(None);
        let mut service = service(&lines, 1);
        let pki = TestPki::generate().expect("test PKI");
        let test_seal = pki.issue_seal(SigningAlgorithm::Es256).expect("test seal");
        let seal = Arc::new(Seal::for_test(
            "ministry",
            &test_seal,
            Arc::new(test_seal.signer().expect("test signer")),
        ));
        Arc::get_mut(&mut service)
            .expect("fixture owns service")
            .seals
            .insert("ministry".to_owned(), seal);
        let text = scraped(&service, &Arc::new(Metrics::default())).await;
        let sample = text
            .lines()
            .find(|line| {
                line.starts_with("render_seal_certificate_expiry_seconds{seal=\"ministry\"} ")
            })
            .unwrap_or_else(|| panic!("no expiry sample: {text}"));
        let seconds: i64 = sample
            .rsplit(' ')
            .next()
            .unwrap()
            .parse()
            .expect("whole seconds");
        assert!(
            seconds > 0,
            "a freshly issued test certificate is valid: {sample}"
        );
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

    /// The legacy API key never reaches the seal route, even on a service
    /// that loaded a seal without OIDC: the bearer layer refuses it before
    /// the handler, with the guidance it needs, as one refusal entry.
    #[tokio::test]
    async fn the_legacy_api_key_is_refused_on_the_seal_route_at_request_time() {
        use axum::body::to_bytes;
        use registry_platform_crypto::document_signature::test_support::TestPki;
        let pki = TestPki::generate().expect("test PKI");
        let test_seal = pki
            .issue_seal(registry_platform_crypto::SigningAlgorithm::Es256)
            .expect("test seal");
        let signer = Arc::new(test_seal.signer().expect("test signer"));
        let lines = AuditLines::new(None);
        let mut service = service(&lines, 1);
        Arc::get_mut(&mut service)
            .expect("fixture owns service")
            .seals
            .insert(
                "ministry".to_owned(),
                Arc::new(Seal::for_test("ministry", &test_seal, signer)),
            );
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/v1/seal/receipt")
            .header(header::AUTHORIZATION, format!("Bearer {TEST_API_KEY}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let response = router(Arc::clone(&service)).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let body = to_bytes(response.into_body(), 16384).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "render.forbidden");
        assert_eq!(body["detail"], LEGACY_KEY_GUIDANCE);
        let accepted = lines.accepted();
        assert_eq!(accepted.len(), 1, "{accepted:?}");
        assert_eq!(accepted[0]["phase"], "response");
        assert_eq!(accepted[0]["record"]["outcome"], "refused");
        assert_eq!(accepted[0]["record"]["problem"], "forbidden");
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

    /// One refused answer, as the golden freezes it: status, the headers a
    /// caller or proxy acts on, and the body without its per-request trace id.
    async fn frozen_answer(response: Response) -> serde_json::Value {
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in [
            "content-type",
            "www-authenticate",
            "cache-control",
            "retry-after",
        ] {
            let values: Vec<serde_json::Value> = response
                .headers()
                .get_all(name)
                .iter()
                .map(|value| value.to_str().expect("ASCII header").into())
                .collect();
            match values.len() {
                0 => {}
                1 => {
                    headers.insert(name.to_owned(), values[0].clone());
                }
                _ => {
                    headers.insert(name.to_owned(), values.into());
                }
            }
        }
        let bytes = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .expect("body");
        let mut body: serde_json::Value = serde_json::from_slice(&bytes).expect("problem body");
        assert!(body["traceId"].is_string(), "{body}");
        body.as_object_mut().expect("object").remove("traceId");
        serde_json::json!({"status": status, "headers": headers, "body": body})
    }

    fn bearer_request(
        method: Method,
        uri: &str,
        authorization: &[Vec<u8>],
    ) -> axum::extract::Request {
        let mut request = axum::http::Request::builder().method(method).uri(uri);
        for value in authorization {
            request = request.header(
                header::AUTHORIZATION,
                header::HeaderValue::from_bytes(value).expect("header value"),
            );
        }
        request
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from("{}"))
            .expect("request")
    }

    /// The service a refusal case runs against.
    #[derive(Clone, Copy)]
    enum Mode {
        /// The legacy API key.
        Legacy,
        /// An OIDC verifier over a static key set.
        Oidc,
        /// The legacy API key on a service that loaded a seal.
        LegacySealed,
        /// An OIDC verifier and a seal that allows a different client.
        OidcSealed,
        /// An OIDC verifier whose key source answers 503.
        Outage,
    }

    async fn refusal_service(mode: Mode) -> Arc<Service> {
        use registry_platform_crypto::document_signature::test_support::TestPki;
        let lines = AuditLines::new(None);
        let mut service = service(&lines, 1);
        let inner = Arc::get_mut(&mut service).expect("fixture owns service");
        if matches!(mode, Mode::Oidc | Mode::OidcSealed) {
            inner.oidc = Some(crate::auth::tests::test_verifier());
        }
        if matches!(mode, Mode::Outage) {
            let origin = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("key source listener");
            let url = format!("http://{}/jwks", origin.local_addr().expect("address"));
            let keys_app =
                Router::new().route("/jwks", get(|| async { StatusCode::SERVICE_UNAVAILABLE }));
            tokio::spawn(async move {
                axum::serve(origin, keys_app).await.expect("key source");
            });
            let fetch_policy = registry_platform_oidc::IssuerNetworkPolicy::new(&url, true)
                .expect("loopback policy")
                .declared_jwks_fetch_policy();
            inner.oidc = Some(crate::auth::tests::test_verifier_over(Arc::new(
                registry_platform_oidc::JwksFetcher::new_with_fetch_url_policy(
                    url,
                    registry_platform_oidc::JwksFetcherConfig::defaults(),
                    fetch_policy,
                ),
            )));
        }
        if matches!(mode, Mode::LegacySealed | Mode::OidcSealed) {
            let pki = TestPki::generate().expect("test PKI");
            let test_seal = pki
                .issue_seal(registry_platform_crypto::SigningAlgorithm::Es256)
                .expect("test seal");
            let signer = Arc::new(test_seal.signer().expect("test signer"));
            inner.seals.insert(
                "ministry".to_owned(),
                Arc::new(Seal::for_test("ministry", &test_seal, signer)),
            );
            // The receipt names the seal, as a sealable document type does.
            inner
                .bundle
                .documents
                .get_mut("receipt")
                .expect("receipt document")
                .spec
                .seal = Some("ministry".to_owned());
        }
        service
    }

    fn token_header(overrides: serde_json::Value) -> Option<String> {
        Some(format!("Bearer {}", crate::auth::tests::token(overrides)))
    }

    /// One refusal: its name, the service, the request, and the check that
    /// must refuse it.
    struct RefusalCase {
        name: &'static str,
        mode: Mode,
        method: Method,
        uri: &'static str,
        /// The `Authorization` header values, in order.
        authorization: Vec<Vec<u8>>,
        check: &'static str,
    }

    impl RefusalCase {
        fn new(
            name: &'static str,
            mode: Mode,
            method: Method,
            uri: &'static str,
            credential: Option<String>,
            check: &'static str,
        ) -> Self {
            Self {
                name,
                mode,
                method,
                uri,
                authorization: credential.into_iter().map(String::into_bytes).collect(),
                check,
            }
        }

        /// A case that sends the given `Authorization` header values as they
        /// are, repeated or not ASCII included.
        fn raw(mut self, authorization: Vec<Vec<u8>>) -> Self {
            self.authorization = authorization;
            self
        }
    }

    /// A client id no refusal answer or log line may repeat.
    const CANARY_CLIENT: &str = "canary-client-0123456789";

    /// Every refusal the access layers and the seal handler make, with the
    /// check each one must record.
    fn refusal_cases() -> Vec<RefusalCase> {
        let legacy = |key: &str| Some(format!("Bearer {key}"));
        vec![
            RefusalCase::new(
                "no-authorization-header",
                Mode::Legacy,
                Method::GET,
                "/v1/documents",
                None,
                "credential-missing",
            ),
            RefusalCase::new(
                "scheme-not-bearer",
                Mode::Legacy,
                Method::GET,
                "/v1/documents",
                Some("Basic dXNlcjpwYXNz".to_owned()),
                "credential-missing",
            ),
            RefusalCase::new(
                "empty-bearer-token",
                Mode::Legacy,
                Method::GET,
                "/v1/documents",
                Some("Bearer ".to_owned()),
                "credential-malformed",
            ),
            RefusalCase::new(
                "value-shorter-than-the-scheme",
                Mode::Legacy,
                Method::GET,
                "/v1/documents",
                Some("Basic".to_owned()),
                "credential-malformed",
            ),
            RefusalCase::new(
                "repeated-authorization-header",
                Mode::Legacy,
                Method::GET,
                "/v1/documents",
                None,
                "credential-malformed",
            )
            .raw(vec![b"Bearer first".to_vec(), b"Bearer second".to_vec()]),
            RefusalCase::new(
                "non-ascii-authorization-header",
                Mode::Legacy,
                Method::GET,
                "/v1/documents",
                None,
                "credential-malformed",
            )
            .raw(vec![b"Bearer caf\xe9".to_vec()]),
            RefusalCase::new(
                "legacy-key-mismatch",
                Mode::Legacy,
                Method::GET,
                "/v1/documents",
                legacy("canary-wrong-key-0123456789abcdef0123456789"),
                "shared-secret",
            ),
            RefusalCase::new(
                "compact-token-shape",
                Mode::Oidc,
                Method::GET,
                "/v1/documents",
                Some("Bearer canary-invalid-token".to_owned()),
                "credential-malformed",
            ),
            RefusalCase::new(
                "token-audience",
                Mode::Oidc,
                Method::GET,
                "/v1/documents",
                token_header(serde_json::json!({"aud":"urn:other"})),
                "token-audience",
            ),
            RefusalCase::new(
                "token-expired",
                Mode::Oidc,
                Method::GET,
                "/v1/documents",
                token_header(serde_json::json!({"exp":1})),
                "token-time",
            ),
            RefusalCase::new(
                "token-client",
                Mode::Oidc,
                Method::GET,
                "/v1/documents",
                token_header(serde_json::json!({"client_id":"other"})),
                "token-client",
            ),
            RefusalCase::new(
                "token-client-canary",
                Mode::Oidc,
                Method::GET,
                "/v1/documents",
                token_header(serde_json::json!({"client_id":CANARY_CLIENT})),
                "token-client",
            ),
            RefusalCase::new(
                "scope-on-render-route",
                Mode::Oidc,
                Method::GET,
                "/v1/documents",
                token_header(serde_json::json!({"scope":"canary-token-scope"})),
                "scope",
            ),
            RefusalCase::new(
                "render-scope-on-seal-route",
                Mode::OidcSealed,
                Method::POST,
                "/v1/seal/receipt",
                token_header(serde_json::json!({})),
                "scope",
            ),
            RefusalCase::new(
                "legacy-key-on-seal-route",
                Mode::LegacySealed,
                Method::POST,
                "/v1/seal/receipt",
                legacy(TEST_API_KEY),
                "operation",
            ),
            RefusalCase::new(
                "key-source-unavailable",
                Mode::Outage,
                Method::GET,
                "/v1/documents",
                token_header(serde_json::json!({})),
                "key-source-unavailable",
            ),
            RefusalCase::new(
                "seal-client-not-allowed",
                Mode::OidcSealed,
                Method::POST,
                "/v1/seal/receipt",
                token_header(serde_json::json!({"scope":"render:seal"})),
                "requester-client",
            ),
        ]
    }

    /// The refusals as the whole stack answers them, frozen in a checked-in
    /// file that was written from the tree before any recording existed. Run
    /// with `REGISTRY_RENDER_WRITE_GOLDEN=1` to rewrite it.
    #[tokio::test]
    async fn refusal_answers_match_the_golden() {
        let mut answers = serde_json::Map::new();
        for RefusalCase {
            name,
            mode,
            method,
            uri,
            authorization,
            ..
        } in refusal_cases()
        {
            let service = refusal_service(mode).await;
            let response = refusal_stack(service, &Arc::new(Metrics::default()))
                .oneshot(bearer_request(method, uri, &authorization))
                .await
                .expect("router");
            answers.insert(name.to_owned(), frozen_answer(response).await);
        }
        let actual = serde_json::Value::Object(answers);
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/authentication_refusals.json");
        if std::env::var_os("REGISTRY_RENDER_WRITE_GOLDEN").is_some() {
            std::fs::create_dir_all(path.parent().expect("parent")).expect("golden directory");
            std::fs::write(
                &path,
                format!("{}\n", serde_json::to_string_pretty(&actual).expect("json")),
            )
            .expect("write golden");
        }
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("golden file"))
                .expect("golden json");
        assert_eq!(actual, expected);
    }

    /// The stack `serve` builds around the router, for the refusal tests.
    fn refusal_stack(service: Arc<Service>, metrics: &Arc<Metrics>) -> Router {
        public_app(service, metrics)
    }

    /// A subscriber that keeps every formatted line in memory.
    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Every refusal is counted once under the check that refused it, writes
    /// one value-free log line that names that check and the request's trace
    /// id, and leaves every other check at zero.
    #[tokio::test]
    async fn each_refusal_is_counted_and_logged_under_its_check() {
        let canaries = [
            "canary-wrong-key-0123456789abcdef0123456789",
            "canary-invalid-token",
            "canary-principal",
            "canary-token-scope",
            CANARY_CLIENT,
        ];
        for RefusalCase {
            name,
            mode,
            method,
            uri,
            authorization,
            check,
        } in refusal_cases()
        {
            let logs = LogCapture::default();
            let subscriber = tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::INFO)
                .with_writer(logs.clone())
                .finish();
            let _guard = tracing::subscriber::set_default(subscriber);
            let service = refusal_service(mode).await;
            let metrics = Arc::new(Metrics::default());
            let response = refusal_stack(Arc::clone(&service), &metrics)
                .oneshot(bearer_request(method, uri, &authorization))
                .await
                .expect("router");
            let trace = registry_platform_httpsec::response_trace_id(response.headers())
                .expect("trace id")
                .to_string();
            let text = scraped(&service, &metrics).await;
            let counted: Vec<&str> = text
                .lines()
                .filter(|line| line.starts_with("render_request_refusals_total{"))
                .filter(|line| !line.ends_with(" 0"))
                .collect();
            assert_eq!(
                counted,
                [format!(
                    "render_request_refusals_total{{check=\"{check}\"}} 1"
                )],
                "{name}"
            );
            let written = String::from_utf8(logs.0.lock().expect("log").clone()).expect("UTF-8");
            // The whole bearer value of a signed token never reaches a log line.
            for value in &authorization {
                if let Some(token) = value
                    .strip_prefix(b"Bearer ")
                    .filter(|token| token.len() > 40)
                {
                    let token = String::from_utf8_lossy(token);
                    assert!(!written.contains(token.as_ref()), "{name}: {written}");
                }
            }
            let lines: Vec<serde_json::Value> = written
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSON log line"))
                .filter(|line| line["fields"]["message"] == "request refused")
                .collect();
            assert_eq!(lines.len(), 1, "{name}: {written}");
            let fields = &lines[0]["fields"];
            assert_eq!(fields["decision"], "refused", "{name}");
            assert_eq!(fields["failed_check"], check, "{name}");
            assert_eq!(fields["trace_id"], trace.as_str(), "{name}");
            // A scope refusal names the values the operator declared. Every
            // other check names none.
            if check == "scope" {
                assert_eq!(fields["scope_claim"], "scope", "{name}");
                let required = if uri.starts_with("/v1/seal/") {
                    SEAL_SCOPE
                } else {
                    RENDER_SCOPE
                };
                assert_eq!(fields["required_scope"], required, "{name}");
                assert!(fields.get("access_profile").is_none(), "{name}");
            } else {
                for field in ["scope_claim", "required_scope", "access_profile"] {
                    assert!(fields.get(field).is_none(), "{name}: {field}");
                }
            }
            for canary in canaries {
                assert!(!written.contains(canary), "{name}: {written}");
            }
        }
    }

    #[tokio::test]
    async fn the_refusal_counter_is_exposed_from_zero_for_every_check() {
        let service = refusal_service(Mode::Legacy).await;
        let text = scraped(&service, &Arc::new(Metrics::default())).await;
        assert!(text.contains(
            "# HELP render_request_refusals_total Requests refused, by the check that failed.\n# TYPE render_request_refusals_total counter\n"
        ));
        for check in registry_platform_authcommon::FailedCheck::ALL {
            assert!(
                text.contains(&format!(
                    "render_request_refusals_total{{check=\"{}\"}} 0",
                    check.as_str()
                )),
                "{}",
                check.as_str()
            );
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "a refusal was built without its failed check")]
    fn a_refusal_status_without_its_check_is_not_built() {
        for kind in [
            ProblemKind::Unauthorized,
            ProblemKind::Forbidden,
            ProblemKind::SealClientNotAllowed,
        ] {
            let _ = problem_response(&RenderProblem::new(kind, "no check"), None);
        }
    }

    #[test]
    fn a_refusal_with_its_check_is_built_without_the_guard() {
        for kind in [
            ProblemKind::Unauthorized,
            ProblemKind::Forbidden,
            ProblemKind::SealClientNotAllowed,
        ] {
            let response = refusal_response(
                &RenderProblem::new(kind, "with check"),
                None,
                FailedCheck::Operation,
            );
            assert!(response.extensions().get::<RefusalNote>().is_some());
        }
    }
}
