// SPDX-License-Identifier: Apache-2.0

//! Operational counters, served only on the operator-private metrics
//! listener.
//!
//! `/metrics` is a route on a separate socket that `metricsListener` names,
//! never on the facade listener, so the public contract is unchanged and
//! reaching the counters requires reaching a different, private address. The
//! listener is off unless the runtime configuration declares it.
//!
//! Every label is closed by construction. The route label is the axum route
//! template that matched, or `unmatched`; the method label is a fixed
//! vocabulary; the status label is a coarse class; the upstream class is the
//! closed [`ErrorClass`] vocabulary restricted to the classes that name a
//! failed call to a source; the sweep store is a fixed set. Paths, record
//! identifiers, principals, and problem details never become labels, so no
//! caller can write text into a series and the series count is bounded by
//! the served route table.
//!
//! Every counter is per process and starts from zero at each start.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use axum::extract::{MatchedPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use registry_adapter_core::ErrorClass;
use registry_platform_authcommon::{DeclaredScope, RefusalNote, RefusalRecorder};
use registry_platform_metrics::{
    CounterVec, Exposition, LabelSpace, CONTENT_TYPE as METRICS_CONTENT_TYPE,
};

/// The path the metrics listener serves.
pub const METRICS_PATH: &str = "/metrics";

/// Route label used when no route template matched the request.
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// The most request series the registry holds. The served route table times
/// the method and status vocabularies stays well under it. A request past it
/// is counted as refused, never added.
const REQUEST_SERIES_LIMIT: usize = 2_048;

const DECLARATION: &str = "the metric declarations are valid";

/// The error classes that name a failed call to a source, the closed label of
/// `adapter_upstream_failures_total`.
const UPSTREAM_CLASSES: [ErrorClass; 11] = [
    ErrorClass::Upstream,
    ErrorClass::UpstreamHttp,
    ErrorClass::UpstreamTimeout,
    ErrorClass::UpstreamConnection,
    ErrorClass::UpstreamMalformed,
    ErrorClass::UpstreamTooLarge,
    ErrorClass::UpstreamRedirect,
    ErrorClass::BreakerOpen,
    ErrorClass::ThrottleRejected,
    ErrorClass::CredentialRejected,
    ErrorClass::EgressRefused,
];

/// The retention stores a sweep runs for, the closed label of
/// `adapter_retention_sweep_failures_total`.
const SWEEP_STORES: [&str; 3] = ["journal", "idempotency", "other"];

/// The process's refusal recorder: one counter and one log budget for every
/// listener of this process, the facade and the payment routes alike.
static REFUSALS: OnceLock<Arc<RefusalRecorder>> = OnceLock::new();

/// The recorder behind `adapter_request_refusals_total` and the
/// `request refused` log line.
pub fn refusal_recorder() -> Arc<RefusalRecorder> {
    Arc::clone(
        REFUSALS.get_or_init(|| Arc::new(RefusalRecorder::new("adapter").expect(DECLARATION))),
    )
}

pub struct Metrics {
    refusals: Arc<RefusalRecorder>,
    requests: CounterVec,
    upstream_failures: CounterVec,
    journal_write_failures: CounterVec,
    sweep_failures: CounterVec,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let upstream: Vec<[&str; 1]> = UPSTREAM_CLASSES.iter().map(|c| [c.class()]).collect();
        let upstream: Vec<&[&str]> = upstream.iter().map(|c| c.as_slice()).collect();
        let sweep: Vec<[&str; 1]> = SWEEP_STORES.iter().map(|s| [*s]).collect();
        let sweep: Vec<&[&str]> = sweep.iter().map(|s| s.as_slice()).collect();
        Self {
            refusals: refusal_recorder(),
            requests: CounterVec::new(
                "adapter_http_requests_total",
                "Answered facade HTTP requests, by route template, method, and status class.",
                LabelSpace::bounded(&["route", "method", "status"], REQUEST_SERIES_LIMIT)
                    .expect(DECLARATION),
            )
            .expect(DECLARATION),
            upstream_failures: CounterVec::new(
                "adapter_upstream_failures_total",
                "Calls to a source that failed, by error class.",
                LabelSpace::closed_zero_filled(&["class"], &upstream).expect(DECLARATION),
            )
            .expect(DECLARATION),
            journal_write_failures: CounterVec::new(
                "adapter_journal_write_failures_total",
                "Audit journal writes that failed, so the exchange answered an internal error.",
                LabelSpace::closed_zero_filled(&[], &[&[]]).expect(DECLARATION),
            )
            .expect(DECLARATION),
            sweep_failures: CounterVec::new(
                "adapter_retention_sweep_failures_total",
                "Retention sweep batches that failed and were left to the next tick, by store.",
                LabelSpace::closed_zero_filled(&["store"], &sweep).expect(DECLARATION),
            )
            .expect(DECLARATION),
        }
    }
}

impl Metrics {
    /// The recorder that counts and logs every refused request.
    #[must_use]
    pub fn refusals(&self) -> Arc<RefusalRecorder> {
        Arc::clone(&self.refusals)
    }

    /// Count one answered request under its closed labels.
    pub fn record_request(&self, route: &str, method: &Method, status: StatusCode) {
        count(
            &self.requests,
            &[route, method_label(method), status_class(status)],
        );
    }

    /// Count one failed route when its class names a failed call to a source.
    /// Any other class is not an upstream failure and is not counted.
    pub fn record_route_failure(&self, class: ErrorClass) {
        if UPSTREAM_CLASSES.contains(&class) {
            count(&self.upstream_failures, &[class.class()]);
        }
    }

    /// Count one failed audit journal write.
    pub fn record_journal_write_failure(&self) {
        count(&self.journal_write_failures, &[]);
    }

    /// Count one failed retention sweep batch.
    pub fn record_sweep_failure(&self, store: &str) {
        let store = match store {
            "journal" => "journal",
            "idempotency response" => "idempotency",
            _ => "other",
        };
        count(&self.sweep_failures, &[store]);
    }

    /// Render the Prometheus text exposition.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = Exposition::new();
        for counter in [
            &self.requests,
            &self.upstream_failures,
            &self.journal_write_failures,
            &self.sweep_failures,
            self.refusals.counter(),
        ] {
            counter.write(&mut out).expect(DECLARATION);
        }
        out.finish()
    }
}

/// Set once the first refused series has been logged, so a full series table
/// does not log at request rate.
static REFUSAL_LOGGED: AtomicBool = AtomicBool::new(false);

/// Count one event. A series the space refuses is not added; the first
/// refusal is logged by metric name alone, never by label value, and later
/// ones are not logged again.
fn count(counter: &CounterVec, values: &[&str]) {
    if let Err(error) = counter.inc(values) {
        if !REFUSAL_LOGGED.swap(true, Ordering::Relaxed) {
            tracing::warn!(error = %error, "a metric series was refused; further refusals are not logged");
        }
    }
}

fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() {
        0..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

/// Count every answered request on the facade listener under the route
/// template it matched.
pub async fn count_requests(
    State(metrics): State<Arc<Metrics>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or(UNMATCHED_ROUTE, MatchedPath::as_str)
        .to_owned();
    let method = request.method().clone();
    let response = next.run(request).await;
    metrics.record_request(&route, &method, response.status());
    response
}

/// Count and log every refused request once, under the check its answer
/// carries in the response extensions. The extension is not serialized, so
/// no byte of the answer depends on it.
pub async fn record_refusals(
    State(recorder): State<Arc<RefusalRecorder>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    if let Some(note) = response.extensions().get::<RefusalNote>() {
        let declared = response.extensions().get::<DeclaredScope>();
        registry_platform_authcommon::record_refusal!(recorder, *note, declared = declared);
    }
    response
}

/// The router the metrics listener serves: the counters and nothing else.
pub fn metrics_router(metrics: Arc<Metrics>) -> Router {
    metrics_router_in_posture(metrics, registry_platform_config::Posture::Production)
}

fn metrics_router_in_posture(
    metrics: Arc<Metrics>,
    posture: registry_platform_config::Posture,
) -> Router {
    Router::new()
        .route(
            METRICS_PATH,
            get(|State(metrics): State<Arc<Metrics>>| async move {
                ([(CONTENT_TYPE, METRICS_CONTENT_TYPE)], metrics.render()).into_response()
            }),
        )
        .with_state(metrics)
        .layer(registry_platform_httpsec::posture_mark(posture))
}

/// How long open metrics connections get to drain once shutdown starts.
pub const METRICS_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve the metrics router until `shutdown` resolves, then give open
/// connections `shutdown_timeout` to drain. A client that sends a partial
/// request head never finishes its connection, so without the deadline it
/// would hold the facade's shutdown.
///
/// # Errors
///
/// A serving fault, or connections that outlive the deadline.
pub async fn serve(
    listener: tokio::net::TcpListener,
    metrics: Arc<Metrics>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    shutdown_timeout: std::time::Duration,
    posture: registry_platform_config::Posture,
) -> std::io::Result<()> {
    let (shutdown_started, shutdown_started_rx) = tokio::sync::oneshot::channel();
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, metrics_router_in_posture(metrics, posture)).with_graceful_shutdown(
            async move {
                shutdown.await;
                let _ = shutdown_started.send(());
            },
        ),
    );
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result,
        started = shutdown_started_rx => {
            started.map_err(std::io::Error::other)?;
            tokio::time::timeout(shutdown_timeout, &mut server)
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "metrics listener connections outlived the shutdown deadline",
                    )
                })?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_counted_by_route_template_method_and_status_class() {
        let metrics = Metrics::default();
        metrics.record_request("/records/{id}", &Method::GET, StatusCode::NOT_FOUND);
        metrics.record_request(
            UNMATCHED_ROUTE,
            &Method::from_bytes(b"BREW").unwrap(),
            StatusCode::OK,
        );
        let text = metrics.render();
        assert!(text.contains(
            "adapter_http_requests_total{route=\"/records/{id}\",method=\"GET\",status=\"4xx\"} 1"
        ));
        assert!(text.contains("method=\"other\""));
    }

    #[test]
    fn each_status_class_has_its_own_label() {
        let metrics = Metrics::default();
        for status in [
            StatusCode::CONTINUE,
            StatusCode::OK,
            StatusCode::NOT_MODIFIED,
            StatusCode::NOT_FOUND,
            StatusCode::BAD_GATEWAY,
            StatusCode::from_u16(600).expect("600 is a valid status code"),
        ] {
            metrics.record_request("/records", &Method::GET, status);
        }
        for class in ["1xx", "2xx", "3xx", "4xx", "5xx", "other"] {
            let line = format!(
                "adapter_http_requests_total{{route=\"/records\",method=\"GET\",status=\"{class}\"}} 1"
            );
            assert!(text_has(&metrics, &line), "{class}");
        }
    }

    #[test]
    fn only_a_failed_call_to_a_source_counts_as_an_upstream_failure() {
        let metrics = Metrics::default();
        metrics.record_route_failure(ErrorClass::UpstreamTimeout);
        metrics.record_route_failure(ErrorClass::UpstreamTimeout);
        metrics.record_route_failure(ErrorClass::BreakerOpen);
        metrics.record_route_failure(ErrorClass::Validation);
        let text = metrics.render();
        assert!(text.contains("adapter_upstream_failures_total{class=\"upstream.timeout\"} 2"));
        assert!(text.contains("adapter_upstream_failures_total{class=\"breaker.open\"} 1"));
        assert!(text.contains("adapter_upstream_failures_total{class=\"upstream.http\"} 0"));
        assert!(!text.contains("validation"));
    }

    #[test]
    fn journal_write_and_sweep_failures_are_counted_from_zero() {
        let metrics = Metrics::default();
        assert!(text_has(&metrics, "adapter_journal_write_failures_total 0"));
        metrics.record_journal_write_failure();
        metrics.record_sweep_failure("idempotency response");
        metrics.record_sweep_failure("journal");
        metrics.record_sweep_failure("test");
        assert!(text_has(&metrics, "adapter_journal_write_failures_total 1"));
        assert!(text_has(
            &metrics,
            "adapter_retention_sweep_failures_total{store=\"idempotency\"} 1"
        ));
        assert!(text_has(
            &metrics,
            "adapter_retention_sweep_failures_total{store=\"journal\"} 1"
        ));
        assert!(text_has(
            &metrics,
            "adapter_retention_sweep_failures_total{store=\"other\"} 1"
        ));
    }

    #[test]
    fn the_refusal_counter_declares_every_check_and_publishes_it_at_zero() {
        let text = Metrics::default().render();
        let declared = text
            .lines()
            .filter(|line| line.starts_with("adapter_request_refusals_total{check=\""))
            .count();
        assert_eq!(declared, registry_platform_authcommon::FailedCheck::COUNT);
    }

    /// The refusal line a scope refusal writes, driven through the recording
    /// layer with the scope values the answer carries.
    async fn refusal_line(check: registry_platform_authcommon::FailedCheck) -> String {
        use registry_platform_testing::CapturedDiagnosticLogs;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let recorder = Arc::new(RefusalRecorder::new("adapter_test").expect("recorder"));
        let app = Router::new()
            .route(
                "/",
                get(move || async move {
                    let mut response = StatusCode::FORBIDDEN.into_response();
                    response.extensions_mut().insert(RefusalNote::new(check));
                    response.extensions_mut().insert(
                        DeclaredScope::new("scope")
                            .with_required_scope("records.read")
                            .with_access_profile("records-reader"),
                    );
                    response
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                recorder,
                record_refusals,
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback test listener");
        let address = listener.local_addr().expect("the bound address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let logs = CapturedDiagnosticLogs::default();
        let _guard = tracing::dispatcher::set_default(&logs.subscriber());
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream
            .write_all(
                b"GET / HTTP/1.1\r\nhost: test\r\nauthorization: Bearer canary-token-scope\r\nconnection: close\r\n\r\n",
            )
            .await
            .expect("send");
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.expect("read");
        assert!(answer.starts_with(b"HTTP/1.1 403"));
        logs.text()
    }

    #[tokio::test]
    async fn metrics_responses_mark_development_only() {
        use registry_platform_config::Posture;
        for (posture, mark) in [
            (Posture::Production, None),
            (Posture::Development, Some("development")),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    metrics_router_in_posture(Arc::new(Metrics::default()), posture),
                )
                .await
            });
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            let headers = response.split_once("\r\n\r\n").unwrap().0;
            assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
            let actual = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("registry-posture")
                    .then(|| value.trim())
            });
            assert_eq!(actual, mark);
            task.abort();
        }
    }

    #[tokio::test]
    async fn a_scope_refusal_line_names_the_declared_values_and_no_token_value() {
        let text = refusal_line(registry_platform_authcommon::FailedCheck::Scope).await;
        assert!(text.contains("\"scope_claim\":\"scope\""), "{text}");
        assert!(
            text.contains("\"required_scope\":\"records.read\""),
            "{text}"
        );
        assert!(
            text.contains("\"access_profile\":\"records-reader\""),
            "{text}"
        );
        assert!(!text.contains("canary-token-scope"), "{text}");
    }

    #[tokio::test]
    async fn a_refusal_other_than_scope_names_no_declared_values() {
        let text = refusal_line(registry_platform_authcommon::FailedCheck::Operation).await;
        assert!(text.contains("request refused"), "{text}");
        assert!(!text.contains("scope_claim"), "{text}");
        assert!(!text.contains("required_scope"), "{text}");
    }

    fn text_has(metrics: &Metrics, line: &str) -> bool {
        metrics.render().lines().any(|found| found == line)
    }

    #[tokio::test]
    async fn partial_request_head_cannot_hold_metrics_shutdown_past_the_deadline() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback test listener");
        let address = listener.local_addr().expect("the bound address");
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(
            listener,
            Arc::new(Metrics::default()),
            async move {
                let _ = shutdown_rx.await;
            },
            std::time::Duration::from_millis(25),
            registry_platform_config::Posture::Production,
        ));

        let mut partial = tokio::net::TcpStream::connect(address)
            .await
            .expect("a client connects to the metrics listener");
        partial
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: loopback\r\nX-Stalled: ")
            .await
            .expect("write an intentionally incomplete request head");
        let mut barrier = tokio::net::TcpStream::connect(address)
            .await
            .expect("the accept loop continues past the partial connection");
        barrier
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: loopback\r\nConnection: close\r\n\r\n")
            .await
            .expect("write a complete request");
        let mut answer = String::new();
        barrier
            .read_to_string(&mut answer)
            .await
            .expect("the barrier response drains");
        assert!(
            answer.starts_with("HTTP/1.1 200"),
            "the request after the partial connection is answered with 200"
        );

        shutdown.send(()).expect("signal metrics-server shutdown");
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("the shutdown bound completes")
            .expect("the metrics server task joins");
        assert!(
            result.is_err(),
            "the stalled client is cut off at the deadline"
        );
        drop(partial);
    }
}
