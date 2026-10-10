//! Version 1 operational telemetry for the Evidence HTTP boundary.
//!
//! Operational records describe service health and performance only. The
//! reviewed field set is route template, operation identifier, trace ID,
//! duration, status category, the public problem code, and the runtime's internal
//! failure category; request bodies, selector profiles or values, source
//! responses, Supported Values, credentials, tokens, authority grants, and
//! script inputs are outside it. The internal failure category is safe to log
//! alongside the public problem code: it is drawn from a fixed, closed set of
//! static strings chosen by Rust, carries no request content, and collapses
//! every unresolved outcome (for example a record that was never found and a
//! record that matched more than once) into the single category the public
//! problem contract also collapses them into. A request that raises no
//! failure logs a fixed placeholder in its place, so the field is always
//! present. It is a log field only: the metric series below stays keyed by
//! route, method, status category, and public problem code, and neither the
//! log record's field set nor the metric series' label set can widen without
//! a review of this module.
//!
//! Source-boundary diagnostics are the one exception to route-keyed series.
//! [`SourceDiagnostics`] holds one entry per source the governed bundle
//! declares, fixed at startup, so its `source` label is bundle text drawn from
//! a closed set that no request can extend. It counts responses whose shape
//! drifted from the declared projection and emits rate-limited operator WARN
//! records that name the source, declared JSON pointers, and closed reasons,
//! never a response value, an undeclared member name, a selector, or a subject.

use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{header::CONTENT_TYPE, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use registry_platform_httpsec::{TraceContext, TraceId};
use ulid::Ulid;

use crate::{problem::ProblemCode, rate_limit::EvidenceRateLimiter};

/// Public correlation header returned on every response.
///
/// Evidence uses the shared W3C trace transport at this boundary. The
/// server-minted operation remains internal and never becomes caller-chosen.
#[cfg(test)]
pub(crate) const CORRELATION_HEADER: &str = "traceparent";

/// Target of the per-request operational record.
pub(crate) const REQUEST_LOG_TARGET: &str = "registry_evidence::request";

/// Target of source-boundary operator diagnostics, shared with the response
/// shape rejection the kernel reports.
pub(crate) const SOURCE_LOG_TARGET: &str = "registry_evidence::source";

/// The shortest interval between two WARN records of one kind for one source.
///
/// A source that changed shape fails every request, so one record per request
/// would let traffic decide how much the operator log holds. The counter still
/// sees every event, and the next record says how many were not logged.
const SOURCE_WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// How many distinct drift findings one WARN record reports.
const REPORTED_DRIFT_FINDINGS: usize = 5;

/// Route label used when no route template matched the request.
const UNMATCHED_ROUTE: &str = "unmatched";

/// Error label used when a response carries no problem code.
const NO_ERROR: &str = "none";

/// Category label used when a response carries no runtime failure.
const NO_CATEGORY: &str = "none";

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";

/// Upper bounds, in seconds, of the request duration histogram.
const DURATION_BUCKETS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// The request-scoped internal audit identifier, minted once at the boundary.
///
/// Handlers read it from the request extensions rather than minting their own,
/// so the audit record and operational log name the same server-minted
/// operation. The W3C trace is carried alongside it for public correlation.
#[derive(Clone)]
pub(crate) struct OperationId {
    value: Arc<str>,
    trace: TraceContext,
}

impl OperationId {
    fn new(trace: TraceContext) -> Self {
        Self {
            value: Ulid::generate().to_string().into(),
            trace,
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    pub(crate) fn trace_id(&self) -> TraceId {
        self.trace.trace_id.clone()
    }

    fn apply_trace(&self, headers: &mut axum::http::HeaderMap) {
        self.trace.apply(headers);
    }
}

impl Deref for OperationId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

/// The runtime's internal failure category, stashed in response extensions by
/// [`crate::server::runtime_failure_response`] the same way the public
/// [`ProblemCode`] is, so the observation layer can read it back without
/// reparsing the response body.
#[derive(Clone, Copy)]
pub(crate) struct FailureCategory(pub(crate) &'static str);

/// Read the boundary-minted identifier for this request.
///
/// The observation layer wraps every route including both fallbacks, so the
/// extension is always present. A handler reached without one would otherwise
/// report an operation that correlates with nothing, so the missing case mints
/// a fresh identifier rather than reporting an empty one.
pub(crate) fn operation_id(extensions: &axum::http::Extensions) -> OperationId {
    extensions.get::<OperationId>().map_or_else(
        || OperationId::new(TraceContext::server_created()),
        Clone::clone,
    )
}

/// Coarse outcome class. Operational records report the class, never the exact
/// status, because the exact status of a denial is part of the closed public
/// problem contract rather than an operational signal.
#[derive(Clone, Copy)]
enum StatusCategory {
    Success,
    ClientError,
    ServerError,
}

impl StatusCategory {
    fn of(status: StatusCode) -> Self {
        if status.is_server_error() {
            Self::ServerError
        } else if status.is_client_error() {
            Self::ClientError
        } else {
            Self::Success
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ClientError => "client-error",
            Self::ServerError => "server-error",
        }
    }
}

/// Observe one request: mint its identifier, serve it, then publish the
/// reviewed operational fields to the log and the metric registry.
pub(crate) async fn observe(
    State(metrics): State<Arc<Metrics>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let operation = OperationId::new(TraceContext::from_headers(request.headers()));
    let route = route_template(&request);
    let method = normalized_method(request.method());
    request.extensions_mut().insert(operation.clone());

    let started = Instant::now();
    let mut response = next.run(request).await;
    let elapsed = started.elapsed();

    let status = StatusCategory::of(response.status());
    let error = response
        .extensions()
        .get::<ProblemCode>()
        .map_or(NO_ERROR, |code| code.code());
    // Log-only: never fold into `metrics.record` below. The metric label set
    // is bounded by the route table under security invariant V1-I33, and this
    // per-failure category would multiply it unboundedly.
    let category = response
        .extensions()
        .get::<FailureCategory>()
        .map_or(NO_CATEGORY, |category| category.0);
    operation.apply_trace(response.headers_mut());

    metrics.record(route, method, status, error, elapsed);
    tracing::info!(
        target: REQUEST_LOG_TARGET,
        route,
        operation = operation.as_str(),
        trace_id = operation.trace_id().as_str(),
        duration_ms = duration_milliseconds(elapsed),
        status = status.as_str(),
        error,
        category,
        "evidence request served"
    );
    response
}

/// Resolve the matched route template.
///
/// Only templates the router registered are reported. An unrouted request
/// reports a single fixed label rather than its requested path, which keeps
/// both the log field and the metric label set bounded by the route table and
/// prevents a caller from writing arbitrary text into either.
fn route_template(request: &Request<Body>) -> &'static str {
    let Some(matched) = request.extensions().get::<MatchedPath>() else {
        return UNMATCHED_ROUTE;
    };
    crate::server::ROUTE_TEMPLATES
        .iter()
        .find(|template| **template == matched.as_str())
        .copied()
        .unwrap_or(UNMATCHED_ROUTE)
}

/// Fold the method into the closed set the route table can serve, so an
/// arbitrary request verb cannot create a metric series.
fn normalized_method(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

fn duration_milliseconds(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// In-process request counters and duration histogram.
///
/// Series are keyed only by the closed label set above, so the registry is
/// bounded by the route table regardless of traffic and needs no eviction.
#[derive(Default)]
pub(crate) struct Metrics {
    series: Mutex<BTreeMap<SeriesKey, Series>>,
    /// Current count of pseudonym keys tracked by the rate limiter, for the
    /// `evidence_rate_limiter_tracked_keys` gauge. Unlike `series`, this is
    /// not derived from request content: it is republished on every scrape
    /// from [`crate::rate_limit::EvidenceRateLimiter::tracked_key_count`],
    /// so it stays a single unlabeled series regardless of traffic. See
    /// security invariant V1-I33.
    rate_limiter_tracked_keys: AtomicUsize,
    /// The limiter the metrics scrape handler samples immediately before
    /// each render. `None` for registries that are never served on the
    /// metrics listener (for example, an unrelated middleware test).
    rate_limiter: Option<Arc<EvidenceRateLimiter>>,
    /// The per-source counters the runtime's source executors increment.
    /// `None` for registries built without a runtime.
    source_diagnostics: Option<Arc<SourceDiagnostics>>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SeriesKey {
    route: &'static str,
    method: &'static str,
    status: &'static str,
    error: &'static str,
}

#[derive(Default)]
struct Series {
    requests: u64,
    duration_sum: f64,
    bucket_counts: [u64; DURATION_BUCKETS.len()],
}

impl Metrics {
    /// A registry that serves the metrics listener: it samples `rate_limiter`
    /// on every scrape to publish the `evidence_rate_limiter_tracked_keys`
    /// gauge, and renders the per-source counters `source_diagnostics` holds.
    pub(crate) fn new(
        rate_limiter: Arc<EvidenceRateLimiter>,
        source_diagnostics: Arc<SourceDiagnostics>,
    ) -> Self {
        Self {
            rate_limiter: Some(rate_limiter),
            source_diagnostics: Some(source_diagnostics),
            ..Self::default()
        }
    }

    fn record(
        &self,
        route: &'static str,
        method: &'static str,
        status: StatusCategory,
        error: &'static str,
        elapsed: Duration,
    ) {
        let key = SeriesKey {
            route,
            method,
            status: status.as_str(),
            error,
        };
        let seconds = elapsed.as_secs_f64();
        let mut series = self
            .series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = series.entry(key).or_default();
        entry.requests += 1;
        entry.duration_sum += seconds;
        for (count, bound) in entry.bucket_counts.iter_mut().zip(DURATION_BUCKETS) {
            if seconds <= bound {
                *count += 1;
            }
        }
    }

    /// Publish the rate limiter's current tracked-key count for the next
    /// render.
    ///
    /// The caller reads the live count from the actual limiter (see
    /// [`crate::rate_limit::EvidenceRateLimiter::tracked_key_count`])
    /// immediately before calling this, so the published gauge reflects the
    /// limiter's state at scrape time rather than a value cached from an
    /// earlier request.
    pub(crate) fn record_rate_limiter_tracked_keys(&self, count: usize) {
        self.rate_limiter_tracked_keys
            .store(count, Ordering::Relaxed);
    }

    /// Render the Prometheus text exposition of the current registry.
    pub(crate) fn render(&self) -> String {
        let series = self
            .series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut body = String::new();
        body.push_str(
            "# HELP evidence_http_requests_total Requests served by the Evidence boundary.\n",
        );
        body.push_str("# TYPE evidence_http_requests_total counter\n");
        for (key, value) in series.iter() {
            body.push_str(&format!(
                "evidence_http_requests_total{{{}}} {}\n",
                labels(key),
                value.requests
            ));
        }
        body.push_str(
            "# HELP evidence_http_request_duration_seconds Request duration at the Evidence boundary.\n",
        );
        body.push_str("# TYPE evidence_http_request_duration_seconds histogram\n");
        for (key, value) in series.iter() {
            for (count, bound) in value.bucket_counts.iter().zip(DURATION_BUCKETS) {
                body.push_str(&format!(
                    "evidence_http_request_duration_seconds_bucket{{{},le=\"{bound}\"}} {count}\n",
                    labels(key)
                ));
            }
            body.push_str(&format!(
                "evidence_http_request_duration_seconds_bucket{{{},le=\"+Inf\"}} {}\n",
                labels(key),
                value.requests
            ));
            body.push_str(&format!(
                "evidence_http_request_duration_seconds_sum{{{}}} {}\n",
                labels(key),
                value.duration_sum
            ));
            body.push_str(&format!(
                "evidence_http_request_duration_seconds_count{{{}}} {}\n",
                labels(key),
                value.requests
            ));
        }
        body.push_str(
            "# HELP evidence_rate_limiter_tracked_keys Pseudonym keys currently tracked by the rate limiter.\n",
        );
        body.push_str("# TYPE evidence_rate_limiter_tracked_keys gauge\n");
        body.push_str(&format!(
            "evidence_rate_limiter_tracked_keys {}\n",
            self.rate_limiter_tracked_keys.load(Ordering::Relaxed)
        ));
        if let Some(source_diagnostics) = &self.source_diagnostics {
            source_diagnostics.render(&mut body);
        }
        body
    }
}

/// Why a source's 404 was not the declared unresolved outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UndeclaredNotFound {
    /// The source declares no `unresolvedProblem`.
    NotDeclared,
    /// The source declares one and this response was not exactly it.
    NotMatched,
}

impl UndeclaredNotFound {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotDeclared => "not declared",
            Self::NotMatched => "not matched",
        }
    }
}

/// Value-free operator diagnostics for every governed source.
///
/// The entry set is fixed when the runtime starts, from the bundle's own
/// source identifiers, so neither the log nor the `source` label can grow with
/// traffic. A report for an identifier outside that set is dropped.
pub(crate) struct SourceDiagnostics {
    sources: BTreeMap<String, SourceSignals>,
}

#[derive(Default)]
struct SourceSignals {
    shape_drift_total: AtomicU64,
    shape_drift_warning: Mutex<WarningWindow>,
    undeclared_not_found_warning: Mutex<WarningWindow>,
}

/// One kind of WARN for one source, admitted at most once per interval.
#[derive(Default)]
struct WarningWindow {
    last_logged: Option<Instant>,
    suppressed: u64,
}

impl WarningWindow {
    /// Whether an event at `now` is logged. When it is, the answer is how many
    /// events of the same kind were not logged since the previous record.
    fn admit(&mut self, now: Instant) -> Option<u64> {
        if self
            .last_logged
            .is_some_and(|last| now.saturating_duration_since(last) < SOURCE_WARNING_INTERVAL)
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.last_logged = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

impl SourceDiagnostics {
    pub(crate) fn new<'a>(source_ids: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            sources: source_ids
                .into_iter()
                .map(|source_id| (source_id.to_owned(), SourceSignals::default()))
                .collect(),
        }
    }

    /// The reporting handle one source executor holds, if `source_id` is one
    /// of the governed sources.
    pub(crate) fn observer(self: &Arc<Self>, source_id: &str) -> Option<SourceObserver> {
        self.sources
            .contains_key(source_id)
            .then(|| SourceObserver {
                diagnostics: Arc::clone(self),
                source_id: source_id.to_owned(),
            })
    }

    fn shape_drift(&self, source_id: &str, findings: &[String], now: Instant) {
        let Some(signals) = self.sources.get(source_id) else {
            return;
        };
        signals.shape_drift_total.fetch_add(1, Ordering::Relaxed);
        let admitted = signals
            .shape_drift_warning
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .admit(now);
        let Some(suppressed) = admitted else {
            return;
        };
        let reported = findings
            .iter()
            .take(REPORTED_DRIFT_FINDINGS)
            .map(String::as_str)
            .collect::<Vec<_>>();
        tracing::warn!(
            target: SOURCE_LOG_TARGET,
            source = source_id,
            violations = reported.join("; "),
            total_violations = findings.len(),
            suppressed,
            "the source response does not match its declared projection"
        );
    }

    fn undeclared_not_found(&self, source_id: &str, reason: UndeclaredNotFound, now: Instant) {
        let Some(signals) = self.sources.get(source_id) else {
            return;
        };
        let admitted = signals
            .undeclared_not_found_warning
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .admit(now);
        let Some(suppressed) = admitted else {
            return;
        };
        tracing::warn!(
            target: SOURCE_LOG_TARGET,
            source = source_id,
            unresolved_problem = reason.as_str(),
            suppressed,
            "source answered 404 with an undeclared shape"
        );
    }

    fn render(&self, body: &mut String) {
        body.push_str(
            "# HELP evidence_source_shape_drift_total Source responses whose shape departed from the declared projection.\n",
        );
        body.push_str("# TYPE evidence_source_shape_drift_total counter\n");
        for (source_id, signals) in &self.sources {
            body.push_str(&format!(
                "evidence_source_shape_drift_total{{source=\"{}\"}} {}\n",
                escape_label_value(source_id),
                signals.shape_drift_total.load(Ordering::Relaxed)
            ));
        }
    }
}

/// Escape a label value under the Prometheus text exposition rules. Source
/// identifiers are governed bundle text, but the exposition must stay
/// well-formed whatever that text holds.
fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// The handle one source executor reports its diagnostics through.
#[derive(Clone)]
pub(crate) struct SourceObserver {
    diagnostics: Arc<SourceDiagnostics>,
    source_id: String,
}

impl SourceObserver {
    /// Count one response whose shape drifted and, at most once per interval,
    /// log the declared pointers it drifted at.
    pub(crate) fn shape_drift(&self, findings: &[String]) {
        self.diagnostics
            .shape_drift(&self.source_id, findings, Instant::now());
    }

    /// Log, at most once per interval, that a 404 was not the declared
    /// unresolved outcome.
    pub(crate) fn undeclared_not_found(&self, reason: UndeclaredNotFound) {
        self.diagnostics
            .undeclared_not_found(&self.source_id, reason, Instant::now());
    }
}

fn labels(key: &SeriesKey) -> String {
    format!(
        "route=\"{}\",method=\"{}\",status=\"{}\",error=\"{}\"",
        key.route, key.method, key.status, key.error
    )
}

/// Build the metrics application.
///
/// It is a separate application on a separate listener: the served counters
/// are operator material, and the public evidence contract does not describe
/// them. Every other path on this listener is unserved rather than delegated
/// back to the evidence routes.
pub(crate) fn metrics_app(metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .fallback(metrics_route_absent)
        .with_state(metrics)
}

async fn render_metrics(State(metrics): State<Arc<Metrics>>) -> Response {
    // Sampled fresh on every scrape rather than cached from request
    // handling, so the gauge reflects the limiter's state at scrape time.
    // A registry built without a limiter (see `Metrics::default`) has
    // nothing to sample and leaves the gauge at its initial zero.
    if let Some(rate_limiter) = &metrics.rate_limiter {
        metrics.record_rate_limiter_tracked_keys(rate_limiter.tracked_key_count().await);
    }
    let mut response = (StatusCode::OK, metrics.render()).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(METRICS_MEDIA_TYPE));
    response
}

async fn metrics_route_absent() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_class_is_kebab_case() {
        assert_eq!(StatusCategory::of(StatusCode::OK).as_str(), "success");
        assert_eq!(
            StatusCategory::of(StatusCode::FORBIDDEN).as_str(),
            "client-error"
        );
        assert_eq!(
            StatusCategory::of(StatusCode::SERVICE_UNAVAILABLE).as_str(),
            "server-error"
        );
    }

    #[test]
    fn series_labels_stay_bounded_by_the_closed_route_and_method_sets() {
        // An arbitrary verb and an unrouted path must not each create a series.
        let metrics = Metrics::default();
        for method in [
            Method::from_bytes(b"PATCH").expect("a valid method"),
            Method::from_bytes(b"BREW").expect("a valid method"),
        ] {
            metrics.record(
                UNMATCHED_ROUTE,
                normalized_method(&method),
                StatusCategory::ClientError,
                ProblemCode::MalformedRequest.code(),
                Duration::from_millis(1),
            );
        }
        let rendered = metrics.render();
        assert_eq!(
            rendered
                .matches("evidence_http_requests_total{route=\"unmatched\",method=\"other\"")
                .count(),
            1,
            "unrecognized methods collapse onto one series"
        );
        assert!(
            rendered.contains("status=\"client-error\",error=\"evidence.invalid-request\"} 2\n")
        );
    }

    #[test]
    fn repeated_inbound_trace_ids_keep_distinct_server_minted_operations() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"),
        );
        let first = OperationId::new(TraceContext::from_headers(&headers));
        let second = OperationId::new(TraceContext::from_headers(&headers));

        assert_eq!(
            first.trace_id().as_str(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(first.trace_id(), second.trace_id());
        assert_ne!(first.as_str(), second.as_str());
    }

    #[test]
    fn rate_limiter_tracked_keys_gauge_is_a_single_unlabeled_series() {
        let metrics = Metrics::default();
        // Populate unrelated request series first, to prove the gauge does
        // not multiply per label the way the request counter and duration
        // histogram do.
        metrics.record(
            "/health",
            "GET",
            StatusCategory::Success,
            NO_ERROR,
            Duration::from_millis(1),
        );
        metrics.record(
            "/v1/evidence",
            "POST",
            StatusCategory::ClientError,
            ProblemCode::MalformedRequest.code(),
            Duration::from_millis(1),
        );
        metrics.record_rate_limiter_tracked_keys(42);

        let rendered = metrics.render();
        assert_eq!(
            rendered
                .matches("evidence_rate_limiter_tracked_keys")
                .count(),
            3, // HELP line, TYPE line, and exactly one value line
            "the gauge is emitted once regardless of how many request series exist"
        );
        assert!(rendered.contains("\nevidence_rate_limiter_tracked_keys 42\n"));
        assert!(
            !rendered.contains("evidence_rate_limiter_tracked_keys{"),
            "the gauge must carry no labels"
        );
    }

    #[tokio::test]
    async fn rate_limiter_tracked_keys_gauge_reflects_keys_added_through_the_limiter_api() {
        use crate::rate_limit::{EvidenceRateLimiter, RateLimitConfig};

        let limiter = EvidenceRateLimiter::new(RateLimitConfig {
            requests_per_principal_per_minute: 60,
            burst_per_principal: 2,
            failed_selector_attempts_per_principal_authority_per_minute: 2,
        })
        .expect("limiter builds");
        limiter
            .check_request("pseudonym-a")
            .await
            .expect("first principal");
        limiter
            .check_request("pseudonym-b")
            .await
            .expect("second principal");
        limiter
            .record_selector_failure("authority-a")
            .await
            .expect("first failure");

        let metrics = Metrics::default();
        metrics.record_rate_limiter_tracked_keys(limiter.tracked_key_count().await);

        let rendered = metrics.render();
        assert!(rendered.contains("\nevidence_rate_limiter_tracked_keys 3\n"));
    }

    /// The gauge must come from the live limiter at scrape time, not from a
    /// value recorded during earlier request handling. Drive a real limiter
    /// through its public API, wire it into a registry the way production
    /// startup does, and scrape it through the actual `/metrics` router
    /// rather than calling `render` directly.
    #[tokio::test]
    async fn metrics_endpoint_samples_the_live_rate_limiter_at_scrape_time() {
        use crate::rate_limit::{EvidenceRateLimiter, RateLimitConfig};

        let limiter = Arc::new(
            EvidenceRateLimiter::new(RateLimitConfig {
                requests_per_principal_per_minute: 60,
                burst_per_principal: 2,
                failed_selector_attempts_per_principal_authority_per_minute: 2,
            })
            .expect("limiter builds"),
        );
        limiter
            .check_request("pseudonym-a")
            .await
            .expect("first principal");
        limiter
            .check_request("pseudonym-b")
            .await
            .expect("second principal");
        limiter
            .record_selector_failure("authority-a")
            .await
            .expect("first failure");
        let expected = limiter.tracked_key_count().await;
        assert_eq!(
            expected, 3,
            "three distinct tracked keys precede the scrape"
        );

        let metrics = Arc::new(Metrics::new(
            Arc::clone(&limiter),
            Arc::new(SourceDiagnostics::new(["source-a"])),
        ));
        let server = axum_test::TestServer::new(metrics_app(metrics));

        let response = server.get("/metrics").await;
        response.assert_status_ok();
        let body = response.text();
        assert!(body.contains(&format!(
            "\nevidence_rate_limiter_tracked_keys {expected}\n"
        )));
        assert!(
            !body.contains("evidence_audit_"),
            "the audit destination publishes no capacity gauge"
        );

        // A key tracked after the registry was built is still visible on the
        // next scrape, proving the value is sampled live rather than cached
        // from construction time.
        limiter
            .check_request("pseudonym-c")
            .await
            .expect("third principal");
        let response = server.get("/metrics").await;
        response.assert_status_ok();
        let body = response.text();
        assert!(body.contains("\nevidence_rate_limiter_tracked_keys 4\n"));
    }

    /// One WARN per interval per kind: the first event is logged, the rest
    /// inside the interval are counted, and the next logged record carries
    /// that count so the log still says how often it happened.
    #[test]
    fn a_warning_window_logs_once_per_interval_and_reports_what_it_suppressed() {
        let mut window = WarningWindow::default();
        let start = Instant::now();
        assert_eq!(window.admit(start), Some(0));
        assert_eq!(window.admit(start + Duration::from_secs(1)), None);
        assert_eq!(
            window.admit(start + SOURCE_WARNING_INTERVAL - Duration::from_millis(1)),
            None
        );
        assert_eq!(window.admit(start + SOURCE_WARNING_INTERVAL), Some(2));
        assert_eq!(
            window.admit(start + SOURCE_WARNING_INTERVAL + Duration::from_secs(1)),
            None
        );
        assert_eq!(window.admit(start + SOURCE_WARNING_INTERVAL * 3), Some(1));
    }

    /// The `source` label is drawn from the governed source set fixed at
    /// startup. A report for any other identifier creates no series, and the
    /// counter counts every drifted response even when its WARN is suppressed.
    #[test]
    fn shape_drift_series_stay_bounded_by_the_governed_sources() {
        let diagnostics = Arc::new(SourceDiagnostics::new(["source-a", "source-b"]));
        assert!(diagnostics.observer("not-governed").is_none());
        let findings = vec!["/total is absent".to_owned()];
        let now = Instant::now();
        diagnostics.shape_drift("source-a", &findings, now);
        diagnostics.shape_drift("source-a", &findings, now);
        diagnostics.shape_drift("not-governed", &findings, now);
        diagnostics.undeclared_not_found("source-b", UndeclaredNotFound::NotDeclared, now);

        let mut body = String::new();
        diagnostics.render(&mut body);
        assert_eq!(
            body,
            "# HELP evidence_source_shape_drift_total Source responses whose shape departed from the declared projection.\n\
             # TYPE evidence_source_shape_drift_total counter\n\
             evidence_source_shape_drift_total{source=\"source-a\"} 2\n\
             evidence_source_shape_drift_total{source=\"source-b\"} 0\n"
        );
    }

    #[test]
    fn source_label_values_are_escaped_for_the_text_exposition() {
        assert_eq!(escape_label_value("plain-id"), "plain-id");
        assert_eq!(escape_label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn a_registry_built_with_source_diagnostics_renders_them_after_the_request_series() {
        let limiter = Arc::new(
            EvidenceRateLimiter::new(crate::rate_limit::RateLimitConfig {
                requests_per_principal_per_minute: 60,
                burst_per_principal: 2,
                failed_selector_attempts_per_principal_authority_per_minute: 2,
            })
            .expect("limiter builds"),
        );
        let metrics = Metrics::new(limiter, Arc::new(SourceDiagnostics::new(["source-a"])));
        let rendered = metrics.render();
        assert!(rendered.contains("\nevidence_source_shape_drift_total{source=\"source-a\"} 0\n"));
        assert!(
            !Metrics::default()
                .render()
                .contains("evidence_source_shape_drift_total"),
            "a registry without a runtime publishes no source series"
        );
    }

    #[test]
    fn duration_buckets_are_cumulative_and_carry_an_infinite_bound() {
        let metrics = Metrics::default();
        metrics.record(
            "/health",
            "GET",
            StatusCategory::Success,
            NO_ERROR,
            Duration::from_millis(30),
        );
        let rendered = metrics.render();
        assert!(rendered.contains("le=\"0.025\"} 0\n"));
        assert!(rendered.contains("le=\"0.05\"} 1\n"));
        assert!(rendered.contains("le=\"+Inf\"} 1\n"));
        assert!(rendered.contains("evidence_http_request_duration_seconds_count{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\"} 1\n"));
    }
}
