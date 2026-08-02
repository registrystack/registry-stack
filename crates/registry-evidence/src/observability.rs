//! Version 1 operational telemetry for the Evidence HTTP boundary.
//!
//! Operational records describe service health and performance only. The
//! reviewed field set is route template, operation identifier, duration,
//! status category, and safe internal error category; request bodies, selector
//! profiles or values, source responses, Supported Values, credentials,
//! tokens, authority grants, and script inputs are outside it. Both the log
//! record and the metric series below are built from that same closed set, so
//! neither can widen without a review of this module.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{header::CONTENT_TYPE, HeaderName, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use ulid::Ulid;

use crate::problem::ProblemCode;

/// Correlation identifier returned to the caller on every response.
///
/// Requests carry no inbound correlation value: the listener contract fixes
/// `trustProxyIdentityHeaders` to false, so a client-supplied identifier would
/// let a caller choose the key its own records are filed under.
pub(crate) const CORRELATION_HEADER: &str = "x-request-id";

/// Target of the per-request operational record.
pub(crate) const REQUEST_LOG_TARGET: &str = "registry_evidence::request";

/// Route label used when no route template matched the request.
const UNMATCHED_ROUTE: &str = "unmatched";

/// Error label used when a response carries no problem code.
const NO_ERROR: &str = "none";

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";

/// Upper bounds, in seconds, of the request duration histogram.
const DURATION_BUCKETS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// The request-scoped correlation identifier, minted once at the boundary.
///
/// Handlers read it from the request extensions rather than minting their own,
/// so the problem body, the audit record, the operational log record, and the
/// response header all name the same operation.
#[derive(Clone)]
pub(crate) struct OperationId(Arc<str>);

impl OperationId {
    fn new() -> Self {
        Self(Ulid::new().to_string().into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Read the boundary-minted identifier for this request.
///
/// The observation layer wraps every route including both fallbacks, so the
/// extension is always present. A handler reached without one would otherwise
/// report an operation that correlates with nothing, so the missing case mints
/// a fresh identifier rather than reporting an empty one.
pub(crate) fn operation_id(extensions: &axum::http::Extensions) -> String {
    extensions.get::<OperationId>().map_or_else(
        || OperationId::new().as_str().to_owned(),
        |id| id.0.to_string(),
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
            Self::ClientError => "client_error",
            Self::ServerError => "server_error",
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
    let operation = OperationId::new();
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
    response.headers_mut().insert(
        HeaderName::from_static(CORRELATION_HEADER),
        HeaderValue::from_str(operation.as_str())
            .expect("a Crockford base32 identifier is a valid header value"),
    );

    metrics.record(route, method, status, error, elapsed);
    tracing::info!(
        target: REQUEST_LOG_TARGET,
        route,
        operation = operation.as_str(),
        duration_ms = duration_milliseconds(elapsed),
        status = status.as_str(),
        error,
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
        body
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
        assert!(rendered.contains("status=\"client_error\",error=\"malformed_request\"} 2\n"));
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
