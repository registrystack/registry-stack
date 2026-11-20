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
use std::sync::Arc;

use axum::extract::{MatchedPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use registry_adapter_core::ErrorClass;
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

pub struct Metrics {
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
        ] {
            counter.write(&mut out).expect(DECLARATION);
        }
        out.finish()
    }
}

/// Count one event. A series the space refuses is not added; the refusal is
/// logged by metric name alone, never by label value.
fn count(counter: &CounterVec, values: &[&str]) {
    if let Err(error) = counter.inc(values) {
        tracing::warn!(error = %error, "a metric series was refused");
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
    if status.is_server_error() {
        "5xx"
    } else if status.is_client_error() {
        "4xx"
    } else {
        "2xx"
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

/// The router the metrics listener serves: the counters and nothing else.
pub fn metrics_router(metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route(
            METRICS_PATH,
            get(|State(metrics): State<Arc<Metrics>>| async move {
                ([(CONTENT_TYPE, METRICS_CONTENT_TYPE)], metrics.render()).into_response()
            }),
        )
        .with_state(metrics)
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

    fn text_has(metrics: &Metrics, line: &str) -> bool {
        metrics.render().lines().any(|found| found == line)
    }
}
