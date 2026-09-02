// SPDX-License-Identifier: Apache-2.0
//! Opt-in operational metrics for Registry Server.
//!
//! The registry below only ever serves the operator-private metrics listener
//! started by an explicit `metricsListener` runtime configuration member. It
//! is a separate binding rather than a route on the Registry listener, so the
//! public Registry contract on that listener is unchanged and reaching the
//! counters requires reaching a different socket.
//!
//! Series labels are closed by construction: the route label is only ever the
//! axum [`MatchedPath`] template the router actually matched (or a single
//! fixed `unmatched` label), the method label is a fixed vocabulary, and the
//! status label is one of three coarse classes. Request paths, query values,
//! principals, record identifiers, and problem codes never become labels, so
//! a caller cannot write arbitrary text into a series and the series count is
//! bounded by the route table regardless of traffic. The pool gauges are
//! republished from the live pool at scrape time and carry only a fixed state
//! label.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{header::CONTENT_TYPE, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use crate::postgres::RuntimePool;

/// Route label used when no registered route template matched the request.
pub(crate) const UNMATCHED_ROUTE: &str = "unmatched";

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";

/// Upper bounds, in seconds, of the request duration histogram.
const DURATION_BUCKETS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// In-process request counters, a duration histogram, and live pool gauges.
///
/// Series are keyed only by the closed label set described on this module, so
/// the registry is bounded by the route table regardless of traffic and needs
/// no eviction.
#[derive(Default)]
pub struct Metrics {
    series: Mutex<BTreeMap<HttpSeriesKey, HttpSeries>>,
    /// The pool the metrics scrape handler samples immediately before each
    /// render. `None` for registries that are never served on the metrics
    /// listener (for example, a focused unit test).
    pool: Option<RuntimePool>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HttpSeriesKey {
    route: String,
    method: &'static str,
    status: &'static str,
}

#[derive(Default)]
struct HttpSeries {
    requests: u64,
    duration_sum: f64,
    bucket_counts: [u64; DURATION_BUCKETS.len()],
}

impl Metrics {
    /// A registry that serves the metrics listener: it samples `pool` on every
    /// scrape to publish the pool gauges.
    pub(crate) fn new(pool: RuntimePool) -> Self {
        Self {
            pool: Some(pool),
            ..Self::default()
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn without_pool_for_test() -> Self {
        Self::default()
    }

    /// Record one served request. `route` must come from
    /// [`route_template`] so the label set stays closed.
    pub(crate) fn record_http(
        &self,
        route: &str,
        method: &'static str,
        status: &'static str,
        elapsed: Duration,
    ) {
        let key = HttpSeriesKey {
            route: route.to_owned(),
            method,
            status,
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
            "# HELP registry_server_http_requests_total Requests served by the Registry boundary.\n",
        );
        body.push_str("# TYPE registry_server_http_requests_total counter\n");
        for (key, value) in series.iter() {
            body.push_str(&format!(
                "registry_server_http_requests_total{{{}}} {}\n",
                labels(key),
                value.requests
            ));
        }
        body.push_str(
            "# HELP registry_server_http_request_duration_seconds Request duration at the Registry boundary.\n",
        );
        body.push_str("# TYPE registry_server_http_request_duration_seconds histogram\n");
        for (key, value) in series.iter() {
            for (count, bound) in value.bucket_counts.iter().zip(DURATION_BUCKETS) {
                body.push_str(&format!(
                    "registry_server_http_request_duration_seconds_bucket{{{},le=\"{bound}\"}} {count}\n",
                    labels(key)
                ));
            }
            body.push_str(&format!(
                "registry_server_http_request_duration_seconds_bucket{{{},le=\"+Inf\"}} {}\n",
                labels(key),
                value.requests
            ));
            body.push_str(&format!(
                "registry_server_http_request_duration_seconds_sum{{{}}} {}\n",
                labels(key),
                value.duration_sum
            ));
            body.push_str(&format!(
                "registry_server_http_request_duration_seconds_count{{{}}} {}\n",
                labels(key),
                value.requests
            ));
        }
        body.push_str(
            "# HELP registry_server_pool_connections Runtime pool connections by state.\n",
        );
        body.push_str("# TYPE registry_server_pool_connections gauge\n");
        // Sampled fresh on every scrape rather than cached from request
        // handling, so the gauges reflect the pool's state at scrape time. A
        // registry built without a pool (see `Metrics::default`) has nothing
        // to sample and leaves the gauges at their initial zero.
        let status = self.pool.as_ref().map(RuntimePool::status);
        for (state, count) in [
            ("max_size", status.as_ref().map(|s| s.max_size)),
            ("size", status.as_ref().map(|s| s.size)),
            ("available", status.as_ref().map(|s| s.available)),
            ("waiting", status.as_ref().map(|s| s.waiting)),
        ] {
            body.push_str(&format!(
                "registry_server_pool_connections{{state=\"{state}\"}} {}\n",
                count.unwrap_or(0)
            ));
        }
        body
    }
}

fn labels(key: &HttpSeriesKey) -> String {
    format!(
        "route=\"{}\",method=\"{}\",status=\"{}\"",
        key.route, key.method, key.status
    )
}

/// Resolve the matched route template for metrics recording.
///
/// Only templates the router registered are reported, so the value is bounded
/// by the compiled route table: record identifiers appear as `{record_id}`
/// placeholders, never as values. An unrouted request reports a single fixed
/// label rather than its requested path.
pub(crate) fn route_template(request: &Request<Body>) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map_or(UNMATCHED_ROUTE, |matched| matched.as_str())
}

/// Build the metrics application.
///
/// It is a separate application on a separate listener: the served counters
/// are operator material, and the public Registry contract does not describe
/// them. Every other path on this listener is unserved rather than delegated
/// back to the Registry routes.
pub fn metrics_app(metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .fallback(metrics_route_absent)
        .method_not_allowed_fallback(metrics_route_absent)
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
    use axum::http::Method;
    use axum::middleware::Next;
    use tower::util::ServiceExt;

    #[test]
    fn duration_buckets_are_cumulative_and_carry_an_infinite_bound() {
        let metrics = Metrics::default();
        metrics.record_http("/health", "GET", "success", Duration::from_millis(30));
        let rendered = metrics.render();
        assert!(rendered.contains("le=\"0.025\"} 0\n"));
        assert!(rendered.contains("le=\"0.05\"} 1\n"));
        assert!(rendered.contains("le=\"+Inf\"} 1\n"));
        assert!(rendered.contains(
            "registry_server_http_request_duration_seconds_count{route=\"/health\",method=\"GET\",status=\"success\"} 1\n"
        ));
    }

    #[test]
    fn series_labels_stay_bounded_by_the_closed_route_and_method_sets() {
        // One fixed unmatched label regardless of how exotic the requested
        // path was, and one series per distinct registered template.
        let metrics = Metrics::default();
        metrics.record_http(
            UNMATCHED_ROUTE,
            "OTHER",
            "client_error",
            Duration::from_millis(1),
        );
        metrics.record_http(
            UNMATCHED_ROUTE,
            "OTHER",
            "client_error",
            Duration::from_millis(2),
        );
        let rendered = metrics.render();
        assert_eq!(
            rendered
                .matches("registry_server_http_requests_total{route=\"unmatched\"")
                .count(),
            1,
            "unrouted requests collapse onto one series"
        );
    }

    #[test]
    fn pool_gauges_are_four_fixed_state_series() {
        let metrics = Metrics::default();
        metrics.record_http("/v1/records", "GET", "success", Duration::from_millis(1));
        let rendered = metrics.render();
        for state in ["max_size", "size", "available", "waiting"] {
            assert_eq!(
                rendered
                    .matches(&format!(
                        "registry_server_pool_connections{{state=\"{state}\"}}"
                    ))
                    .count(),
                1,
                "one {state} gauge regardless of request series"
            );
        }
        assert!(
            !rendered.contains("registry_server_pool_connections{route="),
            "pool gauges carry no route label"
        );
    }

    #[tokio::test]
    async fn metrics_app_serves_prometheus_text_and_refuses_other_paths() {
        let metrics = Arc::new(Metrics::default());
        metrics.record_http("/health", "GET", "success", Duration::from_millis(5));
        let app = metrics_app(Arc::clone(&metrics));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("metrics request builds"),
            )
            .await
            .expect("metrics request responds");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], METRICS_MEDIA_TYPE,);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("metrics body reads");
        let body = std::str::from_utf8(&body).expect("metrics body is UTF-8");
        assert!(body.contains("# TYPE registry_server_http_requests_total counter\n"));
        assert!(body.contains("# TYPE registry_server_pool_connections gauge\n"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/metrics")
                    .body(Body::empty())
                    .expect("metrics post builds"),
            )
            .await
            .expect("metrics post responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/records")
                    .body(Body::empty())
                    .expect("absent path builds"),
            )
            .await
            .expect("absent path responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Drive a real router so the label comes from the mechanism production
    /// uses: the path pattern the router matched, never the requested values.
    #[tokio::test]
    async fn route_template_reports_the_registered_pattern_not_the_request_values() {
        async fn tag_route(request: Request<Body>, next: Next) -> Response {
            let template = route_template(&request).to_owned();
            let mut response = next.run(request).await;
            if let Ok(value) = HeaderValue::from_str(&template) {
                response.headers_mut().insert("x-route-template", value);
            }
            response
        }
        let app = Router::new()
            .route(
                "/v1/records/establishments/{record_id}",
                get(|| async { "record" }),
            )
            .layer(axum::middleware::from_fn(tag_route));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/records/establishments/2f0f6aa9-1cde-4b0e-b5a4-38d7f33f6b11")
                    .body(Body::empty())
                    .expect("record request builds"),
            )
            .await
            .expect("record request responds");
        assert_eq!(
            response.headers()["x-route-template"],
            "/v1/records/establishments/{record_id}",
            "the record identifier in the URI never reaches the label"
        );

        // An unrouted path carries no matched pattern, so the fixed
        // unmatched marker is reported instead of the requested path.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/records/establishments/not/a/uuid/extra")
                    .body(Body::empty())
                    .expect("unrouted request builds"),
            )
            .await
            .expect("unrouted request responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["x-route-template"], UNMATCHED_ROUTE);
    }
}
