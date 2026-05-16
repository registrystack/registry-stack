// SPDX-License-Identifier: Apache-2.0
//! Bounded in-process metrics for the HTTP surface.
//!
//! The collector intentionally keeps its label set small and stable. It
//! never records raw paths, query strings, request ids, principals,
//! key ids, subjects, purpose headers, or client addresses.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use axum::body::Body;
use axum::extract::MatchedPath;
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use tokio::sync::watch;

use crate::audit::{EndpointKind, ErrorCodeExt};
use crate::ingest::ReadinessSnapshot;

const TEXT_PLAIN_004: HeaderValue =
    HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8");
const NO_ERROR_CODE: &str = "none";
const HISTOGRAM_BUCKETS: [f64; 12] = [
    0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500, 5.000, 10.000, 30.000,
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RequestLabels {
    method: &'static str,
    endpoint_kind: &'static str,
    status_code: u16,
    status_class: &'static str,
    error_code: String,
}

#[derive(Debug, Clone)]
struct RequestSeries {
    count: u64,
    duration_sum_seconds: f64,
    duration_buckets: [u64; HISTOGRAM_BUCKETS.len()],
}

impl Default for RequestSeries {
    fn default() -> Self {
        Self {
            count: 0,
            duration_sum_seconds: 0.0,
            duration_buckets: [0; HISTOGRAM_BUCKETS.len()],
        }
    }
}

/// Shared request metrics collector.
#[derive(Debug, Default)]
pub struct RequestMetrics {
    series: Mutex<BTreeMap<RequestLabels, RequestSeries>>,
}

impl RequestMetrics {
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn observe(&self, labels: RequestLabels, duration_seconds: f64) {
        let mut series = lock_or_recover(&self.series);
        let entry = series.entry(labels).or_default();
        entry.count = entry.count.saturating_add(1);
        entry.duration_sum_seconds += duration_seconds;
        for (index, bucket) in HISTOGRAM_BUCKETS.iter().enumerate() {
            if duration_seconds <= *bucket {
                entry.duration_buckets[index] = entry.duration_buckets[index].saturating_add(1);
            }
        }
    }

    fn render(&self, readiness: Option<&ReadinessSnapshot>) -> String {
        let series = lock_or_recover(&self.series).clone();
        let mut out = String::new();

        out.push_str("# HELP data_gate_http_requests_total Total HTTP requests by safe route family labels.\n");
        out.push_str("# TYPE data_gate_http_requests_total counter\n");
        for (labels, values) in &series {
            writeln!(
                out,
                "data_gate_http_requests_total{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\"}} {}",
                labels.method,
                labels.endpoint_kind,
                labels.status_code,
                labels.status_class,
                escape_label(&labels.error_code),
                values.count
            )
            .expect("write to String cannot fail");
        }

        out.push_str("# HELP data_gate_http_request_duration_seconds HTTP request duration histogram by safe route family labels.\n");
        out.push_str("# TYPE data_gate_http_request_duration_seconds histogram\n");
        for (labels, values) in &series {
            for (index, bucket) in HISTOGRAM_BUCKETS.iter().enumerate() {
                writeln!(
                    out,
                    "data_gate_http_request_duration_seconds_bucket{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\",le=\"{:.3}\"}} {}",
                    labels.method,
                    labels.endpoint_kind,
                    labels.status_code,
                    labels.status_class,
                    escape_label(&labels.error_code),
                    bucket,
                    values.duration_buckets[index]
                )
                .expect("write to String cannot fail");
            }
            writeln!(
                out,
                "data_gate_http_request_duration_seconds_bucket{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\",le=\"+Inf\"}} {}",
                labels.method,
                labels.endpoint_kind,
                labels.status_code,
                labels.status_class,
                escape_label(&labels.error_code),
                values.count
            )
            .expect("write to String cannot fail");
            writeln!(
                out,
                "data_gate_http_request_duration_seconds_sum{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\"}} {:.6}",
                labels.method,
                labels.endpoint_kind,
                labels.status_code,
                labels.status_class,
                escape_label(&labels.error_code),
                values.duration_sum_seconds
            )
            .expect("write to String cannot fail");
            writeln!(
                out,
                "data_gate_http_request_duration_seconds_count{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\"}} {}",
                labels.method,
                labels.endpoint_kind,
                labels.status_code,
                labels.status_class,
                escape_label(&labels.error_code),
                values.count
            )
            .expect("write to String cannot fail");
        }

        render_readiness(readiness, &mut out);
        out
    }
}

/// Install the metrics recorder on any router that goes through the
/// server's cross-cutting layer stack.
pub fn install<S>(router: Router<S>, metrics: Arc<RequestMetrics>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(from_fn_with_state(metrics, record_request))
}

/// Admin-listener-only metrics route. Server wiring decides which
/// listener owns this route; the admin listener's network boundary is
/// the scrape boundary.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/metrics", get(metrics))
}

async fn metrics(
    Extension(metrics): Extension<Arc<RequestMetrics>>,
    readiness: Option<Extension<watch::Receiver<ReadinessSnapshot>>>,
) -> Response {
    let readiness = readiness.as_ref().map(|Extension(rx)| rx.borrow().clone());
    let body = metrics.render(readiness.as_ref());
    let mut response = Body::from(body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, TEXT_PLAIN_004);
    response
}

async fn record_request(
    axum::extract::State(metrics): axum::extract::State<Arc<RequestMetrics>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let started = Instant::now();
    let method = method_label(request.method().as_str());
    let path = request.uri().path().to_string();
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string());

    let response = next.run(request).await;
    let duration_seconds = started.elapsed().as_secs_f64();
    let status = response.status();
    let error_code = response
        .extensions()
        .get::<ErrorCodeExt>()
        .map(|ext| ext.0.clone())
        .unwrap_or_else(|| NO_ERROR_CODE.to_string());
    let endpoint_kind = matched_path
        .as_deref()
        .map(endpoint_kind_from_pattern)
        .unwrap_or_else(|| endpoint_kind_from_path(&path));

    metrics.observe(
        RequestLabels {
            method,
            endpoint_kind: endpoint_kind_label(endpoint_kind),
            status_code: status.as_u16(),
            status_class: status_class_label(status),
            error_code,
        },
        duration_seconds,
    );

    response
}

fn render_readiness(readiness: Option<&ReadinessSnapshot>, out: &mut String) {
    out.push_str("# HELP data_gate_readiness_ready_resources Resources currently ready.\n");
    out.push_str("# TYPE data_gate_readiness_ready_resources gauge\n");
    out.push_str("# HELP data_gate_readiness_not_ready_resources Resources currently not ready.\n");
    out.push_str("# TYPE data_gate_readiness_not_ready_resources gauge\n");
    out.push_str("# HELP data_gate_readiness_failed_resources Resources currently failed.\n");
    out.push_str("# TYPE data_gate_readiness_failed_resources gauge\n");
    out.push_str("# HELP data_gate_readiness_unresolved_entities Entities without a resolved backing resource.\n");
    out.push_str("# TYPE data_gate_readiness_unresolved_entities gauge\n");
    out.push_str("# HELP data_gate_readiness_fully_ready Whether all resources are ready and all entities are resolved, as 0 or 1.\n");
    out.push_str("# TYPE data_gate_readiness_fully_ready gauge\n");

    let (ready, not_ready, failed, unresolved, fully_ready) =
        readiness.map_or((0, 0, 0, 0, 0), |snapshot| {
            (
                snapshot.ready.len(),
                snapshot.not_ready.len(),
                snapshot.failed.len(),
                snapshot.unresolved_entities.len(),
                u8::from(snapshot.fully_ready()),
            )
        });
    write!(
        out,
        "data_gate_readiness_ready_resources {}\n\
         data_gate_readiness_not_ready_resources {}\n\
         data_gate_readiness_failed_resources {}\n\
         data_gate_readiness_unresolved_entities {}\n\
         data_gate_readiness_fully_ready {}\n",
        ready, not_ready, failed, unresolved, fully_ready
    )
    .expect("write to String cannot fail");
}

fn method_label(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "OTHER",
    }
}

fn endpoint_kind_from_pattern(pattern: &str) -> EndpointKind {
    match pattern {
        "/health" => EndpointKind::Health,
        "/ready" => EndpointKind::Ready,
        "/metrics" | "/admin/reload" | "/admin/datasets/{dataset_id}/tables/{table_id}/reload" => {
            EndpointKind::Admin
        }
        "/datasets" | "/catalog" | "/catalog/dcat-ap.jsonld" => EndpointKind::Catalog,
        "/catalog/datasets/{dataset_id}/{entity}/schema.jsonld" => EndpointKind::Schema,
        "/datasets/{dataset_id}" => EndpointKind::Dataset,
        "/datasets/{dataset_id}/{entity}/schema" => EndpointKind::Schema,
        "/datasets/{dataset_id}/{entity}/verify" => EndpointKind::Verify,
        "/datasets/{dataset_id}/{entity}" => EndpointKind::Rows,
        "/datasets/{dataset_id}/{entity}/{id}" => EndpointKind::Rows,
        "/datasets/{dataset_id}/{entity}/{id}/{relationship}" => EndpointKind::Rows,
        "/datasets/{dataset_id}/{entity}/aggregates" => EndpointKind::AggregateList,
        "/datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}" => EndpointKind::Aggregate,
        "/openapi.json" => EndpointKind::Openapi,
        _ => EndpointKind::Other,
    }
}

fn endpoint_kind_from_path(path: &str) -> EndpointKind {
    if path == "/health" {
        EndpointKind::Health
    } else if path == "/ready" {
        EndpointKind::Ready
    } else if path == "/metrics" || path.starts_with("/admin") {
        EndpointKind::Admin
    } else if path.starts_with("/catalog/datasets/") {
        EndpointKind::Schema
    } else if path == "/datasets" || path == "/catalog" || path.starts_with("/catalog/") {
        EndpointKind::Catalog
    } else if path == "/openapi.json" || path.starts_with("/openapi") {
        EndpointKind::Openapi
    } else if path.starts_with("/datasets/") {
        classify_dataset_endpoint(path)
    } else {
        EndpointKind::Other
    }
}

fn classify_dataset_endpoint(path: &str) -> EndpointKind {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["datasets", _dataset] => EndpointKind::Dataset,
        ["datasets", _dataset, _entity, "schema"] => EndpointKind::Schema,
        ["datasets", _dataset, _entity, "aggregates"] => EndpointKind::AggregateList,
        ["datasets", _dataset, _entity, "aggregates", _aggregate] => EndpointKind::Aggregate,
        ["datasets", _dataset, _entity, "verify"] => EndpointKind::Verify,
        ["datasets", _dataset, _entity] => EndpointKind::Rows,
        ["datasets", _dataset, _entity, _id] => EndpointKind::Rows,
        ["datasets", _dataset, _entity, _id, _relationship] => EndpointKind::Rows,
        _ => EndpointKind::Dataset,
    }
}

fn endpoint_kind_label(kind: EndpointKind) -> &'static str {
    match kind {
        EndpointKind::Health => "health",
        EndpointKind::Ready => "ready",
        EndpointKind::Catalog => "catalog",
        EndpointKind::Dataset => "dataset",
        EndpointKind::Schema => "schema",
        EndpointKind::Verify => "verify",
        EndpointKind::Rows => "rows",
        EndpointKind::AggregateList => "aggregate_list",
        EndpointKind::Aggregate => "aggregate",
        EndpointKind::Admin => "admin",
        EndpointKind::Openapi => "openapi",
        EndpointKind::Other => "other",
    }
}

fn status_class_label(status: StatusCode) -> &'static str {
    match status.as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

fn escape_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
