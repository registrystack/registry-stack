// SPDX-License-Identifier: Apache-2.0

//! Operational series, served only on the operator-private metrics listener.
//!
//! `/metrics` is a route on a separate socket that `metricsListener` names,
//! never on the public listener, so the public contract is unchanged and
//! reaching the series requires reaching a different, private address.
//!
//! Every label is closed by construction. The route label is the axum route
//! template that matched, or `unmatched`; the method label is a fixed
//! vocabulary; the status label is a coarse class; the state labels are the
//! states the database constraints allow; the worker label names one of the
//! runtime's own loops. Paths, appointment or hold identifiers, principals,
//! and problem details never become labels.
//!
//! The outbox and hook-delivery series are gauges sampled from the store when
//! the metrics are scraped. When a queue cannot be read its gauges have no
//! samples for that scrape, so the series goes stale rather than reporting an
//! empty queue, and the failure is counted in
//! `scheduling_metrics_sample_failures_total` and logged.
//!
//! Worker series report the age of the last pass that completed. A worker
//! that has not yet completed a pass reports the age of the process, so a
//! worker that never succeeds still grows an age.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use registry_platform_metrics::{
    CounterVec, Exposition, LabelSpace, MetricKind, CONTENT_TYPE as METRICS_CONTENT_TYPE,
};

use crate::store::{PostgresStore, QueueDepth};

/// The path the metrics listener serves.
pub const METRICS_PATH: &str = "/metrics";

/// Route label used when no route template matched the request.
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// The most request series the registry holds: the route table times the
/// method and status vocabularies a route can answer with stays well under
/// it. A request past it is counted as refused, never added.
const REQUEST_SERIES_LIMIT: usize = 1024;

const DECLARATION: &str = "the metric declarations are valid";

/// The states `scheduling_outbox.state` admits, in the order the exposition
/// lists them.
const OUTBOX_STATES: [&str; 7] = [
    "pending",
    "leased",
    "delivered",
    "dead-lettered",
    "expired",
    "unknown",
    "cancelled",
];

/// The states `registry_webhook_delivery_state.state` admits, in the order
/// the exposition lists them.
const HOOK_STATES: [&str; 5] = ["pending", "leased", "delivered", "dead-lettered", "expired"];

/// A supervised loop that reports each pass it completes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Worker {
    /// Retires holds past their expiry.
    HoldExpiry,
    /// Erases data past its retention period.
    Retention,
}

impl Worker {
    /// Every worker, in the order the exposition lists them.
    pub const ALL: [Self; 2] = [Self::HoldExpiry, Self::Retention];

    /// The worker's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HoldExpiry => "hold-expiry",
            Self::Retention => "retention",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::HoldExpiry => 0,
            Self::Retention => 1,
        }
    }
}

/// The queue a sample read, the closed label of
/// `scheduling_metrics_sample_failures_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampledQueue {
    Outbox,
    HookDeliveries,
}

impl SampledQueue {
    const ALL: [Self; 2] = [Self::Outbox, Self::HookDeliveries];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Outbox => "outbox",
            Self::HookDeliveries => "hook-deliveries",
        }
    }
}

pub struct Metrics {
    requests: CounterVec,
    sample_failures: CounterVec,
    started: Instant,
    /// Seconds after `started` at which each worker last completed a pass.
    last_success: [AtomicU64; 2],
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let queues: Vec<[&str; 1]> = SampledQueue::ALL
            .iter()
            .map(|queue| [queue.as_str()])
            .collect();
        let queues: Vec<&[&str]> = queues.iter().map(|queue| queue.as_slice()).collect();
        Self {
            requests: CounterVec::new(
                "scheduling_http_requests_total",
                "Answered HTTP requests.",
                LabelSpace::bounded(&["route", "method", "status"], REQUEST_SERIES_LIMIT)
                    .expect(DECLARATION),
            )
            .expect(DECLARATION),
            sample_failures: CounterVec::new(
                "scheduling_metrics_sample_failures_total",
                "Scrapes in which a queue could not be read from the database, by queue.",
                LabelSpace::closed_zero_filled(&["queue"], &queues).expect(DECLARATION),
            )
            .expect(DECLARATION),
            started: Instant::now(),
            last_success: [AtomicU64::new(0), AtomicU64::new(0)],
        }
    }
}

/// What one scrape sampled from the store; `None` for a queue that could not
/// be read.
#[derive(Clone, Debug, Default)]
pub struct Sampled {
    pub outbox: Option<QueueDepth>,
    pub hook_deliveries: Option<QueueDepth>,
}

impl Metrics {
    /// Count one answered request under its closed labels.
    pub fn record_request(&self, route: &str, method: &Method, status: StatusCode) {
        count(
            &self.requests,
            &[route, method_label(method), status_class(status)],
        );
    }

    /// Record that `worker` just completed a pass.
    pub fn record_worker_success(&self, worker: Worker) {
        self.record_worker_success_at(worker, self.started.elapsed().as_secs());
    }

    fn record_worker_success_at(&self, worker: Worker, seconds_since_start: u64) {
        self.last_success[worker.index()].store(seconds_since_start, Ordering::Relaxed);
    }

    /// Count one scrape in which `queue` could not be read.
    pub fn record_sample_failure(&self, queue: SampledQueue) {
        count(&self.sample_failures, &[queue.as_str()]);
    }

    /// Render the Prometheus text exposition, with the queues that were
    /// sampled.
    #[must_use]
    pub fn render(&self, sampled: &Sampled) -> String {
        self.render_at(sampled, self.started.elapsed().as_secs())
    }

    fn render_at(&self, sampled: &Sampled, seconds_since_start: u64) -> String {
        let mut out = Exposition::new();
        self.requests.write(&mut out).expect(DECLARATION);
        self.sample_failures.write(&mut out).expect(DECLARATION);
        write_queue(
            &mut out,
            "scheduling_outbox_items",
            "Reminder and notice intents in the delivery outbox, by state, sampled at scrape.",
            "scheduling_outbox_oldest_pending_age_seconds",
            "Seconds the oldest pending outbox intent is past its due time, zero when none is overdue, sampled at scrape.",
            &OUTBOX_STATES,
            sampled.outbox.as_ref(),
        );
        write_queue(
            &mut out,
            "scheduling_hook_deliveries",
            "Observer-hook deliveries, by state, sampled at scrape.",
            "scheduling_hook_oldest_pending_age_seconds",
            "Seconds since the oldest pending observer-hook delivery's event was captured, zero when none is pending, sampled at scrape.",
            &HOOK_STATES,
            sampled.hook_deliveries.as_ref(),
        );
        out.header(
            "scheduling_worker_last_success_age_seconds",
            Some("Seconds since the worker last completed a pass, or since the process started if it has not yet."),
            MetricKind::Gauge,
        )
        .expect(DECLARATION);
        for worker in Worker::ALL {
            let last = self.last_success[worker.index()].load(Ordering::Relaxed);
            out.sample(
                "scheduling_worker_last_success_age_seconds",
                &[("worker", worker.as_str())],
                seconds_since_start.saturating_sub(last),
            )
            .expect(DECLARATION);
        }
        out.finish()
    }
}

/// One queue's two families. A queue that was not sampled writes its
/// headers and no samples.
fn write_queue(
    out: &mut Exposition,
    items: &str,
    items_help: &str,
    oldest: &str,
    oldest_help: &str,
    states: &[&str],
    depth: Option<&QueueDepth>,
) {
    out.header(items, Some(items_help), MetricKind::Gauge)
        .expect(DECLARATION);
    if let Some(depth) = depth {
        for state in states {
            let count = depth
                .by_state
                .iter()
                .find(|(stored, _)| stored == state)
                .map_or(0, |(_, count)| *count);
            out.sample(items, &[("state", state)], count)
                .expect(DECLARATION);
        }
    }
    out.header(oldest, Some(oldest_help), MetricKind::Gauge)
        .expect(DECLARATION);
    if let Some(depth) = depth {
        out.sample(oldest, &[], depth.oldest_pending_age_seconds)
            .expect(DECLARATION);
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
    } else if status.is_redirection() {
        "3xx"
    } else if status.is_success() {
        "2xx"
    } else if status.is_informational() {
        "1xx"
    } else {
        "other"
    }
}

/// Count every answered request on the public listener under the route
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

/// What the metrics listener reads: the series, and the store the queues are
/// sampled from.
#[derive(Clone, Debug)]
pub struct MetricsState {
    pub metrics: Arc<Metrics>,
    pub store: PostgresStore,
}

/// Serve the series and the sampled queues on the metrics listener.
pub async fn serve_metrics(State(state): State<MetricsState>) -> Response {
    let now = state.store.observed_now();
    let mut sampled = Sampled::default();
    match state.store.outbox_depth(now).await {
        Ok(depth) => sampled.outbox = Some(depth),
        Err(error) => {
            state.metrics.record_sample_failure(SampledQueue::Outbox);
            tracing::warn!(error = %error, "the Scheduling outbox could not be sampled");
        }
    }
    match state.store.hook_delivery_depth(now).await {
        Ok(depth) => sampled.hook_deliveries = Some(depth),
        Err(error) => {
            state
                .metrics
                .record_sample_failure(SampledQueue::HookDeliveries);
            tracing::warn!(error = %error, "the Scheduling hook deliveries could not be sampled");
        }
    }
    (
        [(CONTENT_TYPE, METRICS_CONTENT_TYPE)],
        state.metrics.render(&sampled),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depth(by_state: &[(&str, i64)], oldest: i64) -> QueueDepth {
        QueueDepth {
            by_state: by_state
                .iter()
                .map(|(state, count)| ((*state).to_owned(), *count))
                .collect(),
            oldest_pending_age_seconds: oldest,
        }
    }

    #[test]
    fn labels_are_closed() {
        let metrics = Metrics::default();
        metrics.record_request(
            "/v1/appointments/{appointment_id}",
            &Method::GET,
            StatusCode::NOT_FOUND,
        );
        metrics.record_request(
            UNMATCHED_ROUTE,
            &Method::from_bytes(b"BREW").unwrap(),
            StatusCode::OK,
        );
        let text = metrics.render(&Sampled::default());
        assert!(text.contains(
            "scheduling_http_requests_total{route=\"/v1/appointments/{appointment_id}\",method=\"GET\",status=\"4xx\"} 1"
        ));
        assert!(text.contains(
            "scheduling_http_requests_total{route=\"unmatched\",method=\"other\",status=\"2xx\"} 1"
        ));
    }

    #[test]
    fn every_status_has_its_own_bounded_class() {
        let class = |code: u16| status_class(StatusCode::from_u16(code).unwrap());
        assert_eq!(
            [100, 200, 204, 304, 404, 503, 600].map(class),
            ["1xx", "2xx", "2xx", "3xx", "4xx", "5xx", "other"]
        );
    }

    #[test]
    fn the_queues_are_exposed_only_when_they_were_sampled() {
        let metrics = Metrics::default();
        let unsampled = metrics.render(&Sampled::default());
        assert!(unsampled.contains("# TYPE scheduling_outbox_items gauge"));
        assert!(unsampled.contains("# TYPE scheduling_hook_deliveries gauge"));
        assert!(!unsampled.contains("scheduling_outbox_items{"));
        assert!(!unsampled.contains("\nscheduling_outbox_oldest_pending_age_seconds "));
        assert!(!unsampled.contains("scheduling_hook_deliveries{"));
        assert!(!unsampled.contains("\nscheduling_hook_oldest_pending_age_seconds "));
    }

    #[test]
    fn every_stored_state_is_exposed_from_zero_once_sampled() {
        let metrics = Metrics::default();
        let text = metrics.render(&Sampled {
            outbox: Some(depth(&[("pending", 3), ("dead-lettered", 2)], 90)),
            hook_deliveries: Some(depth(&[("dead-lettered", 1)], 0)),
        });
        for state in OUTBOX_STATES {
            assert!(text.contains(&format!("scheduling_outbox_items{{state=\"{state}\"}}")));
        }
        for state in HOOK_STATES {
            assert!(text.contains(&format!("scheduling_hook_deliveries{{state=\"{state}\"}}")));
        }
        assert!(text.contains("scheduling_outbox_items{state=\"pending\"} 3"));
        assert!(text.contains("scheduling_outbox_items{state=\"dead-lettered\"} 2"));
        assert!(text.contains("scheduling_outbox_items{state=\"expired\"} 0"));
        assert!(text.contains("scheduling_outbox_oldest_pending_age_seconds 90"));
        assert!(text.contains("scheduling_hook_deliveries{state=\"dead-lettered\"} 1"));
        assert!(text.contains("scheduling_hook_oldest_pending_age_seconds 0"));
    }

    #[test]
    fn a_failed_sample_is_counted_by_queue() {
        let metrics = Metrics::default();
        metrics.record_sample_failure(SampledQueue::HookDeliveries);
        let text = metrics.render(&Sampled::default());
        assert!(text.contains("scheduling_metrics_sample_failures_total{queue=\"outbox\"} 0"));
        assert!(
            text.contains("scheduling_metrics_sample_failures_total{queue=\"hook-deliveries\"} 1")
        );
    }

    #[test]
    fn a_worker_reports_the_age_of_its_last_pass() {
        let metrics = Metrics::default();
        let sampled = Sampled::default();
        // Before any pass the age is the process age.
        let text = metrics.render_at(&sampled, 45);
        assert!(
            text.contains("scheduling_worker_last_success_age_seconds{worker=\"hold-expiry\"} 45")
        );
        assert!(
            text.contains("scheduling_worker_last_success_age_seconds{worker=\"retention\"} 45")
        );
        metrics.record_worker_success_at(Worker::HoldExpiry, 40);
        let text = metrics.render_at(&sampled, 45);
        assert!(
            text.contains("scheduling_worker_last_success_age_seconds{worker=\"hold-expiry\"} 5")
        );
        assert!(
            text.contains("scheduling_worker_last_success_age_seconds{worker=\"retention\"} 45")
        );
    }
}
