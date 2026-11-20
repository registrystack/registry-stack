// SPDX-License-Identifier: Apache-2.0

//! Operational series, served only on the operator-private metrics listener.
//!
//! `/metrics` is a route on a separate socket that `metricsListener` names,
//! never on the serving listener, so the public contract is unchanged and
//! reaching the series requires reaching a different, private address.
//!
//! Every label is closed by construction. The route label is the axum route
//! template that matched, or `unmatched`; the method label is a fixed
//! vocabulary; the status label is a coarse class; the state labels are the
//! states the database constraints allow; the worker and sample labels name
//! one of the runtime's own loops or reads. Paths, document, version, grant
//! or owner identifiers, content hashes, and problem details never become
//! labels.
//!
//! The job and hook-delivery series are gauges sampled from PostgreSQL when
//! the metrics are scraped, never per request. Each scrape's reads share one
//! deadline, and each runs in a read-only transaction whose server-side
//! statement timeout is the time left. When a read fails, its gauges have no
//! samples for that scrape, so the series goes stale rather than reporting
//! an empty queue, and the failure is counted in
//! `documents_metrics_sample_failures_total` and logged by its error class
//! alone, never by the driver's message.
//!
//! The cleanup worker reports the age of the last pass that completed. Until
//! it completes one it reports the age of the process, so a worker that never
//! succeeds still grows an age. The verification, erasure, and hook delivery
//! workers report no pass of their own: a stopped one shows as a growing
//! oldest-overdue age instead.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use registry_platform_metrics::{
    sample_error_class, CounterVec, Exposition, LabelSpace, MetricKind, ScrapeDeadline,
    CLASS_NO_TIME_LEFT, CLASS_POOL, CONTENT_TYPE as METRICS_CONTENT_TYPE,
};

use crate::store::PostgresStore;

/// The path the metrics listener serves.
pub const METRICS_PATH: &str = "/metrics";

/// Route label used when no route template matched the request.
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// How long one scrape may spend reading from PostgreSQL, all reads
/// together.
pub use registry_platform_metrics::SCRAPE_BUDGET;

/// The most request series the registry holds: the route table times the
/// method and status vocabularies a route can answer with stays well under
/// it. A request past it is counted as refused, never added.
const REQUEST_SERIES_LIMIT: usize = 1024;

const DECLARATION: &str = "the metric declarations are valid";

/// The states `documents_verification_jobs.state` and
/// `documents_erasure_jobs.state` admit, in the order the exposition lists
/// them.
const JOB_STATES: [&str; 7] = [
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
    /// Expires lapsed uploads, arms due erasures, and erases orphaned
    /// objects.
    Cleanup,
}

impl Worker {
    /// Every worker, in the order the exposition lists them.
    pub const ALL: [Self; 1] = [Self::Cleanup];

    /// The worker's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cleanup => "cleanup",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Cleanup => 0,
        }
    }
}

/// The read a scrape makes, the closed label of
/// `documents_metrics_sample_failures_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sample {
    VerificationJobs,
    ErasureJobs,
    HookDeliveries,
}

impl Sample {
    const ALL: [Self; 3] = [
        Self::VerificationJobs,
        Self::ErasureJobs,
        Self::HookDeliveries,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::VerificationJobs => "verification-jobs",
            Self::ErasureJobs => "erasure-jobs",
            Self::HookDeliveries => "hook-deliveries",
        }
    }

    const fn table(self) -> &'static str {
        match self {
            Self::VerificationJobs => crate::verification::JOB_TABLE,
            Self::ErasureJobs => crate::erasure::JOB_TABLE,
            Self::HookDeliveries => "registry_webhook_delivery_state",
        }
    }
}

/// One queue's depth: the rows in each stored state, and how long the
/// oldest eligible pending row has been waiting.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QueueDepth {
    pub by_state: Vec<(String, i64)>,
    /// Seconds since the oldest pending row became due, zero when none is
    /// due. A row waiting out a retry back-off is not due, so it does not
    /// count.
    pub oldest_overdue_age_seconds: i64,
}

pub struct Metrics {
    requests: CounterVec,
    sample_failures: CounterVec,
    started: Instant,
    /// Seconds after `started` at which each worker last completed a pass.
    last_success: [AtomicU64; 1],
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let samples: Vec<[&str; 1]> = Sample::ALL.iter().map(|sample| [sample.as_str()]).collect();
        let samples: Vec<&[&str]> = samples.iter().map(|sample| sample.as_slice()).collect();
        Self {
            requests: CounterVec::new(
                "documents_http_requests_total",
                "Answered HTTP requests.",
                LabelSpace::bounded(&["route", "method", "status"], REQUEST_SERIES_LIMIT)
                    .expect(DECLARATION),
            )
            .expect(DECLARATION),
            sample_failures: CounterVec::new(
                "documents_metrics_sample_failures_total",
                "Scrape reads from the database that failed, by sample.",
                LabelSpace::closed_zero_filled(&["sample"], &samples).expect(DECLARATION),
            )
            .expect(DECLARATION),
            started: Instant::now(),
            last_success: [AtomicU64::new(0)],
        }
    }
}

/// What one scrape sampled from the database; `None` for a read that failed.
#[derive(Clone, Debug, Default)]
pub struct Sampled {
    pub verification_jobs: Option<QueueDepth>,
    pub erasure_jobs: Option<QueueDepth>,
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

    /// Count one scrape in which `sample` could not be read.
    pub fn record_sample_failure(&self, sample: Sample) {
        count(&self.sample_failures, &[sample.as_str()]);
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
            "documents_verification_jobs",
            "Content verification jobs, by state, sampled at scrape.",
            "documents_verification_oldest_overdue_age_seconds",
            "Seconds the oldest pending content verification job has been due, zero when none is due, sampled at scrape.",
            &JOB_STATES,
            sampled.verification_jobs.as_ref(),
        );
        write_queue(
            &mut out,
            "documents_erasure_jobs",
            "Erasure jobs, by state, sampled at scrape.",
            "documents_erasure_oldest_overdue_age_seconds",
            "Seconds the oldest pending erasure job has been due, zero when none is due, sampled at scrape.",
            &JOB_STATES,
            sampled.erasure_jobs.as_ref(),
        );
        write_queue(
            &mut out,
            "documents_hook_deliveries",
            "Hook deliveries, by state, sampled at scrape.",
            "documents_hook_oldest_overdue_age_seconds",
            "Seconds the oldest pending hook delivery has been due, zero when none is due, sampled at scrape.",
            &HOOK_STATES,
            sampled.hook_deliveries.as_ref(),
        );
        out.header(
            "documents_worker_last_success_age_seconds",
            Some("Seconds since the worker last completed a pass, or since the process started if it has not yet."),
            MetricKind::Gauge,
        )
        .expect(DECLARATION);
        for worker in Worker::ALL {
            let last = self.last_success[worker.index()].load(Ordering::Relaxed);
            out.sample(
                "documents_worker_last_success_age_seconds",
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
        out.sample(oldest, &[], depth.oldest_overdue_age_seconds)
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

/// Count every answered request on the serving listener under the route
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

/// The error class of a driver error: never its text, which can carry query
/// text or row data.
fn database_error_class(error: &tokio_postgres::Error) -> String {
    sample_error_class(
        error.code().map(tokio_postgres::error::SqlState::code),
        error.is_closed(),
    )
}

/// Reads the queues from PostgreSQL for one scrape.
#[derive(Clone, Debug)]
pub struct Sampler {
    store: PostgresStore,
    schema: String,
}

impl Sampler {
    /// A sampler over the tables `schema` holds.
    #[must_use]
    pub fn new(store: PostgresStore, schema: String) -> Self {
        Self { store, schema }
    }

    /// Read every queue, all of them within one `budget`. A read that
    /// fails is logged by its error class and counted once, its queue is
    /// left out, and the other reads still run.
    pub async fn sample(&self, metrics: &Metrics, budget: Duration) -> Sampled {
        let deadline = ScrapeDeadline::with_budget(Instant::now(), budget);
        let mut sampled = Sampled::default();
        for sample in Sample::ALL {
            let slot = match sample {
                Sample::VerificationJobs => &mut sampled.verification_jobs,
                Sample::ErasureJobs => &mut sampled.erasure_jobs,
                Sample::HookDeliveries => &mut sampled.hook_deliveries,
            };
            match deadline
                .run(self.queue_depth(sample.table(), deadline))
                .await
            {
                Ok(depth) => *slot = Some(depth),
                Err(class) => {
                    metrics.record_sample_failure(sample);
                    tracing::warn!(
                        sample = sample.as_str(),
                        class = %class,
                        "a Document Store metrics sample failed; its series are left out of this scrape"
                    );
                }
            }
        }
        sampled
    }

    /// The rows of `table` by state and the age of the oldest due pending
    /// row, in one read-only transaction whose server-side statement
    /// timeout is the time left before `deadline`, so a slow query is
    /// cancelled on the server and not only abandoned by the client. A read
    /// that spent the budget getting a connection fails without querying.
    async fn queue_depth(
        &self,
        table: &str,
        deadline: ScrapeDeadline,
    ) -> Result<QueueDepth, String> {
        let mut client = self.store.client().await.map_err(|error| match error {
            crate::store::StoreError::Pool(deadpool_postgres::PoolError::Backend(error)) => {
                database_error_class(&error)
            }
            _ => CLASS_POOL.to_owned(),
        })?;
        let transaction = client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(|error| database_error_class(&error))?;
        let milliseconds = deadline
            .statement_timeout_milliseconds()
            .ok_or_else(|| CLASS_NO_TIME_LEFT.to_owned())?;
        transaction
            .batch_execute(&format!("SET LOCAL statement_timeout = {milliseconds}"))
            .await
            .map_err(|error| database_error_class(&error))?;
        let mut by_state = Vec::new();
        for row in transaction
            .query(
                &format!(
                    "SELECT state, count(*) FROM {}.{table} GROUP BY state",
                    self.schema
                ),
                &[],
            )
            .await
            .map_err(|error| database_error_class(&error))?
        {
            by_state.push((
                row.try_get::<_, String>(0)
                    .map_err(|error| database_error_class(&error))?,
                row.try_get::<_, i64>(1)
                    .map_err(|error| database_error_class(&error))?,
            ));
        }
        let oldest: i64 = transaction
            .query_one(
                &format!(
                    "SELECT coalesce(floor(extract(epoch FROM
                                transaction_timestamp() - min(next_attempt_at)))::bigint, 0)
                       FROM {}.{table}
                      WHERE state = 'pending'
                        AND next_attempt_at <= transaction_timestamp()",
                    self.schema
                ),
                &[],
            )
            .await
            .map_err(|error| database_error_class(&error))?
            .try_get(0)
            .map_err(|error| database_error_class(&error))?;
        transaction
            .commit()
            .await
            .map_err(|error| database_error_class(&error))?;
        Ok(QueueDepth {
            by_state,
            oldest_overdue_age_seconds: oldest.max(0),
        })
    }
}

/// What the metrics listener reads: the series, and the sampler the queues
/// are read through.
#[derive(Clone, Debug)]
pub struct MetricsState {
    pub metrics: Arc<Metrics>,
    pub sampler: Sampler,
    /// How long one scrape may spend on all of its database reads.
    pub budget: Duration,
}

/// Serve the series and the sampled queues on the metrics listener.
pub async fn serve_metrics(State(state): State<MetricsState>) -> Response {
    let sampled = state.sampler.sample(&state.metrics, state.budget).await;
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
            oldest_overdue_age_seconds: oldest,
        }
    }

    #[test]
    fn labels_are_closed() {
        let metrics = Metrics::default();
        metrics.record_request(
            "/v1/documents/{document_id}",
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
            "documents_http_requests_total{route=\"/v1/documents/{document_id}\",method=\"GET\",status=\"4xx\"} 1"
        ));
        assert!(text.contains(
            "documents_http_requests_total{route=\"unmatched\",method=\"other\",status=\"2xx\"} 1"
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
        let unsampled = Metrics::default().render(&Sampled::default());
        for family in [
            "documents_verification_jobs",
            "documents_erasure_jobs",
            "documents_hook_deliveries",
        ] {
            assert!(unsampled.contains(&format!("# TYPE {family} gauge")));
            assert!(!unsampled.contains(&format!("{family}{{")));
        }
        for family in [
            "documents_verification_oldest_overdue_age_seconds",
            "documents_erasure_oldest_overdue_age_seconds",
            "documents_hook_oldest_overdue_age_seconds",
        ] {
            assert!(unsampled.contains(&format!("# TYPE {family} gauge")));
            assert!(!unsampled.contains(&format!("\n{family} ")));
        }
    }

    #[test]
    fn every_stored_state_is_exposed_from_zero_once_sampled() {
        let text = Metrics::default().render(&Sampled {
            verification_jobs: Some(depth(&[("pending", 3), ("dead-lettered", 2)], 90)),
            erasure_jobs: Some(depth(&[("dead-lettered", 1)], 0)),
            hook_deliveries: Some(depth(&[("leased", 4)], 7)),
        });
        for state in JOB_STATES {
            assert!(text.contains(&format!("documents_verification_jobs{{state=\"{state}\"}}")));
            assert!(text.contains(&format!("documents_erasure_jobs{{state=\"{state}\"}}")));
        }
        for state in HOOK_STATES {
            assert!(text.contains(&format!("documents_hook_deliveries{{state=\"{state}\"}}")));
        }
        assert!(text.contains("documents_verification_jobs{state=\"pending\"} 3"));
        assert!(text.contains("documents_verification_jobs{state=\"dead-lettered\"} 2"));
        assert!(text.contains("documents_verification_jobs{state=\"expired\"} 0"));
        assert!(text.contains("documents_verification_oldest_overdue_age_seconds 90"));
        assert!(text.contains("documents_erasure_jobs{state=\"dead-lettered\"} 1"));
        assert!(text.contains("documents_erasure_oldest_overdue_age_seconds 0"));
        assert!(text.contains("documents_hook_deliveries{state=\"leased\"} 4"));
        assert!(text.contains("documents_hook_oldest_overdue_age_seconds 7"));
    }

    #[test]
    fn a_failed_sample_is_counted_by_sample() {
        let metrics = Metrics::default();
        metrics.record_sample_failure(Sample::HookDeliveries);
        let text = metrics.render(&Sampled::default());
        for (sample, expected) in [
            ("verification-jobs", 0),
            ("erasure-jobs", 0),
            ("hook-deliveries", 1),
        ] {
            assert!(
                text.contains(&format!(
                    "documents_metrics_sample_failures_total{{sample=\"{sample}\"}} {expected}"
                )),
                "{sample}"
            );
        }
    }

    #[test]
    fn a_worker_reports_the_age_of_its_last_pass() {
        let metrics = Metrics::default();
        let sampled = Sampled::default();
        // Before any pass the age is the process age.
        let text = metrics.render_at(&sampled, 45);
        assert!(text.contains("documents_worker_last_success_age_seconds{worker=\"cleanup\"} 45"));
        metrics.record_worker_success_at(Worker::Cleanup, 40);
        let text = metrics.render_at(&sampled, 45);
        assert!(text.contains("documents_worker_last_success_age_seconds{worker=\"cleanup\"} 5"));
    }
}
