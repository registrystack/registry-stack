// SPDX-License-Identifier: Apache-2.0
//! Opt-in operational metrics for Base Registry Engine.
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
//!
//! The worker and queue gauges carry one fixed label each, from
//! [`ProgressWorker`] and [`PendingQueue`]. A worker's age is read from the
//! handle its loop notes successes on. The queue ages are read from the
//! database once per scrape, through at most one pool connection in a
//! read-only transaction under a short statement timeout; when that read
//! fails the scrape publishes no queue age and emits a closed operational
//! event. The package info series carries the single `sha256:` digest of the
//! package this process verified at startup, so it adds one series per
//! process.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
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

/// The bound on the one statement that samples the queue ages.
const QUEUE_SAMPLE_STATEMENT_TIMEOUT: &str = "5s";

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
    /// The background workers this process runs, each with the handle its
    /// loop notes a completed iteration on.
    workers: Vec<(ProgressWorker, Arc<LastSuccess>)>,
    /// Held while one scrape samples the queue ages, so concurrent scrapes
    /// wait for each other and the metrics listener never holds more than
    /// one pool connection.
    queue_sample: tokio::sync::Mutex<()>,
    /// The digest of the package this process verified at startup, published
    /// as `breg_active_package_info`.
    active_package_digest: Option<String>,
}

/// A background worker reported by `breg_worker_last_success_age_seconds`.
///
/// The worker label is one of these fixed values, so the series count is
/// bounded by the workers a process can run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum ProgressWorker {
    Webhook,
    AttachmentVerification,
    Review,
    SubjectAccessLogRetention,
}

impl ProgressWorker {
    pub const ALL: [Self; 4] = [
        Self::Webhook,
        Self::AttachmentVerification,
        Self::Review,
        Self::SubjectAccessLogRetention,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::AttachmentVerification => "attachment-verification",
            Self::Review => "review",
            Self::SubjectAccessLogRetention => "subject-access-log-retention",
        }
    }
}

/// A durable work queue reported by `breg_queue_oldest_pending_age_seconds`.
///
/// The queue label is one of these fixed values, so the series count is
/// bounded by the queues the schema holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PendingQueue {
    WebhookDelivery,
    ReviewSubmission,
    ReviewApplication,
}

impl PendingQueue {
    pub const ALL: [Self; 3] = [
        Self::WebhookDelivery,
        Self::ReviewSubmission,
        Self::ReviewApplication,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WebhookDelivery => "webhook-delivery",
            Self::ReviewSubmission => "review-submission",
            Self::ReviewApplication => "review-application",
        }
    }
}

/// When one background worker last completed an iteration without failure,
/// idle or not, on this process's monotonic clock.
#[derive(Debug, Default)]
pub struct LastSuccess(Mutex<Option<Instant>>);

impl LastSuccess {
    /// Note one iteration that completed without failure.
    pub fn record(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Instant::now());
    }

    /// Time since the last noted success, or `None` before the first.
    #[must_use]
    pub fn age(&self) -> Option<Duration> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .map(|succeeded| succeeded.elapsed())
    }
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

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn with_pool_for_test(pool: RuntimePool) -> Self {
        Self::new(pool)
    }

    /// Report `worker`'s progress from the handle its loop notes successes
    /// on.
    #[must_use]
    pub fn with_worker_progress(
        mut self,
        worker: ProgressWorker,
        last_success: Arc<LastSuccess>,
    ) -> Self {
        self.workers.push((worker, last_success));
        self
    }

    /// Report the digest of the package this process verified at startup.
    /// `package_digest` is the verified `sha256:` identity, a fixed token
    /// that is safe to publish as a label value.
    #[must_use]
    pub fn with_active_package(mut self, package_digest: &str) -> Self {
        debug_assert!(
            package_digest
                .strip_prefix("sha256:")
                .is_some_and(|hex| hex.len() == 64
                    && hex
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))),
            "the active package digest is a verified sha256 identity"
        );
        self.active_package_digest = Some(package_digest.to_owned());
        self
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

    /// Render the Prometheus text exposition of the current registry, with
    /// the queue ages when they were sampled for this scrape.
    pub(crate) fn render(&self, queue_ages: Option<&[(PendingQueue, f64)]>) -> String {
        let series = self
            .series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut body = String::new();
        body.push_str(
            "# HELP breg_http_requests_total Requests served by the Registry boundary.\n",
        );
        body.push_str("# TYPE breg_http_requests_total counter\n");
        for (key, value) in series.iter() {
            body.push_str(&format!(
                "breg_http_requests_total{{{}}} {}\n",
                labels(key),
                value.requests
            ));
        }
        body.push_str(
            "# HELP breg_http_request_duration_seconds Request duration at the Registry boundary.\n",
        );
        body.push_str("# TYPE breg_http_request_duration_seconds histogram\n");
        for (key, value) in series.iter() {
            for (count, bound) in value.bucket_counts.iter().zip(DURATION_BUCKETS) {
                body.push_str(&format!(
                    "breg_http_request_duration_seconds_bucket{{{},le=\"{bound}\"}} {count}\n",
                    labels(key)
                ));
            }
            body.push_str(&format!(
                "breg_http_request_duration_seconds_bucket{{{},le=\"+Inf\"}} {}\n",
                labels(key),
                value.requests
            ));
            body.push_str(&format!(
                "breg_http_request_duration_seconds_sum{{{}}} {}\n",
                labels(key),
                value.duration_sum
            ));
            body.push_str(&format!(
                "breg_http_request_duration_seconds_count{{{}}} {}\n",
                labels(key),
                value.requests
            ));
        }
        body.push_str("# HELP breg_pool_connections Runtime pool connections by state.\n");
        body.push_str("# TYPE breg_pool_connections gauge\n");
        // Sampled fresh on every scrape rather than cached from request
        // handling, so the gauges reflect the pool's state at scrape time. A
        // registry built without a pool (see `Metrics::default`) has nothing
        // to sample and leaves the gauges at their initial zero.
        let status = self.pool.as_ref().map(RuntimePool::status);
        for (state, count) in [
            ("maximum-size", status.as_ref().map(|s| s.max_size)),
            ("size", status.as_ref().map(|s| s.size)),
            ("available", status.as_ref().map(|s| s.available)),
            ("waiting", status.as_ref().map(|s| s.waiting)),
        ] {
            body.push_str(&format!(
                "breg_pool_connections{{state=\"{state}\"}} {}\n",
                count.unwrap_or(0)
            ));
        }
        body.push_str(
            "# HELP breg_worker_last_success_age_seconds Seconds since each background worker last completed an iteration without failure; absent until the first.\n",
        );
        body.push_str("# TYPE breg_worker_last_success_age_seconds gauge\n");
        for (worker, last_success) in &self.workers {
            if let Some(age) = last_success.age() {
                body.push_str(&format!(
                    "breg_worker_last_success_age_seconds{{worker=\"{}\"}} {}\n",
                    worker.label(),
                    age.as_secs_f64()
                ));
            }
        }
        body.push_str(
            "# HELP breg_queue_oldest_pending_age_seconds Seconds the oldest due item in each queue has waited to be claimed, sampled at scrape; zero when none is due.\n",
        );
        body.push_str("# TYPE breg_queue_oldest_pending_age_seconds gauge\n");
        for (queue, seconds) in queue_ages.unwrap_or_default() {
            body.push_str(&format!(
                "breg_queue_oldest_pending_age_seconds{{queue=\"{}\"}} {seconds}\n",
                queue.label()
            ));
        }
        body.push_str(
            "# HELP breg_active_package_info The package this process verified at startup, by digest.\n",
        );
        body.push_str("# TYPE breg_active_package_info gauge\n");
        if let Some(digest) = &self.active_package_digest {
            body.push_str(&format!(
                "breg_active_package_info{{package_digest=\"{digest}\"}} 1\n"
            ));
        }
        body
    }

    /// Sample how long the oldest due item in each queue has waited, at one
    /// database instant. `None` when this registry has no pool, or when the
    /// sample could not be read: that scrape then publishes no queue age,
    /// so the series goes stale rather than reporting an empty queue, and a
    /// failure emits a closed operational event.
    pub(crate) async fn sample_queue_ages(&self) -> Option<Vec<(PendingQueue, f64)>> {
        let pool = self.pool.as_ref()?;
        let _sampling = self.queue_sample.lock().await;
        match read_queue_ages(pool).await {
            Ok(ages) => Some(ages),
            Err(()) => {
                crate::startup::OperationalEvent::MetricsQueueSampleFailed.emit();
                None
            }
        }
    }
}

/// Read every queue age in one bounded, read-only statement. The due
/// predicates follow each worker's claim, so work scheduled for a later
/// retry does not count as waiting. A webhook lease that expired is claimable
/// again, so it has waited since its lease expired. A review submission claim
/// extends its lease without advancing `next_attempt_at`, so a claimable
/// submission has waited since the later of the two; `GREATEST` ignores a
/// NULL lease.
async fn read_queue_ages(pool: &RuntimePool) -> Result<Vec<(PendingQueue, f64)>, ()> {
    let mut client = pool.get().await.map_err(|_| ())?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| ())?;
    transaction
        .execute(
            "SELECT set_config('statement_timeout', $1, true)",
            &[&QUEUE_SAMPLE_STATEMENT_TIMEOUT],
        )
        .await
        .map_err(|_| ())?;
    let row = transaction
        .query_one(
            &format!(
                "SELECT
                    COALESCE((SELECT EXTRACT(EPOCH FROM transaction_timestamp()
                                      - MIN(CASE WHEN state.state = 'pending'
                                                 THEN state.next_attempt_at
                                                 ELSE state.lease_expires_at END))::float8
                                FROM {schema}.registry_webhook_delivery_state state
                               WHERE (state.state = 'pending'
                                      AND state.next_attempt_at <= transaction_timestamp())
                                  OR (state.state = 'leased'
                                      AND state.lease_expires_at <= transaction_timestamp())), 0),
                    COALESCE((SELECT EXTRACT(EPOCH FROM transaction_timestamp()
                                      - MIN(GREATEST(s.next_attempt_at, s.lease_until)))::float8
                                FROM registry_internal.registry_request_review_submissions s
                               WHERE s.state IN ('pending','submitting','uncertain','cancelling')
                                 AND {submission_claimable}), 0),
                    COALESCE((SELECT EXTRACT(EPOCH FROM transaction_timestamp()
                                      - MIN(q.next_attempt_at))::float8
                                FROM registry_internal.registry_request_application_jobs q
                               WHERE q.state IN ('queued','applying')
                                 AND q.attempt_count < $1
                                 AND q.next_attempt_at <= transaction_timestamp()
                                 AND {claimable}), 0)",
                schema = crate::webhook::DELIVERY_SCHEMA,
                submission_claimable = crate::review_store::REVIEW_SUBMISSION_CLAIMABLE,
                claimable = crate::review_store::APPLICATION_JOB_CLAIMABLE,
            ),
            &[&crate::review_store::MAX_APPLICATION_ATTEMPTS],
        )
        .await
        .map_err(|_| ())?;
    let ages = PendingQueue::ALL
        .into_iter()
        .enumerate()
        .map(|(column, queue)| Ok((queue, row.try_get::<_, f64>(column)?)))
        .collect::<Result<Vec<_>, tokio_postgres::Error>>()
        .map_err(|_| ())?;
    transaction.commit().await.map_err(|_| ())?;
    Ok(ages)
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
    let queue_ages = metrics.sample_queue_ages().await;
    let mut response = (StatusCode::OK, metrics.render(queue_ages.as_deref())).into_response();
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
    use std::collections::BTreeSet;
    use tower::util::ServiceExt;

    #[test]
    fn duration_buckets_are_cumulative_and_carry_an_infinite_bound() {
        let metrics = Metrics::default();
        metrics.record_http("/health", "GET", "success", Duration::from_millis(30));
        let rendered = metrics.render(None);
        assert!(rendered.contains("le=\"0.025\"} 0\n"));
        assert!(rendered.contains("le=\"0.05\"} 1\n"));
        assert!(rendered.contains("le=\"+Inf\"} 1\n"));
        assert!(rendered.contains(
            "breg_http_request_duration_seconds_count{route=\"/health\",method=\"GET\",status=\"success\"} 1\n"
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
            "client-error",
            Duration::from_millis(1),
        );
        metrics.record_http(
            UNMATCHED_ROUTE,
            "OTHER",
            "client-error",
            Duration::from_millis(2),
        );
        let rendered = metrics.render(None);
        assert_eq!(
            rendered
                .matches("breg_http_requests_total{route=\"unmatched\"")
                .count(),
            1,
            "unrouted requests collapse onto one series"
        );
    }

    #[test]
    fn pool_gauges_are_four_fixed_state_series() {
        let metrics = Metrics::default();
        metrics.record_http("/v1/records", "GET", "success", Duration::from_millis(1));
        let rendered = metrics.render(None);
        for state in ["maximum-size", "size", "available", "waiting"] {
            assert_eq!(
                rendered
                    .matches(&format!("breg_pool_connections{{state=\"{state}\"}}"))
                    .count(),
                1,
                "one {state} gauge regardless of request series"
            );
        }
        assert!(
            !rendered.contains("breg_pool_connections{route="),
            "pool gauges carry no route label"
        );
    }

    #[test]
    fn worker_last_success_age_is_absent_until_the_worker_first_succeeds() {
        let review = Arc::new(LastSuccess::default());
        let webhook = Arc::new(LastSuccess::default());
        let metrics = Metrics::default()
            .with_worker_progress(ProgressWorker::Review, Arc::clone(&review))
            .with_worker_progress(ProgressWorker::Webhook, Arc::clone(&webhook));
        let rendered = metrics.render(None);
        assert!(rendered.contains("# TYPE breg_worker_last_success_age_seconds gauge\n"));
        assert!(
            !rendered.contains("breg_worker_last_success_age_seconds{"),
            "a worker that never succeeded has no age:\n{rendered}"
        );

        review.record();
        let rendered = metrics.render(None);
        let ages = rendered
            .lines()
            .filter_map(|line| line.strip_prefix("breg_worker_last_success_age_seconds{"))
            .collect::<Vec<_>>();
        assert_eq!(ages.len(), 1, "only the worker that succeeded:\n{rendered}");
        let age = ages[0]
            .strip_prefix("worker=\"review\"} ")
            .expect("the review worker carries its closed label")
            .parse::<f64>()
            .expect("the age is a number of seconds");
        assert!(
            (0.0..60.0).contains(&age),
            "a fresh success is young: {age}"
        );
    }

    #[test]
    fn every_progress_worker_carries_a_distinct_kebab_case_label() {
        let labels: Vec<&str> = ProgressWorker::ALL
            .into_iter()
            .map(ProgressWorker::label)
            .collect();
        let unique: BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(unique.len(), labels.len(), "labels are distinct");
        for label in labels {
            assert!(
                label
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character == '-'),
                "{label} is a fixed kebab-case token"
            );
        }
    }

    #[test]
    fn queue_ages_are_published_only_for_a_sampled_scrape() {
        let metrics = Metrics::default();
        let unsampled = metrics.render(None);
        assert!(unsampled.contains("# TYPE breg_queue_oldest_pending_age_seconds gauge\n"));
        assert!(
            !unsampled.contains("breg_queue_oldest_pending_age_seconds{"),
            "an unsampled scrape publishes no queue age:\n{unsampled}"
        );

        let sampled = metrics.render(Some(&[
            (PendingQueue::WebhookDelivery, 0.0),
            (PendingQueue::ReviewSubmission, 90.5),
            (PendingQueue::ReviewApplication, 0.0),
        ]));
        for expected in [
            "breg_queue_oldest_pending_age_seconds{queue=\"webhook-delivery\"} 0\n",
            "breg_queue_oldest_pending_age_seconds{queue=\"review-submission\"} 90.5\n",
            "breg_queue_oldest_pending_age_seconds{queue=\"review-application\"} 0\n",
        ] {
            assert!(sampled.contains(expected), "{expected} in:\n{sampled}");
        }
    }

    #[test]
    fn the_active_package_digest_is_published_once_as_an_info_series() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let unset = Metrics::default().render(None);
        assert!(unset.contains("# TYPE breg_active_package_info gauge\n"));
        assert!(
            !unset.contains("breg_active_package_info{"),
            "a registry with no verified package publishes no digest:\n{unset}"
        );

        let rendered = Metrics::default().with_active_package(&digest).render(None);
        let samples = rendered
            .lines()
            .filter(|line| line.starts_with("breg_active_package_info{"))
            .collect::<Vec<_>>();
        assert_eq!(
            samples,
            [format!(
                "breg_active_package_info{{package_digest=\"{digest}\"}} 1"
            )],
            "one sample carrying the verified digest:\n{rendered}"
        );
    }

    #[test]
    fn every_pending_queue_carries_a_distinct_kebab_case_label() {
        let labels: Vec<&str> = PendingQueue::ALL
            .into_iter()
            .map(PendingQueue::label)
            .collect();
        let unique: BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(unique.len(), labels.len(), "labels are distinct");
        for label in labels {
            assert!(
                label
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character == '-'),
                "{label} is a fixed kebab-case token"
            );
        }
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
        assert!(body.contains("# TYPE breg_http_requests_total counter\n"));
        assert!(body.contains("# TYPE breg_pool_connections gauge\n"));

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
