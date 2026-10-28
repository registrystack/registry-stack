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
//! handle its loop notes successes on. Queue ages and Record-timer state are
//! read independently on each scrape, through at most one pool connection at
//! a time and separate read-only transactions under short statement
//! timeouts. A failed sample is omitted rather than rendered as an empty
//! queue, and emits a closed operational event without erasing an independent
//! successful sample. The package info series carries the single `sha256:`
//! digest of the package this process verified at startup, so it adds one
//! series per process.

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

/// One database instant for runnable ages and package-blocked application work.
pub(crate) struct QueueSample {
    ages: Vec<(PendingQueue, f64)>,
    blocked_application_jobs: i64,
    timer: Option<TimerSample>,
}

const TIMER_STATUS_SCAN_MAXIMUM: i64 = 10_000;
const TIMER_STATUS_SCAN_SENTINEL: i64 = TIMER_STATUS_SCAN_MAXIMUM + 1;
const TIMER_STATES: [&str; 8] = [
    "pending",
    "leased",
    "completed",
    "refused",
    "blocked",
    "cancelled",
    "superseded",
    "missed",
];
const TIMER_BLOCK_KINDS: [&str; 2] = ["technical", "configuration"];

struct TimerSample {
    observed_live_lease_owners: i64,
    oldest_due_lag_seconds: Option<f64>,
    occurrence_counts: [i64; 8],
    block_counts: [i64; 2],
    current_executed_attempts: i64,
    retained_attempts: i64,
    stale_current_occurrences: i64,
    control_state: &'static str,
    control_compatible: bool,
    counts_truncated: bool,
}

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
    /// Held while one scrape samples operational state, so concurrent scrapes
    /// wait for each other and the metrics listener never holds more than one
    /// pool connection at a time.
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
    Hook,
    RecordTimer,
    AttachmentVerification,
    Review,
    SubjectAccessLogRetention,
}

impl ProgressWorker {
    pub const ALL: [Self; 5] = [
        Self::Hook,
        Self::RecordTimer,
        Self::AttachmentVerification,
        Self::Review,
        Self::SubjectAccessLogRetention,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::RecordTimer => "record-timer",
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
    HookDelivery,
    ReviewSubmission,
    ReviewApplication,
}

impl PendingQueue {
    pub const ALL: [Self; 3] = [
        Self::HookDelivery,
        Self::ReviewSubmission,
        Self::ReviewApplication,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::HookDelivery => "hook-delivery",
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
    pub(crate) fn render(&self, queue_sample: Option<&QueueSample>) -> String {
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
        for (queue, seconds) in queue_sample
            .map(|sample| sample.ages.as_slice())
            .unwrap_or_default()
        {
            body.push_str(&format!(
                "breg_queue_oldest_pending_age_seconds{{queue=\"{}\"}} {seconds}\n",
                queue.label()
            ));
        }
        body.push_str("# HELP breg_proposal_application_blocked_jobs Application jobs closed or held by a package change on the current submitted proposal, sampled at scrape.\n");
        body.push_str("# TYPE breg_proposal_application_blocked_jobs gauge\n");
        if let Some(sample) = queue_sample {
            body.push_str(&format!(
                "breg_proposal_application_blocked_jobs {}\n",
                sample.blocked_application_jobs
            ));
        }
        body.push_str(
            "# HELP breg_record_timer_observed_live_lease_owners Distinct observed current live lease owners, not a census of running replicas.\n",
        );
        body.push_str("# TYPE breg_record_timer_observed_live_lease_owners gauge\n");
        body.push_str(
            "# HELP breg_record_timer_oldest_due_lag_seconds Seconds since the oldest sampled current due timer became due according to PostgreSQL; absent when none is due.\n",
        );
        body.push_str("# TYPE breg_record_timer_oldest_due_lag_seconds gauge\n");
        body.push_str(
            "# HELP breg_record_timer_current_occurrences Current timer occurrences in the bounded sample by closed state and block kind.\n",
        );
        body.push_str("# TYPE breg_record_timer_current_occurrences gauge\n");
        body.push_str(
            "# HELP breg_record_timer_current_executed_attempts Cumulative executed attempts recorded on the bounded current-occurrence sample; a gauge, not a monotonic retry counter.\n",
        );
        body.push_str("# TYPE breg_record_timer_current_executed_attempts gauge\n");
        body.push_str(
            "# HELP breg_record_timer_retained_attempts Retained value-free attempt details for the bounded current-occurrence sample.\n",
        );
        body.push_str("# TYPE breg_record_timer_retained_attempts gauge\n");
        body.push_str(
            "# HELP breg_record_timer_stale_current_occurrences Current unfinished occurrences whose cached policy revision differs from the open binding.\n",
        );
        body.push_str("# TYPE breg_record_timer_stale_current_occurrences gauge\n");
        body.push_str(
            "# HELP breg_record_timer_control_compatible Whether the durable timer protocol, bound instance epoch, and active package match this process.\n",
        );
        body.push_str("# TYPE breg_record_timer_control_compatible gauge\n");
        body.push_str(
            "# HELP breg_record_timer_counts_truncated Whether current occurrence, attempt, or lease-owner counts reached the bounded sample ceiling.\n",
        );
        body.push_str("# TYPE breg_record_timer_counts_truncated gauge\n");
        if let Some(timer) = queue_sample.and_then(|sample| sample.timer.as_ref()) {
            body.push_str(&format!(
                "breg_record_timer_observed_live_lease_owners {}\n",
                timer.observed_live_lease_owners
            ));
            if let Some(seconds) = timer.oldest_due_lag_seconds {
                body.push_str(&format!(
                    "breg_record_timer_oldest_due_lag_seconds {seconds}\n"
                ));
            }
            for (state, count) in TIMER_STATES.into_iter().zip(timer.occurrence_counts) {
                if state == "blocked" {
                    for (block_kind, blocked) in
                        TIMER_BLOCK_KINDS.into_iter().zip(timer.block_counts)
                    {
                        body.push_str(&format!(
                            "breg_record_timer_current_occurrences{{state=\"{state}\",block_kind=\"{block_kind}\"}} {blocked}\n"
                        ));
                    }
                } else {
                    body.push_str(&format!(
                        "breg_record_timer_current_occurrences{{state=\"{state}\",block_kind=\"none\"}} {count}\n"
                    ));
                }
            }
            body.push_str(&format!(
                "breg_record_timer_current_executed_attempts {}\n",
                timer.current_executed_attempts
            ));
            body.push_str(&format!(
                "breg_record_timer_retained_attempts {}\n",
                timer.retained_attempts
            ));
            body.push_str(&format!(
                "breg_record_timer_stale_current_occurrences {}\n",
                timer.stale_current_occurrences
            ));
            body.push_str(&format!(
                "breg_record_timer_control_compatible{{state=\"{}\"}} {}\n",
                timer.control_state,
                u8::from(timer.control_compatible)
            ));
            body.push_str(&format!(
                "breg_record_timer_counts_truncated {}\n",
                u8::from(timer.counts_truncated)
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
    pub(crate) async fn sample_queues(&self) -> Option<QueueSample> {
        let pool = self.pool.as_ref()?;
        let _sampling = self.queue_sample.lock().await;
        match read_queues(pool).await {
            Ok(mut sample) => {
                sample.timer =
                    match read_timer_sample_from_pool(pool, self.active_package_digest.as_deref())
                        .await
                    {
                        Ok(timer) => Some(timer),
                        Err(()) => {
                            crate::startup::OperationalEvent::MetricsTimerSampleFailed.emit();
                            None
                        }
                    };
                Some(sample)
            }
            Err(()) => {
                crate::startup::OperationalEvent::MetricsQueueSampleFailed.emit();
                None
            }
        }
    }
}

/// Read every queue age in one bounded, read-only statement. The due
/// predicates follow each worker's claim, so work scheduled for a later
/// retry does not count as waiting. A hook lease that expired is claimable
/// again, so it has waited since its lease expired. A review submission claim
/// extends its lease without advancing `next_attempt_at`, so a claimable
/// submission has waited since the later of the two; `GREATEST` ignores a
/// NULL lease.
async fn read_queues(pool: &RuntimePool) -> Result<QueueSample, ()> {
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
                                FROM registry_internal.registry_proposal_review_submissions s
                               WHERE s.state IN ('pending','submitting','uncertain','cancelling')
                                 AND {submission_claimable}), 0),
                    COALESCE((SELECT EXTRACT(EPOCH FROM transaction_timestamp()
                                      - MIN(q.next_attempt_at))::float8
                                FROM registry_internal.registry_proposal_application_jobs q
                                JOIN registry_internal.registry_proposal_state p USING(action_id,proposal_id)
                               WHERE q.state IN ('queued','applying')
                                 AND q.attempt_count < q.maximum_attempts
                                 AND p.state='submitted' AND p.submission_version=q.submission_version
                                 AND p.blocked_reason IS NULL AND p.detail_erased_at IS NULL
                                 AND q.next_attempt_at <= transaction_timestamp()), 0),
                    (SELECT count(*) FROM registry_internal.registry_proposal_application_jobs q
                       JOIN registry_internal.registry_proposal_state p USING(action_id,proposal_id)
                      WHERE p.state='submitted' AND p.submission_version=q.submission_version
                        AND p.blocked_reason='package-changed'
                        AND q.state IN ('queued','applying','blocked','cancelled'))",
                schema = crate::hooks::DELIVERY_SCHEMA,
                submission_claimable = crate::review_store::REVIEW_SUBMISSION_CLAIMABLE,
            ),
            &[],
        )
        .await
        .map_err(|_| ())?;
    let ages = PendingQueue::ALL
        .into_iter()
        .enumerate()
        .map(|(column, queue)| Ok((queue, row.try_get::<_, f64>(column)?)))
        .collect::<Result<Vec<_>, tokio_postgres::Error>>()
        .map_err(|_| ())?;
    let blocked_application_jobs = row.try_get::<_, i64>(3).map_err(|_| ())?;
    transaction.commit().await.map_err(|_| ())?;
    Ok(QueueSample {
        ages,
        blocked_application_jobs,
        timer: None,
    })
}

/// Read the timer sample independently from the existing queues. Each scrape
/// holds at most one pool connection at a time: the queue transaction commits
/// before this bounded five-second read-only transaction starts. A timer
/// failure can therefore omit only timer series without erasing healthy queue
/// observations; the total database statement budget per scrape is ten
/// seconds, with no public configuration knob.
async fn read_timer_sample_from_pool(
    pool: &RuntimePool,
    process_package_digest: Option<&str>,
) -> Result<TimerSample, ()> {
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
    let sample = read_timer_sample(&*transaction, process_package_digest).await?;
    transaction.commit().await.map_err(|_| ())?;
    Ok(sample)
}

async fn read_timer_sample(
    client: &impl tokio_postgres::GenericClient,
    process_package_digest: Option<&str>,
) -> Result<TimerSample, ()> {
    let row = client
        .query_one(
            "WITH requested_state(value) AS (
                 VALUES ('pending'),('leased'),('completed'),('refused'),
                        ('blocked'),('cancelled'),('superseded'),('missed')
             ), state_sample AS MATERIALIZED (
                 SELECT requested.value,count(sample.present)::bigint AS sampled_count
                   FROM requested_state AS requested
                   LEFT JOIN LATERAL (
                       SELECT 1 AS present
                         FROM registry_internal.registry_record_timer_generations AS generation
                         JOIN registry_internal.registry_record_timer_current AS current
                           ON current.occurrence_id=generation.occurrence_id
                          AND current.record_type=generation.record_type
                          AND current.record_id=generation.record_id
                          AND current.timer_id=generation.timer_id
                          AND current.binding_incarnation=generation.binding_incarnation
                          AND current.material_signature=generation.material_signature
                        WHERE generation.state=requested.value
                        LIMIT $1
                   ) AS sample ON true
                  GROUP BY requested.value
             ), requested_block(value) AS (
                 VALUES ('technical'),('configuration')
             ), block_sample AS MATERIALIZED (
                 SELECT requested.value,count(sample.present)::bigint AS sampled_count
                   FROM requested_block AS requested
                   LEFT JOIN LATERAL (
                       SELECT 1 AS present
                         FROM registry_internal.registry_record_timer_generations AS generation
                         JOIN registry_internal.registry_record_timer_current AS current
                           ON current.occurrence_id=generation.occurrence_id
                          AND current.record_type=generation.record_type
                          AND current.record_id=generation.record_id
                          AND current.timer_id=generation.timer_id
                          AND current.binding_incarnation=generation.binding_incarnation
                          AND current.material_signature=generation.material_signature
                        WHERE generation.state='blocked'
                          AND generation.block_kind=requested.value
                        LIMIT $1
                   ) AS sample ON true
                  GROUP BY requested.value
             ), sampled AS MATERIALIZED (
                 SELECT generation.occurrence_id,generation.state,generation.block_kind,
                        generation.executed_attempt_count,
                        generation.state IN ('pending','leased','blocked') AND (
                            binding.definition_revision IS NULL
                            OR binding.incarnation<>generation.binding_incarnation
                            OR binding.definition_revision<>generation.definition_revision
                            OR binding.action_revision<>generation.action_revision
                            OR binding.system_grant_revision<>generation.system_grant_revision
                        ) AS stale_revision
                   FROM registry_internal.registry_record_timer_current AS current
                   JOIN registry_internal.registry_record_timer_generations AS generation
                     ON generation.occurrence_id=current.occurrence_id
                    AND generation.record_type=current.record_type
                    AND generation.record_id=current.record_id
                    AND generation.timer_id=current.timer_id
                    AND generation.binding_incarnation=current.binding_incarnation
                    AND generation.material_signature=current.material_signature
                   LEFT JOIN registry_internal.registry_record_timer_bindings AS binding
                     ON binding.record_type=generation.record_type
                    AND binding.timer_id=generation.timer_id
                    AND binding.removed_activation_id IS NULL
                  ORDER BY generation.created_at ASC,generation.occurrence_id ASC
                  LIMIT $1
             ), bounded AS MATERIALIZED (
                 SELECT * FROM sampled LIMIT $2
             ), retained_attempts AS MATERIALIZED (
                 SELECT attempt.occurrence_id
                   FROM registry_internal.registry_record_timer_attempts AS attempt
                   JOIN bounded USING (occurrence_id)
                  ORDER BY attempt.occurrence_id,attempt.attempt_number
                  LIMIT $1
             ), status_aggregate AS (
                 SELECT
                     (SELECT count(*)::bigint FROM sampled) AS sampled_count,
                     count(*) FILTER (WHERE state='pending')::bigint AS pending,
                     count(*) FILTER (WHERE state='leased')::bigint AS leased,
                     count(*) FILTER (WHERE state='completed')::bigint AS completed,
                     count(*) FILTER (WHERE state='refused')::bigint AS refused,
                     count(*) FILTER (WHERE state='blocked')::bigint AS blocked,
                     count(*) FILTER (WHERE state='cancelled')::bigint AS cancelled,
                     count(*) FILTER (WHERE state='superseded')::bigint AS superseded,
                     count(*) FILTER (WHERE state='missed')::bigint AS missed,
                     count(*) FILTER (WHERE block_kind='technical')::bigint AS technical,
                     count(*) FILTER (WHERE block_kind='configuration')::bigint AS configuration,
                     COALESCE(sum(executed_attempt_count),0)::bigint AS executed_attempts,
                     count(*) FILTER (WHERE stale_revision)::bigint AS stale_current,
                     (SELECT count(*)::bigint FROM retained_attempts) AS retained_attempts
                   FROM bounded
             ), sampled_leases AS MATERIALIZED (
                 SELECT generation.claim_owner_id
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                  WHERE generation.state='leased'
                    AND generation.claim_until>clock_timestamp()
                  ORDER BY generation.claim_until ASC,generation.claim_owner_id ASC,
                           generation.occurrence_id ASC
                  LIMIT $1
             ), lease_aggregate AS (
                 SELECT count(*)::bigint AS sampled_lease_count,
                        count(DISTINCT claim_owner_id)::bigint AS owner_count
                   FROM sampled_leases
             ), due AS (
                 SELECT greatest(
                            0,
                            extract(epoch FROM (clock_timestamp()-generation.due_at))::float8
                        ) AS lag_seconds
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                  WHERE generation.state IN ('pending','leased')
                    AND generation.gate_open
                    AND generation.due_at<=clock_timestamp()
                    AND (generation.retry_at IS NULL OR generation.retry_at<=clock_timestamp())
                    AND (generation.not_after IS NULL OR clock_timestamp()<generation.not_after)
                  ORDER BY generation.due_at ASC,generation.occurrence_id ASC
                  LIMIT 1
             ), control AS (
                 SELECT timer.protocol_version,timer.control_state,
                        timer.bound_instance_epoch=registry.epoch AS instance_matches,
                        COALESCE(registry.active_package_digest=$3,false) AS package_matches
                   FROM registry_internal.registry_record_timer_control AS timer
                   JOIN registry_internal.registry_state AS registry ON registry.singleton
                  WHERE timer.singleton
             )
             SELECT
                 status_aggregate.*,lease_aggregate.sampled_lease_count,
                 lease_aggregate.owner_count,
                 (SELECT lag_seconds FROM due) AS lag_seconds,
                 control.protocol_version,control.control_state,control.instance_matches,
                 control.package_matches,
                 (SELECT sampled_count FROM state_sample WHERE value='pending') AS category_pending,
                 (SELECT sampled_count FROM state_sample WHERE value='leased') AS category_leased,
                 (SELECT sampled_count FROM state_sample WHERE value='completed') AS category_completed,
                 (SELECT sampled_count FROM state_sample WHERE value='refused') AS category_refused,
                 (SELECT sampled_count FROM state_sample WHERE value='blocked') AS category_blocked,
                 (SELECT sampled_count FROM state_sample WHERE value='cancelled') AS category_cancelled,
                 (SELECT sampled_count FROM state_sample WHERE value='superseded') AS category_superseded,
                 (SELECT sampled_count FROM state_sample WHERE value='missed') AS category_missed,
                 (SELECT sampled_count FROM block_sample WHERE value='technical') AS category_technical,
                 (SELECT sampled_count FROM block_sample WHERE value='configuration') AS category_configuration,
                 (SELECT bool_or(sampled_count>$2) FROM state_sample)
                    OR (SELECT bool_or(sampled_count>$2) FROM block_sample)
                    AS category_counts_truncated
               FROM status_aggregate CROSS JOIN lease_aggregate CROSS JOIN control",
            &[
                &TIMER_STATUS_SCAN_SENTINEL,
                &TIMER_STATUS_SCAN_MAXIMUM,
                &process_package_digest,
            ],
        )
        .await
        .map_err(|_| ())?;
    let sampled_count = row.try_get::<_, i64>("sampled_count").map_err(|_| ())?;
    let retained_attempts = row.try_get::<_, i64>("retained_attempts").map_err(|_| ())?;
    let occurrence_counts = [
        row.try_get::<_, i64>("category_pending")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
        row.try_get::<_, i64>("category_leased")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
        row.try_get::<_, i64>("category_completed")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
        row.try_get::<_, i64>("category_refused")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
        row.try_get::<_, i64>("category_blocked")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
        row.try_get::<_, i64>("category_cancelled")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
        row.try_get::<_, i64>("category_superseded")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
        row.try_get::<_, i64>("category_missed")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
    ];
    let block_counts = [
        row.try_get::<_, i64>("category_technical")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
        row.try_get::<_, i64>("category_configuration")
            .map_err(|_| ())?
            .min(TIMER_STATUS_SCAN_MAXIMUM),
    ];
    let category_counts_truncated = row
        .try_get::<_, bool>("category_counts_truncated")
        .map_err(|_| ())?;
    let sampled_lease_count = row
        .try_get::<_, i64>("sampled_lease_count")
        .map_err(|_| ())?;
    let observed_live_lease_owners = row.try_get::<_, i64>("owner_count").map_err(|_| ())?;
    let oldest_due_lag_seconds = row
        .try_get::<_, Option<f64>>("lag_seconds")
        .map_err(|_| ())?;
    let protocol_version = row.try_get::<_, i32>("protocol_version").map_err(|_| ())?;
    let control_state = match row
        .try_get::<_, String>("control_state")
        .map_err(|_| ())?
        .as_str()
    {
        "running" => "running",
        "paused" => "paused",
        "adoption-hold" => "adoption-hold",
        _ => return Err(()),
    };
    let instance_matches = row.try_get::<_, bool>("instance_matches").map_err(|_| ())?;
    let package_matches = row.try_get::<_, bool>("package_matches").map_err(|_| ())?;

    Ok(TimerSample {
        observed_live_lease_owners: observed_live_lease_owners.min(TIMER_STATUS_SCAN_MAXIMUM),
        oldest_due_lag_seconds,
        occurrence_counts,
        block_counts,
        current_executed_attempts: row.try_get("executed_attempts").map_err(|_| ())?,
        retained_attempts: retained_attempts.min(TIMER_STATUS_SCAN_MAXIMUM),
        stale_current_occurrences: row.try_get("stale_current").map_err(|_| ())?,
        control_state,
        control_compatible: protocol_version == crate::postgres::SUPPORTED_TIMER_PROTOCOL_VERSION
            && instance_matches
            && package_matches,
        counts_truncated: category_counts_truncated
            || sampled_count > TIMER_STATUS_SCAN_MAXIMUM
            || retained_attempts > TIMER_STATUS_SCAN_MAXIMUM
            || sampled_lease_count > TIMER_STATUS_SCAN_MAXIMUM,
    })
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
    let queue_ages = metrics.sample_queues().await;
    let mut response = (StatusCode::OK, metrics.render(queue_ages.as_ref())).into_response();
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
        let hook = Arc::new(LastSuccess::default());
        let metrics = Metrics::default()
            .with_worker_progress(ProgressWorker::Review, Arc::clone(&review))
            .with_worker_progress(ProgressWorker::Hook, Arc::clone(&hook));
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

        assert!(!unsampled.contains("breg_proposal_application_blocked_jobs 0\n"));
        let sampled = metrics.render(Some(&QueueSample {
            ages: vec![
                (PendingQueue::HookDelivery, 0.0),
                (PendingQueue::ReviewSubmission, 90.5),
                (PendingQueue::ReviewApplication, 0.0),
            ],
            blocked_application_jobs: 2,
            timer: None,
        }));
        assert!(sampled.contains("breg_proposal_application_blocked_jobs 2\n"));
        for expected in [
            "breg_queue_oldest_pending_age_seconds{queue=\"hook-delivery\"} 0\n",
            "breg_queue_oldest_pending_age_seconds{queue=\"review-submission\"} 90.5\n",
            "breg_queue_oldest_pending_age_seconds{queue=\"review-application\"} 0\n",
        ] {
            assert!(sampled.contains(expected), "{expected} in:\n{sampled}");
        }
    }

    #[test]
    fn timer_metrics_use_closed_labels_and_distinguish_observation_from_census() {
        let metrics = Metrics::default();
        let rendered = metrics.render(Some(&QueueSample {
            ages: Vec::new(),
            blocked_application_jobs: 0,
            timer: Some(TimerSample {
                observed_live_lease_owners: 2,
                oldest_due_lag_seconds: Some(12.5),
                occurrence_counts: [1, 2, 3, 4, 2, 5, 6, 7],
                block_counts: [1, 1],
                current_executed_attempts: 8,
                retained_attempts: 7,
                stale_current_occurrences: 1,
                control_state: "paused",
                control_compatible: true,
                counts_truncated: false,
            }),
        }));
        for expected in [
            "# HELP breg_record_timer_observed_live_lease_owners Distinct observed current live lease owners, not a census of running replicas.\n",
            "breg_record_timer_observed_live_lease_owners 2\n",
            "breg_record_timer_oldest_due_lag_seconds 12.5\n",
            "breg_record_timer_current_occurrences{state=\"blocked\",block_kind=\"technical\"} 1\n",
            "breg_record_timer_current_occurrences{state=\"blocked\",block_kind=\"configuration\"} 1\n",
            "breg_record_timer_current_executed_attempts 8\n",
            "breg_record_timer_retained_attempts 7\n",
            "breg_record_timer_stale_current_occurrences 1\n",
            "breg_record_timer_control_compatible{state=\"paused\"} 1\n",
            "breg_record_timer_counts_truncated 0\n",
        ] {
            assert!(rendered.contains(expected), "{expected} in:\n{rendered}");
        }
        for forbidden in ["claim_owner", "occurrence_id", "active_replicas"] {
            assert!(
                !rendered.contains(forbidden),
                "timer metric contract disclosed or mislabeled {forbidden}:\n{rendered}"
            );
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
