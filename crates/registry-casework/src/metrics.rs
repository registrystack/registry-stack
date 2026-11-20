//! Optional operator-private telemetry. Labels contain no caller or subject values.
use crate::{CompletionBacklog, PostgresStore};
use axum::{extract::State, http::header::CONTENT_TYPE, routing::get, Json, Router};
use registry_platform_metrics::{
    sample_error_class, Exposition, MetricKind, ScrapeDeadline, CLASS_NO_TIME_LEFT, CLASS_TIMEOUT,
    CONTENT_TYPE as METRICS_CONTENT_TYPE,
};
use serde_json::json;
use std::sync::Arc;
/// One sample of the database. Each part is sampled on its own, so a failing
/// part leaves out only its own series.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Readings {
    /// The open requests, open tasks and due tasks.
    review: Option<[i64; 3]>,
    completions: Option<CompletionBacklog>,
}

/// The samples whose failure `casework_metrics_sample_failures_total` counts.
#[derive(Clone, Copy)]
enum SampleKind {
    Review,
    CompletionBacklog,
}

impl SampleKind {
    const ALL: [Self; 2] = [Self::Review, Self::CompletionBacklog];

    fn label(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::CompletionBacklog => "completion-backlog",
        }
    }
}

/// Failed samples since the process started, by sample.
#[derive(Default)]
struct SampleFailures([std::sync::atomic::AtomicU64; SampleKind::ALL.len()]);

impl SampleFailures {
    /// Run one sample before `deadline`. A failure or a timeout is logged
    /// by its error class, counted once, and leaves the sample without a
    /// value. The class never carries query text or row data.
    async fn sample<T>(
        &self,
        kind: SampleKind,
        deadline: ScrapeDeadline,
        read: impl std::future::Future<Output = Result<T, String>>,
    ) -> Option<T> {
        let class = match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.at()),
            read,
        )
        .await
        {
            Ok(Ok(value)) => return Some(value),
            Ok(Err(class)) => class,
            Err(_) => CLASS_TIMEOUT.to_owned(),
        };
        self.0[kind as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!(
            sample = kind.label(),
            class = %class,
            "a metrics sample failed; its series are left out of this scrape"
        );
        None
    }

    fn count(&self, kind: SampleKind) -> u64 {
        self.0[kind as usize].load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub(crate) struct MetricsState {
    inner: Arc<MetricsInner>,
}
struct MetricsInner {
    store: PostgresStore,
    package_digest: String,
    failures: SampleFailures,
    readings: tokio::sync::Mutex<Option<(tokio::time::Instant, Readings)>>,
}
impl MetricsState {
    pub(crate) fn new(
        store: PostgresStore,
        _providers: Vec<String>,
        package_digest: String,
    ) -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                store,
                package_digest,
                failures: SampleFailures::default(),
                readings: Default::default(),
            }),
        }
    }
    async fn readings(&self) -> Readings {
        let mut cached = self.inner.readings.lock().await;
        if let Some((at, value)) = &*cached {
            if at.elapsed() < std::time::Duration::from_secs(5) {
                return *value;
            }
        }
        let value = self
            .sample(ScrapeDeadline::from(std::time::Instant::now()))
            .await;
        *cached = Some((tokio::time::Instant::now(), value));
        value
    }
    /// Read every sample before `deadline`.
    async fn sample(&self, deadline: ScrapeDeadline) -> Readings {
        let failures = &self.inner.failures;
        // The review connection is released before the backlog read takes
        // its own, so one scrape holds one pool connection at a time.
        let review = failures
            .sample(
                SampleKind::Review,
                deadline,
                read_review_counts(&self.inner.store, deadline),
            )
            .await;
        let completions = failures
            .sample(
                SampleKind::CompletionBacklog,
                deadline,
                self.inner.store.completion_backlog(deadline),
            )
            .await;
        Readings {
            review,
            completions,
        }
    }
}

/// The open requests, open tasks and due tasks, read in one read-only
/// transaction bounded by the scrape deadline.
async fn read_review_counts(
    store: &PostgresStore,
    deadline: ScrapeDeadline,
) -> Result<[i64; 3], String> {
    let mut client = store.sample_client().await?;
    let transaction = begin_sample(&mut client, deadline).await?;
    let row = transaction
        .query_one(
            "SELECT (SELECT count(*) FROM casework_review_requests WHERE lifecycle='reviewing'),(SELECT count(*) FROM casework_review_tasks WHERE state IN('open','claimed')),(SELECT count(*) FROM casework_review_tasks WHERE state IN('open','claimed') AND deadline_at<=now())",
            &[],
        )
        .await
        .map_err(|error| database_error_class(&error))?;
    transaction
        .commit()
        .await
        .map_err(|error| database_error_class(&error))?;
    Ok([row.get(0), row.get(1), row.get(2)])
}

/// The error class of a driver error: never its text, which can carry query
/// text or row data.
pub(crate) fn database_error_class(error: &tokio_postgres::Error) -> String {
    sample_error_class(
        error.code().map(tokio_postgres::error::SqlState::code),
        error.is_closed(),
    )
}

/// Start a read-only transaction whose server-side `statement_timeout` is
/// the time left before `deadline`, so a slow query is cancelled on the
/// server and not only abandoned by the client. A sample with no time left
/// fails without querying.
pub(crate) async fn begin_sample<'a>(
    client: &'a mut deadpool_postgres::Client,
    deadline: ScrapeDeadline,
) -> Result<deadpool_postgres::Transaction<'a>, String> {
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
    Ok(transaction)
}

/// The exposition of one scrape read before `deadline`, with a fresh
/// failure count.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn scrape_for_test(store: PostgresStore, deadline: ScrapeDeadline) -> String {
    let state = MetricsState::new(store, Vec::new(), "sha256:test".to_owned());
    let readings = state.sample(deadline).await;
    render(readings, &state.inner.failures)
}
pub(crate) fn metrics_router(state: MetricsState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/version", get(version))
        .with_state(state)
}
async fn version(State(state): State<MetricsState>) -> Json<serde_json::Value> {
    Json(json!({"version":env!("CARGO_PKG_VERSION"),"packageDigest":state.inner.package_digest}))
}
async fn metrics(
    State(state): State<MetricsState>,
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    let readings = state.readings().await;
    (
        [(CONTENT_TYPE, METRICS_CONTENT_TYPE)],
        render(readings, &state.inner.failures),
    )
}
/// The exposition for one scrape. A part of `readings` that could not be
/// read has no series. The database counts as up when the review counts were
/// read.
fn render(readings: Readings, failures: &SampleFailures) -> String {
    const DECLARATION: &str = "the metric declarations are valid";
    let mut out = Exposition::new();
    out.header("casework_database_up", None, MetricKind::Gauge)
        .expect(DECLARATION);
    out.sample(
        "casework_database_up",
        &[],
        u8::from(readings.review.is_some()),
    )
    .expect(DECLARATION);
    if let Some(review) = readings.review {
        for (name, value) in [
            "casework_open_review_requests",
            "casework_open_review_tasks",
            "casework_due_review_tasks",
        ]
        .into_iter()
        .zip(review)
        {
            out.header(name, None, MetricKind::Gauge)
                .expect(DECLARATION);
            out.sample(name, &[], value).expect(DECLARATION);
        }
    }
    if let Some(backlog) = readings.completions {
        out.header(
            "casework_completion_deliveries",
            Some("Review completion deliveries not yet delivered, by state, sampled at scrape."),
            MetricKind::Gauge,
        )
        .expect(DECLARATION);
        for (state, value) in [
            ("pending", backlog.pending),
            ("retrying", backlog.retrying),
            ("leased", backlog.leased),
            ("unknown", backlog.unknown),
            ("dead-lettered", backlog.dead_lettered),
            ("expired", backlog.expired),
        ] {
            out.sample("casework_completion_deliveries", &[("state", state)], value)
                .expect(DECLARATION);
        }
        out.header(
            "casework_completion_oldest_undelivered_age_seconds",
            Some("Seconds the oldest undelivered completion delivery has waited, or 0 when none."),
            MetricKind::Gauge,
        )
        .expect(DECLARATION);
        out.sample(
            "casework_completion_oldest_undelivered_age_seconds",
            &[],
            backlog.oldest_undelivered_seconds,
        )
        .expect(DECLARATION);
    }
    out.header(
        "casework_metrics_sample_failures_total",
        Some("Scrape-time database samples that failed since this process started, by sample."),
        MetricKind::Counter,
    )
    .expect(DECLARATION);
    for kind in SampleKind::ALL {
        out.sample(
            "casework_metrics_sample_failures_total",
            &[("sample", kind.label())],
            failures.count(kind),
        )
        .expect(DECLARATION);
    }
    out.finish()
}
#[cfg(test)]
mod tests {
    use super::{render, Readings, SampleFailures, SampleKind};
    use crate::CompletionBacklog;
    use registry_platform_metrics::ScrapeDeadline;

    fn backlog() -> CompletionBacklog {
        CompletionBacklog {
            pending: 1,
            retrying: 2,
            leased: 0,
            unknown: 0,
            dead_lettered: 3,
            expired: 0,
            oldest_undelivered_seconds: 7200,
        }
    }

    const REVIEW: &str = "# TYPE casework_database_up gauge\ncasework_database_up 1\n\
             # TYPE casework_open_review_requests gauge\ncasework_open_review_requests 4\n\
             # TYPE casework_open_review_tasks gauge\ncasework_open_review_tasks 9\n\
             # TYPE casework_due_review_tasks gauge\ncasework_due_review_tasks 2\n";
    const COMPLETIONS: &str = "# HELP casework_completion_deliveries Review completion deliveries not yet delivered, by state, sampled at scrape.\n\
             # TYPE casework_completion_deliveries gauge\n\
             casework_completion_deliveries{state=\"pending\"} 1\n\
             casework_completion_deliveries{state=\"retrying\"} 2\n\
             casework_completion_deliveries{state=\"leased\"} 0\n\
             casework_completion_deliveries{state=\"unknown\"} 0\n\
             casework_completion_deliveries{state=\"dead-lettered\"} 3\n\
             casework_completion_deliveries{state=\"expired\"} 0\n\
             # HELP casework_completion_oldest_undelivered_age_seconds Seconds the oldest undelivered completion delivery has waited, or 0 when none.\n\
             # TYPE casework_completion_oldest_undelivered_age_seconds gauge\n\
             casework_completion_oldest_undelivered_age_seconds 7200\n";
    const FAILURES: &str = "# HELP casework_metrics_sample_failures_total Scrape-time database samples that failed since this process started, by sample.\n\
             # TYPE casework_metrics_sample_failures_total counter\n";

    #[test]
    fn the_scrape_is_byte_stable() {
        let readings = Readings {
            review: Some([4, 9, 2]),
            completions: Some(backlog()),
        };
        assert_eq!(
            render(readings, &SampleFailures::default()),
            format!(
                "{REVIEW}{COMPLETIONS}{FAILURES}\
                 casework_metrics_sample_failures_total{{sample=\"review\"}} 0\n\
                 casework_metrics_sample_failures_total{{sample=\"completion-backlog\"}} 0\n"
            )
        );
        assert_eq!(
            render(Readings::default(), &SampleFailures::default()),
            format!(
                "# TYPE casework_database_up gauge\ncasework_database_up 0\n{FAILURES}\
                 casework_metrics_sample_failures_total{{sample=\"review\"}} 0\n\
                 casework_metrics_sample_failures_total{{sample=\"completion-backlog\"}} 0\n"
            )
        );
    }

    #[test]
    fn a_failed_backlog_leaves_out_only_the_completion_series() {
        let readings = Readings {
            review: Some([4, 9, 2]),
            completions: None,
        };
        let failures = SampleFailures::default();
        failures.0[SampleKind::CompletionBacklog as usize]
            .store(2, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            render(readings, &failures),
            format!(
                "{REVIEW}{FAILURES}\
                 casework_metrics_sample_failures_total{{sample=\"review\"}} 0\n\
                 casework_metrics_sample_failures_total{{sample=\"completion-backlog\"}} 2\n"
            )
        );
    }

    #[tokio::test]
    async fn a_failing_sample_is_counted_and_a_working_one_is_not() {
        let failures = SampleFailures::default();
        let deadline = ScrapeDeadline::from(std::time::Instant::now());
        let review = failures
            .sample(SampleKind::Review, deadline, async {
                Ok::<_, String>([4, 9, 2])
            })
            .await;
        let completions = failures
            .sample(SampleKind::CompletionBacklog, deadline, async {
                Err::<CompletionBacklog, _>("the statement timed out".to_owned())
            })
            .await;
        assert_eq!(review, Some([4, 9, 2]));
        assert_eq!(completions, None);
        assert_eq!(failures.count(SampleKind::Review), 0);
        assert_eq!(failures.count(SampleKind::CompletionBacklog), 1);
    }

    #[tokio::test]
    async fn two_unreachable_samples_share_one_deadline() {
        let failures = SampleFailures::default();
        let started = std::time::Instant::now();
        let deadline = ScrapeDeadline::with_budget(started, std::time::Duration::from_millis(100));
        let review = failures
            .sample(
                SampleKind::Review,
                deadline,
                std::future::pending::<Result<[i64; 3], String>>(),
            )
            .await;
        let completions = failures
            .sample(
                SampleKind::CompletionBacklog,
                deadline,
                std::future::pending::<Result<CompletionBacklog, String>>(),
            )
            .await;
        assert_eq!((review, completions), (None, None));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(190),
            "the second sample must not get a fresh timeout: {:?}",
            started.elapsed()
        );
        assert_eq!(failures.count(SampleKind::Review), 1);
        assert_eq!(failures.count(SampleKind::CompletionBacklog), 1);
    }
}
