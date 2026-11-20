//! Optional operator-private telemetry. Labels contain no caller or subject values.
use crate::{CompletionBacklog, PostgresStore};
use axum::{extract::State, http::header::CONTENT_TYPE, routing::get, Json, Router};
use registry_platform_metrics::{Exposition, MetricKind, CONTENT_TYPE as METRICS_CONTENT_TYPE};
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

/// How long one sample may take before it counts as failed.
const SAMPLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Failed samples since the process started, by sample.
#[derive(Default)]
struct SampleFailures([std::sync::atomic::AtomicU64; SampleKind::ALL.len()]);

impl SampleFailures {
    /// Run one sample under the timeout. A failure or a timeout is logged
    /// with its cause and counted, and leaves the sample without a value.
    async fn sample<T, E: std::fmt::Display>(
        &self,
        kind: SampleKind,
        read: impl std::future::Future<Output = Result<T, E>>,
    ) -> Option<T> {
        let cause = match tokio::time::timeout(SAMPLE_TIMEOUT, read).await {
            Ok(Ok(value)) => return Some(value),
            Ok(Err(error)) => error.to_string(),
            Err(_) => "the sample timed out".to_owned(),
        };
        self.0[kind as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!(
            sample = kind.label(),
            error = %cause,
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
        let failures = &self.inner.failures;
        // The review connection is released before the backlog read takes
        // its own, so one scrape holds one pool connection at a time.
        let review = failures
            .sample(SampleKind::Review, async {
                let client = self
                    .inner
                    .store
                    .client()
                    .await
                    .map_err(|error| error.to_string())?;
                let row = client.query_one("SELECT (SELECT count(*) FROM casework_review_requests WHERE lifecycle='reviewing'),(SELECT count(*) FROM casework_review_tasks WHERE state IN('open','claimed')),(SELECT count(*) FROM casework_review_tasks WHERE state IN('open','claimed') AND deadline_at<=now())",&[]).await.map_err(|error| error.to_string())?;
                Ok::<_, String>([row.get(0), row.get(1), row.get(2)])
            })
            .await;
        let completions = failures
            .sample(
                SampleKind::CompletionBacklog,
                self.inner.store.completion_backlog(),
            )
            .await;
        let value = Readings {
            review,
            completions,
        };
        *cached = Some((tokio::time::Instant::now(), value));
        value
    }
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
        let review = failures
            .sample(SampleKind::Review, async { Ok::<_, String>([4, 9, 2]) })
            .await;
        let completions = failures
            .sample(SampleKind::CompletionBacklog, async {
                Err::<CompletionBacklog, _>("the statement timed out".to_owned())
            })
            .await;
        assert_eq!(review, Some([4, 9, 2]));
        assert_eq!(completions, None);
        assert_eq!(failures.count(SampleKind::Review), 0);
        assert_eq!(failures.count(SampleKind::CompletionBacklog), 1);
    }
}
