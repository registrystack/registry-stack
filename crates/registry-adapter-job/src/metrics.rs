// SPDX-License-Identifier: Apache-2.0

//! Operational metrics of the pass loop, served only on the operator-private
//! metrics listener of `pass --loop`.
//!
//! Every label is a closed vocabulary: the four item states, the pass stop
//! reasons, and the hook refusal reasons. No item key, refusal code, hold
//! code, path, source name, or principal becomes a label. The gauge of items
//! is read from the job store at scrape time. When that read fails the
//! sample is omitted and counted in `adapter_job_gauge_sample_failures_total`,
//! never reported as zero.
//!
//! Counters are per process and start from zero at each start. The last
//! successful pass is tracked in the process, so it is absent until this
//! process has completed a pass that settled its page.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use deadpool_postgres::Pool;
use registry_platform_metrics::{
    CounterVec, Exposition, LabelSpace, MetricKind, CONTENT_TYPE as METRICS_CONTENT_TYPE,
};

use crate::store::{self, ItemStatus};

/// The path the metrics listener serves.
pub const METRICS_PATH: &str = "/metrics";

const DECLARATION: &str = "the metric declarations are valid";

/// The item states the gauge reports, in the item table's own spelling.
const ITEM_STATES: [ItemStatus; 4] = [
    ItemStatus::Pending,
    ItemStatus::Acknowledged,
    ItemStatus::Refused,
    ItemStatus::Held,
];

/// Why a pass did not settle its page, the closed label of
/// `adapter_job_pass_failures_total`. The first four are the pass's own stop
/// reasons. `error` is a pass that failed before it could report, and
/// `store-unreachable` is a loop iteration that could not read the job state.
const PASS_FAILURES: [&str; 6] = [
    "lease-held",
    "page-fault",
    "destination-stop",
    "refusal-limit",
    "error",
    "store-unreachable",
];

/// Why the hook ingress refused a request, the closed label of
/// `adapter_job_hook_refusals_total`. Each is the refusal code's last word
/// group.
const HOOK_REFUSALS: [&str; 8] = [
    "not-found",
    "method",
    "unauthenticated",
    "rate-limited",
    "unavailable",
    "body-timeout",
    "body-too-large",
    "body-unreadable",
];

pub struct JobMetrics {
    pass_failures: CounterVec,
    hook_refusals: CounterVec,
    sample_failures: CounterVec,
    last_success: Mutex<Option<Instant>>,
}

impl fmt::Debug for JobMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobMetrics").finish_non_exhaustive()
    }
}

fn singles(values: &[&'static str]) -> Vec<[&'static str; 1]> {
    values.iter().map(|value| [*value]).collect()
}

fn declared<'a>(values: &'a [[&'static str; 1]]) -> Vec<&'a [&'static str]> {
    values.iter().map(|value| value.as_slice()).collect()
}

impl Default for JobMetrics {
    fn default() -> Self {
        let failures = singles(&PASS_FAILURES);
        let refusals = singles(&HOOK_REFUSALS);
        Self {
            pass_failures: CounterVec::new(
                "adapter_job_pass_failures_total",
                "Loop passes that did not settle their page, by reason.",
                LabelSpace::closed_zero_filled(&["reason"], &declared(&failures))
                    .expect(DECLARATION),
            )
            .expect(DECLARATION),
            hook_refusals: CounterVec::new(
                "adapter_job_hook_refusals_total",
                "Hook-trigger requests the ingress refused, by reason.",
                LabelSpace::closed_zero_filled(&["reason"], &declared(&refusals))
                    .expect(DECLARATION),
            )
            .expect(DECLARATION),
            sample_failures: CounterVec::new(
                "adapter_job_gauge_sample_failures_total",
                "Scrapes whose item counts could not be read from the job store, so the gauge was omitted.",
                LabelSpace::closed_zero_filled(&[], &[&[]]).expect(DECLARATION),
            )
            .expect(DECLARATION),
            last_success: Mutex::new(None),
        }
    }
}

impl JobMetrics {
    /// Record that a pass settled its page now.
    pub fn record_pass_success(&self) {
        *self
            .last_success
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Instant::now());
    }

    /// Count one pass that did not settle, under its closed reason.
    pub fn record_pass_failure(&self, reason: &str) {
        count(&self.pass_failures, &[reason]);
    }

    /// Count one refused hook request, under its closed reason.
    pub fn record_hook_refusal(&self, reason: &str) {
        count(&self.hook_refusals, &[reason]);
    }

    /// Count one scrape whose item counts could not be read.
    pub fn record_sample_failure(&self) {
        count(&self.sample_failures, &[]);
    }

    /// Render the Prometheus text exposition. `items` is the item count by
    /// state when the store read succeeded, and `None` when it failed, in
    /// which case the gauge carries no samples.
    #[must_use]
    pub fn render(&self, items: Option<[(ItemStatus, u64); 4]>) -> String {
        let mut out = Exposition::new();
        for counter in [
            &self.pass_failures,
            &self.hook_refusals,
            &self.sample_failures,
        ] {
            counter.write(&mut out).expect(DECLARATION);
        }
        out.header(
            "adapter_job_items",
            Some("Items in the job store by state, sampled at scrape. Absent when the store could not be read."),
            MetricKind::Gauge,
        )
        .expect(DECLARATION);
        if let Some(items) = items {
            for (state, count) in items {
                out.sample("adapter_job_items", &[("state", state.as_str())], count)
                    .expect(DECLARATION);
            }
        }
        out.header(
            "adapter_job_last_successful_pass_age_seconds",
            Some("Seconds since this process last settled a pass. Absent until one has settled."),
            MetricKind::Gauge,
        )
        .expect(DECLARATION);
        let last = *self
            .last_success
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(last) = last {
            out.sample(
                "adapter_job_last_successful_pass_age_seconds",
                &[],
                last.elapsed().as_secs_f64().floor(),
            )
            .expect(DECLARATION);
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

/// Read the item count by state for `job_id`, in the gauge's declared order.
pub async fn sample_items(pool: &Pool, job_id: &str) -> Result<[(ItemStatus, u64); 4], String> {
    let client = pool
        .get()
        .await
        .map_err(|error| store::pool_cause(&error))?;
    let counts = store::item_status_counts(&client, job_id)
        .await
        .map_err(|error| error.cause())?;
    Ok(ITEM_STATES.map(|state| {
        let count = match state {
            ItemStatus::Pending => counts.pending,
            ItemStatus::Acknowledged => counts.acknowledged,
            ItemStatus::Refused => counts.refused,
            ItemStatus::Held => counts.held,
        };
        (state, count)
    }))
}

/// How long a scrape may wait for the store before the gauge is omitted.
const SAMPLE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct ScrapeState {
    metrics: Arc<JobMetrics>,
    pool: Pool,
    job_id: Arc<str>,
}

/// The router the metrics listener serves: the counters and nothing else.
pub fn metrics_router(metrics: Arc<JobMetrics>, pool: Pool, job_id: &str) -> Router {
    Router::new()
        .route(METRICS_PATH, get(scrape))
        .with_state(ScrapeState {
            metrics,
            pool,
            job_id: Arc::from(job_id),
        })
}

async fn scrape(State(state): State<ScrapeState>) -> impl IntoResponse {
    let sampled = tokio::time::timeout(SAMPLE_DEADLINE, sample_items(&state.pool, &state.job_id))
        .await
        .unwrap_or_else(|_| Err("the item count read timed out".to_owned()));
    let items = match sampled {
        Ok(items) => Some(items),
        Err(cause) => {
            tracing::error!(cause = %cause, "the job item counts could not be read for a scrape");
            state.metrics.record_sample_failure();
            None
        }
    };
    (
        [(CONTENT_TYPE, METRICS_CONTENT_TYPE)],
        state.metrics.render(items),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> [(ItemStatus, u64); 4] {
        [
            (ItemStatus::Pending, 3),
            (ItemStatus::Acknowledged, 40),
            (ItemStatus::Refused, 2),
            (ItemStatus::Held, 1),
        ]
    }

    fn has(text: &str, line: &str) -> bool {
        text.lines().any(|found| found == line)
    }

    #[test]
    fn items_are_reported_by_their_real_state_names() {
        let text = JobMetrics::default().render(Some(items()));
        for line in [
            "adapter_job_items{state=\"pending\"} 3",
            "adapter_job_items{state=\"acknowledged\"} 40",
            "adapter_job_items{state=\"refused\"} 2",
            "adapter_job_items{state=\"held\"} 1",
        ] {
            assert!(has(&text, line), "{text}");
        }
    }

    #[test]
    fn a_failed_item_read_leaves_the_gauge_empty_not_zero() {
        let text = JobMetrics::default().render(None);
        assert!(text.contains("# TYPE adapter_job_items gauge"));
        assert!(!text
            .lines()
            .any(|line| line.starts_with("adapter_job_items{")));
    }

    #[test]
    fn last_pass_age_is_absent_until_a_pass_settles() {
        let metrics = JobMetrics::default();
        let before = metrics.render(None);
        assert!(!before
            .lines()
            .any(|line| line.starts_with("adapter_job_last_successful_pass_age_seconds ")));
        metrics.record_pass_success();
        let after = metrics.render(None);
        assert!(has(
            &after,
            "adapter_job_last_successful_pass_age_seconds 0"
        ));
    }

    #[test]
    fn pass_and_hook_failures_count_under_closed_reasons() {
        let metrics = JobMetrics::default();
        metrics.record_pass_failure("page-fault");
        metrics.record_pass_failure("page-fault");
        metrics.record_pass_failure("an unlisted reason");
        metrics.record_hook_refusal("unauthenticated");
        metrics.record_sample_failure();
        let text = metrics.render(None);
        assert!(has(
            &text,
            "adapter_job_pass_failures_total{reason=\"page-fault\"} 2"
        ));
        assert!(has(
            &text,
            "adapter_job_pass_failures_total{reason=\"refusal-limit\"} 0"
        ));
        assert!(!text.contains("unlisted"));
        assert!(has(
            &text,
            "adapter_job_hook_refusals_total{reason=\"unauthenticated\"} 1"
        ));
        assert!(has(&text, "adapter_job_gauge_sample_failures_total 1"));
    }
}
