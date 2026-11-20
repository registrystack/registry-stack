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

use crate::pass::StopReason;
use crate::serve::{serve_with_shutdown_timeout, ServeEnd};
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
/// `adapter_job_pass_failures_total`. The first three are the pass's own stop
/// reasons. `store-unreachable` is a loop iteration that could not read the
/// job state. A pass that fails before it can report ends the process, so it
/// is not a reason a scrape can observe, and a pass that finds another
/// replica holding the lease is the lease working, not a failure.
const PASS_FAILURES: [&str; 4] = [
    "page-fault",
    "destination-stop",
    "refusal-limit",
    "store-unreachable",
];

/// Why the hook ingress refused a request, the closed label of
/// `adapter_job_hook_refusals_total`. Each is the refusal code's last word
/// group.
pub const HOOK_REFUSALS: [&str; 8] = [
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

    /// Record how a pass ended: settled, held back by another replica's
    /// lease (neither a success nor a failure), or stopped under a closed
    /// reason.
    pub fn record_pass_outcome(&self, stopped: Option<&StopReason>) {
        match stopped {
            None => self.record_pass_success(),
            Some(StopReason::LeaseHeld) => {}
            Some(StopReason::PageFault { .. }) => self.record_pass_failure("page-fault"),
            Some(StopReason::DestinationStop { .. }) => {
                self.record_pass_failure("destination-stop");
            }
            Some(StopReason::RefusalLimit { .. }) => self.record_pass_failure("refusal-limit"),
        }
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
///
/// The count runs in a read-only transaction with a server-side statement
/// timeout, so a query the scrape abandons stops on the server instead of
/// holding a connection the pass needs.
pub async fn sample_items(pool: &Pool, job_id: &str) -> Result<[(ItemStatus, u64); 4], String> {
    let mut client = pool
        .get()
        .await
        .map_err(|error| store::pool_cause(&error))?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|error| store::StoreError::from(error).cause())?;
    transaction
        .batch_execute(&format!(
            "SET LOCAL statement_timeout = {SAMPLE_STATEMENT_TIMEOUT_MILLISECONDS}"
        ))
        .await
        .map_err(|error| store::StoreError::from(error).cause())?;
    let counts = store::item_status_counts(&transaction, job_id)
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

/// The server-side limit on the item count, a little under the scrape's own
/// deadline so an abandoned query stops on the server too.
const SAMPLE_STATEMENT_TIMEOUT_MILLISECONDS: u32 = 4_000;

/// How long a sampled result answers later scrapes without another query.
const SAMPLE_CACHE: Duration = Duration::from_secs(5);

type Sample = Result<[(ItemStatus, u64); 4], String>;

/// One store sample at a time, reused by every scrape inside its lifetime, so
/// scrapers never add more than one count query per interval to the pool the
/// pass also uses. A failed sample is reused too, so a store that is down is
/// not queried by every scrape.
pub struct SampleCache {
    ttl: Duration,
    slot: tokio::sync::Mutex<Option<(Instant, Sample)>>,
}

impl SampleCache {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: tokio::sync::Mutex::new(None),
        }
    }

    /// The cached sample while it is fresh, else the result of `fetch`. The
    /// lock is held across `fetch`, so concurrent callers wait for it and
    /// then reuse its result.
    pub async fn get<F, Fut>(&self, fetch: F) -> Sample
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Sample>,
    {
        let mut slot = self.slot.lock().await;
        if let Some((sampled_at, sample)) = slot.as_ref() {
            if sampled_at.elapsed() < self.ttl {
                return sample.clone();
            }
        }
        let sample = fetch().await;
        *slot = Some((Instant::now(), sample.clone()));
        sample
    }
}

#[derive(Clone)]
struct ScrapeState {
    metrics: Arc<JobMetrics>,
    pool: Pool,
    job_id: Arc<str>,
    samples: Arc<SampleCache>,
}

/// The router the metrics listener serves: the counters and nothing else.
pub fn metrics_router(metrics: Arc<JobMetrics>, pool: Pool, job_id: &str) -> Router {
    Router::new()
        .route(METRICS_PATH, get(scrape))
        .with_state(ScrapeState {
            metrics,
            pool,
            job_id: Arc::from(job_id),
            samples: Arc::new(SampleCache::new(SAMPLE_CACHE)),
        })
}

/// Serve the metrics router until `shutdown` resolves, then give open
/// connections `shutdown_timeout` to drain.
///
/// # Errors
///
/// A serving fault, or connections that outlive the deadline, named by the
/// metrics-serve code.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    shutdown_timeout: Duration,
) -> Result<(), String> {
    serve_with_shutdown_timeout(listener, router, shutdown, shutdown_timeout)
        .await
        .map_err(|end| match end {
            ServeEnd::Serve => "adapter.job.metrics-serve".to_owned(),
            ServeEnd::ShutdownTimeout => "adapter.job.metrics-shutdown-timeout".to_owned(),
        })
}

/// The item counts for a scrape. A failed read is logged and counted when the
/// read happens, so scrapes served from the cache do not count it again.
async fn sampled_items<F, Fut>(
    samples: &SampleCache,
    metrics: &JobMetrics,
    read: F,
) -> Option<[(ItemStatus, u64); 4]>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Sample>,
{
    samples
        .get(|| async {
            let sample = read().await;
            if let Err(cause) = &sample {
                tracing::error!(cause = %cause, "the job item counts could not be read");
                metrics.record_sample_failure();
            }
            sample
        })
        .await
        .ok()
}

async fn scrape(State(state): State<ScrapeState>) -> impl IntoResponse {
    let items = sampled_items(&state.samples, &state.metrics, || async {
        tokio::time::timeout(SAMPLE_DEADLINE, sample_items(&state.pool, &state.job_id))
            .await
            .unwrap_or_else(|_| Err("the item count read timed out".to_owned()))
    })
    .await;
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

    #[tokio::test]
    async fn partial_request_head_cannot_hold_metrics_shutdown_past_the_deadline() {
        use std::io::Write as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback test listener");
        let address = listener.local_addr().expect("the bound address");
        let router = Router::new().route(METRICS_PATH, get(|| async { "ok" }));
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(
            listener,
            router,
            async move {
                let _ = shutdown_rx.await;
            },
            Duration::from_millis(25),
        ));

        let mut partial = std::net::TcpStream::connect(address)
            .expect("a loopback client connects to the metrics listener");
        partial
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: loopback\r\nX-Stalled: ")
            .expect("write an intentionally incomplete request head");
        let barrier = reqwest::get(format!("http://{address}{METRICS_PATH}"))
            .await
            .expect("the accept loop continues past the partial connection");
        assert_eq!(barrier.status(), axum::http::StatusCode::OK);
        barrier.bytes().await.expect("the barrier response drains");

        shutdown.send(()).expect("signal metrics-server shutdown");
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the shutdown bound completes")
            .expect("the metrics server task joins");
        assert!(
            result.is_err_and(|cause| cause.contains("shutdown")),
            "the stalled client is cut off at the deadline"
        );
        drop(partial);
    }

    #[tokio::test]
    async fn concurrent_scrapes_share_one_store_query() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = SampleCache::new(Duration::from_secs(60));
        let queries = AtomicUsize::new(0);
        let fetch = || async {
            queries.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(items())
        };
        let (first, second, third) =
            tokio::join!(cache.get(fetch), cache.get(fetch), cache.get(fetch));
        assert_eq!(first, Ok(items()));
        assert_eq!(second, first);
        assert_eq!(third, first);
        assert_eq!(queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_sample_is_read_again_and_a_failure_is_reused() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = SampleCache::new(Duration::from_millis(30));
        let queries = AtomicUsize::new(0);
        let failing = || async {
            queries.fetch_add(1, Ordering::SeqCst);
            Err("the store is down".to_owned())
        };
        assert!(cache.get(failing).await.is_err());
        assert!(cache.get(failing).await.is_err());
        assert_eq!(queries.load(Ordering::SeqCst), 1, "a failure is reused");
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(cache.get(|| async { Ok(items()) }).await, Ok(items()));
        assert_eq!(cache.get(failing).await, Ok(items()));
        assert_eq!(queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn scrapes_served_from_the_cache_do_not_recount_a_failed_read() {
        let cache = SampleCache::new(Duration::from_secs(60));
        let metrics = JobMetrics::default();
        let failing = || async { Err("the store is down".to_owned()) };
        for _ in 0..3 {
            assert_eq!(sampled_items(&cache, &metrics, failing).await, None);
        }
        let text = metrics.render(None);
        assert!(
            has(&text, "adapter_job_gauge_sample_failures_total 1"),
            "{text}"
        );
    }

    fn has_age_sample(text: &str) -> bool {
        text.lines()
            .any(|line| line.starts_with("adapter_job_last_successful_pass_age_seconds "))
    }

    fn stop(reason: &str) -> StopReason {
        match reason {
            "page-fault" => StopReason::PageFault {
                code: "adapter.job.page-source".to_owned(),
                record: None,
            },
            "destination-stop" => StopReason::DestinationStop {
                code: "destination.unavailable".to_owned(),
            },
            _ => StopReason::RefusalLimit {
                code: "destination.refused".to_owned(),
            },
        }
    }

    #[test]
    fn each_pass_outcome_is_counted_under_its_own_reason() {
        let metrics = JobMetrics::default();
        metrics.record_pass_outcome(Some(&stop("page-fault")));
        metrics.record_pass_outcome(Some(&stop("destination-stop")));
        metrics.record_pass_outcome(Some(&stop("destination-stop")));
        metrics.record_pass_outcome(Some(&stop("refusal-limit")));
        let text = metrics.render(None);
        for line in [
            "adapter_job_pass_failures_total{reason=\"page-fault\"} 1",
            "adapter_job_pass_failures_total{reason=\"destination-stop\"} 2",
            "adapter_job_pass_failures_total{reason=\"refusal-limit\"} 1",
            "adapter_job_pass_failures_total{reason=\"store-unreachable\"} 0",
        ] {
            assert!(has(&text, line), "{line}: {text}");
        }
        assert!(!has_age_sample(&text), "a stopped pass is not a success");
    }

    #[test]
    fn a_standby_replica_holding_no_lease_is_not_a_failure() {
        let metrics = JobMetrics::default();
        metrics.record_pass_outcome(Some(&StopReason::LeaseHeld));
        let text = metrics.render(None);
        assert!(!text.contains("lease-held"), "{text}");
        assert!(
            text.lines()
                .filter(|line| line.starts_with("adapter_job_pass_failures_total{"))
                .all(|line| line.ends_with(" 0")),
            "{text}"
        );
        assert!(!has_age_sample(&text), "a held lease is not a success");
    }

    #[test]
    fn a_settled_pass_resets_the_age() {
        let metrics = JobMetrics::default();
        metrics.record_pass_outcome(None);
        assert!(has(
            &metrics.render(None),
            "adapter_job_last_successful_pass_age_seconds 0"
        ));
    }
}
