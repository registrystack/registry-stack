//! Optional operator-private telemetry. Labels contain no caller or subject values.
use crate::{CompletionBacklog, PostgresStore};
use axum::{extract::State, http::header::CONTENT_TYPE, routing::get, Json, Router};
use registry_platform_metrics::{Exposition, MetricKind, CONTENT_TYPE as METRICS_CONTENT_TYPE};
use serde_json::json;
use std::sync::Arc;
/// One sample of the database: the open requests, open tasks and due tasks,
/// then the completion delivery backlog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Readings {
    review: [i64; 3],
    completions: CompletionBacklog,
}

#[derive(Clone)]
pub(crate) struct MetricsState {
    inner: Arc<MetricsInner>,
}
struct MetricsInner {
    store: PostgresStore,
    package_digest: String,
    readings: tokio::sync::Mutex<Option<(tokio::time::Instant, Option<Readings>)>>,
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
                readings: Default::default(),
            }),
        }
    }
    async fn readings(&self) -> Option<Readings> {
        let mut cached = self.inner.readings.lock().await;
        if let Some((at, value)) = &*cached {
            if at.elapsed() < std::time::Duration::from_secs(5) {
                return *value;
            }
        }
        let read = async {
            let client = match self.inner.store.client().await {
                Ok(client) => client,
                Err(error) => {
                    tracing::warn!(error = %error, "the metrics sample could not get a database connection");
                    return None;
                }
            };
            let row = match client.query_one("SELECT (SELECT count(*) FROM casework_review_requests WHERE lifecycle='reviewing'),(SELECT count(*) FROM casework_review_tasks WHERE state IN('open','claimed')),(SELECT count(*) FROM casework_review_tasks WHERE state IN('open','claimed') AND deadline_at<=now())",&[]).await {
                Ok(row) => row,
                Err(_) => {
                    tracing::warn!("the review counts could not be sampled for the metrics");
                    return None;
                }
            };
            let completions = match self.inner.store.completion_backlog().await {
                Ok(backlog) => backlog,
                Err(error) => {
                    tracing::warn!(error = %error, "the completion backlog could not be sampled for the metrics");
                    return None;
                }
            };
            Some(Readings {
                review: [row.get(0), row.get(1), row.get(2)],
                completions,
            })
        };
        let value = tokio::time::timeout(std::time::Duration::from_secs(5), read)
            .await
            .ok()
            .flatten();
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
    ([(CONTENT_TYPE, METRICS_CONTENT_TYPE)], render(readings))
}
/// The exposition for one scrape: `readings` are the review counts and the
/// completion backlog, or `None` when the database could not be read.
fn render(readings: Option<Readings>) -> String {
    const DECLARATION: &str = "the metric declarations are valid";
    let mut out = Exposition::new();
    out.header("casework_database_up", None, MetricKind::Gauge)
        .expect(DECLARATION);
    out.sample("casework_database_up", &[], u8::from(readings.is_some()))
        .expect(DECLARATION);
    if let Some(readings) = readings {
        for (name, value) in [
            "casework_open_review_requests",
            "casework_open_review_tasks",
            "casework_due_review_tasks",
        ]
        .into_iter()
        .zip(readings.review)
        {
            out.header(name, None, MetricKind::Gauge)
                .expect(DECLARATION);
            out.sample(name, &[], value).expect(DECLARATION);
        }
        let backlog = readings.completions;
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
    out.finish()
}
#[cfg(test)]
mod tests {
    use super::{render, Readings};
    use crate::CompletionBacklog;

    #[test]
    fn the_scrape_is_byte_stable() {
        let readings = Readings {
            review: [4, 9, 2],
            completions: CompletionBacklog {
                pending: 1,
                retrying: 2,
                leased: 0,
                unknown: 0,
                dead_lettered: 3,
                expired: 0,
                oldest_undelivered_seconds: 7200,
            },
        };
        assert_eq!(
            render(Some(readings)),
            "# TYPE casework_database_up gauge\ncasework_database_up 1\n\
             # TYPE casework_open_review_requests gauge\ncasework_open_review_requests 4\n\
             # TYPE casework_open_review_tasks gauge\ncasework_open_review_tasks 9\n\
             # TYPE casework_due_review_tasks gauge\ncasework_due_review_tasks 2\n\
             # HELP casework_completion_deliveries Review completion deliveries not yet delivered, by state, sampled at scrape.\n\
             # TYPE casework_completion_deliveries gauge\n\
             casework_completion_deliveries{state=\"pending\"} 1\n\
             casework_completion_deliveries{state=\"retrying\"} 2\n\
             casework_completion_deliveries{state=\"leased\"} 0\n\
             casework_completion_deliveries{state=\"unknown\"} 0\n\
             casework_completion_deliveries{state=\"dead-lettered\"} 3\n\
             casework_completion_deliveries{state=\"expired\"} 0\n\
             # HELP casework_completion_oldest_undelivered_age_seconds Seconds the oldest undelivered completion delivery has waited, or 0 when none.\n\
             # TYPE casework_completion_oldest_undelivered_age_seconds gauge\n\
             casework_completion_oldest_undelivered_age_seconds 7200\n"
        );
        assert_eq!(
            render(None),
            "# TYPE casework_database_up gauge\ncasework_database_up 0\n"
        );
    }
}
