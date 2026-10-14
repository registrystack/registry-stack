//! Optional operator-private telemetry. Labels contain no caller or subject values.
use crate::PostgresStore;
use axum::{extract::State, http::header::CONTENT_TYPE, routing::get, Json, Router};
use serde_json::json;
use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct MetricsState {
    inner: Arc<MetricsInner>,
}
struct MetricsInner {
    store: PostgresStore,
    package_digest: String,
    readings: tokio::sync::Mutex<Option<(tokio::time::Instant, Option<[i64; 3]>)>>,
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
    async fn readings(&self) -> Option<[i64; 3]> {
        let mut cached = self.inner.readings.lock().await;
        if let Some((at, value)) = &*cached {
            if at.elapsed() < std::time::Duration::from_secs(5) {
                return *value;
            }
        }
        let read = async {
            let client = self.inner.store.client().await.ok()?;
            let row=client.query_one("SELECT (SELECT count(*) FROM casework_review_requests WHERE lifecycle='reviewing'),(SELECT count(*) FROM casework_review_tasks WHERE state IN('open','claimed')),(SELECT count(*) FROM casework_review_tasks WHERE state IN('open','claimed') AND deadline_at<=now())",&[]).await.ok()?;
            Some([row.get(0), row.get(1), row.get(2)])
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
    let mut output = format!(
        "# TYPE casework_database_up gauge\ncasework_database_up {}\n",
        u8::from(readings.is_some())
    );
    if let Some(values) = readings {
        for (name, value) in [
            "casework_open_review_requests",
            "casework_open_review_tasks",
            "casework_due_review_tasks",
        ]
        .into_iter()
        .zip(values)
        {
            output.push_str(&format!("# TYPE {name} gauge\n{name} {value}\n"));
        }
    }
    ([(CONTENT_TYPE, "text/plain; version=0.0.4")], output)
}
