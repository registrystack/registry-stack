// SPDX-License-Identifier: Apache-2.0

//! Opt-in operator telemetry for Registry Casework.
//!
//! The router below only ever serves the operator-private listener started by
//! an explicit `metricsListener` runtime configuration member. It is a
//! separate binding rather than a route on the Casework listener, so the
//! public Casework contract on that listener is unchanged and reaching the
//! telemetry requires reaching a different socket.
//!
//! Every value is read at scrape time: the build and the verified policy
//! package this process serves and, from the Casework database, each
//! configured source's reconciliation health. The database readings are
//! shared by every scrape inside a five-second window and bounded by a read
//! timeout, so the scrape rate never sets the database load. The only label
//! values are the configured source identifiers, the build version, and the
//! package digest, so no caller, record, or request value can become a series.

use std::fmt::Write as _;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::json;

use crate::store::{PostgresStore, SourceReconciliationHealth, StoreError};

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";
/// How long one scrape waits for the database readings before it reports
/// the database down.
const READINGS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// How long one set of database readings answers later scrapes. Scrapes are
/// unauthenticated on the operator-private listener, so this bounds the
/// database work any scrape rate can cause to one reading per window, on one
/// pool connection at a time.
const READINGS_REUSE: std::time::Duration = std::time::Duration::from_secs(5);

/// The database readings one scrape reports, or `None` when they could not
/// be read.
type Readings = Option<Vec<SourceReconciliationHealth>>;

/// What the telemetry listener reports about this process.
#[derive(Clone)]
pub(crate) struct MetricsState {
    inner: Arc<MetricsInner>,
}

/// The database readings one scrape reports.
#[async_trait]
pub(crate) trait MetricsReadings: Send + Sync {
    async fn reconciliation_health(
        &self,
        source_ids: &[String],
    ) -> Result<Vec<SourceReconciliationHealth>, StoreError>;
}

#[async_trait]
impl MetricsReadings for PostgresStore {
    async fn reconciliation_health(
        &self,
        source_ids: &[String],
    ) -> Result<Vec<SourceReconciliationHealth>, StoreError> {
        PostgresStore::reconciliation_health(self, source_ids).await
    }
}

struct MetricsInner {
    store: Arc<dyn MetricsReadings>,
    source_ids: Vec<String>,
    package_digest: Option<String>,
    read_timeout: std::time::Duration,
    /// The last readings and when they were taken. Held across a reading, so
    /// concurrent scrapes wait for the one reading in flight.
    last_readings: tokio::sync::Mutex<Option<(tokio::time::Instant, Readings)>>,
}

impl MetricsState {
    pub(crate) fn new(
        store: Arc<dyn MetricsReadings>,
        source_ids: Vec<String>,
        package_digest: Option<String>,
    ) -> Self {
        Self::with_read_timeout(store, source_ids, package_digest, READINGS_TIMEOUT)
    }

    fn with_read_timeout(
        store: Arc<dyn MetricsReadings>,
        source_ids: Vec<String>,
        package_digest: Option<String>,
        read_timeout: std::time::Duration,
    ) -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                store,
                source_ids,
                package_digest,
                read_timeout,
                last_readings: tokio::sync::Mutex::new(None),
            }),
        }
    }
}

impl MetricsInner {
    /// The database readings for one scrape: the last readings while they
    /// are inside the reuse window, otherwise one fresh reading bounded by
    /// the read timeout.
    async fn readings(&self) -> Readings {
        let mut last = self.last_readings.lock().await;
        if let Some((taken, readings)) = last.as_ref() {
            if taken.elapsed() < READINGS_REUSE {
                return readings.clone();
            }
        }
        let readings = match tokio::time::timeout(self.read_timeout, self.read_database()).await {
            Ok(readings) => readings,
            Err(_) => {
                tracing::warn!(
                    timeout_seconds = self.read_timeout.as_secs_f64(),
                    "Casework metrics timed out reading the database"
                );
                None
            }
        };
        *last = Some((tokio::time::Instant::now(), readings.clone()));
        readings
    }

    async fn read_database(&self) -> Readings {
        match self.store.reconciliation_health(&self.source_ids).await {
            Ok(health) => Some(health),
            Err(error) => {
                tracing::warn!(error = %error, "Casework metrics could not read reconciliation health");
                None
            }
        }
    }
}

/// The operator-private telemetry routes: `/metrics` in the Prometheus text
/// format and `/version` as JSON. Every other path is `404`.
pub(crate) fn metrics_router(state: MetricsState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/version", get(version))
        .with_state(state)
}

async fn version(State(state): State<MetricsState>) -> Response {
    Json(json!({
        "version": registry_platform_buildinfo::DISPLAY_VERSION,
        "packageDigest": state.inner.package_digest,
    }))
    .into_response()
}

async fn metrics(State(state): State<MetricsState>) -> Response {
    let inner = &state.inner;
    let database = inner.readings().await;
    let body = render(
        registry_platform_buildinfo::DISPLAY_VERSION,
        inner.package_digest.as_deref(),
        database.as_deref(),
        Utc::now(),
    );
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(METRICS_MEDIA_TYPE));
    response
}

/// Render one scrape. `database` is `None` when the scrape could not read the
/// Casework database, which `casework_database_up` reports as `0`.
fn render(
    version: &str,
    package_digest: Option<&str>,
    database: Option<&[SourceReconciliationHealth]>,
    now: DateTime<Utc>,
) -> String {
    let mut out = String::new();
    gauge(
        &mut out,
        "casework_build_info",
        "The Casework build and the verified policy package digest this process serves.",
    );
    let _ = writeln!(
        out,
        "casework_build_info{{version=\"{}\",package_digest=\"{}\"}} 1",
        escape(version),
        escape(package_digest.unwrap_or(""))
    );
    gauge(
        &mut out,
        "casework_database_up",
        "Whether this scrape could read the Casework database.",
    );
    let _ = writeln!(out, "casework_database_up {}", u8::from(database.is_some()));
    let Some(health) = database else {
        return out;
    };
    gauge(
        &mut out,
        "casework_source_reconciliation_consecutive_failures",
        "Reconciliation passes that failed in a row for each configured source.",
    );
    for source in health {
        let _ = writeln!(
            out,
            "casework_source_reconciliation_consecutive_failures{{source_id=\"{}\"}} {}",
            escape(&source.source_id),
            source.consecutive_failures
        );
    }
    gauge(
        &mut out,
        "casework_source_reconciliation_last_success_age_seconds",
        "Seconds since each configured source last reconciled successfully; absent until the first success.",
    );
    for source in health {
        if let Some(succeeded) = source.last_succeeded_at {
            let age = (now - succeeded).num_milliseconds().max(0) as f64 / 1000.0;
            let _ = writeln!(
                out,
                "casework_source_reconciliation_last_success_age_seconds{{source_id=\"{}\"}} {age}",
                escape(&source.source_id)
            );
        }
    }
    out
}

fn gauge(out: &mut String, name: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
}

/// Escape a label value as the Prometheus text format requires.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn source(
        id: &str,
        failures: i32,
        succeeded: Option<DateTime<Utc>>,
    ) -> SourceReconciliationHealth {
        SourceReconciliationHealth {
            source_id: id.to_owned(),
            consecutive_failures: failures,
            last_succeeded_at: succeeded,
            last_failed_at: None,
            last_failure: None,
        }
    }

    #[test]
    fn a_scrape_reports_build_and_reconciliation_lag() {
        let now = Utc.with_ymd_and_hms(2026, 9, 25, 12, 0, 0).unwrap();
        let health = [
            source("permits", 0, Some(now - chrono::Duration::seconds(90))),
            source("licences", 4, None),
        ];
        let rendered = render("1.2.3", Some("sha256:abc"), Some(&health), now);
        for line in [
            "casework_build_info{version=\"1.2.3\",package_digest=\"sha256:abc\"} 1",
            "casework_database_up 1",
            "casework_source_reconciliation_consecutive_failures{source_id=\"permits\"} 0",
            "casework_source_reconciliation_consecutive_failures{source_id=\"licences\"} 4",
            "casework_source_reconciliation_last_success_age_seconds{source_id=\"permits\"} 90",
            "# TYPE casework_source_reconciliation_consecutive_failures gauge",
        ] {
            assert!(
                rendered.lines().any(|rendered| rendered == line),
                "missing {line:?} in:\n{rendered}"
            );
        }
        assert!(
            !rendered.contains("last_success_age_seconds{source_id=\"licences\"}"),
            "a source that never succeeded has no age:\n{rendered}"
        );
    }

    #[test]
    fn a_scrape_without_the_database_reports_it_down_and_omits_database_series() {
        let rendered = render(
            "1.2.3",
            None,
            None,
            Utc.with_ymd_and_hms(2026, 9, 25, 12, 0, 0).unwrap(),
        );
        assert!(rendered.contains("casework_database_up 0\n"));
        assert!(rendered.contains("package_digest=\"\"} 1\n"));
        assert!(!rendered.contains("casework_audit_"));
        assert!(!rendered.contains("casework_source_reconciliation"));
    }

    #[derive(Default)]
    struct FakeReadings {
        available: bool,
        stall: bool,
        reads: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl MetricsReadings for FakeReadings {
        async fn reconciliation_health(
            &self,
            source_ids: &[String],
        ) -> Result<Vec<SourceReconciliationHealth>, StoreError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.stall {
                std::future::pending::<()>().await;
            }
            if !self.available {
                return Err(StoreError::Configuration);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Ok(source_ids.iter().map(|id| source(id, 2, None)).collect())
        }
    }

    fn fake_state(readings: Arc<FakeReadings>, read_timeout: std::time::Duration) -> MetricsState {
        MetricsState::with_read_timeout(
            readings,
            vec!["permits".to_owned()],
            Some("sha256:abc".to_owned()),
            read_timeout,
        )
    }

    async fn get(available: bool, path: &str) -> (axum::http::StatusCode, Option<String>, String) {
        let readings = Arc::new(FakeReadings {
            available,
            ..FakeReadings::default()
        });
        get_from(metrics_router(fake_state(readings, READINGS_TIMEOUT)), path).await
    }

    async fn get_from(
        router: Router,
        path: &str,
    ) -> (axum::http::StatusCode, Option<String>, String) {
        use tower::ServiceExt as _;
        let response = router
            .oneshot(
                axum::http::Request::get(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let media = response
            .headers()
            .get(CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_owned());
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, media, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn the_router_serves_metrics_version_and_nothing_else() {
        let (status, media, body) = get(true, "/metrics").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(media.as_deref(), Some(METRICS_MEDIA_TYPE));
        assert!(!body.contains("casework_audit_"), "{body}");
        assert!(body.contains(
            "casework_source_reconciliation_consecutive_failures{source_id=\"permits\"} 2\n"
        ));

        let (status, _, body) = get(false, "/metrics").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(body.contains("casework_database_up 0\n"), "{body}");

        let (status, _, body) = get(true, "/version").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let version: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            version,
            json!({
                "version": registry_platform_buildinfo::DISPLAY_VERSION,
                "packageDigest": "sha256:abc",
            })
        );

        for path in ["/", "/healthz", "/readyz", "/v1/inbox"] {
            assert_eq!(
                get(true, path).await.0,
                axum::http::StatusCode::NOT_FOUND,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn a_scrape_burst_reads_the_database_once() {
        let readings = Arc::new(FakeReadings {
            available: true,
            ..FakeReadings::default()
        });
        let router = metrics_router(fake_state(readings.clone(), READINGS_TIMEOUT));
        let mut scrapes = tokio::task::JoinSet::new();
        for _ in 0..16 {
            scrapes.spawn(get_from(router.clone(), "/metrics"));
        }
        while let Some(scrape) = scrapes.join_next().await {
            let (status, _, body) = scrape.expect("scrape task");
            assert_eq!(status, axum::http::StatusCode::OK);
            assert!(
                body.contains(
                    "casework_source_reconciliation_consecutive_failures{source_id=\"permits\"} 2\n"
                ),
                "{body}"
            );
        }
        let (_, _, body) = get_from(router, "/metrics").await;
        assert!(body.contains("casework_database_up 1\n"), "{body}");
        assert_eq!(
            readings.reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "scrapes inside the reuse window share one database reading"
        );
    }

    #[tokio::test]
    async fn a_stalled_database_reading_reports_the_database_down() {
        let readings = Arc::new(FakeReadings {
            available: true,
            stall: true,
            ..FakeReadings::default()
        });
        let router = metrics_router(fake_state(readings, std::time::Duration::from_millis(50)));
        let (status, _, body) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            get_from(router, "/metrics"),
        )
        .await
        .expect("a stalled reading ends the scrape at the read timeout");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(body.contains("casework_database_up 0\n"), "{body}");
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
