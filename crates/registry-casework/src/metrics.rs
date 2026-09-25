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
//! package this process serves, whether its audit publisher is keeping up,
//! and, from the Casework database, each configured source's reconciliation
//! health and the audit outbox backlog. The only label values are the
//! configured source identifiers, the build version, and the package digest,
//! so no caller, record, or request value can become a series.

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

use crate::service::AuditPublisherHealth;
use crate::store::{PostgresStore, SourceReconciliationHealth, StoreError};

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";

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
    async fn audit_outbox_pending(&self) -> Result<i64, StoreError>;
}

#[async_trait]
impl MetricsReadings for PostgresStore {
    async fn reconciliation_health(
        &self,
        source_ids: &[String],
    ) -> Result<Vec<SourceReconciliationHealth>, StoreError> {
        PostgresStore::reconciliation_health(self, source_ids).await
    }

    async fn audit_outbox_pending(&self) -> Result<i64, StoreError> {
        PostgresStore::audit_outbox_pending(self).await
    }
}

struct MetricsInner {
    store: Arc<dyn MetricsReadings>,
    source_ids: Vec<String>,
    package_digest: Option<String>,
    audit_health: AuditPublisherHealth,
}

impl MetricsState {
    pub(crate) fn new(
        store: Arc<dyn MetricsReadings>,
        source_ids: Vec<String>,
        package_digest: Option<String>,
        audit_health: AuditPublisherHealth,
    ) -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                store,
                source_ids,
                package_digest,
                audit_health,
            }),
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
    let database = match inner.store.reconciliation_health(&inner.source_ids).await {
        Ok(health) => match inner.store.audit_outbox_pending().await {
            Ok(pending) => Some((health, pending)),
            Err(error) => {
                tracing::warn!(error = %error, "Casework metrics could not read the audit outbox");
                None
            }
        },
        Err(error) => {
            tracing::warn!(error = %error, "Casework metrics could not read reconciliation health");
            None
        }
    };
    let body = render(
        registry_platform_buildinfo::DISPLAY_VERSION,
        inner.package_digest.as_deref(),
        inner.audit_health.is_ready(),
        inner.audit_health.is_leader(),
        database
            .as_ref()
            .map(|(health, pending)| (health.as_slice(), *pending)),
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
    audit_publisher_ready: bool,
    audit_publisher_leader: bool,
    database: Option<(&[SourceReconciliationHealth], i64)>,
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
        "casework_audit_publisher_up",
        "Whether the audit publisher's last pass appended every due record to the audit journal.",
    );
    let _ = writeln!(
        out,
        "casework_audit_publisher_up {}",
        u8::from(audit_publisher_ready)
    );
    gauge(
        &mut out,
        "casework_audit_publisher_leader",
        "Whether this runtime holds the audit publication lease and is the one appending to the audit journal.",
    );
    let _ = writeln!(
        out,
        "casework_audit_publisher_leader {}",
        u8::from(audit_publisher_leader)
    );
    gauge(
        &mut out,
        "casework_database_up",
        "Whether this scrape could read the Casework database.",
    );
    let _ = writeln!(out, "casework_database_up {}", u8::from(database.is_some()));
    let Some((health, pending)) = database else {
        return out;
    };
    gauge(
        &mut out,
        "casework_audit_outbox_pending",
        "Audit records committed to the database and not yet appended to the audit journal.",
    );
    let _ = writeln!(out, "casework_audit_outbox_pending {pending}");
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
    fn a_scrape_reports_build_backlog_and_reconciliation_lag() {
        let now = Utc.with_ymd_and_hms(2026, 9, 25, 12, 0, 0).unwrap();
        let health = [
            source("permits", 0, Some(now - chrono::Duration::seconds(90))),
            source("licences", 4, None),
        ];
        let rendered = render(
            "1.2.3",
            Some("sha256:abc"),
            true,
            true,
            Some((&health, 7)),
            now,
        );
        for line in [
            "casework_build_info{version=\"1.2.3\",package_digest=\"sha256:abc\"} 1",
            "casework_audit_publisher_up 1",
            "casework_audit_publisher_leader 1",
            "casework_database_up 1",
            "casework_audit_outbox_pending 7",
            "casework_source_reconciliation_consecutive_failures{source_id=\"permits\"} 0",
            "casework_source_reconciliation_consecutive_failures{source_id=\"licences\"} 4",
            "casework_source_reconciliation_last_success_age_seconds{source_id=\"permits\"} 90",
            "# TYPE casework_audit_outbox_pending gauge",
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
            false,
            false,
            None,
            Utc.with_ymd_and_hms(2026, 9, 25, 12, 0, 0).unwrap(),
        );
        assert!(rendered.contains("casework_database_up 0\n"));
        assert!(rendered.contains("casework_audit_publisher_up 0\n"));
        assert!(rendered.contains("casework_audit_publisher_leader 0\n"));
        assert!(rendered.contains("package_digest=\"\"} 1\n"));
        assert!(!rendered.contains("casework_audit_outbox_pending"));
        assert!(!rendered.contains("casework_source_reconciliation"));
    }

    struct FakeReadings {
        available: bool,
    }

    #[async_trait]
    impl MetricsReadings for FakeReadings {
        async fn reconciliation_health(
            &self,
            source_ids: &[String],
        ) -> Result<Vec<SourceReconciliationHealth>, StoreError> {
            if !self.available {
                return Err(StoreError::Configuration);
            }
            Ok(source_ids.iter().map(|id| source(id, 2, None)).collect())
        }

        async fn audit_outbox_pending(&self) -> Result<i64, StoreError> {
            Ok(5)
        }
    }

    async fn get(available: bool, path: &str) -> (axum::http::StatusCode, Option<String>, String) {
        use tower::ServiceExt as _;
        let state = MetricsState::new(
            Arc::new(FakeReadings { available }),
            vec!["permits".to_owned()],
            Some("sha256:abc".to_owned()),
            AuditPublisherHealth::default(),
        );
        let response = metrics_router(state)
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
        assert!(body.contains("casework_audit_outbox_pending 5\n"), "{body}");
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

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
