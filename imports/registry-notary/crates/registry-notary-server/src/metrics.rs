// SPDX-License-Identifier: Apache-2.0
//! Low-cardinality Prometheus text metrics for Registry Notary.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

#[derive(Debug, Default)]
pub(crate) struct AppMetrics {
    inner: Mutex<MetricsState>,
}

#[derive(Debug, Default)]
struct MetricsState {
    http: BTreeMap<HttpKey, CountDuration>,
    source: BTreeMap<SourceKey, CountDuration>,
    source_retries: BTreeMap<ConnectorKey, u64>,
    source_in_flight: BTreeMap<ConnectorKey, u64>,
    audit: BTreeMap<OutcomeKey, u64>,
    replay: BTreeMap<ReplayKey, u64>,
    credentials: BTreeMap<CredentialKey, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HttpKey {
    method: &'static str,
    route: String,
    status_class: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SourceKey {
    connector: &'static str,
    outcome: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ConnectorKey {
    connector: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OutcomeKey {
    outcome: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReplayKey {
    flow: &'static str,
    outcome: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CredentialKey {
    protocol: &'static str,
    outcome: &'static str,
}

#[derive(Debug, Clone, Copy, Default)]
struct CountDuration {
    count: u64,
    duration_ms_total: u64,
}

impl AppMetrics {
    pub(crate) fn record_http(
        &self,
        method: &str,
        route: &str,
        status: StatusCode,
        duration_ms: u64,
    ) {
        let key = HttpKey {
            method: normalize_method(method),
            route: route.to_string(),
            status_class: status_class(status),
        };
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        let value = metrics.http.entry(key).or_default();
        value.count = value.count.saturating_add(1);
        value.duration_ms_total = value.duration_ms_total.saturating_add(duration_ms);
    }

    pub(crate) fn record_source_request(
        &self,
        connector: &'static str,
        outcome: &'static str,
        duration_ms: u64,
    ) {
        let key = SourceKey { connector, outcome };
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        let value = metrics.source.entry(key).or_default();
        value.count = value.count.saturating_add(1);
        value.duration_ms_total = value.duration_ms_total.saturating_add(duration_ms);
    }

    pub(crate) fn record_source_retry(&self, connector: &'static str) {
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        let value = metrics
            .source_retries
            .entry(ConnectorKey { connector })
            .or_default();
        *value = value.saturating_add(1);
    }

    pub(crate) fn set_source_in_flight(&self, connector: &'static str, value: u64) {
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        metrics
            .source_in_flight
            .insert(ConnectorKey { connector }, value);
    }

    pub(crate) fn record_audit_event(&self, outcome: &'static str) {
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        let value = metrics.audit.entry(OutcomeKey { outcome }).or_default();
        *value = value.saturating_add(1);
    }

    pub(crate) fn record_replay(&self, flow: &'static str, outcome: &'static str) {
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        let value = metrics
            .replay
            .entry(ReplayKey { flow, outcome })
            .or_default();
        *value = value.saturating_add(1);
    }

    pub(crate) fn record_credential(&self, protocol: &'static str, outcome: &'static str) {
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        let value = metrics
            .credentials
            .entry(CredentialKey { protocol, outcome })
            .or_default();
        *value = value.saturating_add(1);
    }

    fn render(&self) -> String {
        let metrics = self.inner.lock().expect("metrics mutex is healthy");
        let mut body = String::new();
        body.push_str("# TYPE registry_notary_http_requests_total counter\n");
        body.push_str("# TYPE registry_notary_http_request_duration_ms_total counter\n");
        for (key, value) in &metrics.http {
            body.push_str(&format!(
                "registry_notary_http_requests_total{{method=\"{}\",route=\"{}\",status_class=\"{}\"}} {}\n",
                escape_metric_label(key.method),
                escape_metric_label(&key.route),
                escape_metric_label(key.status_class),
                value.count
            ));
            body.push_str(&format!(
                "registry_notary_http_request_duration_ms_total{{method=\"{}\",route=\"{}\",status_class=\"{}\"}} {}\n",
                escape_metric_label(key.method),
                escape_metric_label(&key.route),
                escape_metric_label(key.status_class),
                value.duration_ms_total
            ));
        }
        body.push_str("# TYPE registry_notary_source_requests_total counter\n");
        body.push_str("# TYPE registry_notary_source_request_duration_ms_total counter\n");
        for (key, value) in &metrics.source {
            body.push_str(&format!(
                "registry_notary_source_requests_total{{connector=\"{}\",outcome=\"{}\"}} {}\n",
                key.connector, key.outcome, value.count
            ));
            body.push_str(&format!(
                "registry_notary_source_request_duration_ms_total{{connector=\"{}\",outcome=\"{}\"}} {}\n",
                key.connector, key.outcome, value.duration_ms_total
            ));
        }
        body.push_str("# TYPE registry_notary_source_retries_total counter\n");
        for (key, value) in &metrics.source_retries {
            body.push_str(&format!(
                "registry_notary_source_retries_total{{connector=\"{}\"}} {}\n",
                key.connector, value
            ));
        }
        body.push_str("# TYPE registry_notary_source_in_flight gauge\n");
        for (key, value) in &metrics.source_in_flight {
            body.push_str(&format!(
                "registry_notary_source_in_flight{{connector=\"{}\"}} {}\n",
                key.connector, value
            ));
        }
        body.push_str("# TYPE registry_notary_audit_events_total counter\n");
        for (key, value) in &metrics.audit {
            body.push_str(&format!(
                "registry_notary_audit_events_total{{outcome=\"{}\"}} {}\n",
                key.outcome, value
            ));
        }
        body.push_str("# TYPE registry_notary_replay_events_total counter\n");
        for (key, value) in &metrics.replay {
            body.push_str(&format!(
                "registry_notary_replay_events_total{{flow=\"{}\",outcome=\"{}\"}} {}\n",
                key.flow, key.outcome, value
            ));
        }
        body.push_str("# TYPE registry_notary_credential_issuance_total counter\n");
        for (key, value) in &metrics.credentials {
            body.push_str(&format!(
                "registry_notary_credential_issuance_total{{protocol=\"{}\",outcome=\"{}\"}} {}\n",
                key.protocol, key.outcome, value
            ));
        }
        body
    }
}

pub(crate) async fn metrics_handler(State(metrics): State<Arc<AppMetrics>>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics.render(),
    )
        .into_response()
}

pub(crate) async fn metrics_middleware(
    State(metrics): State<Arc<AppMetrics>>,
    request: Request,
    next: Next,
) -> Response {
    let method = normalize_method(request.method().as_str());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());
    let started_at = Instant::now();
    let response = next.run(request).await;
    metrics.record_http(
        method,
        &route,
        response.status(),
        started_at.elapsed().as_millis() as u64,
    );
    response
}

fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        6 => "6xx",
        7 => "7xx",
        8 => "8xx",
        9 => "9xx",
        _ => "other",
    }
}

fn normalize_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "CONNECT" => "CONNECT",
        _ => "OTHER",
    }
}

fn escape_metric_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_labels_escape_prometheus_special_characters() {
        assert_eq!(escape_metric_label("a\\b\n\"c"), "a\\\\b\\n\\\"c");
    }

    #[test]
    fn http_method_labels_collapse_unknown_methods() {
        let metrics = AppMetrics::default();

        metrics.record_http("BREW1", "/healthz", StatusCode::METHOD_NOT_ALLOWED, 1);
        metrics.record_http("BREW2", "/healthz", StatusCode::METHOD_NOT_ALLOWED, 2);
        metrics.record_http("GET", "/healthz", StatusCode::OK, 3);

        let rendered = metrics.render();
        assert!(rendered.contains(
            "registry_notary_http_requests_total{method=\"OTHER\",route=\"/healthz\",status_class=\"4xx\"} 2"
        ));
        assert!(rendered.contains(
            "registry_notary_http_request_duration_ms_total{method=\"OTHER\",route=\"/healthz\",status_class=\"4xx\"} 3"
        ));
        assert!(rendered.contains(
            "registry_notary_http_requests_total{method=\"GET\",route=\"/healthz\",status_class=\"2xx\"} 1"
        ));
        assert!(!rendered.contains("BREW1"));
        assert!(!rendered.contains("BREW2"));
    }
}
