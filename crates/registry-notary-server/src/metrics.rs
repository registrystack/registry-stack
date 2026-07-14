// SPDX-License-Identifier: Apache-2.0
//! Low-cardinality Prometheus text metrics for Registry Notary.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::api::EvidenceErrorCodeContext;

#[derive(Debug, Default)]
pub(crate) struct AppMetrics {
    inner: Mutex<MetricsState>,
}

#[derive(Debug, Default)]
struct MetricsState {
    http: BTreeMap<HttpKey, HttpDuration>,
    audit: BTreeMap<OutcomeKey, u64>,
    replay: BTreeMap<ReplayKey, u64>,
    credentials: BTreeMap<CredentialKey, u64>,
    cel_evaluations: BTreeMap<CelEvaluationKey, CountDuration>,
    cel_worker_pools: BTreeMap<CelWorkerStateKey, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HttpKey {
    method: &'static str,
    endpoint_kind: &'static str,
    status_code: u16,
    status_class: &'static str,
    error_code: String,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CelEvaluationKey {
    outcome: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CelWorkerStateKey {
    state: &'static str,
}

#[derive(Debug, Clone, Copy, Default)]
struct CountDuration {
    count: u64,
    duration_ms_total: u64,
}

const HTTP_DURATION_BUCKETS_SECONDS: &[f64] = &[
    0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500, 5.000, 10.000,
];

#[derive(Debug, Clone)]
struct HttpDuration {
    count: u64,
    duration_sum_seconds: f64,
    duration_buckets: Vec<u64>,
}

impl Default for HttpDuration {
    fn default() -> Self {
        Self {
            count: 0,
            duration_sum_seconds: 0.0,
            duration_buckets: vec![0; HTTP_DURATION_BUCKETS_SECONDS.len()],
        }
    }
}

impl AppMetrics {
    pub(crate) fn record_http(
        &self,
        method: &str,
        endpoint_kind: &'static str,
        status: StatusCode,
        error_code: &str,
        duration_seconds: f64,
    ) {
        let key = HttpKey {
            method: normalize_method(method),
            endpoint_kind,
            status_code: status.as_u16(),
            status_class: status_class(status),
            error_code: error_code.to_string(),
        };
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        let value = metrics.http.entry(key).or_default();
        value.count = value.count.saturating_add(1);
        value.duration_sum_seconds += duration_seconds;
        for (index, bucket) in HTTP_DURATION_BUCKETS_SECONDS.iter().enumerate() {
            if duration_seconds <= *bucket {
                value.duration_buckets[index] = value.duration_buckets[index].saturating_add(1);
            }
        }
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

    #[cfg_attr(not(feature = "registry-notary-cel"), allow(dead_code))]
    pub(crate) fn record_cel_evaluation(&self, outcome: &'static str, duration_ms: u64) {
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        let value = metrics
            .cel_evaluations
            .entry(CelEvaluationKey { outcome })
            .or_default();
        value.count = value.count.saturating_add(1);
        value.duration_ms_total = value.duration_ms_total.saturating_add(duration_ms);
    }

    #[cfg_attr(not(feature = "registry-notary-cel"), allow(dead_code))]
    pub(crate) fn set_cel_worker_pool(&self, state: &'static str, value: u64) {
        let mut metrics = self.inner.lock().expect("metrics mutex is healthy");
        metrics
            .cel_worker_pools
            .insert(CelWorkerStateKey { state }, value);
    }

    fn render(&self) -> String {
        let metrics = self.inner.lock().expect("metrics mutex is healthy");
        let mut body = String::new();
        body.push_str("# TYPE registry_notary_http_requests_total counter\n");
        body.push_str("# TYPE registry_notary_http_request_duration_seconds histogram\n");
        for (key, value) in &metrics.http {
            body.push_str(&format!(
                "registry_notary_http_requests_total{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\"}} {}\n",
                escape_metric_label(key.method),
                escape_metric_label(key.endpoint_kind),
                key.status_code,
                escape_metric_label(key.status_class),
                escape_metric_label(&key.error_code),
                value.count
            ));
            for (index, bucket) in HTTP_DURATION_BUCKETS_SECONDS.iter().enumerate() {
                body.push_str(&format!(
                    "registry_notary_http_request_duration_seconds_bucket{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\",le=\"{:.3}\"}} {}\n",
                    escape_metric_label(key.method),
                    escape_metric_label(key.endpoint_kind),
                    key.status_code,
                    escape_metric_label(key.status_class),
                    escape_metric_label(&key.error_code),
                    bucket,
                    value.duration_buckets[index]
                ));
            }
            body.push_str(&format!(
                "registry_notary_http_request_duration_seconds_bucket{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\",le=\"+Inf\"}} {}\n",
                escape_metric_label(key.method),
                escape_metric_label(key.endpoint_kind),
                key.status_code,
                escape_metric_label(key.status_class),
                escape_metric_label(&key.error_code),
                value.count
            ));
            body.push_str(&format!(
                "registry_notary_http_request_duration_seconds_sum{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\"}} {:.6}\n",
                escape_metric_label(key.method),
                escape_metric_label(key.endpoint_kind),
                key.status_code,
                escape_metric_label(key.status_class),
                escape_metric_label(&key.error_code),
                value.duration_sum_seconds
            ));
            body.push_str(&format!(
                "registry_notary_http_request_duration_seconds_count{{method=\"{}\",endpoint_kind=\"{}\",status_code=\"{}\",status_class=\"{}\",error_code=\"{}\"}} {}\n",
                escape_metric_label(key.method),
                escape_metric_label(key.endpoint_kind),
                key.status_code,
                escape_metric_label(key.status_class),
                escape_metric_label(&key.error_code),
                value.count
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
        body.push_str("# TYPE registry_notary_cel_evaluations_total counter\n");
        body.push_str("# TYPE registry_notary_cel_evaluation_duration_ms_total counter\n");
        for (key, value) in &metrics.cel_evaluations {
            body.push_str(&format!(
                "registry_notary_cel_evaluations_total{{outcome=\"{}\"}} {}\n",
                key.outcome, value.count
            ));
            body.push_str(&format!(
                "registry_notary_cel_evaluation_duration_ms_total{{outcome=\"{}\"}} {}\n",
                key.outcome, value.duration_ms_total
            ));
        }
        body.push_str("# TYPE registry_notary_cel_worker_pool gauge\n");
        for (key, value) in &metrics.cel_worker_pools {
            body.push_str(&format!(
                "registry_notary_cel_worker_pool{{state=\"{}\"}} {}\n",
                key.state, value
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
        .map(|matched| matched.as_str().to_string());
    let path = request.uri().path().to_string();
    let started_at = Instant::now();
    let response = next.run(request).await;
    let error_code = response
        .extensions()
        .get::<EvidenceErrorCodeContext>()
        .map(|context| context.0.as_str())
        .unwrap_or("none");
    metrics.record_http(
        method,
        route
            .as_deref()
            .map(endpoint_kind_from_route)
            .unwrap_or_else(|| endpoint_kind_from_path(&path)),
        response.status(),
        error_code,
        started_at.elapsed().as_secs_f64(),
    );
    response
}

fn endpoint_kind_from_route(route: &str) -> &'static str {
    match route {
        "/healthz" => "health",
        "/ready" => "ready",
        "/metrics" | "/admin/v1/capabilities" | "/admin/v1/posture" | "/admin/v1/reload" => "admin",
        "/openapi.json" | "/docs" | "/docs/scalar.js" => "openapi",
        "/.well-known/evidence-service"
        | "/.well-known/evidence/jwks.json"
        | "/.well-known/openid-credential-issuer" => "well_known",
        "/.well-known/vct/{*vct_path}" | "/credentials/{*vct_path}" => "credential_metadata",
        "/oid4vci/credential-offer"
        | "/oid4vci/offer/start"
        | "/oid4vci/offer/callback"
        | "/oid4vci/token"
        | "/oid4vci/nonce"
        | "/oid4vci/credential" => "oid4vci",
        "/v1/claims" | "/v1/claims/{claim_id}" | "/v1/formats" => "catalog",
        "/v1/evaluations" | "/v1/batch-evaluations" | "/v1/evaluations/{evaluation_id}/render" => {
            "evaluation"
        }
        "/v1/credentials" | "/v1/credentials/{credential_id}/status" => "credential",
        "/federation/v1/evaluations" => "federation",
        _ => "other",
    }
}

fn endpoint_kind_from_path(path: &str) -> &'static str {
    if path == "/healthz" {
        "health"
    } else if path == "/ready" {
        "ready"
    } else if path == "/metrics" || path.starts_with("/admin/") {
        "admin"
    } else if path == "/openapi.json" || path.starts_with("/docs") {
        "openapi"
    } else if path.starts_with("/.well-known/") {
        "well_known"
    } else if path.starts_with("/oid4vci/") {
        "oid4vci"
    } else if path.starts_with("/credentials/") || path.starts_with("/.well-known/vct/") {
        "credential_metadata"
    } else if path.starts_with("/v1/credentials") {
        "credential"
    } else if path.starts_with("/v1/evaluations") || path == "/v1/batch-evaluations" {
        "evaluation"
    } else if path.starts_with("/v1/claims") || path == "/v1/formats" {
        "catalog"
    } else if path.starts_with("/federation/") {
        "federation"
    } else {
        "other"
    }
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

        metrics.record_http(
            "BREW1",
            "health",
            StatusCode::METHOD_NOT_ALLOWED,
            "none",
            0.001,
        );
        metrics.record_http(
            "BREW2",
            "health",
            StatusCode::METHOD_NOT_ALLOWED,
            "none",
            0.002,
        );
        metrics.record_http("GET", "health", StatusCode::OK, "none", 0.003);

        let rendered = metrics.render();
        assert!(rendered.contains(
            "registry_notary_http_requests_total{method=\"OTHER\",endpoint_kind=\"health\",status_code=\"405\",status_class=\"4xx\",error_code=\"none\"} 2"
        ));
        assert!(rendered.contains("# TYPE registry_notary_http_request_duration_seconds histogram"));
        assert!(rendered.contains(
            "registry_notary_http_request_duration_seconds_bucket{method=\"OTHER\",endpoint_kind=\"health\",status_code=\"405\",status_class=\"4xx\",error_code=\"none\",le=\"0.005\"} 2"
        ));
        assert!(rendered.contains(
            "registry_notary_http_request_duration_seconds_bucket{method=\"OTHER\",endpoint_kind=\"health\",status_code=\"405\",status_class=\"4xx\",error_code=\"none\",le=\"+Inf\"} 2"
        ));
        assert!(rendered.contains(
            "registry_notary_http_request_duration_seconds_sum{method=\"OTHER\",endpoint_kind=\"health\",status_code=\"405\",status_class=\"4xx\",error_code=\"none\"} 0.003000"
        ));
        assert!(rendered.contains(
            "registry_notary_http_request_duration_seconds_count{method=\"OTHER\",endpoint_kind=\"health\",status_code=\"405\",status_class=\"4xx\",error_code=\"none\"} 2"
        ));
        assert!(rendered.contains(
            "registry_notary_http_requests_total{method=\"GET\",endpoint_kind=\"health\",status_code=\"200\",status_class=\"2xx\",error_code=\"none\"} 1"
        ));
        assert!(!rendered.contains("registry_notary_http_request_duration_ms_total"));
        assert!(!rendered.contains("route="));
        assert!(!rendered.contains("BREW1"));
        assert!(!rendered.contains("BREW2"));
    }

    #[test]
    fn cel_metrics_are_low_cardinality_and_do_not_include_policy_text() {
        let metrics = AppMetrics::default();

        metrics.record_cel_evaluation("success", 7);
        metrics.record_cel_evaluation("compile_error", 3);
        metrics.set_cel_worker_pool("max", 2);
        metrics.set_cel_worker_pool("idle", 1);
        metrics.set_cel_worker_pool("replacements_total", 4);
        metrics.set_cel_worker_pool("circuit_open", 1);

        let rendered = metrics.render();
        assert!(rendered.contains("registry_notary_cel_evaluations_total{outcome=\"success\"} 1"));
        assert!(rendered.contains(
            "registry_notary_cel_evaluation_duration_ms_total{outcome=\"compile_error\"} 3"
        ));
        assert!(rendered.contains("registry_notary_cel_worker_pool{state=\"max\"} 2"));
        assert!(
            rendered.contains("registry_notary_cel_worker_pool{state=\"replacements_total\"} 4")
        );
        assert!(rendered.contains("registry_notary_cel_worker_pool{state=\"circuit_open\"} 1"));
        assert!(!rendered.contains("source.age"));
        assert!(!rendered.contains("secret-source-value"));
    }
}
