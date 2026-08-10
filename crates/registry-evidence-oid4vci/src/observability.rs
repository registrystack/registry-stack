//! Privacy-safe operational telemetry for the wallet-delivery boundary.
//!
//! Every label is selected from a closed vocabulary in this module. Request
//! paths, issuer identifiers, audiences, credential configuration identifiers,
//! client identifiers, and protocol material are never labels or log fields.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{header::CONTENT_TYPE, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use crate::service::{
    AUTHORIZATION_SERVER_METADATA_PATH, CREDENTIAL_PATH, HEALTH_PATH, ISSUER_METADATA_PATH,
    NONCE_PATH, OFFERS_PATH, READY_PATH, TOKEN_PATH,
};

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";
const DURATION_BUCKETS: [f64; 8] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0, 5.0];
const NO_ERROR: &str = "none";

/// Closed operational outcome vocabulary. Adding a variant is a privacy and
/// cardinality review because every variant becomes a metric series.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Outcome {
    OfferCreated,
    OfferAuthorizationRefused,
    StoreSaturated,
    StoreFault,
    CodeRedeemed,
    CodeClaimRefused,
    TokenClaimed,
    TokenClaimRefused,
    NonceMinted,
    NonceInvalid,
    NonceTampered,
    NonceExpired,
    ProofRefused,
    CredentialIssued,
    EvidenceRefused,
    EvidenceNotAvailable,
    EvidenceUnavailable,
    CleanupExpired,
}

impl Outcome {
    const ALL: [Self; 18] = [
        Self::OfferCreated,
        Self::OfferAuthorizationRefused,
        Self::StoreSaturated,
        Self::StoreFault,
        Self::CodeRedeemed,
        Self::CodeClaimRefused,
        Self::TokenClaimed,
        Self::TokenClaimRefused,
        Self::NonceMinted,
        Self::NonceInvalid,
        Self::NonceTampered,
        Self::NonceExpired,
        Self::ProofRefused,
        Self::CredentialIssued,
        Self::EvidenceRefused,
        Self::EvidenceNotAvailable,
        Self::EvidenceUnavailable,
        Self::CleanupExpired,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::OfferCreated => "offer_created",
            Self::OfferAuthorizationRefused => "offer_authorization_refused",
            Self::StoreSaturated => "store_saturated",
            Self::StoreFault => "store_fault",
            Self::CodeRedeemed => "code_redeemed",
            Self::CodeClaimRefused => "code_claim_refused",
            Self::TokenClaimed => "token_claimed",
            Self::TokenClaimRefused => "token_claim_refused",
            Self::NonceMinted => "nonce_minted",
            Self::NonceInvalid => "nonce_invalid",
            Self::NonceTampered => "nonce_tampered",
            Self::NonceExpired => "nonce_expired",
            Self::ProofRefused => "proof_refused",
            Self::CredentialIssued => "credential_issued",
            Self::EvidenceRefused => "evidence_refused",
            Self::EvidenceNotAvailable => "evidence_not_available",
            Self::EvidenceUnavailable => "evidence_unavailable",
            Self::CleanupExpired => "cleanup_expired",
        }
    }
}

/// Static problem-code marker attached to a response for observation without
/// reparsing or retaining its body.
#[derive(Clone, Copy)]
pub(crate) struct ProblemCode(pub(crate) &'static str);

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct RequestSeriesKey {
    route: &'static str,
    method: &'static str,
    status: &'static str,
    error: &'static str,
}

#[derive(Default)]
struct RequestSeries {
    requests: u64,
    duration_sum: f64,
    buckets: [u64; DURATION_BUCKETS.len()],
}

/// Bounded in-process counters. The registry is created whether or not the
/// listener is enabled so enabling metrics changes observation only, never
/// protocol behavior.
pub(crate) struct Metrics {
    requests: Mutex<BTreeMap<RequestSeriesKey, RequestSeries>>,
    outcomes: Mutex<BTreeMap<Outcome, u64>>,
    store_entries: AtomicUsize,
    store_capacity: usize,
    cleanup_expired: AtomicU64,
}

impl Metrics {
    pub(crate) fn new(store_capacity: usize) -> Self {
        Self {
            requests: Mutex::new(BTreeMap::new()),
            outcomes: Mutex::new(BTreeMap::new()),
            store_entries: AtomicUsize::new(0),
            store_capacity,
            cleanup_expired: AtomicU64::new(0),
        }
    }

    pub(crate) fn record_outcome(&self, outcome: Outcome) {
        let mut outcomes = self
            .outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *outcomes.entry(outcome).or_default() += 1;
    }

    pub(crate) fn record_store_entries(&self, entries: Option<usize>) {
        if let Some(entries) = entries {
            self.store_entries.store(entries, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_cleanup(&self, expired: usize) {
        if expired == 0 {
            return;
        }
        self.cleanup_expired
            .fetch_add(expired as u64, Ordering::Relaxed);
        let mut outcomes = self
            .outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *outcomes.entry(Outcome::CleanupExpired).or_default() += expired as u64;
    }

    fn record_request(
        &self,
        route: &'static str,
        method: &'static str,
        status: &'static str,
        error: &'static str,
        elapsed: Duration,
    ) {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let series = requests.entry(RequestSeriesKey {
            route,
            method,
            status,
            error,
        });
        let series = series.or_default();
        series.requests += 1;
        let seconds = elapsed.as_secs_f64();
        series.duration_sum += seconds;
        for (count, bound) in series.buckets.iter_mut().zip(DURATION_BUCKETS) {
            if seconds <= bound {
                *count += 1;
            }
        }
    }

    pub(crate) fn render(&self) -> String {
        let requests = self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let outcomes = self
            .outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut body = String::new();
        body.push_str("# HELP evidence_oid4vci_http_requests_total Delivery requests by closed outcome class.\n");
        body.push_str("# TYPE evidence_oid4vci_http_requests_total counter\n");
        for (key, series) in requests.iter() {
            body.push_str(&format!(
                "evidence_oid4vci_http_requests_total{{{}}} {}\n",
                request_labels(key),
                series.requests
            ));
        }
        body.push_str(
            "# HELP evidence_oid4vci_http_request_duration_seconds Delivery request latency.\n",
        );
        body.push_str("# TYPE evidence_oid4vci_http_request_duration_seconds histogram\n");
        for (key, series) in requests.iter() {
            for (count, bound) in series.buckets.iter().zip(DURATION_BUCKETS) {
                body.push_str(&format!(
                    "evidence_oid4vci_http_request_duration_seconds_bucket{{{},le=\"{bound}\"}} {count}\n",
                    request_labels(key)
                ));
            }
            body.push_str(&format!(
                "evidence_oid4vci_http_request_duration_seconds_bucket{{{},le=\"+Inf\"}} {}\n",
                request_labels(key),
                series.requests
            ));
            body.push_str(&format!(
                "evidence_oid4vci_http_request_duration_seconds_sum{{{}}} {}\n",
                request_labels(key),
                series.duration_sum
            ));
            body.push_str(&format!(
                "evidence_oid4vci_http_request_duration_seconds_count{{{}}} {}\n",
                request_labels(key),
                series.requests
            ));
        }
        body.push_str("# HELP evidence_oid4vci_outcomes_total Closed protocol and upstream outcome classes.\n");
        body.push_str("# TYPE evidence_oid4vci_outcomes_total counter\n");
        for outcome in Outcome::ALL {
            body.push_str(&format!(
                "evidence_oid4vci_outcomes_total{{outcome=\"{}\"}} {}\n",
                outcome.label(),
                outcomes.get(&outcome).copied().unwrap_or(0)
            ));
        }
        body.push_str("# HELP evidence_oid4vci_store_entries Entries in the fullest independently bounded offer, ledger, or token keyspace.\n");
        body.push_str("# TYPE evidence_oid4vci_store_entries gauge\n");
        body.push_str(&format!(
            "evidence_oid4vci_store_entries {}\n",
            self.store_entries.load(Ordering::Relaxed)
        ));
        body.push_str("# HELP evidence_oid4vci_store_capacity Refusal threshold for each independently bounded offer, ledger, or token keyspace.\n");
        body.push_str("# TYPE evidence_oid4vci_store_capacity gauge\n");
        body.push_str(&format!(
            "evidence_oid4vci_store_capacity {}\n",
            self.store_capacity
        ));
        body.push_str("# HELP evidence_oid4vci_cleanup_expired_total Expired in-memory entries released by cleanup.\n");
        body.push_str("# TYPE evidence_oid4vci_cleanup_expired_total counter\n");
        body.push_str(&format!(
            "evidence_oid4vci_cleanup_expired_total {}\n",
            self.cleanup_expired.load(Ordering::Relaxed)
        ));
        body
    }
}

fn request_labels(key: &RequestSeriesKey) -> String {
    format!(
        "route=\"{}\",method=\"{}\",status=\"{}\",error=\"{}\"",
        key.route, key.method, key.status, key.error
    )
}

pub(crate) async fn observe(
    State(metrics): State<Arc<Metrics>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let route = normalized_route(&request);
    let method = normalized_method(request.method());
    let started = Instant::now();
    let response = next.run(request).await;
    let status = normalized_status(response.status());
    let error = response
        .extensions()
        .get::<ProblemCode>()
        .map_or(NO_ERROR, |problem| normalized_problem(problem.0));
    metrics.record_request(route, method, status, error, started.elapsed());
    log_request(route, method, status, error);
    response
}

fn log_request(
    route: &'static str,
    method: &'static str,
    status: &'static str,
    error: &'static str,
) {
    if (route == HEALTH_PATH || route == READY_PATH) && status == "success" {
        tracing::debug!(
            target: "registry_evidence_oid4vci::request",
            route,
            method,
            status,
            error,
            "delivery probe served"
        );
    } else {
        tracing::info!(
            target: "registry_evidence_oid4vci::request",
            route,
            method,
            status,
            error,
            "delivery request served"
        );
    }
}

fn normalized_route(request: &Request<Body>) -> &'static str {
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    match path {
        Some(HEALTH_PATH) => HEALTH_PATH,
        Some(READY_PATH) => READY_PATH,
        Some(ISSUER_METADATA_PATH) => ISSUER_METADATA_PATH,
        Some(AUTHORIZATION_SERVER_METADATA_PATH) => AUTHORIZATION_SERVER_METADATA_PATH,
        Some(OFFERS_PATH) => OFFERS_PATH,
        Some(TOKEN_PATH) => TOKEN_PATH,
        Some(NONCE_PATH) => NONCE_PATH,
        Some(CREDENTIAL_PATH) => CREDENTIAL_PATH,
        _ => "unmatched",
    }
}

fn normalized_method(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

fn normalized_status(status: StatusCode) -> &'static str {
    if status.is_server_error() {
        "server_error"
    } else if status.is_client_error() {
        "client_error"
    } else {
        "success"
    }
}

fn normalized_problem(problem: &str) -> &'static str {
    match problem {
        "invalid_request" => "invalid_request",
        "invalid_token" => "invalid_token",
        "unsupported_grant_type" => "unsupported_grant_type",
        "invalid_grant" => "invalid_grant",
        "invalid_credential_request" => "invalid_credential_request",
        "credential_request_denied" => "credential_request_denied",
        "invalid_proof" => "invalid_proof",
        "invalid_nonce" => "invalid_nonce",
        "temporarily_unavailable" => "temporarily_unavailable",
        "server_error" => "server_error",
        _ => "other",
    }
}

pub(crate) fn metrics_app(metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .fallback(metrics_route_absent)
        .with_state(metrics)
}

async fn render_metrics(State(metrics): State<Arc<Metrics>>) -> Response {
    let mut response = (StatusCode::OK, metrics.render()).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(METRICS_MEDIA_TYPE));
    response
}

async fn metrics_route_absent() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[derive(Clone, Default)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for LogBuffer {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn rendered_metrics_use_only_closed_labels_and_never_render_canaries() {
        let metrics = Metrics::new(256);
        metrics.record_request(
            "unmatched",
            "other",
            "client_error",
            "other",
            Duration::from_millis(20),
        );
        metrics.record_outcome(Outcome::NonceTampered);
        metrics.record_store_entries(Some(7));
        metrics.record_store_entries(None);
        let rendered = metrics.render();
        for canary in [
            "https://issuer.private.example",
            "https://audience.private.example",
            "holder-key-canary",
            "selector-canary",
            "access-token-canary",
            "nonce-canary",
        ] {
            assert!(!rendered.contains(canary), "metrics rendered {canary}");
        }
        assert!(rendered.contains("outcome=\"nonce_tampered\"} 1"));
        assert!(rendered.contains("outcome=\"store_fault\"} 0"));
        assert!(rendered.contains("evidence_oid4vci_store_entries 7"));
        assert!(rendered.contains("evidence_oid4vci_store_capacity 256"));
    }

    #[test]
    fn operational_request_logs_do_not_render_request_or_deployment_canaries() {
        let buffer = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(buffer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_request(CREDENTIAL_PATH, "POST", "client_error", "invalid_nonce");
        });
        let rendered = String::from_utf8(buffer.0.lock().expect("log buffer lock").clone())
            .expect("logs are UTF-8");
        assert!(rendered.contains("route=\"/credential\""));
        for canary in [
            "https://issuer.private.example",
            "https://audience.private.example",
            "client-canary",
            "configuration-canary",
            "holder-key-canary",
            "selector-canary",
            "access-token-canary",
            "nonce-canary",
        ] {
            assert!(!rendered.contains(canary), "logs rendered {canary}");
        }
    }

    #[test]
    fn successful_probes_log_at_debug_while_probe_failures_stay_visible() {
        let buffer = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(buffer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_request(HEALTH_PATH, "GET", "success", NO_ERROR);
            log_request(READY_PATH, "GET", "server_error", "server_error");
        });
        let rendered = String::from_utf8(buffer.0.lock().expect("log buffer lock").clone())
            .expect("logs are UTF-8");
        assert!(rendered.contains("DEBUG"), "logs: {rendered}");
        assert!(
            rendered.contains("delivery probe served"),
            "logs: {rendered}"
        );
        assert!(rendered.contains(" INFO "), "logs: {rendered}");
        assert!(
            rendered.contains("delivery request served"),
            "logs: {rendered}"
        );
        assert_eq!(
            normalized_problem("credential_request_denied"),
            "credential_request_denied"
        );
    }

    #[tokio::test]
    async fn the_metrics_listener_serves_only_metrics() {
        let server = axum_test::TestServer::new(metrics_app(Arc::new(Metrics::new(256))));
        server.get("/metrics").await.assert_status_ok();
        server
            .get(ISSUER_METADATA_PATH)
            .await
            .assert_status_not_found();
    }
}
