//! Version 1 operational telemetry for the Evidence HTTP boundary.
//!
//! Operational records describe service health and performance only. The
//! reviewed field set is route template, operation identifier, duration,
//! status category, and safe internal error category; request bodies, selector
//! profiles or values, source responses, Supported Values, credentials,
//! tokens, authority grants, and script inputs are outside it. Both the log
//! record and the metric series below are built from that same closed set, so
//! neither can widen without a review of this module.

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
    http::{header::CONTENT_TYPE, HeaderName, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use ulid::Ulid;

use crate::{
    audit::{AuditStorageUsage, EvidenceAuditLog},
    problem::ProblemCode,
    rate_limit::EvidenceRateLimiter,
};

/// Correlation identifier returned to the caller on every response.
///
/// Requests carry no inbound correlation value: the listener contract fixes
/// `trustProxyIdentityHeaders` to false, so a client-supplied identifier would
/// let a caller choose the key its own records are filed under.
pub(crate) const CORRELATION_HEADER: &str = "x-request-id";

/// Target of the per-request operational record.
pub(crate) const REQUEST_LOG_TARGET: &str = "registry_evidence::request";

/// Route label used when no route template matched the request.
const UNMATCHED_ROUTE: &str = "unmatched";

/// Error label used when a response carries no problem code.
const NO_ERROR: &str = "none";

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";

/// Upper bounds, in seconds, of the request duration histogram.
const DURATION_BUCKETS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// The request-scoped correlation identifier, minted once at the boundary.
///
/// Handlers read it from the request extensions rather than minting their own,
/// so the problem body, the audit record, the operational log record, and the
/// response header all name the same operation.
#[derive(Clone)]
pub(crate) struct OperationId(Arc<str>);

impl OperationId {
    fn new() -> Self {
        Self(Ulid::new().to_string().into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Read the boundary-minted identifier for this request.
///
/// The observation layer wraps every route including both fallbacks, so the
/// extension is always present. A handler reached without one would otherwise
/// report an operation that correlates with nothing, so the missing case mints
/// a fresh identifier rather than reporting an empty one.
pub(crate) fn operation_id(extensions: &axum::http::Extensions) -> String {
    extensions.get::<OperationId>().map_or_else(
        || OperationId::new().as_str().to_owned(),
        |id| id.0.to_string(),
    )
}

/// Coarse outcome class. Operational records report the class, never the exact
/// status, because the exact status of a denial is part of the closed public
/// problem contract rather than an operational signal.
#[derive(Clone, Copy)]
enum StatusCategory {
    Success,
    ClientError,
    ServerError,
}

impl StatusCategory {
    fn of(status: StatusCode) -> Self {
        if status.is_server_error() {
            Self::ServerError
        } else if status.is_client_error() {
            Self::ClientError
        } else {
            Self::Success
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ClientError => "client_error",
            Self::ServerError => "server_error",
        }
    }
}

/// Observe one request: mint its identifier, serve it, then publish the
/// reviewed operational fields to the log and the metric registry.
pub(crate) async fn observe(
    State(metrics): State<Arc<Metrics>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let operation = OperationId::new();
    let route = route_template(&request);
    let method = normalized_method(request.method());
    request.extensions_mut().insert(operation.clone());

    let started = Instant::now();
    let mut response = next.run(request).await;
    let elapsed = started.elapsed();

    let status = StatusCategory::of(response.status());
    let error = response
        .extensions()
        .get::<ProblemCode>()
        .map_or(NO_ERROR, |code| code.code());
    response.headers_mut().insert(
        HeaderName::from_static(CORRELATION_HEADER),
        HeaderValue::from_str(operation.as_str())
            .expect("a Crockford base32 identifier is a valid header value"),
    );

    metrics.record(route, method, status, error, elapsed);
    tracing::info!(
        target: REQUEST_LOG_TARGET,
        route,
        operation = operation.as_str(),
        duration_ms = duration_milliseconds(elapsed),
        status = status.as_str(),
        error,
        "evidence request served"
    );
    response
}

/// Resolve the matched route template.
///
/// Only templates the router registered are reported. An unrouted request
/// reports a single fixed label rather than its requested path, which keeps
/// both the log field and the metric label set bounded by the route table and
/// prevents a caller from writing arbitrary text into either.
fn route_template(request: &Request<Body>) -> &'static str {
    let Some(matched) = request.extensions().get::<MatchedPath>() else {
        return UNMATCHED_ROUTE;
    };
    crate::server::ROUTE_TEMPLATES
        .iter()
        .find(|template| **template == matched.as_str())
        .copied()
        .unwrap_or(UNMATCHED_ROUTE)
}

/// Fold the method into the closed set the route table can serve, so an
/// arbitrary request verb cannot create a metric series.
fn normalized_method(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

fn duration_milliseconds(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// In-process request counters and duration histogram.
///
/// Series are keyed only by the closed label set above, so the registry is
/// bounded by the route table regardless of traffic and needs no eviction.
#[derive(Default)]
pub(crate) struct Metrics {
    series: Mutex<BTreeMap<SeriesKey, Series>>,
    /// Current count of pseudonym keys tracked by the rate limiter, for the
    /// `evidence_rate_limiter_tracked_keys` gauge. Unlike `series`, this is
    /// not derived from request content: it is republished on every scrape
    /// from [`crate::rate_limit::EvidenceRateLimiter::tracked_key_count`],
    /// so it stays a single unlabeled series regardless of traffic. See
    /// security invariant V1-I33.
    rate_limiter_tracked_keys: AtomicUsize,
    /// The limiter the metrics scrape handler samples immediately before
    /// each render. `None` for registries that are never served on the
    /// metrics listener (for example, an unrelated middleware test).
    rate_limiter: Option<Arc<EvidenceRateLimiter>>,
    /// Current segment count and total on-disk bytes of the audit chain, for
    /// the `evidence_audit_segments` and `evidence_audit_bytes` gauges.
    /// Rotation never deletes a sealed segment, so nothing in the runtime
    /// bounds this growth; these gauges are how an operator sees the footprint
    /// they own. Republished on every scrape from
    /// [`crate::audit::EvidenceAuditLog::storage_usage`], so they stay two
    /// unlabeled series regardless of traffic. See security invariant V1-I33.
    audit_segments: AtomicUsize,
    audit_bytes: AtomicU64,
    /// The chain the metrics scrape handler samples immediately before each
    /// render. `None` for the same reason as `rate_limiter`.
    audit: Option<Arc<EvidenceAuditLog>>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SeriesKey {
    route: &'static str,
    method: &'static str,
    status: &'static str,
    error: &'static str,
}

#[derive(Default)]
struct Series {
    requests: u64,
    duration_sum: f64,
    bucket_counts: [u64; DURATION_BUCKETS.len()],
}

impl Metrics {
    /// A registry that serves the metrics listener: it samples `rate_limiter`
    /// on every scrape to publish the `evidence_rate_limiter_tracked_keys`
    /// gauge.
    pub(crate) fn new(
        rate_limiter: Arc<EvidenceRateLimiter>,
        audit: Arc<EvidenceAuditLog>,
    ) -> Self {
        Self {
            rate_limiter: Some(rate_limiter),
            audit: Some(audit),
            ..Self::default()
        }
    }

    fn record(
        &self,
        route: &'static str,
        method: &'static str,
        status: StatusCategory,
        error: &'static str,
        elapsed: Duration,
    ) {
        let key = SeriesKey {
            route,
            method,
            status: status.as_str(),
            error,
        };
        let seconds = elapsed.as_secs_f64();
        let mut series = self
            .series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = series.entry(key).or_default();
        entry.requests += 1;
        entry.duration_sum += seconds;
        for (count, bound) in entry.bucket_counts.iter_mut().zip(DURATION_BUCKETS) {
            if seconds <= bound {
                *count += 1;
            }
        }
    }

    /// Publish the rate limiter's current tracked-key count for the next
    /// render.
    ///
    /// The caller reads the live count from the actual limiter (see
    /// [`crate::rate_limit::EvidenceRateLimiter::tracked_key_count`])
    /// immediately before calling this, so the published gauge reflects the
    /// limiter's state at scrape time rather than a value cached from an
    /// earlier request.
    pub(crate) fn record_rate_limiter_tracked_keys(&self, count: usize) {
        self.rate_limiter_tracked_keys
            .store(count, Ordering::Relaxed);
    }

    /// Publish the audit chain's current footprint for the next render.
    ///
    /// Read live from the chain immediately before calling this, for the same
    /// reason as the rate-limiter gauge.
    pub(crate) fn record_audit_storage_usage(&self, usage: AuditStorageUsage) {
        self.audit_segments.store(usage.segments, Ordering::Relaxed);
        self.audit_bytes.store(usage.bytes, Ordering::Relaxed);
    }

    /// Render the Prometheus text exposition of the current registry.
    pub(crate) fn render(&self) -> String {
        let series = self
            .series
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut body = String::new();
        body.push_str(
            "# HELP evidence_http_requests_total Requests served by the Evidence boundary.\n",
        );
        body.push_str("# TYPE evidence_http_requests_total counter\n");
        for (key, value) in series.iter() {
            body.push_str(&format!(
                "evidence_http_requests_total{{{}}} {}\n",
                labels(key),
                value.requests
            ));
        }
        body.push_str(
            "# HELP evidence_http_request_duration_seconds Request duration at the Evidence boundary.\n",
        );
        body.push_str("# TYPE evidence_http_request_duration_seconds histogram\n");
        for (key, value) in series.iter() {
            for (count, bound) in value.bucket_counts.iter().zip(DURATION_BUCKETS) {
                body.push_str(&format!(
                    "evidence_http_request_duration_seconds_bucket{{{},le=\"{bound}\"}} {count}\n",
                    labels(key)
                ));
            }
            body.push_str(&format!(
                "evidence_http_request_duration_seconds_bucket{{{},le=\"+Inf\"}} {}\n",
                labels(key),
                value.requests
            ));
            body.push_str(&format!(
                "evidence_http_request_duration_seconds_sum{{{}}} {}\n",
                labels(key),
                value.duration_sum
            ));
            body.push_str(&format!(
                "evidence_http_request_duration_seconds_count{{{}}} {}\n",
                labels(key),
                value.requests
            ));
        }
        body.push_str(
            "# HELP evidence_rate_limiter_tracked_keys Pseudonym keys currently tracked by the rate limiter.\n",
        );
        body.push_str("# TYPE evidence_rate_limiter_tracked_keys gauge\n");
        body.push_str(&format!(
            "evidence_rate_limiter_tracked_keys {}\n",
            self.rate_limiter_tracked_keys.load(Ordering::Relaxed)
        ));
        body.push_str(
            "# HELP evidence_audit_segments Audit chain segments on disk, sealed and active.\n",
        );
        body.push_str("# TYPE evidence_audit_segments gauge\n");
        body.push_str(&format!(
            "evidence_audit_segments {}\n",
            self.audit_segments.load(Ordering::Relaxed)
        ));
        body.push_str(
            "# HELP evidence_audit_bytes Bytes occupied by the audit chain across every segment.\n",
        );
        body.push_str("# TYPE evidence_audit_bytes gauge\n");
        body.push_str(&format!(
            "evidence_audit_bytes {}\n",
            self.audit_bytes.load(Ordering::Relaxed)
        ));
        body
    }
}

fn labels(key: &SeriesKey) -> String {
    format!(
        "route=\"{}\",method=\"{}\",status=\"{}\",error=\"{}\"",
        key.route, key.method, key.status, key.error
    )
}

/// Build the metrics application.
///
/// It is a separate application on a separate listener: the served counters
/// are operator material, and the public evidence contract does not describe
/// them. Every other path on this listener is unserved rather than delegated
/// back to the evidence routes.
pub(crate) fn metrics_app(metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .fallback(metrics_route_absent)
        .with_state(metrics)
}

async fn render_metrics(State(metrics): State<Arc<Metrics>>) -> Response {
    // Sampled fresh on every scrape rather than cached from request
    // handling, so the gauge reflects the limiter's state at scrape time.
    // A registry built without a limiter (see `Metrics::default`) has
    // nothing to sample and leaves the gauge at its initial zero.
    if let Some(rate_limiter) = &metrics.rate_limiter {
        metrics.record_rate_limiter_tracked_keys(rate_limiter.tracked_key_count().await);
    }
    if let Some(audit) = &metrics.audit {
        // A failed read leaves the previous values standing rather than
        // publishing a zero that would read as an empty chain. It is logged so
        // the staleness is visible instead of silent; the sampled path is
        // operator material and carries no request content.
        match audit.storage_usage().await {
            Ok(usage) => metrics.record_audit_storage_usage(usage),
            Err(error) => tracing::warn!(
                %error,
                "audit storage usage could not be sampled for the capacity gauges"
            ),
        }
    }
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
    use crate::audit::{
        AuditAuthority, AuditDecision, AuditPhase, AuditSubject, AuthorityKind, EvidenceAuditEvent,
        ResponseProtection,
    };

    #[test]
    fn series_labels_stay_bounded_by_the_closed_route_and_method_sets() {
        // An arbitrary verb and an unrouted path must not each create a series.
        let metrics = Metrics::default();
        for method in [
            Method::from_bytes(b"PATCH").expect("a valid method"),
            Method::from_bytes(b"BREW").expect("a valid method"),
        ] {
            metrics.record(
                UNMATCHED_ROUTE,
                normalized_method(&method),
                StatusCategory::ClientError,
                ProblemCode::MalformedRequest.code(),
                Duration::from_millis(1),
            );
        }
        let rendered = metrics.render();
        assert_eq!(
            rendered
                .matches("evidence_http_requests_total{route=\"unmatched\",method=\"other\"")
                .count(),
            1,
            "unrecognized methods collapse onto one series"
        );
        assert!(rendered.contains("status=\"client_error\",error=\"malformed_request\"} 2\n"));
    }

    #[test]
    fn rate_limiter_tracked_keys_gauge_is_a_single_unlabeled_series() {
        let metrics = Metrics::default();
        // Populate unrelated request series first, to prove the gauge does
        // not multiply per label the way the request counter and duration
        // histogram do.
        metrics.record(
            "/health",
            "GET",
            StatusCategory::Success,
            NO_ERROR,
            Duration::from_millis(1),
        );
        metrics.record(
            "/v1/evidence",
            "POST",
            StatusCategory::ClientError,
            ProblemCode::MalformedRequest.code(),
            Duration::from_millis(1),
        );
        metrics.record_rate_limiter_tracked_keys(42);

        let rendered = metrics.render();
        assert_eq!(
            rendered
                .matches("evidence_rate_limiter_tracked_keys")
                .count(),
            3, // HELP line, TYPE line, and exactly one value line
            "the gauge is emitted once regardless of how many request series exist"
        );
        assert!(rendered.contains("\nevidence_rate_limiter_tracked_keys 42\n"));
        assert!(
            !rendered.contains("evidence_rate_limiter_tracked_keys{"),
            "the gauge must carry no labels"
        );
    }

    #[tokio::test]
    async fn rate_limiter_tracked_keys_gauge_reflects_keys_added_through_the_limiter_api() {
        use crate::rate_limit::{EvidenceRateLimiter, RateLimitConfig};

        let limiter = EvidenceRateLimiter::new(RateLimitConfig {
            requests_per_principal_per_minute: 60,
            burst_per_principal: 2,
            failed_selector_attempts_per_principal_authority_per_minute: 2,
        })
        .expect("limiter builds");
        limiter
            .check_request("pseudonym-a")
            .await
            .expect("first principal");
        limiter
            .check_request("pseudonym-b")
            .await
            .expect("second principal");
        limiter
            .record_selector_failure("authority-a")
            .await
            .expect("first failure");

        let metrics = Metrics::default();
        metrics.record_rate_limiter_tracked_keys(limiter.tracked_key_count().await);

        let rendered = metrics.render();
        assert!(rendered.contains("\nevidence_rate_limiter_tracked_keys 3\n"));
    }

    /// The gauge must come from the live limiter at scrape time, not from a
    /// value recorded during earlier request handling. Drive a real limiter
    /// through its public API, wire it into a registry the way production
    /// startup does, and scrape it through the actual `/metrics` router
    /// rather than calling `render` directly.
    #[tokio::test]
    async fn metrics_endpoint_samples_the_live_rate_limiter_at_scrape_time() {
        use crate::rate_limit::{EvidenceRateLimiter, RateLimitConfig};

        let limiter = Arc::new(
            EvidenceRateLimiter::new(RateLimitConfig {
                requests_per_principal_per_minute: 60,
                burst_per_principal: 2,
                failed_selector_attempts_per_principal_authority_per_minute: 2,
            })
            .expect("limiter builds"),
        );
        limiter
            .check_request("pseudonym-a")
            .await
            .expect("first principal");
        limiter
            .check_request("pseudonym-b")
            .await
            .expect("second principal");
        limiter
            .record_selector_failure("authority-a")
            .await
            .expect("first failure");
        let expected = limiter.tracked_key_count().await;
        assert_eq!(
            expected, 3,
            "three distinct tracked keys precede the scrape"
        );

        let (_directory, audit) = scrape_audit_log().await;
        let metrics = Arc::new(Metrics::new(Arc::clone(&limiter), audit));
        let server = axum_test::TestServer::new(metrics_app(metrics));

        let response = server.get("/metrics").await;
        response.assert_status_ok();
        let body = response.text();
        assert!(body.contains(&format!(
            "\nevidence_rate_limiter_tracked_keys {expected}\n"
        )));

        // A key tracked after the registry was built is still visible on the
        // next scrape, proving the value is sampled live rather than cached
        // from construction time.
        limiter
            .check_request("pseudonym-c")
            .await
            .expect("third principal");
        let response = server.get("/metrics").await;
        response.assert_status_ok();
        let body = response.text();
        assert!(body.contains("\nevidence_rate_limiter_tracked_keys 4\n"));
    }

    /// A representative record, so the footprint the gauges report reflects a
    /// real audit line rather than an artificially short one.
    fn scrape_audit_event(log: &EvidenceAuditLog) -> EvidenceAuditEvent {
        EvidenceAuditEvent::new(
            crate::config::AssuranceProfile::EvidenceGrade,
            "01K1EXAMPLE0000000000000000".to_string(),
            AuditPhase::AccessAttempt,
            "urn:example:requirement:v1".to_string(),
            format!("sha256:{}", "0".repeat(64)),
            "casework".to_string(),
            log.pseudonym("requester-v1", "urn:example:trust", b"principal-canary")
                .expect("pseudonym builds"),
            AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
            },
            vec![AuditSubject {
                role: "subject".to_string(),
                selector_profile: "person-v1".to_string(),
                selector_bundle_pseudonym: Some(
                    log.pseudonym("subject-v1", "casework", b"selector-canary")
                        .expect("pseudonym builds"),
                ),
            }],
            ResponseProtection::Signed,
            AuditDecision::Authorized,
            5,
        )
    }

    /// A durable chain over a temporary directory, for tests that need the
    /// metrics registry's live audit sampling. The `TempDir` is returned
    /// because dropping it removes the segments out from under the sink.
    async fn scrape_audit_log() -> (tempfile::TempDir, Arc<EvidenceAuditLog>) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("audit initializes");
        (directory, Arc::new(log))
    }

    #[tokio::test]
    async fn metrics_endpoint_samples_the_live_audit_chain_at_scrape_time() {
        use crate::rate_limit::{EvidenceRateLimiter, RateLimitConfig};

        let limiter = Arc::new(
            EvidenceRateLimiter::new(RateLimitConfig {
                requests_per_principal_per_minute: 10,
                burst_per_principal: 10,
                failed_selector_attempts_per_principal_authority_per_minute: 10,
            })
            .expect("limiter builds"),
        );
        let (_directory, audit) = scrape_audit_log().await;
        let metrics = Arc::new(Metrics::new(limiter, Arc::clone(&audit)));
        let server = axum_test::TestServer::new(metrics_app(metrics));

        let response = server.get("/metrics").await;
        response.assert_status_ok();
        let body = response.text();
        assert!(
            body.contains("\nevidence_audit_segments 1\n"),
            "an untouched chain reports its active segment"
        );
        assert!(
            body.contains("\nevidence_audit_bytes 0\n"),
            "an untouched chain occupies no bytes"
        );
        assert!(
            !body.contains("evidence_audit_segments{") && !body.contains("evidence_audit_bytes{"),
            "the capacity gauges stay unlabeled under V1-I33"
        );

        // Append past the rotation threshold, so the next scrape has to show
        // both a new segment and a larger footprint. This is what proves the
        // gauges are sampled live rather than cached from construction.
        for _ in 0..24 {
            audit
                .append(scrape_audit_event(&audit))
                .await
                .expect("event appends");
        }
        let usage = audit.storage_usage().await.expect("usage reads");
        assert!(
            usage.segments > 1,
            "the appended volume must roll the chain"
        );

        let response = server.get("/metrics").await;
        response.assert_status_ok();
        let body = response.text();
        assert!(body.contains(&format!("\nevidence_audit_segments {}\n", usage.segments)));
        assert!(body.contains(&format!("\nevidence_audit_bytes {}\n", usage.bytes)));
    }

    #[test]
    fn duration_buckets_are_cumulative_and_carry_an_infinite_bound() {
        let metrics = Metrics::default();
        metrics.record(
            "/health",
            "GET",
            StatusCategory::Success,
            NO_ERROR,
            Duration::from_millis(30),
        );
        let rendered = metrics.render();
        assert!(rendered.contains("le=\"0.025\"} 0\n"));
        assert!(rendered.contains("le=\"0.05\"} 1\n"));
        assert!(rendered.contains("le=\"+Inf\"} 1\n"));
        assert!(rendered.contains("evidence_http_request_duration_seconds_count{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\"} 1\n"));
    }
}
