// SPDX-License-Identifier: Apache-2.0

//! Operational counters, served only on the operator-private metrics
//! listener.
//!
//! `/metrics` is a route on a separate socket that `metricsListener` names,
//! never on the public listener, so the public contract is unchanged and
//! reaching the counters requires reaching a different, private address.
//!
//! Every label is closed by construction. The route label is the axum route
//! template that matched, or `unmatched`; the method label is a fixed
//! vocabulary; the status label is a coarse class; the refusal label names
//! one authentication outcome. Paths, message identifiers, principals,
//! clients, contacts, and problem details never become labels, so no caller
//! can write text into a series and the series count is bounded by the route
//! table.
//!
//! Authentication refusals are counted here rather than written to the audit
//! journal: a refused credential names no principal to hold accountable, and
//! journaling it would let an unauthenticated caller grow the journal.
//!
//! Provider callbacks are counted by [`CallbackOutcome`] alone. The provider
//! id in a callback path is caller text until it names an activated
//! provider, so it never becomes a label; a callback that verifies but
//! matches no message is counted as `unmatched` and journals nothing.
//!
//! The rest of the set is closed the same way. Provider attempts are counted
//! by the class the attempt history records, limit refusals by the limit
//! that refused, and retention sweeps by whether they erased anything; none
//! names a provider, profile, or message. The dispatch queue is a gauge
//! sampled from the store when the metrics are scraped, counting only the
//! states work waits in: `pending`, `leased`, and `unknown`. When the store
//! cannot be read the gauge has no samples for that scrape, so the series
//! goes stale rather than reporting an empty queue.
//!
//! Every counter is per process and starts from zero at each start; a
//! retention run by `messagingctl` is a separate process and is recorded in
//! the journal, not here.

use std::fmt;
use std::sync::Arc;

use axum::extract::{MatchedPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use registry_platform_metrics::{
    CounterVec, Exposition, LabelSpace, MetricKind, CONTENT_TYPE as METRICS_CONTENT_TYPE,
};

use crate::auth::AuthenticationError;
use crate::store::{DispatchDepth, PostgresStore};

/// Route label used when no route template matched the request.
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// The most request series the registry holds: the route table (ten
/// templates plus `unmatched`) times the method and status vocabularies a
/// route can answer with stays well under it. A request past it is counted
/// as refused, never added.
const REQUEST_SERIES_LIMIT: usize = 512;

/// The most authentication-refusal series: one per [`AuthenticationError`].
const REFUSAL_SERIES_LIMIT: usize = 8;

const DECLARATION: &str = "the metric declarations are valid";

pub struct Metrics {
    requests: CounterVec,
    refusals: CounterVec,
    callbacks: CounterVec,
    attempts: CounterVec,
    limits: CounterVec,
    retention: CounterVec,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests: CounterVec::new(
                "messaging_http_requests_total",
                "Answered HTTP requests.",
                LabelSpace::bounded(&["route", "method", "status"], REQUEST_SERIES_LIMIT)
                    .expect(DECLARATION),
            )
            .expect(DECLARATION),
            refusals: CounterVec::new(
                "messaging_authentication_refusals_total",
                "Bearer credentials refused before a caller was resolved.",
                LabelSpace::bounded(&["reason"], REFUSAL_SERIES_LIMIT).expect(DECLARATION),
            )
            .expect(DECLARATION),
            callbacks: closed_counter(
                "messaging_provider_callbacks_total",
                "Provider delivery callbacks, by what became of them.",
                "outcome",
                CallbackOutcome::ALL.map(CallbackOutcome::as_str),
            ),
            attempts: closed_counter(
                "messaging_provider_attempts_total",
                "Provider attempts, by the outcome the attempt history records.",
                "outcome",
                AttemptOutcome::ALL.map(AttemptOutcome::as_str),
            ),
            limits: closed_counter(
                "messaging_limit_refusals_total",
                "Submissions, attempts, and provider callbacks a limit refused, by the limit.",
                "limit",
                LimitKind::ALL.map(LimitKind::as_str),
            ),
            retention: closed_counter(
                "messaging_retention_runs_total",
                "Retention sweeps this process ran, by outcome.",
                "outcome",
                RetentionRun::ALL.map(RetentionRun::as_str),
            ),
        }
    }
}

/// What one provider attempt came to, the closed label of
/// `messaging_provider_attempts_total`. The values are the outcome classes
/// the attempt history records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    Accepted,
    Transient,
    Permanent,
    MaybeSent,
}

impl AttemptOutcome {
    /// Every outcome, in the order the exposition lists them.
    pub const ALL: [Self; 4] = [
        Self::Accepted,
        Self::Transient,
        Self::Permanent,
        Self::MaybeSent,
    ];

    /// The outcome's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::MaybeSent => "maybe-sent",
        }
    }
}

/// The limit that refused, the closed label of
/// `messaging_limit_refusals_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    /// An access profile's request rate refused a submission.
    Rate,
    /// An access profile's daily limit refused a submission.
    Daily,
    /// A provider's send rate had no slot for an attempt in its allowance.
    Pacing,
    /// The callback rate refused a provider callback before it was
    /// verified.
    Callback,
}

impl LimitKind {
    /// Every limit, in the order the exposition lists them.
    pub const ALL: [Self; 4] = [Self::Rate, Self::Daily, Self::Pacing, Self::Callback];

    /// The limit's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rate => "rate",
            Self::Daily => "daily",
            Self::Pacing => "pacing",
            Self::Callback => "callback",
        }
    }
}

/// What one retention sweep came to, the closed label of
/// `messaging_retention_runs_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionRun {
    /// The sweep erased at least one payload, record, or receipt.
    Erased,
    /// The sweep found nothing due.
    Idle,
    /// The sweep did not complete; the next one retries it.
    Failed,
}

impl RetentionRun {
    /// Every outcome, in the order the exposition lists them.
    pub const ALL: [Self; 3] = [Self::Erased, Self::Idle, Self::Failed];

    /// The outcome's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Erased => "erased",
            Self::Idle => "idle",
            Self::Failed => "failed",
        }
    }
}

/// What became of one provider callback, the closed label of
/// `messaging_provider_callbacks_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackOutcome {
    /// The path named no receiving provider, or the request did not verify.
    Unverified,
    /// The receipt script could not read the verified callback.
    Unreadable,
    /// The receipt script reported nothing this runtime records.
    Ignored,
    /// The receipt advanced the message's report.
    Applied,
    /// The receipt matched a message and did not advance its report.
    Unchanged,
    /// The receipt's reference names no message of this provider.
    Unmatched,
    /// The receipt's reference names more than one message of this provider.
    Ambiguous,
    /// The callback could not be read or recorded for want of the store or
    /// the receipt script.
    Unavailable,
}

impl CallbackOutcome {
    /// Every outcome, in the order the exposition lists them.
    pub const ALL: [Self; 8] = [
        Self::Unverified,
        Self::Unreadable,
        Self::Ignored,
        Self::Applied,
        Self::Unchanged,
        Self::Unmatched,
        Self::Ambiguous,
        Self::Unavailable,
    ];

    /// The outcome's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Unreadable => "unreadable",
            Self::Ignored => "ignored",
            Self::Applied => "applied",
            Self::Unchanged => "unchanged",
            Self::Unmatched => "unmatched",
            Self::Ambiguous => "ambiguous",
            Self::Unavailable => "unavailable",
        }
    }
}

impl Metrics {
    /// Count one answered request under its closed labels.
    pub fn record_request(&self, route: &str, method: &Method, status: StatusCode) {
        count(
            &self.requests,
            &[route, method_label(method), status_class(status)],
        );
    }

    /// Count one authentication refusal by its outcome.
    pub fn record_authentication_refusal(&self, error: AuthenticationError) {
        let reason = match error {
            AuthenticationError::Refused => "refused",
            AuthenticationError::Claims => "claims",
            AuthenticationError::Profile => "profile",
            AuthenticationError::Unavailable => "unavailable",
        };
        count(&self.refusals, &[reason]);
    }

    /// Count one provider callback by its outcome.
    pub fn record_callback(&self, outcome: CallbackOutcome) {
        count(&self.callbacks, &[outcome.as_str()]);
    }

    /// Count one provider attempt by its outcome.
    pub fn record_attempt(&self, outcome: AttemptOutcome) {
        count(&self.attempts, &[outcome.as_str()]);
    }

    /// Count one refusal by the limit that refused.
    pub fn record_limit_refusal(&self, limit: LimitKind) {
        count(&self.limits, &[limit.as_str()]);
    }

    /// Count one retention sweep by its outcome.
    pub fn record_retention_run(&self, run: RetentionRun) {
        count(&self.retention, &[run.as_str()]);
    }

    /// Render the Prometheus text exposition, with the dispatch queue when
    /// it was sampled.
    #[must_use]
    pub fn render(&self, depth: Option<DispatchDepth>) -> String {
        let mut out = Exposition::new();
        for counter in [
            &self.requests,
            &self.refusals,
            &self.callbacks,
            &self.attempts,
            &self.limits,
            &self.retention,
        ] {
            counter.write(&mut out).expect(DECLARATION);
        }
        out.header(
            "messaging_dispatch_jobs",
            Some("Messages waiting to be sent, being sent, or held unknown, sampled at scrape."),
            MetricKind::Gauge,
        )
        .expect(DECLARATION);
        if let Some(depth) = depth {
            for (state, count) in [
                ("pending", depth.pending),
                ("leased", depth.leased),
                ("unknown", depth.unknown),
            ] {
                out.sample("messaging_dispatch_jobs", &[("state", state)], count)
                    .expect(DECLARATION);
            }
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

/// A counter family whose every label value is declared, so every series is
/// exposed from zero before its first event.
fn closed_counter<const N: usize>(
    name: &str,
    help: &str,
    label: &'static str,
    values: [&'static str; N],
) -> CounterVec {
    let declared: Vec<[&str; 1]> = values.iter().map(|value| [*value]).collect();
    let declared: Vec<&[&str]> = declared.iter().map(|value| value.as_slice()).collect();
    CounterVec::new(
        name,
        help,
        LabelSpace::closed_zero_filled(&[label], &declared).expect(DECLARATION),
    )
    .expect(DECLARATION)
}

fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

fn status_class(status: StatusCode) -> &'static str {
    if status.is_server_error() {
        "5xx"
    } else if status.is_client_error() {
        "4xx"
    } else {
        "2xx"
    }
}

/// Count every answered request on the public listener under the route
/// template it matched.
pub async fn count_requests(
    State(metrics): State<Arc<Metrics>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or(UNMATCHED_ROUTE, MatchedPath::as_str)
        .to_owned();
    let method = request.method().clone();
    let response = next.run(request).await;
    metrics.record_request(&route, &method, response.status());
    response
}

/// What the metrics listener reads: the counters, and the store the
/// dispatch queue is sampled from.
#[derive(Clone, Debug)]
pub struct MetricsState {
    pub metrics: Arc<Metrics>,
    pub store: Option<PostgresStore>,
}

/// Serve the counters and the sampled dispatch queue on the metrics
/// listener.
pub async fn serve_metrics(State(state): State<MetricsState>) -> Response {
    let depth = match &state.store {
        Some(store) => match store.dispatch_depth().await {
            Ok(depth) => Some(depth),
            Err(error) => {
                tracing::warn!(error = %error, "the Messaging dispatch queue could not be sampled");
                None
            }
        },
        None => None,
    };
    (
        [(CONTENT_TYPE, METRICS_CONTENT_TYPE)],
        state.metrics.render(depth),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_closed() {
        let metrics = Metrics::default();
        metrics.record_request(
            "/v1/messages/{message_id}",
            &Method::GET,
            StatusCode::NOT_FOUND,
        );
        metrics.record_request(
            UNMATCHED_ROUTE,
            &Method::from_bytes(b"BREW").unwrap(),
            StatusCode::OK,
        );
        metrics.record_authentication_refusal(AuthenticationError::Unavailable);
        let text = metrics.render(None);
        assert!(text.contains(
            "messaging_http_requests_total{route=\"/v1/messages/{message_id}\",method=\"GET\",status=\"4xx\"} 1"
        ));
        assert!(text.contains("method=\"other\""));
        assert!(text.contains("messaging_authentication_refusals_total{reason=\"unavailable\"} 1"));
    }

    /// The full scrape for a representative state, byte for byte.
    #[test]
    fn the_scrape_is_byte_stable() {
        let metrics = Metrics::default();
        metrics.record_request(
            "/v1/messages/{message_id}",
            &Method::GET,
            StatusCode::NOT_FOUND,
        );
        metrics.record_request(
            UNMATCHED_ROUTE,
            &Method::from_bytes(b"BREW").unwrap(),
            StatusCode::OK,
        );
        metrics.record_authentication_refusal(AuthenticationError::Unavailable);
        metrics.record_authentication_refusal(AuthenticationError::Claims);
        metrics.record_callback(CallbackOutcome::Unmatched);
        metrics.record_callback(CallbackOutcome::Unmatched);
        metrics.record_attempt(AttemptOutcome::MaybeSent);
        metrics.record_limit_refusal(LimitKind::Daily);
        metrics.record_retention_run(RetentionRun::Failed);
        let head = "\
# HELP messaging_http_requests_total Answered HTTP requests.
# TYPE messaging_http_requests_total counter
messaging_http_requests_total{route=\"/v1/messages/{message_id}\",method=\"GET\",status=\"4xx\"} 1
messaging_http_requests_total{route=\"unmatched\",method=\"other\",status=\"2xx\"} 1
# HELP messaging_authentication_refusals_total Bearer credentials refused before a caller was resolved.
# TYPE messaging_authentication_refusals_total counter
messaging_authentication_refusals_total{reason=\"claims\"} 1
messaging_authentication_refusals_total{reason=\"unavailable\"} 1
# HELP messaging_provider_callbacks_total Provider delivery callbacks, by what became of them.
# TYPE messaging_provider_callbacks_total counter
messaging_provider_callbacks_total{outcome=\"unverified\"} 0
messaging_provider_callbacks_total{outcome=\"unreadable\"} 0
messaging_provider_callbacks_total{outcome=\"ignored\"} 0
messaging_provider_callbacks_total{outcome=\"applied\"} 0
messaging_provider_callbacks_total{outcome=\"unchanged\"} 0
messaging_provider_callbacks_total{outcome=\"unmatched\"} 2
messaging_provider_callbacks_total{outcome=\"ambiguous\"} 0
messaging_provider_callbacks_total{outcome=\"unavailable\"} 0
# HELP messaging_provider_attempts_total Provider attempts, by the outcome the attempt history records.
# TYPE messaging_provider_attempts_total counter
messaging_provider_attempts_total{outcome=\"accepted\"} 0
messaging_provider_attempts_total{outcome=\"transient\"} 0
messaging_provider_attempts_total{outcome=\"permanent\"} 0
messaging_provider_attempts_total{outcome=\"maybe-sent\"} 1
# HELP messaging_limit_refusals_total Submissions, attempts, and provider callbacks a limit refused, by the limit.
# TYPE messaging_limit_refusals_total counter
messaging_limit_refusals_total{limit=\"rate\"} 0
messaging_limit_refusals_total{limit=\"daily\"} 1
messaging_limit_refusals_total{limit=\"pacing\"} 0
messaging_limit_refusals_total{limit=\"callback\"} 0
# HELP messaging_retention_runs_total Retention sweeps this process ran, by outcome.
# TYPE messaging_retention_runs_total counter
messaging_retention_runs_total{outcome=\"erased\"} 0
messaging_retention_runs_total{outcome=\"idle\"} 0
messaging_retention_runs_total{outcome=\"failed\"} 1
# HELP messaging_dispatch_jobs Messages waiting to be sent, being sent, or held unknown, sampled at scrape.
# TYPE messaging_dispatch_jobs gauge
";
        assert_eq!(metrics.render(None), head);
        assert_eq!(
            metrics.render(Some(DispatchDepth {
                pending: 3,
                leased: 1,
                unknown: 2,
            })),
            format!(
                "{head}messaging_dispatch_jobs{{state=\"pending\"}} 3\nmessaging_dispatch_jobs{{state=\"leased\"}} 1\nmessaging_dispatch_jobs{{state=\"unknown\"}} 2\n"
            )
        );
    }

    #[test]
    fn every_callback_outcome_is_exposed_from_zero() {
        let metrics = Metrics::default();
        metrics.record_callback(CallbackOutcome::Unmatched);
        metrics.record_callback(CallbackOutcome::Unmatched);
        let text = metrics.render(None);
        assert!(text.contains("messaging_provider_callbacks_total{outcome=\"unmatched\"} 2"));
        for outcome in CallbackOutcome::ALL {
            assert!(text.contains(&format!(
                "messaging_provider_callbacks_total{{outcome=\"{}\"}}",
                outcome.as_str()
            )));
        }
        assert!(text.contains("messaging_provider_callbacks_total{outcome=\"applied\"} 0"));
    }

    #[test]
    fn every_attempt_limit_and_retention_outcome_is_exposed_from_zero() {
        let metrics = Metrics::default();
        metrics.record_attempt(AttemptOutcome::MaybeSent);
        metrics.record_limit_refusal(LimitKind::Daily);
        metrics.record_limit_refusal(LimitKind::Daily);
        metrics.record_retention_run(RetentionRun::Failed);
        let text = metrics.render(None);
        assert!(text.contains("messaging_provider_attempts_total{outcome=\"maybe-sent\"} 1"));
        assert!(text.contains("messaging_provider_attempts_total{outcome=\"accepted\"} 0"));
        assert!(text.contains("messaging_limit_refusals_total{limit=\"daily\"} 2"));
        assert!(text.contains("messaging_limit_refusals_total{limit=\"pacing\"} 0"));
        assert!(text.contains("messaging_retention_runs_total{outcome=\"failed\"} 1"));
        assert!(text.contains("messaging_retention_runs_total{outcome=\"erased\"} 0"));
        for outcome in AttemptOutcome::ALL {
            assert!(text.contains(&format!(
                "messaging_provider_attempts_total{{outcome=\"{}\"}}",
                outcome.as_str()
            )));
        }
        for limit in LimitKind::ALL {
            assert!(text.contains(&format!(
                "messaging_limit_refusals_total{{limit=\"{}\"}}",
                limit.as_str()
            )));
        }
        for run in RetentionRun::ALL {
            assert!(text.contains(&format!(
                "messaging_retention_runs_total{{outcome=\"{}\"}}",
                run.as_str()
            )));
        }
    }

    #[test]
    fn the_dispatch_queue_is_exposed_only_when_it_was_sampled() {
        let metrics = Metrics::default();
        let unsampled = metrics.render(None);
        assert!(unsampled.contains("# TYPE messaging_dispatch_jobs gauge"));
        assert!(!unsampled.contains("messaging_dispatch_jobs{"));
        let sampled = metrics.render(Some(DispatchDepth {
            pending: 3,
            leased: 1,
            unknown: 2,
        }));
        assert!(sampled.contains("messaging_dispatch_jobs{state=\"pending\"} 3"));
        assert!(sampled.contains("messaging_dispatch_jobs{state=\"leased\"} 1"));
        assert!(sampled.contains("messaging_dispatch_jobs{state=\"unknown\"} 2"));
    }
}
