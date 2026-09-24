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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{MatchedPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::AuthenticationError;
use crate::store::{DispatchDepth, PostgresStore};

/// Route label used when no route template matched the request.
pub const UNMATCHED_ROUTE: &str = "unmatched";

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";

#[derive(Debug, Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<RequestKey, u64>>,
    refusals: Mutex<BTreeMap<&'static str, u64>>,
    callbacks: Mutex<BTreeMap<&'static str, u64>>,
    attempts: Mutex<BTreeMap<&'static str, u64>>,
    limits: Mutex<BTreeMap<&'static str, u64>>,
    retention: Mutex<BTreeMap<&'static str, u64>>,
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
}

impl LimitKind {
    /// Every limit, in the order the exposition lists them.
    pub const ALL: [Self; 3] = [Self::Rate, Self::Daily, Self::Pacing];

    /// The limit's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rate => "rate",
            Self::Daily => "daily",
            Self::Pacing => "pacing",
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RequestKey {
    route: String,
    method: &'static str,
    status: &'static str,
}

impl Metrics {
    /// Count one answered request under its closed labels.
    pub fn record_request(&self, route: &str, method: &Method, status: StatusCode) {
        let key = RequestKey {
            route: route.to_owned(),
            method: method_label(method),
            status: status_class(status),
        };
        *self
            .requests
            .lock()
            .expect("the metrics registry is never held across a panic")
            .entry(key)
            .or_default() += 1;
    }

    /// Count one authentication refusal by its outcome.
    pub fn record_authentication_refusal(&self, error: AuthenticationError) {
        let reason = match error {
            AuthenticationError::Refused => "refused",
            AuthenticationError::Claims => "claims",
            AuthenticationError::Profile => "profile",
            AuthenticationError::Unavailable => "unavailable",
        };
        *self
            .refusals
            .lock()
            .expect("the metrics registry is never held across a panic")
            .entry(reason)
            .or_default() += 1;
    }

    /// Count one provider callback by its outcome.
    pub fn record_callback(&self, outcome: CallbackOutcome) {
        bump(&self.callbacks, outcome.as_str());
    }

    /// Count one provider attempt by its outcome.
    pub fn record_attempt(&self, outcome: AttemptOutcome) {
        bump(&self.attempts, outcome.as_str());
    }

    /// Count one refusal by the limit that refused.
    pub fn record_limit_refusal(&self, limit: LimitKind) {
        bump(&self.limits, limit.as_str());
    }

    /// Count one retention sweep by its outcome.
    pub fn record_retention_run(&self, run: RetentionRun) {
        bump(&self.retention, run.as_str());
    }

    /// Render the Prometheus text exposition, with the dispatch queue when
    /// it was sampled.
    #[must_use]
    pub fn render(&self, depth: Option<DispatchDepth>) -> String {
        let mut text = String::new();
        text.push_str("# HELP messaging_http_requests_total Answered HTTP requests.\n");
        text.push_str("# TYPE messaging_http_requests_total counter\n");
        for (key, count) in self
            .requests
            .lock()
            .expect("the metrics registry is never held across a panic")
            .iter()
        {
            text.push_str(&format!(
                "messaging_http_requests_total{{route=\"{}\",method=\"{}\",status=\"{}\"}} {count}\n",
                key.route, key.method, key.status
            ));
        }
        text.push_str(
            "# HELP messaging_authentication_refusals_total Bearer credentials refused before \
             a caller was resolved.\n",
        );
        text.push_str("# TYPE messaging_authentication_refusals_total counter\n");
        for (reason, count) in self
            .refusals
            .lock()
            .expect("the metrics registry is never held across a panic")
            .iter()
        {
            text.push_str(&format!(
                "messaging_authentication_refusals_total{{reason=\"{reason}\"}} {count}\n"
            ));
        }
        text.push_str(
            "# HELP messaging_provider_callbacks_total Provider delivery callbacks, by what \
             became of them.\n",
        );
        text.push_str("# TYPE messaging_provider_callbacks_total counter\n");
        closed_counter(
            &mut text,
            &self.callbacks,
            "messaging_provider_callbacks_total",
            "outcome",
            CallbackOutcome::ALL.map(CallbackOutcome::as_str),
        );
        text.push_str(
            "# HELP messaging_provider_attempts_total Provider attempts, by the outcome the \
             attempt history records.\n",
        );
        text.push_str("# TYPE messaging_provider_attempts_total counter\n");
        closed_counter(
            &mut text,
            &self.attempts,
            "messaging_provider_attempts_total",
            "outcome",
            AttemptOutcome::ALL.map(AttemptOutcome::as_str),
        );
        text.push_str(
            "# HELP messaging_limit_refusals_total Submissions and attempts a limit refused, \
             by the limit.\n",
        );
        text.push_str("# TYPE messaging_limit_refusals_total counter\n");
        closed_counter(
            &mut text,
            &self.limits,
            "messaging_limit_refusals_total",
            "limit",
            LimitKind::ALL.map(LimitKind::as_str),
        );
        text.push_str(
            "# HELP messaging_retention_runs_total Retention sweeps this process ran, by \
             outcome.\n",
        );
        text.push_str("# TYPE messaging_retention_runs_total counter\n");
        closed_counter(
            &mut text,
            &self.retention,
            "messaging_retention_runs_total",
            "outcome",
            RetentionRun::ALL.map(RetentionRun::as_str),
        );
        text.push_str(
            "# HELP messaging_dispatch_jobs Messages waiting to be sent, being sent, or held \
             unknown, sampled at scrape.\n",
        );
        text.push_str("# TYPE messaging_dispatch_jobs gauge\n");
        if let Some(depth) = depth {
            for (state, count) in [
                ("pending", depth.pending),
                ("leased", depth.leased),
                ("unknown", depth.unknown),
            ] {
                text.push_str(&format!(
                    "messaging_dispatch_jobs{{state=\"{state}\"}} {count}\n"
                ));
            }
        }
        text
    }
}

fn bump(counter: &Mutex<BTreeMap<&'static str, u64>>, label: &'static str) {
    *counter
        .lock()
        .expect("the metrics registry is never held across a panic")
        .entry(label)
        .or_default() += 1;
}

/// Write one sample per label value, from zero, so every series exists
/// before its first event.
fn closed_counter<const N: usize>(
    text: &mut String,
    counter: &Mutex<BTreeMap<&'static str, u64>>,
    name: &str,
    label: &str,
    values: [&'static str; N],
) {
    let counts = counter
        .lock()
        .expect("the metrics registry is never held across a panic");
    for value in values {
        let count = counts.get(value).copied().unwrap_or_default();
        text.push_str(&format!("{name}{{{label}=\"{value}\"}} {count}\n"));
    }
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
        [(CONTENT_TYPE, METRICS_MEDIA_TYPE)],
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
