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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{MatchedPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::AuthenticationError;

/// Route label used when no route template matched the request.
pub const UNMATCHED_ROUTE: &str = "unmatched";

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";

#[derive(Debug, Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<RequestKey, u64>>,
    refusals: Mutex<BTreeMap<&'static str, u64>>,
    callbacks: Mutex<BTreeMap<&'static str, u64>>,
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
        *self
            .callbacks
            .lock()
            .expect("the metrics registry is never held across a panic")
            .entry(outcome.as_str())
            .or_default() += 1;
    }

    /// Render the Prometheus text exposition.
    #[must_use]
    pub fn render(&self) -> String {
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
        let callbacks = self
            .callbacks
            .lock()
            .expect("the metrics registry is never held across a panic");
        for outcome in CallbackOutcome::ALL {
            let count = callbacks.get(outcome.as_str()).copied().unwrap_or_default();
            text.push_str(&format!(
                "messaging_provider_callbacks_total{{outcome=\"{}\"}} {count}\n",
                outcome.as_str()
            ));
        }
        text
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

/// Serve the counters on the metrics listener.
pub async fn serve_metrics(State(metrics): State<Arc<Metrics>>) -> Response {
    ([(CONTENT_TYPE, METRICS_MEDIA_TYPE)], metrics.render()).into_response()
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
        let text = metrics.render();
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
        let text = metrics.render();
        assert!(text.contains("messaging_provider_callbacks_total{outcome=\"unmatched\"} 2"));
        for outcome in CallbackOutcome::ALL {
            assert!(text.contains(&format!(
                "messaging_provider_callbacks_total{{outcome=\"{}\"}}",
                outcome.as_str()
            )));
        }
        assert!(text.contains("messaging_provider_callbacks_total{outcome=\"applied\"} 0"));
    }
}
