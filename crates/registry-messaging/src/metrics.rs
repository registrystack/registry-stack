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
}
