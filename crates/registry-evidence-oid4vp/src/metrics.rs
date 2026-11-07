//! Operational counters, served only on the operator-private metrics listener.
//!
//! Every label value comes from the closed [`Event`] vocabulary. Policy
//! identifiers, principals, references, request ids, and paths are never
//! labels, so no caller can write text into a series.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use registry_platform_metrics::{
    CounterVec, Exposition, LabelSpace, MetricKind, MetricsError, CONTENT_TYPE as METRICS_TYPE,
};

use crate::session::SessionStore;

/// The only route the metrics listener serves.
pub const METRICS_PATH: &str = "/metrics";

/// What happened, the closed label of `evidence_oid4vp_events_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    SessionCreated,
    SessionRefusedAuthentication,
    SessionRefusedPolicy,
    SessionRefusedRate,
    SessionRefusedCapacity,
    SessionRefusedUnavailable,
    StatusRead,
    StatusNotFound,
    RequestServed,
    RequestNotFound,
    RequestRefusedRate,
    RequestFailed,
    ResponseAccepted,
    ResponseRefused,
    ResponseRefusedRate,
    ResponseRefusedCapacity,
    ResponseUnavailable,
    WalletError,
    ReadDelivered,
    ReadNotFound,
    ReadPending,
    ReadFailed,
    ReadRefusedAuthentication,
    ReadRefusedRate,
    ReadUnavailable,
}

impl Event {
    const ALL: [Self; 25] = [
        Self::SessionCreated,
        Self::SessionRefusedAuthentication,
        Self::SessionRefusedPolicy,
        Self::SessionRefusedRate,
        Self::SessionRefusedCapacity,
        Self::SessionRefusedUnavailable,
        Self::StatusRead,
        Self::StatusNotFound,
        Self::RequestServed,
        Self::RequestNotFound,
        Self::RequestRefusedRate,
        Self::RequestFailed,
        Self::ResponseAccepted,
        Self::ResponseRefused,
        Self::ResponseRefusedRate,
        Self::ResponseRefusedCapacity,
        Self::ResponseUnavailable,
        Self::WalletError,
        Self::ReadDelivered,
        Self::ReadNotFound,
        Self::ReadPending,
        Self::ReadFailed,
        Self::ReadRefusedAuthentication,
        Self::ReadRefusedRate,
        Self::ReadUnavailable,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::SessionCreated => "session-created",
            Self::SessionRefusedAuthentication => "session-refused-authentication",
            Self::SessionRefusedPolicy => "session-refused-policy",
            Self::SessionRefusedRate => "session-refused-rate",
            Self::SessionRefusedCapacity => "session-refused-capacity",
            Self::SessionRefusedUnavailable => "session-refused-unavailable",
            Self::StatusRead => "status-read",
            Self::StatusNotFound => "status-not-found",
            Self::RequestServed => "request-served",
            Self::RequestNotFound => "request-not-found",
            Self::RequestRefusedRate => "request-refused-rate",
            Self::RequestFailed => "request-failed",
            Self::ResponseAccepted => "response-accepted",
            Self::ResponseRefused => "response-refused",
            Self::ResponseRefusedRate => "response-refused-rate",
            Self::ResponseRefusedCapacity => "response-refused-capacity",
            Self::ResponseUnavailable => "response-unavailable",
            Self::WalletError => "wallet-error",
            Self::ReadDelivered => "read-delivered",
            Self::ReadNotFound => "read-not-found",
            Self::ReadPending => "read-pending",
            Self::ReadFailed => "read-failed",
            Self::ReadRefusedAuthentication => "read-refused-authentication",
            Self::ReadRefusedRate => "read-refused-rate",
            Self::ReadUnavailable => "read-unavailable",
        }
    }
}

/// The service's counters.
pub struct Metrics {
    events: CounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self, MetricsError> {
        let labels: Vec<[&str; 1]> = Event::ALL.iter().map(|event| [event.label()]).collect();
        let declared: Vec<&[&str]> = labels.iter().map(<[&str; 1]>::as_slice).collect();
        Ok(Self {
            events: CounterVec::new(
                "evidence_oid4vp_events_total",
                "Presentation session, request, response, and read events by outcome.",
                LabelSpace::closed_zero_filled(&["event"], &declared)?,
            )?,
        })
    }

    pub fn record(&self, event: Event) {
        if self.events.inc(&[event.label()]).is_err() {
            tracing::error!("a metric event was refused by its closed label space");
        }
    }

    #[must_use]
    pub fn count(&self, event: Event) -> u64 {
        self.events.get(&[event.label()]).unwrap_or(0)
    }

    /// The exposition text, with the live session gauge sampled from `store`.
    pub fn render(&self, store: &SessionStore) -> Result<String, MetricsError> {
        let mut out = Exposition::new();
        self.events.write(&mut out)?;
        out.header(
            "evidence_oid4vp_sessions",
            Some("Presentation sessions held in memory, expired ones not yet cleaned up included."),
            MetricKind::Gauge,
        )?;
        out.sample("evidence_oid4vp_sessions", &[], store.len() as u64)?;
        Ok(out.finish())
    }
}

#[derive(Clone)]
struct MetricsState {
    metrics: Arc<Metrics>,
    store: Arc<SessionStore>,
}

/// The router the private metrics listener serves.
pub fn metrics_app(metrics: Arc<Metrics>, store: Arc<SessionStore>) -> Router {
    Router::new()
        .route(METRICS_PATH, get(scrape))
        .with_state(MetricsState { metrics, store })
}

async fn scrape(State(state): State<MetricsState>) -> Response {
    match state.metrics.render(&state.store) {
        Ok(text) => ([(CONTENT_TYPE, METRICS_TYPE)], text).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
