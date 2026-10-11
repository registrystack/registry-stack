// SPDX-License-Identifier: Apache-2.0
//! Operational counters, served only on the operator-private metrics
//! listener.
//!
//! `/metrics` is a route on a separate socket that `deployment.metricsListener`
//! names, never on the public listener, so the public contract is unchanged
//! and reaching the counters requires reaching a different, private address.
//! Without `metricsListener` nothing is served.
//!
//! Every label is closed by construction: each one is an enum here, and every
//! value is exposed from zero. Run identifiers, idempotency keys, inputs, step
//! outputs, principals, clients, flow ids, step names, authored outcomes and
//! problem details never become labels, so no caller can write text into a
//! series and the series count is fixed by this file.
//!
//! The flow id is not a label either, although an operator declares it and a
//! deployment serves at most sixteen. A per-flow series would need the run's
//! flow at every count, which an attempt whose snapshot does not decode does
//! not have, and it would make the series set depend on the deployment rather
//! than on this file. The audit journal and `coordinatorctl` already answer
//! per-flow questions.
//!
//! A run is counted as admitted when its admission commits; a replayed start
//! key returns the original run and is not counted again. A run is counted as
//! finished each time a committed transaction moves it into a terminal state,
//! by that state, so a failed run an operator later retries or cancels counts
//! again when it ends again. Step attempts are counted by what the worker's
//! attempt came to, local steps (wait, choose, finish) included.
//!
//! Authentication refusals are counted here rather than written to the audit
//! journal: a refused credential names no principal to hold accountable, and
//! journaling it would let an unauthenticated caller grow the journal.
//!
//! The dispatch queue is a gauge sampled from the store when the metrics are
//! scraped, counting only the states work waits in: `pending`, `leased`, and
//! `unknown`. When the store cannot be read the gauge has no samples for that
//! scrape, so the series goes stale rather than reporting an empty queue.
//!
//! Every counter is per process and starts from zero at each start; work done
//! by `coordinatorctl` is a separate process and is recorded in the journal,
//! not here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::store::Store;

/// The only route the metrics listener serves.
pub const METRICS_PATH: &str = "/metrics";

const METRICS_MEDIA_TYPE: &str = "text/plain; version=0.0.4";

#[derive(Debug, Default)]
pub struct Metrics {
    admitted: Mutex<u64>,
    finished: Mutex<BTreeMap<&'static str, u64>>,
    attempts: Mutex<BTreeMap<&'static str, u64>>,
    refusals: Mutex<BTreeMap<&'static str, u64>>,
}

/// The terminal state a run reached, the closed label of
/// `coordinator_runs_finished_total`. The values are the run states the
/// status API reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Finished,
    Failed,
    Cancelled,
    CancelledAfterEffect,
    Expired,
}

impl RunOutcome {
    /// Every terminal state, in the order the exposition lists them.
    pub const ALL: [Self; 5] = [
        Self::Finished,
        Self::Failed,
        Self::Cancelled,
        Self::CancelledAfterEffect,
        Self::Expired,
    ];

    /// The state's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Finished => "finished",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::CancelledAfterEffect => "cancelled-after-effect",
            Self::Expired => "expired",
        }
    }

    /// The terminal state a stored run state names, or `None` for a state
    /// work can still leave (`running`, `attention`, `cancel-requested`).
    #[must_use]
    pub fn from_state(state: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.as_str() == state)
    }
}

/// What one step attempt came to, the closed label of
/// `coordinator_step_attempts_total`: the send outcome the worker handed
/// Dispatch, or `unavailable` when the attempt could not reach the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepAttempt {
    Accepted,
    Transient,
    Permanent,
    MaybeSent,
    Unavailable,
}

impl StepAttempt {
    /// Every outcome, in the order the exposition lists them.
    pub const ALL: [Self; 5] = [
        Self::Accepted,
        Self::Transient,
        Self::Permanent,
        Self::MaybeSent,
        Self::Unavailable,
    ];

    /// The outcome's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::MaybeSent => "maybe-sent",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Why a bearer credential was refused before a caller was resolved, the
/// closed label of `coordinator_authentication_refusals_total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationRefusal {
    /// The credential was missing, malformed, or did not verify.
    Refused,
    /// The credential verified, but no access policy admits its client and
    /// scopes.
    Policy,
    /// The configured verifier could not answer.
    Unavailable,
}

impl AuthenticationRefusal {
    /// Every reason, in the order the exposition lists them.
    pub const ALL: [Self; 3] = [Self::Refused, Self::Policy, Self::Unavailable];

    /// The reason's label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Policy => "policy",
            Self::Unavailable => "unavailable",
        }
    }

    /// The reason an authentication problem code names. Every code other
    /// than a refused policy or an unanswering verifier refused the
    /// credential itself.
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        match code {
            "access.denied" => Self::Policy,
            "access.unavailable" => Self::Unavailable,
            _ => Self::Refused,
        }
    }
}

/// The dispatch jobs waiting in each state work waits in.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchDepth {
    pub pending: i64,
    pub leased: i64,
    pub unknown: i64,
}

impl Metrics {
    /// Count one committed admission.
    pub fn record_run_admitted(&self) {
        *self
            .admitted
            .lock()
            .expect("the metrics registry is never held across a panic") += 1;
    }

    /// Count one committed move of a run into a terminal state.
    pub fn record_run_finished(&self, outcome: RunOutcome) {
        bump(&self.finished, outcome.as_str());
    }

    /// Count one step attempt by its outcome.
    pub fn record_step_attempt(&self, attempt: StepAttempt) {
        bump(&self.attempts, attempt.as_str());
    }

    /// Count one authentication refusal by its reason.
    pub fn record_authentication_refusal(&self, refusal: AuthenticationRefusal) {
        bump(&self.refusals, refusal.as_str());
    }

    /// Render the Prometheus text exposition, with the dispatch queue when
    /// it was sampled.
    #[must_use]
    pub fn render(&self, depth: Option<DispatchDepth>) -> String {
        let mut text = String::new();
        text.push_str("# HELP coordinator_runs_admitted_total Runs whose admission committed.\n");
        text.push_str("# TYPE coordinator_runs_admitted_total counter\n");
        text.push_str(&format!(
            "coordinator_runs_admitted_total {}\n",
            *self
                .admitted
                .lock()
                .expect("the metrics registry is never held across a panic")
        ));
        text.push_str(
            "# HELP coordinator_runs_finished_total Committed moves of a run into a terminal \
             state, by that state.\n",
        );
        text.push_str("# TYPE coordinator_runs_finished_total counter\n");
        closed_counter(
            &mut text,
            &self.finished,
            "coordinator_runs_finished_total",
            "state",
            RunOutcome::ALL.map(RunOutcome::as_str),
        );
        text.push_str(
            "# HELP coordinator_step_attempts_total Step attempts the worker made, by what \
             each came to.\n",
        );
        text.push_str("# TYPE coordinator_step_attempts_total counter\n");
        closed_counter(
            &mut text,
            &self.attempts,
            "coordinator_step_attempts_total",
            "outcome",
            StepAttempt::ALL.map(StepAttempt::as_str),
        );
        text.push_str(
            "# HELP coordinator_authentication_refusals_total Bearer credentials refused \
             before a caller was resolved.\n",
        );
        text.push_str("# TYPE coordinator_authentication_refusals_total counter\n");
        closed_counter(
            &mut text,
            &self.refusals,
            "coordinator_authentication_refusals_total",
            "reason",
            AuthenticationRefusal::ALL.map(AuthenticationRefusal::as_str),
        );
        text.push_str(
            "# HELP coordinator_dispatch_jobs Steps waiting to run, running, or held unknown, \
             sampled at scrape.\n",
        );
        text.push_str("# TYPE coordinator_dispatch_jobs gauge\n");
        if let Some(depth) = depth {
            for (state, count) in [
                ("pending", depth.pending),
                ("leased", depth.leased),
                ("unknown", depth.unknown),
            ] {
                text.push_str(&format!(
                    "coordinator_dispatch_jobs{{state=\"{state}\"}} {count}\n"
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

/// What the metrics listener reads: the store the counters live in and the
/// dispatch queue is sampled from.
#[derive(Clone)]
pub struct MetricsState {
    pub store: Arc<Store>,
}

/// Serve the counters and the sampled dispatch queue on the metrics
/// listener. A queue that cannot be sampled is logged by its problem code
/// alone and leaves the gauge without samples.
pub async fn serve_metrics(State(state): State<MetricsState>) -> Response {
    let depth = match state.store.dispatch_depth().await {
        Ok(depth) => Some(depth),
        Err(error) => {
            tracing::warn!(
                code = %error.code,
                "the dispatch queue could not be sampled; its gauge has no samples this scrape"
            );
            None
        }
    };
    (
        [
            (CONTENT_TYPE, METRICS_MEDIA_TYPE),
            (CACHE_CONTROL, "no-store"),
        ],
        state.store.metrics().render(depth),
    )
        .into_response()
}

/// The operator-private router the metrics listener serves, with the public
/// listener's body limit and security headers. It has no other route.
pub fn metrics_router(store: Arc<Store>) -> Router {
    Router::new()
        .route(METRICS_PATH, get(serve_metrics))
        .layer(registry_platform_httpsec::request_body_limit(65_536))
        .layer(registry_platform_httpsec::security_headers(
            registry_platform_httpsec::CspBuilder::deny_by_default(),
        ))
        .with_state(MetricsState { store })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every sample line the exposition carries, without its value.
    fn series(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.rsplit_once(' ').expect("a sample has a value").0)
            .collect()
    }

    #[test]
    fn the_label_set_is_closed_and_every_value_is_exposed_from_zero() {
        let metrics = Metrics::default();
        let text = metrics.render(Some(DispatchDepth::default()));
        let mut expected = vec!["coordinator_runs_admitted_total".to_owned()];
        expected.extend(RunOutcome::ALL.map(|o| {
            format!(
                "coordinator_runs_finished_total{{state=\"{}\"}}",
                o.as_str()
            )
        }));
        expected.extend(StepAttempt::ALL.map(|a| {
            format!(
                "coordinator_step_attempts_total{{outcome=\"{}\"}}",
                a.as_str()
            )
        }));
        expected.extend(AuthenticationRefusal::ALL.map(|r| {
            format!(
                "coordinator_authentication_refusals_total{{reason=\"{}\"}}",
                r.as_str()
            )
        }));
        expected.extend(
            ["pending", "leased", "unknown"]
                .map(|state| format!("coordinator_dispatch_jobs{{state=\"{state}\"}}")),
        );
        assert_eq!(series(&text), expected);
        assert!(text
            .lines()
            .filter(|line| !line.starts_with('#'))
            .all(|line| line.ends_with(" 0")));
    }

    #[test]
    fn recording_moves_only_the_named_series() {
        let metrics = Metrics::default();
        metrics.record_run_admitted();
        metrics.record_run_admitted();
        metrics.record_run_finished(RunOutcome::CancelledAfterEffect);
        metrics.record_step_attempt(StepAttempt::MaybeSent);
        metrics.record_step_attempt(StepAttempt::MaybeSent);
        metrics.record_step_attempt(StepAttempt::Unavailable);
        metrics.record_authentication_refusal(AuthenticationRefusal::Policy);
        let before = series(&metrics.render(None)).len();
        let text = metrics.render(None);
        assert_eq!(series(&text).len(), before, "recording adds no series");
        for line in [
            "coordinator_runs_admitted_total 2",
            "coordinator_runs_finished_total{state=\"cancelled-after-effect\"} 1",
            "coordinator_runs_finished_total{state=\"finished\"} 0",
            "coordinator_step_attempts_total{outcome=\"maybe-sent\"} 2",
            "coordinator_step_attempts_total{outcome=\"unavailable\"} 1",
            "coordinator_step_attempts_total{outcome=\"accepted\"} 0",
            "coordinator_authentication_refusals_total{reason=\"policy\"} 1",
            "coordinator_authentication_refusals_total{reason=\"refused\"} 0",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} in {text}");
        }
    }

    #[test]
    fn the_dispatch_queue_is_exposed_only_when_it_was_sampled() {
        let metrics = Metrics::default();
        let unsampled = metrics.render(None);
        assert!(unsampled.contains("# TYPE coordinator_dispatch_jobs gauge"));
        assert!(!unsampled.contains("coordinator_dispatch_jobs{"));
        let sampled = metrics.render(Some(DispatchDepth {
            pending: 3,
            leased: 1,
            unknown: 2,
        }));
        assert!(sampled.contains("coordinator_dispatch_jobs{state=\"pending\"} 3"));
        assert!(sampled.contains("coordinator_dispatch_jobs{state=\"leased\"} 1"));
        assert!(sampled.contains("coordinator_dispatch_jobs{state=\"unknown\"} 2"));
    }

    #[test]
    fn only_terminal_run_states_and_known_refusal_codes_map_to_labels() {
        for state in RunOutcome::ALL {
            assert_eq!(RunOutcome::from_state(state.as_str()), Some(state));
        }
        for state in ["running", "attention", "cancel-requested", "", "FINISHED"] {
            assert_eq!(RunOutcome::from_state(state), None, "{state}");
        }
        assert_eq!(
            AuthenticationRefusal::from_code("access.unauthenticated"),
            AuthenticationRefusal::Refused
        );
        assert_eq!(
            AuthenticationRefusal::from_code("access.denied"),
            AuthenticationRefusal::Policy
        );
        assert_eq!(
            AuthenticationRefusal::from_code("access.unavailable"),
            AuthenticationRefusal::Unavailable
        );
    }
}
