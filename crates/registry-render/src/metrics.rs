//! Operational series, served only on the operator-private metrics listener.
//!
//! `/metrics` is a route on a separate socket that `metricsListener` names,
//! never on the public listener, so the document API is unchanged and
//! reaching the series requires reaching a different, private address.
//!
//! Every label is closed by construction. `operation` is `render` or `seal`,
//! `result` is a coarse status class, and `seal` is a seal id the operator
//! wrote in the runtime file, so the set is bounded by that file. Document
//! data, caller identities, request paths and problem details never become
//! labels.
//!
//! The seal expiry gauge is computed from each loaded certificate chain when
//! the metrics are scraped. It reads no database and calls no key provider.

use axum::http::StatusCode;
use registry_platform_metrics::{CounterVec, Exposition, LabelSpace, MetricKind};
use time::OffsetDateTime;

use crate::seal::Seals;

/// The path the metrics listener serves.
pub const METRICS_PATH: &str = "/metrics";

const DECLARATION: &str = "the metric declarations are valid";

/// The operations that produce a document: the render route and the seal
/// route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Render,
    Seal,
}

impl Operation {
    const ALL: [Self; 2] = [Self::Render, Self::Seal];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Render => "render",
            Self::Seal => "seal",
        }
    }
}

/// How a call to a document operation ended, by the status it answered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    /// A 2xx answer: the document was produced.
    Ok,
    /// A 4xx answer: the call was refused, including authentication and
    /// validation refusals.
    Refused,
    /// A 5xx answer: the runtime could not do the work, an audit write
    /// failure or an unavailable seal included.
    Failed,
}

impl Outcome {
    const ALL: [Self; 3] = [Self::Ok, Self::Refused, Self::Failed];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }

    fn of(status: StatusCode) -> Self {
        if status.is_server_error() {
            Self::Failed
        } else if status.is_client_error() {
            Self::Refused
        } else {
            Self::Ok
        }
    }
}

pub struct Metrics {
    documents: CounterVec,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let mut declared: Vec<[&str; 2]> = Vec::new();
        for operation in Operation::ALL {
            for outcome in Outcome::ALL {
                declared.push([operation.as_str(), outcome.as_str()]);
            }
        }
        let declared: Vec<&[&str]> = declared.iter().map(|row| row.as_slice()).collect();
        Self {
            documents: CounterVec::new(
                "render_documents_total",
                "Calls to the render and seal routes, by operation and result.",
                LabelSpace::closed_zero_filled(&["operation", "result"], &declared)
                    .expect(DECLARATION),
            )
            .expect(DECLARATION),
        }
    }
}

impl Metrics {
    /// Count one answered call to a document operation under its status
    /// class.
    pub fn record_document(&self, operation: Operation, status: StatusCode) {
        if let Err(error) = self
            .documents
            .inc(&[operation.as_str(), Outcome::of(status).as_str()])
        {
            tracing::warn!(error = %error, "a metric series was refused");
        }
    }

    /// Render the Prometheus text exposition: the counters, the audit write
    /// failures the audit has counted, and the seal certificate lifetimes at
    /// `now`.
    #[must_use]
    pub fn render(&self, audit_write_failures: u64, seals: &Seals, now: OffsetDateTime) -> String {
        let mut out = Exposition::new();
        self.documents.write(&mut out).expect(DECLARATION);
        out.header(
            "render_audit_write_failures_total",
            Some("Audit entries that could not be written."),
            MetricKind::Counter,
        )
        .expect(DECLARATION);
        out.sample(
            "render_audit_write_failures_total",
            &[],
            audit_write_failures,
        )
        .expect(DECLARATION);
        out.header(
            "render_seal_certificate_expiry_seconds",
            Some("Seconds until the seal certificate stops being valid, negative once it has."),
            MetricKind::Gauge,
        )
        .expect(DECLARATION);
        for (id, seal) in seals {
            out.sample(
                "render_seal_certificate_expiry_seconds",
                &[("seal", id.as_str())],
                seal.seconds_until_expiry(now),
            )
            .expect(DECLARATION);
        }
        out.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_and_result_is_exposed_from_zero() {
        let text = Metrics::default().render(0, &Seals::new(), OffsetDateTime::UNIX_EPOCH);
        for operation in ["render", "seal"] {
            for result in ["ok", "refused", "failed"] {
                assert!(
                    text.contains(&format!(
                        "render_documents_total{{operation=\"{operation}\",result=\"{result}\"}} 0"
                    )),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn a_call_is_counted_under_its_status_class() {
        let metrics = Metrics::default();
        metrics.record_document(Operation::Render, StatusCode::OK);
        metrics.record_document(Operation::Render, StatusCode::UNAUTHORIZED);
        metrics.record_document(Operation::Seal, StatusCode::SERVICE_UNAVAILABLE);
        metrics.record_document(Operation::Seal, StatusCode::INTERNAL_SERVER_ERROR);
        let text = metrics.render(0, &Seals::new(), OffsetDateTime::UNIX_EPOCH);
        assert!(text.contains("render_documents_total{operation=\"render\",result=\"ok\"} 1"));
        assert!(text.contains("render_documents_total{operation=\"render\",result=\"refused\"} 1"));
        assert!(text.contains("render_documents_total{operation=\"seal\",result=\"failed\"} 2"));
        assert!(text.contains("render_documents_total{operation=\"seal\",result=\"ok\"} 0"));
    }

    #[test]
    fn audit_write_failures_are_exposed() {
        let text = Metrics::default().render(3, &Seals::new(), OffsetDateTime::UNIX_EPOCH);
        assert!(text.contains("# TYPE render_audit_write_failures_total counter"));
        assert!(
            text.contains("\nrender_audit_write_failures_total 3\n"),
            "{text}"
        );
    }

    #[test]
    fn with_no_seals_the_expiry_gauge_has_no_samples() {
        let text = Metrics::default().render(0, &Seals::new(), OffsetDateTime::UNIX_EPOCH);
        assert!(text.contains("# TYPE render_seal_certificate_expiry_seconds gauge"));
        assert!(!text.contains("render_seal_certificate_expiry_seconds{"));
    }
}
