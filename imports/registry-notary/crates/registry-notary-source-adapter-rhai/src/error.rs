// SPDX-License-Identifier: Apache-2.0
//! Error taxonomy for the source-adapter scripting engine.
//!
//! Every variant carries only low-cardinality, non-sensitive information:
//! never the script source, never an upstream response body, never a
//! credential. Each variant maps to a small, stable set of public problem
//! codes via [`SourceScriptError::problem_code`] so callers can surface a
//! consistent error contract without leaking internals.

use std::fmt;

/// Stable, public-facing problem codes.
///
/// These are deliberately coarse: they describe *what the caller should do*,
/// not *what went wrong internally*. Internal detail stays in the variant.
pub mod problem_code {
    /// The source could not be reached or produced no usable result.
    pub const UNAVAILABLE: &str = "source.unavailable";
    /// The source did not respond within the allotted budget.
    pub const TIMEOUT: &str = "source.timeout";
    /// The upstream target rejected the request as unauthorized.
    pub const TARGET_AUTH: &str = "source.target_auth";
    /// The upstream target rate-limited the request.
    pub const TARGET_RATE_LIMIT: &str = "source.target_rate_limit";
}

/// The classes of failure a governed script execution can produce.
///
/// Variants are intentionally free of high-cardinality / sensitive payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceScriptError {
    /// The script failed to compile (syntax / parse error).
    Compile {
        /// Short, non-sensitive reason (no script source).
        reason: String,
    },
    /// The named entrypoint function does not exist in the compiled script.
    Entrypoint {
        /// The entrypoint name that was requested.
        entrypoint: String,
    },
    /// The supplied policy violated a configuration contract (caught at
    /// compile/validation time, before any script runs). Fail-fast for
    /// out-of-contract limits/budgets (e.g. an unlimited operation budget, a
    /// zero concurrency pool, or an HTTP-call cap above the hard maximum).
    Config {
        /// Short, non-sensitive reason describing which contract was violated.
        reason: String,
    },
    /// A value crossing the host boundary had an unacceptable type/shape
    /// (e.g. a non-array return, a function/closure, an opaque handle, or a
    /// value that exceeds the configured size caps).
    Type {
        /// Short, non-sensitive description of the type/shape problem.
        detail: String,
    },
    /// The script raised a runtime error during evaluation.
    Runtime {
        /// Short, non-sensitive reason.
        reason: String,
    },
    /// The script attempted an operation the host denied (e.g. a path that
    /// failed canonicalization, or a disallowed capability).
    HostDenied {
        /// Short, non-sensitive reason.
        reason: String,
    },
    /// The upstream target returned an HTTP error status.
    HttpStatus {
        /// The upstream status code (low cardinality).
        status: u16,
    },
    /// The transport to the upstream target failed (connection/IO/timeout at
    /// the transport layer, distinct from a deadline overrun).
    HttpTransport,
    /// A budget was exhausted (operation count, HTTP-call count, output bytes,
    /// or admission saturation).
    Budget {
        /// Which budget was hit (low cardinality), e.g. `"operations"`,
        /// `"http_calls"`, `"output_bytes"`, `"saturated"`.
        kind: BudgetKind,
    },
    /// The wall-clock deadline elapsed before the script finished.
    Deadline,
    /// The script execution panicked (caught at the blocking boundary).
    Panic,
}

/// Which budget tripped, for [`SourceScriptError::Budget`]. Low cardinality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    /// The Rhai operation budget was exhausted (e.g. an infinite loop).
    Operations,
    /// The maximum number of source calls was exceeded.
    HttpCalls,
    /// The serialized output exceeded the configured byte cap.
    OutputBytes,
    /// No execution permit was available (engine saturated).
    Saturated,
}

impl BudgetKind {
    /// A stable, low-cardinality string tag for the budget kind.
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetKind::Operations => "operations",
            BudgetKind::HttpCalls => "http_calls",
            BudgetKind::OutputBytes => "output_bytes",
            BudgetKind::Saturated => "saturated",
        }
    }
}

impl SourceScriptError {
    /// Map this error to its stable, public problem code.
    ///
    /// The mapping is the public contract; the variant detail is internal.
    pub fn problem_code(&self) -> &'static str {
        match self {
            // A deadline overrun is reported as a timeout.
            SourceScriptError::Deadline => problem_code::TIMEOUT,
            // Authentication / authorization rejections from the upstream.
            SourceScriptError::HttpStatus { status } if *status == 401 || *status == 403 => {
                problem_code::TARGET_AUTH
            }
            // Upstream rate limiting.
            SourceScriptError::HttpStatus { status } if *status == 429 => {
                problem_code::TARGET_RATE_LIMIT
            }
            // Gateway/upstream-timeout statuses are surfaced as a timeout.
            SourceScriptError::HttpStatus { status } if *status == 504 => problem_code::TIMEOUT,
            // Everything else collapses to "unavailable": compile/entrypoint/
            // type/runtime/host-denied/other-status/transport/budget/panic.
            _ => problem_code::UNAVAILABLE,
        }
    }

    /// A short, stable variant tag (useful for metrics / structured logs).
    pub fn kind(&self) -> &'static str {
        match self {
            SourceScriptError::Compile { .. } => "compile",
            SourceScriptError::Entrypoint { .. } => "entrypoint",
            SourceScriptError::Config { .. } => "config",
            SourceScriptError::Type { .. } => "type",
            SourceScriptError::Runtime { .. } => "runtime",
            SourceScriptError::HostDenied { .. } => "host_denied",
            SourceScriptError::HttpStatus { .. } => "http_status",
            SourceScriptError::HttpTransport => "http_transport",
            SourceScriptError::Budget { .. } => "budget",
            SourceScriptError::Deadline => "deadline",
            SourceScriptError::Panic => "panic",
        }
    }
}

impl fmt::Display for SourceScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceScriptError::Compile { reason } => write!(f, "compile error: {reason}"),
            SourceScriptError::Entrypoint { entrypoint } => {
                write!(f, "entrypoint `{entrypoint}` not found")
            }
            SourceScriptError::Config { reason } => write!(f, "config error: {reason}"),
            SourceScriptError::Type { detail } => write!(f, "type error: {detail}"),
            SourceScriptError::Runtime { reason } => write!(f, "runtime error: {reason}"),
            SourceScriptError::HostDenied { reason } => write!(f, "host denied: {reason}"),
            SourceScriptError::HttpStatus { status } => write!(f, "upstream status {status}"),
            SourceScriptError::HttpTransport => write!(f, "upstream transport failure"),
            SourceScriptError::Budget { kind } => write!(f, "budget exhausted: {}", kind.as_str()),
            SourceScriptError::Deadline => write!(f, "deadline exceeded"),
            SourceScriptError::Panic => write!(f, "script panicked"),
        }
    }
}

impl std::error::Error for SourceScriptError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_codes_are_stable_and_coarse() {
        assert_eq!(
            SourceScriptError::Deadline.problem_code(),
            problem_code::TIMEOUT
        );
        assert_eq!(
            SourceScriptError::HttpStatus { status: 401 }.problem_code(),
            problem_code::TARGET_AUTH
        );
        assert_eq!(
            SourceScriptError::HttpStatus { status: 403 }.problem_code(),
            problem_code::TARGET_AUTH
        );
        assert_eq!(
            SourceScriptError::HttpStatus { status: 429 }.problem_code(),
            problem_code::TARGET_RATE_LIMIT
        );
        assert_eq!(
            SourceScriptError::HttpStatus { status: 504 }.problem_code(),
            problem_code::TIMEOUT
        );
        assert_eq!(
            SourceScriptError::HttpStatus { status: 500 }.problem_code(),
            problem_code::UNAVAILABLE
        );
        assert_eq!(
            SourceScriptError::Compile { reason: "x".into() }.problem_code(),
            problem_code::UNAVAILABLE
        );
        assert_eq!(
            SourceScriptError::Budget {
                kind: BudgetKind::Operations
            }
            .problem_code(),
            problem_code::UNAVAILABLE
        );
        // A config error is a fail-fast, "unavailable"-class outcome.
        assert_eq!(
            SourceScriptError::Config { reason: "x".into() }.problem_code(),
            problem_code::UNAVAILABLE
        );
    }

    #[test]
    fn config_error_kind_and_display_are_stable() {
        let e = SourceScriptError::Config {
            reason: "max_operations must be > 0".into(),
        };
        assert_eq!(e.kind(), "config");
        assert_eq!(e.to_string(), "config error: max_operations must be > 0");
    }

    #[test]
    fn budget_kind_tags_are_stable() {
        assert_eq!(BudgetKind::Operations.as_str(), "operations");
        assert_eq!(BudgetKind::HttpCalls.as_str(), "http_calls");
        assert_eq!(BudgetKind::OutputBytes.as_str(), "output_bytes");
        assert_eq!(BudgetKind::Saturated.as_str(), "saturated");
    }

    #[test]
    fn display_never_includes_payloads() {
        // Display strings are short and contain only the low-cardinality fields.
        let e = SourceScriptError::HttpStatus { status: 503 };
        assert_eq!(e.to_string(), "upstream status 503");
        assert_eq!(e.kind(), "http_status");
    }
}
