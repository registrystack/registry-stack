// SPDX-License-Identifier: Apache-2.0

//! The client's error taxonomy: configuration defects, transport failures,
//! protocol failures, and exactly validated product problems.
//!
//! Every outcome is matchable without string inspection, and a product
//! problem carries the core's typed `ProblemCode`, whose pinned title and
//! remediation detail the caller reads with `code.title()` and
//! `code.detail()`.

use registry_documents_core::ProblemCode;
use registry_platform_httputil::client::TransportKind;
use thiserror::Error;

/// The stage inside the exchange where the wire stopped matching the pinned
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocumentsProtocolFailure {
    /// The response headers exceed the shared client bounds.
    HeaderBounds,
    /// The response carries no single canonical W3C Trace Context field.
    TraceContext,
    /// The body was not empty where emptiness was required, or was not
    /// exactly the pinned JSON answer.
    Body,
    /// A JSON answer was not exactly `application/json`, or released content
    /// carried no single readable `Content-Type`.
    MediaType,
    /// Released content did not hash to the digest the caller expected. The
    /// content is discarded: none of it reaches the caller.
    ContentDigest,
    /// The problem document did not match the closed problem definition its
    /// code names, or named no code in the closed vocabulary.
    Problem,
    /// A failure answer was not a problem document at all.
    Status,
}

/// Every failure a Document Store call can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DocumentsClientError {
    #[error("Registry Stack Document Store client configuration is invalid: {reason}")]
    Configuration { reason: &'static str },
    #[error("Registry Stack Document Store client request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("Registry Stack Document Store exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error(
        "Registry Stack Document Store refused the request (HTTP {status}, problem {})",
        .code.code()
    )]
    Problem {
        status: u16,
        code: ProblemCode,
        trace_id: Option<String>,
    },
    #[error("Registry Stack Document Store returned an invalid response")]
    Protocol {
        status: u16,
        failure: DocumentsProtocolFailure,
        trace_id: Option<String>,
    },
}

impl DocumentsClientError {
    pub(crate) fn configuration(reason: &'static str) -> Self {
        Self::Configuration { reason }
    }

    pub(crate) fn invalid_request(reason: &'static str) -> Self {
        Self::InvalidRequest { reason }
    }

    /// Whether the request may have taken effect although this error was
    /// returned.
    ///
    /// True for a timeout or broken exchange after the request was sent, an
    /// oversized or unparseable answer, and a 5xx answer: a 5xx may follow a
    /// commit. False for a request defect, a connection that was never
    /// established, and every typed 4xx refusal. When it is true for a
    /// reservation or a grant, the safe recovery is the same request under
    /// the same idempotency key, which the service replays; a new key could
    /// reserve a second document or issue a second grant. For an upload or a
    /// revocation, read the document or grant to learn where it stands.
    ///
    /// A protocol failure counts as unknown conservatively, as an oversized
    /// answer does: the request may have been processed before the answer
    /// went wrong. The client resends a keyed request after such an answer
    /// only when it came with a 5xx status, and never after a 4xx status
    /// line, even when the rest of that answer could not be read.
    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        match self {
            Self::Configuration { .. } | Self::InvalidRequest { .. } => false,
            Self::Transport { kind } => !matches!(kind, TransportKind::Connect),
            Self::Problem { status, .. } => *status >= 500,
            Self::Protocol { .. } => true,
        }
    }

    /// Whether resending the identical keyed request under the same key may
    /// settle an unknown outcome. An oversized or unparseable non-5xx answer
    /// would be replayed unchanged, so it is not resent. A transport failure
    /// carries no status, so the shared classifier, which sees the answer's
    /// status line, still refuses to resend after a 4xx one.
    pub(crate) fn resend_may_settle(&self) -> bool {
        match self {
            Self::Transport { kind } => {
                matches!(kind, TransportKind::Timeout | TransportKind::Exchange)
            }
            Self::Problem { status, .. } | Self::Protocol { status, .. } => *status >= 500,
            Self::Configuration { .. } | Self::InvalidRequest { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(status: u16, code: ProblemCode) -> DocumentsClientError {
        DocumentsClientError::Problem {
            status,
            code,
            trace_id: None,
        }
    }

    fn protocol(status: u16, failure: DocumentsProtocolFailure) -> DocumentsClientError {
        DocumentsClientError::Protocol {
            status,
            failure,
            trace_id: None,
        }
    }

    fn transport(kind: TransportKind) -> DocumentsClientError {
        DocumentsClientError::Transport { kind }
    }

    #[test]
    fn the_unknown_outcome_predicate_separates_maybe_committed_from_refused() {
        let unknown = [
            transport(TransportKind::Timeout),
            transport(TransportKind::Exchange),
            transport(TransportKind::ResponseTooLarge),
            problem(503, ProblemCode::ServiceUnavailable),
            protocol(502, DocumentsProtocolFailure::Status),
            protocol(201, DocumentsProtocolFailure::Body),
            protocol(201, DocumentsProtocolFailure::TraceContext),
            protocol(200, DocumentsProtocolFailure::ContentDigest),
        ];
        for error in &unknown {
            assert!(error.is_outcome_unknown(), "{error:?}");
        }
        let settled = [
            DocumentsClientError::configuration("fixture reason"),
            DocumentsClientError::invalid_request("fixture reason"),
            transport(TransportKind::Connect),
            problem(401, ProblemCode::AuthenticationRefused),
            problem(403, ProblemCode::ProfileNotAuthorized),
            problem(404, ProblemCode::ResourceNotFound),
            problem(409, ProblemCode::IdempotencyKeyReused),
            problem(410, ProblemCode::IdempotencyExpired),
            problem(422, ProblemCode::UploadDigestMismatch),
        ];
        for error in &settled {
            assert!(!error.is_outcome_unknown(), "{error:?}");
        }
    }

    #[test]
    fn only_a_timeout_a_broken_exchange_or_a_5xx_is_resent() {
        let resent = [
            transport(TransportKind::Timeout),
            transport(TransportKind::Exchange),
            problem(503, ProblemCode::ServiceUnavailable),
            protocol(500, DocumentsProtocolFailure::Status),
        ];
        for error in &resent {
            assert!(error.resend_may_settle(), "{error:?}");
        }
        let kept = [
            transport(TransportKind::Connect),
            transport(TransportKind::ResponseTooLarge),
            protocol(201, DocumentsProtocolFailure::Body),
            problem(409, ProblemCode::IdempotencyKeyReused),
            DocumentsClientError::invalid_request("fixture reason"),
        ];
        for error in &kept {
            assert!(!error.resend_may_settle(), "{error:?}");
        }
    }
}
