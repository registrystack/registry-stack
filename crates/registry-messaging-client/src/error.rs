// SPDX-License-Identifier: Apache-2.0

//! The client's error taxonomy: configuration defects, transport failures,
//! protocol failures, and exactly validated product problems.
//!
//! The taxonomy is the caller's recovery contract: every outcome is
//! matchable without string inspection, and a product problem carries the
//! core's typed `ProblemCode`, whose pinned title and remediation detail the
//! caller reads with `code.title()` and `code.detail()`. The client validates
//! the identifying members of a problem, its status, code, type URI, and
//! trace, against that pinned definition before surfacing it. The
//! human-readable title and detail are read from the core, never compared
//! against the answer, so a deployment that rewords one still answers a
//! refusal this caller can recover from.

use registry_messaging_core::ProblemCode;
use registry_platform_httputil::client::TransportKind;
use thiserror::Error;

/// The stage inside the exchange where the wire stopped matching the pinned
/// contract. Every variant is a protocol failure: the caller cannot repair
/// it by editing the request, only by stopping or reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessagingProtocolFailure {
    /// The response headers exceed the shared client bounds.
    HeaderBounds,
    /// The response carries no single canonical W3C Trace Context field.
    TraceContext,
    /// The body was not empty where emptiness was required, or was not
    /// exactly the pinned JSON answer.
    Body,
    /// A JSON answer was not exactly `application/json`.
    MediaType,
    /// The problem document did not match the closed problem definition its
    /// code names, or named no code in the closed vocabulary.
    Problem,
    /// A failure answer was not a problem document at all.
    Status,
}

/// Every failure a Messaging call can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MessagingClientError {
    #[error("Registry Messaging client configuration is invalid: {reason}")]
    Configuration { reason: &'static str },
    #[error("Registry Messaging client request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("Registry Messaging exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error(
        "Registry Messaging refused the request (HTTP {status}, problem {})",
        .code.code()
    )]
    Problem {
        status: u16,
        code: ProblemCode,
        trace_id: Option<String>,
        /// The wait, in whole seconds, a 429 refusal asked for in
        /// `Retry-After`, bounded by `MAXIMUM_RETRY_AFTER_SECONDS`. Always
        /// `None` on any other status, and on a 429 whose header was absent
        /// or outside the bound. The client never waits on a 429 or retries
        /// it; the wait is the caller's to honor.
        retry_after_seconds: Option<u64>,
    },
    #[error("Registry Messaging returned an invalid response")]
    Protocol {
        status: u16,
        failure: MessagingProtocolFailure,
        trace_id: Option<String>,
    },
}

impl MessagingClientError {
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
    /// established, and every typed 4xx refusal, including a 429 limit. When
    /// it is true, the safe recovery for a submission is the same request
    /// under the same idempotency key, which the service either replays or
    /// settles; a new key could send the message twice.
    ///
    /// It is false for `410 idempotency.expired` too, but there an earlier
    /// submission under the key was accepted and its message may have been
    /// sent: reconcile that submission before choosing a new key.
    ///
    /// A protocol failure, such as a 3xx answer or an answer that cannot be
    /// parsed or does not meet the contract, counts as unknown conservatively,
    /// as an oversized answer does: the request may have been processed before
    /// the answer went wrong. The client resends such an answer only when it
    /// came with a 5xx status, because any other answer would be replayed
    /// unchanged. It never resends after a 4xx status line, even when the rest
    /// of that answer could not be read and the error is therefore unknown.
    #[must_use]
    pub fn is_outcome_unknown(&self) -> bool {
        match self {
            Self::Configuration { .. } | Self::InvalidRequest { .. } => false,
            Self::Transport { kind } => !matches!(kind, TransportKind::Connect),
            Self::Problem { status, .. } => *status >= 500,
            Self::Protocol { .. } => true,
        }
    }

    /// Whether resending the identical request under the same key may settle
    /// an unknown outcome. An oversized or unparseable non-5xx answer would be
    /// replayed unchanged, so it is not resent. A transport failure carries no
    /// status, so the shared classifier, which sees the answer's status line,
    /// still refuses to resend a timeout or broken exchange after a 4xx one.
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
    use crate::client::domain_problem;
    use registry_messaging_core::type_uri;
    use registry_platform_httpsec::{ProblemDocument, TraceId};
    use reqwest::StatusCode;

    const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";

    fn document(code: ProblemCode) -> ProblemDocument {
        ProblemDocument {
            type_uri: type_uri(code.code()),
            title: code.title().to_owned(),
            status: code.http_status(),
            detail: code.detail().to_owned(),
            code: code.code().to_owned(),
            trace_id: TraceId::parse(TRACE_ID).expect("fixture trace identifier"),
        }
    }

    #[test]
    fn every_pinned_problem_document_is_its_typed_code() {
        for code in ProblemCode::ALL {
            let status = StatusCode::from_u16(code.http_status()).expect("a pinned status");
            match domain_problem(status, Some(TRACE_ID), &document(*code), None) {
                MessagingClientError::Problem {
                    status: answered,
                    code: typed,
                    trace_id,
                    retry_after_seconds: None,
                } => {
                    assert_eq!(answered, code.http_status());
                    assert_eq!(typed, *code);
                    assert_eq!(trace_id.as_deref(), Some(TRACE_ID));
                }
                other => panic!("expected a typed problem for {code:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_reworded_title_or_detail_is_still_the_problem_the_code_names() {
        let pinned = document(ProblemCode::MessageNotVisible);
        let reworded = [
            ProblemDocument {
                title: "Not here".to_owned(),
                ..pinned.clone()
            },
            ProblemDocument {
                detail: "Nothing to see.".to_owned(),
                ..pinned.clone()
            },
        ];
        for answer in reworded {
            assert!(matches!(
                domain_problem(StatusCode::NOT_FOUND, Some(TRACE_ID), &answer, None),
                MessagingClientError::Problem {
                    code: ProblemCode::MessageNotVisible,
                    ..
                }
            ));
        }
    }

    #[test]
    fn every_problem_mismatch_degrades_to_a_protocol_failure() {
        let pinned = document(ProblemCode::MessageNotVisible);
        let mismatches = [
            ProblemDocument {
                status: 403,
                ..pinned.clone()
            },
            ProblemDocument {
                type_uri: "https://example.test/problems/other/message/not-visible".to_owned(),
                ..pinned.clone()
            },
            ProblemDocument {
                code: "message.unknown".to_owned(),
                ..pinned.clone()
            },
            ProblemDocument {
                code: "authorization.refused".to_owned(),
                ..pinned.clone()
            },
        ];
        for mismatch in mismatches {
            assert!(
                matches!(
                    domain_problem(StatusCode::NOT_FOUND, Some(TRACE_ID), &mismatch, None),
                    MessagingClientError::Protocol {
                        status: 404,
                        failure: MessagingProtocolFailure::Problem,
                        ..
                    }
                ),
                "{mismatch:?}"
            );
        }
        // A code whose pinned status differs from the answered status.
        assert!(matches!(
            domain_problem(StatusCode::FORBIDDEN, Some(TRACE_ID), &pinned, None),
            MessagingClientError::Protocol {
                failure: MessagingProtocolFailure::Problem,
                ..
            }
        ));
        // The response trace header must match the document's own trace.
        for header in [None, Some("ffffffffffffffffffffffffffffffff")] {
            assert!(matches!(
                domain_problem(StatusCode::NOT_FOUND, header, &pinned, None),
                MessagingClientError::Protocol {
                    failure: MessagingProtocolFailure::Problem,
                    ..
                }
            ));
        }
    }

    #[test]
    fn a_wait_rides_only_on_a_typed_too_many_requests_problem() {
        let pinned = document(ProblemCode::MessageNotVisible);
        assert!(matches!(
            domain_problem(StatusCode::NOT_FOUND, Some(TRACE_ID), &pinned, Some(5)),
            MessagingClientError::Problem {
                retry_after_seconds: None,
                ..
            }
        ));
        let mismatch = ProblemDocument {
            status: 429,
            ..pinned
        };
        assert!(matches!(
            domain_problem(
                StatusCode::TOO_MANY_REQUESTS,
                Some(TRACE_ID),
                &mismatch,
                Some(5)
            ),
            MessagingClientError::Protocol {
                status: 429,
                failure: MessagingProtocolFailure::Problem,
                ..
            }
        ));
    }

    #[test]
    fn the_unknown_outcome_predicate_separates_maybe_committed_from_refused() {
        let problem = |status, code| MessagingClientError::Problem {
            status,
            code,
            trace_id: None,
            retry_after_seconds: None,
        };
        let protocol = |status, failure| MessagingClientError::Protocol {
            status,
            failure,
            trace_id: None,
        };
        let transport = |kind| MessagingClientError::Transport { kind };
        let unknown = [
            transport(TransportKind::Timeout),
            transport(TransportKind::Exchange),
            transport(TransportKind::ResponseTooLarge),
            problem(503, ProblemCode::ServiceUnavailable),
            protocol(502, MessagingProtocolFailure::Status),
            protocol(202, MessagingProtocolFailure::Body),
            protocol(202, MessagingProtocolFailure::TraceContext),
        ];
        for error in &unknown {
            assert!(error.is_outcome_unknown(), "{error:?}");
        }
        let settled = [
            MessagingClientError::configuration("fixture reason"),
            MessagingClientError::invalid_request("fixture reason"),
            transport(TransportKind::Connect),
            problem(401, ProblemCode::AuthenticationRefused),
            problem(403, ProblemCode::ProfileNotAuthorized),
            problem(409, ProblemCode::IdempotencyKeyReused),
            problem(410, ProblemCode::IdempotencyExpired),
            problem(422, ProblemCode::TemplateDataInvalid),
            problem(429, ProblemCode::RateLimitExceeded),
        ];
        for error in &settled {
            assert!(!error.is_outcome_unknown(), "{error:?}");
        }
    }

    #[test]
    fn only_a_timeout_a_broken_exchange_or_a_5xx_is_resent() {
        let resent = [
            MessagingClientError::Transport {
                kind: TransportKind::Timeout,
            },
            MessagingClientError::Transport {
                kind: TransportKind::Exchange,
            },
            MessagingClientError::Problem {
                status: 503,
                code: ProblemCode::ServiceUnavailable,
                trace_id: None,
                retry_after_seconds: None,
            },
            MessagingClientError::Protocol {
                status: 500,
                failure: MessagingProtocolFailure::Status,
                trace_id: None,
            },
        ];
        for error in &resent {
            assert!(error.resend_may_settle(), "{error:?}");
        }
        let kept = [
            MessagingClientError::Transport {
                kind: TransportKind::Connect,
            },
            MessagingClientError::Transport {
                kind: TransportKind::ResponseTooLarge,
            },
            MessagingClientError::Protocol {
                status: 202,
                failure: MessagingProtocolFailure::Body,
                trace_id: None,
            },
            MessagingClientError::Problem {
                status: 409,
                code: ProblemCode::IdempotencyKeyReused,
                trace_id: None,
                retry_after_seconds: None,
            },
            MessagingClientError::invalid_request("fixture reason"),
        ];
        for error in &kept {
            assert!(!error.resend_may_settle(), "{error:?}");
        }
    }

    #[test]
    fn display_names_the_product_and_the_typed_code() {
        let problem = domain_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            Some(TRACE_ID),
            &document(ProblemCode::ServiceUnavailable),
            None,
        );
        assert_eq!(
            problem.to_string(),
            "Registry Messaging refused the request (HTTP 503, problem service.unavailable)"
        );
        assert_eq!(
            MessagingClientError::configuration("fixture reason").to_string(),
            "Registry Messaging client configuration is invalid: fixture reason"
        );
    }
}
