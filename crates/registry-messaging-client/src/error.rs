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
            match domain_problem(status, Some(TRACE_ID), &document(*code)) {
                MessagingClientError::Problem {
                    status: answered,
                    code: typed,
                    trace_id,
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
                domain_problem(StatusCode::NOT_FOUND, Some(TRACE_ID), &answer),
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
                    domain_problem(StatusCode::NOT_FOUND, Some(TRACE_ID), &mismatch),
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
            domain_problem(StatusCode::FORBIDDEN, Some(TRACE_ID), &pinned),
            MessagingClientError::Protocol {
                failure: MessagingProtocolFailure::Problem,
                ..
            }
        ));
        // The response trace header must match the document's own trace.
        for header in [None, Some("ffffffffffffffffffffffffffffffff")] {
            assert!(matches!(
                domain_problem(StatusCode::NOT_FOUND, header, &pinned),
                MessagingClientError::Protocol {
                    failure: MessagingProtocolFailure::Problem,
                    ..
                }
            ));
        }
    }

    #[test]
    fn display_names_the_product_and_the_typed_code() {
        let problem = domain_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            Some(TRACE_ID),
            &document(ProblemCode::ServiceUnavailable),
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
