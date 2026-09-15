// SPDX-License-Identifier: Apache-2.0

//! The client's error taxonomy: caller-side request defects, transport
//! failures, protocol failures, and exactly validated product problems.
//!
//! The taxonomy is the caller's recovery contract: every outcome is
//! matchable without string inspection, and a product problem carries the
//! core's typed `ProblemCode`, whose pinned title and remediation detail the
//! caller reads with `code.title()` and `code.detail()`. The client
//! validates the identifying members of a problem, its status, code, type
//! URI, and trace, against that pinned definition before surfacing it. The
//! human-readable title and detail are read from the core, never compared
//! against the answer, so a deployment that rewords one still answers a
//! refusal this caller can recover from.

use registry_platform_httputil::client::TransportKind;
use registry_scheduling_core::ProblemCode;
use thiserror::Error;

/// The stage inside the exchange where the wire stopped matching the pinned
/// contract. Every variant is a protocol failure: the caller cannot repair
/// it by editing the request, only by stopping or reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchedulingProtocolFailure {
    /// The response headers exceed the shared client bounds.
    HeaderBounds,
    /// The response carries no single canonical W3C Trace Context field.
    TraceContext,
    /// A JSON answer was not exactly `application/json`.
    MediaType,
    /// The body was not empty where emptiness was required, was
    /// unparseable, or carried a field the contract refuses.
    Body,
    /// The problem document did not match the closed problem definition its
    /// code names, or named no code in the closed vocabulary.
    Problem,
    /// A failure answer was not a problem document at all.
    Status,
}

/// Every failure a Scheduling call can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SchedulingClientError {
    #[error("Registry Scheduling client configuration is invalid: {reason}")]
    Configuration { reason: &'static str },
    #[error("Registry Scheduling client request is invalid: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("Registry Scheduling exchange did not complete: {kind}")]
    Transport { kind: TransportKind },
    #[error(
        "Registry Scheduling refused the request (HTTP {status}, problem {})",
        .code.code()
    )]
    Problem {
        status: u16,
        code: ProblemCode,
        trace_id: Option<String>,
    },
    #[error("Registry Scheduling returned an invalid response")]
    Protocol {
        status: u16,
        failure: SchedulingProtocolFailure,
        trace_id: Option<String>,
    },
}

impl SchedulingClientError {
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
    use registry_platform_httpsec::{ProblemDocument, TraceId};
    use registry_scheduling_core::type_uri;
    use reqwest::StatusCode;

    const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";

    fn exhaustive_document() -> ProblemDocument {
        let code = ProblemCode::CapacityExhausted;
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
    fn an_exact_problem_document_is_a_typed_domain_problem() {
        let document = exhaustive_document();
        let trace = Some(document.trace_id.as_str());
        match domain_problem(StatusCode::CONFLICT, trace, &document) {
            SchedulingClientError::Problem {
                status: 409,
                code: ProblemCode::CapacityExhausted,
                trace_id,
            } => assert_eq!(trace_id.as_deref(), trace),
            other => panic!("expected a typed domain problem, got {other:?}"),
        }
    }

    /// The request-edge family is part of the closed vocabulary, so the
    /// product's own route-not-found answer is a typed problem, never edge
    /// talk; only a foreign dialect's is.
    #[test]
    fn the_products_own_request_edge_problem_is_typed() {
        let code = ProblemCode::RequestNotFound;
        let document = ProblemDocument {
            type_uri: type_uri(code.code()),
            title: code.title().to_owned(),
            status: code.http_status(),
            detail: code.detail().to_owned(),
            code: code.code().to_owned(),
            trace_id: TraceId::parse(TRACE_ID).expect("fixture trace identifier"),
        };
        match domain_problem(StatusCode::NOT_FOUND, Some(TRACE_ID), &document) {
            SchedulingClientError::Problem {
                status: 404,
                code: ProblemCode::RequestNotFound,
                ..
            } => {}
            other => panic!("expected a typed request-edge problem, got {other:?}"),
        }
    }

    /// The pinned title and remediation detail are this client's own copy of
    /// the vocabulary, not members to hold a deployment to. A deployment that
    /// rewords one has not changed which refusal it answered, and a client
    /// that refused the answer over the wording would turn an editorial
    /// change into an unrecoverable protocol failure.
    #[test]
    fn a_reworded_title_or_detail_is_still_the_problem_the_code_names() {
        let document = exhaustive_document();
        let trace = Some(document.trace_id.as_str());
        let reworded = vec![
            ProblemDocument {
                title: "No capacity remains".to_owned(),
                ..document.clone()
            },
            ProblemDocument {
                detail: "Every opening at that start is taken.".to_owned(),
                ..document.clone()
            },
        ];
        for answer in reworded {
            match domain_problem(StatusCode::CONFLICT, trace, &answer) {
                SchedulingClientError::Problem {
                    status: 409,
                    code: ProblemCode::CapacityExhausted,
                    ..
                } => {}
                other => panic!("expected a typed domain problem, got {other:?}"),
            }
        }
    }

    #[test]
    fn every_problem_mismatch_degrades_to_a_protocol_failure() {
        let document = exhaustive_document();
        let trace = Some(document.trace_id.as_str());

        let mismatches: Vec<ProblemDocument> = vec![
            ProblemDocument {
                status: 500,
                ..document.clone()
            },
            ProblemDocument {
                type_uri: format!(
                    "https://example.test/problems/other/{}",
                    document.code.replace('.', "/")
                ),
                ..document.clone()
            },
            ProblemDocument {
                code: "capacity.unexhausted".to_owned(),
                ..document.clone()
            },
        ];
        for mismatch in mismatches {
            assert!(
                matches!(
                    domain_problem(StatusCode::CONFLICT, trace, &mismatch),
                    SchedulingClientError::Protocol {
                        status: 409,
                        failure: SchedulingProtocolFailure::Problem,
                        ..
                    }
                ),
                "{mismatch:?}"
            );
        }

        // The response trace header must match the document's own trace
        // identifier; a missing or different one is edge talk, never a
        // domain problem.
        assert!(matches!(
            domain_problem(
                StatusCode::CONFLICT,
                Some("ffffffffffffffffffffffffffffffff"),
                &document
            ),
            SchedulingClientError::Protocol {
                status: 409,
                failure: SchedulingProtocolFailure::Problem,
                ..
            }
        ));
        assert!(matches!(
            domain_problem(StatusCode::CONFLICT, None, &document),
            SchedulingClientError::Protocol {
                status: 409,
                failure: SchedulingProtocolFailure::Problem,
                ..
            }
        ));
    }

    #[test]
    fn display_names_the_product_the_stage_and_the_typed_code() {
        let document = exhaustive_document();
        let problem = domain_problem(
            StatusCode::CONFLICT,
            Some(document.trace_id.as_str()),
            &document,
        );
        assert_eq!(
            problem.to_string(),
            "Registry Scheduling refused the request (HTTP 409, problem capacity.exhausted)"
        );
        let configuration = SchedulingClientError::configuration("fixture reason");
        assert_eq!(
            configuration.to_string(),
            "Registry Scheduling client configuration is invalid: fixture reason"
        );
        let invalid_request = SchedulingClientError::invalid_request("fixture reason");
        assert_eq!(
            invalid_request.to_string(),
            "Registry Scheduling client request is invalid: fixture reason"
        );
        let transport = SchedulingClientError::Transport {
            kind: TransportKind::Timeout,
        };
        assert_eq!(
            transport.to_string(),
            "Registry Scheduling exchange did not complete: the configured timeout elapsed"
        );
        let protocol = SchedulingClientError::Protocol {
            status: 200,
            failure: SchedulingProtocolFailure::MediaType,
            trace_id: None,
        };
        assert_eq!(
            protocol.to_string(),
            "Registry Scheduling returned an invalid response"
        );
    }
}
