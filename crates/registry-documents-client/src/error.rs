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
    /// The body was not empty where emptiness was required.
    Body,
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
}
