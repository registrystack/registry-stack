// SPDX-License-Identifier: Apache-2.0

//! Bounded client for the Registry Stack Document Store.
//!
//! A thin relying-party client over the pinned Document Store HTTP
//! contract. The closed problem vocabulary and the wire documents come from
//! `registry-documents-core`; the shared transport primitives, the exact
//! problem document shape, and trace correlation come from
//! `registry-platform-httpsec` and `registry-platform-httputil`. This crate
//! never depends on the Document Store runtime or its operator tooling and
//! adds no document semantics of its own.
//!
//! The client covers every route the runtime serves: liveness, reserving a
//! document, sending its content, reading and listing documents, downloading
//! a version's content, issuing, listing, and revoking grants, and listing
//! the policies a caller may use. It keeps the deployment prefix of the
//! configured service URL, never follows redirects, reads every answer under
//! a bounded byte ceiling, reads one list page per call, and lands every
//! failure in one named shape: a configuration defect, a request refused
//! before it was sent, a transport failure, a protocol failure, or a
//! validated product problem surfaced as its typed code.
//!
//! Only the two idempotency-keyed mutations, reserving a document and
//! issuing a grant, are ever resent, and only under the caller's own key
//! while their outcome is unknown. A download is checked against the digest
//! the caller expects before any of its bytes is returned.

#![deny(unsafe_code)]

mod client;
mod error;

pub use client::{
    DocumentContent, DocumentsClient, DocumentsClientConfig, DocumentsComplete, PageRequest,
    UploadBody,
};
pub use error::{DocumentsClientError, DocumentsProtocolFailure};
pub use registry_documents_core::{
    type_uri, ContentType, CustodianRef, DocumentAction, DocumentGrantPage, DocumentGrantView,
    DocumentLabel, DocumentPage, DocumentPolicyList, DocumentPolicyView, DocumentStatus,
    DocumentVersionView, DocumentView, GrantState, GranteeRef, IssueGrantRequest, PolicyBinding,
    ProblemCode, ReservationView, ReserveDocumentRequest, DEFAULT_PAGE_SIZE,
    DOCUMENTS_PROBLEM_TYPE_BASE, HEALTH_PATH, MAXIMUM_LABEL_BYTES, MAXIMUM_PAGE_SIZE,
};
pub use registry_platform_httputil::client::{BearerToken, TransportKind};
pub use registry_platform_yaml::{Digest, ExternalId, LocalId};
