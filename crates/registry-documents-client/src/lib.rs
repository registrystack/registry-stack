// SPDX-License-Identifier: Apache-2.0

//! Bounded client for the Registry Stack Document Store.
//!
//! A thin relying-party client over the pinned Document Store HTTP
//! contract. The closed problem vocabulary and every route name come from
//! `registry-documents-core`; the shared transport primitives, the exact
//! problem document shape, and trace correlation come from
//! `registry-platform-httpsec` and `registry-platform-httputil`. This crate
//! never depends on the Document Store runtime or its operator tooling and
//! adds no document semantics of its own.
//!
//! The client covers the unauthenticated liveness route. It never follows
//! redirects, reads every response under a bounded byte ceiling, and lands
//! every failure in one named shape: a configuration defect, a transport
//! failure, a protocol failure, or a validated product problem surfaced as
//! its typed code.

#![deny(unsafe_code)]

mod client;
mod error;

pub use client::{DocumentsClient, DocumentsClientConfig, DocumentsComplete};
pub use error::{DocumentsClientError, DocumentsProtocolFailure};
pub use registry_documents_core::{
    type_uri, ProblemCode, DOCUMENTS_PROBLEM_TYPE_BASE, HEALTH_PATH,
};
pub use registry_platform_httputil::client::TransportKind;
