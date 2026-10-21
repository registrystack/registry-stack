// SPDX-License-Identifier: Apache-2.0
//! Bounded outbound transports a runtime keeps content bytes with.
//!
//! [`s3`] stores whole objects in one S3-compatible bucket that has never
//! enabled versioning, under a key prefix and binding domain the calling
//! product supplies. [`verifier`] submits content to one external HTTP
//! verifier for an `approved` or `rejected` verdict. Both read their
//! configuration from the shared blocks
//! [`registry_platform_config::ObjectStorageConfig`] and
//! [`registry_platform_config::AttachmentVerifierConfig`].
//!
//! The transports own only bytes and verdicts. References, locking, pending
//! writes, deletion retries, quarantine, and release authority stay with the
//! calling product and its database. No transport retries a request, follows
//! a redirect, or reports a URL, object key, credential, or response body in
//! an error.

pub mod s3;
pub mod verifier;

pub use s3::{ObjectNamespace, ObjectStoreError, S3ObjectStore, S3Settings};
pub use verifier::{HttpVerifier, HttpVerifierSettings, Verdict, VerifierError, VerifierNamespace};
