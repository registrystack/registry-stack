// SPDX-License-Identifier: Apache-2.0
//! Typed Registry Notary HTTP client.
//!
//! This crate is the Rust client for Registry Notary. It wraps the HTTP API
//! with typed request and response types, strict transport defaults, bounded
//! response reads, route-aware retries, and redacted error surfaces.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use registry_notary_client::RegistryNotaryClient;
//!
//! let client = RegistryNotaryClient::builder("https://notary.example.gov")
//!     .bearer_token("token")
//!     .default_purpose("benefits_eligibility")
//!     .user_agent("benefits-api/1.0")
//!     .build()?;
//!
//! let evaluation = client
//!     .evaluate_target("Person")
//!     .target_identifier("national_id", "person-1")
//!     .relationship("self")
//!     .claims(["person-is-alive"])
//!     .disclosure("predicate")
//!     .send()
//!     .await?;
//!
//! if let Some(result) = evaluation.body.first_result() {
//!     println!("{} = {:?}", result.claim_id, result.satisfied);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Wire request types and helper wrappers
//!
//! Request types come from `registry-notary-core` for routes whose wire shapes
//! are part of the service contract. Batch evaluation now uses
//! [`registry_notary_core::BatchEvaluateResponse`] directly. The helper
//! wrappers in [`responses`] are not compatibility workarounds; they add
//! redacted formatting or ergonomic accessors on top of the wire responses.
//!
//! # Feature flags
//!
//! - `oid4vci` enables OpenID4VCI endpoint helpers.
//! - `federation` enables delegated evaluation JWS submission.
//! - `json-facade` enables a binding-safe JSON facade for Python and Node
//!   wrappers.
//! - `verifier` enables explicit, opt-in SD-JWT VC verification helpers.
//! - `test-support` exposes the test-only `reqwest::Client` override and
//!   loopback HTTP allowance.
//!
//! # Safety contract
//!
//! The client rejects multiple authentication modes, disables redirects,
//! ignores proxy environment variables, bounds every response body, and redacts
//! raw Problem Details `detail`, compact credentials, holder proofs, nonces,
//! SD-JWT disclosures, and token material from incidental formatting surfaces.

pub mod auth;
mod client;
pub mod error;
pub mod headers;
pub mod options;
pub mod responses;

#[cfg(feature = "json-facade")]
pub mod facade;
#[cfg(feature = "federation")]
pub mod federation;
#[cfg(feature = "oid4vci")]
pub mod oid4vci;
#[cfg(feature = "verifier")]
pub mod verifier;

pub use client::{EvaluateBuilder, NotaryClientBuilder, RegistryNotaryClient};
pub use error::{
    NotaryClientBuildError, NotaryClientError, Oid4vciError, PortableClientError,
    PortableErrorKind, ProblemDetails,
};
pub use options::{RequestOptions, RetryAfter, RetryPolicy};
pub use responses::{
    AdminReloadResponse, CredentialIssueResponse, CredentialStatusResponse,
    CredentialStatusUpdateRequest, EnabledSignerSurfaceChecks, EvaluateResponse, Evaluation,
    FormatsResponse, HealthResponse, ListClaimsResponse, NotaryResponse, ReadinessChecks,
    ReadinessResponse, SignerCustodyChecks, SignerCustodySurfaces, SignerSurfaceChecks,
    SigningProviderReadinessChecks,
};
#[cfg(feature = "verifier")]
pub use verifier::{HolderBindingPolicy, VerificationError, VerifiedCredential, VerifyOptions};
