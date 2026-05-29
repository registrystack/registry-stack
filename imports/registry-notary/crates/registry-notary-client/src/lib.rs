// SPDX-License-Identifier: Apache-2.0
//! Registry Notary HTTP client.

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

pub use client::{EvaluateBuilder, NotaryClientBuilder, RegistryNotaryClient};
pub use error::{
    NotaryClientBuildError, NotaryClientError, Oid4vciError, PortableClientError,
    PortableErrorKind, ProblemDetails,
};
pub use options::{RequestOptions, RetryAfter, RetryPolicy};
pub use responses::{
    AdminReloadResponse, BatchEvaluation, CredentialIssueResponse, CredentialStatusResponse,
    CredentialStatusUpdateRequest, EvaluateResponse, Evaluation, FormatsResponse, HealthResponse,
    ListClaimsResponse, NotaryResponse,
};
