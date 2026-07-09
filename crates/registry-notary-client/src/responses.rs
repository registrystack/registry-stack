// SPDX-License-Identifier: Apache-2.0
//! Client-owned response types and ergonomic wrappers.

use std::{collections::BTreeMap, fmt};

use registry_notary_core::{BatchEvaluateResponse, ClaimResultView};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::options::RetryAfter;

#[doc(hidden)]
pub trait SafeDebug {
    fn fmt_debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

macro_rules! impl_safe_debug {
    ($($t:ty),* $(,)?) => {
        $(
            impl SafeDebug for $t {
                fn fmt_debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::Debug::fmt(self, f)
                }
            }
        )*
    };
}

/// Response body for `POST /v1/evaluations`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    /// Claim results returned by the server.
    pub results: Vec<ClaimResultView>,
}

/// Response body for `GET /v1/claims`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListClaimsResponse {
    /// Claim definitions as server-owned JSON documents.
    pub data: Vec<serde_json::Value>,
}

/// Response body for `GET /v1/formats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatsResponse {
    /// Supported evidence formats.
    pub formats: Vec<registry_notary_core::EvidenceFormat>,
}

/// Response body for direct credential issuance.
///
/// This contains credential material intentionally. `Debug` redacts the compact
/// credential, issuer-signed JWT, and disclosures.
#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialIssueResponse {
    /// Server credential id.
    pub credential_id: String,
    /// Credential profile used for issuance.
    pub credential_profile: String,
    /// Credential format, for example SD-JWT VC.
    pub format: String,
    /// Issuer identifier.
    pub issuer: String,
    /// Credential expiry timestamp.
    pub expires_at: String,
    /// Compact credential body.
    pub credential: String,
    /// Issuer-signed JWT component.
    pub issuer_signed_jwt: String,
    /// SD-JWT disclosures.
    pub disclosures: Vec<String>,
}

impl fmt::Debug for CredentialIssueResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialIssueResponse")
            .field("credential_id", &self.credential_id)
            .field("credential_profile", &self.credential_profile)
            .field("format", &self.format)
            .field("issuer", &self.issuer)
            .field("expires_at", &self.expires_at)
            .field("credential", &"<redacted>")
            .field("issuer_signed_jwt", &"<redacted>")
            .field("disclosures", &"<redacted>")
            .finish()
    }
}

/// Response body for credential status lookup and update.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusResponse {
    /// Server credential id.
    pub credential_id: String,
    /// Issuer identifier.
    pub issuer: String,
    /// Credential profile used for issuance.
    pub credential_profile: String,
    /// Current lifecycle status.
    pub status: String,
    /// Issuance timestamp.
    pub issued_at: String,
    /// Expiry timestamp.
    pub expires_at: String,
    /// Last status update timestamp.
    pub updated_at: String,
}

/// Request body for admin credential status update.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusUpdateRequest {
    /// New status value.
    pub status: String,
}

/// Response body for `POST /admin/v1/reload`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminReloadResponse {
    /// Whether reload executed.
    pub reloaded: bool,
    /// Reload status.
    pub status: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Health response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    /// Overall status.
    pub status: String,
    /// Service-specific checks.
    pub checks: serde_json::Value,
}

/// Readiness response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessResponse {
    /// Overall readiness status.
    pub status: String,
    /// Readiness checks, including signer-custody facts.
    pub checks: ReadinessChecks,
}

/// Aggregate readiness checks returned on both success and failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessChecks {
    /// Total number of readiness checks.
    pub total: usize,
    /// Checks that are ready.
    pub ok: usize,
    /// Checks that are serving with reduced assurance.
    pub degraded: usize,
    /// Checks that are not ready.
    pub failed: usize,
    /// Signing-provider health and custody facts.
    pub signing_providers: SigningProviderReadinessChecks,
}

/// Runtime signer health and custody checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningProviderReadinessChecks {
    /// Active signing providers checked by the runtime.
    pub total: usize,
    /// Signing providers that are ready.
    pub ok: usize,
    /// Signing providers that are not ready.
    pub failed: usize,
    /// Custody facts for configured signing roles.
    pub custody: SignerCustodyChecks,
}

/// Public, non-secret signer-custody facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerCustodyChecks {
    /// Active provider kinds and their counts.
    pub active_provider_counts: BTreeMap<String, usize>,
    /// Distinct providers bound to custody-relevant signing roles.
    pub signing_provider_count: usize,
    /// Custody-relevant providers using local JWK or file material.
    pub local_software_signing_provider_count: usize,
    /// Whether the deployment profile requires explicit custody approval.
    pub custody_approval_required: bool,
    /// Whether the operator declared that custody review has approved the signers.
    pub custody_approved: bool,
    /// Custody-relevant providers not covered by approval.
    pub unapproved_signing_provider_count: usize,
    /// Counts grouped by signing surface.
    pub surfaces: SignerCustodySurfaces,
}

/// Signer-custody facts grouped by Notary signing surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerCustodySurfaces {
    /// Credential issuance signer facts.
    pub credential_issuance: SignerSurfaceChecks,
    /// Access-token issuance signer facts.
    pub access_token_issuance: EnabledSignerSurfaceChecks,
    /// Federation response signer facts.
    pub federation: EnabledSignerSurfaceChecks,
}

/// Signer counts for an always-available signing surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerSurfaceChecks {
    /// Distinct signing providers used by the surface.
    pub signing_provider_count: usize,
    /// Surface providers using local JWK or file material.
    pub local_software_signing_provider_count: usize,
    /// Surface providers not covered by custody approval.
    pub unapproved_signing_provider_count: usize,
}

/// Signer counts for an optional signing surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnabledSignerSurfaceChecks {
    /// Whether the optional surface is enabled.
    pub enabled: bool,
    /// Distinct signing providers used by the surface.
    pub signing_provider_count: usize,
    /// Surface providers using local JWK or file material.
    pub local_software_signing_provider_count: usize,
    /// Surface providers not covered by custody approval.
    pub unapproved_signing_provider_count: usize,
}

impl_safe_debug!(
    EvaluateResponse,
    ListClaimsResponse,
    FormatsResponse,
    CredentialIssueResponse,
    CredentialStatusResponse,
    AdminReloadResponse,
    HealthResponse,
    ReadinessResponse,
    ReadinessChecks,
    SigningProviderReadinessChecks,
    SignerCustodyChecks,
    SignerCustodySurfaces,
    SignerSurfaceChecks,
    EnabledSignerSurfaceChecks,
    BatchEvaluateResponse,
    serde_json::Value,
    String,
);

impl<T: fmt::Debug> SafeDebug for Vec<T> {
    fn fmt_debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(feature = "oid4vci")]
impl_safe_debug!(
    registry_platform_oid4vci::CredentialIssuerMetadata,
    registry_platform_oid4vci::CredentialOffer,
);

#[cfg(feature = "oid4vci")]
impl SafeDebug for registry_platform_oid4vci::NonceResponse {
    fn fmt_debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(feature = "oid4vci")]
impl SafeDebug for registry_platform_oid4vci::CredentialResponse {
    fn fmt_debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// HTTP response wrapper returned by all typed client methods.
///
/// The wrapper preserves selected response metadata captured before body
/// decoding. `Debug` uses [`SafeDebug`] to avoid accidental credential leaks for
/// sensitive body types.
#[derive(Clone)]
pub struct NotaryResponse<T> {
    /// Decoded response body.
    pub body: T,
    /// HTTP status returned by the server.
    pub status: StatusCode,
    /// Server `X-Request-Id`, when present.
    pub request_id: Option<String>,
    /// Server `Retry-After`, when present.
    pub retry_after: Option<RetryAfter>,
}

struct SafeDebugBody<'a, T>(&'a T);

impl<T: SafeDebug> fmt::Debug for SafeDebugBody<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt_debug(f)
    }
}

impl<T: SafeDebug> fmt::Debug for NotaryResponse<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotaryResponse")
            .field("body", &SafeDebugBody(&self.body))
            .field("status", &self.status)
            .field("request_id", &self.request_id)
            .field("retry_after", &self.retry_after)
            .finish()
    }
}

impl<T> NotaryResponse<T> {
    pub(crate) fn map<U>(self, body: U) -> NotaryResponse<U> {
        NotaryResponse {
            body,
            status: self.status,
            request_id: self.request_id,
            retry_after: self.retry_after,
        }
    }
}

/// Ergonomic wrapper over an evaluation response.
#[derive(Debug, Clone)]
pub struct Evaluation {
    /// Claim results returned by the server.
    pub results: Vec<ClaimResultView>,
}

impl Evaluation {
    /// Return the first result's evaluation id.
    #[must_use]
    pub fn evaluation_id(&self) -> Option<&str> {
        self.results
            .first()
            .map(|result| result.evaluation_id.as_str())
    }

    /// Return the first claim result.
    #[must_use]
    pub fn first_result(&self) -> Option<&ClaimResultView> {
        self.results.first()
    }

    /// Return the first result matching `claim_id`.
    #[must_use]
    pub fn result_for(&self, claim_id: &str) -> Option<&ClaimResultView> {
        self.results
            .iter()
            .find(|result| result.claim_id == claim_id)
    }
}

impl_safe_debug!(Evaluation);
