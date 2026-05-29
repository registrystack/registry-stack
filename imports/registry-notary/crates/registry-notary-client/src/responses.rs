// SPDX-License-Identifier: Apache-2.0
//! Client-owned response DTOs and ergonomic wrappers.

use std::fmt;

use registry_notary_core::{BatchEvaluateResponse, BatchItemResponse, ClaimResultView};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub results: Vec<ClaimResultView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListClaimsResponse {
    pub data: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatsResponse {
    pub formats: Vec<registry_notary_core::EvidenceFormat>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialIssueResponse {
    pub credential_id: String,
    pub credential_profile: String,
    pub format: String,
    pub issuer: String,
    pub expires_at: String,
    pub credential: String,
    pub issuer_signed_jwt: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusResponse {
    pub credential_id: String,
    pub issuer: String,
    pub credential_profile: String,
    pub status: String,
    pub issued_at: String,
    pub expires_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialStatusUpdateRequest {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminReloadResponse {
    pub reloaded: bool,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
    pub checks: serde_json::Value,
}

impl_safe_debug!(
    EvaluateResponse,
    ListClaimsResponse,
    FormatsResponse,
    CredentialIssueResponse,
    CredentialStatusResponse,
    AdminReloadResponse,
    HealthResponse,
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

#[derive(Clone)]
pub struct NotaryResponse<T> {
    pub body: T,
    pub request_id: Option<String>,
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
            .field("request_id", &self.request_id)
            .field("retry_after", &self.retry_after)
            .finish()
    }
}

impl<T> NotaryResponse<T> {
    pub(crate) fn map<U>(self, body: U) -> NotaryResponse<U> {
        NotaryResponse {
            body,
            request_id: self.request_id,
            retry_after: self.retry_after,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Evaluation {
    pub results: Vec<ClaimResultView>,
}

impl Evaluation {
    #[must_use]
    pub fn evaluation_id(&self) -> Option<&str> {
        self.results
            .first()
            .map(|result| result.evaluation_id.as_str())
    }

    #[must_use]
    pub fn first_result(&self) -> Option<&ClaimResultView> {
        self.results.first()
    }

    #[must_use]
    pub fn result_for(&self, claim_id: &str) -> Option<&ClaimResultView> {
        self.results
            .iter()
            .find(|result| result.claim_id == claim_id)
    }
}

#[derive(Debug, Clone)]
pub struct BatchEvaluation {
    pub inner: BatchEvaluateResponse,
}

impl_safe_debug!(Evaluation, BatchEvaluation);

impl BatchEvaluation {
    pub fn succeeded(&self) -> impl Iterator<Item = &BatchItemResponse> {
        self.inner.items.iter().filter(|item| {
            matches!(
                item.status,
                registry_notary_core::BatchItemStatus::Succeeded
            )
        })
    }

    pub fn failed(&self) -> impl Iterator<Item = &BatchItemResponse> {
        self.inner
            .items
            .iter()
            .filter(|item| matches!(item.status, registry_notary_core::BatchItemStatus::Failed))
    }
}
