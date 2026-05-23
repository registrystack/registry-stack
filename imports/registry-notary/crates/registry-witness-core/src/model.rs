// SPDX-License-Identifier: Apache-2.0
//! Registry Witness request, response, and view types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const FORMAT_CLAIM_RESULT_JSON: &str = "application/vnd.registry-witness.claim-result+json";
pub const FORMAT_CCCEV_JSONLD: &str = "application/ld+json; profile=\"cccev\"";
pub const FORMAT_SD_JWT_VC: &str = "application/dc+sd-jwt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureProfile {
    Value,
    Predicate,
    Redacted,
}

impl DisclosureProfile {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "value" => Some(Self::Value),
            "predicate" => Some(Self::Predicate),
            "redacted" => Some(Self::Redacted),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Predicate => "predicate",
            Self::Redacted => "redacted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureDowngrade {
    Deny,
    Default,
    Redacted,
}

impl DisclosureDowngrade {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "deny" | "none" => Some(Self::Deny),
            "default" => Some(Self::Default),
            "redacted" => Some(Self::Redacted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    pub subject: SubjectRequest,
    pub claims: Vec<String>,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRequest {
    pub id: String,
    #[serde(default)]
    pub id_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchEvaluateRequest {
    pub subjects: Vec<SubjectRequest>,
    pub claims: Vec<String>,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub prefer: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchEvaluateResponse {
    pub batch_id: String,
    pub status: BatchStatus,
    pub claims: Vec<String>,
    pub items: Vec<BatchItemResponse>,
    pub summary: BatchSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Completed,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchSummary {
    pub succeeded: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchItemResponse {
    pub input_index: usize,
    pub subject_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_id: Option<String>,
    pub status: BatchItemStatus,
    pub claim_results: Vec<BatchClaimResultView>,
    pub errors: Vec<BatchItemError>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchItemStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchClaimResultView {
    pub result_id: String,
    pub claim_id: String,
    pub claim_version: String,
    pub value_type: String,
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub satisfied: Option<bool>,
    pub disclosure: String,
    pub provenance: ClaimProvenance,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchItemError {
    pub code: String,
    pub title: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenderRequest {
    pub evaluation_id: String,
    pub format: String,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub claims: Option<Vec<String>>,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIssueRequest {
    pub evaluation_id: String,
    #[serde(default)]
    pub credential_profile: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub claims: Option<Vec<String>>,
    #[serde(default)]
    pub disclosure: Option<String>,
    #[serde(default)]
    pub holder: Option<HolderRequest>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HolderRequest {
    #[serde(default)]
    pub binding: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIssueResponse {
    pub credential_id: String,
    pub format: String,
    pub issuer: String,
    pub expires_at: String,
    pub credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFormat {
    pub id: String,
    pub kind: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResultView {
    pub evaluation_id: String,
    pub claim_id: String,
    pub claim_version: String,
    pub subject_type: String,
    pub subject_ref: String,
    pub value: Option<Value>,
    pub satisfied: Option<bool>,
    pub disclosure: String,
    pub format: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub provenance: ClaimProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimProvenance {
    pub source_count: usize,
    pub source_versions: BTreeMap<String, String>,
    pub computed_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvaluation {
    pub client_id: String,
    pub purpose: String,
    pub claim_ids: Vec<String>,
    pub disclosure: String,
    pub format: String,
    pub results: Vec<ClaimResultView>,
    pub created_at: String,
    pub expires_at: String,
    pub request_hash: String,
}

#[derive(Debug, Clone)]
pub struct EvidencePrincipal {
    pub principal_id: String,
    pub scopes: Vec<String>,
}

impl EvidencePrincipal {
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|candidate| candidate == scope)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceAuditEvent {
    pub event_id: String,
    pub occurred_at: String,
    pub principal_id: Option<String>,
    pub decision: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub verification_id: Option<String>,
    pub claim_hash: Option<String>,
    pub row_count: Option<u64>,
    pub error_code: Option<String>,
}
