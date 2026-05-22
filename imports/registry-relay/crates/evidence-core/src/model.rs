// SPDX-License-Identifier: Apache-2.0
//! Evidence Server request, response, and view types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const FORMAT_CLAIM_RESULT_JSON: &str = "application/vnd.evidence-server.claim-result+json";
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
    pub items: Vec<BatchItemResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BatchItemResponse {
    Ok {
        subject_ref: String,
        evaluation_id: String,
        results: Vec<ClaimResultView>,
    },
    Error {
        subject_ref: String,
        code: &'static str,
        detail: &'static str,
    },
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
    pub format: String,
    pub enabled: bool,
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
    pub subject_id: String,
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
