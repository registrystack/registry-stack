//! Live source answers, separate from authored display fields and persisted review state.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewContextAnswer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(length(max = 2000), extend("x-maximum-utf8-bytes" = 2000)))]
    pub text: Option<String>,
    #[cfg_attr(feature = "schema", schemars(length(max = 32)))]
    pub documents: Vec<ReviewAnswerDocument>,
    pub answered_at: DateTime<Utc>,
}

impl std::fmt::Debug for ReviewContextAnswer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReviewContextAnswer")
            .field("text", &"<redacted>")
            .field("document_count", &self.documents.len())
            .field("answered_at", &self.answered_at)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewAnswerDocument {
    pub id: String,
    #[cfg_attr(feature = "schema", schemars(regex(pattern = "^[0-9a-f]{64}$")))]
    pub sha256: String,
    pub content_type: String,
    pub byte_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<ReviewAnswerDownload>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewAnswerDownload {
    #[cfg_attr(feature = "schema", schemars(regex(pattern = "^GET$")))]
    pub method: String,
    pub operation: String,
    pub access_profile: String,
    pub path: String,
}
