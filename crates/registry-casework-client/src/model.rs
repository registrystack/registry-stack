use std::fmt;

use registry_platform_httputil::client::BearerToken;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication and explicit profile selection for exactly one call.
///
/// The client borrows the token, attaches it to one request, and never retains
/// it in client state or a recovery object.
pub struct CaseworkAuth<'a> {
    pub token: &'a BearerToken,
    pub profile: &'a str,
    pub source_profile: Option<&'a str>,
}

impl<'a> CaseworkAuth<'a> {
    #[must_use]
    pub fn new(token: &'a BearerToken, profile: &'a str) -> Self {
        Self {
            token,
            profile,
            source_profile: None,
        }
    }

    #[must_use]
    pub fn with_source_profile(mut self, source_profile: &'a str) -> Self {
        self.source_profile = Some(source_profile);
        self
    }
}

impl fmt::Debug for CaseworkAuth<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaseworkAuth")
            .field("token", &"<redacted>")
            .field("profile", &"<selected>")
            .field("source_profile", &self.source_profile.map(|_| "<selected>"))
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkComplete<T> {
    pub value: T,
    pub trace_id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPageQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Pagination for source work-item history, whose cursor is an opaque source
/// continuation rather than a unified review event identifier.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkItemHistoryQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskDecisionRequest {
    pub decision: registry_casework_core::ReviewerDecisionKind,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReviewResultResponse {
    Available(Box<CaseworkComplete<registry_casework_core::ReviewResult>>),
    Pending { trace_id: String },
    ConcealedOrUnknown { trace_id: String },
    Expired { trace_id: String },
}
