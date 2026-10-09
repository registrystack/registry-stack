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

impl<T> From<registry_review_client::ReviewComplete<T>> for CaseworkComplete<T> {
    fn from(value: registry_review_client::ReviewComplete<T>) -> Self {
        Self {
            value: value.value,
            trace_id: value.trace_id,
        }
    }
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
    pub ownership: Option<registry_casework_core::ReviewTaskOwnership>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Bounded supervisory discovery over the queues the selected profile serves.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupervisoryReviewTaskQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// Exact canonical request selection, applied before pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
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

#[cfg(test)]
mod tests {
    use super::{ReviewTaskQuery, SupervisoryReviewTaskQuery};
    use registry_casework_core::ReviewTaskOwnership;
    use serde_json::json;

    #[test]
    fn reviewer_ownership_uses_the_closed_wire_names() {
        let query = ReviewTaskQuery {
            ownership: Some(ReviewTaskOwnership::AssignedToMe),
            ..ReviewTaskQuery::default()
        };
        assert_eq!(
            serde_json::to_value(query).expect("serialize query"),
            json!({"ownership": "assigned_to_me"})
        );
        assert!(serde_json::from_value::<ReviewTaskQuery>(json!({
            "ownership": "someone_elses"
        }))
        .is_err());
    }

    #[test]
    fn supervisory_query_has_no_ownership_selector() {
        assert!(serde_json::from_value::<SupervisoryReviewTaskQuery>(json!({
            "ownership": "unclaimed"
        }))
        .is_err());
    }

    #[test]
    fn supervisory_request_selection_uses_a_canonical_uuid() {
        let request_id = uuid::Uuid::from_u128(9);
        let query = SupervisoryReviewTaskQuery {
            request_id: Some(request_id),
            ..Default::default()
        };
        let wire = json!({"requestId": "00000000-0000-0000-0000-000000000009"});
        assert_eq!(serde_json::to_value(&query).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<SupervisoryReviewTaskQuery>(wire).unwrap(),
            query
        );
        for invalid in [
            json!(""),
            json!("not-a-uuid"),
            json!(42),
            json!({}),
            json!([]),
        ] {
            assert!(serde_json::from_value::<SupervisoryReviewTaskQuery>(json!({
                "requestId": invalid
            }))
            .is_err());
        }
    }
}
