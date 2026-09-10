//! Source-neutral HTTP request and response contract.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AttemptStatus, Draft, HoldingSummary, IssuerPrincipal, OperationName, Page, SourceBinding,
    TeamRecord, WorkItem,
};

pub const CASEWORK_PROFILE_HEADER: &str = "registry-casework-profile";
pub const SOURCE_PROFILE_HEADER: &str = "registry-source-profile";
/// Prefix for every public Registry Casework problem type URI.
pub const CASEWORK_PROBLEM_TYPE_BASE: &str =
    "https://id.registrystack.org/problems/registry-casework/";
pub const AUTHENTICATION_REFUSED_PROBLEM: &str = "authentication.refused";
pub const IDEMPOTENCY_KEY_REUSED_PROBLEM: &str = "idempotency.key-reused";
pub const OPERATION_NOT_AUTHORIZED_PROBLEM: &str = "operation.not-authorized";
pub const PRECONDITION_FAILED_PROBLEM: &str = "precondition.failed";
pub const PRECONDITION_REQUIRED_PROBLEM: &str = "precondition.required";
pub const PROFILE_NOT_AUTHORIZED_PROBLEM: &str = "profile.not-authorized";
pub const PROFILE_NOT_HUMAN_PROBLEM: &str = "profile.not-human";
pub const REQUEST_BODY_TOO_LARGE_PROBLEM: &str = "request.body-too-large";
pub const REQUEST_INVALID_PROBLEM: &str = "request.invalid";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const RUNTIME_FAILURE_PROBLEM: &str = "runtime.failure";
pub const SERVICE_UNAVAILABLE_PROBLEM: &str = "service.unavailable";
pub const SOURCE_BAD_GATEWAY_PROBLEM: &str = "source.bad-gateway";
pub const SOURCE_NOT_FOUND_PROBLEM: &str = "source.not-found";
pub const SOURCE_SIGNATURE_INVALID_PROBLEM: &str = "source.signature-invalid";
pub const WORK_ITEM_ALREADY_CLAIMED_PROBLEM: &str = "work-item.already-claimed";
pub const WORK_ITEM_NOT_HOLDER_PROBLEM: &str = "work-item.not-holder";
pub const WORK_ITEM_NOT_OFFERED_PROBLEM: &str = "work-item.not-offered";
pub const WORK_ITEM_NOT_VISIBLE_PROBLEM: &str = "work-item.not-visible";
pub const WORK_ITEM_PROPOSAL_CHANGED_PROBLEM: &str = "work-item.proposal-changed";
pub const WORK_ITEM_RECOVERY_PENDING_PROBLEM: &str = "work-item.recovery-pending";
pub const WORK_ITEM_SOURCE_UNAVAILABLE_PROBLEM: &str = "work-item.source-unavailable";
pub const WORK_ITEM_SUPERSEDED_PROBLEM: &str = "work-item.superseded";
/// Carries the original durable attempt UUID only on an entitled
/// `work-item.recovery-pending` response.
pub const ATTEMPT_REFERENCE_HEADER: &str = "registry-casework-attempt";
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
pub const IF_MATCH_HEADER: &str = "if-match";
pub const MAXIMUM_CASEWORK_PROFILE_BYTES: usize = 128;
pub const MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub const WORK_ITEMS_PATH: &str = "/v1/work-items";
pub const NEXT_WORK_ITEM_PATH: &str = "/v1/work-items/next";
pub const HOLDINGS_PATH: &str = "/v1/holdings";
pub const DIRECTORY_PATH: &str = "/v1/directory";
pub const DESCRIPTION_PATH: &str = "/v1/casework";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxView {
    Mine,
    MyTeams,
    TeamHoldings,
    Overdue,
    CompletedByMe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListWorkItemsQuery {
    pub view: InboxView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NextWorkItemQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoldingsQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimRequest {}

pub type ReleaseRequest = ClaimRequest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SaveDraftRequest {
    pub binding: SourceBinding,
    pub reason: String,
    #[serde(default)]
    pub flagged_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecideRequest {
    pub displayed_binding: SourceBinding,
    pub source_profile_id: String,
    pub operation: OperationName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub flagged_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverAttemptRequest {
    pub source_profile_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationResponse {
    pub item: WorkItem,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<AttemptStatus>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapDirectoryRequest {
    pub team_id: String,
    pub staff: Vec<IssuerPrincipal>,
    pub supervisors: Vec<IssuerPrincipal>,
    pub queue_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryResponse {
    pub revision: i64,
    pub teams: Vec<TeamRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Description {
    pub project_id: String,
    pub policy_version: String,
    pub queues: Vec<crate::QueueRecord>,
    pub sources: Vec<crate::SourcePolicy>,
}

pub type WorkItemPage = Page<WorkItem>;
pub type HoldingsPage = Page<HoldingSummary>;
pub type HistoryPage = Page<crate::HistoryEntry>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ItemPath {
    pub item_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptPath {
    pub item_id: Uuid,
    pub attempt_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DraftResponse {
    pub draft: Draft,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_contract_rejects_unknown_fields() {
        let body = r#"{
            "expectedRevision": 2,
            "displayedBinding": {
                "sourceRevision": "4",
                "version": "proposal-2",
                "integrity": "sha256:abc",
                "generation": "package-a"
            },
            "sourceProfileId": "reviewer",
            "operation": "approve",
            "surprise": true
        }"#;
        assert!(serde_json::from_str::<DecideRequest>(body).is_err());
    }
}
