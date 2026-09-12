//! Source-neutral HTTP request and response contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AttemptStatus, Draft, HoldingSummary, IssuerPrincipal, OperationName, Page, SourceBinding,
    SubjectRef, TeamRecord, WorkItem,
};

pub const CASEWORK_PROFILE_HEADER: &str = "registry-casework-profile";
pub const SOURCE_PROFILE_HEADER: &str = "registry-source-profile";
/// Prefix for every public Registry Casework problem type URI.
pub const CASEWORK_PROBLEM_TYPE_BASE: &str =
    "https://id.registrystack.org/problems/registry-casework/";
pub const ABSENCE_COVER_CYCLE_PROBLEM: &str = "absence.cover-cycle";
pub const ABSENCE_INVALID_PERIOD_PROBLEM: &str = "absence.invalid-period";
pub const ABSENCE_OVERLAP_PROBLEM: &str = "absence.overlap";
pub const ABSENCE_SELF_COVER_PROBLEM: &str = "absence.self-cover";
pub const AUTHENTICATION_REFUSED_PROBLEM: &str = "authentication.refused";
pub const CLOCK_RECOMPUTE_PREVIEW_EXPIRED_PROBLEM: &str = "clock.recompute-preview-expired";
pub const CURSOR_EXPIRED_PROBLEM: &str = "cursor.expired";
pub const CURSOR_INVALID_PROBLEM: &str = "cursor.invalid";
pub const IDEMPOTENCY_EXPIRED_PROBLEM: &str = "idempotency.expired";
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
pub const REQUEST_REASON_UNSUPPORTED_PROBLEM: &str = "request.reason-unsupported";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const RUNTIME_FAILURE_PROBLEM: &str = "runtime.failure";
pub const SERVICE_UNAVAILABLE_PROBLEM: &str = "service.unavailable";
pub const SOURCE_BAD_GATEWAY_PROBLEM: &str = "source.bad-gateway";
pub const SOURCE_NOT_FOUND_PROBLEM: &str = "source.not-found";
pub const SOURCE_PROFILE_NOT_APPLICABLE_PROBLEM: &str = "source-profile.not-applicable";
pub const SOURCE_PROFILE_REQUIRED_PROBLEM: &str = "source-profile.required";
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
/// Carries a bounded JSON path only on an entitled request-validation problem.
pub const VALIDATION_PATH_HEADER: &str = "registry-casework-validation-path";
/// Carries a closed, value-free validation reason beside `VALIDATION_PATH_HEADER`.
pub const VALIDATION_REASON_HEADER: &str = "registry-casework-validation-reason";
pub const MAXIMUM_CASEWORK_PROFILE_BYTES: usize = 128;
pub const MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES: usize = 128;
pub const MAXIMUM_DIRECTORY_IDENTIFIER_BYTES: usize = 128;
pub const MAXIMUM_DIRECTORY_PRINCIPALS: usize = 100;
pub const MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES: usize = 2_048;
pub const MAXIMUM_DIRECTORY_DISPLAY_NAME_BYTES: usize = 500;
pub const MAXIMUM_DIRECTORY_SERVED_QUEUES: usize = 100;
pub const WORK_ITEMS_PATH: &str = "/v1/work-items";
pub const HOSTED_ITEMS_PATH: &str = "/v1/hosted-items";
pub const HOSTED_TERMINAL_PATH: &str = "/v1/hosted-items/terminal";
pub const HOSTED_ACCOUNTABILITY_PATH: &str = "/v1/hosted-accountability";
pub const NEXT_WORK_ITEM_PATH: &str = "/v1/work-items/next";
pub const HOLDINGS_PATH: &str = "/v1/holdings";
pub const DIRECTORY_PATH: &str = "/v1/directory";
pub const DIRECTORY_TARGETS_PATH: &str = "/v1/directory/targets";
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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxSort {
    #[default]
    Due,
    Age,
    Type,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListWorkItemsQuery {
    pub view: InboxView,
    #[serde(default)]
    pub sort: InboxSort,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Exact, case-sensitive match on an explicitly configured source field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubjectSelectorError {
    #[error("the subject selector must provide all three components")]
    Incomplete,
    #[error("a subject selector component is invalid")]
    InvalidComponent,
}

impl ListWorkItemsQuery {
    /// Returns the exact source-neutral subject selector, when supplied.
    ///
    /// The three wire fields are kept flat for query-string interoperability,
    /// but partial selectors are never interpreted as broader searches.
    pub fn subject(&self) -> Result<Option<SubjectRef>, SubjectSelectorError> {
        if self.reference.is_some()
            && (self.source_id.is_some()
                || self.subject_kind.is_some()
                || self.subject_id.is_some())
        {
            return Err(SubjectSelectorError::Incomplete);
        }
        match (&self.source_id, &self.subject_kind, &self.subject_id) {
            (None, None, None) => Ok(None),
            (Some(source_id), Some(kind), Some(id)) => {
                if [source_id, kind, id]
                    .into_iter()
                    .any(|value| value.is_empty())
                {
                    return Err(SubjectSelectorError::InvalidComponent);
                }
                Ok(Some(SubjectRef {
                    source_id: source_id.clone(),
                    kind: kind.clone(),
                    id: id.clone(),
                }))
            }
            _ => Err(SubjectSelectorError::Incomplete),
        }
    }

    pub fn reference(&self) -> Result<Option<&str>, SubjectSelectorError> {
        self.reference
            .as_deref()
            .map(|value| {
                if value.is_empty()
                    || value.chars().count() > 512
                    || value.chars().any(char::is_control)
                {
                    Err(SubjectSelectorError::InvalidComponent)
                } else {
                    Ok(value)
                }
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedTerminalQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedPageQuery {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbsencesQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryTargetPurpose {
    Assignment,
    AbsencePerson,
    AbsenceCover,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryTargetsQuery {
    pub purpose: DirectoryTargetPurpose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DirectoryTargetsQueryError {
    #[error("the directory target query fields do not match its purpose")]
    Combination,
    #[error("a directory target query value is invalid")]
    Value,
}

impl DirectoryTargetsQuery {
    pub fn check(&self) -> Result<(), DirectoryTargetsQueryError> {
        match self.purpose {
            DirectoryTargetPurpose::Assignment => {
                if self.person_issuer.is_some() || self.person_subject.is_some() {
                    return Err(DirectoryTargetsQueryError::Combination);
                }
                if self.queue.as_deref().is_none_or(str::is_empty) {
                    return Err(DirectoryTargetsQueryError::Value);
                }
            }
            DirectoryTargetPurpose::AbsencePerson => {
                if self.queue.is_some()
                    || self.person_issuer.is_some()
                    || self.person_subject.is_some()
                {
                    return Err(DirectoryTargetsQueryError::Combination);
                }
            }
            DirectoryTargetPurpose::AbsenceCover => {
                if self.queue.is_some() {
                    return Err(DirectoryTargetsQueryError::Combination);
                }
                let Some(person) = self.person() else {
                    return Err(DirectoryTargetsQueryError::Combination);
                };
                if !valid_directory_principal(&person) {
                    return Err(DirectoryTargetsQueryError::Value);
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn person(&self) -> Option<IssuerPrincipal> {
        self.person_issuer
            .as_ref()
            .zip(self.person_subject.as_ref())
            .map(|(issuer, subject)| IssuerPrincipal {
                issuer: issuer.clone(),
                subject: subject.clone(),
            })
    }
}

fn valid_directory_principal(person: &IssuerPrincipal) -> bool {
    !person.issuer.is_empty()
        && person.issuer.len() <= MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES
        && !person.issuer.chars().any(char::is_control)
        && !person.subject.is_empty()
        && person.subject.len() <= MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES
        && !person.subject.chars().any(char::is_control)
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
pub struct DirectoryTeamUpdateRequest {
    pub staff: Vec<crate::DirectoryMember>,
    pub supervisors: Vec<crate::DirectoryMember>,
    pub served_queues: Vec<String>,
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
    #[serde(default)]
    pub calendars: Vec<crate::CalendarPolicy>,
    #[serde(default)]
    pub clocks: Vec<crate::ClockPolicy>,
    #[serde(default)]
    pub hosted_kinds: Vec<crate::HostedKindPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkItemPage {
    pub items: Vec<WorkItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub status: crate::PageStatus,
    pub served_queues: Vec<String>,
}

pub type HoldingsPage = Page<HoldingSummary>;
pub type DirectoryTargetPage = Page<crate::DirectoryMember>;
pub type HistoryPage = Page<crate::HistoryEntry>;
pub type HostedNotePage = Page<crate::HostedNote>;
pub type HostedHistoryPage = Page<HostedHistoryEntry>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedHistoryKind {
    Created,
    Claimed,
    Assigned,
    Delegated,
    CaseloadMoved,
    Released,
    NoteAdded,
    Completed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedHistoryEntry {
    pub event_id: Uuid,
    pub item_id: Uuid,
    pub item_revision: i64,
    pub kind: HostedHistoryKind,
    pub occurred_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<crate::OpaqueActorRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment: Option<crate::AssignmentContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ItemPath {
    pub item_id: Uuid,
}

pub type HostedItemPath = ItemPath;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedAccountabilityPath {
    pub event_id: Uuid,
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

    #[test]
    fn list_query_requires_one_complete_subject_selector() {
        let exact: ListWorkItemsQuery = serde_json::from_value(serde_json::json!({
            "view": "my_teams",
            "sourceId": "source-one",
            "subjectKind": "resident-record",
            "subjectId": "human reference 42"
        }))
        .expect("complete selector decodes");
        assert_eq!(
            exact.subject().expect("complete selector validates"),
            Some(SubjectRef {
                source_id: "source-one".to_owned(),
                kind: "resident-record".to_owned(),
                id: "human reference 42".to_owned(),
            })
        );

        for invalid in [
            serde_json::json!({"view": "my_teams", "sourceId": "source-one"}),
            serde_json::json!({
                "view": "my_teams",
                "sourceId": "source-one",
                "subjectKind": "resident-record",
                "subjectId": ""
            }),
        ] {
            let query: ListWorkItemsQuery =
                serde_json::from_value(invalid).expect("wire shape decodes");
            assert!(query.subject().is_err());
        }

        let long_source_id = "s".repeat(512);
        let admitted: ListWorkItemsQuery = serde_json::from_value(serde_json::json!({
            "view": "my_teams",
            "sourceId": long_source_id,
            "subjectKind": "resident-record",
            "subjectId": "00000000-0000-4000-8000-000000000001"
        }))
        .expect("the admitted selector decodes");
        assert_eq!(
            admitted
                .subject()
                .expect("the query adds no narrower component ceiling")
                .expect("the selector is present")
                .source_id
                .len(),
            512
        );
    }

    #[test]
    fn list_query_binds_exact_reference_and_closed_sort_values() {
        let query: ListWorkItemsQuery = serde_json::from_value(serde_json::json!({
            "view": "my_teams",
            "sort": "type",
            "reference": "案件-42"
        }))
        .expect("reference query decodes");
        assert_eq!(query.sort, InboxSort::Type);
        assert_eq!(query.reference().unwrap(), Some("案件-42"));
        assert_eq!(query.subject().unwrap(), None);

        for invalid in [
            serde_json::json!({
                "view": "my_teams",
                "reference": "CASE-42",
                "sourceId": "source-one",
                "subjectKind": "resident-record",
                "subjectId": "42"
            }),
            serde_json::json!({"view": "my_teams", "reference": ""}),
            serde_json::json!({"view": "my_teams", "reference": "x\ny"}),
        ] {
            let query: ListWorkItemsQuery =
                serde_json::from_value(invalid).expect("wire shape decodes");
            assert!(query.subject().is_err() || query.reference().is_err());
        }
        let too_long: String = std::iter::repeat_n('案', 513).collect();
        let query: ListWorkItemsQuery = serde_json::from_value(serde_json::json!({
            "view": "my_teams",
            "reference": too_long
        }))
        .expect("wire shape decodes");
        assert!(query.reference().is_err());
        assert!(
            serde_json::from_value::<ListWorkItemsQuery>(serde_json::json!({
                "view": "my_teams",
                "sort": "unknown"
            }))
            .is_err()
        );
    }

    #[test]
    fn work_item_page_always_carries_the_current_served_queues() {
        let page = WorkItemPage {
            items: Vec::new(),
            next_cursor: None,
            status: crate::PageStatus::Complete,
            served_queues: Vec::new(),
        };
        let wire = serde_json::to_value(page).expect("page serializes");
        assert_eq!(wire["servedQueues"], serde_json::json!([]));
        assert!(wire.get("nextCursor").is_none());
        assert!(serde_json::from_value::<WorkItemPage>(serde_json::json!({
            "items": [],
            "status": "complete"
        }))
        .is_err());
    }

    #[test]
    fn directory_target_query_fields_are_bound_to_their_purpose() {
        let assignment: DirectoryTargetsQuery = serde_json::from_value(serde_json::json!({
            "purpose": "assignment",
            "queue": "review"
        }))
        .expect("assignment query decodes");
        assignment.check().expect("assignment query validates");
        assert_eq!(assignment.person(), None);

        let absence_person: DirectoryTargetsQuery =
            serde_json::from_value(serde_json::json!({"purpose": "absence_person"}))
                .expect("absence-person query decodes");
        absence_person
            .check()
            .expect("absence-person query validates");

        let absence_cover: DirectoryTargetsQuery = serde_json::from_value(serde_json::json!({
            "purpose": "absence_cover",
            "personIssuer": "https://identity.example",
            "personSubject": "officer-one"
        }))
        .expect("absence-cover query decodes");
        absence_cover
            .check()
            .expect("absence-cover query validates");
        assert_eq!(
            absence_cover.person(),
            Some(IssuerPrincipal {
                issuer: "https://identity.example".to_owned(),
                subject: "officer-one".to_owned(),
            })
        );

        for invalid in [
            serde_json::json!({"purpose": "assignment"}),
            serde_json::json!({"purpose": "assignment", "queue": ""}),
            serde_json::json!({
                "purpose": "assignment",
                "queue": "review",
                "personIssuer": "https://identity.example",
                "personSubject": "officer-one"
            }),
            serde_json::json!({"purpose": "absence_person", "queue": "review"}),
            serde_json::json!({
                "purpose": "absence_cover",
                "personIssuer": "https://identity.example"
            }),
            serde_json::json!({
                "purpose": "absence_cover",
                "personIssuer": "",
                "personSubject": "officer-one"
            }),
        ] {
            let query: DirectoryTargetsQuery =
                serde_json::from_value(invalid).expect("wire shape decodes");
            assert!(query.check().is_err());
        }
    }
}
