//! Source-neutral HTTP request and response contract.

use serde::{Deserialize, Serialize};

use crate::{HoldingSummary, IssuerPrincipal, Page, TeamRecord};

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
pub const REQUEST_LIMIT_OUT_OF_RANGE_PROBLEM: &str = "request.limit-out-of-range";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const RUNTIME_FAILURE_PROBLEM: &str = "runtime.failure";
pub const SERVICE_UNAVAILABLE_PROBLEM: &str = "service.unavailable";
pub const SOURCE_BAD_GATEWAY_PROBLEM: &str = "source.bad-gateway";
pub const SOURCE_PROFILE_NOT_APPLICABLE_PROBLEM: &str = "source-profile.not-applicable";
pub const SOURCE_PROFILE_REQUIRED_PROBLEM: &str = "source-profile.required";
pub const REVIEW_POLICY_MISMATCH_PROBLEM: &str = "review.policy-mismatch";
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
pub const HOLDINGS_PATH: &str = "/v1/holdings";
pub const DIRECTORY_PATH: &str = "/v1/directory";
pub const DIRECTORY_TARGETS_PATH: &str = "/v1/directory/targets";
pub const DESCRIPTION_PATH: &str = "/v1/casework";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum InboxView {
    Mine,
    MyTeams,
    TeamHoldings,
    Overdue,
    CompletedByMe,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum InboxSort {
    #[default]
    Due,
    Age,
    Type,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPageQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NextReviewTaskQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoldingsQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AbsencesQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum DirectoryTargetPurpose {
    Assignment,
    AbsencePerson,
    AbsenceCover,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimRequest {}

pub type ReleaseRequest = ClaimRequest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapDirectoryRequest {
    pub team_id: String,
    pub staff: Vec<IssuerPrincipal>,
    pub supervisors: Vec<IssuerPrincipal>,
    pub queue_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryTeamUpdateRequest {
    pub staff: Vec<crate::DirectoryMember>,
    pub supervisors: Vec<crate::DirectoryMember>,
    pub served_queues: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryResponse {
    pub revision: i64,
    pub teams: Vec<TeamRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Description {
    pub project_id: String,
    pub policy_version: String,
    pub queues: Vec<crate::QueueRecord>,
    pub review_policies: Vec<crate::ReviewPolicy>,
    pub context_providers: Vec<crate::ReviewContextProviderPolicy>,
    #[serde(default)]
    pub calendars: Vec<crate::CalendarPolicy>,
    #[serde(default)]
    pub clocks: Vec<crate::ClockPolicy>,
}

pub type HoldingsPage = Page<HoldingSummary>;
pub type DirectoryTargetPage = Page<crate::DirectoryMember>;

#[cfg(test)]
mod tests {
    use super::*;
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
            serde_json::from_value(serde_json::json!({"purpose": "absence-person"}))
                .expect("absence-person query decodes");
        absence_person
            .check()
            .expect("absence-person query validates");

        let absence_cover: DirectoryTargetsQuery = serde_json::from_value(serde_json::json!({
            "purpose": "absence-cover",
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
            serde_json::json!({"purpose": "absence-person", "queue": "review"}),
            serde_json::json!({
                "purpose": "absence-cover",
                "personIssuer": "https://identity.example"
            }),
            serde_json::json!({
                "purpose": "absence-cover",
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
