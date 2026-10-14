//! Bounded review staffing contracts. Selectors never create authority.
use crate::{ContentDigest, IssuerPrincipal, ReviewTaskOwnership, SubjectBinding};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReviewTaskSort {
    #[default]
    Due,
    Subject,
    Reference,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewStaffingQuery {
    pub queue: Option<String>,
    pub ownership: Option<ReviewTaskOwnership>,
    pub subject_source: Option<String>,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub subject_version: Option<String>,
    pub subject_digest: Option<ContentDigest>,
    pub reference: Option<String>,
    #[serde(default)]
    pub sort: ReviewTaskSort,
    pub cursor: Option<Uuid>,
    pub limit: Option<usize>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the review staffing request is invalid")]
pub struct ReviewStaffingError;
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
impl ReviewStaffingQuery {
    pub fn check(&self) -> Result<(), ReviewStaffingError> {
        let n = [
            self.subject_source.is_some(),
            self.subject_type.is_some(),
            self.subject_id.is_some(),
            self.subject_version.is_some(),
            self.subject_digest.is_some(),
        ]
        .into_iter()
        .filter(|v| *v)
        .count();
        if n != 0 && n != 5
            || self.limit.is_some_and(|n| n == 0 || n > 100)
            || [
                &self.queue,
                &self.subject_source,
                &self.subject_type,
                &self.subject_id,
                &self.subject_version,
            ]
            .into_iter()
            .flatten()
            .any(|s| !text(s, 128))
            || self.reference.as_ref().is_some_and(|s| !text(s, 256))
        {
            return Err(ReviewStaffingError);
        }
        Ok(())
    }
    pub fn subject(&self) -> Result<Option<SubjectBinding>, ReviewStaffingError> {
        self.check()?;
        Ok(
            match (
                &self.subject_source,
                &self.subject_type,
                &self.subject_id,
                &self.subject_version,
                &self.subject_digest,
            ) {
                (Some(source), Some(subject_type), Some(id), Some(version), Some(digest)) => {
                    Some(SubjectBinding {
                        source: source.clone(),
                        subject_type: subject_type.clone(),
                        id: id.clone(),
                        version: version.clone(),
                        digest: digest.clone(),
                    })
                }
                _ => None,
            },
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCaseloadMoveRequest {
    pub from: IssuerPrincipal,
    pub to: IssuerPrincipal,
    pub queue: Option<String>,
    pub reason: String,
}
impl ReviewCaseloadMoveRequest {
    pub fn check(&self) -> Result<(), ReviewStaffingError> {
        if self.from == self.to
            || !text(&self.reason, 2000)
            || [
                &self.from.issuer,
                &self.from.subject,
                &self.to.issuer,
                &self.to.subject,
            ]
            .into_iter()
            .any(|s| !text(s, 2048))
            || self.queue.as_ref().is_some_and(|s| !text(s, 128))
        {
            Err(ReviewStaffingError)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCaseloadTask {
    pub task_id: Uuid,
    pub revision: i64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCaseloadPreview {
    pub preview_id: Uuid,
    pub directory_revision: i64,
    pub tasks: Vec<ReviewCaseloadTask>,
    pub expires_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCaseloadApplyRequest {
    pub preview_id: Uuid,
}
impl ReviewCaseloadApplyRequest {
    pub fn check(&self) -> Result<(), ReviewStaffingError> {
        if self.preview_id.is_nil() {
            Err(ReviewStaffingError)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCaseloadResult {
    pub moved: Vec<ReviewCaseloadTask>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewClockRecomputeRequest {
    pub task_ids: Vec<Uuid>,
}
impl ReviewClockRecomputeRequest {
    pub fn check(&self) -> Result<(), ReviewStaffingError> {
        let unique: std::collections::BTreeSet<_> = self.task_ids.iter().collect();
        if self.task_ids.is_empty()
            || self.task_ids.len() > 100
            || unique.len() != self.task_ids.len()
            || self.task_ids.iter().any(Uuid::is_nil)
        {
            Err(ReviewStaffingError)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewClockRecomputeTask {
    pub task_id: Uuid,
    pub revision: i64,
    pub deadline_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewClockRecomputePreview {
    pub preview_id: Uuid,
    pub directory_revision: i64,
    pub tasks: Vec<ReviewClockRecomputeTask>,
    pub expires_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewClockRecomputeApplyRequest {
    pub preview_id: Uuid,
}
impl ReviewClockRecomputeApplyRequest {
    pub fn check(&self) -> Result<(), ReviewStaffingError> {
        if self.preview_id.is_nil() {
            Err(ReviewStaffingError)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewClockRecomputeResult {
    pub tasks: Vec<ReviewClockRecomputeTask>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_subject_filter_rejects_partial_binding() {
        let q = ReviewStaffingQuery {
            subject_id: Some("canary".into()),
            ..Default::default()
        };
        assert!(q.check().is_err());
        assert!(ReviewStaffingQuery::default().check().is_ok());
    }
    #[test]
    fn recompute_refuses_duplicates() {
        let id = Uuid::new_v4();
        assert!(ReviewClockRecomputeRequest {
            task_ids: vec![id, id]
        }
        .check()
        .is_err());
    }
}
