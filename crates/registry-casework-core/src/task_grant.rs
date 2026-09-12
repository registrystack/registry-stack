//! Governed task delegation policy and immutable source-bound authorization.
use crate::{
    CaseworkProject, CaseworkRole, IssuerPrincipal, OccurrenceState, SourceBinding, SubjectRef,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use thiserror::Error;
use uuid::Uuid;

pub const TASK_GRANT_LIFETIME_SECONDS: u64 = 900;
pub const TASK_ASSERTION_LIFETIME_SECONDS: u64 = 60;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskTemplate {
    pub id: String,
    pub version: String,
    pub label: String,
    pub eligible_teams: Vec<String>,
    pub eligible_profiles: Vec<String>,
    pub source: String,
    pub item_kinds: Vec<String>,
    pub item_states: Vec<OccurrenceState>,
    pub agent: IssuerPrincipal,
    pub client: String,
    pub resource: String,
    pub purpose: String,
    pub bounds: TaskGrantBounds,
    /// Exact token identity keys mapped to governed source logical fields.
    /// Values are extracted from the approving caller's disclosed source read.
    pub subjects: BTreeMap<String, String>,
    pub lifetime_seconds: u64,
}

impl fmt::Debug for TaskTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskTemplate")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskGrantBounds {
    Evidence { requirement: String },
    Breg { permissions: Vec<TaskPermission> },
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskPermission {
    pub collection: String,
    pub operations: Vec<String>,
}

impl TaskGrantBounds {
    pub fn check(&self) -> Result<(), TaskGrantError> {
        match self {
            Self::Evidence { requirement } if bounded(requirement, 512) => Ok(()),
            Self::Breg { permissions } if !permissions.is_empty() && permissions.len() <= 64 => {
                let mut collections = BTreeSet::new();
                for permission in permissions {
                    if !bounded(&permission.collection, 512)
                        || !collections.insert(&permission.collection)
                        || !unique(&permission.operations, 32)
                        || permission
                            .operations
                            .iter()
                            .any(|op| !op.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'))
                    {
                        return Err(TaskGrantError::Policy);
                    }
                }
                Ok(())
            }
            _ => Err(TaskGrantError::Policy),
        }
    }
}

impl TaskTemplate {
    pub fn check(&self, project: &CaseworkProject) -> Result<(), TaskGrantError> {
        let source = project
            .sources
            .iter()
            .find(|source| source.id == self.source)
            .ok_or(TaskGrantError::Policy)?;
        if !crate::valid_directory_identifier(&self.id)
            || !bounded(&self.version, 128)
            || !bounded(&self.label, 160)
            || !unique(&self.eligible_teams, 32)
            || self
                .eligible_teams
                .iter()
                .any(|team| !crate::valid_directory_identifier(team))
            || !unique(&self.eligible_profiles, 32)
            || self.eligible_profiles.iter().any(|id| {
                !project.access_profiles.iter().any(|profile| {
                    profile.id == *id
                        && matches!(profile.role, CaseworkRole::Staff | CaseworkRole::Supervisor)
                })
            })
            || !unique(&self.item_kinds, 32)
            || self.item_kinds.iter().any(|kind| {
                !source
                    .requests
                    .iter()
                    .any(|request| request.entity == *kind)
            })
            || self.item_states.is_empty()
            || self.item_states.len() > 4
            || self.item_states.iter().any(|state| {
                !matches!(
                    state,
                    OccurrenceState::Claimed
                        | OccurrenceState::WaitingApplicant
                        | OccurrenceState::WaitingApplication
                )
            })
            || self
                .item_states
                .iter()
                .enumerate()
                .any(|(index, state)| self.item_states[..index].contains(state))
            || !bounded(&self.agent.issuer, 512)
            || !bounded(&self.agent.subject, 512)
            || !bounded(&self.client, 512)
            || !bounded(&self.resource, 512)
            || !bounded(&self.purpose, 128)
            || self.purpose.bytes().any(|byte| {
                !(byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b':' | b'.'))
            })
            || self.subjects.is_empty()
            || self.subjects.len() > 32
            || self.subjects.iter().any(|(claim, field)| {
                !crate::valid_directory_identifier(claim) || !bounded(field, 128)
            })
            || self.lifetime_seconds == 0
            || self.lifetime_seconds > TASK_GRANT_LIFETIME_SECONDS
        {
            return Err(TaskGrantError::Policy);
        }
        self.bounds.check()
    }

    pub fn disclosed_subjects(
        &self,
        disclosed: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>, TaskGrantError> {
        self.subjects
            .iter()
            .map(|(claim, field)| {
                let value = disclosed.get(field).ok_or(TaskGrantError::Subjects)?;
                match value {
                    Value::String(value) if bounded(value, 512) => (),
                    Value::Bool(_) => (),
                    Value::Number(number)
                        if number.as_i64().is_some() || number.as_u64().is_some() => {}
                    _ => return Err(TaskGrantError::Subjects),
                }
                Ok((claim.clone(), value.clone()))
            })
            .collect()
    }
}

/// Ephemeral exact values from one source read. Never serialized as a work-item view.
pub struct TaskSubjectContext {
    pub binding: SourceBinding,
    pub values: BTreeMap<String, Value>,
}
impl fmt::Debug for TaskSubjectContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TaskSubjectContext(<redacted>)")
    }
}

/// Proposal identity excludes ordinary source revision churn.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskProposalIdentity {
    pub version: String,
    pub integrity: Option<String>,
    pub generation: String,
}
impl From<&SourceBinding> for TaskProposalIdentity {
    fn from(binding: &SourceBinding) -> Self {
        Self {
            version: binding.version.clone(),
            integrity: binding.integrity.clone(),
            generation: binding.generation.clone(),
        }
    }
}

/// Protected persisted record. No bearer or client private key is retained.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrant {
    pub id: Uuid,
    pub item_id: Uuid,
    pub template: TaskTemplate,
    pub authority: String,
    pub source_issuer: String,
    pub approver: IssuerPrincipal,
    pub approver_profile: String,
    pub source_subject: SubjectRef,
    pub proposal: TaskProposalIdentity,
    pub subjects: BTreeMap<String, Value>,
    pub approved_at: u64,
    pub expires_at: u64,
}
impl fmt::Debug for TaskGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskGrant")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskApprovalRequest {
    pub template_id: String,
    pub template_version: String,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TaskGrantError {
    #[error("the governed task template is invalid")]
    Policy,
    #[error("the required task subject is not disclosed as a bounded scalar")]
    Subjects,
}
fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && !value.contains('*')
}
fn unique(values: &[String], maximum: usize) -> bool {
    !values.is_empty()
        && values.len() <= maximum
        && values.iter().all(|value| bounded(value, 512))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proposal_identity_ignores_only_mutable_source_revision() {
        let binding = SourceBinding {
            source_revision: "before".into(),
            version: "proposal-1".into(),
            integrity: Some("digest".into()),
            generation: "source-1".into(),
        };
        let mut next = binding.clone();
        next.source_revision = "after".into();
        assert!(TaskProposalIdentity::from(&binding) == TaskProposalIdentity::from(&next));
        next.version = "proposal-2".into();
        assert!(TaskProposalIdentity::from(&binding) != TaskProposalIdentity::from(&next));
    }
    #[test]
    fn exact_bounds_reject_wildcards_duplicate_collections_and_ambiguous_operations() {
        for value in [
            serde_json::json!({"type":"breg","permissions":[]}),
            serde_json::json!({"type":"evidence","requirement":"*"}),
            serde_json::json!({"type":"breg","permissions":[{"collection":"records","operations":["get","get"]}]}),
            serde_json::json!({"type":"breg","permissions":[{"collection":"records","operations":["get"]},{"collection":"records","operations":["list"]}]}),
        ] {
            let bounds: TaskGrantBounds = serde_json::from_value(value).unwrap();
            assert!(bounds.check().is_err());
        }
        let bounds: TaskGrantBounds = serde_json::from_value(serde_json::json!({"type":"breg","permissions":[{"collection":"records","operations":["get","create"]}]})).unwrap();
        assert!(bounds.check().is_ok());
    }
}

/// The exact authorization a human can approve after a current disclosed read.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskTemplatePreview {
    pub id: String,
    pub version: String,
    pub label: String,
    pub agent: IssuerPrincipal,
    pub client: String,
    pub resource: String,
    pub purpose: String,
    pub bounds: TaskGrantBounds,
    pub subjects: BTreeMap<String, Value>,
    pub lifetime_seconds: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskTemplatePreviews {
    pub item_revision: i64,
    pub templates: Vec<TaskTemplatePreview>,
}

/// Grant metadata. Stored subjects are deliberately absent: preview and approval
/// derive selectors from the caller's current disclosed source representation.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantView {
    pub id: Uuid,
    pub template_id: String,
    pub template_version: String,
    pub agent: IssuerPrincipal,
    pub client: String,
    pub resource: String,
    pub purpose: String,
    pub bounds: TaskGrantBounds,
    pub expires_at: u64,
    pub invalidated: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantList {
    pub grants: Vec<TaskGrantView>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantRevocation {
    pub id: Uuid,
    pub invalidated: bool,
}

/// Short-lived credential response. Deliberately does not implement Debug.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskAssertionResponse {
    pub assertion: String,
    pub expires_at: u64,
    pub grant_expires_at: u64,
}

/// Fresh status returned only to the service client registered for this resource.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatus {
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<TaskGrantStatusDetails>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatusDetails {
    pub grant_id: Uuid,
    pub authority: String,
    pub source_issuer: String,
    pub principal: String,
    pub client: String,
    pub resource: String,
    pub purpose: String,
    pub bounds: TaskGrantBounds,
    pub subjects: BTreeMap<String, Value>,
    pub expires_at: u64,
}
