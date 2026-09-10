use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CaseworkRole;
use crate::HostedKindPolicy;

pub const CASEWORK_API_VERSION: &str = "registry.registrystack.org/casework/v1alpha1";
pub const CASEWORK_KIND: &str = "CaseworkProject";

fn default_page_size() -> usize {
    25
}
fn default_candidate_budget() -> usize {
    100
}
fn default_source_read_budget() -> usize {
    25
}
fn default_concurrency() -> usize {
    4
}
fn default_deadline_ms() -> u64 {
    2_000
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkProject {
    pub api_version: String,
    pub kind: String,
    pub casework: CaseworkIdentity,
    pub access_profiles: Vec<AccessProfile>,
    pub queues: Vec<QueuePolicy>,
    #[serde(default)]
    pub sources: Vec<SourcePolicy>,
    #[serde(default)]
    pub hosted_kinds: Vec<HostedKindPolicy>,
    #[serde(default)]
    pub inbox: InboxPolicy,
}

impl CaseworkProject {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigLoadError> {
        let bytes = std::fs::read(path).map_err(ConfigLoadError::Read)?;
        let project: Self = serde_norway::from_slice(&bytes).map_err(ConfigLoadError::Parse)?;
        project.check().map_err(ConfigLoadError::Check)?;
        Ok(project)
    }

    pub fn check(&self) -> Result<(), ConfigError> {
        if self.api_version != CASEWORK_API_VERSION || self.kind != CASEWORK_KIND {
            return Err(ConfigError::Envelope);
        }
        if self.casework.id.is_empty() || self.casework.version.is_empty() {
            return Err(ConfigError::Identifier);
        }
        let queues: BTreeSet<_> = self.queues.iter().map(|queue| &queue.id).collect();
        if queues.len() != self.queues.len() || queues.len() != 1 {
            return Err(ConfigError::DefaultQueue);
        }
        let profiles: BTreeSet<_> = self.access_profiles.iter().map(|p| &p.id).collect();
        if profiles.len() != self.access_profiles.len()
            || self.access_profiles.iter().any(|profile| {
                profile.id.is_empty()
                    || profile.principal_claim.is_empty()
                    || profile.required_scopes.is_empty()
            })
            || !self
                .access_profiles
                .iter()
                .any(|p| p.role == CaseworkRole::Staff)
            || !self
                .access_profiles
                .iter()
                .any(|p| p.role == CaseworkRole::Supervisor)
            || !self
                .access_profiles
                .iter()
                .any(|p| p.role == CaseworkRole::Administrator)
        {
            return Err(ConfigError::AccessProfiles);
        }
        let hosted_kinds: BTreeSet<_> = self.hosted_kinds.iter().map(|kind| &kind.id).collect();
        if self.hosted_kinds.len() > crate::MAXIMUM_HOSTED_KINDS
            || hosted_kinds.len() != self.hosted_kinds.len()
            || !self.hosted_kinds.is_empty()
                && !self
                    .access_profiles
                    .iter()
                    .any(|profile| profile.role == CaseworkRole::Requester)
            || self.hosted_kinds.iter().any(|kind| {
                kind.check().is_err()
                    || !queues.contains(&kind.queue)
                    || kind.deciding_profiles.iter().any(|profile_id| {
                        self.access_profiles
                            .iter()
                            .find(|profile| profile.id == *profile_id)
                            .is_none_or(|profile| {
                                !matches!(
                                    profile.role,
                                    CaseworkRole::Staff | CaseworkRole::Supervisor
                                )
                            })
                    })
            })
            || self
                .access_profiles
                .iter()
                .any(|profile| match profile.role {
                    CaseworkRole::Requester => {
                        profile.kinds.is_empty()
                            || profile.kinds.len() > crate::MAXIMUM_HOSTED_KINDS
                            || profile.kinds.iter().collect::<BTreeSet<_>>().len()
                                != profile.kinds.len()
                            || profile
                                .kinds
                                .iter()
                                .any(|kind| !hosted_kinds.contains(kind))
                    }
                    CaseworkRole::Staff
                    | CaseworkRole::Supervisor
                    | CaseworkRole::Administrator => !profile.kinds.is_empty(),
                })
        {
            return Err(ConfigError::HostedKinds);
        }
        if self.sources.is_empty() && self.hosted_kinds.is_empty() {
            return Err(ConfigError::NoConfiguredWork);
        }
        if self.sources.iter().any(|source| {
            source.id.is_empty()
                || source.adapter.is_empty()
                || source.description.is_empty()
                || source.requests.is_empty()
                || source.requests.iter().any(|request| {
                    request.entity.is_empty()
                        || !queues.contains(&request.queue)
                        || request.target.as_ref().is_some_and(|target| {
                            target.id.is_empty()
                                || parse_elapsed_seconds(&target.after.elapsed).is_none()
                        })
                })
        }) {
            return Err(ConfigError::Identifier);
        }
        self.inbox.check()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkIdentity {
    pub id: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessProfile {
    pub id: String,
    pub principal_claim: String,
    pub required_scopes: Vec<String>,
    pub role: CaseworkRole,
    /// Hosted kinds a Requester profile may create. Human profiles never use
    /// this list to acquire payload access or decision authority.
    #[serde(default)]
    pub kinds: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueuePolicy {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourcePolicy {
    pub id: String,
    pub adapter: String,
    pub description: String,
    pub requests: Vec<SourceRequestPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceRequestPolicy {
    pub entity: String,
    pub queue: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PassiveTargetPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassiveTargetPolicy {
    pub id: String,
    pub after: ElapsedDuration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ElapsedDuration {
    pub elapsed: String,
}

/// Parse the checkpoint's deliberately small ISO-8601 elapsed-time subset.
/// Calendar and compound durations belong to the later clock evaluator.
#[must_use]
pub fn parse_elapsed_seconds(value: &str) -> Option<i64> {
    let body = value.strip_prefix("PT")?;
    let (number, multiplier) = if let Some(number) = body.strip_suffix('H') {
        (number, 60 * 60)
    } else if let Some(number) = body.strip_suffix('M') {
        (number, 60)
    } else if let Some(number) = body.strip_suffix('S') {
        (number, 1)
    } else {
        return None;
    };
    let amount = number.parse::<i64>().ok()?;
    (amount > 0)
        .then(|| amount.checked_mul(multiplier))
        .flatten()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InboxPolicy {
    #[serde(default = "default_page_size")]
    pub default_page_size: usize,
    #[serde(default = "default_candidate_budget")]
    pub maximum_candidate_scan: usize,
    #[serde(default = "default_source_read_budget")]
    pub maximum_source_reads: usize,
    #[serde(default = "default_concurrency")]
    pub maximum_concurrent_source_reads: usize,
    #[serde(default = "default_deadline_ms")]
    pub page_deadline_milliseconds: u64,
}

impl Default for InboxPolicy {
    fn default() -> Self {
        Self {
            default_page_size: default_page_size(),
            maximum_candidate_scan: default_candidate_budget(),
            maximum_source_reads: default_source_read_budget(),
            maximum_concurrent_source_reads: default_concurrency(),
            page_deadline_milliseconds: default_deadline_ms(),
        }
    }
}

impl InboxPolicy {
    fn check(&self) -> Result<(), ConfigError> {
        if self.default_page_size == 0
            || self.default_page_size > 100
            || self.maximum_candidate_scan < self.default_page_size
            || self.maximum_candidate_scan > 10_000
            || self.maximum_source_reads == 0
            || self.maximum_source_reads > self.maximum_candidate_scan
            || self.maximum_concurrent_source_reads == 0
            || self.maximum_concurrent_source_reads > 32
            || !(100..=30_000).contains(&self.page_deadline_milliseconds)
        {
            return Err(ConfigError::InboxBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("the Casework project envelope is invalid")]
    Envelope,
    #[error("a Casework identifier is invalid")]
    Identifier,
    #[error("the checkpoint requires exactly one default queue")]
    DefaultQueue,
    #[error("staff, supervisor, and administrator access profiles are required")]
    AccessProfiles,
    #[error("the hosted kind policy or its profile grants are invalid")]
    HostedKinds,
    #[error("the Casework project configures no source or hosted work")]
    NoConfiguredWork,
    #[error("the inbox work and response bounds are invalid")]
    InboxBounds,
}

#[derive(Debug, Error)]
pub enum ConfigLoadError {
    #[error("the Casework project could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Casework project is not valid YAML")]
    Parse(#[source] serde_norway::Error),
    #[error(transparent)]
    Check(#[from] ConfigError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standalone_decision_starter_kind;

    fn profile(id: &str, role: CaseworkRole, kinds: &[&str]) -> AccessProfile {
        AccessProfile {
            id: id.to_owned(),
            principal_claim: "registry_principal".to_owned(),
            required_scopes: vec![format!("casework:{id}")],
            role,
            kinds: kinds.iter().map(|kind| (*kind).to_owned()).collect(),
        }
    }

    fn project() -> CaseworkProject {
        CaseworkProject {
            api_version: CASEWORK_API_VERSION.to_owned(),
            kind: CASEWORK_KIND.to_owned(),
            casework: CaseworkIdentity {
                id: "standalone".to_owned(),
                version: "1".to_owned(),
            },
            access_profiles: vec![
                profile("staff", CaseworkRole::Staff, &[]),
                profile("supervisor", CaseworkRole::Supervisor, &[]),
                profile("administrator", CaseworkRole::Administrator, &[]),
                profile("requester", CaseworkRole::Requester, &["decision"]),
            ],
            queues: vec![QueuePolicy {
                id: "decisions".to_owned(),
                label: "Decisions".to_owned(),
            }],
            sources: Vec::new(),
            hosted_kinds: vec![standalone_decision_starter_kind()],
            inbox: InboxPolicy::default(),
        }
    }

    #[test]
    fn standalone_work_requires_an_explicit_hosted_kind() {
        let mut project = project();
        assert_eq!(project.check(), Ok(()));

        project.hosted_kinds.clear();
        project.access_profiles.pop();
        assert_eq!(project.check(), Err(ConfigError::NoConfiguredWork));
    }

    #[test]
    fn requester_grants_are_closed_over_declared_kinds() {
        let mut candidate = project();
        candidate.access_profiles[3].kinds = vec!["undeclared".to_owned()];
        assert_eq!(candidate.check(), Err(ConfigError::HostedKinds));

        let mut candidate = project();
        candidate.access_profiles[2].kinds = vec!["decision".to_owned()];
        assert_eq!(candidate.check(), Err(ConfigError::HostedKinds));
    }

    #[test]
    fn administrator_is_not_a_hosted_deciding_profile() {
        let mut project = project();
        project.hosted_kinds[0].deciding_profiles = vec!["administrator".to_owned()];
        assert_eq!(project.check(), Err(ConfigError::HostedKinds));
    }
}
