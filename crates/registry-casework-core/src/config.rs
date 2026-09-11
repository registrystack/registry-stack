use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CaseworkRole;
use crate::HostedKindPolicy;
use crate::{check_clock_policies, check_routing_policy, CalendarPolicy, ClockPolicy, RoutingRule};

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
    pub calendars: Vec<CalendarPolicy>,
    #[serde(default)]
    pub clocks: Vec<ClockPolicy>,
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
        let queues: BTreeSet<_> = self.queues.iter().map(|queue| queue.id.clone()).collect();
        if queues.len() != self.queues.len()
            || queues.is_empty()
            || self.queues.iter().any(|queue| {
                queue.id.is_empty() || queue.label.trim().is_empty() || queue.label.len() > 160
            })
        {
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
        if !human_roles_are_separately_scoped(&self.access_profiles) {
            return Err(ConfigError::AccessProfileScopes);
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
        check_clock_policies(&self.calendars, &self.clocks, &queues)
            .map_err(|_| ConfigError::Clocks)?;
        let clock_ids = self
            .clocks
            .iter()
            .map(ClockPolicy::id)
            .collect::<BTreeSet<_>>();
        for source in &self.sources {
            if source.id.is_empty()
                || source.adapter.is_empty()
                || source.description.is_empty()
                || source.requests.is_empty()
            {
                return Err(ConfigError::Identifier);
            }
            for request in &source.requests {
                if request.entity.is_empty()
                    || !queues.contains(&request.queue)
                    || request.target.as_ref().is_some_and(|target| {
                        target.id.is_empty()
                            || parse_elapsed_seconds(&target.after.elapsed).is_none()
                    })
                {
                    return Err(ConfigError::Identifier);
                }
                check_routing_policy(
                    &request.queue,
                    &request.projection,
                    &request.routing,
                    &queues,
                    None,
                )
                .map_err(|_| ConfigError::Routing)?;
                if request
                    .clock
                    .as_deref()
                    .is_some_and(|clock| !clock_ids.contains(clock))
                {
                    return Err(ConfigError::Clocks);
                }
            }
        }
        self.inbox.check()
    }
}

/// The selected profile carries the caller's role, so the token must be what
/// separates one human role from another: two human roles that require the
/// same scopes let one token select either, and an administrator profile whose
/// scopes are all required elsewhere is reachable by every caller that holds
/// them.
fn human_roles_are_separately_scoped(profiles: &[AccessProfile]) -> bool {
    fn is_human(role: CaseworkRole) -> bool {
        matches!(
            role,
            CaseworkRole::Staff | CaseworkRole::Supervisor | CaseworkRole::Administrator
        )
    }
    fn scopes(profile: &AccessProfile) -> BTreeSet<&String> {
        profile.required_scopes.iter().collect()
    }
    let distinct = profiles.iter().enumerate().all(|(index, left)| {
        profiles.iter().skip(index + 1).all(|right| {
            left.role == right.role
                || !is_human(left.role)
                || !is_human(right.role)
                || scopes(left) != scopes(right)
        })
    });
    let elsewhere: BTreeSet<&String> = profiles
        .iter()
        .filter(|profile| profile.role != CaseworkRole::Administrator)
        .flat_map(|profile| profile.required_scopes.iter())
        .collect();
    distinct
        && profiles
            .iter()
            .filter(|profile| profile.role == CaseworkRole::Administrator)
            .all(|profile| {
                profile
                    .required_scopes
                    .iter()
                    .any(|scope| !elsewhere.contains(scope))
            })
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projection: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing: Vec<RoutingRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock: Option<String>,
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
    #[error("the Casework queues are invalid")]
    DefaultQueue,
    #[error("staff, supervisor, and administrator access profiles are required")]
    AccessProfiles,
    #[error("the staff, supervisor, and administrator access profiles must require different scopes from one another, and the administrator profile must require a scope no other profile requires")]
    AccessProfileScopes,
    #[error("the hosted kind policy or its profile grants are invalid")]
    HostedKinds,
    #[error("the Casework project configures no source or hosted work")]
    NoConfiguredWork,
    #[error("a source routing policy is invalid")]
    Routing,
    #[error("a clock or calendar policy is invalid")]
    Clocks,
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
            calendars: Vec::new(),
            clocks: Vec::new(),
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
    fn human_roles_are_not_reachable_through_one_shared_scope_set() {
        let mut candidate = project();
        candidate.access_profiles[1].required_scopes =
            candidate.access_profiles[0].required_scopes.clone();
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));
    }

    #[test]
    fn the_administrator_profile_requires_a_scope_of_its_own() {
        let mut candidate = project();
        candidate.access_profiles[2].required_scopes = vec![
            "casework:staff".to_owned(),
            "casework:supervisor".to_owned(),
        ];
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));
    }

    #[test]
    fn the_shipped_example_projects_load() {
        let examples =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/casework/examples");
        for example in [
            "professional-review",
            "standalone-decision",
            "multi-stage-routing-clocks",
        ] {
            let path = examples.join(example).join("casework.yaml");
            CaseworkProject::load(&path)
                .unwrap_or_else(|error| panic!("{} loads: {error}", path.display()));
        }
    }

    #[test]
    fn administrator_is_not_a_hosted_deciding_profile() {
        let mut project = project();
        project.hosted_kinds[0].deciding_profiles = vec!["administrator".to_owned()];
        assert_eq!(project.check(), Err(ConfigError::HostedKinds));
    }

    #[test]
    fn multi_queue_routing_and_named_clocks_use_the_documented_authoring_shape() {
        let project: CaseworkProject = serde_norway::from_str(
            r#"apiVersion: registry.registrystack.org/casework/v1alpha1
kind: CaseworkProject
casework: {id: regional-review, version: "1"}
accessProfiles:
  - {id: staff, principalClaim: sub, requiredScopes: [casework:staff], role: staff}
  - {id: supervisor, principalClaim: sub, requiredScopes: [casework:supervisor], role: supervisor}
  - {id: administrator, principalClaim: sub, requiredScopes: [casework:admin], role: administrator}
queues:
  - {id: triage, label: Triage}
  - {id: northern-review, label: Northern review}
  - {id: southern-review, label: Southern review}
  - {id: overdue-review, label: Overdue review}
sources:
  - id: professional-register
    adapter: breg
    description: sources/professional-register.json
    requests:
      - entity: scope-correction
        queue: triage
        projection: [region]
        clock: review-deadline
        routing:
          - id: northern-requests
            because: The request's governed region is north.
            when: {fields: {region: {equals: north}}}
            queue: northern-review
          - id: southern-requests
            because: The request's governed region is south or islands.
            when: {fields: {region: {oneOf: [south, islands]}}}
            queue: southern-review
calendars:
  - id: office
    timezone: Asia/Bangkok
    workingWeekdays: [monday, tuesday, wednesday, thursday, friday]
    holidaySet: office-holidays
clocks:
  - id: review-deadline
    scope: activity
    anchor: stageEnteredAt
    calendar: office
    after: {workingDays: 5}
    dueTime: "17:00"
    atRisk: {workingDaysBefore: 1}
    reminders: [{id: due-soon, workingDaysBefore: 1}]
    steps:
      - id: supervisor-at-deadline
        because: The review deadline passed while the review remained active.
        at: due
        action: {reassign: {queue: overdue-review}}
"#,
        )
        .expect("documented policy parses");
        assert_eq!(project.check(), Ok(()));
        assert_eq!(project.queues.len(), 4);
        assert_eq!(project.sources[0].requests[0].routing.len(), 2);
    }
}
