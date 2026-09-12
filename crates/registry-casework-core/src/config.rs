use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CaseworkRole;
use crate::HostedKindPolicy;
use crate::{check_clock_policies, check_routing_policy, CalendarPolicy, ClockPolicy, RoutingRule};

pub const CASEWORK_API_VERSION: &str = "registry.registrystack.org/casework/v1alpha1";
pub const CASEWORK_KIND: &str = "CaseworkProject";
// Matches the maintained Mint issuer's bounded RFC 6749 scope-token contract.
const MAXIMUM_REQUIRED_SCOPE_BYTES: usize = 256;

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

/// Whether an identifier can select a Casework access profile over HTTP.
#[must_use]
pub fn valid_profile_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAXIMUM_CASEWORK_PROFILE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_required_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_REQUIRED_SCOPE_BYTES
        && value.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

/// Whether an identifier can be stored and selected by the Casework directory.
#[must_use]
pub fn valid_directory_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAXIMUM_DIRECTORY_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
        let deserializer = serde_norway::Deserializer::from_slice(&bytes);
        let project: Self = serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let path = error.path().to_string();
            ConfigLoadError::Parse {
                path: if path.is_empty() {
                    "/".to_owned()
                } else {
                    path
                },
                source: error.into_inner(),
            }
        })?;
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
                !valid_directory_identifier(&queue.id)
                    || queue.label.trim().is_empty()
                    || queue.label.len() > 160
            })
        {
            return Err(ConfigError::DefaultQueue);
        }
        if self
            .access_profiles
            .iter()
            .any(|profile| !valid_profile_identifier(&profile.id))
        {
            return Err(ConfigError::Identifier);
        }
        let profiles: BTreeSet<_> = self.access_profiles.iter().map(|p| &p.id).collect();
        if profiles.len() != self.access_profiles.len()
            || self.access_profiles.iter().any(|profile| {
                profile.principal_claim.is_empty()
                    || profile.required_scopes.is_empty()
                    || profile
                        .required_scopes
                        .iter()
                        .any(|scope| !valid_required_scope(scope))
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
        if !access_roles_are_separately_scoped(&self.access_profiles) {
            return Err(ConfigError::AccessProfileScopes);
        }
        let hosted_kinds: BTreeSet<_> = self.hosted_kinds.iter().map(|kind| &kind.id).collect();
        for (kind_index, kind) in self.hosted_kinds.iter().enumerate() {
            if !queues.contains(&kind.queue) {
                return Err(ConfigError::Reference {
                    path: format!("hostedKinds[{kind_index}].queue"),
                    target: "queue",
                });
            }
            for (profile_index, profile_id) in kind.deciding_profiles.iter().enumerate() {
                if self
                    .access_profiles
                    .iter()
                    .find(|profile| profile.id == *profile_id)
                    .is_none_or(|profile| {
                        !matches!(profile.role, CaseworkRole::Staff | CaseworkRole::Supervisor)
                    })
                {
                    return Err(ConfigError::Reference {
                        path: format!(
                            "hostedKinds[{kind_index}].decidingProfiles[{profile_index}]"
                        ),
                        target: "staff or supervisor access profile",
                    });
                }
            }
        }
        for (profile_index, profile) in self.access_profiles.iter().enumerate() {
            if profile.role == CaseworkRole::Requester {
                for (kind_index, kind) in profile.kinds.iter().enumerate() {
                    if !hosted_kinds.contains(kind) {
                        return Err(ConfigError::Reference {
                            path: format!("accessProfiles[{profile_index}].kinds[{kind_index}]"),
                            target: "hosted kind",
                        });
                    }
                }
            }
        }
        if self.hosted_kinds.len() > crate::MAXIMUM_HOSTED_KINDS
            || hosted_kinds.len() != self.hosted_kinds.len()
            || !self.hosted_kinds.is_empty()
                && !self
                    .access_profiles
                    .iter()
                    .any(|profile| profile.role == CaseworkRole::Requester)
            || self.hosted_kinds.iter().any(|kind| kind.check().is_err())
            || self
                .access_profiles
                .iter()
                .any(|profile| match profile.role {
                    CaseworkRole::Requester => {
                        profile.kinds.is_empty()
                            || profile.kinds.len() > crate::MAXIMUM_HOSTED_KINDS
                            || profile.kinds.iter().collect::<BTreeSet<_>>().len()
                                != profile.kinds.len()
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
        let calendar_ids = self
            .calendars
            .iter()
            .map(|calendar| calendar.id.as_str())
            .collect::<BTreeSet<_>>();
        for (clock_index, clock) in self.clocks.iter().enumerate() {
            if let ClockPolicy::Activity {
                calendar, steps, ..
            } = clock
            {
                if !calendar_ids.contains(calendar.as_str()) {
                    return Err(ConfigError::Reference {
                        path: format!("clocks[{clock_index}].calendar"),
                        target: "calendar",
                    });
                }
                for (step_index, step) in steps.iter().enumerate() {
                    if !queues.contains(&step.action.reassign.queue) {
                        return Err(ConfigError::Reference {
                            path: format!(
                                "clocks[{clock_index}].steps[{step_index}].action.reassign.queue"
                            ),
                            target: "queue",
                        });
                    }
                }
            }
        }
        check_clock_policies(&self.calendars, &self.clocks, &queues)
            .map_err(|_| ConfigError::Clocks)?;
        let clock_ids = self
            .clocks
            .iter()
            .map(ClockPolicy::id)
            .collect::<BTreeSet<_>>();
        let source_ids: BTreeSet<_> = self.sources.iter().map(|source| &source.id).collect();
        if source_ids.len() != self.sources.len() {
            return Err(ConfigError::Identifier);
        }
        for (source_index, source) in self.sources.iter().enumerate() {
            if source.id.is_empty()
                || source.adapter.is_empty()
                || source.description.is_empty()
                || source.requests.is_empty()
            {
                return Err(ConfigError::Identifier);
            }
            for (request_index, request) in source.requests.iter().enumerate() {
                let request_path = format!("sources[{source_index}].requests[{request_index}]");
                if !queues.contains(&request.queue) {
                    return Err(ConfigError::Reference {
                        path: format!("{request_path}.queue"),
                        target: "queue",
                    });
                }
                if request.entity.is_empty()
                    || request.display_reference.as_ref().is_some_and(|reference| {
                        reference.field.is_empty()
                            || reference.field.len() > 512
                            || reference.field.chars().any(char::is_control)
                    })
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
                .map_err(|error| ConfigError::Semantic {
                    path: format!("{request_path}.{}", error.path),
                    member: "routing policy",
                })?;
                if request
                    .clock
                    .as_deref()
                    .is_some_and(|clock| !clock_ids.contains(clock))
                {
                    return Err(ConfigError::Reference {
                        path: format!("{request_path}.clock"),
                        target: "clock",
                    });
                }
            }
        }
        self.inbox.check()
    }
}

/// The selected profile carries the caller's identity and role, so every
/// profile must require a scope absent from the combined scopes of all other
/// profiles at the same or a lower role. Otherwise credentials assembled from
/// those grants could select authority belonging to this profile, including
/// authority retained under an earlier hosted-kind policy. A higher-role
/// credential may still explicitly carry the scopes required by a lower role.
fn access_roles_are_separately_scoped(profiles: &[AccessProfile]) -> bool {
    fn role_rank(role: CaseworkRole) -> u8 {
        match role {
            CaseworkRole::Requester => 0,
            CaseworkRole::Staff => 1,
            CaseworkRole::Supervisor => 2,
            CaseworkRole::Administrator => 3,
        }
    }
    profiles.iter().enumerate().all(|(target_index, target)| {
        let target_rank = role_rank(target.role);
        let other_same_or_lower_scopes: BTreeSet<&String> = profiles
            .iter()
            .enumerate()
            .filter(|(index, profile)| {
                *index != target_index && role_rank(profile.role) <= target_rank
            })
            .flat_map(|(_, profile)| profile.required_scopes.iter())
            .collect();
        target
            .required_scopes
            .iter()
            .any(|scope| !other_same_or_lower_scopes.contains(scope))
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
    /// One source-owned string field that may be retained for exact officer
    /// lookup. It remains subject to the current caller's source disclosure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_reference: Option<DisplayReferencePolicy>,
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
pub struct DisplayReferencePolicy {
    pub field: String,
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
    } else {
        (body.strip_suffix('S')?, 1)
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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("the Casework project envelope is invalid")]
    Envelope,
    #[error("a Casework identifier is invalid")]
    Identifier,
    #[error("the Casework queues are invalid")]
    DefaultQueue,
    #[error("staff, supervisor, and administrator access profiles are required")]
    AccessProfiles,
    #[error(
        "every access profile must require a scope absent from the combined scopes of every other profile at the same or a lower role"
    )]
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
    #[error("{path} references an unknown or ineligible {target}")]
    Reference { path: String, target: &'static str },
    #[error("{member} is invalid at {path}")]
    Semantic { path: String, member: &'static str },
}

impl ConfigError {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Reference { path, .. } | Self::Semantic { path, .. } => path,
            _ => "/",
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigLoadError {
    #[error("the Casework project could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Casework project is not valid YAML at {path}")]
    Parse {
        path: String,
        #[source]
        source: serde_norway::Error,
    },
    #[error(transparent)]
    Check(#[from] ConfigError),
}

impl ConfigLoadError {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Check(error) => error.path(),
            Self::Read(_) => "/",
            Self::Parse { path, .. } => path,
        }
    }
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

    fn hosted_kind(id: &str, deciding_profiles: &[&str]) -> HostedKindPolicy {
        let mut kind = standalone_decision_starter_kind();
        kind.id = id.to_owned();
        kind.deciding_profiles = deciding_profiles
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect();
        kind
    }

    fn project_with_source_queue(queue: &str) -> CaseworkProject {
        let mut candidate = project();
        candidate.queues[0].id = queue.to_owned();
        candidate.sources = vec![SourcePolicy {
            id: "source".to_owned(),
            adapter: "adapter".to_owned(),
            description: "Source".to_owned(),
            requests: vec![SourceRequestPolicy {
                entity: "item".to_owned(),
                queue: queue.to_owned(),
                display_reference: None,
                projection: Vec::new(),
                routing: Vec::new(),
                clock: None,
                target: None,
            }],
        }];
        candidate.hosted_kinds.clear();
        candidate.access_profiles.pop();
        candidate
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
        assert_eq!(
            candidate.check().unwrap_err().path(),
            "accessProfiles[3].kinds[0]"
        );

        let mut candidate = project();
        candidate.access_profiles[2].kinds = vec!["decision".to_owned()];
        assert_eq!(candidate.check(), Err(ConfigError::HostedKinds));
    }

    #[test]
    fn every_same_role_profile_requires_an_independently_selectable_scope() {
        let mut candidate = project();
        candidate
            .hosted_kinds
            .push(hosted_kind("appeal", &["staff"]));
        let mut appeal_requester =
            profile("appeal-requester", CaseworkRole::Requester, &["appeal"]);
        appeal_requester.required_scopes = candidate.access_profiles[3].required_scopes.clone();
        candidate.access_profiles.push(appeal_requester);
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));

        let mut candidate = project();
        // Current equality cannot prove that retained items pinned the same
        // deciding-profile set under an earlier policy.
        let mut retained_profile = profile("retained-staff", CaseworkRole::Staff, &[]);
        retained_profile.required_scopes = candidate.access_profiles[0].required_scopes.clone();
        candidate.access_profiles.push(retained_profile);
        candidate.hosted_kinds[0]
            .deciding_profiles
            .push("retained-staff".to_owned());
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));

        let mut combined = project();
        combined.access_profiles[0].required_scopes = vec!["casework:a".to_owned()];
        let mut staff_b = profile("staff-b", CaseworkRole::Staff, &[]);
        staff_b.required_scopes = vec!["casework:b".to_owned()];
        combined.access_profiles.push(staff_b);
        let mut appeal_staff = profile("appeal-staff", CaseworkRole::Staff, &[]);
        appeal_staff.required_scopes = vec!["casework:a".to_owned(), "casework:b".to_owned()];
        combined.access_profiles.push(appeal_staff);
        combined
            .hosted_kinds
            .push(hosted_kind("appeal", &["appeal-staff"]));
        assert_eq!(combined.check(), Err(ConfigError::AccessProfileScopes));

        let mut remapped = project();
        let mut alternate = profile("staff-by-sub", CaseworkRole::Staff, &[]);
        alternate.principal_claim = "sub".to_owned();
        alternate.required_scopes = remapped.access_profiles[0].required_scopes.clone();
        remapped.access_profiles.push(alternate);
        remapped.hosted_kinds[0]
            .deciding_profiles
            .push("staff-by-sub".to_owned());
        assert_eq!(remapped.check(), Err(ConfigError::AccessProfileScopes));
    }

    #[test]
    fn one_profile_cannot_be_selected_by_combining_lower_and_same_role_scopes() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes =
            vec!["casework:a".to_owned(), "casework:b".to_owned()];
        candidate.access_profiles[3].required_scopes = vec!["casework:a".to_owned()];
        let mut peer = profile("staff-b", CaseworkRole::Staff, &[]);
        peer.required_scopes = vec!["casework:b".to_owned()];
        candidate.access_profiles.push(peer);

        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));
    }

    #[test]
    fn same_role_profiles_may_share_base_scopes_when_each_has_its_own_scope() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes = vec![
            "casework:staff".to_owned(),
            "casework:staff-primary".to_owned(),
        ];
        let mut alternate = profile("staff-by-sub", CaseworkRole::Staff, &[]);
        alternate.principal_claim = "sub".to_owned();
        alternate.required_scopes = vec![
            "casework:staff".to_owned(),
            "casework:staff-alternate".to_owned(),
        ];
        candidate.access_profiles.push(alternate);
        candidate.hosted_kinds[0]
            .deciding_profiles
            .push("staff-by-sub".to_owned());
        assert_eq!(candidate.check(), Ok(()));
    }

    #[test]
    fn required_scopes_use_bounded_rfc_6749_scope_tokens() {
        for valid in [
            "!#$%&'()*+,-./012:;<=>?@AZ[]^_`az{|}~".to_owned(),
            "x".repeat(MAXIMUM_REQUIRED_SCOPE_BYTES),
        ] {
            let mut candidate = project();
            candidate.access_profiles[0].required_scopes = vec![valid];
            assert_eq!(candidate.check(), Ok(()));
        }

        for invalid in [
            String::new(),
            "x".repeat(MAXIMUM_REQUIRED_SCOPE_BYTES + 1),
            "casework:staff review".to_owned(),
            "casework:staff\"review".to_owned(),
            "casework:staff\\review".to_owned(),
            "casework:staff\u{1f}review".to_owned(),
            "casework:staff\u{7f}review".to_owned(),
            "casework:réview".to_owned(),
        ] {
            let mut candidate = project();
            candidate.access_profiles[0].required_scopes = vec![invalid];
            assert_eq!(candidate.check(), Err(ConfigError::AccessProfiles));
        }
    }

    #[test]
    fn source_ids_are_unique_independently_of_their_description_files() {
        let mut candidate = project_with_source_queue("decisions");
        let mut duplicate = candidate.sources[0].clone();
        duplicate.adapter = "other-adapter".to_owned();
        duplicate.description = "other-description.json".to_owned();
        candidate.sources.push(duplicate);
        assert_eq!(candidate.check(), Err(ConfigError::Identifier));
    }

    #[test]
    fn higher_roles_are_not_reachable_through_lower_role_scope_sets() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes =
            vec!["casework:review".to_owned(), "casework:manage".to_owned()];
        candidate.access_profiles[1].required_scopes = vec!["casework:manage".to_owned()];
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));

        let mut candidate = project();
        candidate.access_profiles[1].required_scopes = vec![
            "casework:supervise".to_owned(),
            "casework:administer".to_owned(),
        ];
        candidate.access_profiles[2].required_scopes = vec!["casework:administer".to_owned()];
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));

        let mut candidate = project();
        candidate.access_profiles[0].required_scopes = vec!["casework:a".to_owned()];
        candidate.access_profiles[1].required_scopes =
            vec!["casework:a".to_owned(), "casework:b".to_owned()];
        candidate.access_profiles.push(AccessProfile {
            id: "staff-secondary".to_owned(),
            principal_claim: "registry_principal".to_owned(),
            required_scopes: vec!["casework:b".to_owned()],
            role: CaseworkRole::Staff,
            kinds: Vec::new(),
        });
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));

        let mut candidate = project();
        candidate.access_profiles[3].required_scopes =
            candidate.access_profiles[1].required_scopes.clone();
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));
    }

    #[test]
    fn administrator_requires_a_scope_absent_from_combined_non_administrator_grants() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes = vec!["casework:review".to_owned()];
        candidate.access_profiles[1].required_scopes = vec!["casework:manage".to_owned()];
        candidate.access_profiles[2].required_scopes =
            vec!["casework:review".to_owned(), "casework:manage".to_owned()];
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));

        let mut candidate = project();
        candidate.access_profiles[2].required_scopes =
            candidate.access_profiles[3].required_scopes.clone();
        assert_eq!(candidate.check(), Err(ConfigError::AccessProfileScopes));
    }

    #[test]
    fn access_profile_ids_match_the_http_selection_contract() {
        for valid in ["staff.review:v1_2-3".to_owned(), "x".repeat(128)] {
            let mut candidate = project();
            candidate.access_profiles[2].id = valid;
            assert_eq!(candidate.check(), Ok(()));
        }

        for invalid in [
            String::new(),
            "x".repeat(129),
            "staff/reviewer".to_owned(),
            "staff reviewer".to_owned(),
            "stáff".to_owned(),
        ] {
            let mut candidate = project();
            candidate.access_profiles[2].id = invalid;
            assert_eq!(candidate.check(), Err(ConfigError::Identifier));
        }
    }

    #[test]
    fn queue_ids_match_the_directory_assignment_contract() {
        for valid in ["review.queue_1-2".to_owned(), "x".repeat(128)] {
            let candidate = project_with_source_queue(&valid);
            assert_eq!(candidate.check(), Ok(()));
        }

        for invalid in [
            String::new(),
            "x".repeat(129),
            "review/queue".to_owned(),
            "review queue".to_owned(),
            "réview".to_owned(),
            "review:queue".to_owned(),
        ] {
            let candidate = project_with_source_queue(&invalid);
            assert_eq!(candidate.check(), Err(ConfigError::DefaultQueue));
        }
    }

    #[test]
    fn higher_role_scope_requirements_allow_nested_and_independent_profiles() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes = vec!["casework:human".to_owned()];
        candidate.access_profiles[1].required_scopes =
            vec!["casework:human".to_owned(), "casework:manage".to_owned()];
        candidate.access_profiles[2].required_scopes = vec![
            "casework:human".to_owned(),
            "casework:manage".to_owned(),
            "casework:administer".to_owned(),
        ];
        assert_eq!(candidate.check(), Ok(()));

        let mut candidate = project();
        candidate.access_profiles[0].required_scopes =
            vec!["casework:shared".to_owned(), "casework:staff".to_owned()];
        candidate.access_profiles[1].required_scopes = vec![
            "casework:shared".to_owned(),
            "casework:supervisor".to_owned(),
            "casework:supervisor-primary".to_owned(),
        ];
        candidate.access_profiles[2].required_scopes = vec![
            "casework:staff".to_owned(),
            "casework:supervisor".to_owned(),
            "casework:administrator".to_owned(),
        ];
        candidate.access_profiles.push(AccessProfile {
            id: "supervisor-secondary".to_owned(),
            principal_claim: "registry_principal".to_owned(),
            required_scopes: vec![
                "casework:shared".to_owned(),
                "casework:supervisor".to_owned(),
                "casework:supervisor-secondary".to_owned(),
            ],
            role: CaseworkRole::Supervisor,
            kinds: Vec::new(),
        });
        assert_eq!(candidate.check(), Ok(()));
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
        assert_eq!(
            project.check().unwrap_err().path(),
            "hostedKinds[0].decidingProfiles[0]"
        );
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

        let mut invalid = project.clone();
        invalid.sources[0].requests[0].routing[1].queue = "missing".to_owned();
        assert_eq!(
            invalid.check().unwrap_err().path(),
            "sources[0].requests[0].routing[1].queue"
        );

        let mut invalid = project.clone();
        invalid.sources[0].requests[0].clock = Some("missing".to_owned());
        assert_eq!(
            invalid.check().unwrap_err().path(),
            "sources[0].requests[0].clock"
        );

        let mut invalid = project.clone();
        let ClockPolicy::Activity { calendar, .. } = &mut invalid.clocks[0] else {
            panic!("fixture has an activity clock")
        };
        *calendar = "missing".to_owned();
        assert_eq!(invalid.check().unwrap_err().path(), "clocks[0].calendar");
    }
}
