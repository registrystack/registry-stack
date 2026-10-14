//! Governed task delegation policy and immutable source-bound authorization.
use crate::finding::{ConfigFinding, Findings};
use crate::{CaseworkProject, CaseworkRole, IssuerPrincipal};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt};
use thiserror::Error;
use uuid::Uuid;

pub const TASK_GRANT_LIFETIME_SECONDS: u64 = 900;
pub const TASK_ASSERTION_LIFETIME_SECONDS: u64 = 60;
/// Explicit opt-in authorization ceiling. This never changes credential TTLs.
pub const DEFERRED_TASK_GRANT_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TaskAuthorizationMode {
    #[default]
    Immediate,
    Deferred,
}

impl TaskAuthorizationMode {
    pub fn is_immediate(&self) -> bool {
        *self == Self::Immediate
    }
    pub fn maximum_lifetime_seconds(self) -> u64 {
        match self {
            Self::Immediate => TASK_GRANT_LIFETIME_SECONDS,
            Self::Deferred => DEFERRED_TASK_GRANT_LIFETIME_SECONDS,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(
    feature = "schema",
    schemars(extend("allOf" = [{
        "if": {"properties": {"authorizationMode": {"const": "deferred"}}, "required": ["authorizationMode"]},
        "then": {"properties": {"lifetimeSeconds": {"maximum": DEFERRED_TASK_GRANT_LIFETIME_SECONDS}}},
        "else": {"properties": {"lifetimeSeconds": {"maximum": TASK_GRANT_LIFETIME_SECONDS}}}
    }, {
        "if": {"properties": {"authorizationMode": {"const": "deferred"}}, "required": ["authorizationMode"]},
        "then": {"properties": {"bounds": {"properties": {"type": {"not": {"const": "evidence"}}}}}}
    }]))
)]
pub struct TaskTemplate {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub version: String,
    pub label: String,
    pub eligible_teams: Vec<String>,
    pub eligible_profiles: Vec<String>,
    pub source: String,
    /// Policies whose currently held ReviewTasks may issue this grant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_policies: Vec<String>,
    #[serde(deserialize_with = "template_agent")]
    #[cfg_attr(feature = "schema", schemars(with = "TemplateAgent"))]
    pub agent: IssuerPrincipal,
    pub client: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub purpose: String,
    pub bounds: TaskGrantBounds,
    /// Evidence-only requester context signed into the authority assertion.
    /// Other products derive neither requester admission nor relying-party
    /// audience from these fields and therefore forbid the block entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_context: Option<EvidenceRequesterContext>,
    /// Exact token identity keys mapped to governed source logical fields.
    /// Values are extracted from the approving caller's disclosed source read.
    #[serde(deserialize_with = "crate::typed::external_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::ExternalId, String>")
    )]
    pub subjects: BTreeMap<String, String>,
    /// Immediate authorizations last at most fifteen minutes. Deferred is an
    /// explicit governed window of at most seven days; assertion TTL stays sixty seconds.
    #[serde(default, skip_serializing_if = "TaskAuthorizationMode::is_immediate")]
    pub authorization_mode: TaskAuthorizationMode,
    #[serde(
        deserialize_with = "crate::typed::bounded_u64::<_, 1, DEFERRED_TASK_GRANT_LIFETIME_SECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::BoundedU64<1, DEFERRED_TASK_GRANT_LIFETIME_SECONDS>"
        )
    )]
    pub lifetime_seconds: u64,
}

/// The agent a template names, as `casework.yaml` writes it: the issuer is
/// the URL of the token issuer that authenticates the agent (CFG-VAL-7).
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TemplateAgent {
    #[serde(deserialize_with = "crate::typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    issuer: String,
    subject: String,
}

fn template_agent<'de, D>(deserializer: D) -> Result<IssuerPrincipal, D::Error>
where
    D: Deserializer<'de>,
{
    let agent = TemplateAgent::deserialize(deserializer)?;
    Ok(IssuerPrincipal {
        issuer: agent.issuer,
        subject: agent.subject,
    })
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRequesterContext {
    pub requester_tags: Vec<String>,
    pub audience: String,
}

impl fmt::Debug for EvidenceRequesterContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvidenceRequesterContext")
            .field("requester_tags", &"<redacted>")
            .field("audience", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for TaskTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskTemplate")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// The product-specific authority a task grant carries, chosen by its `type`
/// member. The shared reader's union helper decodes it so every error inside
/// a variant keeps its position (CFG-SCHEMA-8); the wire form is unchanged.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum TaskGrantBounds {
    Evidence {
        requirement: String,
    },
    Breg {
        permissions: Vec<TaskPermission>,
    },
    Scheduling {
        permissions: Vec<SchedulingTaskPermission>,
    },
}
registry_platform_yaml::tagged_union!(TaskGrantBounds);

/// The serialized form of [`TaskGrantBounds`], kept byte-identical to the
/// stored and published shape.
#[derive(Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
enum TaskGrantBoundsWire<'a> {
    Evidence {
        requirement: &'a str,
    },
    Breg {
        permissions: &'a [TaskPermission],
    },
    Scheduling {
        permissions: &'a [SchedulingTaskPermission],
    },
}

impl Serialize for TaskGrantBounds {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Evidence { requirement } => TaskGrantBoundsWire::Evidence { requirement },
            Self::Breg { permissions } => TaskGrantBoundsWire::Breg { permissions },
            Self::Scheduling { permissions } => TaskGrantBoundsWire::Scheduling { permissions },
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct TaskPermission {
    pub collection: String,
    pub operations: Vec<String>,
}

/// Exact Scheduling commitment authority copied into a task grant.
///
/// This duplicates the public wire shape deliberately: Casework is an
/// authority for governed templates, not a dependency on Scheduling's runtime
/// or model crate.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingTaskPermission {
    pub service: String,
    pub location: String,
    pub actions: Vec<String>,
}

impl TaskGrantBounds {
    pub fn check(&self) -> Result<(), TaskGrantError> {
        if self.findings().is_empty() {
            Ok(())
        } else {
            Err(TaskGrantError::Policy)
        }
    }

    /// Every problem in these bounds, located by pointers relative to the
    /// `bounds` member.
    #[must_use]
    pub fn findings(&self) -> Vec<ConfigFinding> {
        let mut findings = Findings::default();
        match self {
            Self::Evidence { requirement } => {
                if !bounded_grant_identifier(requirement, 512) {
                    findings.push(
                        "casework.task-template.invalid-bounds",
                        "/requirement",
                        GRANT_IDENTIFIER_MESSAGE,
                        "Write the Evidence requirement identifier.",
                    );
                }
            }
            Self::Breg { permissions } => {
                permission_count_findings(&mut findings, permissions.len());
                findings.repeated(
                    permissions.iter().enumerate().map(|(index, permission)| {
                        (
                            format!("/permissions/{index}/collection"),
                            permission.collection.as_str(),
                        )
                    }),
                    "casework.task-template.duplicate-permission",
                    "this collection already has a permission",
                    "Merge the operations into one permission per collection.",
                );
                for (index, permission) in permissions.iter().enumerate() {
                    let at = format!("/permissions/{index}");
                    if !bounded_grant_identifier(&permission.collection, 512) {
                        findings.push(
                            "casework.task-template.invalid-bounds",
                            format!("{at}/collection"),
                            GRANT_IDENTIFIER_MESSAGE,
                            "Write the registry collection identifier.",
                        );
                    }
                    list_findings(
                        &mut findings,
                        &format!("{at}/operations"),
                        &permission.operations,
                        32,
                    );
                    for (operation_index, operation) in permission.operations.iter().enumerate() {
                        if !crate::typed::valid_local_identifier(operation) {
                            findings.push(
                                "casework.task-template.invalid-operation",
                                format!("{at}/operations/{operation_index}"),
                                "expected 1 to 64 characters: a lowercase letter, then lowercase letters, digits, '_', or '-'",
                                "Write a registry operation, such as get or list.",
                            );
                        }
                    }
                }
            }
            Self::Scheduling { permissions } => {
                permission_count_findings(&mut findings, permissions.len());
                findings.repeated(
                    permissions.iter().enumerate().map(|(index, permission)| {
                        (
                            format!("/permissions/{index}"),
                            (permission.service.as_str(), permission.location.as_str()),
                        )
                    }),
                    "casework.task-template.duplicate-permission",
                    "this service and location already have a permission",
                    "Merge the actions into one permission per service and location.",
                );
                for (index, permission) in permissions.iter().enumerate() {
                    let at = format!("/permissions/{index}");
                    for (member, value) in [
                        ("service", &permission.service),
                        ("location", &permission.location),
                    ] {
                        if !bounded_grant_identifier(value, 512) {
                            findings.push(
                                "casework.task-template.invalid-bounds",
                                format!("{at}/{member}"),
                                GRANT_IDENTIFIER_MESSAGE,
                                "Write the Scheduling identifier.",
                            );
                        }
                    }
                    list_findings(
                        &mut findings,
                        &format!("{at}/actions"),
                        &permission.actions,
                        32,
                    );
                    for (action_index, action) in permission.actions.iter().enumerate() {
                        if !valid_operation(action) {
                            findings.push(
                                "casework.task-template.invalid-operation",
                                format!("{at}/actions/{action_index}"),
                                "expected 1 to 128 characters: a lowercase letter, then lowercase letters, digits, '.', '_', ':', or '-'",
                                "Write a Scheduling action, such as appointment.book.",
                            );
                        }
                    }
                }
            }
        }
        findings.into_vec()
    }
}

const GRANT_IDENTIFIER_MESSAGE: &str =
    "expected 1 to 512 bytes with no whitespace, control characters, or '*'";

fn permission_count_findings(findings: &mut Findings, count: usize) {
    if count == 0 || count > 64 {
        findings.push(
            "casework.task-template.permissions-out-of-range",
            "/permissions",
            "expected 1 to 64 permissions",
            "List at least one permission and no more than 64.",
        );
    }
}

/// The findings `unique` stands for: a non-empty, bounded list of distinct
/// bounded values, at `pointer`.
fn list_findings(findings: &mut Findings, pointer: &str, values: &[String], maximum: usize) {
    if values.is_empty() {
        findings.push(
            "casework.task-template.empty-list",
            pointer,
            "expected at least one entry",
            "List at least one entry.",
        );
    }
    if values.len() > maximum {
        findings.push(
            "casework.task-template.too-many-entries",
            pointer,
            format!("at most {maximum} entries may be listed"),
            "Remove entries until no more than the bound remain.",
        );
    }
    for (index, value) in values.iter().enumerate() {
        if !bounded(value, 512) {
            findings.push(
                "casework.task-template.invalid-entry",
                format!("{pointer}/{index}"),
                "expected 1 to 512 bytes with no control characters or '*'",
                "Write the entry without control characters or '*'.",
            );
        }
    }
    findings.repeated(
        values
            .iter()
            .enumerate()
            .map(|(index, value)| (format!("{pointer}/{index}"), value.as_str())),
        "casework.task-template.duplicate-entry",
        "this entry is already listed",
        "List each entry once.",
    );
}

impl TaskTemplate {
    pub fn check(&self, project: &CaseworkProject) -> Result<(), TaskGrantError> {
        if self.findings(project).is_empty() {
            Ok(())
        } else {
            Err(TaskGrantError::Policy)
        }
    }

    /// Every problem in this template, located by pointers relative to the
    /// template.
    #[must_use]
    pub fn findings(&self, project: &CaseworkProject) -> Vec<ConfigFinding> {
        let mut findings = Findings::default();
        list_findings(&mut findings, "/reviewPolicies", &self.review_policies, 32);
        if !project
            .context_providers
            .iter()
            .any(|provider| provider.source_namespace == self.source)
            && !project
                .trusted_producers
                .iter()
                .any(|producer| producer.source_namespaces.contains(&self.source))
        {
            findings.push(
                "casework.task-template.unknown-source",
                "/source",
                "the source namespace is not declared by a provider or producer",
                "Name an admitted namespace.",
            );
        }
        if !crate::typed::valid_local_identifier(&self.id) {
            findings.push(
                "casework.task-template.invalid-id",
                "/id",
                crate::finding::IDENTIFIER_MESSAGE,
                crate::finding::IDENTIFIER_ACTION,
            );
        }
        for (member, value, maximum) in
            [("version", &self.version, 128), ("label", &self.label, 160)]
        {
            if !bounded(value, maximum) {
                findings.push(
                    "casework.task-template.invalid-text",
                    format!("/{member}"),
                    format!("expected 1 to {maximum} bytes with no control characters or '*'"),
                    "Write the value without control characters or '*'.",
                );
            }
        }
        list_findings(&mut findings, "/eligibleTeams", &self.eligible_teams, 32);
        for (index, team) in self.eligible_teams.iter().enumerate() {
            if bounded(team, 512) && !crate::valid_directory_identifier(team) {
                findings.push(
                    "casework.task-template.invalid-team",
                    format!("/eligibleTeams/{index}"),
                    crate::finding::DIRECTORY_IDENTIFIER_MESSAGE,
                    crate::finding::DIRECTORY_IDENTIFIER_ACTION,
                );
            }
        }
        list_findings(
            &mut findings,
            "/eligibleProfiles",
            &self.eligible_profiles,
            32,
        );
        for (index, id) in self.eligible_profiles.iter().enumerate() {
            let eligible = project.access_profiles.iter().any(|profile| {
                profile.id == *id
                    && matches!(profile.role, CaseworkRole::Staff | CaseworkRole::Supervisor)
            });
            if !eligible {
                findings.push(
                    "casework.task-template.ineligible-profile",
                    format!("/eligibleProfiles/{index}"),
                    "no staff or supervisor access profile has this id",
                    "Name an access profile with role staff or supervisor.",
                );
            }
        }
        for (index, kind) in self.review_policies.iter().enumerate() {
            let decidable = project.review_policies.iter().any(|candidate| {
                candidate.id == *kind
                    && candidate.stages.iter().any(|stage| {
                        stage
                            .deciding_profiles
                            .iter()
                            .any(|profile| self.eligible_profiles.contains(profile))
                    })
            });
            if !decidable {
                findings.push(
                    "casework.task-template.unknown-review-policy",
                    format!("/reviewPolicies/{index}"),
                    "no review policy with this id has a stage decided by one of the template's eligibleProfiles",
                    "Name a review policy declared under reviewPolicies whose stage lists an eligible profile in decidingProfiles.",
                );
            }
        }
        for (index, team) in self.eligible_teams.iter().enumerate() {
            if !project.teams.iter().any(|declared| declared.id == *team) {
                findings.push(
                    "casework.task-template.unknown-team",
                    format!("/eligibleTeams/{index}"),
                    "the eligible team is not declared",
                    "Declare this team under teams.",
                );
            }
        }
        for (index, policy_id) in self.review_policies.iter().enumerate() {
            let Some(policy) = project
                .review_policies
                .iter()
                .find(|policy| policy.id == *policy_id)
            else {
                continue;
            };
            let namespace_matches = match &policy.context {
                crate::ReviewContextPolicy::Submitted => {
                    project.trusted_producers.iter().any(|producer| {
                        producer.review_policies.contains(policy_id)
                            && producer.source_namespaces.contains(&self.source)
                    })
                }
                crate::ReviewContextPolicy::CurrentSource { provider, .. } => {
                    project.context_providers.iter().any(|candidate| {
                        candidate.id == *provider && candidate.source_namespace == self.source
                    })
                }
            };
            if !namespace_matches {
                findings.push(
                    "casework.task-template.policy-namespace",
                    format!("/reviewPolicies/{index}"),
                    "the template namespace does not match the policy's source contract",
                    "Use the policy's admitted source namespace.",
                );
            }
            for (claim, field) in &self.subjects {
                let schema = policy
                    .display_schema
                    .get("properties")
                    .and_then(|properties| properties.get(field));
                if schema
                    .and_then(|schema| schema.get("type"))
                    .and_then(Value::as_str)
                    .is_none_or(|kind| !matches!(kind, "string" | "boolean" | "integer" | "number"))
                {
                    findings.push(
                        "casework.task-template.unknown-subject-field",
                        format!(
                            "/subjects/{}",
                            registry_platform_yaml::escape_pointer_segment(claim)
                        ),
                        "the subject expression must select a declared scalar context field",
                        "Name one scalar field in every selected policy's displaySchema.",
                    );
                }
            }
        }
        for (pointer, value) in [
            ("/agent/issuer", &self.agent.issuer),
            ("/agent/subject", &self.agent.subject),
            ("/client", &self.client),
            ("/resource", &self.resource),
        ] {
            if !bounded(value, 512) {
                findings.push(
                    "casework.task-template.invalid-text",
                    pointer,
                    "expected 1 to 512 bytes with no control characters or '*'",
                    "Write the value without control characters or '*'.",
                );
            }
        }
        list_findings(&mut findings, "/scopes", &self.scopes, 32);
        for (index, scope) in self.scopes.iter().enumerate() {
            if scope.len() > 128
                || !scope
                    .bytes()
                    .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
            {
                findings.push(
                    "casework.task-template.invalid-scope",
                    format!("/scopes/{index}"),
                    "expected an OAuth scope token of at most 128 printable ASCII characters, without spaces, '\"', or '\\'",
                    "Write one OAuth scope per entry.",
                );
            }
        }
        if !bounded(&self.purpose, 128)
            || !matches!(self.purpose.as_bytes().first(), Some(b'a'..=b'z'))
            || self.purpose.bytes().any(|byte| {
                !(byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b':' | b'.'))
            })
        {
            findings.push(
                "casework.task-template.invalid-purpose",
                "/purpose",
                "expected 1 to 128 characters: a lowercase letter, then lowercase letters, digits, '-', '_', ':', or '.'",
                "Write a purpose, such as eligibility.review.",
            );
        }
        if self.subjects.is_empty() || self.subjects.len() > 32 {
            findings.push(
                "casework.task-template.subjects-out-of-range",
                "/subjects",
                "expected 1 to 32 subject claims",
                "Map at least one token claim, and no more than 32, to a source field.",
            );
        }
        for (claim, field) in &self.subjects {
            let at = format!(
                "/subjects/{}",
                registry_platform_yaml::escape_pointer_segment(claim)
            );
            if !crate::valid_directory_identifier(claim) {
                findings.push(
                    "casework.task-template.invalid-subject-claim",
                    at.as_str(),
                    crate::finding::DIRECTORY_IDENTIFIER_MESSAGE,
                    crate::finding::DIRECTORY_IDENTIFIER_ACTION,
                );
            }
            if !bounded(field, 128) {
                findings.push(
                    "casework.task-template.invalid-subject-field",
                    at,
                    "expected a source field name of 1 to 128 bytes with no control characters or '*'",
                    "Write the governed source field the claim takes its value from.",
                );
            }
        }
        let maximum_lifetime = self.authorization_mode.maximum_lifetime_seconds();
        if self.lifetime_seconds == 0 || self.lifetime_seconds > maximum_lifetime {
            findings.push(
                "casework.task-template.lifetime-out-of-range",
                "/lifetimeSeconds",
                format!(
                    "expected a whole number of seconds from 1 to {maximum_lifetime} for this authorizationMode"
                ),
                "Write a lifetime within the bound.",
            );
        }
        // Evidence checks only the grant deadline and no grant status, so an
        // Evidence grant keeps the immediate window.
        if self.authorization_mode == TaskAuthorizationMode::Deferred
            && matches!(self.bounds, TaskGrantBounds::Evidence { .. })
        {
            findings.push(
                "casework.task-template.deferred-evidence",
                "/authorizationMode",
                "a deferred grant cannot carry bounds of type evidence",
                "Remove authorizationMode, or use BREG or Scheduling bounds.",
            );
        }
        findings.extend_under("/bounds", self.bounds.findings());
        match (&self.bounds, &self.evidence_context) {
            (TaskGrantBounds::Evidence { .. }, Some(context)) => {
                findings.extend_under("/evidenceContext", context.findings());
            }
            (TaskGrantBounds::Evidence { .. }, None) => findings.push(
                "casework.task-template.missing-evidence-context",
                "/bounds",
                "an Evidence grant carries an evidenceContext",
                "Add evidenceContext with requesterTags and audience.",
            ),
            (TaskGrantBounds::Breg { .. } | TaskGrantBounds::Scheduling { .. }, Some(_)) => {
                findings.push(
                    "casework.task-template.unexpected-evidence-context",
                    "/evidenceContext",
                    "evidenceContext applies only to bounds of type evidence",
                    "Remove evidenceContext.",
                );
            }
            (TaskGrantBounds::Breg { .. } | TaskGrantBounds::Scheduling { .. }, None) => {}
        }
        findings.into_vec()
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
                        if number.as_i64().is_some_and(|value| {
                            value.unsigned_abs() <= crate::MAXIMUM_PORTABLE_JSON_INTEGER
                        }) || number
                            .as_u64()
                            .is_some_and(|value| value <= crate::MAXIMUM_PORTABLE_JSON_INTEGER) => {
                    }
                    _ => return Err(TaskGrantError::Subjects),
                }
                Ok((claim.clone(), value.clone()))
            })
            .collect()
    }
}

impl EvidenceRequesterContext {
    fn findings(&self) -> Vec<ConfigFinding> {
        let mut findings = Findings::default();
        list_findings(&mut findings, "/requesterTags", &self.requester_tags, 32);
        for (index, tag) in self.requester_tags.iter().enumerate() {
            if !valid_evidence_tag(tag) {
                findings.push(
                    "casework.task-template.invalid-requester-tag",
                    format!("/requesterTags/{index}"),
                    "expected 1 to 128 characters: a lowercase letter, then lowercase letters, digits, '.', '_', or '-'",
                    "Write a requester tag the Evidence deployment admits.",
                );
            }
        }
        if !registry_platform_httputil::valid_resource_uri(&self.audience) {
            findings.push(
                "casework.task-template.invalid-audience",
                "/audience",
                "expected an absolute resource URI with no fragment and no user information",
                "Write the relying-party audience as an absolute URI, such as https://evidence.example.org.",
            );
        }
        findings.into_vec()
    }
}

fn valid_evidence_tag(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskGrant {
    pub id: Uuid,
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub task_revision: i64,
    /// Deferred authorization pins responsibility independently of draft edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment_generation: Option<i64>,
    pub holder: IssuerPrincipal,
    pub template: TaskTemplate,
    pub template_digest: crate::ContentDigest,
    pub source_issuer: String,
    pub approver_profile: String,
    pub subject: crate::SubjectBinding,
    pub subjects: BTreeMap<String, Value>,
    pub approved_at: u64,
    pub expires_at: u64,
}

impl fmt::Debug for ReviewTaskGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReviewTaskGrant")
            .field("task_id", &self.task_id)
            .field("request_id", &self.request_id)
            .field("task_revision", &self.task_revision)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
fn bounded_grant_identifier(value: &str, maximum: usize) -> bool {
    bounded(value, maximum) && !value.chars().any(char::is_whitespace)
}
fn valid_operation(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 128
        && !value.contains('*')
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskTemplatePreview {
    pub id: String,
    pub version: String,
    pub label: String,
    pub agent: IssuerPrincipal,
    pub client: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub purpose: String,
    pub bounds: TaskGrantBounds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_context: Option<EvidenceRequesterContext>,
    pub subjects: BTreeMap<String, Value>,
    /// Immediate authorizations last at most fifteen minutes. Deferred is an
    /// explicit governed window of at most seven days; assertion TTL stays sixty seconds.
    #[serde(default, skip_serializing_if = "TaskAuthorizationMode::is_immediate")]
    pub authorization_mode: TaskAuthorizationMode,
    pub lifetime_seconds: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskTemplatePreviews {
    pub task_revision: i64,
    pub templates: Vec<TaskTemplatePreview>,
}

/// Grant metadata. Stored subjects are deliberately absent: preview and approval
/// derive selectors from the caller's current disclosed source representation.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantView {
    pub id: Uuid,
    pub template_id: String,
    pub template_version: String,
    pub agent: IssuerPrincipal,
    pub client: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub purpose: String,
    pub bounds: TaskGrantBounds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_context: Option<EvidenceRequesterContext>,
    /// Immediate authorizations last at most fifteen minutes. Deferred is an
    /// explicit governed window of at most seven days; assertion TTL stays sixty seconds.
    #[serde(default, skip_serializing_if = "TaskAuthorizationMode::is_immediate")]
    pub authorization_mode: TaskAuthorizationMode,
    pub expires_at: u64,
    pub invalidated: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantList {
    pub grants: Vec<TaskGrantView>,
}

#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantRevocation {
    pub id: Uuid,
    pub invalidated: bool,
}

/// Short-lived credential response. Deliberately does not implement Debug.
#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskAssertionResponse {
    pub assertion: String,
    pub expires_at: u64,
    pub grant_expires_at: u64,
}

/// Fresh status returned only to the service client registered for this resource.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatus {
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<TaskGrantStatusDetails>,
}

#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskGrantStatusDetails {
    pub grant_id: Uuid,
    pub source_issuer: String,
    pub principal: String,
    pub client: String,
    pub resource: String,
    pub purpose: String,
    pub bounds: TaskGrantBounds,
    pub subjects: BTreeMap<String, Value>,
    pub expires_at: u64,
}
