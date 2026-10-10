use std::collections::BTreeSet;
use std::path::Path;

pub use registry_platform_yaml::ProjectIdentity;
use registry_platform_yaml::{
    ApiVersion, Decoded, EnvelopeRule, Expect, FormatSpec, Identified, Reader, Refusal, RemovedKey,
    Report, RetiredApiVersion, ScalarHook, ScalarSite,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::finding::{
    findings_report, ConfigFinding, Findings, ELAPSED_ACTION, ELAPSED_MESSAGE, IDENTIFIER_ACTION,
    IDENTIFIER_MESSAGE,
};
use crate::CaseworkRole;
use crate::ReviewKindPolicy;
use crate::MAXIMUM_REVIEW_RETENTION_DAYS;
use crate::{
    clock_policy_findings, routing_policy_findings, CalendarPolicy, ClockPolicy, RoutingRule,
};

pub const CASEWORK_API_VERSION: &str = "id.registrystack.org/formats/casework/project/v1alpha1";
pub const CASEWORK_KIND: &str = "CaseworkProject";
// Matches the maximum RFC 6749 scope-token size Casework accepts.
const MAXIMUM_REQUIRED_SCOPE_BYTES: usize = 256;
/// The most sources one project declares, which bounds the source
/// descriptions a project check reads.
pub const MAXIMUM_SOURCES: usize = 64;

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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkProject {
    pub api_version: String,
    pub kind: String,
    pub project: ProjectIdentity,
    #[serde(deserialize_with = "crate::typed::unique_id_list")]
    pub access_profiles: Vec<AccessProfile>,
    #[serde(deserialize_with = "crate::typed::unique_id_list")]
    pub queues: Vec<QueuePolicy>,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub sources: Vec<SourcePolicy>,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub review_kinds: Vec<ReviewKindPolicy>,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub review_producers: Vec<ReviewProducerPolicy>,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub calendars: Vec<CalendarPolicy>,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub clocks: Vec<ClockPolicy>,
    #[serde(default)]
    pub inbox: InboxPolicy,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub task_templates: Vec<crate::TaskTemplate>,
}

/// The named lists of a project are unique by `id` (CFG-ID-5).
macro_rules! identified {
    ($($item:ty),+ $(,)?) => {$(
        impl Identified for $item {
            fn id(&self) -> &str {
                &self.id
            }
        }
    )+};
}
identified!(
    AccessProfile,
    QueuePolicy,
    SourcePolicy,
    ReviewKindPolicy,
    ReviewProducerPolicy,
    CalendarPolicy,
    crate::TaskTemplate,
);

impl Identified for ClockPolicy {
    fn id(&self) -> &str {
        ClockPolicy::id(self)
    }
}

/// The format a `casework.yaml` file declares (CFG-ENV-1).
pub const CASEWORK_PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CASEWORK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CASEWORK_API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: "registry.registrystack.org/casework/v1alpha1",
            replacement:
                "Write apiVersion: id.registrystack.org/formats/casework/project/v1alpha1.",
        }],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/casework",
            replacement:
                "Write the project identity as project: {id: PROJECT_ID, version: \"VERSION\"}.",
        },
        RemovedKey {
            pointer: "/clocks/*/scope",
            replacement: "Write the clock's kind as type: subject or type: activity.",
        },
    ],
};

/// The name a project read from bytes carries in its diagnostics.
pub const CASEWORK_PROJECT_FILE: &str = "casework.yaml";

const PROFILE_IDENTIFIER_MESSAGE: &str =
    "expected 1 to 128 ASCII letters, digits, '-', '_', '.', or ':'";
const PROFILE_IDENTIFIER_ACTION: &str = "Write an access profile identifier, such as caseworker.";
const REVIEW_NAME_MESSAGE: &str = "expected 1 to 128 ASCII letters, digits, '-', '_', '.', or ':'";
const UNKNOWN_QUEUE_MESSAGE: &str = "no queue in queues has this id";
const UNKNOWN_QUEUE_ACTION: &str = "Name a queue declared under queues.";
const UNKNOWN_CLOCK_MESSAGE: &str = "no clock in clocks has this id";
const UNKNOWN_CLOCK_ACTION: &str = "Name a clock declared under clocks.";

/// Refuses every `${...}` expression in `casework.yaml`: substitution applies
/// to `runtime.yaml` only (CFG-SEC-2). The action names where the deployment
/// binds a value instead.
struct AuthoredSubstitution;

impl AuthoredSubstitution {
    fn check(site: &ScalarSite<'_>) -> Result<(), Refusal> {
        if !contains_environment_expression(site.text) {
            return Ok(());
        }
        let issuer = matches!(
            site.keys.last(),
            Some(&("issuer" | "trustedInitiatorIssuer"))
        );
        let suggested_action = if issuer {
            "Write the issuer in casework.yaml directly; runtime.yaml binds no issuer of an authored principal, so a deployment that trusts a different issuer builds its own package."
        } else {
            "Write the value in casework.yaml directly; substitution applies to runtime.yaml only, where sources.<id> binds a source endpoint and its credentials and reviewCompletionDestinations.<id> binds a completion destination."
        };
        Err(Refusal {
            code: "config.substitution-not-allowed".to_owned(),
            message: "a `${...}` expression is written in casework.yaml; substitution applies to runtime.yaml only".to_owned(),
            suggested_action: suggested_action.to_owned(),
        })
    }
}

impl ScalarHook for AuthoredSubstitution {
    fn key(&mut self, site: &ScalarSite<'_>) -> Result<(), Refusal> {
        Self::check(site)
    }

    fn value(&mut self, site: &ScalarSite<'_>) -> Result<Option<String>, Refusal> {
        Self::check(site).map(|()| None)
    }
}

/// Whether `text` holds a `${NAME}`, `${NAME:-default}`, or `${NAME:?message}`
/// expression, the forms runtime substitution reads.
pub(crate) fn contains_environment_expression(text: &str) -> bool {
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let name_end = after
            .find(|character: char| character != '_' && !character.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        let name = &after[..name_end];
        let tail = &after[name_end..];
        let mut characters = name.chars();
        let valid_name =
            matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_alphabetic());
        if valid_name && (tail.starts_with('}') || tail.starts_with(":-") || tail.starts_with(":?"))
        {
            return true;
        }
        rest = after;
    }
    false
}

impl CaseworkProject {
    /// Read and check one `casework.yaml` file through the shared reader.
    /// `file` is the name diagnostics carry. A refusal is the report a check
    /// command prints unchanged: every structural problem, or every finding
    /// of the semantic checks, each at its position.
    pub fn read(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let mut hook = AuthoredSubstitution;
        let decoded = Reader::new(file)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&CASEWORK_PROJECT_FORMAT))?;
        let findings = decoded.value.findings();
        if findings.is_empty() {
            Ok(decoded)
        } else {
            Err(findings_report(&decoded.document, &findings))
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigLoadError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(ConfigLoadError::Read)?;
        Self::read(&path.display().to_string(), &bytes)
            .map(|decoded| decoded.value)
            .map_err(ConfigLoadError::Refused)
    }

    /// Decode and validate one captured Casework project document.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ConfigLoadError> {
        Self::read(CASEWORK_PROJECT_FILE, bytes)
            .map(|decoded| decoded.value)
            .map_err(ConfigLoadError::Refused)
    }

    pub fn check(&self) -> Result<(), ConfigError> {
        let findings = self.findings();
        if findings.is_empty() {
            Ok(())
        } else {
            Err(ConfigError { findings })
        }
    }

    /// Every problem the semantic checks find, each located by an RFC 6901
    /// pointer into the project (CFG-DIAG-5).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn findings(&self) -> Vec<ConfigFinding> {
        let mut findings = Findings::default();
        if self.api_version != CASEWORK_API_VERSION {
            findings.push(
                "casework.project.wrong-api-version",
                "/apiVersion",
                "this is not the Casework project apiVersion",
                format!("Write apiVersion: {CASEWORK_API_VERSION}."),
            );
        }
        if self.kind != CASEWORK_KIND {
            findings.push(
                "casework.project.wrong-kind",
                "/kind",
                "this is not the Casework project kind",
                format!("Write kind: {CASEWORK_KIND}."),
            );
        }
        if self.project.version.is_empty() {
            findings.push(
                "casework.project.empty-version",
                "/project/version",
                "the project version is empty",
                "Write the project version, such as 1.",
            );
        }
        self.task_template_findings(&mut findings);
        let queues: BTreeSet<_> = self.queues.iter().map(|queue| queue.id.clone()).collect();
        self.queue_findings(&mut findings);
        self.access_profile_findings(&mut findings);
        self.review_kind_findings(&mut findings, &queues);
        self.review_producer_findings(&mut findings);
        if self.sources.is_empty() && self.review_kinds.is_empty() {
            findings.push(
                "casework.project.no-work",
                "",
                "the project declares neither sources nor reviewKinds, so it has no work to coordinate",
                "Declare a source under sources or a review kind under reviewKinds.",
            );
        }
        for finding in clock_policy_findings(&self.calendars, &self.clocks, &queues) {
            findings.add(finding);
        }
        self.source_findings(&mut findings, &queues);
        self.inbox.findings(&mut findings);
        findings.into_vec()
    }

    fn task_template_findings(&self, findings: &mut Findings) {
        if self.task_templates.len() > 64 {
            findings.push(
                "casework.task-template.too-many",
                "/taskTemplates",
                "at most 64 task templates may be declared",
                "Remove task templates until no more than the bound remain.",
            );
        }
        findings.repeated(
            self.task_templates
                .iter()
                .enumerate()
                .map(|(index, template)| {
                    (format!("/taskTemplates/{index}/id"), template.id.as_str())
                }),
            "casework.task-template.duplicate-id",
            "this task template id is already declared",
            "Give every task template a unique id.",
        );
        for (index, template) in self.task_templates.iter().enumerate() {
            findings.extend_under(&format!("/taskTemplates/{index}"), template.findings(self));
        }
    }

    fn queue_findings(&self, findings: &mut Findings) {
        if self.queues.is_empty() {
            findings.push(
                "casework.queue.none",
                "/queues",
                "a project declares at least one queue",
                "Declare a queue under queues.",
            );
        }
        findings.repeated(
            self.queues
                .iter()
                .enumerate()
                .map(|(index, queue)| (format!("/queues/{index}/id"), queue.id.as_str())),
            "casework.queue.duplicate-id",
            "this queue id is already declared",
            "Give every queue a unique id.",
        );
        for (index, queue) in self.queues.iter().enumerate() {
            if !crate::typed::valid_local_identifier(&queue.id) {
                findings.push(
                    "casework.queue.invalid-id",
                    format!("/queues/{index}/id"),
                    IDENTIFIER_MESSAGE,
                    IDENTIFIER_ACTION,
                );
            }
            if queue.label.trim().is_empty() || queue.label.len() > 160 {
                findings.push(
                    "casework.queue.invalid-label",
                    format!("/queues/{index}/label"),
                    "expected a label of 1 to 160 bytes that is not only spaces",
                    "Write a short label for the queue.",
                );
            }
        }
    }

    fn access_profile_findings(&self, findings: &mut Findings) {
        for (index, profile) in self.access_profiles.iter().enumerate() {
            if !crate::typed::valid_local_identifier(&profile.id) {
                findings.push(
                    "casework.access-profile.invalid-id",
                    format!("/accessProfiles/{index}/id"),
                    IDENTIFIER_MESSAGE,
                    PROFILE_IDENTIFIER_ACTION,
                );
            }
        }
        findings.repeated(
            self.access_profiles
                .iter()
                .enumerate()
                .map(|(index, profile)| {
                    (format!("/accessProfiles/{index}/id"), profile.id.as_str())
                }),
            "casework.access-profile.duplicate-id",
            "this access profile id is already declared",
            "Give every access profile a unique id.",
        );
        for (index, profile) in self.access_profiles.iter().enumerate() {
            let at = format!("/accessProfiles/{index}");
            if profile.principal_claim.is_empty() {
                findings.push(
                    "casework.access-profile.empty-principal-claim",
                    format!("{at}/principalClaim"),
                    "the principal claim is empty",
                    "Name the token claim that carries the caller's principal, such as registry_principal.",
                );
            }
            if profile.required_scopes.is_empty() {
                findings.push(
                    "casework.access-profile.no-required-scope",
                    format!("{at}/requiredScopes"),
                    "an access profile requires at least one scope",
                    "List the OAuth scope a caller holds to select this profile.",
                );
            }
            for (scope_index, scope) in profile.required_scopes.iter().enumerate() {
                if !valid_required_scope(scope) {
                    findings.push(
                        "casework.access-profile.invalid-scope",
                        format!("{at}/requiredScopes/{scope_index}"),
                        format!(
                            "expected an OAuth scope token of 1 to {MAXIMUM_REQUIRED_SCOPE_BYTES} printable ASCII characters, without spaces, '\"', or '\\'"
                        ),
                        "Write one OAuth scope per entry.",
                    );
                }
            }
        }
        for (role, name) in [
            (CaseworkRole::Staff, "staff"),
            (CaseworkRole::Supervisor, "supervisor"),
            (CaseworkRole::Administrator, "administrator"),
        ] {
            if !self
                .access_profiles
                .iter()
                .any(|profile| profile.role == role)
            {
                findings.push(
                    "casework.access-profile.missing-role",
                    "/accessProfiles",
                    format!("no access profile has role {name}"),
                    format!("Declare an access profile with role: {name}."),
                );
            }
        }
        for index in profiles_without_a_separate_scope(&self.access_profiles) {
            findings.push(
                "casework.access-profile.shared-scopes",
                format!("/accessProfiles/{index}/requiredScopes"),
                "every scope this profile requires is also required by another profile at the same or a lower role, so their credentials could select this profile",
                "Require a scope that no other profile at the same or a lower role requires.",
            );
        }
    }

    fn review_kind_findings(&self, findings: &mut Findings, queues: &BTreeSet<String>) {
        if self.review_kinds.len() > crate::MAXIMUM_REVIEW_KINDS {
            findings.push(
                "casework.review-kind.too-many",
                "/reviewKinds",
                format!(
                    "at most {} review kinds may be declared",
                    crate::MAXIMUM_REVIEW_KINDS
                ),
                "Remove review kinds until no more than the bound remain.",
            );
        }
        findings.repeated(
            self.review_kinds
                .iter()
                .enumerate()
                .map(|(index, kind)| (format!("/reviewKinds/{index}/id"), kind.id.as_str())),
            "casework.review-kind.duplicate-id",
            "this review kind id is already declared",
            "Give every review kind a unique id.",
        );
        for (kind_index, kind) in self.review_kinds.iter().enumerate() {
            let at = format!("/reviewKinds/{kind_index}");
            findings.extend_under(&at, kind.findings());
            for (clock_index, clock_id) in kind.clocks.iter().enumerate() {
                if !self.clocks.iter().any(|clock| clock.id() == clock_id) {
                    findings.push(
                        "casework.review-kind.unknown-clock",
                        format!("{at}/clocks/{clock_index}"),
                        UNKNOWN_CLOCK_MESSAGE,
                        UNKNOWN_CLOCK_ACTION,
                    );
                }
            }
            for (stage_index, stage) in kind.stages.iter().enumerate() {
                let stage_at = format!("{at}/stages/{stage_index}");
                if !queues.contains(&stage.queue) {
                    findings.push(
                        "casework.review-kind.unknown-queue",
                        format!("{stage_at}/queue"),
                        UNKNOWN_QUEUE_MESSAGE,
                        UNKNOWN_QUEUE_ACTION,
                    );
                }
                for (profile_index, profile_id) in stage.deciding_profiles.iter().enumerate() {
                    if self
                        .access_profiles
                        .iter()
                        .find(|profile| profile.id == *profile_id)
                        .is_none_or(|profile| {
                            !matches!(profile.role, CaseworkRole::Staff | CaseworkRole::Supervisor)
                        })
                    {
                        findings.push(
                            "casework.review-kind.ineligible-deciding-profile",
                            format!("{stage_at}/decidingProfiles/{profile_index}"),
                            "no staff or supervisor access profile has this id",
                            "Name an access profile with role staff or supervisor.",
                        );
                    }
                }
            }
        }
    }

    fn review_producer_findings(&self, findings: &mut Findings) {
        if self.review_producers.len() > 64 {
            findings.push(
                "casework.review-producer.too-many",
                "/reviewProducers",
                "at most 64 review producers may be declared",
                "Remove review producers until no more than the bound remain.",
            );
        }
        findings.repeated(
            self.review_producers
                .iter()
                .enumerate()
                .map(|(index, producer)| {
                    (format!("/reviewProducers/{index}/id"), producer.id.as_str())
                }),
            "casework.review-producer.duplicate-id",
            "this review producer id is already declared",
            "Give every review producer a unique id.",
        );
        findings.repeated(
            self.review_producers
                .iter()
                .enumerate()
                .map(|(index, producer)| {
                    (
                        format!("/reviewProducers/{index}"),
                        (
                            producer.profile.as_str(),
                            producer.issuer.as_str(),
                            producer.subject.as_str(),
                        ),
                    )
                }),
            "casework.review-producer.duplicate-principal",
            "another review producer already has this profile, issuer, and subject",
            "Give each review producer its own principal.",
        );
        if !self.review_kinds.is_empty() && self.review_producers.is_empty() {
            findings.push(
                "casework.review-producer.none",
                "/reviewProducers",
                "review kinds are declared but no review producer may submit them",
                "Declare a review producer under reviewProducers, or remove reviewKinds.",
            );
        }
        if self.review_kinds.is_empty() && !self.review_producers.is_empty() {
            findings.push(
                "casework.review-producer.without-review-kinds",
                "/reviewProducers",
                "review producers are declared but no review kind exists",
                "Declare the review kinds they submit under reviewKinds, or remove reviewProducers.",
            );
        }
        for (producer_index, producer) in self.review_producers.iter().enumerate() {
            let at = format!("/reviewProducers/{producer_index}");
            producer.findings(findings, &at);
            if self
                .access_profiles
                .iter()
                .find(|profile| profile.id == producer.profile)
                .is_none_or(|profile| profile.role != CaseworkRole::Requester)
            {
                findings.push(
                    "casework.review-producer.not-a-requester-profile",
                    format!("{at}/profile"),
                    "no requester access profile has this id",
                    "Name an access profile with role requester.",
                );
            }
            if let Some(initiator_profile) = &producer.initiator_profile {
                let requester_profile = self.access_profiles.iter().any(|profile| {
                    profile.id == *initiator_profile && profile.role == CaseworkRole::Requester
                });
                let producer_profile = self
                    .review_producers
                    .iter()
                    .any(|other| other.profile == *initiator_profile);
                if !requester_profile || producer_profile {
                    findings.push(
                        "casework.review-producer.ineligible-initiator-profile",
                        format!("{at}/initiatorProfile"),
                        "the initiator profile must be a requester access profile that no review producer uses",
                        "Name a requester access profile reserved for initiators.",
                    );
                }
                if producer.trusted_initiator_issuer.is_none() {
                    findings.add(
                        ConfigFinding::new(
                            "casework.review-producer.missing-trusted-initiator-issuer",
                            format!("{at}/trustedInitiatorIssuer"),
                            "initiatorProfile needs trustedInitiatorIssuer",
                            "Add trustedInitiatorIssuer naming the issuer that authenticates initiators.",
                        )
                        .with_related(format!("{at}/initiatorProfile"), "initiatorProfile is written here"),
                    );
                }
            }
            let mut exclusion_reported = producer.trusted_initiator_issuer.is_some();
            for (kind_index, kind_id) in producer.kinds.iter().enumerate() {
                let Some((declared_index, kind)) = self
                    .review_kinds
                    .iter()
                    .enumerate()
                    .find(|(_, kind)| kind.id == *kind_id)
                else {
                    findings.push(
                        "casework.review-producer.unknown-review-kind",
                        format!("{at}/kinds/{kind_index}"),
                        "no review kind in reviewKinds has this id",
                        "Name a review kind declared under reviewKinds.",
                    );
                    continue;
                };
                if kind.retention.terminal_days < producer.recovery_days {
                    findings.add(
                        ConfigFinding::new(
                            "casework.review-producer.recovery-exceeds-retention",
                            format!("{at}/recoveryDays"),
                            "recoveryDays is longer than the result retention of a review kind this producer submits",
                            "Make recoveryDays no longer than that review kind's retention.terminalDays.",
                        )
                        .with_related(
                            format!("/reviewKinds/{declared_index}/retention/terminalDays"),
                            "terminalDays is written here",
                        ),
                    );
                }
                if !exclusion_reported {
                    if let Some(stage_index) =
                        kind.stages.iter().position(|stage| stage.exclude_initiator)
                    {
                        exclusion_reported = true;
                        findings.add(
                            ConfigFinding::new(
                                "casework.review-producer.missing-trusted-initiator-issuer",
                                format!("{at}/trustedInitiatorIssuer"),
                                "a review kind this producer submits excludes the initiator from deciding, which needs trustedInitiatorIssuer",
                                "Add trustedInitiatorIssuer naming the issuer that authenticates initiators.",
                            )
                            .with_related(
                                format!(
                                    "/reviewKinds/{declared_index}/stages/{stage_index}/excludeInitiator"
                                ),
                                "excludeInitiator is set here",
                            ),
                        );
                    }
                }
            }
        }
    }

    fn source_findings(&self, findings: &mut Findings, queues: &BTreeSet<String>) {
        let clock_ids = self
            .clocks
            .iter()
            .map(ClockPolicy::id)
            .collect::<BTreeSet<_>>();
        if self.sources.len() > MAXIMUM_SOURCES {
            findings.push(
                "casework.source.too-many",
                "/sources",
                format!("at most {MAXIMUM_SOURCES} sources may be declared"),
                "Remove sources until no more than the bound remain.",
            );
        }
        findings.repeated(
            self.sources
                .iter()
                .enumerate()
                .map(|(index, source)| (format!("/sources/{index}/id"), source.id.as_str())),
            "casework.source.duplicate-id",
            "this source id is already declared",
            "Give every source a unique id.",
        );
        for (source_index, source) in self.sources.iter().enumerate() {
            let at = format!("/sources/{source_index}");
            for (member, empty, action) in [
                (
                    "id",
                    source.id.is_empty(),
                    "Write the source id, such as civil-registry.",
                ),
                (
                    "adapter",
                    source.adapter.is_empty(),
                    "Write the adapter, such as breg.",
                ),
                (
                    "description",
                    source.description.is_empty(),
                    "Write the path of the source description file, relative to casework.yaml.",
                ),
            ] {
                if empty {
                    findings.push(
                        match member {
                            "id" => "casework.source.empty-id",
                            "adapter" => "casework.source.empty-adapter",
                            _ => "casework.source.empty-description",
                        },
                        format!("{at}/{member}"),
                        format!("{member} is empty"),
                        action,
                    );
                }
            }
            if source.requests.is_empty() {
                findings.push(
                    "casework.source.no-requests",
                    format!("{at}/requests"),
                    "a source declares at least one request",
                    "Declare a request under requests.",
                );
            }
            findings.repeated(
                source.requests.iter().enumerate().map(|(index, request)| {
                    (
                        format!("{at}/requests/{index}/entity"),
                        request.entity.as_str(),
                    )
                }),
                "casework.request.duplicate-entity",
                "another request of this source already names this entity",
                "Declare one request per entity.",
            );
            for (request_index, request) in source.requests.iter().enumerate() {
                let request_at = format!("{at}/requests/{request_index}");
                request.findings(findings, &request_at);
                for routing in routing_policy_findings(
                    &request.queue,
                    &request.projection,
                    &request.routing,
                    queues,
                    None,
                ) {
                    findings.push(
                        routing.reason.code(),
                        format!("{request_at}{}", routing.path),
                        routing.reason.message(),
                        routing.reason.suggested_action(),
                    );
                }
                if request
                    .clock
                    .as_deref()
                    .is_some_and(|clock| !clock_ids.contains(clock))
                {
                    findings.push(
                        "casework.request.unknown-clock",
                        format!("{request_at}/clock"),
                        UNKNOWN_CLOCK_MESSAGE,
                        UNKNOWN_CLOCK_ACTION,
                    );
                }
            }
        }
    }
}

/// The indices of the profiles that do not require a scope absent from the
/// combined scopes of every other profile at the same or a lower role. The
/// selected profile carries the caller's identity and role, so credentials
/// assembled from those other grants could select authority belonging to such
/// a profile, including authority retained under an earlier review policy. A
/// higher-role credential may still explicitly carry the scopes required by a
/// lower role. A profile that requires no scope is reported as such and not
/// here.
fn profiles_without_a_separate_scope(profiles: &[AccessProfile]) -> Vec<usize> {
    fn role_rank(role: CaseworkRole) -> u8 {
        match role {
            CaseworkRole::Requester => 0,
            CaseworkRole::Staff => 1,
            CaseworkRole::Supervisor => 2,
            CaseworkRole::Administrator => 3,
        }
    }
    profiles
        .iter()
        .enumerate()
        .filter(|(target_index, target)| {
            let target_rank = role_rank(target.role);
            let other_same_or_lower_scopes: BTreeSet<&String> = profiles
                .iter()
                .enumerate()
                .filter(|(index, profile)| {
                    index != target_index && role_rank(profile.role) <= target_rank
                })
                .flat_map(|(_, profile)| profile.required_scopes.iter())
                .collect();
            !target.required_scopes.is_empty()
                && target
                    .required_scopes
                    .iter()
                    .all(|scope| other_same_or_lower_scopes.contains(scope))
        })
        .map(|(index, _)| index)
        .collect()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessProfile {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub principal_claim: String,
    #[serde(deserialize_with = "crate::typed::unique_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<String>", length(min = 1))
    )]
    pub required_scopes: Vec<String>,
    pub role: CaseworkRole,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewProducerPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub profile: String,
    #[serde(deserialize_with = "crate::typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub issuer: String,
    pub subject: String,
    #[serde(
        default,
        deserialize_with = "crate::typed::optional_url",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub trusted_initiator_issuer: Option<String>,
    /// The requester profile a person named as this producer's initiator
    /// authenticates with to read the requester-visible history of their own
    /// requests. Absent, no initiator reads anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_profile: Option<String>,
    pub source_namespaces: Vec<String>,
    pub kinds: Vec<String>,
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_REVIEW_RETENTION_DAYS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_REVIEW_RETENTION_DAYS>")
    )]
    pub recovery_days: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<ReviewCompletionDestinationPolicy>,
}

impl ReviewProducerPolicy {
    /// The findings in the producer's own members, at `at`.
    fn findings(&self, findings: &mut Findings, at: &str) {
        if !crate::typed::valid_local_identifier(&self.id) {
            findings.push(
                "casework.review-producer.invalid-id",
                format!("{at}/id"),
                IDENTIFIER_MESSAGE,
                "Write a review producer identifier, such as benefits-portal.",
            );
        }
        if !valid_profile_identifier(&self.profile) {
            findings.push(
                "casework.review-producer.invalid-profile",
                format!("{at}/profile"),
                PROFILE_IDENTIFIER_MESSAGE,
                PROFILE_IDENTIFIER_ACTION,
            );
        }
        for (member, value, maximum, code) in [
            (
                "issuer",
                Some(&self.issuer),
                512,
                "casework.review-producer.invalid-issuer",
            ),
            (
                "subject",
                Some(&self.subject),
                256,
                "casework.review-producer.invalid-subject",
            ),
            (
                "trustedInitiatorIssuer",
                self.trusted_initiator_issuer.as_ref(),
                256,
                "casework.review-producer.invalid-trusted-initiator-issuer",
            ),
        ] {
            if value.is_some_and(|value| !bounded_config_text(value, maximum)) {
                findings.push(
                    code,
                    format!("{at}/{member}"),
                    format!(
                        "expected 1 to {maximum} bytes that are not only spaces and have no control characters"
                    ),
                    format!("Write {member} as the token issuer or subject sends it."),
                );
            }
        }
        if self
            .initiator_profile
            .as_ref()
            .is_some_and(|profile| !valid_profile_identifier(profile))
        {
            findings.push(
                "casework.review-producer.invalid-initiator-profile",
                format!("{at}/initiatorProfile"),
                PROFILE_IDENTIFIER_MESSAGE,
                PROFILE_IDENTIFIER_ACTION,
            );
        }
        if !(1..=crate::MAXIMUM_REVIEW_RETENTION_DAYS).contains(&self.recovery_days) {
            findings.push(
                "casework.review-producer.recovery-days-out-of-range",
                format!("{at}/recoveryDays"),
                format!(
                    "expected a whole number of days from 1 to {}",
                    crate::MAXIMUM_REVIEW_RETENTION_DAYS
                ),
                "Write a number of days within the bound.",
            );
        }
        name_list_findings(
            findings,
            &format!("{at}/sourceNamespaces"),
            &self.source_namespaces,
            64,
            [
                "casework.review-producer.no-source-namespaces",
                "casework.review-producer.too-many-source-namespaces",
                "casework.review-producer.invalid-source-namespace",
                "casework.review-producer.duplicate-source-namespace",
            ],
        );
        name_list_findings(
            findings,
            &format!("{at}/kinds"),
            &self.kinds,
            crate::MAXIMUM_REVIEW_KINDS,
            [
                "casework.review-producer.no-kinds",
                "casework.review-producer.too-many-kinds",
                "casework.review-producer.invalid-kind",
                "casework.review-producer.duplicate-kind",
            ],
        );
        if let Some(completion) = &self.completion {
            completion.findings(findings, &format!("{at}/completion"));
        }
    }
}

/// The findings of a non-empty, bounded list of distinct review names at
/// `pointer`: `codes` are the empty, too-many, invalid, and duplicate codes.
fn name_list_findings(
    findings: &mut Findings,
    pointer: &str,
    values: &[String],
    maximum: usize,
    [empty, too_many, invalid, duplicate]: [&'static str; 4],
) {
    if values.is_empty() {
        findings.push(
            empty,
            pointer,
            "expected at least one entry",
            "List at least one entry.",
        );
    }
    if values.len() > maximum {
        findings.push(
            too_many,
            pointer,
            format!("at most {maximum} entries may be listed"),
            "Remove entries until no more than the bound remain.",
        );
    }
    for (index, value) in values.iter().enumerate() {
        if !valid_review_name(value) {
            findings.push(
                invalid,
                format!("{pointer}/{index}"),
                REVIEW_NAME_MESSAGE,
                "Write a name of letters, digits, '-', '_', '.', or ':'.",
            );
        }
    }
    findings.repeated(
        values
            .iter()
            .enumerate()
            .map(|(index, value)| (format!("{pointer}/{index}"), value.as_str())),
        duplicate,
        "this entry is already listed",
        "List each entry once.",
    );
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCompletionDestinationPolicy {
    pub destination_id: String,
    pub recipient_binding: String,
}

impl ReviewCompletionDestinationPolicy {
    fn findings(&self, findings: &mut Findings, at: &str) {
        if !valid_review_name(&self.destination_id) {
            findings.push(
                "casework.review-producer.invalid-completion-destination",
                format!("{at}/destinationId"),
                REVIEW_NAME_MESSAGE,
                "Name the completion destination runtime.yaml binds under reviewCompletionDestinations.",
            );
        }
        if self.recipient_binding.is_empty()
            || self.recipient_binding.len() > 256
            || !self
                .recipient_binding
                .bytes()
                .all(|byte| matches!(byte, 0x21..=0x7e))
        {
            findings.push(
                "casework.review-producer.invalid-recipient-binding",
                format!("{at}/recipientBinding"),
                "expected 1 to 256 printable ASCII characters without spaces",
                "Write the recipient binding the completion destination expects.",
            );
        }
    }
}

fn valid_review_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn bounded_config_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum
        && value.chars().all(|character| !character.is_control())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueuePolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourcePolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub adapter: String,
    pub description: String,
    pub requests: Vec<SourceRequestPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// Source fields that may be returned to an authorized human reviewing a
    /// unified source-context task. Values are fetched afresh through that
    /// caller's source credential and are never retained by Casework.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_projection: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing: Vec<RoutingRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PassiveTargetPolicy>,
}

impl SourceRequestPolicy {
    /// The findings in the request's own members, at `at`.
    fn findings(&self, findings: &mut Findings, at: &str) {
        if self.entity.is_empty() {
            findings.push(
                "casework.request.empty-entity",
                format!("{at}/entity"),
                "entity is empty",
                "Write the source entity this request routes, such as birth-registration.",
            );
        }
        if self.display_reference.as_ref().is_some_and(|reference| {
            reference.field.is_empty()
                || reference.field.len() > 512
                || reference.field.chars().any(char::is_control)
        }) {
            findings.push(
                "casework.request.invalid-display-reference",
                format!("{at}/displayReference/field"),
                "expected a field name of 1 to 512 bytes with no control characters",
                "Write the source field Casework retains for exact lookup.",
            );
        }
        if let Some(target) = &self.target {
            if target.id.is_empty() {
                findings.push(
                    "casework.request.empty-target-id",
                    format!("{at}/target/id"),
                    "the target id is empty",
                    "Write the target id, such as first-decision.",
                );
            }
            if parse_elapsed_seconds(&target.after.elapsed).is_none() {
                findings.push(
                    "casework.request.invalid-target-elapsed",
                    format!("{at}/target/after/elapsed"),
                    ELAPSED_MESSAGE,
                    ELAPSED_ACTION,
                );
            }
        }
        if self.context_projection.len() > 32 {
            findings.push(
                "casework.request.too-many-context-fields",
                format!("{at}/contextProjection"),
                "at most 32 context fields may be listed",
                "Remove context fields until no more than the bound remain.",
            );
        }
        findings.repeated(
            self.context_projection
                .iter()
                .enumerate()
                .map(|(index, field)| (format!("{at}/contextProjection/{index}"), field.as_str())),
            "casework.request.duplicate-context-field",
            "this context field is already listed",
            "List each context field once.",
        );
        for (index, field) in self.context_projection.iter().enumerate() {
            if field.is_empty() || field.len() > 128 || field.chars().any(char::is_control) {
                findings.push(
                    "casework.request.invalid-context-field",
                    format!("{at}/contextProjection/{index}"),
                    "expected a field name of 1 to 128 bytes with no control characters",
                    "Write the source field a reviewer may read.",
                );
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisplayReferencePolicy {
    pub field: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassiveTargetPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub after: ElapsedDuration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InboxPolicy {
    #[serde(
        default = "default_page_size",
        deserialize_with = "crate::typed::bounded_usize::<_, 1, 100>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, 100>")
    )]
    pub default_page_size: usize,
    #[serde(
        default = "default_candidate_budget",
        deserialize_with = "crate::typed::bounded_usize::<_, 1, 10_000>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, 10_000>")
    )]
    pub maximum_candidate_scan: usize,
    #[serde(
        default = "default_source_read_budget",
        deserialize_with = "crate::typed::bounded_usize::<_, 1, 10_000>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, 10_000>")
    )]
    pub maximum_source_reads: usize,
    #[serde(
        default = "default_concurrency",
        deserialize_with = "crate::typed::bounded_usize::<_, 1, 32>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, 32>")
    )]
    pub maximum_concurrent_source_reads: usize,
    #[serde(
        default = "default_deadline_ms",
        deserialize_with = "crate::typed::bounded_u64::<_, 100, 30_000>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU64<100, 30_000>")
    )]
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
    /// The reader refuses a file whose member is out of range; these
    /// findings hold the same bounds for a policy built in code, and the
    /// bounds between members for both.
    fn findings(&self, findings: &mut Findings) {
        let mut out_of_range = |member: &str, bound: &str| {
            findings.push(
                "casework.inbox.out-of-range",
                format!("/inbox/{member}"),
                format!("expected {bound}"),
                "Write a value within the bound.",
            );
        };
        if self.default_page_size == 0 || self.default_page_size > 100 {
            out_of_range("defaultPageSize", "a whole number from 1 to 100");
        }
        if self.maximum_candidate_scan > 10_000 {
            out_of_range("maximumCandidateScan", "a whole number of at most 10000");
        }
        if self.maximum_source_reads == 0 {
            out_of_range("maximumSourceReads", "a whole number of at least 1");
        }
        if self.maximum_concurrent_source_reads == 0 || self.maximum_concurrent_source_reads > 32 {
            out_of_range(
                "maximumConcurrentSourceReads",
                "a whole number from 1 to 32",
            );
        }
        if !(100..=30_000).contains(&self.page_deadline_milliseconds) {
            out_of_range(
                "pageDeadlineMilliseconds",
                "a whole number of milliseconds from 100 to 30000",
            );
        }
        if self.maximum_candidate_scan < self.default_page_size {
            findings.add(
                ConfigFinding::new(
                    "casework.inbox.inconsistent-bounds",
                    "/inbox/maximumCandidateScan",
                    "maximumCandidateScan is smaller than defaultPageSize",
                    "Make maximumCandidateScan at least defaultPageSize.",
                )
                .with_related("/inbox/defaultPageSize", "defaultPageSize is set here"),
            );
        }
        if self.maximum_source_reads > self.maximum_candidate_scan {
            findings.add(
                ConfigFinding::new(
                    "casework.inbox.inconsistent-bounds",
                    "/inbox/maximumSourceReads",
                    "maximumSourceReads is larger than maximumCandidateScan",
                    "Make maximumSourceReads no larger than maximumCandidateScan.",
                )
                .with_related(
                    "/inbox/maximumCandidateScan",
                    "maximumCandidateScan is set here",
                ),
            );
        }
    }
}

/// Every problem [`CaseworkProject::check`] found, in the order it found
/// them. Never empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    findings: Vec<ConfigFinding>,
}

impl ConfigError {
    #[must_use]
    pub fn findings(&self) -> &[ConfigFinding] {
        &self.findings
    }

    #[must_use]
    pub fn into_findings(self) -> Vec<ConfigFinding> {
        self.findings
    }

    /// The pointer of the first finding.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.findings[0].pointer
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let first = &self.findings[0];
        let at = if first.pointer.is_empty() {
            "the project root"
        } else {
            first.pointer.as_str()
        };
        write!(formatter, "{} at {at}: {}", first.code, first.message)?;
        match self.findings.len() {
            1 => Ok(()),
            2 => formatter.write_str(" (and 1 more problem)"),
            count => write!(formatter, " (and {} more problems)", count - 1),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Error)]
pub enum ConfigLoadError {
    #[error("the Casework project could not be read")]
    Read(#[source] std::io::Error),
    /// The reader's or the semantic checks' report, printed unchanged.
    #[error(transparent)]
    Refused(Report),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ReviewContextStrategy, ReviewKindPurpose, ReviewRetentionPolicy, ReviewStagePolicy,
    };
    use serde_json::json;

    fn profile(id: &str, role: CaseworkRole) -> AccessProfile {
        AccessProfile {
            id: id.to_owned(),
            principal_claim: "registry_principal".to_owned(),
            required_scopes: vec![format!("casework:{id}")],
            role,
        }
    }

    fn project() -> CaseworkProject {
        CaseworkProject {
            task_templates: Vec::new(),
            api_version: CASEWORK_API_VERSION.to_owned(),
            kind: CASEWORK_KIND.to_owned(),
            project: ProjectIdentity {
                id: "standalone".parse().unwrap(),
                version: "1".to_owned(),
            },
            access_profiles: vec![
                profile("staff", CaseworkRole::Staff),
                profile("supervisor", CaseworkRole::Supervisor),
                profile("administrator", CaseworkRole::Administrator),
                profile("requester", CaseworkRole::Requester),
            ],
            queues: vec![QueuePolicy {
                id: "decisions".to_owned(),
                label: "Decisions".to_owned(),
            }],
            sources: Vec::new(),
            review_kinds: vec![review_kind()],
            review_producers: vec![review_producer()],
            calendars: Vec::new(),
            clocks: Vec::new(),
            inbox: InboxPolicy::default(),
        }
    }

    fn review_kind() -> ReviewKindPolicy {
        ReviewKindPolicy {
            id: "registry-correction".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewKindPurpose::Approval,
            context_strategy: ReviewContextStrategy::Source,
            stages: vec![ReviewStagePolicy {
                id: "review".to_owned(),
                queue: "decisions".to_owned(),
                deciding_profiles: vec!["staff".to_owned()],
                required_approvals: 1,
                exclude_initiator: true,
                exclude_previous_stage_reviewers: true,
            }],
            clocks: Vec::new(),
            retention: ReviewRetentionPolicy {
                terminal_days: 90,
                accountability_days: 365,
            },
            display_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["summary"],
                "properties": {"summary": {"type": "string", "maxLength": 160}}
            }),
            result_schema: None,
            outcomes: Vec::new(),
        }
    }

    fn review_producer() -> ReviewProducerPolicy {
        ReviewProducerPolicy {
            id: "registry".to_owned(),
            profile: "requester".to_owned(),
            issuer: "https://registry.example".to_owned(),
            subject: "registry-service".to_owned(),
            trusted_initiator_issuer: Some("https://people.example".to_owned()),
            initiator_profile: None,
            source_namespaces: vec!["registry".to_owned()],
            kinds: vec!["registry-correction".to_owned()],
            recovery_days: 30,
            completion: Some(ReviewCompletionDestinationPolicy {
                destination_id: "registry-review-completion".to_owned(),
                recipient_binding: "sha256:recipient-binding".to_owned(),
            }),
        }
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
                context_projection: Vec::new(),
                routing: Vec::new(),
                clock: None,
                target: None,
            }],
        }];
        candidate.review_kinds.clear();
        candidate.review_producers.clear();
        candidate.access_profiles.pop();
        candidate
    }

    /// The code and pointer of every finding, in the order the check reports
    /// them.
    fn refusals(project: &CaseworkProject) -> Vec<(&'static str, String)> {
        project
            .findings()
            .into_iter()
            .map(|finding| (finding.code, finding.pointer))
            .collect()
    }

    fn read(yaml: &str) -> Result<CaseworkProject, Report> {
        CaseworkProject::read(CASEWORK_PROJECT_FILE, yaml.as_bytes()).map(|decoded| decoded.value)
    }

    /// The code, pointer, and line of every diagnostic of a refused read.
    fn diagnostics(yaml: &str) -> Vec<(String, String, Option<usize>)> {
        read(yaml)
            .expect_err("the project is refused")
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code.clone(),
                    diagnostic.path.clone(),
                    diagnostic.source.as_ref().and_then(|source| source.line),
                )
            })
            .collect()
    }

    const MINIMAL: &str = r#"apiVersion: id.registrystack.org/formats/casework/project/v1alpha1
kind: CaseworkProject
project: {id: regional-review, version: "1"}
accessProfiles:
  - {id: staff, principalClaim: sub, requiredScopes: [casework:staff], role: staff}
  - {id: supervisor, principalClaim: sub, requiredScopes: [casework:supervisor], role: supervisor}
  - {id: administrator, principalClaim: sub, requiredScopes: [casework:admin], role: administrator}
queues:
  - {id: triage, label: Triage}
sources:
  - id: register
    adapter: breg
    description: sources/register.json
    requests:
      - entity: correction
        queue: triage
"#;

    #[track_caller]
    fn refused(project: &CaseworkProject, code: &'static str, pointer: &str) {
        assert_eq!(refusals(project), [(code, pointer.to_owned())]);
    }

    #[test]
    fn cfg_env_2_the_project_header_names_its_format() {
        assert_eq!(
            CASEWORK_API_VERSION,
            "id.registrystack.org/formats/casework/project/v1alpha1"
        );
        let project = read(MINIMAL).expect("the project is read");
        assert_eq!(project.api_version, CASEWORK_API_VERSION);
        assert_eq!(project.check(), Ok(()));
    }

    #[test]
    fn cfg_id_1_a_source_id_and_a_target_id_are_local_identifiers() {
        let underscored = MINIMAL.replace("id: register", "id: civil_register");
        assert_eq!(read(&underscored).unwrap().check(), Ok(()));
        let source = MINIMAL.replace("id: register", "id: Civil Register");
        assert_eq!(
            diagnostics(&source),
            [(
                "config.invalid-value".to_owned(),
                "/sources/0/id".to_owned(),
                Some(11)
            )]
        );
        let targeted = |id: &str| {
            format!("{MINIMAL}        target:\n          id: {id}\n          after: {{elapsed: PT48H}}\n")
        };
        assert_eq!(read(&targeted("first_decision")).unwrap().check(), Ok(()));
        assert_eq!(
            diagnostics(&targeted("First.Decision")),
            [(
                "config.invalid-value".to_owned(),
                "/sources/0/requests/0/target/id".to_owned(),
                Some(18)
            )]
        );
    }

    #[test]
    fn cfg_id_1_a_profile_a_queue_and_a_producer_id_are_local_identifiers() {
        let with_producer = |profile: &str, queue: &str, producer: &str| {
            let project = MINIMAL
                .replace("{id: staff,", &format!("{{id: {profile},"))
                .replace("{id: triage,", &format!("{{id: {queue},"))
                .replace("queue: triage", &format!("queue: {queue}"))
                .replace(
                    "queues:\n",
                    "  - {id: producer, principalClaim: sub, requiredScopes: [casework:producer], role: requester}\nqueues:\n",
                );
            format!(
                "{project}reviewProducers:\n  - {{id: {producer}, profile: producer, issuer: \"https://issuer.test\", subject: registry-service, sourceNamespaces: [registry], kinds: [correction], recoveryDays: 7}}\nreviewKinds:\n  - id: correction\n    version: \"1\"\n    purpose: approval\n    contextStrategy: source\n    stages:\n      - {{id: review, queue: {queue}, decidingProfiles: [supervisor], requiredApprovals: 1}}\n    outcomes:\n      - {{id: needs-change, label: Request changes, settlement: changes-requested, reasonRequired: true}}\n    retention: {{terminalDays: 30, accountabilityDays: 365}}\n    displaySchema: {{type: object, additionalProperties: false, properties: {{}}}}\n"
            )
        };
        assert_eq!(
            read(&with_producer(
                "front_desk-2",
                "first_triage-2",
                "benefits_portal-2"
            ))
            .unwrap()
            .check(),
            Ok(())
        );
        for (yaml, pointer, line) in [
            (
                with_producer("staff.review:v1", "triage", "registry"),
                "/accessProfiles/0/id",
                5,
            ),
            (
                with_producer("staff", "Triage.Desk", "registry"),
                "/queues/0/id",
                10,
            ),
            (
                with_producer("staff", "triage", "benefits.portal:v1"),
                "/reviewProducers/0/id",
                19,
            ),
        ] {
            assert_eq!(
                diagnostics(&yaml)
                    .into_iter()
                    .filter(|(_, path, _)| path == pointer)
                    .collect::<Vec<_>>(),
                [(
                    "config.invalid-value".to_owned(),
                    pointer.to_owned(),
                    Some(line)
                )]
            );
        }
    }

    #[test]
    fn review_producer_ids_follow_the_local_identifier_grammar() {
        for valid in ["benefits_portal-2".to_owned(), "x".repeat(64)] {
            let mut candidate = project();
            candidate.review_producers[0].id = valid;
            assert_eq!(candidate.check(), Ok(()));
        }
        for invalid in [
            String::new(),
            "x".repeat(65),
            "benefits.portal".to_owned(),
            "benefits:portal".to_owned(),
            "Portal".to_owned(),
            "1portal".to_owned(),
        ] {
            let mut candidate = project();
            candidate.review_producers[0].id = invalid;
            refused(
                &candidate,
                "casework.review-producer.invalid-id",
                "/reviewProducers/0/id",
            );
        }
    }

    #[test]
    fn cfg_change_2_the_retired_project_header_names_its_replacement() {
        let retired = MINIMAL.replacen(
            CASEWORK_API_VERSION,
            "registry.registrystack.org/casework/v1alpha1",
            1,
        );
        let report = read(&retired).expect_err("the retired header is refused");
        let found = report.diagnostics();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].code, "config.retired-api-version");
        assert_eq!(found[0].path, "/apiVersion");
        assert!(found[0]
            .suggested_action
            .contains("apiVersion: id.registrystack.org/formats/casework/project/v1alpha1"));
    }

    #[test]
    fn cfg_env_6_the_project_is_named_in_a_project_block() {
        let project = read(MINIMAL).expect("the project block is read");
        assert_eq!(project.project.id.as_str(), "regional-review");
        assert_eq!(project.project.version, "1");
        assert_eq!(project.check(), Ok(()));
    }

    #[test]
    fn cfg_change_3_the_removed_casework_block_names_the_project_block() {
        let removed = MINIMAL.replacen("project: {id", "casework: {id", 1);
        assert!(removed.contains("\ncasework: {id"));
        let report = read(&removed).expect_err("the removed block is refused");
        let found = report.diagnostics();
        let removal = found
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .expect("the removed key is reported");
        assert_eq!(removal.path, "/casework");
        assert!(removal.suggested_action.contains("project: {id: "));
    }

    #[test]
    fn cfg_id_7_the_removed_clock_scope_tag_names_type() {
        let authored = format!(
            "{MINIMAL}clocks:\n  - id: response-budget\n    scope: subject\n    anchor: first-submitted-at\n    completeOn: review-completed\n    after: {{elapsed: PT48H}}\n    pauseWhile: [awaiting-applicant]\n"
        );
        let report = read(&authored).expect_err("the removed tag is refused");
        let found = report.diagnostics();
        let removal = found
            .iter()
            .find(|diagnostic| diagnostic.code == "config.removed-key")
            .expect("the removed key is reported");
        assert_eq!(removal.path, "/clocks/0/scope");
        assert!(removal.suggested_action.contains("type: subject"));
        assert!(removal.suggested_action.contains("type: activity"));

        let current = authored.replacen("scope: subject", "type: subject", 1);
        read(&current).expect("the clock is read by its type");
    }

    #[test]
    fn cfg_name_2_the_previous_waiting_state_spellings_are_refused_and_the_current_named() {
        for (previous, current) in [
            ("waiting_applicant", "waiting-applicant"),
            ("waiting_application", "waiting-application"),
        ] {
            let authored = format!(
                "{MINIMAL}taskTemplates:\n  - id: summary\n    version: \"1\"\n    label: Prepare summary\n    eligibleTeams: [team]\n    eligibleProfiles: [staff]\n    source: source\n    itemKinds: [request]\n    itemStates: [{previous}]\n    agent: {{issuer: \"https://issuer.test\", subject: agent}}\n    client: agent-client\n    resource: urn:test:breg\n    scopes: [\"records:get\"]\n    purpose: prepare-summary\n    bounds: {{type: breg, permissions: [{{collection: records, operations: [get]}}]}}\n    subjects: {{subject_reference: subject-reference}}\n    lifetimeSeconds: 900\n"
            );
            let report = read(&authored).expect_err("the previous spelling is refused");
            let found = report.diagnostics();
            let refusal = found
                .iter()
                .find(|diagnostic| diagnostic.path == "/taskTemplates/0/itemStates/0")
                .expect("the item state is reported where it is written");
            assert_eq!(refusal.code, "config.unknown-variant");
            assert!(
                refusal.message.contains(current) || refusal.suggested_action.contains(current),
                "{previous} names {current}"
            );
        }
    }

    #[test]
    fn cfg_name_2_the_previous_settlement_spelling_is_refused_and_the_current_named() {
        let authored = |settlement: &str| {
            let project = MINIMAL.replace(
                "queues:\n",
                "  - {id: producer, principalClaim: sub, requiredScopes: [casework:producer], role: requester}\nqueues:\n",
            );
            format!(
                "{project}reviewProducers:\n  - {{id: registry, profile: producer, issuer: \"https://issuer.test\", subject: registry-service, sourceNamespaces: [registry], kinds: [correction], recoveryDays: 7}}\nreviewKinds:\n  - id: correction\n    version: \"1\"\n    purpose: approval\n    contextStrategy: source\n    stages:\n      - {{id: review, queue: triage, decidingProfiles: [staff], requiredApprovals: 1}}\n    outcomes:\n      - {{id: needs-change, label: Request changes, settlement: {settlement}, reasonRequired: true}}\n    retention: {{terminalDays: 30, accountabilityDays: 365}}\n    displaySchema: {{type: object, additionalProperties: false, properties: {{}}}}\n"
            )
        };
        let project = read(&authored("changes-requested")).expect("the settlement is read");
        assert_eq!(
            project.review_kinds[0].outcomes[0].settlement,
            crate::ReviewOutcomeSettlement::ChangesRequested
        );

        let report =
            read(&authored("changes_requested")).expect_err("the previous spelling is refused");
        let found = report.diagnostics();
        let refusal = found
            .iter()
            .find(|diagnostic| diagnostic.path == "/reviewKinds/0/outcomes/0/settlement")
            .expect("the settlement is reported where it is written");
        assert_eq!(refusal.code, "config.unknown-variant");
        assert!(
            refusal.message.contains("changes-requested")
                || refusal.suggested_action.contains("changes-requested"),
            "the refusal names the current spelling"
        );
    }

    #[test]
    fn standalone_work_requires_an_explicit_review_kind() {
        let mut project = project();
        assert_eq!(project.check(), Ok(()));

        project.review_kinds.clear();
        project.review_producers.clear();
        project.access_profiles.pop();
        refused(&project, "casework.project.no-work", "");
    }

    #[test]
    fn review_producers_are_exact_and_recovery_fits_result_retention() {
        let candidate = project();
        assert_eq!(candidate.check(), Ok(()));

        let mut changed_identity = candidate.clone();
        let mut duplicate = changed_identity.review_producers[0].clone();
        duplicate.id = "registry-alias".to_owned();
        changed_identity.review_producers.push(duplicate);
        refused(
            &changed_identity,
            "casework.review-producer.duplicate-principal",
            "/reviewProducers/1",
        );

        let mut excessive_recovery = candidate.clone();
        excessive_recovery.review_producers[0].recovery_days = 91;
        refused(
            &excessive_recovery,
            "casework.review-producer.recovery-exceeds-retention",
            "/reviewProducers/0/recoveryDays",
        );

        let mut oversized_initiator_issuer = candidate.clone();
        oversized_initiator_issuer.review_producers[0].trusted_initiator_issuer =
            Some("i".repeat(257));
        refused(
            &oversized_initiator_issuer,
            "casework.review-producer.invalid-trusted-initiator-issuer",
            "/reviewProducers/0/trustedInitiatorIssuer",
        );

        let mut invalid_recipient_header = candidate.clone();
        invalid_recipient_header.review_producers[0]
            .completion
            .as_mut()
            .expect("completion policy")
            .recipient_binding = "récepteur".to_owned();
        refused(
            &invalid_recipient_header,
            "casework.review-producer.invalid-recipient-binding",
            "/reviewProducers/0/completion/recipientBinding",
        );

        let mut unknown_clock = candidate.clone();
        unknown_clock.review_kinds[0].clocks = vec!["missing-clock".to_owned()];
        refused(
            &unknown_clock,
            "casework.review-kind.unknown-clock",
            "/reviewKinds/0/clocks/0",
        );

        let mut undeclared_namespace = candidate;
        undeclared_namespace.review_producers[0].source_namespaces = vec!["registry/path".into()];
        refused(
            &undeclared_namespace,
            "casework.review-producer.invalid-source-namespace",
            "/reviewProducers/0/sourceNamespaces/0",
        );
    }

    #[test]
    fn an_initiator_profile_is_a_distinct_requester_profile_with_a_trusted_issuer() {
        let mut candidate = project();
        candidate
            .access_profiles
            .push(profile("initiator", CaseworkRole::Requester));
        candidate.review_producers[0].initiator_profile = Some("initiator".to_owned());
        assert_eq!(candidate.check(), Ok(()));

        let mut undeclared = candidate.clone();
        undeclared.review_producers[0].initiator_profile = Some("missing".to_owned());
        refused(
            &undeclared,
            "casework.review-producer.ineligible-initiator-profile",
            "/reviewProducers/0/initiatorProfile",
        );

        let mut reviewer_profile = candidate.clone();
        reviewer_profile.review_producers[0].initiator_profile = Some("staff".to_owned());
        refused(
            &reviewer_profile,
            "casework.review-producer.ineligible-initiator-profile",
            "/reviewProducers/0/initiatorProfile",
        );

        // A producer's own profile authenticates the service, not the people
        // it names, so it can never double as an initiator profile.
        let mut producer_profile = candidate.clone();
        producer_profile.review_producers[0].initiator_profile = Some("requester".to_owned());
        refused(
            &producer_profile,
            "casework.review-producer.ineligible-initiator-profile",
            "/reviewProducers/0/initiatorProfile",
        );

        let mut untrusted = candidate;
        untrusted.review_kinds[0].stages[0].exclude_initiator = false;
        untrusted.review_producers[0].trusted_initiator_issuer = None;
        refused(
            &untrusted,
            "casework.review-producer.missing-trusted-initiator-issuer",
            "/reviewProducers/0/trustedInitiatorIssuer",
        );
    }

    #[test]
    fn every_same_role_profile_requires_an_independently_selectable_scope() {
        let mut candidate = project();
        let mut appeal_requester = profile("appeal-requester", CaseworkRole::Requester);
        appeal_requester.required_scopes = candidate.access_profiles[3].required_scopes.clone();
        candidate.access_profiles.push(appeal_requester);
        assert_eq!(
            refusals(&candidate),
            [
                (
                    "casework.access-profile.shared-scopes",
                    "/accessProfiles/3/requiredScopes".to_owned()
                ),
                (
                    "casework.access-profile.shared-scopes",
                    "/accessProfiles/4/requiredScopes".to_owned()
                ),
            ]
        );

        let mut candidate = project();
        // Current equality cannot prove that retained items pinned the same
        // deciding-profile set under an earlier policy.
        let mut retained_profile = profile("retained-staff", CaseworkRole::Staff);
        retained_profile.required_scopes = candidate.access_profiles[0].required_scopes.clone();
        candidate.access_profiles.push(retained_profile);
        candidate.review_kinds[0].stages[0]
            .deciding_profiles
            .push("retained-staff".to_owned());
        assert_eq!(
            refusals(&candidate),
            [
                (
                    "casework.access-profile.shared-scopes",
                    "/accessProfiles/0/requiredScopes".to_owned()
                ),
                (
                    "casework.access-profile.shared-scopes",
                    "/accessProfiles/4/requiredScopes".to_owned()
                ),
            ]
        );

        let mut combined = project();
        combined.access_profiles[0].required_scopes = vec!["casework:a".to_owned()];
        let mut staff_b = profile("staff-b", CaseworkRole::Staff);
        staff_b.required_scopes = vec!["casework:b".to_owned()];
        combined.access_profiles.push(staff_b);
        let mut appeal_staff = profile("appeal-staff", CaseworkRole::Staff);
        appeal_staff.required_scopes = vec!["casework:a".to_owned(), "casework:b".to_owned()];
        combined.access_profiles.push(appeal_staff);
        combined.review_kinds[0].stages[0]
            .deciding_profiles
            .push("appeal-staff".to_owned());
        assert_eq!(
            refusals(&combined),
            [
                "/accessProfiles/0",
                "/accessProfiles/4",
                "/accessProfiles/5"
            ]
            .map(|at| (
                "casework.access-profile.shared-scopes",
                format!("{at}/requiredScopes")
            ))
        );

        let mut remapped = project();
        let mut alternate = profile("staff-by-sub", CaseworkRole::Staff);
        alternate.principal_claim = "sub".to_owned();
        alternate.required_scopes = remapped.access_profiles[0].required_scopes.clone();
        remapped.access_profiles.push(alternate);
        remapped.review_kinds[0].stages[0]
            .deciding_profiles
            .push("staff-by-sub".to_owned());
        assert_eq!(
            refusals(&remapped),
            ["/accessProfiles/0", "/accessProfiles/4"].map(|at| (
                "casework.access-profile.shared-scopes",
                format!("{at}/requiredScopes")
            ))
        );
    }

    #[test]
    fn one_profile_cannot_be_selected_by_combining_lower_and_same_role_scopes() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes =
            vec!["casework:a".to_owned(), "casework:b".to_owned()];
        candidate.access_profiles[3].required_scopes = vec!["casework:a".to_owned()];
        let mut peer = profile("staff-b", CaseworkRole::Staff);
        peer.required_scopes = vec!["casework:b".to_owned()];
        candidate.access_profiles.push(peer);

        assert_eq!(
            refusals(&candidate),
            [
                (
                    "casework.access-profile.shared-scopes",
                    "/accessProfiles/0/requiredScopes".to_owned()
                ),
                (
                    "casework.access-profile.shared-scopes",
                    "/accessProfiles/4/requiredScopes".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn same_role_profiles_may_share_base_scopes_when_each_has_its_own_scope() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes = vec![
            "casework:staff".to_owned(),
            "casework:staff-primary".to_owned(),
        ];
        let mut alternate = profile("staff-by-sub", CaseworkRole::Staff);
        alternate.principal_claim = "sub".to_owned();
        alternate.required_scopes = vec![
            "casework:staff".to_owned(),
            "casework:staff-alternate".to_owned(),
        ];
        candidate.access_profiles.push(alternate);
        candidate.review_kinds[0].stages[0]
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
            refused(
                &candidate,
                "casework.access-profile.invalid-scope",
                "/accessProfiles/0/requiredScopes/0",
            );
        }
    }

    #[test]
    fn source_ids_are_unique_independently_of_their_description_files() {
        let mut candidate = project_with_source_queue("decisions");
        let mut duplicate = candidate.sources[0].clone();
        duplicate.adapter = "other-adapter".to_owned();
        duplicate.description = "other-description.json".to_owned();
        candidate.sources.push(duplicate);
        refused(&candidate, "casework.source.duplicate-id", "/sources/1/id");
    }

    #[test]
    fn a_project_declares_a_bounded_number_of_sources() {
        let mut candidate = project_with_source_queue("decisions");
        let source = candidate.sources[0].clone();
        candidate.sources = (0..=MAXIMUM_SOURCES)
            .map(|index| {
                let mut source = source.clone();
                source.id = format!("source-{index}");
                source
            })
            .collect();
        refused(&candidate, "casework.source.too-many", "/sources");
    }

    #[test]
    fn request_entities_are_unique_within_a_source() {
        let mut candidate = project_with_source_queue("decisions");
        let duplicate = candidate.sources[0].requests[0].clone();
        candidate.sources[0].requests.push(duplicate);
        refused(
            &candidate,
            "casework.request.duplicate-entity",
            "/sources/0/requests/1/entity",
        );
    }

    #[test]
    fn source_context_projection_is_unique_and_bounded() {
        let mut candidate = project_with_source_queue("decisions");
        candidate.sources[0].requests[0].context_projection =
            vec!["summary".to_owned(), "attachment-metadata".to_owned()];
        assert_eq!(candidate.check(), Ok(()));

        candidate.sources[0].requests[0]
            .context_projection
            .push("summary".to_owned());
        refused(
            &candidate,
            "casework.request.duplicate-context-field",
            "/sources/0/requests/0/contextProjection/2",
        );

        candidate.sources[0].requests[0].context_projection = vec!["x".repeat(129)];
        refused(
            &candidate,
            "casework.request.invalid-context-field",
            "/sources/0/requests/0/contextProjection/0",
        );
    }

    #[test]
    fn higher_roles_are_not_reachable_through_lower_role_scope_sets() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes =
            vec!["casework:review".to_owned(), "casework:manage".to_owned()];
        candidate.access_profiles[1].required_scopes = vec!["casework:manage".to_owned()];
        refused(
            &candidate,
            "casework.access-profile.shared-scopes",
            "/accessProfiles/1/requiredScopes",
        );

        let mut candidate = project();
        candidate.access_profiles[1].required_scopes = vec![
            "casework:supervise".to_owned(),
            "casework:administer".to_owned(),
        ];
        candidate.access_profiles[2].required_scopes = vec!["casework:administer".to_owned()];
        refused(
            &candidate,
            "casework.access-profile.shared-scopes",
            "/accessProfiles/2/requiredScopes",
        );

        let mut candidate = project();
        candidate.access_profiles[0].required_scopes = vec!["casework:a".to_owned()];
        candidate.access_profiles[1].required_scopes =
            vec!["casework:a".to_owned(), "casework:b".to_owned()];
        candidate.access_profiles.push(AccessProfile {
            id: "staff-secondary".to_owned(),
            principal_claim: "registry_principal".to_owned(),
            required_scopes: vec!["casework:b".to_owned()],
            role: CaseworkRole::Staff,
        });
        refused(
            &candidate,
            "casework.access-profile.shared-scopes",
            "/accessProfiles/1/requiredScopes",
        );

        let mut candidate = project();
        candidate.access_profiles[3].required_scopes =
            candidate.access_profiles[1].required_scopes.clone();
        refused(
            &candidate,
            "casework.access-profile.shared-scopes",
            "/accessProfiles/1/requiredScopes",
        );
    }

    #[test]
    fn administrator_requires_a_scope_absent_from_combined_non_administrator_grants() {
        let mut candidate = project();
        candidate.access_profiles[0].required_scopes = vec!["casework:review".to_owned()];
        candidate.access_profiles[1].required_scopes = vec!["casework:manage".to_owned()];
        candidate.access_profiles[2].required_scopes =
            vec!["casework:review".to_owned(), "casework:manage".to_owned()];
        refused(
            &candidate,
            "casework.access-profile.shared-scopes",
            "/accessProfiles/2/requiredScopes",
        );

        let mut candidate = project();
        candidate.access_profiles[2].required_scopes =
            candidate.access_profiles[3].required_scopes.clone();
        refused(
            &candidate,
            "casework.access-profile.shared-scopes",
            "/accessProfiles/2/requiredScopes",
        );
    }

    #[test]
    fn access_profile_ids_match_the_http_selection_contract() {
        for valid in ["staff_review-2".to_owned(), "x".repeat(64)] {
            let mut candidate = project();
            candidate.access_profiles[2].id = valid;
            assert_eq!(candidate.check(), Ok(()));
        }

        for invalid in [
            String::new(),
            "x".repeat(65),
            "staff/reviewer".to_owned(),
            "staff reviewer".to_owned(),
            "stáff".to_owned(),
            "staff.review:v1".to_owned(),
            "Staff".to_owned(),
            "1staff".to_owned(),
        ] {
            let mut candidate = project();
            candidate.access_profiles[2].id = invalid;
            refused(
                &candidate,
                "casework.access-profile.invalid-id",
                "/accessProfiles/2/id",
            );
        }
    }

    #[test]
    fn queue_ids_match_the_directory_assignment_contract() {
        for valid in ["review_queue-2".to_owned(), "x".repeat(64)] {
            let candidate = project_with_source_queue(&valid);
            assert_eq!(candidate.check(), Ok(()));
        }

        for invalid in [
            String::new(),
            "x".repeat(65),
            "review/queue".to_owned(),
            "review queue".to_owned(),
            "réview".to_owned(),
            "review:queue".to_owned(),
            "review.queue".to_owned(),
            "Review".to_owned(),
            "1review".to_owned(),
        ] {
            let candidate = project_with_source_queue(&invalid);
            refused(&candidate, "casework.queue.invalid-id", "/queues/0/id");
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
    fn administrator_is_not_a_review_deciding_profile() {
        let mut project = project();
        project.review_kinds[0].stages[0].deciding_profiles = vec!["administrator".to_owned()];
        refused(
            &project,
            "casework.review-kind.ineligible-deciding-profile",
            "/reviewKinds/0/stages/0/decidingProfiles/0",
        );
    }

    #[test]
    fn multi_queue_routing_and_named_clocks_use_the_documented_authoring_shape() {
        let project = read(
            r#"apiVersion: id.registrystack.org/formats/casework/project/v1alpha1
kind: CaseworkProject
project: {id: regional-review, version: "1"}
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
    type: activity
    anchor: stage-entered-at
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
        .expect("documented policy reads");
        assert_eq!(project.check(), Ok(()));
        assert_eq!(project.queues.len(), 4);
        assert_eq!(project.sources[0].requests[0].routing.len(), 2);

        let mut invalid = project.clone();
        invalid.sources[0].requests[0].routing[1].queue = "missing".to_owned();
        assert_eq!(
            refusals(&invalid),
            [(
                "casework.routing.unknown-queue",
                "/sources/0/requests/0/routing/1/queue".to_owned()
            )]
        );

        let mut invalid = project.clone();
        invalid.sources[0].requests[0].clock = Some("missing".to_owned());
        assert_eq!(
            refusals(&invalid),
            [(
                "casework.request.unknown-clock",
                "/sources/0/requests/0/clock".to_owned()
            )]
        );

        let mut invalid = project.clone();
        let ClockPolicy::Activity { calendar, .. } = &mut invalid.clocks[0] else {
            panic!("fixture has an activity clock")
        };
        *calendar = "missing".to_owned();
        refused(
            &invalid,
            "casework.clock.unknown-calendar",
            "/clocks/0/calendar",
        );
    }

    #[test]
    fn cfg_id_5_a_repeated_id_in_a_named_list_is_refused_by_the_reader() {
        let found = |yaml: String, pointer: &str, line: usize| {
            assert_eq!(
                diagnostics(&yaml),
                [(
                    "config.duplicate-id".to_owned(),
                    pointer.to_owned(),
                    Some(line)
                )]
            );
        };
        found(
            MINIMAL.replace(
                "  - {id: triage, label: Triage}\n",
                "  - {id: triage, label: Triage}\n  - {id: triage, label: Again}\n",
            ),
            "/queues/1/id",
            10,
        );
        found(
            MINIMAL.replace(
                "  - {id: supervisor, principalClaim",
                "  - {id: staff, principalClaim",
            ),
            "/accessProfiles/1/id",
            6,
        );
        found(
            format!("{MINIMAL}  - id: register\n    adapter: breg\n    description: sources/other.json\n    requests:\n      - entity: other\n        queue: triage\n"),
            "/sources/1/id",
            17,
        );
    }

    #[test]
    fn cfg_id_6_a_repeated_required_scope_is_refused_by_the_reader() {
        let yaml = MINIMAL.replace(
            "requiredScopes: [casework:staff]",
            "requiredScopes: [casework:staff, casework:staff]",
        );
        assert_eq!(
            diagnostics(&yaml),
            [(
                "config.duplicate-item".to_owned(),
                "/accessProfiles/0/requiredScopes/1".to_owned(),
                Some(5)
            )]
        );
    }

    #[test]
    fn a_read_reports_every_semantic_finding_at_its_line() {
        assert_eq!(read(MINIMAL).map(|_| ()), Ok(()));
        let yaml = MINIMAL
            .replace("  - {id: triage, label: Triage}\n", "  - {id: triage, label: Triage}\n  - {id: second, label: \" \"}\n")
            .replace("        queue: triage\n", "        queue: triage\n        clock: missing\n        contextProjection: [summary, summary]\n");
        assert_eq!(
            diagnostics(&yaml),
            [
                (
                    "casework.queue.invalid-label".to_owned(),
                    "/queues/1/label".to_owned(),
                    Some(10)
                ),
                (
                    "casework.request.duplicate-context-field".to_owned(),
                    "/sources/0/requests/0/contextProjection/1".to_owned(),
                    Some(19)
                ),
                (
                    "casework.request.unknown-clock".to_owned(),
                    "/sources/0/requests/0/clock".to_owned(),
                    Some(18)
                ),
            ]
        );
    }

    #[test]
    fn a_read_reports_every_unknown_key_with_its_position() {
        let yaml = MINIMAL
            .replace(
                "kind: CaseworkProject\n",
                "kind: CaseworkProject\nqueue: triage\n",
            )
            .replace(
                "        queue: triage\n",
                "        queue: triage\n        clocks: [deadline]\n",
            );
        let report = read(&yaml).expect_err("unknown keys are refused");
        let unknown: Vec<_> = report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                let source = diagnostic.source.as_ref().expect("a position");
                (
                    diagnostic.code.as_str(),
                    diagnostic.path.as_str(),
                    source.line,
                    source.column,
                )
            })
            .collect();
        assert_eq!(
            unknown,
            [
                ("config.unknown-key", "/queue", Some(3), Some(1)),
                (
                    "config.unknown-key",
                    "/sources/0/requests/0/clocks",
                    Some(18),
                    Some(9)
                ),
            ]
        );
    }

    #[test]
    fn substitution_is_refused_with_where_the_deployment_binds_the_value() {
        let issuer = MINIMAL.replace("sources:\n", "reviewProducers: []\nsources:\n");
        assert_eq!(read(&issuer).map(|_| ()), Ok(()));

        let report = read(&MINIMAL.replace("adapter: breg", "adapter: ${ADAPTER}"))
            .expect_err("substitution is refused");
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.substitution-not-allowed");
        assert_eq!(diagnostic.path, "/sources/0/adapter");
        assert!(diagnostic
            .suggested_action
            .contains("sources.<id> binds a source endpoint"));
        assert!(!report.render_human().contains("ADAPTER"));

        let producer = MINIMAL.replace(
            "sources:\n",
            "reviewProducers:\n  - {id: registry, profile: staff, issuer: \"${ISSUER}\"}\nsources:\n",
        );
        let report = read(&producer).expect_err("substitution is refused");
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.substitution-not-allowed");
        assert_eq!(diagnostic.path, "/reviewProducers/0/issuer");
        assert!(diagnostic
            .suggested_action
            .contains("runtime.yaml binds no issuer of an authored principal"));
    }

    #[test]
    fn a_read_refuses_bounds_repeats_and_issuers_at_their_positions() {
        for (member, code, pointer) in [
            (
                "inbox: {defaultPageSize: 0}\n",
                "config.out-of-range",
                "/inbox/defaultPageSize",
            ),
            (
                "calendars:\n  - {id: office, timezone: UTC, holidaySet: national, workingWeekdays: [monday, monday]}\n",
                "config.duplicate-item",
                "/calendars/0/workingWeekdays/1",
            ),
            (
                "reviewProducers:\n  - {id: portal, profile: staff, issuer: portal, subject: portal, kinds: [licence]}\n",
                "config.invalid-value",
                "/reviewProducers/0/issuer",
            ),
        ] {
            let yaml = MINIMAL.replace("queues:\n", &format!("{member}queues:\n"));
            let refused = diagnostics(&yaml);
            assert_eq!(refused.len(), 1, "{refused:?}");
            assert_eq!(
                (refused[0].0.as_str(), refused[0].1.as_str()),
                (code, pointer)
            );
            let line = member.lines().count() + 7;
            assert_eq!(refused[0].2, Some(line), "{pointer}");
        }
    }

    #[test]
    fn a_null_predicate_value_is_refused_at_its_position() {
        let yaml = MINIMAL.replace(
            "        queue: triage\n",
            "        queue: triage\n        projection: [region]\n        routing:\n          - id: unset-region\n            because: The region is unset.\n            when: {fields: {region: {equals: null}}}\n            queue: triage\n",
        );
        assert_eq!(
            diagnostics(&yaml),
            [(
                "config.null-value".to_owned(),
                "/sources/0/requests/0/routing/0/when/fields/region/equals".to_owned(),
                Some(21)
            )]
        );
    }
}
