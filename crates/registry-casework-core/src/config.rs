use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub use registry_platform_yaml::ProjectIdentity;
use registry_platform_yaml::{
    ApiVersion, Decoded, EnvelopeRule, Expect, FormatSpec, Identified, Reader, Refusal, RemovedKey,
    Report, RetiredApiVersion, ScalarHook, ScalarSite,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::finding::{
    findings_report, ConfigFinding, Findings, IDENTIFIER_ACTION, IDENTIFIER_MESSAGE,
};
use crate::CaseworkRole;
use crate::ReviewPolicy;
use crate::MAXIMUM_RECEIPT_RETENTION_DAYS;
use crate::{clock_policy_findings, routing_policy_findings, CalendarPolicy, ClockPolicy};

pub const CASEWORK_API_VERSION: &str = "id.registrystack.org/formats/casework/project/v1alpha1";
pub const CASEWORK_KIND: &str = "CaseworkProject";
// Matches the maximum RFC 6749 scope-token size Casework accepts.
const MAXIMUM_REQUIRED_SCOPE_BYTES: usize = 256;
/// The most sources one project declares, which bounds the source
/// descriptions a project check reads.
pub const MAXIMUM_CONTEXT_PROVIDERS: usize = 64;

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
    #[serde(
        deserialize_with = "crate::typed::id_keyed",
        serialize_with = "crate::typed::serialize_id_keyed"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::typed::id_keyed_schema::<AccessProfile>")
    )]
    pub access_profiles: Vec<AccessProfile>,
    #[serde(
        deserialize_with = "crate::typed::id_keyed",
        serialize_with = "crate::typed::serialize_id_keyed"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::typed::id_keyed_schema::<QueuePolicy>")
    )]
    pub queues: Vec<QueuePolicy>,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub context_providers: Vec<crate::ReviewContextProviderPolicy>,
    #[serde(
        default,
        deserialize_with = "crate::typed::id_keyed",
        serialize_with = "crate::typed::serialize_id_keyed"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::typed::id_keyed_schema::<TeamPolicy>")
    )]
    pub teams: Vec<TeamPolicy>,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub review_policies: Vec<ReviewPolicy>,
    #[serde(
        default,
        deserialize_with = "crate::typed::id_keyed",
        serialize_with = "crate::typed::serialize_id_keyed"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::typed::id_keyed_schema::<ReviewProducerPolicy>")
    )]
    pub trusted_producers: Vec<ReviewProducerPolicy>,
    #[serde(
        default,
        deserialize_with = "crate::typed::id_keyed",
        serialize_with = "crate::typed::serialize_id_keyed"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::typed::id_keyed_schema::<CalendarPolicy>")
    )]
    pub calendars: Vec<CalendarPolicy>,
    #[serde(
        default,
        deserialize_with = "crate::typed::id_keyed",
        serialize_with = "crate::typed::serialize_id_keyed"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::typed::id_keyed_schema::<ClockPolicy>")
    )]
    pub clocks: Vec<ClockPolicy>,
    #[serde(default)]
    pub inbox: InboxPolicy,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    pub task_templates: Vec<crate::TaskTemplate>,
}

/// The pointer to a named item of an id-keyed collection (CFG-ID-5).
fn keyed(collection: &str, id: &str) -> String {
    format!(
        "/{collection}/{}",
        registry_platform_yaml::escape_pointer_segment(id)
    )
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
    crate::ReviewContextProviderPolicy,
    TeamPolicy,
    ReviewPolicy,
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
            replacement: "Write the clock's kind as type: subject or type: stage.",
        },
        RemovedKey {
            pointer: "/clocks/*/after/elapsed",
            replacement: "Write the budget in one unit, such as after: {hours: 48}; after: {minutes: N} and after: {days: N}, each day 24 hours, are also accepted. See row F1 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/reviewPolicies/*/retention/terminalDays",
            replacement: "Write the same number of days as retention.terminalRetentionDays. See row F2 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/reviewPolicies/*/retention/accountabilityDays",
            replacement: "Write the same number of days as retention.accountabilityRetentionDays. See row F2 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/trustedProducers/*/recoveryDays",
            replacement: "Write the same number of days as retention: {receiptRetentionDays: N}, at most 365. See row F3 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/accessProfiles/*/id",
            replacement: "Write accessProfiles as a mapping from each id to the rest of its entry, accessProfiles: {PROFILE_ID: {role: ...}}, with no id member. See row F4 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/queues/*/id",
            replacement: "Write queues as a mapping from each id to the rest of its entry, queues: {QUEUE_ID: {label: ...}}, with no id member. See row F4 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/teams/*/id",
            replacement: "Write teams as a mapping from each id to the rest of its entry, teams: {TEAM_ID: {label: ...}}, with no id member. See row F4 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/trustedProducers/*/id",
            replacement: "Write trustedProducers as a mapping from each id to the rest of its entry, trustedProducers: {PRODUCER_ID: {profile: ...}}, with no id member. See row F4 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/calendars/*/id",
            replacement: "Write calendars as a mapping from each id to the rest of its entry, calendars: {CALENDAR_ID: {timezone: ...}}, with no id member. See row F4 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/clocks/*/id",
            replacement: "Write clocks as a mapping from each id to the rest of its entry, clocks: {CLOCK_ID: {type: ...}}, with no id member. See row F4 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/reviewPolicies/*/outcomes/*/id",
            replacement: "Write outcomes as a mapping from each id to the rest of its entry, outcomes: {OUTCOME_ID: {label: ...}}, with no id member. See row F4 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/clocks/*/reminders/*/id",
            replacement: "Write reminders as a mapping from each id to its lead time, reminders: {REMINDER_ID: {before: {workingDays: N}}}, with no id member. See row F4 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/clocks/*/completeOn",
            replacement: "Remove completeOn; a subject clock completes when the review result is terminal. See row F7 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/clocks/*/atRisk/workingDaysBefore",
            replacement: "Write the lead time as atRisk: {before: {workingDays: N}}. See row F8 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/clocks/*/reminders/*/workingDaysBefore",
            replacement: "Write the reminder's lead time as {before: {workingDays: N}}. See row F8 of the format table in the Casework CHANGELOG.",
        },
        RemovedKey {
            pointer: "/reviewPolicies/*/routing/*/when/activity",
            replacement: "Remove activity; routing applies whenever a task is created, and a rule that names a stage matches only that stage's tasks. See row F9 of the format table in the Casework CHANGELOG.",
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
        Self::check(site)?;
        retired_clock_value(site).map(|()| None)
    }
}

/// Refuses a clock value the format table retired, naming its replacement
/// and its row. A retired key is refused through the format's removed keys;
/// these are values, so the reader's key table cannot see them.
fn retired_clock_value(site: &ScalarSite<'_>) -> Result<(), Refusal> {
    let in_clock = site.keys.first() == Some(&"clocks") && site.keys.len() <= 3;
    let (value, action) = match (in_clock, site.keys.last(), site.text) {
        (true, Some(&"type"), "activity") => (
            "activity",
            "Write type: stage. See row F5 of the format table in the Casework CHANGELOG.",
        ),
        (true, Some(&"anchor"), "request-accepted-at") => (
            "request-accepted-at",
            "Write anchor: {type: request-accepted}. See row F6 of the format table in the Casework CHANGELOG.",
        ),
        (true, Some(&"anchor"), "stage-entered-at") => (
            "stage-entered-at",
            "Write anchor: {type: stage-entered}. See row F6 of the format table in the Casework CHANGELOG.",
        ),
        _ => return Ok(()),
    };
    Err(Refusal {
        code: "config.unknown-variant".to_owned(),
        message: format!("`{value}` is no longer accepted"),
        suggested_action: action.to_owned(),
    })
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
    fn decode(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let mut hook = AuthoredSubstitution;
        Reader::new(file)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&CASEWORK_PROJECT_FORMAT))
    }

    /// Discover exact local schema inputs without reading the filesystem.
    /// The same positioned, structural reader is used by compilation.
    pub fn schema_references(file: &str, bytes: &[u8]) -> Result<Vec<String>, Report> {
        let decoded = Self::decode(file, bytes)?;
        Ok(decoded
            .value
            .review_policies
            .iter()
            .filter_map(|policy| {
                policy
                    .display_schema
                    .get("$ref")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    /// Compile captured project and schema bytes. There is no ambient-file fallback.
    pub fn read_with_schemas(
        file: &str,
        bytes: &[u8],
        schemas: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Decoded<Self>, Report> {
        Self::read_with_resolver(file, bytes, |reference| {
            schemas.get(reference).cloned().ok_or(())
        })
    }

    pub fn read(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let directory = Path::new(file)
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        Self::read_with_resolver(file, bytes, |reference| {
            let root = directory.canonicalize().map_err(|_| ())?;
            let path = root.join(reference).canonicalize().map_err(|_| ())?;
            if !path.starts_with(&root) {
                return Err(());
            }
            let metadata = std::fs::metadata(&path).map_err(|_| ())?;
            if !metadata.is_file() || metadata.len() > 64 * 1024 {
                return Err(());
            }
            std::fs::read(path).map_err(|_| ())
        })
    }

    fn read_with_resolver(
        file: &str,
        bytes: &[u8],
        resolver: impl Fn(&str) -> Result<Vec<u8>, ()>,
    ) -> Result<Decoded<Self>, Report> {
        let mut decoded = Self::decode(file, bytes)?;
        let schema_findings = decoded.value.resolve_display_schemas(resolver);
        if !schema_findings.is_empty() {
            return Err(findings_report(&decoded.document, &schema_findings));
        }
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
        self.review_policy_findings(&mut findings, &queues);
        self.trusted_producer_findings(&mut findings);
        if self.review_policies.is_empty() {
            findings.push(
                "casework.project.no-work",
                "",
                "the project declares no reviewPolicies",
                "Declare a review policy under reviewPolicies.",
            );
        }
        for finding in clock_policy_findings(&self.calendars, &self.clocks, &queues) {
            findings.add(finding);
        }
        self.context_provider_findings(&mut findings);
        self.team_findings(&mut findings, &queues);
        self.inbox.findings(&mut findings);
        findings.into_vec()
    }

    pub fn compile_policy(
        &self,
        id: &str,
    ) -> Result<crate::ReviewPolicyClosure, crate::ReviewPolicyError> {
        self.review_policies
            .iter()
            .find(|policy| policy.id == id)
            .ok_or(crate::ReviewPolicyError::Identity)?
            .compile(self)
    }

    /// Purpose capabilities reachable from this policy, rather than every
    /// capability another policy may use on the same provider.
    pub fn required_context_capabilities(
        &self,
        policy: &ReviewPolicy,
    ) -> BTreeSet<crate::ReviewContextCapability> {
        use crate::ReviewContextCapability as Capability;
        if matches!(policy.context, crate::ReviewContextPolicy::Submitted) {
            return BTreeSet::new();
        }
        let mut required = BTreeSet::from([Capability::HumanDisplay, Capability::ServiceStatus]);
        if !policy.routing_fields().is_empty() {
            required.insert(Capability::RoutingContext);
        }
        if self.task_templates.iter().any(|template| {
            template.review_policies.contains(&policy.id) && !template.subjects.is_empty()
        }) {
            required.insert(Capability::TaskGrantContext);
        }
        required
    }

    pub(crate) fn policy_dependencies(
        &self,
        policy: &ReviewPolicy,
    ) -> crate::ReviewPolicyDependencies {
        let clocks: Vec<_> = self
            .clocks
            .iter()
            .filter(|clock| policy.clocks.iter().any(|id| id == clock.id()))
            .cloned()
            .collect();
        let calendars = self.calendars.iter().filter(|calendar| clocks.iter().any(|clock| matches!(clock, ClockPolicy::Stage { calendar: id, .. } if *id == calendar.id))).cloned().collect();
        crate::ReviewPolicyDependencies {
            access_profiles: self.access_profiles.clone(),
            queues: self.queues.clone(),
            teams: self.teams.clone(),
            clocks,
            calendars,
            context_provider: match &policy.context {
                crate::ReviewContextPolicy::Submitted => None,
                crate::ReviewContextPolicy::CurrentSource { provider, .. } => self
                    .context_providers
                    .iter()
                    .find(|candidate| candidate.id == *provider)
                    .cloned()
                    .map(|mut dependency| {
                        let required = self.required_context_capabilities(policy);
                        dependency
                            .capabilities
                            .retain(|capability| required.contains(capability));
                        dependency
                            .service_profiles
                            .retain(|capability, _| required.contains(capability));
                        dependency
                    }),
            },
            task_templates: self
                .task_templates
                .iter()
                .filter(|template| template.review_policies.contains(&policy.id))
                .cloned()
                .collect(),
            trusted_producers: self
                .trusted_producers
                .iter()
                .filter(|producer| producer.review_policies.contains(&policy.id))
                .cloned()
                .collect(),
            inbox: self.inbox.clone(),
        }
    }

    fn resolve_display_schemas(
        &mut self,
        resolver: impl Fn(&str) -> Result<Vec<u8>, ()>,
    ) -> Vec<ConfigFinding> {
        let mut findings = Findings::default();
        for (index, policy) in self.review_policies.iter_mut().enumerate() {
            let at = format!("/reviewPolicies/{index}/displaySchema");
            let reference = policy
                .display_schema
                .get("$ref")
                .and_then(serde_json::Value::as_str);
            let bytes = if let Some(reference) = reference {
                let relative = Path::new(reference);
                let safe = policy
                    .display_schema
                    .as_object()
                    .is_some_and(|object| object.len() == 1)
                    && !relative.is_absolute()
                    && !reference.is_empty()
                    && relative.components().all(|part| {
                        matches!(
                            part,
                            std::path::Component::Normal(_) | std::path::Component::CurDir
                        )
                    });
                let read = if safe { resolver(reference) } else { Err(()) };
                let Ok(bytes) = read else {
                    findings.push(
                        "casework.review-policy.schema-artifact",
                        format!("{at}/$ref"),
                        "the captured local display schema is absent or outside the project",
                        "Capture one bounded local JSON schema file relative to casework.yaml.",
                    );
                    continue;
                };
                bytes
            } else {
                let Ok(bytes) =
                    registry_platform_canonical_json::canonicalize_json(&policy.display_schema)
                else {
                    findings.push(
                        "casework.review-policy.schema-artifact",
                        &at,
                        "the inline schema cannot be canonically encoded",
                        "Write a bounded JSON schema object.",
                    );
                    continue;
                };
                bytes
            };
            if bytes.len() > 64 * 1024 {
                findings.push(
                    "casework.review-policy.schema-artifact",
                    &at,
                    "the display schema exceeds the artifact byte bound",
                    "Keep the schema within 64 KiB.",
                );
                continue;
            }
            if let crate::ReviewContextPolicy::CurrentSource { contract, .. } = &policy.context {
                if crate::ContentDigest::for_bytes(&bytes) != contract.schema_digest {
                    findings.push("casework.review-policy.schema-digest",&at,"the schema bytes do not match context.contract.schemaDigest", "Export the producer contract and file together; for inline schemas hash their canonical JSON bytes.");
                    continue;
                }
            }
            match serde_json::from_slice(&bytes) {
                Ok(schema) => policy.display_schema = schema,
                Err(_) => findings.push(
                    "casework.review-policy.schema-artifact",
                    &at,
                    "the captured display schema is not JSON",
                    "Export one bounded local JSON schema file.",
                ),
            }
        }
        findings.into_vec()
    }

    fn context_provider_findings(&self, findings: &mut Findings) {
        use crate::{ReviewContextCapability as Capability, ReviewContextPolicy};
        if self.context_providers.len() > MAXIMUM_CONTEXT_PROVIDERS {
            findings.push(
                "casework.context-provider.too-many",
                "/contextProviders",
                "at most 64 context providers may be declared",
                "Remove unused providers.",
            );
        }
        findings.repeated(
            self.context_providers
                .iter()
                .enumerate()
                .map(|(i, p)| (format!("/contextProviders/{i}/id"), p.id.as_str())),
            "casework.context-provider.duplicate-id",
            "this provider id is already declared",
            "Give each provider a unique id.",
        );
        for (index, provider) in self.context_providers.iter().enumerate() {
            let at = format!("/contextProviders/{index}");
            for (name, value) in [
                ("id", &provider.id),
                ("sourceNamespace", &provider.source_namespace),
                ("deploymentRef", &provider.deployment_ref),
            ] {
                if !valid_review_name(value) {
                    findings.push(
                        "casework.context-provider.invalid-identity",
                        format!("{at}/{name}"),
                        "a provider identity is invalid",
                        "Write one bounded identifier.",
                    );
                }
            }
            let unique: BTreeSet<_> = provider.capabilities.iter().copied().collect();
            if unique.is_empty() || unique.len() != provider.capabilities.len() {
                findings.push(
                    "casework.context-provider.capabilities",
                    format!("{at}/capabilities"),
                    "capabilities must be nonempty and unique",
                    "Declare each implemented purpose once.",
                );
            }
            for (capability, profile) in &provider.service_profiles {
                if *capability == Capability::HumanDisplay
                    || !unique.contains(capability)
                    || !valid_profile_identifier(profile)
                {
                    findings.push("casework.context-provider.service-profile",format!("{at}/serviceProfiles"),"serviceProfiles must name a declared service capability and a bounded source profile", "Bind only purpose-specific service profiles.");
                }
            }
        }
        for (index, policy) in self.review_policies.iter().enumerate() {
            if let ReviewContextPolicy::CurrentSource { provider, contract } = &policy.context {
                let at = format!("/reviewPolicies/{index}/context");
                if !bounded_config_text(&contract.id, crate::MAXIMUM_CONTEXT_CONTRACT_ID_BYTES) {
                    findings.push(
                        "casework.review-policy.context-contract",
                        format!("{at}/contract/id"),
                        "the contract id is invalid",
                        "Copy the producer contract's exact id.",
                    );
                }
                let Some(provider) = self
                    .context_providers
                    .iter()
                    .find(|candidate| candidate.id == *provider)
                else {
                    findings.push(
                        "casework.review-policy.unknown-provider",
                        format!("{at}/provider"),
                        "no context provider has this id",
                        "Declare this provider under contextProviders.",
                    );
                    continue;
                };
                let required = self.required_context_capabilities(policy);
                for capability in required {
                    if !provider.capabilities.contains(&capability)
                        || (capability != Capability::HumanDisplay
                            && !provider.service_profiles.contains_key(&capability))
                    {
                        findings.push(
                            "casework.review-policy.provider-capability",
                            format!("{at}/provider"),
                            "the provider lacks a required purpose capability or service profile",
                            "Declare and implement only the service capabilities this policy uses.",
                        );
                    }
                }
                for producer in self
                    .trusted_producers
                    .iter()
                    .filter(|producer| producer.review_policies.contains(&policy.id))
                {
                    if !producer
                        .source_namespaces
                        .contains(&provider.source_namespace)
                    {
                        findings.push(
                            "casework.review-policy.provider-namespace",
                            format!("{at}/provider"),
                            "the provider namespace is not admitted for a trusted producer",
                            "Align the exact producer and context-provider namespace.",
                        );
                    }
                }
            }
            let projection = policy.routing_fields();
            if policy.routing.is_empty() {
                continue;
            }
            let metadata = crate::RoutingSourceMetadata {
                stages: policy.stages.iter().map(|stage| stage.id.clone()).collect(),
                fields: policy
                    .display_schema
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .into_iter()
                    .flat_map(|properties| properties.iter())
                    .filter(|(field, _)| projection.contains(field))
                    .map(|(field, schema)| crate::RoutingFieldDescriptor {
                        field: field.clone(),
                        api_name: field.clone(),
                        schema: schema.clone(),
                    })
                    .collect(),
            };
            for stage in &policy.stages {
                for finding in routing_policy_findings(
                    &stage.queue,
                    &projection,
                    &policy.routing,
                    &self.queues.iter().map(|queue| queue.id.clone()).collect(),
                    Some(&metadata),
                ) {
                    findings.push(
                        finding.reason.code(),
                        format!("/reviewPolicies/{index}/routing{}", finding.path),
                        finding.reason.message(),
                        finding.reason.suggested_action(),
                    );
                }
            }
        }
    }

    fn team_findings(&self, findings: &mut Findings, queues: &BTreeSet<String>) {
        findings.repeated(
            self.teams
                .iter()
                .map(|t| (keyed("teams", &t.id), t.id.as_str())),
            "casework.team.duplicate-id",
            "this team id is already declared",
            "Give each team a unique id.",
        );
        for team in &self.teams {
            let at = keyed("teams", &team.id);
            if !valid_directory_identifier(&team.id) || !bounded_config_text(&team.label, 160) {
                findings.push(
                    "casework.team.identity",
                    &at,
                    "the team id or label is invalid",
                    "Write a bounded id and label.",
                );
            }
            if team.serves.is_empty() || team.serves.iter().any(|queue| !queues.contains(queue)) {
                findings.push(
                    "casework.team.queues",
                    format!("{at}/serves"),
                    "the team must serve declared queues",
                    "Name one or more declared queues.",
                );
            }
            for (name, ids, role) in [
                ("memberProfiles", &team.member_profiles, CaseworkRole::Staff),
                (
                    "supervisorProfiles",
                    &team.supervisor_profiles,
                    CaseworkRole::Supervisor,
                ),
            ] {
                if ids.is_empty()
                    || ids.iter().any(|id| {
                        !self
                            .access_profiles
                            .iter()
                            .any(|profile| profile.id == *id && profile.role == role)
                    })
                {
                    findings.push(
                        "casework.team.profiles",
                        format!("{at}/{name}"),
                        "a team profile is absent or has the wrong role",
                        "Name declared profiles of the required role.",
                    );
                }
            }
        }
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
                .map(|queue| (keyed("queues", &queue.id), queue.id.as_str())),
            "casework.queue.duplicate-id",
            "this queue id is already declared",
            "Give every queue a unique id.",
        );
        for queue in &self.queues {
            if !crate::typed::valid_local_identifier(&queue.id) {
                findings.push(
                    "casework.queue.invalid-id",
                    keyed("queues", &queue.id),
                    IDENTIFIER_MESSAGE,
                    IDENTIFIER_ACTION,
                );
            }
            if queue.label.trim().is_empty() || queue.label.len() > 160 {
                findings.push(
                    "casework.queue.invalid-label",
                    format!("{}/label", keyed("queues", &queue.id)),
                    "expected a label of 1 to 160 bytes that is not only spaces",
                    "Write a short label for the queue.",
                );
            }
        }
    }

    fn access_profile_findings(&self, findings: &mut Findings) {
        for profile in &self.access_profiles {
            if !crate::typed::valid_local_identifier(&profile.id) {
                findings.push(
                    "casework.access-profile.invalid-id",
                    keyed("accessProfiles", &profile.id),
                    IDENTIFIER_MESSAGE,
                    PROFILE_IDENTIFIER_ACTION,
                );
            }
        }
        findings.repeated(
            self.access_profiles
                .iter()
                .map(|profile| (keyed("accessProfiles", &profile.id), profile.id.as_str())),
            "casework.access-profile.duplicate-id",
            "this access profile id is already declared",
            "Give every access profile a unique id.",
        );
        for profile in &self.access_profiles {
            let at = keyed("accessProfiles", &profile.id);
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
                format!(
                    "{}/requiredScopes",
                    keyed("accessProfiles", &self.access_profiles[index].id)
                ),
                "every scope this profile requires is also required by another profile at the same or a lower role, so their credentials could select this profile",
                "Require a scope that no other profile at the same or a lower role requires.",
            );
        }
    }

    fn review_policy_findings(&self, findings: &mut Findings, queues: &BTreeSet<String>) {
        if self.review_policies.len() > crate::MAXIMUM_REVIEW_POLICIES {
            findings.push(
                "casework.review-policy.too-many",
                "/reviewPolicies",
                format!(
                    "at most {} review policies may be declared",
                    crate::MAXIMUM_REVIEW_POLICIES
                ),
                "Remove review policies until no more than the bound remain.",
            );
        }
        findings.repeated(
            self.review_policies
                .iter()
                .enumerate()
                .map(|(index, policy)| (format!("/reviewPolicies/{index}/id"), policy.id.as_str())),
            "casework.review-policy.duplicate-id",
            "this review policy id is already declared",
            "Give every review policy a unique id.",
        );
        for (policy_index, policy) in self.review_policies.iter().enumerate() {
            let at = format!("/reviewPolicies/{policy_index}");
            findings.extend_under(&at, policy.findings());
            for (clock_index, clock_id) in policy.clocks.iter().enumerate() {
                if !self.clocks.iter().any(|clock| clock.id() == clock_id) {
                    findings.push(
                        "casework.review-policy.unknown-clock",
                        format!("{at}/clocks/{clock_index}"),
                        UNKNOWN_CLOCK_MESSAGE,
                        UNKNOWN_CLOCK_ACTION,
                    );
                }
            }
            for (stage_index, stage) in policy.stages.iter().enumerate() {
                let stage_at = format!("{at}/stages/{stage_index}");
                if !queues.contains(&stage.queue) {
                    findings.push(
                        "casework.review-policy.unknown-queue",
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
                            "casework.review-policy.ineligible-deciding-profile",
                            format!("{stage_at}/decidingProfiles/{profile_index}"),
                            "no staff or supervisor access profile has this id",
                            "Name an access profile with role staff or supervisor.",
                        );
                    }
                }
            }
        }
    }

    fn trusted_producer_findings(&self, findings: &mut Findings) {
        if self.trusted_producers.len() > 64 {
            findings.push(
                "casework.review-producer.too-many",
                "/trustedProducers",
                "at most 64 review producers may be declared",
                "Remove review producers until no more than the bound remain.",
            );
        }
        findings.repeated(
            self.trusted_producers.iter().map(|producer| {
                (
                    keyed("trustedProducers", &producer.id),
                    producer.id.as_str(),
                )
            }),
            "casework.review-producer.duplicate-id",
            "this review producer id is already declared",
            "Give every review producer a unique id.",
        );
        findings.repeated(
            self.trusted_producers.iter().map(|producer| {
                (
                    keyed("trustedProducers", &producer.id),
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
        if !self.review_policies.is_empty() && self.trusted_producers.is_empty() {
            findings.push(
                "casework.review-producer.none",
                "/trustedProducers",
                "review policies are declared but no review producer may submit them",
                "Declare a review producer under trustedProducers, or remove reviewPolicies.",
            );
        }
        if self.review_policies.is_empty() && !self.trusted_producers.is_empty() {
            findings.push(
                "casework.review-producer.without-review-policys",
                "/trustedProducers",
                "review producers are declared but no review policy exists",
                "Declare the review policies they submit under reviewPolicies, or remove trustedProducers.",
            );
        }
        for producer in &self.trusted_producers {
            let at = keyed("trustedProducers", &producer.id);
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
                    .trusted_producers
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
            for (policy_index, policy_id) in producer.review_policies.iter().enumerate() {
                let Some((declared_index, policy)) = self
                    .review_policies
                    .iter()
                    .enumerate()
                    .find(|(_, policy)| policy.id == *policy_id)
                else {
                    findings.push(
                        "casework.review-producer.unknown-review-policy",
                        format!("{at}/reviewPolicies/{policy_index}"),
                        "no review policy in reviewPolicies has this id",
                        "Name a review policy declared under reviewPolicies.",
                    );
                    continue;
                };
                if policy.retention.terminal_retention_days
                    < producer.retention.receipt_retention_days
                {
                    findings.add(
                        ConfigFinding::new(
                            "casework.review-producer.recovery-exceeds-retention",
                            format!("{at}/retention/receiptRetentionDays"),
                            "receiptRetentionDays is longer than the result retention of a review policy this producer submits",
                            "Make receiptRetentionDays no longer than that review policy's retention.terminalRetentionDays.",
                        )
                        .with_related(
                            format!(
                                "/reviewPolicies/{declared_index}/retention/terminalRetentionDays"
                            ),
                            "terminalRetentionDays is written here",
                        ),
                    );
                }
                if !exclusion_reported {
                    if let Some(stage_index) = policy
                        .stages
                        .iter()
                        .position(|stage| stage.exclude_initiator)
                    {
                        exclusion_reported = true;
                        findings.add(
                            ConfigFinding::new(
                                "casework.review-producer.missing-trusted-initiator-issuer",
                                format!("{at}/trustedInitiatorIssuer"),
                                "a review policy this producer submits excludes the initiator from deciding, which needs trustedInitiatorIssuer",
                                "Add trustedInitiatorIssuer naming the issuer that authenticates initiators.",
                            )
                            .with_related(
                                format!(
                                    "/reviewPolicies/{declared_index}/stages/{stage_index}/excludeInitiator"
                                ),
                                "excludeInitiator is set here",
                            ),
                        );
                    }
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
    pub review_policies: Vec<String>,
    pub retention: ProducerRetention,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<ReviewCompletionDestinationPolicy>,
}

/// How long Casework keeps what a producer needs to recover a submission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProducerRetention {
    /// Days a submission receipt stays readable for recovery, at most 365.
    #[serde(
        deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_RECEIPT_RETENTION_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_RECEIPT_RETENTION_DAYS>")
    )]
    pub receipt_retention_days: u32,
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
        if !(1..=crate::MAXIMUM_RECEIPT_RETENTION_DAYS)
            .contains(&self.retention.receipt_retention_days)
        {
            findings.push(
                "casework.review-producer.recovery-days-out-of-range",
                format!("{at}/retention/receiptRetentionDays"),
                format!(
                    "expected a whole number of days from 1 to {}",
                    crate::MAXIMUM_RECEIPT_RETENTION_DAYS
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
            &format!("{at}/reviewPolicies"),
            &self.review_policies,
            crate::MAXIMUM_REVIEW_POLICIES,
            [
                "casework.review-producer.no-policies",
                "casework.review-producer.too-many-policies",
                "casework.review-producer.invalid-policy",
                "casework.review-producer.duplicate-policy",
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
pub struct TeamPolicy {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub label: String,
    pub serves: Vec<String>,
    pub member_profiles: Vec<String>,
    pub supervisor_profiles: Vec<String>,
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
