// SPDX-License-Identifier: Apache-2.0

//! The authored project file, `messaging.yaml`.
//!
//! A Messaging project is the directory `package.root` names, holding
//! `messaging.yaml` and one directory per template version under
//! `templates/<id>/<version>/`. The project file names the project in its
//! `project` block, declares the providers a deployment routes through (by
//! type, never by endpoint or credential, which are runtime configuration),
//! the sender profiles callers select, the template versions the project
//! ships, and who may call the runtime, as `accessProfiles[]`, so a reviewer
//! reads the callers next to what they may send. Every member is closed, so an
//! unknown key is refused rather than ignored.
//!
//! The shared reader refuses what one member decides by itself: its type,
//! its identifier grammar, its bounds, a repeated identifier. What reads two
//! members together, such as a reference to a declaration, is a
//! [`MessagingFinding`] the check reports at the member.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_yaml::{
    ApiVersion, Decoded, EnvelopeRule, Expect, FormatSpec, Identified, Invalid, ProjectIdentity,
    Reader, RemovedKey, Report, RetiredApiVersion,
};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::access::{AccessProfile, AccessProfileError, AccessProfiles, AccessRole};
use crate::finding::{FindingReason, MessagingFinding};
use crate::naming::{
    MESSAGING_PROJECT_API_VERSION, MESSAGING_PROJECT_KIND, RETIRED_MESSAGING_PROJECT_API_VERSION,
};
use crate::sms::MAXIMUM_SMS_SEGMENTS;

/// The most providers, sender profiles, template versions, or access
/// profiles one project declares.
pub const MAXIMUM_PACKAGE_DECLARATIONS: usize = 256;

/// The longest template version label accepted.
pub const MAXIMUM_TEMPLATE_VERSION_BYTES: usize = 32;

/// The longest sender identity accepted: an RFC 5321 path.
pub const MAXIMUM_SENDER_BYTES: usize = 254;

/// Attempts one message gets when its sender profile declares no `retry`.
pub const DEFAULT_MAXIMUM_ATTEMPTS: u8 = 5;

/// The most attempts a sender profile may allow one message.
pub const MAXIMUM_ATTEMPTS: u8 = 20;

/// The first retry delay when a sender profile declares no `retry`.
pub const DEFAULT_INITIAL_RETRY_DELAY_SECONDS: u32 = 30;

/// The longest retry delay when a sender profile declares no `retry`.
pub const DEFAULT_MAXIMUM_RETRY_DELAY_SECONDS: u32 = 3_600;

/// The longest retry delay any sender profile may declare: one day.
pub const MAXIMUM_RETRY_DELAY_SECONDS: u32 = 86_400;

/// How long an accepted message may wait to be sent when neither the
/// request nor its sender profile says otherwise: one day.
pub const DEFAULT_EXPIRY_SECONDS: u32 = 86_400;

/// The shortest default expiry a sender profile may declare.
pub const MINIMUM_EXPIRY_SECONDS: u32 = 60;

/// The longest default expiry a sender profile may declare: thirty days.
pub const MAXIMUM_EXPIRY_SECONDS: u32 = 2_592_000;

// The reader bounds below are const generics, which take a `u32`.
const MAXIMUM_ATTEMPTS_BOUND: u32 = MAXIMUM_ATTEMPTS as u32;
const MAXIMUM_SMS_SEGMENTS_BOUND: u32 = MAXIMUM_SMS_SEGMENTS as u32;

/// The format a `messaging.yaml` file declares (CFG-ENV-1).
pub const MESSAGING_PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: MESSAGING_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(MESSAGING_PROJECT_API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: RETIRED_MESSAGING_PROJECT_API_VERSION,
            replacement:
                "Write apiVersion: id.registrystack.org/formats/messaging/project/v1alpha1 \
                          and kind: MessagingProject, and add a project block with id and a text \
                          version.",
        }],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/providers/*/kind",
            replacement: "Write type.",
        },
        RemovedKey {
            pointer: "/accessProfiles/*/dailyLimit",
            replacement: "Write maximumMessagesPerDay.",
        },
    ],
};

/// A delivery channel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Channel {
    Email,
    Sms,
}

impl Channel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
        }
    }
}

/// The transport a provider speaks. Its endpoint and credentials are runtime
/// configuration; only the type is project.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    Smtp,
    Http,
}

impl ProviderKind {
    /// Whether this type can carry `channel`.
    #[must_use]
    pub const fn carries(self, channel: Channel) -> bool {
        match self {
            Self::Smtp => matches!(channel, Channel::Email),
            Self::Http => true,
        }
    }
}

/// One declared provider, referenced by sender profiles through `id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDeclaration {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(rename = "type")]
    pub kind: ProviderKind,
    /// The provider deduplicates submissions on the idempotency key the
    /// runtime sends, so sending one message twice delivers it once. This is
    /// the one declaration of that capability: an HTTP provider's scripts
    /// see the key only when it is set, and an `smtp` provider may not set
    /// it.
    #[serde(default)]
    pub idempotent_submit: bool,
}

impl Identified for ProviderDeclaration {
    fn id(&self) -> &str {
        &self.id
    }
}

/// What a caller selects: a channel, the provider carrying it, the sender
/// identity, for SMS the most segments one message may use, and how the
/// worker retries, holds, and expires its messages.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenderProfile {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub channel: Channel,
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub provider: String,
    /// The from address for email, the sender identifier for SMS.
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 254)))]
    pub sender: String,
    /// For SMS, and only for SMS, the most segments one message may use.
    #[serde(
        default,
        deserialize_with = "crate::typed::optional_bounded_u8::<_, 1, MAXIMUM_SMS_SEGMENTS_BOUND>"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 10)))]
    pub maximum_segments: Option<u8>,
    /// How a send that definitely failed is retried. Absent means the
    /// defaults [`SenderProfile::retry_policy`] reports.
    #[serde(default)]
    pub retry: Option<RetryPolicy>,
    /// What happens when a send may have reached the provider.
    #[serde(default)]
    pub on_uncertain: UncertainPolicy,
    /// The operator's explicit choice that a duplicate message is better
    /// than a missed one, which permits `onUncertain: retry` through a
    /// provider that does not deduplicate.
    #[serde(default)]
    pub accept_duplicates: bool,
    /// How long an accepted message may wait to be sent when its request
    /// names no `expiresAt`. Absent means [`DEFAULT_EXPIRY_SECONDS`].
    #[serde(
        default,
        deserialize_with = "crate::typed::optional_bounded_u32::<_, MINIMUM_EXPIRY_SECONDS, MAXIMUM_EXPIRY_SECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = MINIMUM_EXPIRY_SECONDS, max = MAXIMUM_EXPIRY_SECONDS))
    )]
    pub default_expiry_seconds: Option<u32>,
}

impl Identified for SenderProfile {
    fn id(&self) -> &str {
        &self.id
    }
}

impl SenderProfile {
    /// The declared retry policy, or the defaults.
    #[must_use]
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry.unwrap_or(RetryPolicy {
            maximum_attempts: DEFAULT_MAXIMUM_ATTEMPTS,
            initial_delay_seconds: DEFAULT_INITIAL_RETRY_DELAY_SECONDS,
            maximum_delay_seconds: DEFAULT_MAXIMUM_RETRY_DELAY_SECONDS,
        })
    }

    /// The declared default expiry, or [`DEFAULT_EXPIRY_SECONDS`].
    #[must_use]
    pub fn expiry_seconds(&self) -> u32 {
        self.default_expiry_seconds
            .unwrap_or(DEFAULT_EXPIRY_SECONDS)
    }
}

/// How a send that definitely failed is retried: exponential backoff that
/// doubles from `initialDelaySeconds` up to `maximumDelaySeconds`, with
/// jitter, until `maximumAttempts` attempts were made.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    #[serde(deserialize_with = "crate::typed::bounded_u8::<_, 1, MAXIMUM_ATTEMPTS_BOUND>")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 20)))]
    pub maximum_attempts: u8,
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_RETRY_DELAY_SECONDS>")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAXIMUM_RETRY_DELAY_SECONDS)))]
    pub initial_delay_seconds: u32,
    /// At least `initialDelaySeconds`.
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_RETRY_DELAY_SECONDS>")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAXIMUM_RETRY_DELAY_SECONDS)))]
    pub maximum_delay_seconds: u32,
}

/// What the worker does with a send that may have reached the provider.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum UncertainPolicy {
    /// Stop the message as `unknown` until an operator settles it.
    #[default]
    Hold,
    /// Send it again with the same provider idempotency key.
    Retry,
}

impl UncertainPolicy {
    #[must_use]
    pub const fn is_hold(&self) -> bool {
        matches!(self, Self::Hold)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Retry => "retry",
        }
    }
}

/// One template version, under `templates/<id>/<version>/`, as the wire
/// contract names it.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateReference {
    pub id: String,
    pub version: String,
}

/// One template version the project declares.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateDeclaration {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    /// A version label: 1 to 32 lowercase letters, digits, dots, or hyphens,
    /// starting with a letter or digit. Quote a numeric one.
    #[serde(deserialize_with = "template_version")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 1, max = 32),
            regex(pattern = r"^[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*$")
        )
    )]
    pub version: String,
}

impl TemplateDeclaration {
    #[must_use]
    pub fn reference(&self) -> TemplateReference {
        TemplateReference {
            id: self.id.clone(),
            version: self.version.clone(),
        }
    }
}

// The refusal below states this bound in static text.
const _: () = assert!(MAXIMUM_TEMPLATE_VERSION_BYTES == 32);

fn template_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let version = String::deserialize(deserializer)?;
    if valid_template_version(&version) {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(Invalid::expected(
            "a version label: 1 to 32 lowercase letters, digits, dots, or hyphens, starting with \
             a letter or digit",
            "Write a version such as \"1\" or \"2026.1\".",
        )))
    }
}

/// The project file as authored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessagingProject {
    pub api_version: String,
    pub kind: String,
    pub project: ProjectIdentity,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueIdList<ProviderDeclaration>",
            length(max = 256)
        )
    )]
    pub providers: Vec<ProviderDeclaration>,
    #[serde(default, deserialize_with = "crate::typed::unique_id_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueIdList<SenderProfile>",
            length(max = 256)
        )
    )]
    pub sender_profiles: Vec<SenderProfile>,
    #[serde(default, deserialize_with = "crate::typed::unique_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<TemplateDeclaration>",
            length(max = 256)
        )
    )]
    pub templates: Vec<TemplateDeclaration>,
    /// Who may call the deployment, at least one profile: a project that
    /// names no caller serves none.
    #[serde(deserialize_with = "access_profiles")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueIdList<AccessProfile>",
            length(min = 1, max = 256)
        )
    )]
    pub access_profiles: Vec<AccessProfile>,
}

fn access_profiles<'de, D>(deserializer: D) -> Result<Vec<AccessProfile>, D::Error>
where
    D: Deserializer<'de>,
{
    let profiles = crate::typed::unique_id_list::<D, AccessProfile>(deserializer)?;
    if profiles.is_empty() {
        return Err(serde::de::Error::custom(Invalid::expected(
            "a list of at least one access profile",
            "Declare the access profile each calling client resolves to.",
        )));
    }
    Ok(profiles)
}

/// Why a project cannot be used. Every message is the project's own
/// finding or a fixed sentence: none repeats a value the files hold.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PackageError {
    #[error("{}", first_message(.0))]
    Findings(Vec<MessagingFinding>),
    #[error(transparent)]
    AccessProfile(#[from] AccessProfileError),
    #[error("the package digest must be sha256: followed by 64 lowercase hexadecimal digits")]
    InvalidDigest,
}

fn first_message(findings: &[MessagingFinding]) -> &'static str {
    findings.first().map_or(
        "the Messaging project does not pass its checks",
        |finding| finding.reason.message(),
    )
}

/// The project after its own checks, indexed for the package it belongs to.
#[derive(Clone, Debug)]
pub struct CheckedManifest {
    pub access_profiles: AccessProfiles,
    pub sender_profiles: BTreeMap<String, SenderProfile>,
    pub providers: BTreeMap<String, ProviderDeclaration>,
    pub templates: BTreeSet<TemplateReference>,
}

impl MessagingProject {
    /// Read one `messaging.yaml` through `reader`, without the checks that
    /// read two members together. A refusal is the report a check prints
    /// unchanged.
    pub fn decode(reader: Reader<'_>, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        reader.decode(bytes, &Expect::one(&MESSAGING_PROJECT_FORMAT))
    }

    /// Every finding about the file, in document order: what reads two
    /// members together. What one member decides by itself the reader
    /// already refused. Template contents are checked with each template.
    #[must_use]
    pub fn findings(&self) -> Vec<MessagingFinding> {
        let mut findings = Vec::new();
        for (member, count) in [
            ("/providers", self.providers.len()),
            ("/senderProfiles", self.sender_profiles.len()),
            ("/templates", self.templates.len()),
            ("/accessProfiles", self.access_profiles.len()),
        ] {
            if count > MAXIMUM_PACKAGE_DECLARATIONS {
                findings.push(MessagingFinding::new(FindingReason::TooManyEntries, member));
            }
        }
        for (index, provider) in self.providers.iter().enumerate() {
            if provider.kind == ProviderKind::Smtp && provider.idempotent_submit {
                findings.push(MessagingFinding::new(
                    FindingReason::IdempotentSmtp,
                    format!("/providers/{index}/idempotentSubmit"),
                ));
            }
        }
        for (index, profile) in self.sender_profiles.iter().enumerate() {
            self.sender_profile_findings(index, profile, &mut findings);
        }
        self.access_profile_findings(&mut findings);
        findings
    }

    fn sender_profile_findings(
        &self,
        index: usize,
        profile: &SenderProfile,
        findings: &mut Vec<MessagingFinding>,
    ) {
        let at = |member: &str| format!("/senderProfiles/{index}/{member}");
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.id == profile.provider);
        match provider {
            None => findings.push(MessagingFinding::new(
                FindingReason::UnknownProvider,
                at("provider"),
            )),
            Some(provider) if !provider.kind.carries(profile.channel) => findings.push(
                MessagingFinding::new(FindingReason::ProviderCannotCarryChannel, at("provider")),
            ),
            Some(_) => {}
        }
        match profile.channel {
            Channel::Email if !valid_email_sender(&profile.sender) => findings.push(
                MessagingFinding::new(FindingReason::InvalidEmailSender, at("sender")),
            ),
            Channel::Sms if !valid_sms_sender(&profile.sender) => findings.push(
                MessagingFinding::new(FindingReason::InvalidSmsSender, at("sender")),
            ),
            _ => {}
        }
        match (profile.channel, profile.maximum_segments) {
            (Channel::Sms, None) => findings.push(MessagingFinding::new(
                FindingReason::MissingMaximumSegments,
                at("maximumSegments"),
            )),
            (Channel::Email, Some(_)) => findings.push(MessagingFinding::new(
                FindingReason::EmailMaximumSegments,
                at("maximumSegments"),
            )),
            _ => {}
        }
        if profile
            .retry
            .is_some_and(|retry| retry.maximum_delay_seconds < retry.initial_delay_seconds)
        {
            findings.push(MessagingFinding::new(
                FindingReason::RetryDelayOrder,
                at("retry/maximumDelaySeconds"),
            ));
        }
        // A send that may have reached the provider is sent again only when a
        // second send cannot deliver twice, or the operator chose duplicates.
        if let Some(provider) = provider {
            if profile.on_uncertain == UncertainPolicy::Retry
                && !provider.idempotent_submit
                && !profile.accept_duplicates
            {
                findings.push(MessagingFinding::new(
                    FindingReason::UncertainRetryDuplicates,
                    at("onUncertain"),
                ));
            }
        }
    }

    fn access_profile_findings(&self, findings: &mut Vec<MessagingFinding>) {
        let template_ids: BTreeSet<&str> = self
            .templates
            .iter()
            .map(|template| template.id.as_str())
            .collect();
        let mut clients = BTreeSet::new();
        for (index, profile) in self.access_profiles.iter().enumerate() {
            let at = |member: &str| format!("/accessProfiles/{index}/{member}");
            for (item, scope) in profile.required_scopes.iter().enumerate() {
                if wildcard_spelled(scope) {
                    findings.push(MessagingFinding::new(
                        FindingReason::WildcardSpelledItem,
                        at(&format!("requiredScopes/{item}")),
                    ));
                }
            }
            for (item, client) in profile.requester_clients.iter().enumerate() {
                let pointer = at(&format!("requesterClients/{item}"));
                if wildcard_spelled(client) {
                    findings.push(MessagingFinding::new(
                        FindingReason::WildcardSpelledItem,
                        pointer.clone(),
                    ));
                }
                if !clients.insert(client.as_str()) {
                    findings.push(MessagingFinding::new(
                        FindingReason::SharedRequesterClient,
                        pointer,
                    ));
                }
            }
            match profile.role {
                AccessRole::Sender if profile.sends_nothing() => findings.push(
                    MessagingFinding::new(FindingReason::SenderWithoutTargets, at("role")),
                ),
                AccessRole::Operator if profile.declares_sending_permissions() => {
                    findings.push(MessagingFinding::new(
                        FindingReason::OperatorWithSendingPermissions,
                        at("role"),
                    ))
                }
                _ => {}
            }
            for (item, sender) in profile.sender_profiles.iter().enumerate() {
                let pointer = at(&format!("senderProfiles/{item}"));
                if wildcard_spelled(sender) {
                    findings.push(MessagingFinding::new(
                        FindingReason::WildcardSpelledItem,
                        pointer.clone(),
                    ));
                }
                if !self
                    .sender_profiles
                    .iter()
                    .any(|declared| &declared.id == sender)
                {
                    findings.push(MessagingFinding::new(
                        FindingReason::UnknownSenderProfile,
                        pointer,
                    ));
                }
            }
            for (item, template) in profile.templates.iter().enumerate() {
                let pointer = at(&format!("templates/{item}"));
                if wildcard_spelled(template) {
                    findings.push(MessagingFinding::new(
                        FindingReason::WildcardSpelledItem,
                        pointer.clone(),
                    ));
                }
                if !template_ids.contains(template.as_str()) {
                    findings.push(MessagingFinding::new(
                        FindingReason::UnknownTemplate,
                        pointer,
                    ));
                }
            }
        }
    }

    /// A finding for each declared template version `shipped` lacks.
    #[must_use]
    pub fn missing_templates(
        &self,
        shipped: &BTreeSet<TemplateReference>,
    ) -> Vec<MessagingFinding> {
        self.templates
            .iter()
            .enumerate()
            .filter(|(_, template)| !shipped.contains(&template.reference()))
            .map(|(index, _)| {
                MessagingFinding::new(
                    FindingReason::MissingTemplate,
                    format!("/templates/{index}"),
                )
            })
            .collect()
    }

    /// Whether the project declares the template version.
    #[must_use]
    pub fn declares_template(&self, reference: &TemplateReference) -> bool {
        self.templates
            .iter()
            .any(|template| template.id == reference.id && template.version == reference.version)
    }

    /// Check every declaration and every reference between them, and index
    /// them. Template contents are checked when the package is assembled.
    pub fn check(&self) -> Result<CheckedManifest, PackageError> {
        let errors: Vec<MessagingFinding> = self
            .findings()
            .into_iter()
            .filter(MessagingFinding::is_error)
            .collect();
        if !errors.is_empty() {
            return Err(PackageError::Findings(errors));
        }
        let access_profiles = AccessProfiles::new(self.access_profiles.clone())?;
        Ok(CheckedManifest {
            access_profiles,
            sender_profiles: self
                .sender_profiles
                .iter()
                .map(|profile| (profile.id.clone(), profile.clone()))
                .collect(),
            providers: self
                .providers
                .iter()
                .map(|provider| (provider.id.clone(), provider.clone()))
                .collect(),
            templates: self
                .templates
                .iter()
                .map(TemplateDeclaration::reference)
                .collect(),
        })
    }
}

/// An item spelled like a wildcard, which a list of names reads as one name
/// (CFG-EMPTY-2).
fn wildcard_spelled(item: &str) -> bool {
    matches!(item, "*" | "unrestricted")
}

/// Whether `value` is a template version label: 1 to 32 lowercase letters,
/// digits, dots, or hyphens, starting with a letter or digit, with no empty
/// dot-separated run.
#[must_use]
pub fn valid_template_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_TEMPLATE_VERSION_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
        && !value.split('.').any(str::is_empty)
}

/// One address, `local@domain`, of visible ASCII without spaces or angle
/// brackets. Display names and address lists are refused.
pub(crate) fn valid_email_sender(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    value.len() <= MAXIMUM_SENDER_BYTES
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'<' | b'>' | b',' | b';'))
}

/// An E.164 number: `+`, then 2 to 15 digits not starting with zero.
pub(crate) fn valid_e164(value: &str) -> bool {
    value.strip_prefix('+').is_some_and(|digits| {
        (2..=15).contains(&digits.len())
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && !digits.starts_with('0')
    })
}

/// An E.164 number, or an alphanumeric sender of 1 to 11 characters.
fn valid_sms_sender(value: &str) -> bool {
    if value.starts_with('+') {
        return valid_e164(value);
    }
    (1..=11).contains(&value.len())
        && !value.starts_with(' ')
        && !value.ends_with(' ')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b' ')
}

/// Whether `value` is a package digest: `sha256:` and 64 lowercase
/// hexadecimal digits.
#[must_use]
pub fn valid_package_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn decode(value: &serde_json::Value) -> Result<MessagingProject, Report> {
        MessagingProject::decode(
            Reader::new("messaging.yaml"),
            &serde_json::to_vec(value).unwrap(),
        )
        .map(|decoded| decoded.value)
    }

    pub(crate) fn project(value: serde_json::Value) -> MessagingProject {
        decode(&value).unwrap()
    }

    pub(crate) fn valid() -> serde_json::Value {
        json!({
            "apiVersion": MESSAGING_PROJECT_API_VERSION,
            "kind": MESSAGING_PROJECT_KIND,
            "project": {"id": "notices", "version": "2026.1"},
            "providers": [
                {"id": "relay", "type": "smtp"},
                {"id": "sms-gateway", "type": "http"}
            ],
            "senderProfiles": [
                {"id": "transactional", "channel": "email", "provider": "relay",
                 "sender": "notices@example.org"},
                {"id": "notices-sms", "channel": "sms", "provider": "sms-gateway",
                 "sender": "Registry", "maximumSegments": 2}
            ],
            "templates": [
                {"id": "appointment-reminder", "version": "1"},
                {"id": "appointment-reminder", "version": "2"}
            ],
            "accessProfiles": [{
                "id": "case-notices",
                "principalClaim": "sub",
                "requiredScopes": ["messaging:send"],
                "requesterClients": ["case-system"],
                "role": "sender",
                "senderProfiles": ["transactional"],
                "templates": ["appointment-reminder"],
                "requestsPerMinute": 60,
                "burst": 10
            }]
        })
    }

    /// The codes and paths a refused read reports.
    fn refused(value: &serde_json::Value) -> Vec<(String, String)> {
        decode(value)
            .unwrap_err()
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect()
    }

    /// The codes and paths of the findings a read file carries.
    fn findings(value: serde_json::Value) -> Vec<(String, String)> {
        project(value)
            .findings()
            .iter()
            .map(|finding| (finding.code(), finding.path.clone()))
            .collect()
    }

    fn one(code: &str, path: &str) -> Vec<(String, String)> {
        vec![(code.to_owned(), path.to_owned())]
    }

    #[test]
    fn a_valid_project_yields_its_declarations() {
        let project = project(valid());
        assert_eq!(project.project.id.as_str(), "notices");
        assert_eq!(project.project.version, "2026.1");
        assert!(project.findings().is_empty());
        let checked = project.check().unwrap();
        assert!(checked.access_profiles.get("case-notices").is_some());
        assert_eq!(checked.sender_profiles.len(), 2);
        assert_eq!(checked.providers.len(), 2);
        assert_eq!(checked.templates.len(), 2);
    }

    #[test]
    fn every_unknown_member_is_refused_at_its_key() {
        let mut value = valid();
        value["templatez"] = json!([]);
        value["accessProfiles"][0]["allowEverything"] = json!(true);
        value["senderProfiles"][0]["endpoint"] = json!("https://relay.example.org");
        value["providers"][0]["credentialRef"] = json!("secret:env/RELAY");
        value["templates"][0]["latest"] = json!(true);
        let reported = refused(&value);
        for path in [
            "/templatez",
            "/accessProfiles/0/allowEverything",
            "/senderProfiles/0/endpoint",
            "/providers/0/credentialRef",
            "/templates/0/latest",
        ] {
            assert!(
                reported.contains(&("config.unknown-key".to_owned(), path.to_owned())),
                "{path}: {reported:?}"
            );
        }
        let mut value = valid();
        value["providers"][0]["type"] = json!("sendmail");
        assert_eq!(refused(&value)[0].1, "/providers/0/type");
    }

    #[test]
    fn the_envelope_the_project_block_and_the_profile_list_are_checked() {
        let mut value = valid();
        value["apiVersion"] = json!(RETIRED_MESSAGING_PROJECT_API_VERSION);
        assert_eq!(refused(&value)[0].0, "config.retired-api-version");
        let mut value = valid();
        value["kind"] = json!("SchedulingProject");
        assert_eq!(refused(&value)[0].0, "config.wrong-kind");
        let mut value = valid();
        value.as_object_mut().unwrap().remove("project");
        assert_eq!(refused(&value)[0].1, "");
        let mut value = valid();
        value["project"]["id"] = json!("Notices");
        assert_eq!(refused(&value)[0].1, "/project/id");
        let mut value = valid();
        value["accessProfiles"] = json!([]);
        assert_eq!(refused(&value)[0].1, "/accessProfiles");
    }

    #[test]
    fn the_former_spellings_name_their_replacements() {
        let mut value = valid();
        value["providers"][0] = json!({"id": "relay", "kind": "smtp"});
        value["accessProfiles"][0]["dailyLimit"] = json!(100);
        let reported = refused(&value);
        assert!(reported.contains(&(
            "config.removed-key".to_owned(),
            "/providers/0/kind".to_owned()
        )));
        assert!(reported.contains(&(
            "config.removed-key".to_owned(),
            "/accessProfiles/0/dailyLimit".to_owned()
        )));
    }

    #[test]
    fn every_reference_must_name_a_declaration() {
        let mut value = valid();
        value["accessProfiles"][0]["templates"] = json!(["unknown-template"]);
        value["accessProfiles"][0]["senderProfiles"] = json!(["unknown-profile"]);
        value["senderProfiles"][0]["provider"] = json!("elsewhere");
        assert_eq!(
            findings(value),
            vec![
                (
                    "messaging.project.unknown-provider".to_owned(),
                    "/senderProfiles/0/provider".to_owned()
                ),
                (
                    "messaging.project.unknown-sender-profile".to_owned(),
                    "/accessProfiles/0/senderProfiles/0".to_owned()
                ),
                (
                    "messaging.project.unknown-template".to_owned(),
                    "/accessProfiles/0/templates/0".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_provider_type_carries_only_its_channels() {
        let mut value = valid();
        value["senderProfiles"][1]["provider"] = json!("relay");
        assert_eq!(
            findings(value),
            one(
                "messaging.project.provider-cannot-carry-channel",
                "/senderProfiles/1/provider"
            )
        );
    }

    #[test]
    fn identifiers_versions_and_duplicates_are_refused_by_the_reader() {
        let mut value = valid();
        value["templates"][1]["version"] = json!("1");
        assert_eq!(
            refused(&value)[0],
            (
                "config.duplicate-item".to_owned(),
                "/templates/1".to_owned()
            )
        );
        let mut value = valid();
        value["providers"][1]["id"] = json!("relay");
        assert_eq!(refused(&value)[0].1, "/providers/1/id");
        for version in ["", "latest/1", "1..2", ".1", "V1", "-1", &"1".repeat(33)] {
            let mut value = valid();
            value["templates"][1]["version"] = json!(version);
            assert_eq!(refused(&value)[0].1, "/templates/1/version", "{version}");
        }
        for version in ["1", "2026-09", "1.2.0"] {
            assert!(valid_template_version(version), "{version}");
        }
        let mut value = valid();
        value["templates"][0]["id"] = json!("Appointment");
        assert_eq!(refused(&value)[0].1, "/templates/0/id");
    }

    #[test]
    fn senders_and_segment_limits_fit_their_channel() {
        for sender in [
            "Notices <notices@example.org>",
            "a@b",
            "notices@example.org, other@example.org",
            "no-at-sign",
        ] {
            let mut value = valid();
            value["senderProfiles"][0]["sender"] = json!(sender);
            assert_eq!(
                findings(value),
                one(
                    "messaging.project.invalid-email-sender",
                    "/senderProfiles/0/sender"
                ),
                "{sender}"
            );
        }
        for sender in ["+0123", "+1", "TwelveChars1", " Lead", "Reg!stry"] {
            let mut value = valid();
            value["senderProfiles"][1]["sender"] = json!(sender);
            assert_eq!(
                findings(value),
                one(
                    "messaging.project.invalid-sms-sender",
                    "/senderProfiles/1/sender"
                ),
                "{sender}"
            );
        }
        let mut value = valid();
        value["senderProfiles"][1]["sender"] = json!("+15551234567");
        assert!(project(value).check().is_ok());
        let mut value = valid();
        value["senderProfiles"][1]
            .as_object_mut()
            .unwrap()
            .remove("maximumSegments");
        assert_eq!(
            findings(value),
            one(
                "messaging.project.missing-maximum-segments",
                "/senderProfiles/1/maximumSegments"
            )
        );
        for segments in [0, 11] {
            let mut value = valid();
            value["senderProfiles"][1]["maximumSegments"] = json!(segments);
            assert_eq!(
                refused(&value)[0],
                (
                    "config.out-of-range".to_owned(),
                    "/senderProfiles/1/maximumSegments".to_owned()
                )
            );
        }
        let mut value = valid();
        value["senderProfiles"][0]["maximumSegments"] = json!(1);
        assert_eq!(
            findings(value),
            one(
                "messaging.project.email-maximum-segments",
                "/senderProfiles/0/maximumSegments"
            )
        );
    }

    #[test]
    fn a_sender_profile_carries_a_bounded_dispatch_policy() {
        let checked = project(valid()).check().unwrap();
        let profile = &checked.sender_profiles["transactional"];
        assert_eq!(
            profile.retry_policy(),
            RetryPolicy {
                maximum_attempts: DEFAULT_MAXIMUM_ATTEMPTS,
                initial_delay_seconds: DEFAULT_INITIAL_RETRY_DELAY_SECONDS,
                maximum_delay_seconds: DEFAULT_MAXIMUM_RETRY_DELAY_SECONDS,
            }
        );
        assert_eq!(profile.on_uncertain, UncertainPolicy::Hold);
        assert!(!profile.accept_duplicates);
        assert_eq!(profile.expiry_seconds(), DEFAULT_EXPIRY_SECONDS);

        let mut value = valid();
        value["senderProfiles"][0]["retry"] = json!({
            "maximumAttempts": 3, "initialDelaySeconds": 10, "maximumDelaySeconds": 60
        });
        value["senderProfiles"][0]["defaultExpirySeconds"] = json!(3600);
        let checked = project(value).check().unwrap();
        let profile = &checked.sender_profiles["transactional"];
        assert_eq!(profile.retry_policy().maximum_attempts, 3);
        assert_eq!(profile.expiry_seconds(), 3600);

        for (retry, member) in [
            (
                json!({"maximumAttempts": 0, "initialDelaySeconds": 10, "maximumDelaySeconds": 60}),
                "maximumAttempts",
            ),
            (
                json!({"maximumAttempts": 21, "initialDelaySeconds": 10, "maximumDelaySeconds": 60}),
                "maximumAttempts",
            ),
            (
                json!({"maximumAttempts": 3, "initialDelaySeconds": 0, "maximumDelaySeconds": 60}),
                "initialDelaySeconds",
            ),
            (
                json!({"maximumAttempts": 3, "initialDelaySeconds": 10, "maximumDelaySeconds": 86_401}),
                "maximumDelaySeconds",
            ),
        ] {
            let mut value = valid();
            value["senderProfiles"][0]["retry"] = retry.clone();
            assert_eq!(
                refused(&value)[0],
                (
                    "config.out-of-range".to_owned(),
                    format!("/senderProfiles/0/retry/{member}")
                ),
                "{retry}"
            );
        }
        let mut value = valid();
        value["senderProfiles"][0]["retry"] = json!({
            "maximumAttempts": 3, "initialDelaySeconds": 60, "maximumDelaySeconds": 10
        });
        assert_eq!(
            findings(value),
            one(
                "messaging.project.retry-delay-order",
                "/senderProfiles/0/retry/maximumDelaySeconds"
            )
        );
        for expiry in [0, 59, MAXIMUM_EXPIRY_SECONDS + 1] {
            let mut value = valid();
            value["senderProfiles"][0]["defaultExpirySeconds"] = json!(expiry);
            assert_eq!(
                refused(&value)[0].1,
                "/senderProfiles/0/defaultExpirySeconds",
                "{expiry}"
            );
        }
        let mut value = valid();
        value["senderProfiles"][0]["retry"] = json!({
            "maximumAttempts": 3, "initialDelaySeconds": 10, "maximumDelaySeconds": 60,
            "jitter": false
        });
        assert_eq!(refused(&value)[0].1, "/senderProfiles/0/retry/jitter");
        let mut value = valid();
        value["senderProfiles"][0]["onUncertain"] = json!("resend");
        assert_eq!(refused(&value)[0].1, "/senderProfiles/0/onUncertain");
    }

    #[test]
    fn retrying_an_uncertain_send_needs_provider_deduplication_or_an_explicit_choice() {
        let mut value = valid();
        value["senderProfiles"][1]["onUncertain"] = json!("retry");
        assert_eq!(
            findings(value.clone()),
            one(
                "messaging.project.uncertain-retry-duplicates",
                "/senderProfiles/1/onUncertain"
            )
        );
        assert!(matches!(
            project(value.clone()).check(),
            Err(PackageError::Findings(_))
        ));
        let mut deduplicating = value.clone();
        deduplicating["providers"][1]["idempotentSubmit"] = json!(true);
        let checked = project(deduplicating).check().unwrap();
        assert_eq!(
            checked.sender_profiles["notices-sms"].on_uncertain,
            UncertainPolicy::Retry
        );
        let mut accepting = value;
        accepting["senderProfiles"][1]["acceptDuplicates"] = json!(true);
        assert!(project(accepting).check().is_ok());
    }

    #[test]
    fn an_smtp_provider_cannot_declare_idempotent_submission() {
        let mut value = valid();
        value["providers"][0]["idempotentSubmit"] = json!(true);
        assert_eq!(
            findings(value),
            one(
                "messaging.project.idempotent-smtp",
                "/providers/0/idempotentSubmit"
            )
        );
    }

    #[test]
    fn every_finding_is_reported_together() {
        let mut value = valid();
        value["providers"][0]["idempotentSubmit"] = json!(true);
        value["senderProfiles"][0]["sender"] = json!("no-at-sign");
        value["accessProfiles"][0]["templates"] = json!(["unknown-template"]);
        let Err(PackageError::Findings(findings)) = project(value).check() else {
            panic!("the project passed its checks");
        };
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn an_allow_list_item_spelled_as_a_wildcard_is_a_warning() {
        let mut value = valid();
        value["accessProfiles"][0]["requesterClients"] = json!(["case-system", "*"]);
        let project = project(value);
        assert_eq!(
            project
                .findings()
                .iter()
                .map(|finding| (finding.code(), finding.path.clone(), finding.is_error()))
                .collect::<Vec<_>>(),
            vec![(
                "messaging.project.wildcard-spelled-item".to_owned(),
                "/accessProfiles/0/requesterClients/1".to_owned(),
                false
            )]
        );
        assert!(project.check().is_ok());
    }

    #[test]
    fn a_missing_template_version_is_reported_at_its_declaration() {
        let project = project(valid());
        let shipped = BTreeSet::from([TemplateReference {
            id: "appointment-reminder".to_owned(),
            version: "1".to_owned(),
        }]);
        assert_eq!(
            project
                .missing_templates(&shipped)
                .iter()
                .map(|finding| (finding.code(), finding.path.clone()))
                .collect::<Vec<_>>(),
            one("messaging.project.missing-template", "/templates/1")
        );
    }

    #[test]
    fn a_package_digest_is_sha256_hex() {
        assert!(valid_package_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_package_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!valid_package_digest(&format!("sha512:{}", "a".repeat(64))));
        assert!(!valid_package_digest("sha256:"));
    }
}
