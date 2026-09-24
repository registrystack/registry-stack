// SPDX-License-Identifier: Apache-2.0

//! The authored package manifest.
//!
//! A package is the directory `package.root` names, holding `messaging.yaml`
//! and one directory per template version under `templates/<id>/<version>/`.
//! The manifest declares the providers a deployment routes through (by kind,
//! never by endpoint or credential, which are runtime configuration), the
//! sender profiles callers select, the template versions the package ships,
//! and who may call the runtime, as `accessProfiles[]`, so a reviewer reads
//! the callers next to what they may send. Every member is closed, so an
//! unknown key is refused rather than ignored.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::access::{valid_identifier, AccessProfile, AccessProfileError, AccessProfiles};
use crate::naming::{MESSAGING_PACKAGE_API_VERSION, MESSAGING_PACKAGE_KIND};
use crate::sms::MAXIMUM_SMS_SEGMENTS;

/// The most providers, sender profiles, or template versions one package
/// declares.
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

/// A delivery channel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
/// configuration; only the kind is package.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKind {
    Smtp,
    Http,
}

impl ProviderKind {
    /// Whether this kind can carry `channel`.
    #[must_use]
    pub const fn carries(self, channel: Channel) -> bool {
        match self {
            Self::Smtp => matches!(channel, Channel::Email),
            Self::Http => true,
        }
    }
}

/// One declared provider, referenced by sender profiles through `id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDeclaration {
    pub id: String,
    pub kind: ProviderKind,
    /// The provider deduplicates submissions on the idempotency key the
    /// runtime sends, so sending one message twice delivers it once.
    #[serde(default, skip_serializing_if = "is_false")]
    pub idempotent_submit: bool,
}

/// What a caller selects: a channel, the provider carrying it, the sender
/// identity, for SMS the most segments one message may use, and how the
/// worker retries, holds, and expires its messages.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenderProfile {
    pub id: String,
    pub channel: Channel,
    pub provider: String,
    /// The from address for email, the sender identifier for SMS.
    pub sender: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_segments: Option<u8>,
    /// How a send that definitely failed is retried. Absent means the
    /// defaults [`SenderProfile::retry_policy`] reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryPolicy>,
    /// What happens when a send may have reached the provider.
    #[serde(default, skip_serializing_if = "UncertainPolicy::is_hold")]
    pub on_uncertain: UncertainPolicy,
    /// The operator's explicit choice that a duplicate message is better
    /// than a missed one, which permits `onUncertain: retry` through a
    /// provider that does not deduplicate.
    #[serde(default, skip_serializing_if = "is_false")]
    pub accept_duplicates: bool,
    /// How long an accepted message may wait to be sent when its request
    /// names no `expiresAt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_expiry_seconds: Option<u32>,
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub maximum_attempts: u8,
    pub initial_delay_seconds: u32,
    pub maximum_delay_seconds: u32,
}

impl RetryPolicy {
    fn is_valid(self) -> bool {
        (1..=MAXIMUM_ATTEMPTS).contains(&self.maximum_attempts)
            && self.initial_delay_seconds >= 1
            && (self.initial_delay_seconds..=MAXIMUM_RETRY_DELAY_SECONDS)
                .contains(&self.maximum_delay_seconds)
    }
}

/// What the worker does with a send that may have reached the provider.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
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

const fn is_false(value: &bool) -> bool {
    !*value
}

/// One template version the package ships, under
/// `templates/<id>/<version>/`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateReference {
    pub id: String,
    pub version: String,
}

/// The package manifest as authored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessagingPackage {
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub providers: Vec<ProviderDeclaration>,
    #[serde(default)]
    pub sender_profiles: Vec<SenderProfile>,
    #[serde(default)]
    pub templates: Vec<TemplateReference>,
    pub access_profiles: Vec<AccessProfile>,
}

/// Why a parsed package cannot be used. Identifiers are package content an
/// author wrote, never caller data, so they are named to point at the entry.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PackageError {
    #[error("unsupported Messaging package apiVersion; expected {MESSAGING_PACKAGE_API_VERSION}")]
    InvalidApiVersion,
    #[error("unsupported Messaging package kind; expected {MESSAGING_PACKAGE_KIND}")]
    InvalidKind,
    #[error("the Messaging package declares no access profile")]
    NoAccessProfiles,
    #[error(transparent)]
    AccessProfile(#[from] AccessProfileError),
    #[error("the package declares more than {MAXIMUM_PACKAGE_DECLARATIONS} {0}")]
    TooManyDeclarations(&'static str),
    #[error("{kind} identifier `{id}` is not a lowercase kebab identifier of at most 64 bytes")]
    InvalidIdentifier { kind: &'static str, id: String },
    #[error("{kind} `{id}` is declared more than once")]
    Duplicate { kind: &'static str, id: String },
    #[error(
        "template `{id}` version `{version}` is not a version label: 1 to 32 lowercase letters, \
         digits, dots, or hyphens, starting with a letter or digit"
    )]
    InvalidTemplateVersion { id: String, version: String },
    #[error("sender profile `{profile}` names provider `{provider}`, which the package does not declare")]
    UnknownProvider { profile: String, provider: String },
    #[error("sender profile `{profile}` routes {channel} through provider `{provider}`, whose kind cannot carry it")]
    ProviderChannel {
        profile: String,
        channel: &'static str,
        provider: String,
    },
    #[error(
        "sender profile `{0}` names an invalid sender: an email sender is one address, an SMS \
         sender is an E.164 number or 1 to 11 letters, digits, or spaces"
    )]
    InvalidSender(String),
    #[error(
        "sender profile `{0}` must declare maximumSegments from 1 to {MAXIMUM_SMS_SEGMENTS} for \
         SMS and none for email"
    )]
    InvalidMaximumSegments(String),
    #[error(
        "sender profile `{0}` declares an invalid retry: maximumAttempts from 1 to \
         {MAXIMUM_ATTEMPTS}, initialDelaySeconds at least 1, and maximumDelaySeconds from \
         initialDelaySeconds to {MAXIMUM_RETRY_DELAY_SECONDS}"
    )]
    InvalidRetry(String),
    #[error(
        "sender profile `{0}` declares defaultExpirySeconds outside {MINIMUM_EXPIRY_SECONDS} to \
         {MAXIMUM_EXPIRY_SECONDS}"
    )]
    InvalidExpiry(String),
    #[error(
        "sender profile `{profile}` declares onUncertain: retry, but provider `{provider}` does \
         not declare idempotentSubmit and the profile does not set acceptDuplicates"
    )]
    UncertainRetry { profile: String, provider: String },
    #[error("access profile `{profile}` names {kind} `{id}`, which the package does not declare")]
    UnknownReference {
        profile: String,
        kind: &'static str,
        id: String,
    },
    #[error("template `{id}` version `{version}`: {reason}")]
    Template {
        id: String,
        version: String,
        reason: String,
    },
    #[error("the package ships template `{id}` version `{version}` without declaring it")]
    UndeclaredTemplate { id: String, version: String },
    #[error("the package declares template `{id}` version `{version}` but ships no such template")]
    MissingTemplate { id: String, version: String },
    #[error("the package digest must be sha256: followed by 64 lowercase hexadecimal digits")]
    InvalidDigest,
}

/// The manifest after its own checks, indexed for the package it belongs to.
#[derive(Clone, Debug)]
pub struct CheckedManifest {
    pub access_profiles: AccessProfiles,
    pub sender_profiles: BTreeMap<String, SenderProfile>,
    pub providers: BTreeMap<String, ProviderDeclaration>,
    pub templates: BTreeSet<TemplateReference>,
}

impl MessagingPackage {
    /// Check the envelope, every declaration, and every reference between
    /// them. Template contents are checked when the package is assembled.
    pub fn check(&self) -> Result<CheckedManifest, PackageError> {
        if self.api_version != MESSAGING_PACKAGE_API_VERSION {
            return Err(PackageError::InvalidApiVersion);
        }
        if self.kind != MESSAGING_PACKAGE_KIND {
            return Err(PackageError::InvalidKind);
        }
        if self.access_profiles.is_empty() {
            return Err(PackageError::NoAccessProfiles);
        }
        for (kind, count) in [
            ("providers", self.providers.len()),
            ("sender profiles", self.sender_profiles.len()),
            ("templates", self.templates.len()),
        ] {
            if count > MAXIMUM_PACKAGE_DECLARATIONS {
                return Err(PackageError::TooManyDeclarations(kind));
            }
        }
        let providers = index("provider", &self.providers, |provider| &provider.id)?;
        let sender_profiles = index("sender profile", &self.sender_profiles, |profile| {
            &profile.id
        })?;
        for profile in self.sender_profiles.iter() {
            check_sender_profile(profile, &providers)?;
        }
        let mut templates = BTreeSet::new();
        for template in &self.templates {
            if !valid_identifier(&template.id) {
                return Err(PackageError::InvalidIdentifier {
                    kind: "template",
                    id: template.id.clone(),
                });
            }
            if !valid_template_version(&template.version) {
                return Err(PackageError::InvalidTemplateVersion {
                    id: template.id.clone(),
                    version: template.version.clone(),
                });
            }
            if !templates.insert(template.clone()) {
                return Err(PackageError::Duplicate {
                    kind: "template version",
                    id: format!("{}@{}", template.id, template.version),
                });
            }
        }
        let access_profiles = AccessProfiles::new(self.access_profiles.clone())?;
        let template_ids: BTreeSet<&str> = templates.iter().map(|t| t.id.as_str()).collect();
        for profile in access_profiles.iter() {
            for sender in &profile.sender_profiles {
                if !sender_profiles.contains_key(sender) {
                    return Err(PackageError::UnknownReference {
                        profile: profile.id.clone(),
                        kind: "sender profile",
                        id: sender.clone(),
                    });
                }
            }
            for template in &profile.templates {
                if !template_ids.contains(template.as_str()) {
                    return Err(PackageError::UnknownReference {
                        profile: profile.id.clone(),
                        kind: "template",
                        id: template.clone(),
                    });
                }
            }
        }
        Ok(CheckedManifest {
            access_profiles,
            sender_profiles,
            providers,
            templates,
        })
    }
}

fn index<T: Clone>(
    kind: &'static str,
    entries: &[T],
    id: impl Fn(&T) -> &String,
) -> Result<BTreeMap<String, T>, PackageError> {
    let mut indexed = BTreeMap::new();
    for entry in entries {
        let key = id(entry);
        if !valid_identifier(key) {
            return Err(PackageError::InvalidIdentifier {
                kind,
                id: key.clone(),
            });
        }
        if indexed.insert(key.clone(), entry.clone()).is_some() {
            return Err(PackageError::Duplicate {
                kind,
                id: key.clone(),
            });
        }
    }
    Ok(indexed)
}

fn check_sender_profile(
    profile: &SenderProfile,
    providers: &BTreeMap<String, ProviderDeclaration>,
) -> Result<(), PackageError> {
    let provider =
        providers
            .get(&profile.provider)
            .ok_or_else(|| PackageError::UnknownProvider {
                profile: profile.id.clone(),
                provider: profile.provider.clone(),
            })?;
    if !provider.kind.carries(profile.channel) {
        return Err(PackageError::ProviderChannel {
            profile: profile.id.clone(),
            channel: profile.channel.as_str(),
            provider: provider.id.clone(),
        });
    }
    let sender_valid = match profile.channel {
        Channel::Email => valid_email_sender(&profile.sender),
        Channel::Sms => valid_sms_sender(&profile.sender),
    };
    if !sender_valid {
        return Err(PackageError::InvalidSender(profile.id.clone()));
    }
    let segments_valid = match profile.channel {
        Channel::Email => profile.maximum_segments.is_none(),
        Channel::Sms => profile
            .maximum_segments
            .is_some_and(|maximum| (1..=MAXIMUM_SMS_SEGMENTS).contains(&maximum)),
    };
    if !segments_valid {
        return Err(PackageError::InvalidMaximumSegments(profile.id.clone()));
    }
    if profile.retry.is_some_and(|retry| !retry.is_valid()) {
        return Err(PackageError::InvalidRetry(profile.id.clone()));
    }
    if profile.default_expiry_seconds.is_some_and(|seconds| {
        !(MINIMUM_EXPIRY_SECONDS..=MAXIMUM_EXPIRY_SECONDS).contains(&seconds)
    }) {
        return Err(PackageError::InvalidExpiry(profile.id.clone()));
    }
    // A send that may have reached the provider is sent again only when a
    // second send cannot deliver twice, or the operator chose duplicates.
    if profile.on_uncertain == UncertainPolicy::Retry
        && !provider.idempotent_submit
        && !profile.accept_duplicates
    {
        return Err(PackageError::UncertainRetry {
            profile: profile.id.clone(),
            provider: provider.id.clone(),
        });
    }
    Ok(())
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

    fn package(value: serde_json::Value) -> Result<MessagingPackage, serde_json::Error> {
        serde_json::from_value(value)
    }

    pub(crate) fn valid() -> serde_json::Value {
        json!({
            "apiVersion": MESSAGING_PACKAGE_API_VERSION,
            "kind": MESSAGING_PACKAGE_KIND,
            "providers": [
                {"id": "relay", "kind": "smtp"},
                {"id": "sms-gateway", "kind": "http"}
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

    fn refusal(value: serde_json::Value) -> PackageError {
        package(value).unwrap().check().unwrap_err()
    }

    #[test]
    fn a_valid_package_yields_its_declarations() {
        let checked = package(valid()).unwrap().check().unwrap();
        assert!(checked.access_profiles.get("case-notices").is_some());
        assert_eq!(checked.sender_profiles.len(), 2);
        assert_eq!(checked.providers.len(), 2);
        assert_eq!(checked.templates.len(), 2);
    }

    #[test]
    fn an_unknown_member_is_refused() {
        let mut value = valid();
        value["templatez"] = json!([]);
        assert!(package(value).is_err());
        let mut value = valid();
        value["accessProfiles"][0]["allowEverything"] = json!(true);
        assert!(package(value).is_err());
        let mut value = valid();
        value["senderProfiles"][0]["endpoint"] = json!("https://relay.example.org");
        assert!(package(value).is_err());
        let mut value = valid();
        value["providers"][0]["credentialRef"] = json!("secret:env/RELAY");
        assert!(package(value).is_err());
        let mut value = valid();
        value["templates"][0]["latest"] = json!(true);
        assert!(package(value).is_err());
        let mut value = valid();
        value["providers"][0]["kind"] = json!("sendmail");
        assert!(package(value).is_err());
    }

    #[test]
    fn the_envelope_and_the_profile_list_are_checked() {
        let mut value = valid();
        value["apiVersion"] = json!("registry.registrystack.org/messaging-package/v0");
        assert_eq!(refusal(value), PackageError::InvalidApiVersion);
        let mut value = valid();
        value["kind"] = json!("SchedulingPolicyPackage");
        assert_eq!(refusal(value), PackageError::InvalidKind);
        let mut value = valid();
        value["accessProfiles"] = json!([]);
        assert_eq!(refusal(value), PackageError::NoAccessProfiles);
    }

    #[test]
    fn every_reference_must_name_a_declaration() {
        let mut value = valid();
        value["accessProfiles"][0]["templates"] = json!(["unknown-template"]);
        assert!(matches!(
            refusal(value),
            PackageError::UnknownReference {
                kind: "template",
                ..
            }
        ));
        let mut value = valid();
        value["accessProfiles"][0]["senderProfiles"] = json!(["unknown-profile"]);
        assert!(matches!(
            refusal(value),
            PackageError::UnknownReference {
                kind: "sender profile",
                ..
            }
        ));
        let mut value = valid();
        value["senderProfiles"][0]["provider"] = json!("elsewhere");
        assert!(matches!(
            refusal(value),
            PackageError::UnknownProvider { .. }
        ));
    }

    #[test]
    fn a_provider_kind_carries_only_its_channels() {
        let mut value = valid();
        value["senderProfiles"][1]["provider"] = json!("relay");
        assert!(matches!(
            refusal(value),
            PackageError::ProviderChannel { channel: "sms", .. }
        ));
    }

    #[test]
    fn identifiers_versions_and_duplicates_are_checked() {
        let mut value = valid();
        value["templates"][1]["version"] = json!("1");
        assert!(matches!(refusal(value), PackageError::Duplicate { .. }));
        let mut value = valid();
        value["providers"][1]["id"] = json!("relay");
        assert!(matches!(refusal(value), PackageError::Duplicate { .. }));
        for version in ["", "latest/1", "1..2", ".1", "V1", "-1", &"1".repeat(33)] {
            let mut value = valid();
            value["templates"][1]["version"] = json!(version);
            assert!(
                matches!(refusal(value), PackageError::InvalidTemplateVersion { .. }),
                "{version}"
            );
        }
        for version in ["1", "2026-09", "1.2.0"] {
            assert!(valid_template_version(version), "{version}");
        }
        let mut value = valid();
        value["templates"][0]["id"] = json!("Appointment");
        assert!(matches!(
            refusal(value),
            PackageError::InvalidIdentifier { .. }
        ));
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
            assert!(
                matches!(refusal(value), PackageError::InvalidSender(_)),
                "{sender}"
            );
        }
        for sender in ["+0123", "+1", "TwelveChars1", " Lead", "Reg!stry"] {
            let mut value = valid();
            value["senderProfiles"][1]["sender"] = json!(sender);
            assert!(
                matches!(refusal(value), PackageError::InvalidSender(_)),
                "{sender}"
            );
        }
        let mut value = valid();
        value["senderProfiles"][1]["sender"] = json!("+15551234567");
        assert!(package(value).unwrap().check().is_ok());
        for segments in [json!(null), json!(0), json!(11)] {
            let mut value = valid();
            value["senderProfiles"][1]["maximumSegments"] = segments;
            assert!(matches!(
                refusal(value),
                PackageError::InvalidMaximumSegments(_)
            ));
        }
        let mut value = valid();
        value["senderProfiles"][0]["maximumSegments"] = json!(1);
        assert!(matches!(
            refusal(value),
            PackageError::InvalidMaximumSegments(_)
        ));
    }

    #[test]
    fn a_sender_profile_carries_a_bounded_dispatch_policy() {
        let checked = package(valid()).unwrap().check().unwrap();
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
        let checked = package(value).unwrap().check().unwrap();
        let profile = &checked.sender_profiles["transactional"];
        assert_eq!(profile.retry_policy().maximum_attempts, 3);
        assert_eq!(profile.expiry_seconds(), 3600);

        for retry in [
            json!({"maximumAttempts": 0, "initialDelaySeconds": 10, "maximumDelaySeconds": 60}),
            json!({"maximumAttempts": 21, "initialDelaySeconds": 10, "maximumDelaySeconds": 60}),
            json!({"maximumAttempts": 3, "initialDelaySeconds": 0, "maximumDelaySeconds": 60}),
            json!({"maximumAttempts": 3, "initialDelaySeconds": 60, "maximumDelaySeconds": 10}),
            json!({"maximumAttempts": 3, "initialDelaySeconds": 10, "maximumDelaySeconds": 86_401}),
        ] {
            let mut value = valid();
            value["senderProfiles"][0]["retry"] = retry.clone();
            assert!(
                matches!(refusal(value), PackageError::InvalidRetry(_)),
                "{retry}"
            );
        }
        for expiry in [0, 59, MAXIMUM_EXPIRY_SECONDS + 1] {
            let mut value = valid();
            value["senderProfiles"][0]["defaultExpirySeconds"] = json!(expiry);
            assert!(
                matches!(refusal(value), PackageError::InvalidExpiry(_)),
                "{expiry}"
            );
        }
        let mut value = valid();
        value["senderProfiles"][0]["retry"] = json!({
            "maximumAttempts": 3, "initialDelaySeconds": 10, "maximumDelaySeconds": 60,
            "jitter": false
        });
        assert!(package(value).is_err());
        let mut value = valid();
        value["senderProfiles"][0]["onUncertain"] = json!("resend");
        assert!(package(value).is_err());
    }

    #[test]
    fn retrying_an_uncertain_send_needs_provider_deduplication_or_an_explicit_choice() {
        let mut value = valid();
        value["senderProfiles"][1]["onUncertain"] = json!("retry");
        assert_eq!(
            refusal(value.clone()),
            PackageError::UncertainRetry {
                profile: "notices-sms".to_owned(),
                provider: "sms-gateway".to_owned(),
            }
        );
        let mut deduplicating = value.clone();
        deduplicating["providers"][1]["idempotentSubmit"] = json!(true);
        let checked = package(deduplicating).unwrap().check().unwrap();
        assert_eq!(
            checked.sender_profiles["notices-sms"].on_uncertain,
            UncertainPolicy::Retry
        );
        let mut accepting = value;
        accepting["senderProfiles"][1]["acceptDuplicates"] = json!(true);
        assert!(package(accepting).unwrap().check().is_ok());
    }

    #[test]
    fn a_package_digest_is_sha256_hex() {
        assert!(valid_package_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_package_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!valid_package_digest(&format!("sha512:{}", "a".repeat(64))));
        assert!(!valid_package_digest("sha256:"));
    }
}
