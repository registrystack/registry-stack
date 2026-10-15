// SPDX-License-Identifier: Apache-2.0
//! Distinct Proposal resources and exact, caller-controlled transition attempts.

use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegRecoveryHint {
    Refresh,
    Retry,
    CorrectInput,
    Terminal,
    ReceiptOnly,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegAvailabilityReason {
    PendingReview,
    StaleRevision,
    ContractChanged,
    DependencyOutage,
    InvalidInput,
    AlreadyApplied,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegAvailability {
    pub available: bool,
    pub observed_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<BRegAvailabilityReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<BRegRecoveryHint>,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalState {
    Draft,
    Submitted,
    Applied,
    Cancelled,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalApplicationState {
    Pending,
    Applying,
    Blocked,
    Applied,
    Cancelled,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalApplicationMode {
    Automatic,
    Manual,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalApplicationReason {
    ContractChanged,
    DependencyOutage,
    LeaseExpired,
    ApplicationRefused,
    AttemptsExhausted,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAutomaticRetry {
    pub scheduled: bool,
    pub attempts: u16,
    pub maximum_attempts: u16,
}
/// Local application progress for the enclosing exact frozen submission.
/// It neither follows a successor nor reconciles an unknown mutation command.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalApplicationStatus {
    pub state: BRegProposalApplicationState,
    pub mode: BRegProposalApplicationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<BRegProposalApplicationReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<BRegRecoveryHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automatic_retry: Option<BRegProposalAutomaticRetry>,
}

/// Inert server-issued link. Only a client-bound Proposal promotes its use.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalLink {
    method: String,
    path: String,
    access_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    if_match: Option<String>,
    operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    availability: Option<BRegAvailability>,
}
impl BRegProposalLink {
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn availability(&self) -> Option<&BRegAvailability> {
        self.availability.as_ref()
    }
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
    pub(crate) fn access_profile(&self) -> &str {
        &self.access_profile
    }
    pub(crate) fn if_match(&self) -> Option<&str> {
        self.if_match.as_deref()
    }
}
impl fmt::Debug for BRegProposalLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegProposalLink(<inert>)")
    }
}

/// Inert slot metadata disclosed on an authorized Proposal representation.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAttachment {
    id: String,
    required: bool,
    maximum_bytes: u64,
    content_types: Vec<String>,
    classification: String,
    links: BTreeMap<String, BRegProposalLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<BRegProposalAttachmentValue>,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAttachmentValue {
    submission_version: u32,
    sha256: String,
    content_type: String,
    byte_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uploaded_at: Option<String>,
    verification_status: String,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalApplication {
    pub application_id: String,
    pub submission_version: u32,
    pub effect_digest: String,
    pub result_links: Vec<BRegProposalResultReference>,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalResultReference {
    pub record_type: String,
    pub record_id: String,
    pub revision: u64,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewDocument {
    pub id: String,
    pub action_id: String,
    pub action_revision: String,
    pub submission_version: u32,
    pub revision: u64,
    pub effect_digest: String,
    pub subject: BRegProposalReviewSubject,
    pub context: BRegProposalReviewContext,
    pub reviewable: bool,
    /// Provider correlation for the exact accepted submission, on status reads only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<registry_review_protocol::PolicySelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<BRegProposalReviewResult>,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewSubject {
    pub source: String,
    pub subject_type: String,
    pub id: String,
    pub version: String,
    pub digest: String,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewContext {
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<BRegProposalReviewContextContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<String, Value>>,
}
/// Exact local interface exported by the governed producer, independent of a review policy pin.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewContextContract {
    pub id: String,
    pub revision: String,
    pub schema_digest: String,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewResult {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_until: Option<String>,
}
impl BRegProposalAttachment {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub const fn required(&self) -> bool {
        self.required
    }
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }
    pub fn content_types(&self) -> &[String] {
        &self.content_types
    }
    pub fn link(&self, operation: &str) -> Option<&BRegProposalLink> {
        self.links.get(operation)
    }
}

/// A Proposal is independently versioned and never decoded as a Record subtype.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposal {
    id: String,
    action_id: String,
    action_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input: Option<serde_json::Map<String, Value>>,
    submission_version: u32,
    revision: u64,
    state: BRegProposalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_digest: Option<String>,
    links: BTreeMap<String, BRegProposalLink>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attachments: BTreeMap<String, BRegProposalAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application: Option<BRegProposalApplication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_status: Option<BRegProposalApplicationStatus>,
    #[serde(skip)]
    source: Option<String>,
}
impl BRegProposal {
    /// Only input fields explicitly disclosed to the selected caller profile.
    pub fn input(&self) -> Option<&serde_json::Map<String, Value>> {
        self.input.as_ref()
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BaseRegistryClientError> {
        if bytes.len() > DEFAULT_MAX_RESPONSE_BYTES as usize {
            return Err(refusal());
        }
        let value = crate::strict_json::from_slice(bytes).map_err(|_| refusal())?;
        let proposal: Self = serde_json::from_value(value).map_err(|_| refusal())?;
        proposal.validate()?;
        Ok(proposal)
    }
    fn validate(&self) -> Result<(), BaseRegistryClientError> {
        if Uuid::parse_str(&self.id).is_err()
            || self.submission_version == 0
            || self.revision == 0
            || self.state == BRegProposalState::Submitted && self.effect_digest.is_none()
            || self.state == BRegProposalState::Draft && self.effect_digest.is_some()
            || self.state == BRegProposalState::Applied
                && self.effect_digest.is_some()
                && self.application.is_none()
            || !identifier(&self.action_id)
            || !digest(&self.action_revision)
            || self
                .effect_digest
                .as_ref()
                .is_some_and(|value| !digest(value))
            || self
                .blocked_reason
                .as_deref()
                .is_some_and(|reason| reason != "package-changed")
        {
            return Err(refusal());
        }
        if self.application_status.as_ref().is_some_and(|status| {
            self.effect_digest.is_none()
                || self.submission_version == 0
                || self.state == BRegProposalState::Draft
                || status.reason.is_some() != status.recovery.is_some()
                || status.state == BRegProposalApplicationState::Blocked && status.reason.is_none()
                || matches!(
                    status.state,
                    BRegProposalApplicationState::Applied | BRegProposalApplicationState::Cancelled
                ) && (status.reason.is_some() || status.automatic_retry.is_some())
                || status.mode == BRegProposalApplicationMode::Automatic
                    && matches!(
                        status.state,
                        BRegProposalApplicationState::Pending
                            | BRegProposalApplicationState::Applying
                            | BRegProposalApplicationState::Blocked
                    )
                    && status.automatic_retry.is_none()
                || match status.state {
                    BRegProposalApplicationState::Applied => {
                        self.state != BRegProposalState::Applied || self.application.is_none()
                    }
                    BRegProposalApplicationState::Cancelled => {
                        self.state != BRegProposalState::Cancelled
                    }
                    _ => self.state != BRegProposalState::Submitted,
                }
                || status.automatic_retry.as_ref().is_some_and(|retry| {
                    status.mode != BRegProposalApplicationMode::Automatic
                        || !(1..=1000).contains(&retry.maximum_attempts)
                        || retry.attempts > retry.maximum_attempts
                        || retry.scheduled
                            && (retry.attempts == retry.maximum_attempts
                                || !matches!(
                                    status.state,
                                    BRegProposalApplicationState::Pending
                                        | BRegProposalApplicationState::Applying
                                ))
                })
        }) {
            return Err(refusal());
        }
        if self
            .title
            .as_ref()
            .is_some_and(|title| title.chars().count() > 1024)
        {
            return Err(refusal());
        }
        if self.application.as_ref().is_some_and(|application| {
            self.state != BRegProposalState::Applied
                || self.submission_version == 0
                || Uuid::parse_str(&application.application_id).is_err()
                || application.submission_version != self.submission_version
                || !digest(&application.effect_digest)
                || self
                    .effect_digest
                    .as_ref()
                    .is_none_or(|digest| digest != &application.effect_digest)
                || application.result_links.len() > 16
                || application.result_links.iter().any(|reference| {
                    !identifier(&reference.record_type)
                        || Uuid::parse_str(&reference.record_id).is_err()
                        || reference.revision == 0
                })
        }) {
            return Err(refusal());
        }
        for (operation, link) in &self.links {
            validate_link(link)?;
            let (expected_method, expected_operation) = match operation.as_str() {
                "self" => ("GET", "get"),
                "reviewContext" => ("GET", "get-review-context"),
                "reviewStatus" => ("GET", "get-review-status"),
                "submit" | "edit" | "revise" | "rebase" | "retry" | "cancel" | "apply" => {
                    ("POST", operation.as_str())
                }
                _ => return Err(refusal()),
            };
            let segments = link.path.split('/').skip(1).collect::<Vec<_>>();
            let valid_locator = match segments.as_slice() {
                ["v1", "proposals", id] if operation == "self" => *id == self.id,
                ["v1", "proposals", id, suffix] => {
                    *id == self.id
                        && *suffix
                            == match operation.as_str() {
                                "reviewContext" => "review-context",
                                "reviewStatus" => "review-status",
                                _ => expected_operation,
                            }
                }
                _ => false,
            };
            if !valid_locator
                || link.method != expected_method
                || link.operation != expected_operation
                || link.availability.as_ref().is_some_and(|availability| {
                    availability.observed_revision != self.revision
                        || !availability.available
                            && (availability.reason.is_none() || availability.recovery.is_none())
                })
            {
                return Err(refusal());
            }
        }
        if self.attachments.len() > MAX_BREG_ATTACHMENT_SLOTS {
            return Err(refusal());
        }
        for (id, slot) in &self.attachments {
            if id != &slot.id
                || !identifier(id)
                || slot.maximum_bytes == 0
                || slot.maximum_bytes > MAX_BREG_ATTACHMENT_BYTES
                || slot.content_types.is_empty()
                || slot.content_types.len() > MAX_BREG_ATTACHMENT_CONTENT_TYPES
                || !matches!(
                    slot.classification.as_str(),
                    "public" | "internal" | "restricted"
                )
                || slot
                    .content_types
                    .iter()
                    .any(|media| !crate::attachment::valid_attachment_content_type(media))
            {
                return Err(refusal());
            }
            for (operation, link) in &slot.links {
                let method = match operation.as_str() {
                    "download" => "GET",
                    "upload" => "PATCH",
                    "remove" => "DELETE",
                    _ => return Err(refusal()),
                };
                let expected = format!("/v1/proposals/{}/attachments/{id}", self.id);
                let path = if operation == "download" {
                    format!("{expected}?submissionVersion={}", self.submission_version)
                } else {
                    expected
                };
                if link.method != method
                    || link.path != path
                    || &link.operation != operation
                    || !identifier(&link.access_profile)
                    || method != "GET" && !valid_condition(link.if_match.as_deref())
                    || link
                        .availability
                        .as_ref()
                        .is_some_and(|availability| availability.observed_revision != self.revision)
                {
                    return Err(refusal());
                }
            }
            if slot.value.as_ref().is_some_and(|value| {
                value.submission_version != self.submission_version
                    || value.sha256.len() != 64
                    || !value
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || value.byte_size == 0
                    || value.byte_size > MAX_BREG_ATTACHMENT_BYTES
                    || !crate::attachment::valid_attachment_content_type(&value.content_type)
                    || !matches!(
                        value.verification_status.as_str(),
                        "notRequired" | "pending" | "approved" | "rejected"
                    )
                    || value
                        .uploaded_at
                        .as_deref()
                        .is_none_or(|value| proposal_instant(value).is_none())
            }) {
                return Err(refusal());
            }
        }
        Ok(())
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn action_id(&self) -> &str {
        &self.action_id
    }
    pub fn action_revision(&self) -> &str {
        &self.action_revision
    }
    pub fn effect_digest(&self) -> Option<&str> {
        self.effect_digest.as_deref()
    }
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
    pub fn application(&self) -> Option<&BRegProposalApplication> {
        self.application.as_ref()
    }
    pub fn application_status(&self) -> Option<&BRegProposalApplicationStatus> {
        self.application_status.as_ref()
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn submission_version(&self) -> u32 {
        self.submission_version
    }
    pub const fn state(&self) -> BRegProposalState {
        self.state
    }
    pub fn blocked_reason(&self) -> Option<&str> {
        self.blocked_reason.as_deref()
    }
    pub fn link(&self, operation: &str) -> Option<&BRegProposalLink> {
        self.links.get(operation)
    }
    pub fn attachment(&self, id: &str) -> Option<&BRegProposalAttachment> {
        self.attachments.get(id)
    }
    pub(crate) fn bind(mut self, source: String) -> Self {
        self.source = Some(source);
        self
    }
    pub(crate) fn bind_profile(
        self,
        source: String,
        profile: &str,
    ) -> Result<Self, BaseRegistryClientError> {
        if self
            .links
            .values()
            .chain(
                self.attachments
                    .values()
                    .flat_map(|slot| slot.links.values()),
            )
            .any(|link| link.access_profile != profile)
        {
            return Err(refusal());
        }
        Ok(self.bind(source))
    }
}
impl fmt::Debug for BRegProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegProposal(<redacted>)")
    }
}

/// One explicitly bounded collection response. The caller chooses each continuation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalPage {
    pub items: Vec<BRegProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone)]
pub struct BRegProposalCollection {
    source: String,
    registry_revision: String,
    path: String,
    profile: String,
}

/// Source-bound UUID lookup authority, promoted only from the metadata Get descriptor.
#[derive(Clone)]
pub struct BRegProposalGetBinding {
    source: String,
    profile: String,
    path: String,
}
/// Purpose-specific authority to read one Proposal review document by UUID.
/// Constructed only from the caller-visible runtime metadata inventory.
#[derive(Clone)]
pub struct BRegProposalReviewBinding {
    source: String,
    profile: String,
    action: String,
    operation: &'static str,
    suffix: &'static str,
}
impl BRegProposalReviewBinding {
    pub(crate) fn from_metadata(
        actions: &Value,
        source: &str,
        profile: &str,
        action: &str,
        status: bool,
    ) -> Result<Self, BaseRegistryClientError> {
        let operation = if status {
            "get-review-status"
        } else {
            "get-review-context"
        };
        let suffix = if status {
            "review-status"
        } else {
            "review-context"
        };
        if !identifier(profile)
            || !identifier(action)
            || !actions.as_array().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry["actionId"].as_str() == Some(action)
                        && entry["accessProfile"].as_str() == Some(profile)
                        && entry["operations"].as_array().is_some_and(|operations| {
                            operations
                                .iter()
                                .any(|value| value.as_str() == Some(operation))
                        })
                })
            })
        {
            return Err(refusal());
        }
        Ok(Self {
            source: source.to_owned(),
            profile: profile.to_owned(),
            action: action.to_owned(),
            operation,
            suffix,
        })
    }
}
impl fmt::Debug for BRegProposalReviewBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegProposalReviewBinding(<bound>)")
    }
}
impl BRegProposalGetBinding {
    pub(crate) fn from_metadata(
        value: &Value,
        source: &str,
        profile: &str,
    ) -> Result<Self, BaseRegistryClientError> {
        if !identifier(profile)
            || value.get("method").and_then(Value::as_str) != Some("GET")
            || value.get("path").and_then(Value::as_str) != Some("/v1/proposals/{proposal_id}")
            || !value
                .get("accessProfiles")
                .and_then(Value::as_array)
                .is_some_and(|profiles| {
                    profiles.iter().any(|value| value.as_str() == Some(profile))
                })
        {
            return Err(refusal());
        }
        Ok(Self {
            source: source.to_owned(),
            profile: profile.to_owned(),
            path: "/v1/proposals/{proposal_id}".to_owned(),
        })
    }
}
impl fmt::Debug for BRegProposalGetBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegProposalGetBinding(<redacted>)")
    }
}
impl fmt::Debug for BRegProposalCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegProposalCollection(<bound>)")
    }
}
impl BRegProposalCollection {
    pub(crate) fn from_metadata(
        value: &Value,
        source: &str,
        revision: &str,
        profile: &str,
    ) -> Result<Self, BaseRegistryClientError> {
        let path = value
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(refusal)?;
        let profiles = value
            .get("accessProfiles")
            .and_then(Value::as_array)
            .ok_or_else(refusal)?;
        if value.get("method").and_then(Value::as_str) != Some("GET")
            || !profiles
                .iter()
                .any(|candidate| candidate.as_str() == Some(profile))
            || !path.starts_with("/v1/")
            || path.contains(['?', '#', '%', '\\'])
            || path.split('/').skip(1).any(|segment| !identifier(segment))
        {
            return Err(refusal());
        }
        Ok(Self {
            source: source.to_owned(),
            registry_revision: revision.to_owned(),
            path: path.to_owned(),
            profile: profile.to_owned(),
        })
    }
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct BRegProposalQuery {
    pub action: Option<String>,
    pub owner_is_caller: bool,
    pub target: Option<String>,
    pub state: Option<BRegProposalState>,
    pub cursor: Option<String>,
    pub top: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedEvidence {
    version: u8,
    source: String,
    proposal_id: String,
    action_id: String,
    action_revision: String,
    submission_version: u32,
    revision: u64,
    state: BRegProposalState,
    link: BRegProposalLink,
    body: String,
    key: String,
}
/// Original exact transition evidence, containing inputs and key material.
/// Persist it in application-protected state before sending. Parsing grants no authority.
#[derive(Clone)]
pub struct BRegPreparedProposal {
    bytes: Zeroizing<Vec<u8>>,
    executable: bool,
}
impl BRegPreparedProposal {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BaseRegistryClientError> {
        if bytes.len() > DEFAULT_MAX_RESPONSE_BYTES as usize {
            return Err(refusal());
        }
        let value = crate::strict_json::from_slice(bytes).map_err(|_| refusal())?;
        let data: PreparedEvidence = serde_json::from_value(value).map_err(|_| refusal())?;
        if data.version != 2
            || data.revision == 0
            || data
                .link
                .availability
                .as_ref()
                .is_some_and(|availability| availability.observed_revision != data.revision)
            || Uuid::parse_str(&data.proposal_id).is_err()
            || !digest(&data.action_revision)
        {
            return Err(refusal());
        }
        validate_link(&data.link)?;
        BRegIdempotencyKey::parse(&data.key).map_err(|_| refusal())?;
        let body = crate::strict_json::from_slice(data.body.as_bytes()).map_err(|_| refusal())?;
        validate_body(&data.link.operation, &body)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            executable: false,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn decode(&self) -> Result<PreparedEvidence, BaseRegistryClientError> {
        serde_json::from_slice(&self.bytes).map_err(|_| refusal())
    }
}
impl fmt::Debug for BRegPreparedProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegPreparedProposal(<redacted>)")
    }
}
impl BaseRegistryClient {
    /// Read the native review endpoint using only its advertised purpose grant.
    /// The caller need not hold the broader Proposal Get permission.
    pub async fn read_proposal_review_by_id(
        &self,
        binding: &BRegProposalReviewBinding,
        id: &str,
    ) -> Result<BRegComplete<BRegProposalReviewDocument>, BaseRegistryClientError> {
        if binding.source != self.source_binding()
            || !Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id)
        {
            return Err(refusal());
        }
        let link = BRegProposalLink {
            method: "GET".to_owned(),
            path: format!("/v1/proposals/{id}/{}", binding.suffix),
            access_profile: binding.profile.clone(),
            operation: binding.operation.to_owned(),
            if_match: None,
            availability: None,
        };
        let response = self.proposal_exchange(&link, None, None).await?;
        let value =
            crate::strict_json::from_slice(response.value.as_bytes()).map_err(|_| refusal())?;
        let document: BRegProposalReviewDocument =
            serde_json::from_value(value).map_err(|_| refusal())?;
        let is_context = binding.operation == "get-review-context";
        if document.id != id
            || document.action_id != binding.action
            || !digest(&document.action_revision)
            || document.submission_version == 0
            || document.revision == 0
            || !digest(&document.effect_digest)
            || document.subject.subject_type != "proposal"
            || document.subject.id != id
            || document.subject.version != document.submission_version.to_string()
            || document.subject.digest != document.effect_digest
            || document.subject.source.is_empty()
            || document.subject.source.len() > 512
            || document.context.reference.is_empty()
            || document.context.reference.len() > 2048
            || document.context.contract.as_ref().is_some_and(|contract| {
                !contract.id.starts_with("urn:registry:breg:review-context:")
                    || contract.id.len() > 2048
                    || contract.id.chars().any(char::is_control)
                    || !digest(&contract.revision)
                    || !digest(&contract.schema_digest)
            })
            || document.authority.is_some() != document.policy.is_some()
            || document
                .policy
                .as_ref()
                .is_some_and(|policy| policy.check().is_err())
            || !valid_review_projection(&document, is_context)
        {
            return Err(refusal());
        }
        Ok(BRegComplete {
            value: document,
            metadata: response.metadata,
        })
    }

    /// Resolve a UUID through an advertised Get capability, without requiring List.
    pub async fn get_proposal(
        &self,
        binding: &BRegProposalGetBinding,
        id: &str,
    ) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        self.get_proposal_observation(binding, id).await.outcome
    }

    /// Observe one authorized Proposal, preserving the receiver's scheduling
    /// hint even when its response cannot supply a usable representation.
    /// No retry or mutation is performed by this method.
    pub async fn get_proposal_observation(
        &self,
        binding: &BRegProposalGetBinding,
        id: &str,
    ) -> BRegObservation<BRegProposal> {
        let mut retry_after = BRegRetryAfter::Absent;
        let outcome = async {
            if binding.source != self.source_binding()
                || !Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id)
            {
                return Err(refusal());
            }
            let link = BRegProposalLink {
                method: "GET".to_owned(),
                path: binding.path.replace("{proposal_id}", id),
                access_profile: binding.profile.clone(),
                operation: "get".to_owned(),
                if_match: None,
                availability: None,
            };
            let observation = self.proposal_observation_exchange(&link).await;
            retry_after = observation.retry_after;
            let response = observation.outcome?;
            let proposal = BRegProposal::from_slice(response.value.as_bytes())?;
            if proposal.id != id {
                return Err(refusal());
            }
            Ok(BRegComplete {
                value: proposal.bind_profile(self.source_binding(), &binding.profile)?,
                metadata: response.metadata,
            })
        }
        .await;
        BRegObservation {
            outcome,
            retry_after,
        }
    }
    pub async fn read_proposal_review_status(
        &self,
        proposal: &BRegProposal,
    ) -> Result<BRegComplete<BRegProposalReviewDocument>, BaseRegistryClientError> {
        self.read_proposal_review(proposal, "reviewStatus").await
    }
    pub async fn read_proposal_review_context(
        &self,
        proposal: &BRegProposal,
    ) -> Result<BRegComplete<BRegProposalReviewDocument>, BaseRegistryClientError> {
        self.read_proposal_review(proposal, "reviewContext").await
    }
    async fn read_proposal_review(
        &self,
        proposal: &BRegProposal,
        operation: &str,
    ) -> Result<BRegComplete<BRegProposalReviewDocument>, BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str()) {
            return Err(refusal());
        }
        let link = proposal.links.get(operation).ok_or_else(refusal)?;
        let response = self.proposal_exchange(link, None, None).await?;
        let value =
            crate::strict_json::from_slice(response.value.as_bytes()).map_err(|_| refusal())?;
        let document: BRegProposalReviewDocument =
            serde_json::from_value(value).map_err(|_| refusal())?;
        if document.id != proposal.id
            || document.action_id != proposal.action_id
            || document.action_revision != proposal.action_revision
            || document.submission_version != proposal.submission_version
            || document.revision < proposal.revision
            || !digest(&document.effect_digest)
            || proposal
                .effect_digest
                .as_deref()
                .is_some_and(|digest| digest != document.effect_digest)
            || document.subject.subject_type != "proposal"
            || document.subject.id != proposal.id
            || document.subject.version != proposal.submission_version.to_string()
            || document.subject.digest != document.effect_digest
            || document.subject.source.is_empty()
            || document.subject.source.len() > 512
            || document.context.reference.is_empty()
            || document.context.reference.len() > 2048
            || document.context.contract.as_ref().is_some_and(|contract| {
                !contract.id.starts_with("urn:registry:breg:review-context:")
                    || contract.id.len() > 2048
                    || contract.id.chars().any(char::is_control)
                    || !digest(&contract.revision)
                    || !digest(&contract.schema_digest)
            })
            || document.authority.is_some() != document.policy.is_some()
            || document
                .policy
                .as_ref()
                .is_some_and(|policy| policy.check().is_err())
            || !valid_review_projection(&document, operation == "reviewContext")
        {
            return Err(refusal());
        }
        Ok(BRegComplete {
            value: document,
            metadata: response.metadata,
        })
    }
    fn proposal_slot<'a>(
        &self,
        proposal: &'a BRegProposal,
        slot: &str,
        operation: &str,
    ) -> Result<(&'a BRegProposalAttachment, &'a BRegProposalLink), BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str()) {
            return Err(refusal());
        }
        let slot = proposal.attachments.get(slot).ok_or_else(refusal)?;
        let link = slot
            .links
            .get(operation)
            .filter(|link| {
                link.availability
                    .as_ref()
                    .is_none_or(|availability| availability.available)
            })
            .ok_or_else(refusal)?;
        Ok((slot, link))
    }
    pub async fn download_proposal_attachment(
        &self,
        proposal: &BRegProposal,
        slot: &str,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        let (slot, link) = self.proposal_slot(proposal, slot, "download")?;
        // Retained bytes may predate a narrower current upload policy.
        let maximum_bytes = slot
            .value
            .as_ref()
            .map_or(slot.maximum_bytes, |value| value.byte_size);
        self.proposal_attachment_exchange(link, None, None, None, maximum_bytes)
            .await
    }
    pub async fn upload_proposal_attachment(
        &self,
        proposal: &BRegProposal,
        slot: &str,
        content_type: &str,
        bytes: &[u8],
        key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        let (slot, link) = self.proposal_slot(proposal, slot, "upload")?;
        if bytes.is_empty()
            || bytes.len() as u64 > slot.maximum_bytes
            || !slot
                .content_types
                .iter()
                .any(|accepted| accepted == content_type)
        {
            return Err(refusal());
        }
        let response = self
            .proposal_attachment_exchange(
                link,
                Some(bytes.to_vec()),
                Some(content_type),
                Some(key),
                slot.maximum_bytes,
            )
            .await?;
        self.proposal_attachment_response(proposal, link, response)
    }
    pub async fn delete_proposal_attachment(
        &self,
        proposal: &BRegProposal,
        slot: &str,
        key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        let (slot, link) = self.proposal_slot(proposal, slot, "remove")?;
        let response = self
            .proposal_attachment_exchange(link, None, None, Some(key), slot.maximum_bytes)
            .await?;
        self.proposal_attachment_response(proposal, link, response)
    }
    fn proposal_attachment_response(
        &self,
        prior: &BRegProposal,
        link: &BRegProposalLink,
        response: BRegComplete<BRegRawDocument>,
    ) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        let current = BRegProposal::from_slice(response.value.as_bytes())?;
        if current.id != prior.id
            || current.action_id != prior.action_id
            || current.action_revision != prior.action_revision
            || !transition_progress(
                "edit",
                prior.state,
                prior.submission_version,
                prior.revision,
                &current,
            )
        {
            return Err(refusal());
        }
        Ok(BRegComplete {
            value: current.bind_profile(self.source_binding(), &link.access_profile)?,
            metadata: response.metadata,
        })
    }
    /// List one bounded, explicitly authorized page. No automatic continuation.
    pub async fn list_proposals(
        &self,
        collection: &BRegProposalCollection,
        query: &BRegProposalQuery,
    ) -> Result<BRegComplete<BRegProposalPage>, BaseRegistryClientError> {
        if collection.source != self.source_binding()
            || query.top.is_some_and(|top| !(1..=100).contains(&top))
            || query
                .action
                .as_ref()
                .is_some_and(|action| !identifier(action))
            || query
                .target
                .as_ref()
                .is_some_and(|target| Uuid::parse_str(target).is_err())
            || query
                .cursor
                .as_ref()
                .is_some_and(|cursor| !valid_cursor(cursor))
        {
            return Err(refusal());
        }
        let mut pairs = vec![("accessProfile".to_owned(), collection.profile.clone())];
        if let Some(action) = &query.action {
            pairs.push(("action".to_owned(), action.clone()));
        }
        if query.owner_is_caller {
            pairs.push(("owner".to_owned(), "caller".to_owned()));
        }
        if let Some(target) = &query.target {
            pairs.push(("target".to_owned(), target.clone()));
        }
        if let Some(state) = query.state {
            pairs.push((
                "state".to_owned(),
                serde_json::to_value(state)
                    .map_err(|_| refusal())?
                    .as_str()
                    .ok_or_else(refusal)?
                    .to_owned(),
            ));
        }
        if let Some(cursor) = &query.cursor {
            pairs.push(("cursor".to_owned(), cursor.clone()));
        }
        if let Some(top) = query.top {
            pairs.push(("top".to_owned(), top.to_string()));
        }
        let response = self
            .proposal_list_exchange(&collection.path, &pairs)
            .await?;
        let value =
            crate::strict_json::from_slice(response.value.as_bytes()).map_err(|_| refusal())?;
        let mut page: BRegProposalPage = serde_json::from_value(value).map_err(|_| refusal())?;
        if page.items.len() > query.top.unwrap_or(50) as usize
            || page
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| !valid_cursor(cursor))
        {
            return Err(refusal());
        }
        for item in &mut page.items {
            item.validate()?;
            if query
                .action
                .as_ref()
                .is_some_and(|action| action != &item.action_id)
                || query.state.is_some_and(|state| state != item.state)
            {
                return Err(refusal());
            }
            if item
                .links
                .values()
                .chain(
                    item.attachments
                        .values()
                        .flat_map(|slot| slot.links.values()),
                )
                .any(|link| link.access_profile != collection.profile)
            {
                return Err(refusal());
            }
            item.source = Some(self.source_binding());
        }
        Ok(BRegComplete {
            value: page,
            metadata: response.metadata,
        })
    }
    /// Validate and bind a promoted transition without I/O or Evidence acquisition.
    pub fn prepare_proposal(
        &self,
        proposal: &BRegProposal,
        operation: &str,
        body: Value,
        key: &BRegIdempotencyKey,
    ) -> Result<BRegPreparedProposal, BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str()) {
            return Err(refusal());
        }
        let link = proposal
            .links
            .get(operation)
            .filter(|link| {
                link.method == "POST"
                    && link
                        .availability
                        .as_ref()
                        .is_none_or(|availability| availability.available)
            })
            .ok_or_else(refusal)?;
        validate_body(operation, &body)?;
        if operation == "apply"
            && (body["submissionVersion"].as_u64() != Some(u64::from(proposal.submission_version))
                || proposal
                    .effect_digest
                    .as_deref()
                    .is_some_and(|digest| body["effectDigest"].as_str() != Some(digest)))
        {
            return Err(refusal());
        }
        let evidence = PreparedEvidence {
            version: 2,
            source: self.source_binding(),
            proposal_id: proposal.id.clone(),
            action_id: proposal.action_id.clone(),
            action_revision: proposal.action_revision.clone(),
            submission_version: proposal.submission_version,
            revision: proposal.revision,
            state: proposal.state,
            link: link.clone(),
            body: serde_json::to_string(&body).map_err(|_| refusal())?,
            key: key.as_str().to_owned(),
        };
        let mut attempt = BRegPreparedProposal::from_slice(
            &serde_json::to_vec(&evidence).map_err(|_| refusal())?,
        )?;
        attempt.executable = true;
        Ok(attempt)
    }
    /// Execute the exact prepared transition; its response is another bound Proposal.
    pub async fn execute_proposal(
        &self,
        attempt: &BRegPreparedProposal,
    ) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        let evidence = attempt.decode()?;
        if !attempt.executable || evidence.source != self.source_binding() {
            return Err(refusal());
        }
        let key = BRegIdempotencyKey::parse(&evidence.key).map_err(|_| refusal())?;
        let response = self
            .proposal_exchange(
                &evidence.link,
                Some(evidence.body.as_bytes().to_vec()),
                Some(&key),
            )
            .await?;
        let proposal = BRegProposal::from_slice(response.value.as_bytes())?;
        if !transition_successor(&evidence, &proposal) {
            return Err(refusal());
        }
        Ok(BRegComplete {
            value: proposal.bind_profile(self.source_binding(), &evidence.link.access_profile)?,
            metadata: response.metadata,
        })
    }
    /// Explicitly read one server-promoted resource link. No linked resource is followed automatically.
    pub async fn read_proposal(
        &self,
        proposal: &BRegProposal,
    ) -> Result<BRegComplete<BRegProposal>, BaseRegistryClientError> {
        if proposal.source.as_deref() != Some(self.source_binding().as_str()) {
            return Err(refusal());
        }
        let link = proposal.links.get("self").ok_or_else(refusal)?;
        let response = self.proposal_exchange(link, None, None).await?;
        let current = BRegProposal::from_slice(response.value.as_bytes())?;
        if current.id != proposal.id
            || current.action_id != proposal.action_id
            || current.revision < proposal.revision
        {
            return Err(refusal());
        }
        Ok(BRegComplete {
            value: current.bind_profile(self.source_binding(), &link.access_profile)?,
            metadata: response.metadata,
        })
    }
    /// Revalidate saved evidence against a current authorized resource, retaining the original bytes.
    pub fn recover_proposal(
        &self,
        current: &BRegProposal,
        attempt: &BRegPreparedProposal,
    ) -> Result<BRegPreparedProposal, BaseRegistryClientError> {
        let evidence = attempt.decode()?;
        let successor = transition_successor(&evidence, current);
        let same_version = evidence.submission_version == current.submission_version;
        let advanced_draft =
            matches!(evidence.link.operation.as_str(), "revise" | "rebase") && successor;
        let rebased_draft = evidence.link.operation == "rebase" && successor;
        if current.source.as_deref() != Some(self.source_binding().as_str())
            || evidence.source != self.source_binding()
            || evidence.proposal_id != current.id
            || evidence.action_id != current.action_id
            || current.revision < evidence.revision
            || evidence.action_revision != current.action_revision && !rebased_draft
            || !(same_version || advanced_draft)
            || !current.links.values().any(|link| {
                link.path == evidence.link.path
                    && link.method == evidence.link.method
                    && link.access_profile == evidence.link.access_profile
                    && link.operation == evidence.link.operation
                    && (link == &evidence.link
                        || successor
                            && link
                                .availability
                                .as_ref()
                                .is_some_and(|availability| availability.available)
                        || link.availability.as_ref().is_some_and(|availability| {
                            availability.recovery == Some(BRegRecoveryHint::ReceiptOnly)
                        }))
            })
        {
            return Err(refusal());
        }
        let mut recovered = BRegPreparedProposal::from_slice(attempt.as_bytes())?;
        recovered.executable = true;
        Ok(recovered)
    }
}
// Mutation receipts describe this one transition, including on a same-key replay.
// A current read may have advanced further and is checked separately during recovery.
fn transition_successor(evidence: &PreparedEvidence, current: &BRegProposal) -> bool {
    let operation = evidence.link.operation.as_str();
    current.id == evidence.proposal_id
        && current.action_id == evidence.action_id
        && (current.action_revision == evidence.action_revision || operation == "rebase")
        && transition_progress(
            operation,
            evidence.state,
            evidence.submission_version,
            evidence.revision,
            current,
        )
        && (operation != "apply"
            || crate::strict_json::from_slice(evidence.body.as_bytes()).is_ok_and(|body| {
                body["effectDigest"].as_str() == current.effect_digest.as_deref()
            }))
}
fn transition_progress(
    operation: &str,
    prior_state: BRegProposalState,
    prior_version: u32,
    prior_revision: u64,
    current: &BRegProposal,
) -> bool {
    use BRegProposalState::{Applied, Cancelled, Draft, Submitted};
    let (state, version) = match (operation, prior_state) {
        ("edit", Draft) | ("rebase", Draft) => (Draft, Some(prior_version)),
        ("submit", Draft) | ("retry", Submitted) => (Submitted, Some(prior_version)),
        ("revise" | "rebase", Submitted) => (Draft, prior_version.checked_add(1)),
        ("cancel", Draft | Submitted) => (Cancelled, Some(prior_version)),
        ("apply", Submitted) => (Applied, Some(prior_version)),
        _ => return false,
    };
    prior_revision.checked_add(1) == Some(current.revision)
        && current.state == state
        && version == Some(current.submission_version)
}
fn valid_review_projection(document: &BRegProposalReviewDocument, is_context: bool) -> bool {
    if is_context {
        document.context.contract.is_some()
            && document.context.fields.is_some()
            && document.result.is_none()
            && document.request_id.is_none()
    } else {
        document.context.fields.is_none()
            && document.request_id.as_deref().is_none_or(|id| {
                document.policy.is_some()
                    && Uuid::parse_str(id)
                        .is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == id)
            })
            && document.result.is_some() == document.policy.is_some()
            && document.result.as_ref().is_none_or(valid_review_result)
    }
}
fn valid_review_result(result: &BRegProposalReviewResult) -> bool {
    if result.state == "pending" {
        return result.result_id.is_none()
            && result.completed_at.is_none()
            && result.available_until.is_none();
    }
    // Expiry changes only the public state of retained terminal evidence.
    // As in the shared Review result contract, retention must follow completion;
    // the client does not reinterpret the server's state using its own clock.
    matches!(
        result.state.as_str(),
        "approved"
            | "rejected"
            | "changes-requested"
            | "answered"
            | "cancelled"
            | "superseded"
            | "expired"
    ) && result
        .result_id
        .as_deref()
        .is_some_and(|id| Uuid::parse_str(id).is_ok_and(|id| !id.is_nil()))
        && result
            .completed_at
            .as_deref()
            .and_then(proposal_instant)
            .is_some_and(|completed| {
                result
                    .available_until
                    .as_deref()
                    .and_then(proposal_instant)
                    .is_some_and(|until| until > completed)
            })
}
fn proposal_instant(value: &str) -> Option<OffsetDateTime> {
    (value.len() <= 64)
        .then(|| OffsetDateTime::parse(value, &Rfc3339).ok())
        .flatten()
}
fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= 512
        && cursor.bytes().all(|byte| (33..=126).contains(&byte))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
fn valid_condition(etag: Option<&str>) -> bool {
    etag.is_some_and(|etag| {
        etag.len() >= 3
            && etag.len() <= 256
            && etag.starts_with('"')
            && etag.ends_with('"')
            && !etag[1..etag.len() - 1]
                .bytes()
                .any(|byte| byte <= 32 || byte >= 127 || byte == b'"')
    })
}
fn validate_body(operation: &str, body: &Value) -> Result<(), BaseRegistryClientError> {
    let object = body.as_object().ok_or_else(refusal)?;
    let valid = match operation {
        "submit" | "cancel" | "retry" => object.is_empty(),
        "edit" | "rebase" => object.len() == 1 && object.get("input").is_some_and(Value::is_object),
        "revise" => {
            object.is_empty()
                || object.len() == 1 && object.get("input").is_some_and(Value::is_object)
        }
        "apply" => {
            object.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "submissionVersion" | "effectDigest" | "reason"
                )
            }) && object
                .get("submissionVersion")
                .and_then(Value::as_u64)
                .is_some_and(|version| version > 0 && version <= u64::from(u32::MAX))
                && object
                    .get("effectDigest")
                    .and_then(Value::as_str)
                    .is_some_and(digest)
                && object.get("reason").is_none_or(|value| {
                    value.as_str().is_some_and(|reason| {
                        !reason.contains('\0') && reason.chars().count() <= 4096
                    })
                })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(refusal())
    }
}
fn validate_link(link: &BRegProposalLink) -> Result<(), BaseRegistryClientError> {
    if !matches!(link.method.as_str(), "GET" | "POST")
        || !link.path.starts_with("/v1/")
        || link.path.len() > 2048
        || link.path.contains(['?', '#', '%', '\\'])
        || link
            .path
            .split('/')
            .skip(1)
            .any(|segment| !identifier(segment) || matches!(segment, "." | ".."))
        || !identifier(&link.access_profile)
        || !identifier(&link.operation)
        || link.method == "POST" && !valid_condition(link.if_match.as_deref())
    {
        return Err(refusal());
    }
    Ok(())
}
fn refusal() -> BaseRegistryClientError {
    BaseRegistryClientError::invalid_request(
        "the Base Registry Engine Proposal contract or attempt is invalid",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const REVISION: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID: &str = "00000000-0000-4000-8000-000000000001";

    async fn proposal_response_client(
        initial: Value,
    ) -> (
        BaseRegistryClient,
        std::sync::Arc<std::sync::Mutex<Value>>,
        tokio::task::JoinHandle<()>,
    ) {
        use axum::{extract::State, routing::any, Json, Router};
        use std::sync::{Arc, Mutex};
        let response = Arc::new(Mutex::new(initial));
        let app = Router::new()
            .fallback(any(|State(value): State<Arc<Mutex<Value>>>| async move {
                (
                    [
                        (
                            "traceparent",
                            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                        ),
                        ("cache-control", "no-store"),
                        ("vary", "authorization, accept"),
                    ],
                    Json(value.lock().unwrap().clone()),
                )
            }))
            .with_state(response.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (client(&format!("http://{address}/")), response, server)
    }

    fn transition_document(operation: &str, state: &str, version: u32, revision: u64) -> Value {
        let mut value = document();
        value["state"] = json!(state);
        value["submissionVersion"] = json!(version);
        value["revision"] = json!(revision);
        if state == "draft" {
            value.as_object_mut().unwrap().remove("effectDigest");
        } else if state == "applied" {
            value["application"] = json!({"applicationId":ID,"submissionVersion":version,
                "effectDigest":REVISION,"resultLinks":[]});
        }
        let mut link = value["links"]["apply"].clone();
        link["path"] = json!(format!("/v1/proposals/{ID}/{operation}"));
        link["operation"] = json!(operation);
        link["availability"]["observedRevision"] = json!(revision);
        value["links"] = json!({operation:link});
        value
    }

    #[tokio::test]
    async fn transition_receipts_refuse_the_unchanged_proposal() {
        let original = transition_document("submit", "draft", 1, 2);
        let (client, _, server) = proposal_response_client(original.clone()).await;
        let prior = proposal(&client, original);
        let attempt = client
            .prepare_proposal(
                &prior,
                "submit",
                json!({}),
                &BRegIdempotencyKey::parse("unchanged-submit").unwrap(),
            )
            .unwrap();
        assert!(client.execute_proposal(&attempt).await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn proposal_reads_refuse_a_revision_older_than_the_held_proposal() {
        let mut older = document();
        older["revision"] = json!(1);
        older["links"]["apply"]["availability"]["observedRevision"] = json!(1);
        let (client, response, server) = proposal_response_client(older).await;
        let prior = proposal(&client, document());
        assert!(client.read_proposal(&prior).await.is_err());
        for (revision, state, version) in [(2, "submitted", 1), (3, "applied", 1), (5, "draft", 2)]
        {
            let mut current = document();
            current["revision"] = json!(revision);
            current["state"] = json!(state);
            if state == "draft" {
                current.as_object_mut().unwrap().remove("effectDigest");
            } else if state == "applied" {
                current["application"] = json!({"applicationId":ID,"submissionVersion":version,
                    "effectDigest":REVISION,"resultLinks":[]});
            }
            current["submissionVersion"] = json!(version);
            current["links"]["apply"]["availability"]["observedRevision"] = json!(revision);
            if version == 2 {
                current["actionRevision"] = json!(format!("sha256:{}", "b".repeat(64)));
            }
            *response.lock().unwrap() = current.clone();
            assert_eq!(
                serde_json::to_value(client.read_proposal(&prior).await.unwrap().value).unwrap(),
                current
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn transition_receipts_require_exact_progress_and_allow_exact_replay() {
        let (client, response, server) = proposal_response_client(json!({})).await;
        for (operation, before, after, version, body) in [
            ("edit", "draft", "draft", 1, json!({"input":{}})),
            ("submit", "draft", "submitted", 1, json!({})),
            ("revise", "submitted", "draft", 2, json!({})),
            ("rebase", "draft", "draft", 1, json!({"input":{}})),
            ("rebase", "submitted", "draft", 2, json!({"input":{}})),
            ("retry", "submitted", "submitted", 1, json!({})),
            ("cancel", "draft", "cancelled", 1, json!({})),
            ("cancel", "submitted", "cancelled", 1, json!({})),
            (
                "apply",
                "submitted",
                "applied",
                1,
                json!({"submissionVersion":1,"effectDigest":REVISION}),
            ),
        ] {
            // Availability is optional. The held Proposal supplies the original revision/state.
            let mut original = transition_document(operation, before, 1, 2);
            original["links"][operation]
                .as_object_mut()
                .unwrap()
                .remove("availability");
            let prior = proposal(&client, original.clone());
            let prepared = client
                .prepare_proposal(
                    &prior,
                    operation,
                    body,
                    &BRegIdempotencyKey::parse("exact-transition").unwrap(),
                )
                .unwrap();
            let restored = BRegPreparedProposal::from_slice(prepared.as_bytes()).unwrap();
            let attempt = client.recover_proposal(&prior, &restored).unwrap();
            assert_eq!(attempt.as_bytes(), prepared.as_bytes());
            let receipt = transition_document(operation, after, version, 3);
            *response.lock().unwrap() = receipt.clone();
            for _ in 0..2 {
                let value = client.execute_proposal(&attempt).await.unwrap().value;
                assert_eq!(
                    serde_json::to_value(value).unwrap(),
                    receipt,
                    "{operation}:{before}"
                );
            }
            for (field, value) in [
                ("revision", json!(2)),
                ("revision", json!(4)),
                ("submissionVersion", json!(if version == 1 { 2 } else { 1 })),
                (
                    "state",
                    json!(if after == "draft" {
                        "submitted"
                    } else {
                        "draft"
                    }),
                ),
            ] {
                let mut invalid = receipt.clone();
                invalid[field] = value;
                invalid["links"][operation]["availability"]["observedRevision"] =
                    invalid["revision"].clone();
                *response.lock().unwrap() = invalid;
                assert!(
                    client.execute_proposal(&attempt).await.is_err(),
                    "{operation}:{before}:{field}"
                );
            }
            if operation == "apply" {
                for effect in [Value::Null, json!(format!("sha256:{}", "b".repeat(64)))] {
                    let mut invalid = receipt.clone();
                    invalid["effectDigest"] = effect;
                    *response.lock().unwrap() = invalid;
                    assert!(client.execute_proposal(&attempt).await.is_err());
                }
            }
            let mut rollback = original;
            rollback["revision"] = json!(1);
            rollback["links"][operation]["availability"] = json!({"available":false,"observedRevision":1,
                "reason":"stale-revision","recovery":"receipt-only"});
            assert!(client
                .recover_proposal(&proposal(&client, rollback), &restored)
                .is_err());
        }
        server.abort();
    }

    #[tokio::test]
    async fn receipt_recovery_after_later_reads_replays_the_original_successor() {
        let original = transition_document("submit", "draft", 1, 2);
        let (client, response, server) = proposal_response_client(json!({})).await;
        let prior = proposal(&client, original);
        let attempt = client
            .prepare_proposal(
                &prior,
                "submit",
                json!({}),
                &BRegIdempotencyKey::parse("lost-submit-response").unwrap(),
            )
            .unwrap();
        let saved = BRegPreparedProposal::from_slice(attempt.as_bytes()).unwrap();
        let mut later = transition_document("submit", "applied", 1, 4);
        later["links"]["submit"]["availability"] = json!({"available":false,"observedRevision":4,
            "reason":"already-applied","recovery":"receipt-only"});
        let recovered = client
            .recover_proposal(&proposal(&client, later.clone()), &saved)
            .unwrap();
        assert_eq!(recovered.as_bytes(), saved.as_bytes());
        let receipt = transition_document("submit", "submitted", 1, 3);
        *response.lock().unwrap() = receipt.clone();
        assert_eq!(
            serde_json::to_value(client.execute_proposal(&recovered).await.unwrap().value).unwrap(),
            receipt
        );
        *response.lock().unwrap() = later;
        assert!(client.execute_proposal(&recovered).await.is_err());
        server.abort();
    }

    #[test]
    fn prepared_proposals_require_the_original_state_and_revision() {
        let client = client("https://registry.example/");
        let prior = proposal(&client, transition_document("submit", "draft", 1, 2));
        let attempt = client
            .prepare_proposal(
                &prior,
                "submit",
                json!({}),
                &BRegIdempotencyKey::parse("bound-transition").unwrap(),
            )
            .unwrap();
        let evidence: Value = serde_json::from_slice(attempt.as_bytes()).unwrap();
        assert_eq!(evidence["version"], json!(2));
        assert_eq!(evidence["state"], json!("draft"));
        assert_eq!(evidence["revision"], json!(2));
        for field in ["state", "revision"] {
            let mut invalid = evidence.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(
                BRegPreparedProposal::from_slice(&serde_json::to_vec(&invalid).unwrap()).is_err()
            );
        }
        for (field, value) in [
            ("version", json!(1)),
            ("revision", json!(0)),
            ("revision", json!(3)),
        ] {
            let mut invalid = evidence.clone();
            invalid[field] = value;
            assert!(
                BRegPreparedProposal::from_slice(&serde_json::to_vec(&invalid).unwrap()).is_err()
            );
        }
    }

    #[tokio::test]
    async fn transition_receipts_refuse_revision_and_submission_overflow() {
        let (client, response, server) = proposal_response_client(json!({})).await;
        for (operation, state, version, revision, body) in [
            ("submit", "draft", 1, u64::MAX, json!({})),
            ("revise", "submitted", u32::MAX, 2, json!({})),
            ("rebase", "submitted", u32::MAX, 2, json!({"input":{}})),
        ] {
            let prior = proposal(
                &client,
                transition_document(operation, state, version, revision),
            );
            let attempt = client
                .prepare_proposal(
                    &prior,
                    operation,
                    body,
                    &BRegIdempotencyKey::parse("overflow-transition").unwrap(),
                )
                .unwrap();
            *response.lock().unwrap() = transition_document(
                operation,
                if operation == "submit" {
                    "submitted"
                } else {
                    "draft"
                },
                version,
                if revision == u64::MAX { 1 } else { 3 },
            );
            assert!(
                client.execute_proposal(&attempt).await.is_err(),
                "{operation}"
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn transition_responses_refuse_changed_action_revisions_without_rebase() {
        let (client, response, server) = proposal_response_client(json!({})).await;
        for (operation, before, after, body) in [
            ("edit", "draft", "draft", json!({"input":{}})),
            ("submit", "draft", "submitted", json!({})),
            ("revise", "submitted", "draft", json!({})),
            ("cancel", "submitted", "cancelled", json!({})),
            ("retry", "submitted", "submitted", json!({})),
            (
                "apply",
                "submitted",
                "applied",
                json!({"submissionVersion":1,"effectDigest":REVISION}),
            ),
        ] {
            let prior = proposal(&client, transition_document(operation, before, 1, 2));
            let attempt = client
                .prepare_proposal(
                    &prior,
                    operation,
                    body,
                    &BRegIdempotencyKey::parse("transition-binding").unwrap(),
                )
                .unwrap();
            let current = transition_document(
                operation,
                after,
                if operation == "revise" { 2 } else { 1 },
                3,
            );
            *response.lock().unwrap() = current.clone();
            assert!(
                client.execute_proposal(&attempt).await.is_ok(),
                "{operation}"
            );
            let mut changed = current;
            changed["actionRevision"] = json!(format!("sha256:{}", "b".repeat(64)));
            *response.lock().unwrap() = changed;
            assert!(
                client.execute_proposal(&attempt).await.is_err(),
                "{operation} accepted a changed Action revision"
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn rebase_receipts_recover_changed_action_revisions_for_draft_and_submitted_work() {
        let (client, response, server) = proposal_response_client(json!({})).await;
        for (state, before, after) in [("draft", 1, 1), ("draft", 2, 2), ("submitted", 1, 2)] {
            let prior = proposal(&client, transition_document("rebase", state, before, 2));
            let attempt = client
                .prepare_proposal(
                    &prior,
                    "rebase",
                    json!({"input":{}}),
                    &BRegIdempotencyKey::parse("rebase-binding").unwrap(),
                )
                .unwrap();
            let mut current = transition_document("rebase", "draft", after, 3);
            current["actionRevision"] = json!(format!("sha256:{}", "b".repeat(64)));
            *response.lock().unwrap() = current.clone();
            let rebased = client.execute_proposal(&attempt).await.unwrap().value;
            assert_eq!(
                client
                    .recover_proposal(&rebased, &attempt)
                    .unwrap()
                    .as_bytes(),
                attempt.as_bytes()
            );
            for (field, value) in [
                ("revision", json!(4)),
                ("submissionVersion", json!(after + 2)),
                ("state", json!("submitted")),
            ] {
                let mut unrelated = current.clone();
                unrelated[field] = value;
                if field == "state" {
                    unrelated["effectDigest"] = json!(REVISION);
                }
                if field == "revision" {
                    unrelated["links"]["rebase"]["availability"]["observedRevision"] = json!(4);
                }
                *response.lock().unwrap() = unrelated.clone();
                assert!(
                    client.execute_proposal(&attempt).await.is_err(),
                    "execute:{state}:{field}"
                );
                assert!(
                    client
                        .recover_proposal(&proposal(&client, unrelated), &attempt)
                        .is_err(),
                    "{state}:{field}"
                );
            }
        }
        server.abort();
    }

    #[tokio::test]
    async fn proposal_start_refuses_later_states_but_accepts_exact_draft_replay() {
        let fixture: Value =
            serde_json::from_slice(include_bytes!("../tests/fixtures/attachments.json")).unwrap();
        let original = fixture["proposal"].clone();
        let (client, response, server) = proposal_response_client(original.clone()).await;
        let action =
            crate::BRegMetadata::from_slice(&serde_json::to_vec(&fixture["metadata"]).unwrap())
                .unwrap()
                .bind_source(client.source_binding())
                .select_action("correct", "writer")
                .unwrap();
        let request =
            crate::BRegActionInvocationRequest::new(&action, serde_json::Map::new(), None).unwrap();
        let key = BRegIdempotencyKey::parse("exact-start-replay").unwrap();
        for _ in 0..2 {
            let started = client
                .start_proposal(&action, &request, &key)
                .await
                .unwrap();
            assert_eq!(started.value.state(), BRegProposalState::Draft);
            assert_eq!(serde_json::to_value(started.value).unwrap(), original);
        }
        for state in ["submitted", "applied", "cancelled"] {
            let mut later = original.clone();
            later["state"] = json!(state);
            if state == "applied" {
                later["effectDigest"] = json!(REVISION);
                later["application"] = json!({"applicationId":ID,
                    "submissionVersion":2,"effectDigest":REVISION,"resultLinks":[]});
            }
            *response.lock().unwrap() = later;
            assert!(
                client
                    .start_proposal(&action, &request, &key)
                    .await
                    .is_err(),
                "Start accepted {state} work"
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn attachment_receipts_refuse_the_unchanged_proposal() {
        let fixture: Value =
            serde_json::from_slice(include_bytes!("../tests/fixtures/attachments.json")).unwrap();
        let original = fixture["proposal"].clone();
        let (client, _, server) = proposal_response_client(original.clone()).await;
        let prior = proposal(&client, original);
        let key = BRegIdempotencyKey::parse("unchanged-attachment").unwrap();
        let upload = client
            .upload_proposal_attachment(&prior, "supporting-file", "application/pdf", b"%PDF", &key)
            .await;
        let remove = client
            .delete_proposal_attachment(&prior, "supporting-file", &key)
            .await;
        assert_eq!([upload.is_err(), remove.is_err()], [true, true]);
        server.abort();
    }

    #[tokio::test]
    async fn attachment_mutation_responses_preserve_the_action_revision() {
        let fixture: Value =
            serde_json::from_slice(include_bytes!("../tests/fixtures/attachments.json")).unwrap();
        let original = fixture["proposal"].clone();
        let mut current = original.clone();
        current["revision"] = json!(4);
        let (client, response, server) = proposal_response_client(current.clone()).await;
        let prior = proposal(&client, original);
        let key = BRegIdempotencyKey::parse("attachment-binding").unwrap();
        assert!(client
            .upload_proposal_attachment(&prior, "supporting-file", "application/pdf", b"%PDF", &key)
            .await
            .is_ok());
        assert!(client
            .delete_proposal_attachment(&prior, "supporting-file", &key)
            .await
            .is_ok());
        for (field, value) in [
            (
                "actionRevision",
                json!(format!("sha256:{}", "b".repeat(64))),
            ),
            ("revision", json!(3)),
            ("revision", json!(5)),
            ("state", json!("submitted")),
            ("submissionVersion", json!(3)),
        ] {
            let mut changed = current.clone();
            changed[field] = value;
            // Keep this response independently valid so receipt correlation makes the refusal.
            changed["attachments"] = json!({});
            *response.lock().unwrap() = changed;
            assert!(
                client
                    .upload_proposal_attachment(
                        &prior,
                        "supporting-file",
                        "application/pdf",
                        b"%PDF",
                        &key
                    )
                    .await
                    .is_err(),
                "upload:{field}"
            );
            assert!(
                client
                    .delete_proposal_attachment(&prior, "supporting-file", &key)
                    .await
                    .is_err(),
                "remove:{field}"
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn proposal_list_refuses_unusable_response_cursors() {
        let (client, response, server) = proposal_response_client(json!({"items":[]})).await;
        let collection = BRegProposalCollection::from_metadata(
            &json!({"method":"GET","path":"/v1/proposals","accessProfiles":["author"]}),
            &client.source_binding(),
            REVISION,
            "author",
        )
        .unwrap();
        for cursor in [
            "".to_owned(),
            " ".to_owned(),
            "cursor\nvalue".to_owned(),
            "cursor\tvalue".to_owned(),
            "é".to_owned(),
            "x".repeat(513),
        ] {
            *response.lock().unwrap() = json!({"items":[],"nextCursor":cursor});
            assert!(
                client
                    .list_proposals(&collection, &BRegProposalQuery::default())
                    .await
                    .is_err(),
                "accepted unusable cursor"
            );
        }
        for cursor in [ID.to_owned(), "x".repeat(512)] {
            *response.lock().unwrap() = json!({"items":[],"nextCursor":cursor});
            let page = client
                .list_proposals(&collection, &BRegProposalQuery::default())
                .await
                .unwrap()
                .value;
            assert!(client
                .list_proposals(
                    &collection,
                    &BRegProposalQuery {
                        cursor: page.next_cursor,
                        ..Default::default()
                    }
                )
                .await
                .is_ok());
        }
        server.abort();
    }

    #[tokio::test]
    async fn promoted_review_status_refuses_display_fields_like_uuid_status_reads() {
        let valid = json!({"id":ID,"actionId":"correct-address","actionRevision":REVISION,
            "submissionVersion":1,"revision":2,"effectDigest":REVISION,
            "subject":{"source":"directory","subjectType":"proposal","id":ID,"version":"1","digest":REVISION},
            "context":{"reference":"breg:directory:correct-address:proposal:1"},"reviewable":true});
        let (client, response, server) = proposal_response_client(valid.clone()).await;
        let mut prior = document();
        prior["links"]["reviewStatus"] = json!({"method":"GET","path":format!("/v1/proposals/{ID}/review-status"),"accessProfile":"author","operation":"get-review-status"});
        let prior = proposal(&client, prior);
        let binding=BRegProposalReviewBinding::from_metadata(
            &json!([{"actionId":"correct-address","accessProfile":"author","operations":["get-review-status"]}]),
            &client.source_binding(),"author","correct-address",true).unwrap();
        assert!(client.read_proposal_review_status(&prior).await.is_ok());
        let mut older = valid.clone();
        older["revision"] = json!(1);
        *response.lock().unwrap() = older;
        assert!(client.read_proposal_review_status(&prior).await.is_err());
        *response.lock().unwrap() = valid.clone();
        assert!(client
            .read_proposal_review_by_id(&binding, ID)
            .await
            .is_ok());
        for fields in [json!({}), json!({"private":"source value"})] {
            let mut changed = valid.clone();
            changed["context"]["fields"] = fields;
            *response.lock().unwrap() = changed;
            assert!(client
                .read_proposal_review_by_id(&binding, ID)
                .await
                .is_err());
            assert!(
                client.read_proposal_review_status(&prior).await.is_err(),
                "promoted status accepted display fields"
            );
        }
        server.abort();
    }
    #[tokio::test]
    async fn review_status_preserves_only_valid_accepted_request_correlation() {
        let valid = json!({"id":ID,"actionId":"correct-address","actionRevision":REVISION,
            "submissionVersion":1,"revision":2,"effectDigest":REVISION,
            "subject":{"source":"directory","subjectType":"proposal","id":ID,"version":"1","digest":REVISION},
            "context":{"reference":"breg:directory:correct-address:proposal:1"},"reviewable":true,
            "authority":"review","policy":{"id":"address-review"},"result":{"state":"pending"},"requestId":ID});
        let (client, response, server) = proposal_response_client(valid.clone()).await;
        let mut prior = document();
        prior["links"]["reviewStatus"] = json!({"method":"GET","path":format!("/v1/proposals/{ID}/review-status"),"accessProfile":"author","operation":"get-review-status"});
        let prior = proposal(&client, prior);
        let binding = BRegProposalReviewBinding::from_metadata(
            &json!([{"actionId":"correct-address","accessProfile":"author","operations":["get-review-status"]}]),
            &client.source_binding(), "author", "correct-address", true).unwrap();
        assert_eq!(
            client
                .read_proposal_review_status(&prior)
                .await
                .unwrap()
                .value
                .request_id
                .as_deref(),
            Some(ID)
        );
        assert_eq!(
            client
                .read_proposal_review_by_id(&binding, ID)
                .await
                .unwrap()
                .value
                .request_id
                .as_deref(),
            Some(ID)
        );
        let mut pending = valid.clone();
        pending.as_object_mut().unwrap().remove("requestId");
        *response.lock().unwrap() = pending;
        assert!(client
            .read_proposal_review_status(&prior)
            .await
            .unwrap()
            .value
            .request_id
            .is_none());
        for request_id in [
            json!(""),
            json!("not-a-request"),
            json!("00000000-0000-0000-0000-000000000000"),
            json!("00000000-0000-4000-8000-00000000000A"),
            json!(42),
        ] {
            let mut invalid = valid.clone();
            invalid["requestId"] = request_id;
            *response.lock().unwrap() = invalid;
            assert!(client.read_proposal_review_status(&prior).await.is_err());
            assert!(client
                .read_proposal_review_by_id(&binding, ID)
                .await
                .is_err());
        }
        let mut no_review = valid;
        for field in ["authority", "policy", "result"] {
            no_review.as_object_mut().unwrap().remove(field);
        }
        *response.lock().unwrap() = no_review;
        assert!(client.read_proposal_review_status(&prior).await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn review_context_exchange_requires_a_closed_producer_contract_binding() {
        use axum::{extract::State, routing::get, Json, Router};
        use std::sync::{Arc, Mutex};

        let valid = json!({"id":ID,"actionId":"correct-address","actionRevision":REVISION,
            "submissionVersion":1,"revision":2,"effectDigest":REVISION,
            "subject":{"source":"directory","subjectType":"proposal","id":ID,"version":"1","digest":REVISION},
            "context":{"reference":"breg:directory:correct-address:proposal:1",
                "contract":{"id":"urn:registry:breg:review-context:directory:correct-address:review-address",
                    "revision":REVISION,"schemaDigest":REVISION},"fields":{"proposedAddress":"Allowed"}},
            "reviewable":true});
        let response = Arc::new(Mutex::new(valid.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                &format!("/v1/proposals/{ID}/review-context"),
                get(|State(value): State<Arc<Mutex<Value>>>| async move {
                    (
                        [
                            (
                                "traceparent",
                                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                            ),
                            ("cache-control", "no-store"),
                            ("vary", "authorization, accept"),
                        ],
                        Json(value.lock().unwrap().clone()),
                    )
                }),
            )
            .with_state(response.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = client(&format!("http://{address}/"));
        let mut promoted = document();
        promoted["links"]["reviewContext"] = json!({"method":"GET",
            "path":format!("/v1/proposals/{ID}/review-context"),"accessProfile":"author","operation":"get-review-context"});
        let promoted = proposal(&client, promoted);
        let accepted = client
            .read_proposal_review_context(&promoted)
            .await
            .unwrap();
        assert_eq!(
            accepted.value.context.contract.unwrap().schema_digest,
            REVISION
        );
        let actions = json!([{"actionId":"correct-address","accessProfile":"author","operations":["get-review-context"]}]);
        let purpose = BRegProposalReviewBinding::from_metadata(
            &actions,
            &client.source_binding(),
            "author",
            "correct-address",
            false,
        )
        .unwrap();
        assert_eq!(
            client
                .read_proposal_review_by_id(&purpose, ID)
                .await
                .unwrap()
                .value
                .context
                .contract
                .unwrap()
                .schema_digest,
            REVISION
        );
        let mut refused = Vec::new();
        let mut status_correlation = valid.clone();
        status_correlation["requestId"] = json!(ID);
        refused.push(status_correlation);
        for field in ["id", "revision", "schemaDigest"] {
            let mut changed = valid.clone();
            changed["context"]["contract"][field] = json!("unbound-contract-canary");
            refused.push(changed);
        }
        for field in ["contract", "fields"] {
            let mut changed = valid.clone();
            changed["context"].as_object_mut().unwrap().remove(field);
            refused.push(changed);
        }
        for field in ["id", "revision", "schemaDigest"] {
            let mut changed = valid.clone();
            changed["context"]["contract"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            refused.push(changed);
        }
        for (field, malformed) in [
            ("contract", Value::Null),
            ("contract", json!([])),
            ("fields", Value::Null),
            ("fields", json!([])),
        ] {
            let mut changed = valid.clone();
            changed["context"][field] = malformed;
            refused.push(changed);
        }
        let mut widened_contract = valid.clone();
        widened_contract["context"]["contract"]["authority"] = json!("private-canary");
        refused.push(widened_contract);
        let mut missing_reference = valid.clone();
        missing_reference["context"]
            .as_object_mut()
            .unwrap()
            .remove("reference");
        refused.push(missing_reference);
        let mut old_local_id = valid.clone();
        old_local_id["context"]["id"] = json!("review-address");
        refused.push(old_local_id);
        for changed in refused {
            *response.lock().unwrap() = changed;
            assert!(client
                .read_proposal_review_context(&promoted)
                .await
                .is_err());
            assert!(client
                .read_proposal_review_by_id(&purpose, ID)
                .await
                .is_err());
        }
        server.abort();
    }

    fn application_status_document(state: &str, mode: &str) -> Value {
        let mut value = document();
        value["effectDigest"] = json!(REVISION);
        value["state"] = json!(match state {
            "applied" => "applied",
            "cancelled" => "cancelled",
            _ => "submitted",
        });
        let mut status = json!({"state":state,"mode":mode});
        if mode == "automatic" && matches!(state, "pending" | "applying" | "blocked") {
            status["automaticRetry"] = json!({"scheduled":state == "pending", "attempts":if state == "pending" { 0 } else { 1 }, "maximumAttempts":3});
        }
        if state == "blocked" {
            status["reason"] = json!("dependency-outage");
            status["recovery"] = json!("retry");
        }
        if state == "applied" {
            value["application"] = json!({"applicationId":ID,"submissionVersion":1,"effectDigest":REVISION,"resultLinks":[]});
        }
        value["applicationStatus"] = status;
        value
    }

    #[test]
    fn application_status_preserves_current_progress_and_retained_evidence_absence() {
        for (state, mode) in [
            ("pending", "automatic"),
            ("applying", "automatic"),
            ("blocked", "automatic"),
            ("pending", "manual"),
            ("applied", "automatic"),
            ("cancelled", "manual"),
        ] {
            let value = application_status_document(state, mode);
            let decoded = BRegProposal::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(
                serde_json::to_value(decoded.application_status().unwrap()).unwrap(),
                value["applicationStatus"],
                "{state}/{mode}"
            );
        }
        // A scheduled job has performed zero attempts initially. An exhausted
        // blocked job remains inspectable, but may not claim another attempt.
        let mut exhausted = application_status_document("blocked", "automatic");
        exhausted["applicationStatus"]["reason"] = json!("attempts-exhausted");
        exhausted["applicationStatus"]["recovery"] = json!("refresh");
        exhausted["applicationStatus"]["automaticRetry"]["attempts"] = json!(3);
        assert!(BRegProposal::from_slice(&serde_json::to_vec(&exhausted).unwrap()).is_ok());
        for state in ["applied", "cancelled"] {
            let mut erased = application_status_document(state, "automatic");
            for field in ["applicationStatus", "application", "effectDigest"] {
                erased.as_object_mut().unwrap().remove(field);
            }
            let decoded = BRegProposal::from_slice(&serde_json::to_vec(&erased).unwrap()).unwrap();
            assert!(decoded.application_status().is_none(), "{state}");
        }
    }

    #[test]
    fn application_status_rejects_unbound_inconsistent_and_unbounded_retry_claims() {
        type CorruptDocument = fn(&mut Value);
        let cases: &[(&str, CorruptDocument)] = &[
            ("missing frozen digest", |v| {
                v.as_object_mut().unwrap().remove("effectDigest");
            }),
            ("malformed frozen digest", |v| {
                v["effectDigest"] = json!("sha256:UPPERCASE");
            }),
            ("missing submission version", |v| {
                v.as_object_mut().unwrap().remove("submissionVersion");
            }),
            ("zero submission version", |v| {
                v["submissionVersion"] = json!(0);
            }),
            ("overflowing submission version", |v| {
                v["submissionVersion"] = json!(4_294_967_296_u64);
            }),
            ("receipt version differs from frozen version", |v| {
                *v = application_status_document("applied", "automatic");
                v["application"]["submissionVersion"] = json!(2);
            }),
            ("receipt digest differs from frozen digest", |v| {
                *v = application_status_document("applied", "automatic");
                v["application"]["effectDigest"] = json!(format!("sha256:{}", "b".repeat(64)));
            }),
            (
                "submitted pending status cannot retain an application receipt",
                |v| {
                    v["application"] = json!({"applicationId":ID,"submissionVersion":1,"effectDigest":REVISION,"resultLinks":[]});
                },
            ),
            ("recovery without a reason is not a status", |v| {
                v["applicationStatus"]["recovery"] = json!("retry");
            }),
            (
                "cancelled proposal cannot retain an application receipt",
                |v| {
                    *v = application_status_document("applied", "automatic");
                    v["state"] = json!("cancelled");
                    v.as_object_mut().unwrap().remove("applicationStatus");
                },
            ),
            ("retained receipt requires top-level frozen digest", |v| {
                *v = application_status_document("applied", "automatic");
                v.as_object_mut().unwrap().remove("applicationStatus");
                v.as_object_mut().unwrap().remove("effectDigest");
            }),
            ("retained receipt requires positive frozen version", |v| {
                *v = application_status_document("applied", "automatic");
                v.as_object_mut().unwrap().remove("applicationStatus");
                v["submissionVersion"] = json!(0);
                v["application"]["submissionVersion"] = json!(0);
            }),
            ("draft has no frozen application", |v| {
                v["state"] = json!("draft");
            }),
            ("pending status on applied proposal", |v| {
                v["state"] = json!("applied");
            }),
            ("applied status on submitted proposal", |v| {
                *v = application_status_document("applied", "automatic");
                v["state"] = json!("submitted");
            }),
            ("applied status without receipt", |v| {
                *v = application_status_document("applied", "automatic");
                v.as_object_mut().unwrap().remove("application");
            }),
            ("cancelled status on submitted proposal", |v| {
                *v = application_status_document("cancelled", "automatic");
                v["state"] = json!("submitted");
            }),
            ("blocked status missing reason", |v| {
                *v = application_status_document("blocked", "automatic");
                v["applicationStatus"]
                    .as_object_mut()
                    .unwrap()
                    .remove("reason");
            }),
            ("blocked status missing recovery", |v| {
                *v = application_status_document("blocked", "automatic");
                v["applicationStatus"]
                    .as_object_mut()
                    .unwrap()
                    .remove("recovery");
            }),
            ("automatic status missing retry bounds", |v| {
                v["applicationStatus"]
                    .as_object_mut()
                    .unwrap()
                    .remove("automaticRetry");
            }),
            ("manual status cannot promise automatic retry", |v| {
                v["applicationStatus"]["mode"] = json!("manual");
            }),
            ("zero maximum attempts", |v| {
                v["applicationStatus"]["automaticRetry"]["maximumAttempts"] = json!(0);
            }),
            ("maximum attempts exceeds governed ceiling", |v| {
                v["applicationStatus"]["automaticRetry"]["maximumAttempts"] = json!(1001);
            }),
            ("overflowing attempts", |v| {
                v["applicationStatus"]["automaticRetry"]["attempts"] = json!(65_536);
            }),
            ("negative attempts", |v| {
                v["applicationStatus"]["automaticRetry"]["attempts"] = json!(-1);
            }),
            ("attempts exceed maximum", |v| {
                v["applicationStatus"]["automaticRetry"]["attempts"] = json!(4);
            }),
            ("exhausted job cannot be scheduled", |v| {
                v["applicationStatus"]["automaticRetry"]["attempts"] = json!(3);
            }),
            ("blocked job cannot be scheduled", |v| {
                *v = application_status_document("blocked", "automatic");
                v["applicationStatus"]["automaticRetry"]["scheduled"] = json!(true);
            }),
            ("terminal job cannot be scheduled", |v| {
                *v = application_status_document("applied", "automatic");
                v["applicationStatus"]["automaticRetry"] =
                    json!({"scheduled":true,"attempts":1,"maximumAttempts":3});
            }),
            ("unknown status member", |v| {
                v["applicationStatus"]["workerId"] = json!("private-canary");
            }),
            ("unknown retry member", |v| {
                v["applicationStatus"]["automaticRetry"]["nextAttemptAt"] = json!("private-canary");
            }),
            ("unknown status state", |v| {
                v["applicationStatus"]["state"] = json!("ready");
            }),
        ];
        for (label, mutate) in cases {
            let mut value = application_status_document("pending", "automatic");
            mutate(&mut value);
            assert!(
                BRegProposal::from_slice(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{label}"
            );
        }
    }

    #[test]
    fn purpose_bindings_require_the_exact_advertised_action_and_profile() {
        let actions = json!([
            {"actionId":"correct-address","accessProfile":"reviewer","operations":["get-review-context"]},
            {"actionId":"correct-address","accessProfile":"status","operations":["get-review-status"]},
        ]);
        let source = "https://registry.example/";
        assert!(BRegProposalReviewBinding::from_metadata(
            &actions,
            source,
            "reviewer",
            "correct-address",
            false
        )
        .is_ok());
        assert!(BRegProposalReviewBinding::from_metadata(
            &actions,
            source,
            "status",
            "correct-address",
            true
        )
        .is_ok());
        assert!(BRegProposalReviewBinding::from_metadata(
            &actions,
            source,
            "status",
            "correct-address",
            false
        )
        .is_err());
        assert!(BRegProposalReviewBinding::from_metadata(
            &actions,
            source,
            "reviewer",
            "correct-address",
            true
        )
        .is_err());
        assert!(BRegProposalReviewBinding::from_metadata(
            &actions,
            source,
            "reviewer",
            "other-action",
            false
        )
        .is_err());
    }
    #[tokio::test]
    async fn direct_review_read_refuses_foreign_binding_and_noncanonical_id_before_io() {
        let source = client("https://registry.example/");
        let actions = json!([{"actionId":"correct-address","accessProfile":"reviewer","operations":["get-review-context"]}]);
        let binding = BRegProposalReviewBinding::from_metadata(
            &actions,
            &source.source_binding(),
            "reviewer",
            "correct-address",
            false,
        )
        .unwrap();
        assert!(client("https://other.example/")
            .read_proposal_review_by_id(&binding, ID)
            .await
            .is_err());
        assert!(source
            .read_proposal_review_by_id(&binding, "../other")
            .await
            .is_err());
    }
    #[test]
    fn application_receipts_refuse_internal_actor_and_reason_projections() {
        let mut value = document();
        value["state"] = json!("applied");
        value["effectDigest"] = json!(REVISION);
        value["application"] = json!({"applicationId":ID,"submissionVersion":1,"effectDigest":REVISION,"resultLinks":[]});
        assert!(BRegProposal::from_slice(&serde_json::to_vec(&value).unwrap()).is_ok());
        for field in ["appliedBy", "appliedAt", "reason", "reasonPresent"] {
            let mut widened = value.clone();
            widened["application"][field] = json!("private-canary");
            assert!(BRegProposal::from_slice(&serde_json::to_vec(&widened).unwrap()).is_err());
        }
    }
    fn client(origin: &str) -> BaseRegistryClient {
        BaseRegistryClient::new(BaseRegistryClientConfig::new(origin.parse().unwrap())).unwrap()
    }
    fn document() -> Value {
        json!({"id":ID,"actionId":"correct-address","actionRevision":REVISION,
        "submissionVersion":1,"revision":2,"state":"submitted","effectDigest":REVISION,"links":{
            "self":{"method":"GET","path":format!("/v1/proposals/{ID}"),"accessProfile":"author","operation":"get"},
            "apply":{"method":"POST","path":format!("/v1/proposals/{ID}/apply"),"accessProfile":"author","operation":"apply","ifMatch":"\"original-condition\"",
                "availability":{"available":true,"observedRevision":2}}
        }})
    }
    fn proposal(client: &BaseRegistryClient, value: Value) -> BRegProposal {
        BRegProposal::from_slice(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .bind(client.source_binding())
    }
    #[test]
    fn inspection_is_inert_and_transitions_are_bound_to_the_client_origin() {
        let client = client("https://registry.example/base/");
        let bytes = serde_json::to_vec(&document()).unwrap();
        let inert = BRegProposal::from_slice(&bytes).unwrap();
        let key = BRegIdempotencyKey::parse("original-key").unwrap();
        assert!(client
            .prepare_proposal(&inert, "apply", json!({}), &key)
            .is_err());
        let bound = proposal(&client, document());
        let attempt = client
            .prepare_proposal(
                &bound,
                "apply",
                json!({"submissionVersion":1,"effectDigest":REVISION}),
                &key,
            )
            .unwrap();
        assert!(!format!("{attempt:?}").contains("original-key"));
        let other = super::tests::client("https://other.example/");
        assert!(other
            .prepare_proposal(&bound, "apply", json!({}), &key)
            .is_err());
        let restored = BRegPreparedProposal::from_slice(attempt.as_bytes()).unwrap();
        assert!(!restored.executable);
        assert!(
            client
                .recover_proposal(&bound, &restored)
                .unwrap()
                .executable
        );
        assert_eq!(restored.as_bytes(), attempt.as_bytes());
    }
    #[test]
    fn committed_recovery_retains_original_condition_body_key_and_contract() {
        let client = client("https://registry.example/");
        let original = proposal(&client, document());
        let attempt = client
            .prepare_proposal(
                &original,
                "apply",
                json!({"submissionVersion":1,"effectDigest":REVISION}),
                &BRegIdempotencyKey::parse("original-key").unwrap(),
            )
            .unwrap();
        let mut terminal = document();
        terminal["state"] = json!("applied");
        terminal["application"] = json!({"applicationId":ID,"submissionVersion":1,
            "effectDigest":REVISION,"resultLinks":[]});
        terminal["revision"] = json!(3);
        terminal["links"]["apply"]["ifMatch"] = json!("\"current-condition\"");
        terminal["links"]["apply"]["availability"] = json!({"available":false,"observedRevision":3,"reason":"already-applied","recovery":"receipt-only"});
        let terminal = proposal(&client, terminal);
        assert!(client
            .prepare_proposal(
                &terminal,
                "apply",
                json!({}),
                &BRegIdempotencyKey::parse("new-key").unwrap()
            )
            .is_err());
        let recovered = client.recover_proposal(&terminal, &attempt).unwrap();
        assert_eq!(recovered.as_bytes(), attempt.as_bytes());
        let mut changed = document();
        changed["actionRevision"] =
            json!("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(client
            .recover_proposal(&proposal(&client, changed), &attempt)
            .is_err());
        let mut revoked = document();
        revoked["links"].as_object_mut().unwrap().remove("apply");
        assert!(client
            .recover_proposal(&proposal(&client, revoked), &attempt)
            .is_err());
    }
    #[test]
    fn revised_and_rebased_receipts_require_the_exact_next_draft_version() {
        let client = client("https://registry.example/");
        for operation in ["revise", "rebase"] {
            let mut original = document();
            let mut link = original["links"]["apply"].clone();
            link["path"] = json!(format!("/v1/proposals/{ID}/{operation}"));
            link["operation"] = json!(operation);
            original["links"] = json!({operation:link});
            let attempt = client
                .prepare_proposal(
                    &proposal(&client, original.clone()),
                    operation,
                    if operation == "rebase" {
                        json!({"input":{"address":"Updated"}})
                    } else {
                        json!({})
                    },
                    &BRegIdempotencyKey::parse("retained-transition").unwrap(),
                )
                .unwrap();
            let mut current = original;
            current["state"] = json!("draft");
            current.as_object_mut().unwrap().remove("effectDigest");
            current["submissionVersion"] = json!(2);
            current["revision"] = json!(3);
            current["links"][operation]["ifMatch"] = json!("\"new-condition\"");
            current["links"][operation]["availability"] = if operation == "revise" {
                json!({"available":false,"observedRevision":3,"reason":"stale-revision","recovery":"receipt-only"})
            } else {
                json!({"available":true,"observedRevision":3})
            };
            if operation == "rebase" {
                current["actionRevision"] = json!(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                );
            }
            assert_eq!(
                client
                    .recover_proposal(&proposal(&client, current.clone()), &attempt)
                    .unwrap()
                    .as_bytes(),
                attempt.as_bytes()
            );
            for (key, value) in [
                ("submissionVersion", json!(3)),
                ("revision", json!(4)),
                ("state", json!("submitted")),
            ] {
                let mut unrelated = current.clone();
                unrelated[key] = value;
                if key == "state" {
                    unrelated["effectDigest"] = json!(REVISION);
                }
                if key == "revision" {
                    unrelated["links"][operation]["availability"]["observedRevision"] = json!(4);
                }
                assert!(
                    client
                        .recover_proposal(&proposal(&client, unrelated), &attempt)
                        .is_err(),
                    "{operation}:{key}"
                );
            }
            if operation == "revise" {
                current["actionRevision"] = json!(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                );
                assert!(client
                    .recover_proposal(&proposal(&client, current), &attempt)
                    .is_err());
            }
        }
    }

    #[tokio::test]
    async fn proposal_uuid_lookup_refuses_foreign_bindings_and_noncanonical_ids_before_io() {
        let source = client("https://registry.example/tenant/");
        let descriptor = json!({"method":"GET","path":"/v1/proposals/{proposal_id}","accessProfiles":["reviewer"]});
        let binding = BRegProposalGetBinding::from_metadata(
            &descriptor,
            &source.source_binding(),
            "reviewer",
        )
        .unwrap();
        assert!(client("https://other.example/")
            .get_proposal(&binding, ID)
            .await
            .is_err());
        for id in [
            "../secret",
            "00000000-0000-4000-8000-00000000000A",
            "invalid",
        ] {
            assert!(source.get_proposal(&binding, id).await.is_err());
        }
        let mut disclosed = document();
        disclosed["input"] = json!({"addressLine":"Allowed"});
        assert_eq!(proposal(&source, disclosed).input().unwrap().len(), 1);
    }
    #[test]
    fn link_confinement_duplicate_members_and_revision_bound_availability_are_checked() {
        for path in [
            "https://other.example/",
            "/v1/proposals/../secret",
            "/v1/proposals/%2e%2e",
            "/v1/proposals/a?accessProfile=admin",
        ] {
            let mut invalid = document();
            invalid["links"]["apply"]["path"] = json!(path);
            assert!(BRegProposal::from_slice(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut invalid = document();
        invalid["links"]["apply"]["availability"]["observedRevision"] = json!(1);
        assert!(BRegProposal::from_slice(&serde_json::to_vec(&invalid).unwrap()).is_err());
        assert!(BRegProposal::from_slice(br#"{"id":"a","id":"b"}"#).is_err());
        let mut start_only = document();
        start_only["links"] = json!({});
        assert!(BRegProposal::from_slice(&serde_json::to_vec(&start_only).unwrap()).is_ok());
    }
    #[test]
    fn a_get_grant_does_not_promote_collection_authority() {
        assert!(BRegProposalCollection::from_metadata(
            &json!({"method":"GET","path":"/v1/proposals","accessProfiles":["list-author"]}),
            "https://registry.example/",
            REVISION,
            "get-author"
        )
        .is_err());
        assert!(BRegProposalCollection::from_metadata(
            &json!({"method":"GET","path":"/v1/proposals","accessProfiles":["list-author"]}),
            "https://registry.example/",
            REVISION,
            "list-author"
        )
        .is_ok());
    }
    #[tokio::test]
    async fn proposal_list_refuses_items_outside_requested_state() {
        use axum::{extract::State, routing::get, Json, Router};
        use std::sync::{Arc, Mutex};

        let response = Arc::new(Mutex::new(json!({"items":[]})));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/v1/proposals",
                get(|State(value): State<Arc<Mutex<Value>>>| async move {
                    (
                        [
                            (
                                "traceparent",
                                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                            ),
                            ("cache-control", "no-store"),
                            ("vary", "authorization, accept"),
                        ],
                        Json(value.lock().unwrap().clone()),
                    )
                }),
            )
            .with_state(response.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = client(&format!("http://{address}/"));
        let collection = BRegProposalCollection::from_metadata(
            &json!({"method":"GET","path":"/v1/proposals","accessProfiles":["author"]}),
            &client.source_binding(),
            REVISION,
            "author",
        )
        .unwrap();
        let states = [
            BRegProposalState::Draft,
            BRegProposalState::Submitted,
            BRegProposalState::Applied,
            BRegProposalState::Cancelled,
        ];
        for returned in states {
            let mut item = document();
            item["state"] = serde_json::to_value(returned).unwrap();
            if returned == BRegProposalState::Draft {
                item.as_object_mut().unwrap().remove("effectDigest");
            } else if returned == BRegProposalState::Applied {
                item["application"] = json!({"applicationId":ID,"submissionVersion":1,
                    "effectDigest":REVISION,"resultLinks":[]});
            }
            *response.lock().unwrap() = json!({"items":[item]});
            for requested in states {
                let query = BRegProposalQuery {
                    state: Some(requested),
                    ..Default::default()
                };
                let result = client.list_proposals(&collection, &query).await;
                assert_eq!(
                    result.is_ok(),
                    requested == returned,
                    "requested {requested:?}, returned {returned:?}"
                );
            }
            assert!(client
                .list_proposals(&collection, &BRegProposalQuery::default())
                .await
                .is_ok());
        }
        *response.lock().unwrap() = json!({"items":[]});
        assert!(client
            .list_proposals(
                &collection,
                &BRegProposalQuery {
                    state: Some(BRegProposalState::Submitted),
                    ..Default::default()
                }
            )
            .await
            .is_ok());
        server.abort();
    }
    #[test]
    fn promoted_links_bind_method_operation_resource_and_selected_profile() {
        for (field, value) in [
            ("method", "GET"),
            ("operation", "cancel"),
            (
                "path",
                "/v1/proposals/00000000-0000-4000-8000-000000000002/apply",
            ),
            ("ifMatch", "\"bad\"quote\""),
        ] {
            let mut invalid = document();
            invalid["links"]["apply"][field] = json!(value);
            assert!(
                BRegProposal::from_slice(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "{field}"
            );
        }
        let parsed = BRegProposal::from_slice(&serde_json::to_vec(&document()).unwrap()).unwrap();
        assert!(parsed
            .clone()
            .bind_profile("https://registry.example/base/".to_owned(), "other-profile")
            .is_err());
        assert!(parsed
            .bind_profile("https://registry.example/base/".to_owned(), "author")
            .is_ok());
    }
    #[test]
    fn lifecycle_bodies_are_closed_before_transport() {
        for (operation, body) in [
            ("submit", json!({"input":{}})),
            ("edit", json!({})),
            (
                "apply",
                json!({"proposalVersion":1,"effectDigest":REVISION}),
            ),
            (
                "apply",
                json!({"submissionVersion":0,"effectDigest":REVISION}),
            ),
            ("revise", json!({"rebase":true})),
        ] {
            assert!(validate_body(operation, &body).is_err());
        }
        assert!(validate_body(
            "apply",
            &json!({"submissionVersion":1,"effectDigest":REVISION})
        )
        .is_ok());
        assert!(validate_body("rebase", &json!({"input":{"address":"Example"}})).is_ok());
    }
}
