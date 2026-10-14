// SPDX-License-Identifier: Apache-2.0
//! Distinct Proposal resources and exact, caller-controlled transition attempts.

use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegRecoveryHint {
    Refresh,
    Retry,
    CorrectInput,
    Terminal,
    ReceiptOnly,
}
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalState {
    Draft,
    Submitted,
    Applied,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalApplicationState {
    Pending,
    Applying,
    Blocked,
    Applied,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalApplicationMode {
    Automatic,
    Manual,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegProposalApplicationReason {
    ContractChanged,
    DependencyOutage,
    LeaseExpired,
    ApplicationRefused,
    AttemptsExhausted,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalAutomaticRetry {
    pub scheduled: bool,
    pub attempts: u16,
    pub maximum_attempts: u16,
}
/// Local application progress for the enclosing exact frozen submission.
/// It neither follows a successor nor reconciles an unknown mutation command.
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalApplication {
    pub application_id: String,
    pub submission_version: u32,
    pub effect_digest: String,
    pub result_links: Vec<BRegProposalResultReference>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalResultReference {
    pub record_type: String,
    pub record_id: String,
    pub revision: u64,
}
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<BRegProposalReviewPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<BRegProposalReviewResult>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewSubject {
    pub source: String,
    pub subject_type: String,
    pub id: String,
    pub version: String,
    pub digest: String,
}
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewContextContract {
    pub id: String,
    pub revision: String,
    pub schema_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BRegProposalReviewPolicy {
    pub id: String,
    pub version: String,
    pub digest: String,
}
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
            || self.revision == 0
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
                        .as_ref()
                        .is_some_and(|value| value.len() > 64)
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
        if data.version != 1
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
            || document.policy.as_ref().is_some_and(|policy| {
                !digest(&policy.digest) || policy.id.is_empty() || policy.version.is_empty()
            })
            || document.result.as_ref().is_some_and(|result| {
                !matches!(
                    result.state.as_str(),
                    "pending"
                        | "approved"
                        | "rejected"
                        | "changes-requested"
                        | "answered"
                        | "cancelled"
                        | "superseded"
                        | "expired"
                ) || result
                    .result_id
                    .as_deref()
                    .is_some_and(|id| Uuid::parse_str(id).is_err())
            })
            || is_context
                && (document.context.contract.is_none() || document.context.fields.is_none())
            || !is_context
                && (document.context.contract.is_some() || document.context.fields.is_some())
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
        let response = self.proposal_exchange(&link, None, None).await?;
        let proposal = BRegProposal::from_slice(response.value.as_bytes())?;
        if proposal.id != id {
            return Err(refusal());
        }
        Ok(BRegComplete {
            value: proposal.bind_profile(self.source_binding(), &binding.profile)?,
            metadata: response.metadata,
        })
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
            || document.policy.as_ref().is_some_and(|policy| {
                !digest(&policy.digest) || policy.id.is_empty() || policy.version.is_empty()
            })
            || document.result.as_ref().is_some_and(|result| {
                !matches!(
                    result.state.as_str(),
                    "pending"
                        | "approved"
                        | "rejected"
                        | "changes-requested"
                        | "answered"
                        | "cancelled"
                        | "superseded"
                        | "expired"
                ) || result
                    .result_id
                    .as_deref()
                    .is_some_and(|id| Uuid::parse_str(id).is_err())
            })
            || operation == "reviewContext"
                && (document.context.contract.is_none() || document.context.fields.is_none())
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
        self.proposal_attachment_exchange(link, None, None, None, slot.maximum_bytes)
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
        if current.id != prior.id || current.action_id != prior.action_id {
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
            || query.cursor.as_ref().is_some_and(|cursor| {
                cursor.len() > 512
                    || cursor.is_empty()
                    || cursor.bytes().any(|byte| byte <= 32 || byte >= 127)
            })
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
                .is_some_and(|cursor| cursor.len() > 512)
        {
            return Err(refusal());
        }
        for item in &mut page.items {
            item.validate()?;
            if query
                .action
                .as_ref()
                .is_some_and(|action| action != &item.action_id)
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
            version: 1,
            source: self.source_binding(),
            proposal_id: proposal.id.clone(),
            action_id: proposal.action_id.clone(),
            action_revision: proposal.action_revision.clone(),
            submission_version: proposal.submission_version,
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
            .proposal_exchange(&evidence.link, Some(evidence.body.into_bytes()), Some(&key))
            .await?;
        let proposal = BRegProposal::from_slice(response.value.as_bytes())?;
        if proposal.id != evidence.proposal_id || proposal.action_id != evidence.action_id {
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
        if current.id != proposal.id || current.action_id != proposal.action_id {
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
        let next_revision = evidence
            .link
            .availability
            .as_ref()
            .is_some_and(|availability| {
                availability.observed_revision.checked_add(1) == Some(current.revision)
            });
        let same_version = evidence.submission_version == current.submission_version;
        let advanced_draft = matches!(evidence.link.operation.as_str(), "revise" | "rebase")
            && current.state == BRegProposalState::Draft
            && evidence.submission_version.checked_add(1) == Some(current.submission_version)
            && next_revision;
        if current.source.as_deref() != Some(self.source_binding().as_str())
            || evidence.source != self.source_binding()
            || evidence.proposal_id != current.id
            || evidence.action_id != current.action_id
            || evidence.action_revision != current.action_revision
            || !(same_version || advanced_draft)
            || !current.links.values().any(|link| {
                link.path == evidence.link.path
                    && link.method == evidence.link.method
                    && link.access_profile == evidence.link.access_profile
                    && link.operation == evidence.link.operation
                    && (link == &evidence.link
                        || next_revision
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
        let cases: &[(&str, fn(&mut Value))] = &[
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
        "submissionVersion":1,"revision":2,"state":"submitted","links":{
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
            current["submissionVersion"] = json!(2);
            current["revision"] = json!(3);
            current["links"][operation]["ifMatch"] = json!("\"new-condition\"");
            current["links"][operation]["availability"] = if operation == "revise" {
                json!({"available":false,"observedRevision":3,"reason":"stale-revision","recovery":"receipt-only"})
            } else {
                json!({"available":true,"observedRevision":3})
            };
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
                (
                    "actionRevision",
                    json!(
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    ),
                ),
            ] {
                let mut unrelated = current.clone();
                unrelated[key] = value;
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
