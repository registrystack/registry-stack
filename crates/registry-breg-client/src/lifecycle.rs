//! Inert Base Registry Engine change-request annotations and promoted actor actions.
//!
//! A record's `request.actions` member is advisory, caller-specific data. It is
//! decoded without granting execution authority. An action becomes executable
//! only after [`BRegRequestMetadata::promote_actions`] binds it to a
//! crate-owned, validated Registry Metadata handle and the exact record
//! envelope from which it was read.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Serialize, Serializer};
use serde_json::{json, Map, Value};
use url::Url;
use uuid::Uuid;

/// Maximum Unicode characters in an application reason.
pub const MAX_BREG_APPLICATION_REASON_CHARACTERS: usize = 4_096;

/// Maximum actor-action links accepted on one record.
pub const MAX_BREG_REQUEST_ACTIONS: usize = 64;
/// Maximum lifecycle operation bindings in metadata.
pub const MAX_BREG_LIFECYCLE_OPERATION_BINDINGS: usize = 4;
/// Maximum bytes accepted for one actor-action href.
pub const MAX_BREG_ACTION_HREF_BYTES: usize = 2_048;
/// Maximum bytes accepted for an opaque snapshot reference.
pub const MAX_BREG_SNAPSHOT_REFERENCE_BYTES: usize = 4_096;
/// Maximum retained proposals accepted in one caller-controlled history page.
pub const MAX_BREG_RETAINED_PROPOSALS: usize = 50;
/// Maximum caller-visible result references accepted for one retained proposal.
pub const MAX_BREG_REQUEST_RESULT_REFERENCES: usize = 16;

const MAX_REQUEST_EXTENSION_BYTES: usize = 2_097_152;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_TIMESTAMP_BYTES: usize = 128;

/// One of Base Registry Engine's closed change-request lifecycle operations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(clippy::enum_variant_names)]
pub enum BRegLifecycleOperation {
    SubmitRequest,
    ReviseRequest,
    CancelRequest,
    ApplyRequest,
}

impl BRegLifecycleOperation {
    /// All supported lifecycle operations, in workflow order.
    pub const ALL: [Self; 4] = [
        Self::SubmitRequest,
        Self::ReviseRequest,
        Self::CancelRequest,
        Self::ApplyRequest,
    ];

    /// Returns the exact Registry Metadata and record-link identifier.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::SubmitRequest => "submit_request",
            Self::ReviseRequest => "revise_request",
            Self::CancelRequest => "cancel_request",
            Self::ApplyRequest => "apply_request",
        }
    }

    const fn requires_proposal_binding(self) -> bool {
        matches!(self, Self::ApplyRequest)
    }

    const fn path_suffix(self) -> &'static str {
        match self {
            Self::SubmitRequest => "/actions/submit",
            Self::ReviseRequest => "/actions/revise",
            Self::CancelRequest => "/actions/cancel",
            Self::ApplyRequest => "/actions/apply",
        }
    }
}

/// Base Registry Engine's closed request workflow state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegRequestState {
    Draft,
    Submitted,
    Cancelled,
    Applied,
}

/// One caller-visible record affected by an exact applied request proposal.
///
/// This is provenance only. It grants no authority to read the target and its
/// revision is not a current ETag or write precondition.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegRequestResultReference {
    target_entity_identifier: String,
    target_record_identifier: Uuid,
    target_revision: u64,
}

impl BRegRequestResultReference {
    #[must_use]
    pub fn target_entity_identifier(&self) -> &str {
        &self.target_entity_identifier
    }

    #[must_use]
    pub const fn target_record_identifier(&self) -> Uuid {
        self.target_record_identifier
    }

    /// Returns the revision written by the application, not the current target revision.
    #[must_use]
    pub const fn target_revision(&self) -> u64 {
        self.target_revision
    }
}

impl fmt::Debug for BRegRequestResultReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRequestResultReference")
            .field("target_entity_identifier", &"<redacted>")
            .field("target_record_identifier", &"<redacted>")
            .field("target_revision", &"<redacted>")
            .finish()
    }
}

/// One exact retained proposal from a caller-selected history page.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegRetainedRequestProposal {
    request_entity_identifier: String,
    request_identifier: Uuid,
    proposal_version: BRegProposalVersion,
    breg_state: BRegRequestState,
    current: bool,
    contract_fingerprint: String,
    detail_erased: bool,
    application_identifier: Option<Uuid>,
    result_link_count: u16,
    result_references: Vec<BRegRequestResultReference>,
    effect_digest: Option<BRegEffectDigest>,
}

impl BRegRetainedRequestProposal {
    #[must_use]
    pub fn request_entity_identifier(&self) -> &str {
        &self.request_entity_identifier
    }

    #[must_use]
    pub const fn request_identifier(&self) -> Uuid {
        self.request_identifier
    }

    #[must_use]
    pub const fn proposal_version(&self) -> BRegProposalVersion {
        self.proposal_version
    }

    #[must_use]
    pub const fn breg_state(&self) -> BRegRequestState {
        self.breg_state
    }

    #[must_use]
    pub const fn current(&self) -> bool {
        self.current
    }

    #[must_use]
    pub fn contract_fingerprint(&self) -> &str {
        &self.contract_fingerprint
    }

    #[must_use]
    pub const fn detail_erased(&self) -> bool {
        self.detail_erased
    }

    #[must_use]
    pub const fn application_identifier(&self) -> Option<Uuid> {
        self.application_identifier
    }

    /// Caller-visible count, never an undisclosed application total.
    #[must_use]
    pub const fn result_link_count(&self) -> u16 {
        self.result_link_count
    }

    /// Caller-visible inert result references in server order.
    #[must_use]
    pub fn result_references(&self) -> &[BRegRequestResultReference] {
        &self.result_references
    }

    #[must_use]
    pub fn effect_digest(&self) -> Option<&BRegEffectDigest> {
        self.effect_digest.as_ref()
    }
}

impl fmt::Debug for BRegRetainedRequestProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRetainedRequestProposal")
            .field("request_entity_identifier", &"<redacted>")
            .field("request_identifier", &"<redacted>")
            .field("proposal_version", &self.proposal_version)
            .field("breg_state", &self.breg_state)
            .field("current", &self.current)
            .field("contract_fingerprint", &"<redacted>")
            .field("detail_erased", &self.detail_erased)
            .field("has_application", &self.application_identifier.is_some())
            .field("visible_result_count", &self.result_references.len())
            .field("has_effect_digest", &self.effect_digest.is_some())
            .finish()
    }
}

/// One explicitly loaded retained request-history page.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegRetainedRequestHistoryPage {
    proposals: Vec<BRegRetainedRequestProposal>,
    next_after_proposal_version: Option<BRegProposalVersion>,
}

impl BRegRetainedRequestHistoryPage {
    #[must_use]
    pub fn proposals(&self) -> &[BRegRetainedRequestProposal] {
        &self.proposals
    }

    /// Cursor for one caller-initiated subsequent record GET.
    #[must_use]
    pub const fn next_after_proposal_version(&self) -> Option<BRegProposalVersion> {
        self.next_after_proposal_version
    }

    /// Locate one exact request proposal within this page only.
    #[must_use]
    pub fn find_proposal(
        &self,
        request_entity_identifier: &str,
        request_identifier: Uuid,
        proposal_version: BRegProposalVersion,
    ) -> Option<&BRegRetainedRequestProposal> {
        self.proposals.iter().find(|proposal| {
            proposal.request_entity_identifier == request_entity_identifier
                && proposal.request_identifier == request_identifier
                && proposal.proposal_version == proposal_version
        })
    }

    /// Locate one exact applied proposal within this page only.
    #[must_use]
    pub fn find_application(
        &self,
        request_entity_identifier: &str,
        request_identifier: Uuid,
        proposal_version: BRegProposalVersion,
        application_identifier: Uuid,
    ) -> Option<&BRegRetainedRequestProposal> {
        self.find_proposal(
            request_entity_identifier,
            request_identifier,
            proposal_version,
        )
        .filter(|proposal| proposal.application_identifier == Some(application_identifier))
    }
}

impl fmt::Debug for BRegRetainedRequestHistoryPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRetainedRequestHistoryPage")
            .field("proposal_count", &self.proposals.len())
            .field(
                "has_next_after_proposal_version",
                &self.next_after_proposal_version.is_some(),
            )
            .finish()
    }
}

/// The review requirement frozen into a visible change-request proposal.
#[derive(Clone, Eq, PartialEq)]
pub enum BRegRequestReviewRequirement {
    /// Review is explicitly not required.
    None,
    /// Review is delegated to the named external authority and policy.
    External(BRegExternalReviewRequirement),
}

impl fmt::Debug for BRegRequestReviewRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("BRegRequestReviewRequirement::None"),
            Self::External(_) => {
                formatter.write_str("BRegRequestReviewRequirement::External(<redacted>)")
            }
        }
    }
}

/// A bounded external review authority and policy identifier.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegExternalReviewRequirement {
    authority: String,
    policy_id: String,
}

impl BRegExternalReviewRequirement {
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

impl fmt::Debug for BRegExternalReviewRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegExternalReviewRequirement(<redacted>)")
    }
}

/// Frozen, caller-visible review requirement for the current proposal.
///
/// This is descriptive only. It cannot grant a lifecycle action or cause the
/// client to infer that an automatic application is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BRegRequestProposal {
    review: BRegRequestReviewRequirement,
}

impl BRegRequestProposal {
    #[must_use]
    pub const fn review(&self) -> &BRegRequestReviewRequirement {
        &self.review
    }
}

impl BRegRequestState {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "draft" => Some(Self::Draft),
            "submitted" => Some(Self::Submitted),
            "cancelled" => Some(Self::Cancelled),
            "applied" => Some(Self::Applied),
            _ => None,
        }
    }

    const fn identifier(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Cancelled => "cancelled",
            Self::Applied => "applied",
        }
    }
}

/// A positive change-request proposal version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BRegProposalVersion(u32);

impl BRegProposalVersion {
    fn from_value(value: &Value) -> Result<Self, BRegLifecycleDecodeError> {
        value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .map(Self)
            .ok_or(BRegLifecycleDecodeError::Profile)
    }

    /// Returns the positive integer version.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Serialize for BRegProposalVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

/// An exact lowercase SHA-256 proposal digest.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegEffectDigest(String);

impl BRegEffectDigest {
    fn parse(value: &str) -> Result<Self, BRegLifecycleDecodeError> {
        if valid_effect_digest(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(BRegLifecycleDecodeError::Profile)
        }
    }

    /// Returns the header- and body-safe digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BRegEffectDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegEffectDigest(<redacted>)")
    }
}

impl Serialize for BRegEffectDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

/// Retained application metadata on a normal request record.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegRetainedApplication {
    application_identifier: String,
    proposal_version: BRegProposalVersion,
    effect_digest: Option<BRegEffectDigest>,
    applied_at: String,
    reason_present: bool,
    reason: Option<String>,
}

impl BRegRetainedApplication {
    /// Returns the canonical application UUID.
    #[must_use]
    pub fn application_identifier(&self) -> &str {
        &self.application_identifier
    }

    #[must_use]
    pub const fn proposal_version(&self) -> BRegProposalVersion {
        self.proposal_version
    }

    #[must_use]
    pub fn effect_digest(&self) -> Option<&BRegEffectDigest> {
        self.effect_digest.as_ref()
    }

    #[must_use]
    pub fn applied_at(&self) -> &str {
        &self.applied_at
    }

    #[must_use]
    pub const fn reason_present(&self) -> bool {
        self.reason_present
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

impl fmt::Debug for BRegRetainedApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRetainedApplication")
            .field("application_identifier", &"<redacted>")
            .field("proposal_version", &self.proposal_version)
            .field("effect_digest", &"<redacted>")
            .field("applied_at", &"<redacted>")
            .field("reason_present", &self.reason_present)
            .field("reason", &"<redacted>")
            .finish()
    }
}

/// Full application receipt returned only by a successful lifecycle action.
/// Record projections may omit the digest, but action receipts may not.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegLifecycleReceiptApplication {
    application_identifier: String,
    proposal_version: BRegProposalVersion,
    effect_digest: BRegEffectDigest,
    applied_at: String,
}

impl BRegLifecycleReceiptApplication {
    #[must_use]
    pub fn application_identifier(&self) -> &str {
        &self.application_identifier
    }

    #[must_use]
    pub const fn proposal_version(&self) -> BRegProposalVersion {
        self.proposal_version
    }

    #[must_use]
    pub fn effect_digest(&self) -> &BRegEffectDigest {
        &self.effect_digest
    }

    #[must_use]
    pub fn applied_at(&self) -> &str {
        &self.applied_at
    }
}

impl fmt::Debug for BRegLifecycleReceiptApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLifecycleReceiptApplication")
            .field("application_identifier", &"<redacted>")
            .field("proposal_version", &self.proposal_version)
            .field("effect_digest", &"<redacted>")
            .field("applied_at", &"<redacted>")
            .finish()
    }
}

/// The minimal application provenance stub retained after detail erasure.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegErasedApplication {
    application_identifier: String,
    proposal_version: BRegProposalVersion,
    reason_present: bool,
}

impl BRegErasedApplication {
    #[must_use]
    pub fn application_identifier(&self) -> &str {
        &self.application_identifier
    }

    #[must_use]
    pub const fn proposal_version(&self) -> BRegProposalVersion {
        self.proposal_version
    }

    /// Whether the applier recorded a remark whose text erasure removed.
    #[must_use]
    pub const fn reason_present(&self) -> bool {
        self.reason_present
    }
}

impl fmt::Debug for BRegErasedApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegErasedApplication")
            .field("application_identifier", &"<redacted>")
            .field("proposal_version", &self.proposal_version)
            .field("reason_present", &self.reason_present)
            .finish()
    }
}

/// Application metadata whose shape is bound to request-detail retention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BRegRecordApplication {
    Retained(BRegRetainedApplication),
    Erased(BRegErasedApplication),
}

/// Current status of an externally owned review. This projection is descriptive
/// and never grants BReg application authority.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegExternalReviewStatus {
    submission: BRegExternalReviewSubmission,
    result: BRegExternalReviewResult,
    delivery: BRegExternalReviewDelivery,
    application: BRegExternalReviewApplication,
    recovery: BRegExternalReviewRecovery,
}

impl BRegExternalReviewStatus {
    #[must_use]
    pub const fn submission(&self) -> &BRegExternalReviewSubmission {
        &self.submission
    }
    #[must_use]
    pub const fn result(&self) -> &BRegExternalReviewResult {
        &self.result
    }
    #[must_use]
    pub const fn delivery(&self) -> &BRegExternalReviewDelivery {
        &self.delivery
    }
    #[must_use]
    pub const fn application(&self) -> &BRegExternalReviewApplication {
        &self.application
    }
    #[must_use]
    pub const fn recovery(&self) -> &BRegExternalReviewRecovery {
        &self.recovery
    }
}

impl fmt::Debug for BRegExternalReviewStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegExternalReviewStatus")
            .field("submission_state", &self.submission.state)
            .field("result_state", &self.result.state)
            .field("delivery_state", &self.delivery.state)
            .field("application_state", &self.application.state)
            .field("recovery_state", &self.recovery.state)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegExternalReviewSubmissionState {
    Pending,
    Accepted,
    Uncertain,
    Cancelling,
    Cancelled,
    Failed,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegExternalReviewSubmission {
    state: BRegExternalReviewSubmissionState,
    authority: String,
    request_id: Option<String>,
    submission_digest: Option<BRegEffectDigest>,
    recovery_deadline: Option<String>,
    policy: Option<BRegExternalReviewPolicy>,
}

impl BRegExternalReviewSubmission {
    #[must_use]
    pub const fn state(&self) -> BRegExternalReviewSubmissionState {
        self.state
    }
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
    #[must_use]
    pub fn submission_digest(&self) -> Option<&BRegEffectDigest> {
        self.submission_digest.as_ref()
    }
    /// Deadline for bounded recovery of the current submission attempt.
    #[must_use]
    pub fn recovery_deadline(&self) -> Option<&str> {
        self.recovery_deadline.as_deref()
    }
    #[must_use]
    pub const fn policy(&self) -> Option<&BRegExternalReviewPolicy> {
        self.policy.as_ref()
    }
}

impl fmt::Debug for BRegExternalReviewSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegExternalReviewSubmission")
            .field("state", &self.state)
            .field("has_request_id", &self.request_id.is_some())
            .field("has_submission_digest", &self.submission_digest.is_some())
            .field("has_recovery_deadline", &self.recovery_deadline.is_some())
            .field("has_policy", &self.policy.is_some())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegExternalReviewPolicy {
    id: String,
    version: String,
    digest: BRegEffectDigest,
}

impl BRegExternalReviewPolicy {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
    #[must_use]
    pub fn digest(&self) -> &BRegEffectDigest {
        &self.digest
    }
}

impl fmt::Debug for BRegExternalReviewPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegExternalReviewPolicy(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegExternalReviewResultState {
    Pending,
    Approved,
    Rejected,
    ChangesRequested,
    Answered,
    Cancelled,
    Superseded,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegExternalReviewResult {
    state: BRegExternalReviewResultState,
    result_id: Option<String>,
    completed_at: Option<String>,
    available_until: Option<String>,
}

impl BRegExternalReviewResult {
    #[must_use]
    pub const fn state(&self) -> BRegExternalReviewResultState {
        self.state
    }
    #[must_use]
    pub fn result_id(&self) -> Option<&str> {
        self.result_id.as_deref()
    }
    #[must_use]
    pub fn completed_at(&self) -> Option<&str> {
        self.completed_at.as_deref()
    }
    #[must_use]
    pub fn available_until(&self) -> Option<&str> {
        self.available_until.as_deref()
    }
}

impl fmt::Debug for BRegExternalReviewResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegExternalReviewResult")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegExternalReviewDeliveryState {
    Polling,
    Received,
    Reconciled,
    Unmatched,
    Exhausted,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegExternalReviewDelivery {
    state: BRegExternalReviewDeliveryState,
    event_id: Option<String>,
    received_at: Option<String>,
}

impl BRegExternalReviewDelivery {
    #[must_use]
    pub const fn state(&self) -> BRegExternalReviewDeliveryState {
        self.state
    }
    #[must_use]
    pub fn event_id(&self) -> Option<&str> {
        self.event_id.as_deref()
    }
    #[must_use]
    pub fn received_at(&self) -> Option<&str> {
        self.received_at.as_deref()
    }
}

impl fmt::Debug for BRegExternalReviewDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegExternalReviewDelivery")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegExternalReviewApplicationMode {
    Manual,
    Automatic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegExternalReviewApplicationState {
    AwaitingReview,
    Ready,
    Queued,
    Applying,
    Applied,
    Blocked,
    /// An approval past its availability that was never applied. It can no
    /// longer be applied: the owner revises the request or cancels it.
    Expired,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegExternalReviewApplication {
    mode: BRegExternalReviewApplicationMode,
    state: BRegExternalReviewApplicationState,
    executor: Option<String>,
    application_id: Option<String>,
    attempts: Option<u16>,
    next_attempt_at: Option<String>,
    receipt_recovered: bool,
}

impl BRegExternalReviewApplication {
    #[must_use]
    pub const fn mode(&self) -> BRegExternalReviewApplicationMode {
        self.mode
    }
    #[must_use]
    pub const fn state(&self) -> BRegExternalReviewApplicationState {
        self.state
    }
    #[must_use]
    pub fn executor(&self) -> Option<&str> {
        self.executor.as_deref()
    }
    #[must_use]
    pub fn application_id(&self) -> Option<&str> {
        self.application_id.as_deref()
    }
    /// Number of bounded automatic-application attempts already claimed.
    #[must_use]
    pub const fn attempts(&self) -> Option<u16> {
        self.attempts
    }
    /// Next eligible automatic-application attempt time.
    #[must_use]
    pub fn next_attempt_at(&self) -> Option<&str> {
        self.next_attempt_at.as_deref()
    }
    /// Whether the application receipt was recovered from already-applied source state.
    #[must_use]
    pub const fn receipt_recovered(&self) -> bool {
        self.receipt_recovered
    }
}

impl fmt::Debug for BRegExternalReviewApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegExternalReviewApplication")
            .field("mode", &self.mode)
            .field("state", &self.state)
            .field("has_executor", &self.executor.is_some())
            .field("has_application_id", &self.application_id.is_some())
            .field("attempts", &self.attempts)
            .field("has_next_attempt_at", &self.next_attempt_at.is_some())
            .field("receipt_recovered", &self.receipt_recovered)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegExternalReviewRecoveryState {
    None,
    OperatorAttention,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BRegExternalReviewRecovery {
    state: BRegExternalReviewRecoveryState,
    code: Option<String>,
}

impl BRegExternalReviewRecovery {
    #[must_use]
    pub const fn state(&self) -> BRegExternalReviewRecoveryState {
        self.state
    }
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
}

impl fmt::Debug for BRegExternalReviewRecovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegExternalReviewRecovery")
            .field("state", &self.state)
            .field("has_code", &self.code.is_some())
            .finish()
    }
}
/// Validated but inert change-request metadata extracted from a Registry
/// Record. Its action links cannot be executed until promoted.
#[derive(Clone, PartialEq)]
pub struct BRegRequestMetadata {
    breg_state: BRegRequestState,
    proposal_version: BRegProposalVersion,
    effect_digest: Option<BRegEffectDigest>,
    proposal: Option<BRegRequestProposal>,
    editable: bool,
    detail_erased: bool,
    actions: Vec<InertBRegLifecycleAction>,
    application: Option<BRegRecordApplication>,
    retained_history: Option<BRegRetainedRequestHistoryPage>,
    review: Option<BRegExternalReviewStatus>,
    submitter_reference: Option<String>,
    applier_reference: Option<String>,
}

impl BRegRequestMetadata {
    /// Extracts Base Registry Engine request annotations from a shared Registry
    /// Record. Absence means the record is not a visible change request.
    pub fn from_record(
        record: &crate::RegistryRecord,
    ) -> Result<Option<Self>, BRegLifecycleDecodeError> {
        let metadata = record
            .extensions
            .get("request")
            .cloned()
            .map(|value| Self::from_value(value, record.domain_data.is_empty()))
            .transpose()?;
        if metadata.as_ref().is_some_and(|metadata| {
            metadata.retained_history.as_ref().is_some_and(|history| {
                history.proposals.iter().any(|proposal| {
                    proposal.request_identifier.to_string() != record.record_identifier
                })
            })
        }) {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        Ok(metadata)
    }

    /// Decodes a record's `request` extension under the exact Base Registry Engine
    /// response contract.
    ///
    /// `domain_data_is_empty` must be derived from the containing Registry
    /// Record. An erased-detail marker is refused while domain data remains.
    pub fn from_value(
        value: Value,
        domain_data_is_empty: bool,
    ) -> Result<Self, BRegLifecycleDecodeError> {
        if serde_json::to_vec(&value)
            .map_err(|_| BRegLifecycleDecodeError::Profile)?
            .len()
            > MAX_REQUEST_EXTENSION_BYTES
        {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        let mut object = exact_object(
            value,
            &["bregState", "proposalVersion", "editable"],
            &[
                "effectDigest",
                "proposal",
                "detailErased",
                "actions",
                "application",
                "history",
                "review",
                "submitterReference",
                "applierReference",
            ],
        )?;

        let breg_state = take_string(&mut object, "bregState").and_then(|value| {
            BRegRequestState::parse(&value).ok_or(BRegLifecycleDecodeError::Profile)
        })?;
        let proposal_version = BRegProposalVersion::from_value(
            &object
                .remove("proposalVersion")
                .ok_or(BRegLifecycleDecodeError::Profile)?,
        )?;
        let editable = object
            .remove("editable")
            .and_then(|value| value.as_bool())
            .ok_or(BRegLifecycleDecodeError::Profile)?;
        let effect_digest = take_optional_digest(&mut object, "effectDigest")?;
        let proposal = match object.remove("proposal") {
            None | Some(Value::Null) => None,
            Some(value) => Some(decode_proposal(value)?),
        };
        let detail_erased = match object.remove("detailErased") {
            None => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(BRegLifecycleDecodeError::Profile),
        };
        if detail_erased && (!domain_data_is_empty || editable) {
            return Err(BRegLifecycleDecodeError::Profile);
        }

        let actions = match object.remove("actions") {
            None => Vec::new(),
            Some(Value::Array(values)) if values.len() <= MAX_BREG_REQUEST_ACTIONS => values
                .into_iter()
                .map(InertBRegLifecycleAction::from_value)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(BRegLifecycleDecodeError::Profile),
        };
        if detail_erased && !actions.is_empty() {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        reject_duplicate_action_bindings(&actions)?;

        let application = match object.remove("application") {
            None | Some(Value::Null) => None,
            Some(value) if detail_erased => Some(BRegRecordApplication::Erased(
                decode_erased_application(value)?,
            )),
            Some(value) => Some(BRegRecordApplication::Retained(
                decode_retained_application(value)?,
            )),
        };
        let review = object
            .remove("review")
            .map(decode_external_review_status)
            .transpose()?;
        if detail_erased && review.is_some() {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        let submitter_reference = take_optional_identifier(&mut object, "submitterReference")?;
        let applier_reference = take_optional_identifier(&mut object, "applierReference")?;
        if applier_reference.is_some() && application.is_none() {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        let retained_history = match object.remove("history") {
            None | Some(Value::Null) => None,
            Some(value) => Some(decode_retained_history(value)?),
        };
        if let Some(current) = retained_history
            .as_ref()
            .and_then(|history| history.proposals.iter().find(|proposal| proposal.current))
        {
            let application_identifier =
                application.as_ref().map(|application| match application {
                    BRegRecordApplication::Retained(application) => {
                        application.application_identifier.as_str()
                    }
                    BRegRecordApplication::Erased(application) => {
                        application.application_identifier.as_str()
                    }
                });
            if current.proposal_version != proposal_version
                || current.breg_state != breg_state
                || current
                    .application_identifier
                    .map(|value| value.to_string())
                    .as_deref()
                    != application_identifier
            {
                return Err(BRegLifecycleDecodeError::Profile);
            }
        }
        Ok(Self {
            breg_state,
            proposal_version,
            effect_digest,
            proposal,
            editable,
            detail_erased,
            actions,
            application,
            retained_history,
            review,
            submitter_reference,
            applier_reference,
        })
    }

    #[must_use]
    pub const fn breg_state(&self) -> BRegRequestState {
        self.breg_state
    }

    #[must_use]
    pub const fn proposal_version(&self) -> BRegProposalVersion {
        self.proposal_version
    }

    #[must_use]
    pub fn effect_digest(&self) -> Option<&BRegEffectDigest> {
        self.effect_digest.as_ref()
    }

    /// Returns the frozen current-proposal policy, if this request has one.
    #[must_use]
    pub fn proposal(&self) -> Option<&BRegRequestProposal> {
        self.proposal.as_ref()
    }

    #[must_use]
    pub const fn editable(&self) -> bool {
        self.editable
    }

    #[must_use]
    pub const fn detail_erased(&self) -> bool {
        self.detail_erased
    }

    #[must_use]
    pub fn application(&self) -> Option<&BRegRecordApplication> {
        self.application.as_ref()
    }

    #[must_use]
    pub fn review(&self) -> Option<&BRegExternalReviewStatus> {
        self.review.as_ref()
    }

    #[must_use]
    pub fn submitter_reference(&self) -> Option<&str> {
        self.submitter_reference.as_deref()
    }

    #[must_use]
    pub fn applier_reference(&self) -> Option<&str> {
        self.applier_reference.as_deref()
    }

    /// Returns the explicitly loaded typed history page. It is never consulted
    /// for lifecycle execution and does not advance pagination or fetch targets.
    #[must_use]
    pub fn retained_history(&self) -> Option<&BRegRetainedRequestHistoryPage> {
        self.retained_history.as_ref()
    }

    /// Returns the advertised operation identifiers without exposing hrefs or
    /// preconditions as executable authority.
    pub fn advertised_operations(&self) -> impl Iterator<Item = BRegLifecycleOperation> + '_ {
        self.actions.iter().map(|action| action.operation)
    }

    /// Promotes every advisory action only after exact Registry Metadata,
    /// selected-profile, record, route, href and precondition binding.
    pub fn promote_actions(
        &self,
        authority: &BRegLifecycleAuthority,
        record: &BRegLifecycleRecordBinding,
    ) -> Result<Vec<BRegLifecycleAction>, BRegLifecyclePromotionError> {
        if !authority.matches_record(record) {
            return Err(BRegLifecyclePromotionError::Binding);
        }

        self.actions
            .iter()
            .map(|action| {
                if let Some(proposal_version) = action.proposal_version {
                    if proposal_version != self.proposal_version
                        || action.effect_digest.as_ref() != self.effect_digest.as_ref()
                    {
                        return Err(BRegLifecyclePromotionError::Binding);
                    }
                }
                authority.promote(
                    action,
                    record,
                    self.proposal_version,
                    self.effect_digest.clone(),
                )
            })
            .collect()
    }
}

impl fmt::Debug for BRegRequestMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegRequestMetadata")
            .field("breg_state", &self.breg_state)
            .field("proposal_version", &self.proposal_version)
            .field(
                "effect_digest",
                &self.effect_digest.as_ref().map(|_| "<redacted>"),
            )
            .field("proposal", &self.proposal)
            .field("editable", &self.editable)
            .field("detail_erased", &self.detail_erased)
            .field("action_count", &self.actions.len())
            .field("application", &self.application)
            .field("review", &self.review)
            .field(
                "has_submitter_reference",
                &self.submitter_reference.is_some(),
            )
            .field("has_applier_reference", &self.applier_reference.is_some())
            .field(
                "retained_history",
                &self.retained_history.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq)]
struct InertBRegLifecycleAction {
    operation: BRegLifecycleOperation,
    href: String,
    if_match: String,
    rebase: Option<bool>,
    proposal_version: Option<BRegProposalVersion>,
    effect_digest: Option<BRegEffectDigest>,
}

impl InertBRegLifecycleAction {
    fn from_value(value: Value) -> Result<Self, BRegLifecycleDecodeError> {
        let mut object = exact_object(
            value,
            &["operation", "method", "href", "ifMatch"],
            &["rebase", "proposalVersion", "effectDigest"],
        )?;
        let operation = parse_operation(&take_string(&mut object, "operation")?)?;
        if take_string(&mut object, "method")? != "POST" {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        let href = take_string(&mut object, "href")?;
        validate_relative_action_href(&href)?;
        let if_match = take_string(&mut object, "ifMatch")?;
        if !valid_action_if_match(&if_match) {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        let rebase = match object.remove("rebase") {
            None => None,
            Some(Value::Bool(value)) => Some(value),
            Some(_) => return Err(BRegLifecycleDecodeError::Profile),
        };
        let proposal_version = take_optional_proposal_version(&mut object, "proposalVersion")?;
        let effect_digest = take_optional_digest(&mut object, "effectDigest")?;
        if proposal_version.is_some() != effect_digest.is_some() {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        if operation.requires_proposal_binding()
            && (proposal_version.is_none() || effect_digest.is_none())
        {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        if matches!(operation, BRegLifecycleOperation::ReviseRequest) {
            if rebase.is_none() {
                return Err(BRegLifecycleDecodeError::Profile);
            }
        } else if rebase.is_some() {
            return Err(BRegLifecycleDecodeError::Profile);
        }

        Ok(Self {
            operation,
            href,
            if_match,
            rebase,
            proposal_version,
            effect_digest,
        })
    }
}

impl fmt::Debug for InertBRegLifecycleAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InertBRegLifecycleAction")
            .field("operation", &self.operation)
            .field("href", &"<redacted>")
            .field("if_match", &"<redacted>")
            .field("rebase", &self.rebase)
            .field(
                "proposal_version",
                &self.proposal_version.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "effect_digest",
                &self.effect_digest.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A crate-owned capability handle derived from Registry Metadata v1.
///
/// Its constructors are crate-private so response data cannot manufacture the
/// authority needed to promote its own links.
#[derive(Clone, PartialEq)]
pub struct BRegLifecycleAuthority {
    registry_identifier: String,
    dataset_identifier: String,
    registry_revision: String,
    entity_type_identifier: String,
    access_profile_identifier: String,
    source_binding: String,
    operations: Vec<BRegLifecycleOperationBinding>,
}

impl BRegLifecycleAuthority {
    pub(crate) fn new(
        registry_identifier: String,
        dataset_identifier: String,
        registry_revision: String,
        entity_type_identifier: String,
        access_profile_identifier: String,
        source_binding: String,
        operations: Vec<BRegLifecycleOperationBinding>,
    ) -> Result<Self, BRegLifecyclePromotionError> {
        for identifier in [
            &registry_identifier,
            &dataset_identifier,
            &entity_type_identifier,
            &access_profile_identifier,
        ] {
            validate_identifier(identifier).map_err(|_| BRegLifecyclePromotionError::Authority)?;
        }
        if operations.is_empty() || operations.len() > MAX_BREG_LIFECYCLE_OPERATION_BINDINGS {
            return Err(BRegLifecyclePromotionError::Authority);
        }
        let mut keys = BTreeSet::new();
        for binding in &operations {
            binding.validate()?;
            if !keys.insert(binding.operation) {
                return Err(BRegLifecyclePromotionError::Authority);
            }
        }
        if registry_revision.is_empty()
            || registry_revision.len() > MAX_IDENTIFIER_BYTES
            || source_binding.is_empty()
            || source_binding.len() > MAX_BREG_ACTION_HREF_BYTES
        {
            return Err(BRegLifecyclePromotionError::Authority);
        }
        Ok(Self {
            registry_identifier,
            dataset_identifier,
            registry_revision,
            entity_type_identifier,
            access_profile_identifier,
            source_binding,
            operations,
        })
    }

    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }

    #[must_use]
    pub(crate) fn matches_source(&self, source: &str) -> bool {
        self.source_binding == source
    }

    pub(crate) fn recovery_identity(&self) -> Value {
        json!({
            "registry": self.registry_identifier,
            "dataset": self.dataset_identifier,
            "revision": self.registry_revision,
            "entity": self.entity_type_identifier,
            "profile": self.access_profile_identifier,
        })
    }

    pub(crate) fn matches_recovery_identity(&self, identity: &Value) -> bool {
        *identity == self.recovery_identity()
    }

    pub(crate) fn recover_action(
        &self,
        identity: Value,
        body: &str,
    ) -> Result<BRegLifecycleAction, BRegLifecyclePromotionError> {
        let mut identity = exact_object(
            identity,
            &[
                "operation",
                "href",
                "ifMatch",
                "recordIdentifier",
                "recordRevision",
                "proposalVersion",
            ],
            &["effectDigest", "rebase"],
        )
        .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        let operation = parse_operation(
            &take_string(&mut identity, "operation")
                .map_err(|_| BRegLifecyclePromotionError::Binding)?,
        )
        .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        let href =
            take_string(&mut identity, "href").map_err(|_| BRegLifecyclePromotionError::Binding)?;
        validate_relative_action_href(&href).map_err(|_| BRegLifecyclePromotionError::Binding)?;
        let if_match = take_string(&mut identity, "ifMatch")
            .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        if !valid_action_if_match(&if_match) {
            return Err(BRegLifecyclePromotionError::Binding);
        }
        let record_identifier = take_string(&mut identity, "recordIdentifier")
            .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        validate_canonical_uuid(&record_identifier)
            .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        let record_revision = identity
            .remove("recordRevision")
            .and_then(|value| value.as_u64())
            .filter(|value| *value > 0)
            .ok_or(BRegLifecyclePromotionError::Binding)?;
        let proposal_version = BRegProposalVersion::from_value(
            &identity
                .remove("proposalVersion")
                .ok_or(BRegLifecyclePromotionError::Binding)?,
        )
        .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        let effect_digest = take_optional_digest(&mut identity, "effectDigest")
            .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        let rebase = match identity.remove("rebase") {
            None => None,
            Some(Value::Bool(value)) => Some(value),
            Some(_) => return Err(BRegLifecyclePromotionError::Binding),
        };

        let mut bindings = self
            .operations
            .iter()
            .filter(|binding| binding.operation == operation);
        let binding = bindings
            .next()
            .filter(|_| bindings.next().is_none())
            .ok_or(BRegLifecyclePromotionError::Binding)?;
        if binding.href_for(&record_identifier, &self.access_profile_identifier)? != href {
            return Err(BRegLifecyclePromotionError::Binding);
        }

        let body_value = crate::strict_json::from_slice(body.as_bytes())
            .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        let action_body = recovery_action_body(
            operation,
            proposal_version,
            effect_digest.clone(),
            rebase,
            body_value,
        )?;
        if serde_json::to_string(&action_body).map_err(|_| BRegLifecyclePromotionError::Binding)?
            != body
        {
            return Err(BRegLifecyclePromotionError::Binding);
        }

        Ok(BRegLifecycleAction {
            operation,
            href,
            if_match: BRegActionIfMatch(if_match),
            body: action_body,
            registry_revision: self.registry_revision.clone(),
            source_binding: self.source_binding.clone(),
            record_identifier,
            expected_receipt_revision: record_revision
                .checked_add(1)
                .ok_or(BRegLifecyclePromotionError::Binding)?,
            proposal_version,
            effect_digest,
        })
    }

    fn matches_record(&self, record: &BRegLifecycleRecordBinding) -> bool {
        self.registry_identifier == record.registry_identifier
            && self.dataset_identifier == record.dataset_identifier
            && self.entity_type_identifier == record.entity_type_identifier
    }

    fn promote(
        &self,
        action: &InertBRegLifecycleAction,
        record: &BRegLifecycleRecordBinding,
        proposal_version: BRegProposalVersion,
        effect_digest: Option<BRegEffectDigest>,
    ) -> Result<BRegLifecycleAction, BRegLifecyclePromotionError> {
        let mut matches = self
            .operations
            .iter()
            .filter(|binding| binding.operation == action.operation);
        let binding = matches
            .next()
            .filter(|_| matches.next().is_none())
            .ok_or(BRegLifecyclePromotionError::Binding)?;
        let expected_href =
            binding.href_for(&record.record_identifier, &self.access_profile_identifier)?;
        if expected_href != action.href {
            return Err(BRegLifecyclePromotionError::Binding);
        }

        let body = match action.operation {
            BRegLifecycleOperation::SubmitRequest => BRegLifecycleActionBody::SubmitRequest,
            BRegLifecycleOperation::CancelRequest => BRegLifecycleActionBody::CancelRequest,
            BRegLifecycleOperation::ReviseRequest => BRegLifecycleActionBody::ReviseRequest {
                rebase: action.rebase.ok_or(BRegLifecyclePromotionError::Binding)?,
            },
            BRegLifecycleOperation::ApplyRequest => {
                let proposal_version = action
                    .proposal_version
                    .ok_or(BRegLifecyclePromotionError::Binding)?;
                let effect_digest = action
                    .effect_digest
                    .clone()
                    .ok_or(BRegLifecyclePromotionError::Binding)?;
                BRegLifecycleActionBody::ApplyRequest {
                    proposal_version,
                    effect_digest,
                    reason: None,
                }
            }
        };
        let expected_receipt_revision = record
            .record_revision
            .checked_add(1)
            .ok_or(BRegLifecyclePromotionError::Binding)?;

        Ok(BRegLifecycleAction {
            operation: action.operation,
            href: action.href.clone(),
            if_match: BRegActionIfMatch(action.if_match.clone()),
            body,
            registry_revision: self.registry_revision.clone(),
            source_binding: self.source_binding.clone(),
            record_identifier: record.record_identifier.clone(),
            expected_receipt_revision,
            proposal_version,
            effect_digest,
        })
    }
}

impl fmt::Debug for BRegLifecycleAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLifecycleAuthority")
            .field("registry_identifier", &"<redacted>")
            .field("registry_revision", &"<redacted>")
            .field("entity_type_identifier", &"<redacted>")
            .field("access_profile_identifier", &"<redacted>")
            .field("source_binding", &"<redacted>")
            .field("operation_count", &self.operations.len())
            .finish()
    }
}

/// One metadata-validated lifecycle route. Registry Metadata decoding creates
/// these bindings inside the crate.
#[derive(Clone, PartialEq)]
pub struct BRegLifecycleOperationBinding {
    operation: BRegLifecycleOperation,
    path_template: String,
}

impl BRegLifecycleOperationBinding {
    pub(crate) fn new(operation: BRegLifecycleOperation, path_template: String) -> Self {
        Self {
            operation,
            path_template,
        }
    }

    fn validate(&self) -> Result<(), BRegLifecyclePromotionError> {
        validate_route_template(&self.path_template)
            .map_err(|_| BRegLifecyclePromotionError::Authority)?;
        if !self.path_template.ends_with(self.operation.path_suffix()) {
            return Err(BRegLifecyclePromotionError::Authority);
        }
        Ok(())
    }

    fn href_for(
        &self,
        record_identifier: &str,
        access_profile_identifier: &str,
    ) -> Result<String, BRegLifecyclePromotionError> {
        let path = self.path_template.replace("{record_id}", record_identifier);
        let href = format!(
            "{path}?accessProfile={}",
            percent_encode_query_value(access_profile_identifier)
        );
        if href.len() > MAX_BREG_ACTION_HREF_BYTES {
            return Err(BRegLifecyclePromotionError::Binding);
        }
        Ok(href)
    }
}

impl fmt::Debug for BRegLifecycleOperationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLifecycleOperationBinding")
            .field("operation", &self.operation)
            .field("path_template", &"<redacted>")
            .finish()
    }
}

/// Exact Registry Record envelope binding used during action promotion.
#[derive(Clone, PartialEq)]
pub struct BRegLifecycleRecordBinding {
    registry_identifier: String,
    dataset_identifier: String,
    entity_type_identifier: String,
    record_identifier: String,
    record_revision: u64,
}

impl BRegLifecycleRecordBinding {
    pub(crate) fn from_record(
        meta: &crate::RegistryRecordMeta,
        record: &crate::RegistryRecord,
    ) -> Result<Self, BRegLifecyclePromotionError> {
        Self::new(
            meta.registry_identifier.clone(),
            meta.dataset_identifier.clone(),
            meta.entity_type_identifier.clone(),
            record.record_identifier.clone(),
            record
                .revision_identifier
                .parse::<i64>()
                .ok()
                .filter(|revision| {
                    *revision > 0 && revision.to_string() == record.revision_identifier
                })
                .and_then(|revision| u64::try_from(revision).ok())
                .ok_or(BRegLifecyclePromotionError::Binding)?,
        )
    }

    pub(crate) fn new(
        registry_identifier: String,
        dataset_identifier: String,
        entity_type_identifier: String,
        record_identifier: String,
        record_revision: u64,
    ) -> Result<Self, BRegLifecyclePromotionError> {
        for identifier in [
            &registry_identifier,
            &dataset_identifier,
            &entity_type_identifier,
        ] {
            validate_identifier(identifier).map_err(|_| BRegLifecyclePromotionError::Binding)?;
        }
        validate_canonical_uuid(&record_identifier)
            .map_err(|_| BRegLifecyclePromotionError::Binding)?;
        if record_revision == 0 {
            return Err(BRegLifecyclePromotionError::Binding);
        }
        Ok(Self {
            registry_identifier,
            dataset_identifier,
            entity_type_identifier,
            record_identifier,
            record_revision,
        })
    }
}

impl fmt::Debug for BRegLifecycleRecordBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLifecycleRecordBinding")
            .field("registry_identifier", &"<redacted>")
            .field("dataset_identifier", &"<redacted>")
            .field("entity_type_identifier", &"<redacted>")
            .field("record_identifier", &"<redacted>")
            .field("has_record_revision", &true)
            .finish()
    }
}

/// An action-specific strong `If-Match` value. Debug output is redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegActionIfMatch(String);

impl BRegActionIfMatch {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BRegActionIfMatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegActionIfMatch(<redacted>)")
    }
}

/// A metadata- and record-bound lifecycle action safe to send once.
#[derive(Clone, PartialEq)]
pub struct BRegLifecycleAction {
    operation: BRegLifecycleOperation,
    href: String,
    if_match: BRegActionIfMatch,
    body: BRegLifecycleActionBody,
    registry_revision: String,
    source_binding: String,
    record_identifier: String,
    expected_receipt_revision: u64,
    proposal_version: BRegProposalVersion,
    effect_digest: Option<BRegEffectDigest>,
}

impl BRegLifecycleAction {
    #[must_use]
    pub const fn operation(&self) -> BRegLifecycleOperation {
        self.operation
    }

    /// Returns the exact relative-origin href validated against Registry
    /// Metadata, the selected access profile and the record UUID.
    #[must_use]
    pub fn href(&self) -> &str {
        &self.href
    }

    #[must_use]
    pub fn if_match(&self) -> &BRegActionIfMatch {
        &self.if_match
    }

    #[must_use]
    pub fn body(&self) -> &BRegLifecycleActionBody {
        &self.body
    }

    /// Return a copy carrying a reason on an apply body. Empty text
    /// is permitted; all text is preserved exactly for explicit retry.
    /// Validation performs no token acquisition or I/O.
    pub fn with_reason(&self, reason: impl Into<String>) -> Result<Self, BRegLifecycleActionError> {
        let reason = reason.into();
        if reason.contains('\0') || reason.chars().count() > MAX_BREG_APPLICATION_REASON_CHARACTERS
        {
            return Err(BRegLifecycleActionError::Reason);
        }
        let mut action = self.clone();
        match &mut action.body {
            BRegLifecycleActionBody::ApplyRequest { reason: value, .. } => *value = Some(reason),
            _ => return Err(BRegLifecycleActionError::Reason),
        }
        Ok(action)
    }

    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }

    #[must_use]
    pub(crate) fn matches_source(&self, source: &str) -> bool {
        self.source_binding == source
    }

    pub(crate) fn recovery_identity(&self) -> Value {
        let mut identity = json!({
            "operation": self.operation.identifier(),
            "href": self.href,
            "ifMatch": self.if_match.as_str(),
            "recordIdentifier": self.record_identifier,
            "recordRevision": self.expected_receipt_revision - 1,
            "proposalVersion": self.proposal_version,
        });
        if let Some(effect_digest) = &self.effect_digest {
            identity["effectDigest"] = Value::String(effect_digest.as_str().to_owned());
        }
        if let BRegLifecycleActionBody::ReviseRequest { rebase } = &self.body {
            identity["rebase"] = Value::Bool(*rebase);
        }
        identity
    }

    #[must_use]
    pub(crate) fn matches_record_identifier(&self, record_identifier: &str) -> bool {
        self.record_identifier == record_identifier
    }

    pub(crate) fn accepts_receipt(&self, receipt: &BRegLifecycleActionReceipt) -> bool {
        let request = receipt.request();
        let state_matches = match self.operation {
            BRegLifecycleOperation::SubmitRequest => {
                request.breg_state() == BRegRequestState::Submitted
            }
            BRegLifecycleOperation::ReviseRequest => {
                request.breg_state() == BRegRequestState::Draft
            }
            BRegLifecycleOperation::CancelRequest => {
                request.breg_state() == BRegRequestState::Cancelled
            }
            BRegLifecycleOperation::ApplyRequest => {
                request.breg_state() == BRegRequestState::Applied
            }
        };
        let proposal_matches = match self.operation {
            BRegLifecycleOperation::SubmitRequest => {
                request.proposal_version() == Some(self.proposal_version)
                    && request.effect_digest().is_some()
            }
            BRegLifecycleOperation::ReviseRequest => {
                request.proposal_version().is_some_and(|version| {
                    self.proposal_version
                        .get()
                        .checked_add(1)
                        .is_some_and(|expected| version.get() == expected)
                }) && request.effect_digest().is_none()
            }
            _ => {
                request.proposal_version() == Some(self.proposal_version)
                    && request.effect_digest() == self.effect_digest.as_ref()
            }
        };
        if !self.matches_record_identifier(receipt.record_identifier())
            || receipt.revision() != self.expected_receipt_revision
            || receipt
                .snapshot()
                .strip_prefix("breg1_")
                .is_none_or(|value| validate_canonical_uuid(value).is_err())
            || !state_matches
            || !proposal_matches
        {
            return false;
        }
        match (self.operation, request.application()) {
            (BRegLifecycleOperation::ApplyRequest, Some(application)) => {
                application.proposal_version() == self.proposal_version
                    && Some(application.effect_digest()) == self.effect_digest.as_ref()
            }
            (BRegLifecycleOperation::ApplyRequest, None) => false,
            (_, None) => true,
            (_, Some(_)) => false,
        }
    }
}

impl fmt::Debug for BRegLifecycleAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLifecycleAction")
            .field("operation", &self.operation)
            .field("href", &"<redacted>")
            .field("if_match", &self.if_match)
            .field("body", &self.body)
            .field("registry_revision", &"<redacted>")
            .field("source_binding", &"<redacted>")
            .field("record_identifier", &"<redacted>")
            .field("expected_receipt_revision", &"<redacted>")
            .field("proposal_version", &"<redacted>")
            .field(
                "effect_digest",
                &self.effect_digest.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Exact request body synthesized from one promoted actor action.
#[derive(Clone, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum BRegLifecycleActionBody {
    SubmitRequest,
    ReviseRequest {
        rebase: bool,
    },
    CancelRequest,
    ApplyRequest {
        proposal_version: BRegProposalVersion,
        effect_digest: BRegEffectDigest,
        reason: Option<String>,
    },
}

fn recovery_action_body(
    operation: BRegLifecycleOperation,
    proposal_version: BRegProposalVersion,
    effect_digest: Option<BRegEffectDigest>,
    rebase: Option<bool>,
    supplied: Value,
) -> Result<BRegLifecycleActionBody, BRegLifecyclePromotionError> {
    if (operation.requires_proposal_binding() && effect_digest.is_none())
        || matches!(operation, BRegLifecycleOperation::ReviseRequest) != rebase.is_some()
    {
        return Err(BRegLifecyclePromotionError::Binding);
    }
    let reason = supplied.get("reason").cloned();
    let body = match operation {
        BRegLifecycleOperation::SubmitRequest => BRegLifecycleActionBody::SubmitRequest,
        BRegLifecycleOperation::ReviseRequest => BRegLifecycleActionBody::ReviseRequest {
            rebase: rebase.ok_or(BRegLifecyclePromotionError::Binding)?,
        },
        BRegLifecycleOperation::CancelRequest => BRegLifecycleActionBody::CancelRequest,
        BRegLifecycleOperation::ApplyRequest => BRegLifecycleActionBody::ApplyRequest {
            proposal_version,
            effect_digest: effect_digest.ok_or(BRegLifecyclePromotionError::Binding)?,
            reason: recovery_reason(reason)?,
        },
    };
    if body.to_value() != supplied {
        return Err(BRegLifecyclePromotionError::Binding);
    }
    Ok(body)
}

fn recovery_reason(reason: Option<Value>) -> Result<Option<String>, BRegLifecyclePromotionError> {
    match reason {
        None => Ok(None),
        Some(Value::String(reason))
            if !reason.contains('\0')
                && reason.chars().count() <= MAX_BREG_APPLICATION_REASON_CHARACTERS =>
        {
            Ok(Some(reason))
        }
        Some(_) => Err(BRegLifecyclePromotionError::Binding),
    }
}

impl BRegLifecycleActionBody {
    /// Returns the exact JSON object required by Base Registry Engine.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::SubmitRequest | Self::CancelRequest => json!({}),
            Self::ReviseRequest { rebase } => json!({"rebase": rebase}),
            Self::ApplyRequest {
                proposal_version,
                effect_digest,
                reason,
            } => {
                let mut body =
                    json!({"proposalVersion": proposal_version, "effectDigest": effect_digest});
                if let Some(reason) = reason {
                    body["reason"] = Value::String(reason.clone());
                }
                body
            }
        }
    }
}

impl fmt::Debug for BRegLifecycleActionBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SubmitRequest => "BRegLifecycleActionBody::SubmitRequest",
            Self::ReviseRequest { .. } => "BRegLifecycleActionBody::ReviseRequest(<redacted>)",
            Self::CancelRequest => "BRegLifecycleActionBody::CancelRequest",
            Self::ApplyRequest { .. } => "BRegLifecycleActionBody::ApplyRequest(<redacted>)",
        })
    }
}

impl Serialize for BRegLifecycleActionBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_value().serialize(serializer)
    }
}

/// A distinct successful response for change-request actor actions.
#[derive(Clone, PartialEq)]
pub struct BRegLifecycleActionReceipt {
    record_identifier: String,
    revision: u64,
    snapshot: String,
    actor_reference: Option<String>,
    request: BRegLifecycleReceiptRequest,
}

impl BRegLifecycleActionReceipt {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BRegLifecycleDecodeError> {
        let value =
            crate::strict_json::from_slice(bytes).map_err(|_| BRegLifecycleDecodeError::Json)?;
        Self::from_value(value)
    }

    pub fn from_value(value: Value) -> Result<Self, BRegLifecycleDecodeError> {
        let mut object = exact_object(
            value,
            &["id", "revision", "snapshot", "request"],
            &["actorReference"],
        )?;
        let record_identifier = take_string(&mut object, "id")?;
        validate_canonical_uuid(&record_identifier)?;
        let revision = object
            .remove("revision")
            .and_then(|value| value.as_u64())
            .filter(|revision| *revision > 0)
            .ok_or(BRegLifecycleDecodeError::Profile)?;
        let snapshot = take_string(&mut object, "snapshot")?;
        if snapshot.is_empty()
            || snapshot.len() > MAX_BREG_SNAPSHOT_REFERENCE_BYTES
            || snapshot.chars().any(char::is_control)
        {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        let request = decode_receipt_request(
            object
                .remove("request")
                .ok_or(BRegLifecycleDecodeError::Profile)?,
        )?;
        let actor_reference = take_optional_identifier(&mut object, "actorReference")?;
        Ok(Self {
            record_identifier,
            revision,
            snapshot,
            actor_reference,
            request,
        })
    }

    #[must_use]
    pub fn record_identifier(&self) -> &str {
        &self.record_identifier
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn snapshot(&self) -> &str {
        &self.snapshot
    }

    /// Opaque acting identity correlation. Older compatible servers may omit it.
    #[must_use]
    pub fn actor_reference(&self) -> Option<&str> {
        self.actor_reference.as_deref()
    }

    #[must_use]
    pub fn request(&self) -> &BRegLifecycleReceiptRequest {
        &self.request
    }

    /// Return the exact validated receipt projection for durable attempt and
    /// accountability storage. This contains no credential or record fields.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut value = json!({
            "id": self.record_identifier,
            "revision": self.revision,
            "snapshot": self.snapshot,
            "request": self.request.to_value(),
        });
        if let Some(actor_reference) = &self.actor_reference {
            value["actorReference"] = Value::String(actor_reference.clone());
        }
        value
    }
}

impl fmt::Debug for BRegLifecycleActionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLifecycleActionReceipt")
            .field("record_identifier", &"<redacted>")
            .field("revision", &self.revision)
            .field("snapshot", &"<redacted>")
            .field("has_actor_reference", &self.actor_reference.is_some())
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct BRegLifecycleReceiptRequest {
    breg_state: BRegRequestState,
    proposal_version: Option<BRegProposalVersion>,
    effect_digest: Option<BRegEffectDigest>,
    proposal: Option<BRegRequestProposal>,
    application: Option<BRegLifecycleReceiptApplication>,
}

impl BRegLifecycleReceiptRequest {
    #[must_use]
    pub const fn breg_state(&self) -> BRegRequestState {
        self.breg_state
    }

    #[must_use]
    pub const fn proposal_version(&self) -> Option<BRegProposalVersion> {
        self.proposal_version
    }

    #[must_use]
    pub fn effect_digest(&self) -> Option<&BRegEffectDigest> {
        self.effect_digest.as_ref()
    }

    #[must_use]
    pub fn proposal(&self) -> Option<&BRegRequestProposal> {
        self.proposal.as_ref()
    }

    #[must_use]
    pub fn application(&self) -> Option<&BRegLifecycleReceiptApplication> {
        self.application.as_ref()
    }

    fn to_value(&self) -> Value {
        let mut value = json!({
            "bregState": self.breg_state.identifier(),
            "proposalVersion": self.proposal_version,
            "effectDigest": self.effect_digest,
            "application": self.application.as_ref().map(|application| json!({
                "applicationId": application.application_identifier,
                "proposalVersion": application.proposal_version,
                "effectDigest": application.effect_digest,
                "appliedAt": application.applied_at,
            })),
        });
        if let Some(proposal) = &self.proposal {
            value["proposal"] = json!({
                "review": match &proposal.review {
                    BRegRequestReviewRequirement::None => json!({"mode": "none"}),
                    BRegRequestReviewRequirement::External(requirement) => json!({
                        "authority": requirement.authority,
                        "policyId": requirement.policy_id,
                    }),
                },
            });
        }
        value
    }
}

impl fmt::Debug for BRegLifecycleReceiptRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegLifecycleReceiptRequest")
            .field("breg_state", &self.breg_state)
            .field("proposal_version", &self.proposal_version)
            .field(
                "effect_digest",
                &self.effect_digest.as_ref().map(|_| "<redacted>"),
            )
            .field("proposal", &self.proposal)
            .field("application", &self.application)
            .finish()
    }
}

/// Coarse, value-free Base Registry Engine lifecycle decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BRegLifecycleDecodeError {
    #[error("Base Registry Engine lifecycle response is not valid JSON")]
    Json,
    #[error("Base Registry Engine lifecycle response does not conform")]
    Profile,
}

/// Coarse, value-free lifecycle action input failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BRegLifecycleActionError {
    #[error("Base Registry Engine application reason requires no NUL and at most 4096 Unicode characters")]
    Reason,
}

/// Coarse, value-free action promotion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BRegLifecyclePromotionError {
    #[error("Base Registry Engine lifecycle authority does not conform")]
    Authority,
    #[error("Base Registry Engine lifecycle action is not bound to its authority and record")]
    Binding,
}

fn decode_proposal(value: Value) -> Result<BRegRequestProposal, BRegLifecycleDecodeError> {
    let mut object = exact_object(value, &["review"], &[])?;
    let review = decode_review_requirement(
        object
            .remove("review")
            .ok_or(BRegLifecycleDecodeError::Profile)?,
    )?;
    Ok(BRegRequestProposal { review })
}

pub(crate) fn decode_review_requirement(
    value: Value,
) -> Result<BRegRequestReviewRequirement, BRegLifecycleDecodeError> {
    let Value::Object(mut object) = value else {
        return Err(BRegLifecycleDecodeError::Profile);
    };
    if object.len() == 1 && object.remove("mode") == Some(Value::String("none".to_owned())) {
        return Ok(BRegRequestReviewRequirement::None);
    }
    if object.len() != 2 {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    let authority = take_string(&mut object, "authority")?;
    let policy_id = take_string(&mut object, "policyId")?;
    validate_identifier(&authority)?;
    validate_identifier(&policy_id)?;
    Ok(BRegRequestReviewRequirement::External(
        BRegExternalReviewRequirement {
            authority,
            policy_id,
        },
    ))
}

fn decode_external_review_status(
    value: Value,
) -> Result<BRegExternalReviewStatus, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &[
            "submission",
            "result",
            "delivery",
            "application",
            "recovery",
        ],
        &[],
    )?;
    let submission = decode_external_review_submission(take_required(&mut object, "submission")?)?;
    let result = decode_external_review_result(take_required(&mut object, "result")?)?;
    let delivery = decode_external_review_delivery(take_required(&mut object, "delivery")?)?;
    let application =
        decode_external_review_application(take_required(&mut object, "application")?)?;
    let recovery = decode_external_review_recovery(take_required(&mut object, "recovery")?)?;
    if application.application_id.is_some()
        && application.state != BRegExternalReviewApplicationState::Applied
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(BRegExternalReviewStatus {
        submission,
        result,
        delivery,
        application,
        recovery,
    })
}

fn decode_external_review_submission(
    value: Value,
) -> Result<BRegExternalReviewSubmission, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &["state", "authority"],
        &[
            "requestId",
            "submissionDigest",
            "recoveryDeadline",
            "policy",
        ],
    )?;
    let state = match take_string(&mut object, "state")?.as_str() {
        "pending" => BRegExternalReviewSubmissionState::Pending,
        "accepted" => BRegExternalReviewSubmissionState::Accepted,
        "uncertain" => BRegExternalReviewSubmissionState::Uncertain,
        "cancelling" => BRegExternalReviewSubmissionState::Cancelling,
        "cancelled" => BRegExternalReviewSubmissionState::Cancelled,
        "failed" => BRegExternalReviewSubmissionState::Failed,
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    let authority = take_string(&mut object, "authority")?;
    validate_identifier(&authority)?;
    let request_id = take_optional_uuid(&mut object, "requestId")?;
    let submission_digest = take_optional_digest(&mut object, "submissionDigest")?;
    let recovery_deadline = take_optional_utc_timestamp(&mut object, "recoveryDeadline")?;
    let policy = object
        .remove("policy")
        .map(decode_external_review_policy)
        .transpose()?;
    if request_id.is_some() != submission_digest.is_some()
        || request_id.is_some() != policy.is_some()
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    // The correlation members exist only while the accepted binding survives:
    // an accepted submission always carries them, the binding-less states
    // never do, and the cancellation states keep whichever form their binding
    // retention left them with.
    match state {
        BRegExternalReviewSubmissionState::Accepted if request_id.is_none() => {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        BRegExternalReviewSubmissionState::Pending
        | BRegExternalReviewSubmissionState::Uncertain
        | BRegExternalReviewSubmissionState::Failed
            if request_id.is_some() =>
        {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        _ => {}
    }
    Ok(BRegExternalReviewSubmission {
        state,
        authority,
        request_id,
        submission_digest,
        recovery_deadline,
        policy,
    })
}

fn decode_external_review_policy(
    value: Value,
) -> Result<BRegExternalReviewPolicy, BRegLifecycleDecodeError> {
    let mut object = exact_object(value, &["id", "version", "digest"], &[])?;
    let id = take_string(&mut object, "id")?;
    let version = take_string(&mut object, "version")?;
    validate_identifier(&id)?;
    validate_identifier(&version)?;
    let digest = BRegEffectDigest::parse(&take_string(&mut object, "digest")?)?;
    Ok(BRegExternalReviewPolicy {
        id,
        version,
        digest,
    })
}

fn decode_external_review_result(
    value: Value,
) -> Result<BRegExternalReviewResult, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &["state"],
        &["resultId", "completedAt", "availableUntil"],
    )?;
    let state = match take_string(&mut object, "state")?.as_str() {
        "pending" => BRegExternalReviewResultState::Pending,
        "approved" => BRegExternalReviewResultState::Approved,
        "rejected" => BRegExternalReviewResultState::Rejected,
        "changesRequested" => BRegExternalReviewResultState::ChangesRequested,
        "answered" => BRegExternalReviewResultState::Answered,
        "cancelled" => BRegExternalReviewResultState::Cancelled,
        "superseded" => BRegExternalReviewResultState::Superseded,
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    let result_id = take_optional_uuid(&mut object, "resultId")?;
    let completed_at = take_optional_utc_timestamp(&mut object, "completedAt")?;
    let available_until = take_optional_utc_timestamp(&mut object, "availableUntil")?;
    let terminal = state != BRegExternalReviewResultState::Pending;
    if terminal != (result_id.is_some() && completed_at.is_some() && available_until.is_some())
        || (!terminal
            && (result_id.is_some() || completed_at.is_some() || available_until.is_some()))
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(BRegExternalReviewResult {
        state,
        result_id,
        completed_at,
        available_until,
    })
}

fn decode_external_review_delivery(
    value: Value,
) -> Result<BRegExternalReviewDelivery, BRegLifecycleDecodeError> {
    let mut object = exact_object(value, &["state"], &["eventId", "receivedAt"])?;
    let state = match take_string(&mut object, "state")?.as_str() {
        "polling" => BRegExternalReviewDeliveryState::Polling,
        "received" => BRegExternalReviewDeliveryState::Received,
        "reconciled" => BRegExternalReviewDeliveryState::Reconciled,
        "unmatched" => BRegExternalReviewDeliveryState::Unmatched,
        "exhausted" => BRegExternalReviewDeliveryState::Exhausted,
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    let event_id = take_optional_uuid(&mut object, "eventId")?;
    let received_at = take_optional_utc_timestamp(&mut object, "receivedAt")?;
    let delivered = state != BRegExternalReviewDeliveryState::Polling;
    if delivered != (event_id.is_some() && received_at.is_some())
        || (!delivered && (event_id.is_some() || received_at.is_some()))
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(BRegExternalReviewDelivery {
        state,
        event_id,
        received_at,
    })
}

fn decode_external_review_application(
    value: Value,
) -> Result<BRegExternalReviewApplication, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &["mode", "state"],
        &[
            "executor",
            "applicationId",
            "attempts",
            "nextAttemptAt",
            "receiptRecovered",
        ],
    )?;
    let mode = match take_string(&mut object, "mode")?.as_str() {
        "manual" => BRegExternalReviewApplicationMode::Manual,
        "automatic" => BRegExternalReviewApplicationMode::Automatic,
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    let state = match take_string(&mut object, "state")?.as_str() {
        "awaitingReview" => BRegExternalReviewApplicationState::AwaitingReview,
        "ready" => BRegExternalReviewApplicationState::Ready,
        "queued" => BRegExternalReviewApplicationState::Queued,
        "applying" => BRegExternalReviewApplicationState::Applying,
        "applied" => BRegExternalReviewApplicationState::Applied,
        "blocked" => BRegExternalReviewApplicationState::Blocked,
        "expired" => BRegExternalReviewApplicationState::Expired,
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    let executor = take_optional_identifier(&mut object, "executor")?;
    if (mode == BRegExternalReviewApplicationMode::Automatic) != executor.is_some() {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    let application_id = take_optional_uuid(&mut object, "applicationId")?;
    let attempts = match object.remove("attempts") {
        None => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value <= 1000)
                .ok_or(BRegLifecycleDecodeError::Profile)?,
        ),
    };
    let next_attempt_at = take_optional_utc_timestamp(&mut object, "nextAttemptAt")?;
    let receipt_recovered = match object.remove("receiptRecovered") {
        None => false,
        Some(Value::Bool(true))
            if mode == BRegExternalReviewApplicationMode::Automatic
                && state == BRegExternalReviewApplicationState::Applied
                && application_id.is_some() =>
        {
            true
        }
        Some(_) => return Err(BRegLifecycleDecodeError::Profile),
    };
    if (next_attempt_at.is_some() && attempts.is_none())
        || (mode == BRegExternalReviewApplicationMode::Manual
            && (attempts.is_some() || next_attempt_at.is_some()))
        || (next_attempt_at.is_some()
            && !matches!(
                state,
                BRegExternalReviewApplicationState::Queued
                    | BRegExternalReviewApplicationState::Applying
            ))
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(BRegExternalReviewApplication {
        mode,
        state,
        executor,
        application_id,
        attempts,
        next_attempt_at,
        receipt_recovered,
    })
}

fn decode_external_review_recovery(
    value: Value,
) -> Result<BRegExternalReviewRecovery, BRegLifecycleDecodeError> {
    let mut object = exact_object(value, &["state"], &["code"])?;
    let state = match take_string(&mut object, "state")?.as_str() {
        "none" => BRegExternalReviewRecoveryState::None,
        "operatorAttention" => BRegExternalReviewRecoveryState::OperatorAttention,
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    let code = take_optional_identifier(&mut object, "code")?;
    if state == BRegExternalReviewRecoveryState::None && code.is_some() {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(BRegExternalReviewRecovery { state, code })
}
fn decode_retained_application(
    value: Value,
) -> Result<BRegRetainedApplication, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &["applicationId", "proposalVersion", "appliedAt"],
        &["effectDigest", "reasonPresent", "reason"],
    )?;
    let application_identifier = take_string(&mut object, "applicationId")?;
    validate_canonical_uuid(&application_identifier)?;
    let proposal_version = BRegProposalVersion::from_value(
        &object
            .remove("proposalVersion")
            .ok_or(BRegLifecycleDecodeError::Profile)?,
    )?;
    let effect_digest = take_optional_digest(&mut object, "effectDigest")?;
    let applied_at = take_string(&mut object, "appliedAt")?;
    validate_timestamp(&applied_at)?;
    let reason_present = match object.remove("reasonPresent") {
        None => false,
        Some(Value::Bool(value)) => value,
        Some(_) => return Err(BRegLifecycleDecodeError::Profile),
    };
    let reason = match object.remove("reason") {
        None => None,
        Some(Value::String(reason))
            if reason_present
                && !reason.contains('\0')
                && reason.chars().count() <= MAX_BREG_APPLICATION_REASON_CHARACTERS =>
        {
            Some(reason)
        }
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    Ok(BRegRetainedApplication {
        application_identifier,
        proposal_version,
        effect_digest,
        applied_at,
        reason_present,
        reason,
    })
}

fn decode_retained_history(
    value: Value,
) -> Result<BRegRetainedRequestHistoryPage, BRegLifecycleDecodeError> {
    let mut object = exact_object(value, &["proposals", "nextAfterProposalVersion"], &[])?;
    let proposals = match object.remove("proposals") {
        Some(Value::Array(proposals)) if proposals.len() <= MAX_BREG_RETAINED_PROPOSALS => {
            proposals
                .into_iter()
                .map(decode_retained_proposal)
                .collect::<Result<Vec<_>, _>>()?
        }
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    let next_after_proposal_version = match object.remove("nextAfterProposalVersion") {
        Some(Value::Null) => None,
        Some(value) => Some(BRegProposalVersion::from_value(&value)?),
        None => return Err(BRegLifecycleDecodeError::Profile),
    };

    let mut request_identity = None;
    let mut previous_version = None;
    let mut current_count = 0_usize;
    for proposal in &proposals {
        let identity = (
            proposal.request_entity_identifier.as_str(),
            proposal.request_identifier,
        );
        if request_identity.is_some_and(|expected| expected != identity) {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        request_identity = Some(identity);
        if previous_version.is_some_and(|version| version >= proposal.proposal_version) {
            return Err(BRegLifecycleDecodeError::Profile);
        }
        previous_version = Some(proposal.proposal_version);
        current_count += usize::from(proposal.current);
    }
    if current_count > 1
        || next_after_proposal_version.is_some_and(|cursor| {
            proposals
                .last()
                .is_none_or(|proposal| proposal.proposal_version != cursor)
        })
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }

    Ok(BRegRetainedRequestHistoryPage {
        proposals,
        next_after_proposal_version,
    })
}

fn decode_retained_proposal(
    value: Value,
) -> Result<BRegRetainedRequestProposal, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &[
            "requestEntityId",
            "requestId",
            "proposalVersion",
            "bregState",
            "current",
            "contractFingerprint",
            "detailErased",
            "applicationId",
            "resultLinkCount",
            "resultLinks",
        ],
        &["effectDigest"],
    )?;
    let request_entity_identifier = take_string(&mut object, "requestEntityId")?;
    validate_identifier(&request_entity_identifier)?;
    let request_identifier = take_string(&mut object, "requestId")?;
    validate_canonical_uuid(&request_identifier)?;
    let request_identifier =
        Uuid::parse_str(&request_identifier).map_err(|_| BRegLifecycleDecodeError::Profile)?;
    let proposal_version = BRegProposalVersion::from_value(
        &object
            .remove("proposalVersion")
            .ok_or(BRegLifecycleDecodeError::Profile)?,
    )?;
    let breg_state = BRegRequestState::parse(&take_string(&mut object, "bregState")?)
        .ok_or(BRegLifecycleDecodeError::Profile)?;
    let current = object
        .remove("current")
        .and_then(|value| value.as_bool())
        .ok_or(BRegLifecycleDecodeError::Profile)?;
    let contract_fingerprint = take_string(&mut object, "contractFingerprint")?;
    validate_identifier(&contract_fingerprint)?;
    let detail_erased = object
        .remove("detailErased")
        .and_then(|value| value.as_bool())
        .ok_or(BRegLifecycleDecodeError::Profile)?;
    let application_identifier = match object.remove("applicationId") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => {
            validate_canonical_uuid(&value)?;
            Some(Uuid::parse_str(&value).map_err(|_| BRegLifecycleDecodeError::Profile)?)
        }
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    let result_link_count = object
        .remove("resultLinkCount")
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| usize::from(*value) <= MAX_BREG_REQUEST_RESULT_REFERENCES)
        .ok_or(BRegLifecycleDecodeError::Profile)?;
    let result_references = match object.remove("resultLinks") {
        Some(Value::Array(values)) if values.len() <= MAX_BREG_REQUEST_RESULT_REFERENCES => values
            .into_iter()
            .map(decode_request_result_reference)
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(BRegLifecycleDecodeError::Profile),
    };
    if usize::from(result_link_count) != result_references.len()
        || application_identifier.is_none() && !result_references.is_empty()
        || application_identifier.is_some() && !matches!(breg_state, BRegRequestState::Applied)
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    let effect_digest = take_optional_digest(&mut object, "effectDigest")?;
    Ok(BRegRetainedRequestProposal {
        request_entity_identifier,
        request_identifier,
        proposal_version,
        breg_state,
        current,
        contract_fingerprint,
        detail_erased,
        application_identifier,
        result_link_count,
        result_references,
        effect_digest,
    })
}

fn decode_request_result_reference(
    value: Value,
) -> Result<BRegRequestResultReference, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &["targetEntityId", "targetRecordId", "targetRevision"],
        &[],
    )?;
    let target_entity_identifier = take_string(&mut object, "targetEntityId")?;
    validate_identifier(&target_entity_identifier)?;
    let target_record_identifier = take_string(&mut object, "targetRecordId")?;
    validate_canonical_uuid(&target_record_identifier)?;
    let target_record_identifier = Uuid::parse_str(&target_record_identifier)
        .map_err(|_| BRegLifecycleDecodeError::Profile)?;
    let target_revision = object
        .remove("targetRevision")
        .and_then(|value| value.as_u64())
        .filter(|value| *value > 0 && *value <= 9_007_199_254_740_991)
        .ok_or(BRegLifecycleDecodeError::Profile)?;
    Ok(BRegRequestResultReference {
        target_entity_identifier,
        target_record_identifier,
        target_revision,
    })
}

fn decode_receipt_application(
    value: Value,
) -> Result<BRegLifecycleReceiptApplication, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &[
            "applicationId",
            "proposalVersion",
            "effectDigest",
            "appliedAt",
        ],
        &[],
    )?;
    let application_identifier = take_string(&mut object, "applicationId")?;
    validate_canonical_uuid(&application_identifier)?;
    let proposal_version = BRegProposalVersion::from_value(
        &object
            .remove("proposalVersion")
            .ok_or(BRegLifecycleDecodeError::Profile)?,
    )?;
    let effect_digest = BRegEffectDigest::parse(&take_string(&mut object, "effectDigest")?)?;
    let applied_at = take_string(&mut object, "appliedAt")?;
    validate_timestamp(&applied_at)?;
    Ok(BRegLifecycleReceiptApplication {
        application_identifier,
        proposal_version,
        effect_digest,
        applied_at,
    })
}

fn decode_erased_application(
    value: Value,
) -> Result<BRegErasedApplication, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &["applicationId", "proposalVersion"],
        &["reasonPresent"],
    )?;
    let application_identifier = take_string(&mut object, "applicationId")?;
    validate_canonical_uuid(&application_identifier)?;
    let proposal_version = BRegProposalVersion::from_value(
        &object
            .remove("proposalVersion")
            .ok_or(BRegLifecycleDecodeError::Profile)?,
    )?;
    let reason_present = match object.remove("reasonPresent") {
        None => false,
        Some(Value::Bool(value)) => value,
        Some(_) => return Err(BRegLifecycleDecodeError::Profile),
    };
    Ok(BRegErasedApplication {
        application_identifier,
        proposal_version,
        reason_present,
    })
}

fn decode_receipt_request(
    value: Value,
) -> Result<BRegLifecycleReceiptRequest, BRegLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &[
            "bregState",
            "proposalVersion",
            "effectDigest",
            "application",
        ],
        &["proposal"],
    )?;
    let breg_state = BRegRequestState::parse(&take_string(&mut object, "bregState")?)
        .ok_or(BRegLifecycleDecodeError::Profile)?;
    let proposal_version = take_optional_proposal_version(&mut object, "proposalVersion")?;
    let effect_digest = take_optional_digest(&mut object, "effectDigest")?;
    let proposal = match object.remove("proposal") {
        None => None,
        Some(Value::Null) => None,
        Some(value) => Some(decode_proposal(value)?),
    };
    let application = match object.remove("application") {
        Some(Value::Null) => None,
        Some(value) => Some(decode_receipt_application(value)?),
        None => return Err(BRegLifecycleDecodeError::Profile),
    };
    Ok(BRegLifecycleReceiptRequest {
        breg_state,
        proposal_version,
        effect_digest,
        proposal,
        application,
    })
}

fn exact_object(
    value: Value,
    required: &[&str],
    optional: &[&str],
) -> Result<Map<String, Value>, BRegLifecycleDecodeError> {
    let Value::Object(object) = value else {
        return Err(BRegLifecycleDecodeError::Profile);
    };
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(object)
}

fn take_string(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<String, BRegLifecycleDecodeError> {
    object
        .remove(member)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(BRegLifecycleDecodeError::Profile)
}

fn take_required(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Value, BRegLifecycleDecodeError> {
    object
        .remove(member)
        .ok_or(BRegLifecycleDecodeError::Profile)
}

fn take_optional_identifier(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<String>, BRegLifecycleDecodeError> {
    match object.remove(member) {
        None => Ok(None),
        Some(Value::String(value)) => {
            validate_identifier(&value)?;
            Ok(Some(value))
        }
        Some(_) => Err(BRegLifecycleDecodeError::Profile),
    }
}

fn take_optional_uuid(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<String>, BRegLifecycleDecodeError> {
    match object.remove(member) {
        None => Ok(None),
        Some(Value::String(value)) => {
            validate_canonical_uuid(&value)?;
            Ok(Some(value))
        }
        Some(_) => Err(BRegLifecycleDecodeError::Profile),
    }
}

fn take_optional_utc_timestamp(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<String>, BRegLifecycleDecodeError> {
    match object.remove(member) {
        None => Ok(None),
        Some(Value::String(value)) => {
            validate_utc_timestamp(&value)?;
            Ok(Some(value))
        }
        Some(_) => Err(BRegLifecycleDecodeError::Profile),
    }
}

fn take_optional_proposal_version(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<BRegProposalVersion>, BRegLifecycleDecodeError> {
    match object.remove(member) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => BRegProposalVersion::from_value(&value).map(Some),
    }
}

fn take_optional_digest(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<BRegEffectDigest>, BRegLifecycleDecodeError> {
    match object.remove(member) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => BRegEffectDigest::parse(&value).map(Some),
        Some(_) => Err(BRegLifecycleDecodeError::Profile),
    }
}

fn parse_operation(value: &str) -> Result<BRegLifecycleOperation, BRegLifecycleDecodeError> {
    BRegLifecycleOperation::ALL
        .into_iter()
        .find(|operation| operation.identifier() == value)
        .ok_or(BRegLifecycleDecodeError::Profile)
}

fn reject_duplicate_action_bindings(
    actions: &[InertBRegLifecycleAction],
) -> Result<(), BRegLifecycleDecodeError> {
    let mut keys = BTreeSet::new();
    for action in actions {
        if !keys.insert(action.operation) {
            return Err(BRegLifecycleDecodeError::Profile);
        }
    }
    Ok(())
}

fn valid_effect_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn valid_action_if_match(value: &str) -> bool {
    value.len() > 12
        && value.len() <= 256
        && value.starts_with("\"breg-action-")
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

fn validate_identifier(value: &str) -> Result<(), BRegLifecycleDecodeError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn validate_canonical_uuid(value: &str) -> Result<(), BRegLifecycleDecodeError> {
    let parsed = Uuid::parse_str(value).map_err(|_| BRegLifecycleDecodeError::Profile)?;
    if parsed.hyphenated().to_string() != value {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), BRegLifecycleDecodeError> {
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(|_| ())
        .map_err(|_| BRegLifecycleDecodeError::Profile)
}

fn validate_utc_timestamp(value: &str) -> Result<(), BRegLifecycleDecodeError> {
    validate_timestamp(value)?;
    let parsed = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| BRegLifecycleDecodeError::Profile)?;
    if parsed.offset() != time::UtcOffset::UTC {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn validate_relative_action_href(href: &str) -> Result<(), BRegLifecycleDecodeError> {
    if href.is_empty()
        || href.len() > MAX_BREG_ACTION_HREF_BYTES
        || !href.starts_with('/')
        || href.starts_with("//")
        || href.chars().any(char::is_control)
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    let base =
        Url::parse("https://registry.invalid/").map_err(|_| BRegLifecycleDecodeError::Profile)?;
    let parsed = base
        .join(href)
        .map_err(|_| BRegLifecycleDecodeError::Profile)?;
    if parsed.origin() != base.origin()
        || parsed.fragment().is_some()
        || parsed.username() != ""
        || parsed.password().is_some()
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    let mut query = parsed.query_pairs();
    let Some((name, value)) = query.next() else {
        return Err(BRegLifecycleDecodeError::Profile);
    };
    if name != "accessProfile" || value.is_empty() || query.next().is_some() {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn validate_route_template(path: &str) -> Result<(), BRegLifecycleDecodeError> {
    if path.is_empty()
        || path.len() > MAX_BREG_ACTION_HREF_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('?')
        || path.contains('#')
        || path.chars().any(char::is_control)
        || path.matches("{record_id}").count() != 1
        || path.contains("..")
    {
        return Err(BRegLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn percent_encode_query_value(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}
