//! Inert Registry Server change-request annotations and promoted actor actions.
//!
//! A record's `request.actions` member is advisory, caller-specific data. It is
//! decoded without granting execution authority. An action becomes executable
//! only after [`RegistryServerRequestMetadata::promote_actions`] binds it to a
//! crate-owned, validated Registry Metadata handle and the exact record
//! envelope from which it was read.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Serialize, Serializer};
use serde_json::{json, Map, Value};
use url::Url;
use uuid::Uuid;

/// Maximum actor-action links accepted on one record.
pub const MAX_REGISTRY_SERVER_REQUEST_ACTIONS: usize = 64;
/// Maximum lifecycle operation bindings in metadata. Thirty-two review stages
/// can each expose three decisions, plus the four non-stage transitions.
pub const MAX_REGISTRY_SERVER_LIFECYCLE_OPERATION_BINDINGS: usize = 100;
/// Maximum targets accepted in one review preview.
pub const MAX_REGISTRY_SERVER_REVIEW_TARGETS: usize = 16;
/// Maximum fields accepted in a review target's `before` or `after` object.
pub const MAX_REGISTRY_SERVER_REVIEW_OBJECT_MEMBERS: usize = 128;
/// Maximum bytes accepted for one actor-action href.
pub const MAX_REGISTRY_SERVER_ACTION_HREF_BYTES: usize = 2_048;
/// Maximum bytes accepted for an opaque snapshot reference.
pub const MAX_REGISTRY_SERVER_SNAPSHOT_REFERENCE_BYTES: usize = 4_096;

const MAX_REQUEST_EXTENSION_BYTES: usize = 2_097_152;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_TIMESTAMP_BYTES: usize = 128;

/// One of Registry Server's closed change-request lifecycle operations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RegistryServerLifecycleOperation {
    SubmitRequest,
    ApproveRequest,
    RejectRequest,
    RequestRevision,
    ReviseRequest,
    CancelRequest,
    ApplyRequest,
}

impl RegistryServerLifecycleOperation {
    /// All supported lifecycle operations, in workflow order.
    pub const ALL: [Self; 7] = [
        Self::SubmitRequest,
        Self::ApproveRequest,
        Self::RejectRequest,
        Self::RequestRevision,
        Self::ReviseRequest,
        Self::CancelRequest,
        Self::ApplyRequest,
    ];

    /// Returns the exact Registry Metadata and record-link identifier.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::SubmitRequest => "submit_request",
            Self::ApproveRequest => "approve_request",
            Self::RejectRequest => "reject_request",
            Self::RequestRevision => "request_revision",
            Self::ReviseRequest => "revise_request",
            Self::CancelRequest => "cancel_request",
            Self::ApplyRequest => "apply_request",
        }
    }

    const fn is_review(self) -> bool {
        matches!(
            self,
            Self::ApproveRequest | Self::RejectRequest | Self::RequestRevision
        )
    }

    const fn requires_proposal_binding(self) -> bool {
        self.is_review() || matches!(self, Self::ApplyRequest)
    }

    const fn path_suffix(self) -> &'static str {
        match self {
            Self::SubmitRequest => "/actions/submit",
            Self::ApproveRequest => "/approve",
            Self::RejectRequest => "/reject",
            Self::RequestRevision => "/request-revision",
            Self::ReviseRequest => "/actions/revise",
            Self::CancelRequest => "/actions/cancel",
            Self::ApplyRequest => "/actions/apply",
        }
    }
}

/// Registry Server's closed request workflow state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryServerRequestState {
    Draft,
    Submitted,
    Approved,
    NeedsChanges,
    Rejected,
    Canceled,
    Applied,
}

/// Closed review policy frozen into a visible change-request proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryServerRequestReviewMode {
    None,
    Staged,
}

impl RegistryServerRequestReviewMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "staged" => Some(Self::Staged),
            _ => None,
        }
    }
}

/// Closed application disposition frozen into a visible proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryServerRequestApplicationDisposition {
    Apply,
    Queue,
}

impl RegistryServerRequestApplicationDisposition {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "apply" => Some(Self::Apply),
            "queue" => Some(Self::Queue),
            _ => None,
        }
    }
}

/// A finite, compiled queue reason carried by a visible proposal.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryServerRequestQueueReason {
    code: String,
    label: String,
}

impl RegistryServerRequestQueueReason {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl fmt::Debug for RegistryServerRequestQueueReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerRequestQueueReason")
            .field("code", &self.code)
            .field("label", &"<redacted>")
            .finish()
    }
}

/// Frozen, caller-visible planning policy for the current proposal.
///
/// This is descriptive only. It cannot grant a lifecycle action or cause the
/// client to infer that an automatic application is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryServerRequestProposal {
    review_mode: RegistryServerRequestReviewMode,
    application_disposition: RegistryServerRequestApplicationDisposition,
    queue_reason: Option<RegistryServerRequestQueueReason>,
}

impl RegistryServerRequestProposal {
    #[must_use]
    pub const fn review_mode(&self) -> RegistryServerRequestReviewMode {
        self.review_mode
    }

    #[must_use]
    pub const fn application_disposition(&self) -> RegistryServerRequestApplicationDisposition {
        self.application_disposition
    }

    #[must_use]
    pub fn queue_reason(&self) -> Option<&RegistryServerRequestQueueReason> {
        self.queue_reason.as_ref()
    }
}

impl RegistryServerRequestState {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "draft" => Some(Self::Draft),
            "submitted" => Some(Self::Submitted),
            "approved" => Some(Self::Approved),
            "needs_changes" => Some(Self::NeedsChanges),
            "rejected" => Some(Self::Rejected),
            "canceled" => Some(Self::Canceled),
            "applied" => Some(Self::Applied),
            _ => None,
        }
    }
}

/// A positive change-request proposal version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegistryServerProposalVersion(u32);

impl RegistryServerProposalVersion {
    fn from_value(value: &Value) -> Result<Self, RegistryServerLifecycleDecodeError> {
        value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .map(Self)
            .ok_or(RegistryServerLifecycleDecodeError::Profile)
    }

    /// Returns the positive integer version.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Serialize for RegistryServerProposalVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

/// An exact lowercase SHA-256 proposal digest.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryServerEffectDigest(String);

impl RegistryServerEffectDigest {
    fn parse(value: &str) -> Result<Self, RegistryServerLifecycleDecodeError> {
        if valid_effect_digest(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(RegistryServerLifecycleDecodeError::Profile)
        }
    }

    /// Returns the header- and body-safe digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RegistryServerEffectDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryServerEffectDigest(<redacted>)")
    }
}

impl Serialize for RegistryServerEffectDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

/// Retained application metadata on a normal request record.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryServerRetainedApplication {
    application_identifier: String,
    proposal_version: RegistryServerProposalVersion,
    effect_digest: Option<RegistryServerEffectDigest>,
    applied_at: String,
}

impl RegistryServerRetainedApplication {
    /// Returns the canonical application UUID.
    #[must_use]
    pub fn application_identifier(&self) -> &str {
        &self.application_identifier
    }

    #[must_use]
    pub const fn proposal_version(&self) -> RegistryServerProposalVersion {
        self.proposal_version
    }

    #[must_use]
    pub fn effect_digest(&self) -> Option<&RegistryServerEffectDigest> {
        self.effect_digest.as_ref()
    }

    #[must_use]
    pub fn applied_at(&self) -> &str {
        &self.applied_at
    }
}

impl fmt::Debug for RegistryServerRetainedApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerRetainedApplication")
            .field("application_identifier", &"<redacted>")
            .field("proposal_version", &self.proposal_version)
            .field("effect_digest", &"<redacted>")
            .field("applied_at", &"<redacted>")
            .finish()
    }
}

/// Full application receipt returned only by a successful lifecycle action.
/// Record projections may omit the digest, but action receipts may not.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryServerLifecycleReceiptApplication {
    application_identifier: String,
    proposal_version: RegistryServerProposalVersion,
    effect_digest: RegistryServerEffectDigest,
    applied_at: String,
}

impl RegistryServerLifecycleReceiptApplication {
    #[must_use]
    pub fn application_identifier(&self) -> &str {
        &self.application_identifier
    }

    #[must_use]
    pub const fn proposal_version(&self) -> RegistryServerProposalVersion {
        self.proposal_version
    }

    #[must_use]
    pub fn effect_digest(&self) -> &RegistryServerEffectDigest {
        &self.effect_digest
    }

    #[must_use]
    pub fn applied_at(&self) -> &str {
        &self.applied_at
    }
}

impl fmt::Debug for RegistryServerLifecycleReceiptApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerLifecycleReceiptApplication")
            .field("application_identifier", &"<redacted>")
            .field("proposal_version", &self.proposal_version)
            .field("effect_digest", &"<redacted>")
            .field("applied_at", &"<redacted>")
            .finish()
    }
}

/// The minimal application provenance stub retained after detail erasure.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryServerErasedApplication {
    application_identifier: String,
    proposal_version: RegistryServerProposalVersion,
}

impl RegistryServerErasedApplication {
    #[must_use]
    pub fn application_identifier(&self) -> &str {
        &self.application_identifier
    }

    #[must_use]
    pub const fn proposal_version(&self) -> RegistryServerProposalVersion {
        self.proposal_version
    }
}

impl fmt::Debug for RegistryServerErasedApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerErasedApplication")
            .field("application_identifier", &"<redacted>")
            .field("proposal_version", &self.proposal_version)
            .finish()
    }
}

/// Application metadata whose shape is bound to request-detail retention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryServerRecordApplication {
    Retained(RegistryServerRetainedApplication),
    Erased(RegistryServerErasedApplication),
}

/// A review preview for a caller-authorized lifecycle decision.
#[derive(Clone, PartialEq)]
pub struct RegistryServerRequestReview {
    targets: Vec<RegistryServerRequestReviewTarget>,
}

impl RegistryServerRequestReview {
    #[must_use]
    pub fn targets(&self) -> &[RegistryServerRequestReviewTarget] {
        &self.targets
    }
}

impl fmt::Debug for RegistryServerRequestReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerRequestReview")
            .field("target_count", &self.targets.len())
            .finish()
    }
}

/// A create or patch target preview. Field values are inert and never used as
/// mutation authority by this client.
#[derive(Clone, PartialEq)]
pub struct RegistryServerRequestReviewTarget {
    entity_identifier: String,
    record_identifier: String,
    operation: RegistryServerReviewOperation,
    base_revision: Option<u64>,
    before: Option<BTreeMap<String, Value>>,
    after: BTreeMap<String, Value>,
}

impl RegistryServerRequestReviewTarget {
    #[must_use]
    pub fn entity_identifier(&self) -> &str {
        &self.entity_identifier
    }

    #[must_use]
    pub fn record_identifier(&self) -> &str {
        &self.record_identifier
    }

    #[must_use]
    pub const fn operation(&self) -> RegistryServerReviewOperation {
        self.operation
    }

    #[must_use]
    pub const fn base_revision(&self) -> Option<u64> {
        self.base_revision
    }

    #[must_use]
    pub fn before(&self) -> Option<&BTreeMap<String, Value>> {
        self.before.as_ref()
    }

    #[must_use]
    pub fn after(&self) -> &BTreeMap<String, Value> {
        &self.after
    }
}

impl fmt::Debug for RegistryServerRequestReviewTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerRequestReviewTarget")
            .field("entity_identifier", &"<redacted>")
            .field("record_identifier", &"<redacted>")
            .field("operation", &self.operation)
            .field("base_revision", &self.base_revision)
            .field(
                "before_member_count",
                &self.before.as_ref().map(BTreeMap::len),
            )
            .field("after_member_count", &self.after.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryServerReviewOperation {
    Create,
    Patch,
}

/// Validated but inert change-request metadata extracted from a Registry
/// Record. Its action links cannot be executed until promoted.
#[derive(Clone, PartialEq)]
pub struct RegistryServerRequestMetadata {
    server_state: RegistryServerRequestState,
    proposal_version: RegistryServerProposalVersion,
    effect_digest: Option<RegistryServerEffectDigest>,
    proposal: Option<RegistryServerRequestProposal>,
    editable: bool,
    detail_erased: bool,
    actions: Vec<InertRegistryServerLifecycleAction>,
    application: Option<RegistryServerRecordApplication>,
    retained_history: Option<Value>,
}

impl RegistryServerRequestMetadata {
    /// Extracts Registry Server request annotations from a shared Registry
    /// Record. Absence means the record is not a visible change request.
    pub fn from_record(
        record: &crate::RegistryRecord,
    ) -> Result<Option<Self>, RegistryServerLifecycleDecodeError> {
        record
            .extensions
            .get("request")
            .cloned()
            .map(|value| Self::from_value(value, record.domain_data.is_empty()))
            .transpose()
    }

    /// Decodes a record's `request` extension under the exact Registry Server
    /// response contract.
    ///
    /// `domain_data_is_empty` must be derived from the containing Registry
    /// Record. An erased-detail marker is refused while domain data remains.
    pub fn from_value(
        value: Value,
        domain_data_is_empty: bool,
    ) -> Result<Self, RegistryServerLifecycleDecodeError> {
        if serde_json::to_vec(&value)
            .map_err(|_| RegistryServerLifecycleDecodeError::Profile)?
            .len()
            > MAX_REQUEST_EXTENSION_BYTES
        {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }
        let mut object = exact_object(
            value,
            &["serverState", "proposalVersion", "editable"],
            &[
                "effectDigest",
                "proposal",
                "detailErased",
                "actions",
                "application",
                "history",
            ],
        )?;

        let server_state = take_string(&mut object, "serverState").and_then(|value| {
            RegistryServerRequestState::parse(&value)
                .ok_or(RegistryServerLifecycleDecodeError::Profile)
        })?;
        let proposal_version = RegistryServerProposalVersion::from_value(
            &object
                .remove("proposalVersion")
                .ok_or(RegistryServerLifecycleDecodeError::Profile)?,
        )?;
        let editable = object
            .remove("editable")
            .and_then(|value| value.as_bool())
            .ok_or(RegistryServerLifecycleDecodeError::Profile)?;
        let effect_digest = take_optional_digest(&mut object, "effectDigest")?;
        let proposal = match object.remove("proposal") {
            None | Some(Value::Null) => None,
            Some(value) => Some(decode_proposal(value)?),
        };
        let detail_erased = match object.remove("detailErased") {
            None => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(RegistryServerLifecycleDecodeError::Profile),
        };
        if detail_erased && (!domain_data_is_empty || editable) {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }

        let actions = match object.remove("actions") {
            None => Vec::new(),
            Some(Value::Array(values)) if values.len() <= MAX_REGISTRY_SERVER_REQUEST_ACTIONS => {
                values
                    .into_iter()
                    .map(InertRegistryServerLifecycleAction::from_value)
                    .collect::<Result<Vec<_>, _>>()?
            }
            Some(_) => return Err(RegistryServerLifecycleDecodeError::Profile),
        };
        if detail_erased && !actions.is_empty() {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }
        reject_duplicate_action_bindings(&actions)?;

        let application = match object.remove("application") {
            None | Some(Value::Null) => None,
            Some(value) if detail_erased => Some(RegistryServerRecordApplication::Erased(
                decode_erased_application(value)?,
            )),
            Some(value) => Some(RegistryServerRecordApplication::Retained(
                decode_retained_application(value)?,
            )),
        };
        let retained_history = match object.remove("history") {
            None => None,
            Some(Value::Object(history)) => Some(Value::Object(history)),
            Some(_) => return Err(RegistryServerLifecycleDecodeError::Profile),
        };

        Ok(Self {
            server_state,
            proposal_version,
            effect_digest,
            proposal,
            editable,
            detail_erased,
            actions,
            application,
            retained_history,
        })
    }

    #[must_use]
    pub const fn server_state(&self) -> RegistryServerRequestState {
        self.server_state
    }

    #[must_use]
    pub const fn proposal_version(&self) -> RegistryServerProposalVersion {
        self.proposal_version
    }

    #[must_use]
    pub fn effect_digest(&self) -> Option<&RegistryServerEffectDigest> {
        self.effect_digest.as_ref()
    }

    /// Returns the frozen current-proposal policy, if this request has one.
    #[must_use]
    pub fn proposal(&self) -> Option<&RegistryServerRequestProposal> {
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
    pub fn application(&self) -> Option<&RegistryServerRecordApplication> {
        self.application.as_ref()
    }

    /// Returns retained history as inert JSON. It is never consulted for
    /// lifecycle execution.
    #[must_use]
    pub fn retained_history(&self) -> Option<&Value> {
        self.retained_history.as_ref()
    }

    /// Returns the advertised operation identifiers without exposing hrefs or
    /// preconditions as executable authority.
    pub fn advertised_operations(
        &self,
    ) -> impl Iterator<Item = RegistryServerLifecycleOperation> + '_ {
        self.actions.iter().map(|action| action.operation)
    }

    /// Promotes every advisory action only after exact Registry Metadata,
    /// selected-profile, record, route, stage, href and precondition binding.
    pub fn promote_actions(
        &self,
        authority: &RegistryServerLifecycleAuthority,
        record: &RegistryServerLifecycleRecordBinding,
    ) -> Result<Vec<RegistryServerLifecycleAction>, RegistryServerLifecyclePromotionError> {
        if !authority.matches_record(record) {
            return Err(RegistryServerLifecyclePromotionError::Binding);
        }

        self.actions
            .iter()
            .map(|action| {
                if let Some(proposal_version) = action.proposal_version {
                    if proposal_version != self.proposal_version
                        || action.effect_digest.as_ref() != self.effect_digest.as_ref()
                    {
                        return Err(RegistryServerLifecyclePromotionError::Binding);
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

impl fmt::Debug for RegistryServerRequestMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerRequestMetadata")
            .field("server_state", &self.server_state)
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
            .field(
                "retained_history",
                &self.retained_history.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq)]
struct InertRegistryServerLifecycleAction {
    operation: RegistryServerLifecycleOperation,
    href: String,
    if_match: String,
    stage: Option<String>,
    rebase: Option<bool>,
    proposal_version: Option<RegistryServerProposalVersion>,
    effect_digest: Option<RegistryServerEffectDigest>,
    review: Option<RegistryServerRequestReview>,
}

impl InertRegistryServerLifecycleAction {
    fn from_value(value: Value) -> Result<Self, RegistryServerLifecycleDecodeError> {
        let mut object = exact_object(
            value,
            &["operation", "method", "href", "ifMatch"],
            &[
                "stage",
                "rebase",
                "proposalVersion",
                "effectDigest",
                "review",
            ],
        )?;
        let operation = parse_operation(&take_string(&mut object, "operation")?)?;
        if take_string(&mut object, "method")? != "POST" {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }
        let href = take_string(&mut object, "href")?;
        validate_relative_action_href(&href)?;
        let if_match = take_string(&mut object, "ifMatch")?;
        if !valid_action_if_match(&if_match) {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }
        let stage = take_optional_identifier(&mut object, "stage")?;
        let rebase = match object.remove("rebase") {
            None => None,
            Some(Value::Bool(value)) => Some(value),
            Some(_) => return Err(RegistryServerLifecycleDecodeError::Profile),
        };
        let proposal_version = take_optional_proposal_version(&mut object, "proposalVersion")?;
        let effect_digest = take_optional_digest(&mut object, "effectDigest")?;
        if proposal_version.is_some() != effect_digest.is_some() {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }
        let review = match object.remove("review") {
            None => None,
            Some(value) => Some(decode_review(value)?),
        };

        if operation.is_review() {
            if stage.is_none()
                || review.is_none()
                || proposal_version.is_none()
                || effect_digest.is_none()
                || rebase.is_some()
            {
                return Err(RegistryServerLifecycleDecodeError::Profile);
            }
        } else if stage.is_some() || review.is_some() {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }
        if operation.requires_proposal_binding()
            && (proposal_version.is_none() || effect_digest.is_none())
        {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }
        if matches!(operation, RegistryServerLifecycleOperation::ReviseRequest) {
            if rebase.is_none() {
                return Err(RegistryServerLifecycleDecodeError::Profile);
            }
        } else if rebase.is_some() {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }

        Ok(Self {
            operation,
            href,
            if_match,
            stage,
            rebase,
            proposal_version,
            effect_digest,
            review,
        })
    }
}

impl fmt::Debug for InertRegistryServerLifecycleAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InertRegistryServerLifecycleAction")
            .field("operation", &self.operation)
            .field("href", &"<redacted>")
            .field("if_match", &"<redacted>")
            .field("stage", &self.stage.as_ref().map(|_| "<redacted>"))
            .field("rebase", &self.rebase)
            .field(
                "proposal_version",
                &self.proposal_version.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "effect_digest",
                &self.effect_digest.as_ref().map(|_| "<redacted>"),
            )
            .field("review", &self.review)
            .finish()
    }
}

/// A crate-owned capability handle derived from Registry Metadata v1.
///
/// Its constructors are crate-private so response data cannot manufacture the
/// authority needed to promote its own links.
#[derive(Clone, PartialEq)]
pub struct RegistryServerLifecycleAuthority {
    registry_identifier: String,
    dataset_identifier: String,
    registry_revision: String,
    entity_type_identifier: String,
    access_profile_identifier: String,
    source_binding: String,
    operations: Vec<RegistryServerLifecycleOperationBinding>,
}

impl RegistryServerLifecycleAuthority {
    pub(crate) fn new(
        registry_identifier: String,
        dataset_identifier: String,
        registry_revision: String,
        entity_type_identifier: String,
        access_profile_identifier: String,
        source_binding: String,
        operations: Vec<RegistryServerLifecycleOperationBinding>,
    ) -> Result<Self, RegistryServerLifecyclePromotionError> {
        for identifier in [
            &registry_identifier,
            &dataset_identifier,
            &entity_type_identifier,
            &access_profile_identifier,
        ] {
            validate_identifier(identifier)
                .map_err(|_| RegistryServerLifecyclePromotionError::Authority)?;
        }
        if operations.is_empty()
            || operations.len() > MAX_REGISTRY_SERVER_LIFECYCLE_OPERATION_BINDINGS
        {
            return Err(RegistryServerLifecyclePromotionError::Authority);
        }
        let mut keys = BTreeSet::new();
        for binding in &operations {
            binding.validate()?;
            if !keys.insert((binding.operation, binding.stage.clone())) {
                return Err(RegistryServerLifecyclePromotionError::Authority);
            }
        }
        if registry_revision.is_empty()
            || registry_revision.len() > MAX_IDENTIFIER_BYTES
            || source_binding.is_empty()
            || source_binding.len() > MAX_REGISTRY_SERVER_ACTION_HREF_BYTES
        {
            return Err(RegistryServerLifecyclePromotionError::Authority);
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

    fn matches_record(&self, record: &RegistryServerLifecycleRecordBinding) -> bool {
        self.registry_identifier == record.registry_identifier
            && self.dataset_identifier == record.dataset_identifier
            && self.entity_type_identifier == record.entity_type_identifier
    }

    fn promote(
        &self,
        action: &InertRegistryServerLifecycleAction,
        record: &RegistryServerLifecycleRecordBinding,
        proposal_version: RegistryServerProposalVersion,
        effect_digest: Option<RegistryServerEffectDigest>,
    ) -> Result<RegistryServerLifecycleAction, RegistryServerLifecyclePromotionError> {
        let mut matches = self.operations.iter().filter(|binding| {
            binding.operation == action.operation && binding.stage == action.stage
        });
        let binding = matches
            .next()
            .filter(|_| matches.next().is_none())
            .ok_or(RegistryServerLifecyclePromotionError::Binding)?;
        let expected_href =
            binding.href_for(&record.record_identifier, &self.access_profile_identifier)?;
        if expected_href != action.href {
            return Err(RegistryServerLifecyclePromotionError::Binding);
        }

        let body = match action.operation {
            RegistryServerLifecycleOperation::SubmitRequest => {
                RegistryServerLifecycleActionBody::SubmitRequest
            }
            RegistryServerLifecycleOperation::CancelRequest => {
                RegistryServerLifecycleActionBody::CancelRequest
            }
            RegistryServerLifecycleOperation::ReviseRequest => {
                RegistryServerLifecycleActionBody::ReviseRequest {
                    rebase: action
                        .rebase
                        .ok_or(RegistryServerLifecyclePromotionError::Binding)?,
                }
            }
            operation => {
                let proposal_version = action
                    .proposal_version
                    .ok_or(RegistryServerLifecyclePromotionError::Binding)?;
                let effect_digest = action
                    .effect_digest
                    .clone()
                    .ok_or(RegistryServerLifecyclePromotionError::Binding)?;
                match operation {
                    RegistryServerLifecycleOperation::ApproveRequest => {
                        RegistryServerLifecycleActionBody::ApproveRequest {
                            proposal_version,
                            effect_digest,
                        }
                    }
                    RegistryServerLifecycleOperation::RejectRequest => {
                        RegistryServerLifecycleActionBody::RejectRequest {
                            proposal_version,
                            effect_digest,
                        }
                    }
                    RegistryServerLifecycleOperation::RequestRevision => {
                        RegistryServerLifecycleActionBody::RequestRevision {
                            proposal_version,
                            effect_digest,
                        }
                    }
                    RegistryServerLifecycleOperation::ApplyRequest => {
                        RegistryServerLifecycleActionBody::ApplyRequest {
                            proposal_version,
                            effect_digest,
                        }
                    }
                    _ => return Err(RegistryServerLifecyclePromotionError::Binding),
                }
            }
        };
        let expected_receipt_revision = record
            .record_revision
            .checked_add(1)
            .ok_or(RegistryServerLifecyclePromotionError::Binding)?;

        Ok(RegistryServerLifecycleAction {
            operation: action.operation,
            href: action.href.clone(),
            if_match: RegistryServerActionIfMatch(action.if_match.clone()),
            stage: action.stage.clone(),
            body,
            review: action.review.clone(),
            registry_revision: self.registry_revision.clone(),
            source_binding: self.source_binding.clone(),
            record_identifier: record.record_identifier.clone(),
            expected_receipt_revision,
            proposal_version,
            effect_digest,
        })
    }
}

impl fmt::Debug for RegistryServerLifecycleAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerLifecycleAuthority")
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
pub struct RegistryServerLifecycleOperationBinding {
    operation: RegistryServerLifecycleOperation,
    path_template: String,
    stage: Option<String>,
}

impl RegistryServerLifecycleOperationBinding {
    pub(crate) fn new(
        operation: RegistryServerLifecycleOperation,
        path_template: String,
        stage: Option<String>,
    ) -> Self {
        Self {
            operation,
            path_template,
            stage,
        }
    }

    fn validate(&self) -> Result<(), RegistryServerLifecyclePromotionError> {
        validate_route_template(&self.path_template)
            .map_err(|_| RegistryServerLifecyclePromotionError::Authority)?;
        match (self.operation.is_review(), self.stage.as_deref()) {
            (true, Some(stage)) => validate_identifier(stage)
                .map_err(|_| RegistryServerLifecyclePromotionError::Authority)?,
            (false, None) => {}
            _ => return Err(RegistryServerLifecyclePromotionError::Authority),
        }
        let suffix = if self.operation.is_review() {
            format!(
                "/actions/stages/{}/{}",
                self.stage
                    .as_deref()
                    .ok_or(RegistryServerLifecyclePromotionError::Authority)?,
                self.operation.path_suffix().trim_start_matches('/')
            )
        } else {
            self.operation.path_suffix().to_owned()
        };
        if !self.path_template.ends_with(&suffix) {
            return Err(RegistryServerLifecyclePromotionError::Authority);
        }
        Ok(())
    }

    fn href_for(
        &self,
        record_identifier: &str,
        access_profile_identifier: &str,
    ) -> Result<String, RegistryServerLifecyclePromotionError> {
        let path = self.path_template.replace("{record_id}", record_identifier);
        let href = format!(
            "{path}?accessProfile={}",
            percent_encode_query_value(access_profile_identifier)
        );
        if href.len() > MAX_REGISTRY_SERVER_ACTION_HREF_BYTES {
            return Err(RegistryServerLifecyclePromotionError::Binding);
        }
        Ok(href)
    }
}

impl fmt::Debug for RegistryServerLifecycleOperationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerLifecycleOperationBinding")
            .field("operation", &self.operation)
            .field("path_template", &"<redacted>")
            .field("stage", &self.stage.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Exact Registry Record envelope binding used during action promotion.
#[derive(Clone, PartialEq)]
pub struct RegistryServerLifecycleRecordBinding {
    registry_identifier: String,
    dataset_identifier: String,
    entity_type_identifier: String,
    record_identifier: String,
    record_revision: u64,
}

impl RegistryServerLifecycleRecordBinding {
    pub(crate) fn from_record(
        meta: &crate::RegistryRecordMeta,
        record: &crate::RegistryRecord,
    ) -> Result<Self, RegistryServerLifecyclePromotionError> {
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
                .ok_or(RegistryServerLifecyclePromotionError::Binding)?,
        )
    }

    pub(crate) fn new(
        registry_identifier: String,
        dataset_identifier: String,
        entity_type_identifier: String,
        record_identifier: String,
        record_revision: u64,
    ) -> Result<Self, RegistryServerLifecyclePromotionError> {
        for identifier in [
            &registry_identifier,
            &dataset_identifier,
            &entity_type_identifier,
        ] {
            validate_identifier(identifier)
                .map_err(|_| RegistryServerLifecyclePromotionError::Binding)?;
        }
        validate_canonical_uuid(&record_identifier)
            .map_err(|_| RegistryServerLifecyclePromotionError::Binding)?;
        if record_revision == 0 {
            return Err(RegistryServerLifecyclePromotionError::Binding);
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

impl fmt::Debug for RegistryServerLifecycleRecordBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerLifecycleRecordBinding")
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
pub struct RegistryServerActionIfMatch(String);

impl RegistryServerActionIfMatch {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RegistryServerActionIfMatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryServerActionIfMatch(<redacted>)")
    }
}

/// A metadata- and record-bound lifecycle action safe to send once.
#[derive(Clone, PartialEq)]
pub struct RegistryServerLifecycleAction {
    operation: RegistryServerLifecycleOperation,
    href: String,
    if_match: RegistryServerActionIfMatch,
    stage: Option<String>,
    body: RegistryServerLifecycleActionBody,
    review: Option<RegistryServerRequestReview>,
    registry_revision: String,
    source_binding: String,
    record_identifier: String,
    expected_receipt_revision: u64,
    proposal_version: RegistryServerProposalVersion,
    effect_digest: Option<RegistryServerEffectDigest>,
}

impl RegistryServerLifecycleAction {
    #[must_use]
    pub const fn operation(&self) -> RegistryServerLifecycleOperation {
        self.operation
    }

    /// Returns the exact relative-origin href validated against Registry
    /// Metadata, the selected access profile and the record UUID.
    #[must_use]
    pub fn href(&self) -> &str {
        &self.href
    }

    #[must_use]
    pub fn if_match(&self) -> &RegistryServerActionIfMatch {
        &self.if_match
    }

    #[must_use]
    pub fn stage(&self) -> Option<&str> {
        self.stage.as_deref()
    }

    #[must_use]
    pub fn body(&self) -> &RegistryServerLifecycleActionBody {
        &self.body
    }

    #[must_use]
    pub fn review(&self) -> Option<&RegistryServerRequestReview> {
        self.review.as_ref()
    }

    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }

    #[must_use]
    pub(crate) fn matches_source(&self, source: &str) -> bool {
        self.source_binding == source
    }

    #[must_use]
    pub(crate) fn matches_record_identifier(&self, record_identifier: &str) -> bool {
        self.record_identifier == record_identifier
    }

    pub(crate) fn accepts_receipt(&self, receipt: &RegistryServerLifecycleActionReceipt) -> bool {
        let request = receipt.request();
        let state_matches = match self.operation {
            RegistryServerLifecycleOperation::SubmitRequest => {
                request.server_state() == RegistryServerRequestState::Submitted
            }
            RegistryServerLifecycleOperation::ApproveRequest => matches!(
                request.server_state(),
                RegistryServerRequestState::Submitted | RegistryServerRequestState::Approved
            ),
            RegistryServerLifecycleOperation::RejectRequest => {
                request.server_state() == RegistryServerRequestState::Rejected
            }
            RegistryServerLifecycleOperation::RequestRevision => {
                request.server_state() == RegistryServerRequestState::NeedsChanges
            }
            RegistryServerLifecycleOperation::ReviseRequest => {
                request.server_state() == RegistryServerRequestState::Draft
            }
            RegistryServerLifecycleOperation::CancelRequest => {
                request.server_state() == RegistryServerRequestState::Canceled
            }
            RegistryServerLifecycleOperation::ApplyRequest => {
                request.server_state() == RegistryServerRequestState::Applied
            }
        };
        let proposal_matches = match self.operation {
            RegistryServerLifecycleOperation::SubmitRequest => {
                request.proposal_version() == Some(self.proposal_version)
                    && request.effect_digest().is_some()
            }
            RegistryServerLifecycleOperation::ReviseRequest => {
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
                .strip_prefix("rs1_")
                .is_none_or(|value| validate_canonical_uuid(value).is_err())
            || !state_matches
            || !proposal_matches
        {
            return false;
        }
        match (self.operation, request.application()) {
            (RegistryServerLifecycleOperation::ApplyRequest, Some(application)) => {
                application.proposal_version() == self.proposal_version
                    && Some(application.effect_digest()) == self.effect_digest.as_ref()
            }
            (RegistryServerLifecycleOperation::ApplyRequest, None) => false,
            (_, None) => true,
            (_, Some(_)) => false,
        }
    }
}

impl fmt::Debug for RegistryServerLifecycleAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerLifecycleAction")
            .field("operation", &self.operation)
            .field("href", &"<redacted>")
            .field("if_match", &self.if_match)
            .field("stage", &self.stage.as_ref().map(|_| "<redacted>"))
            .field("body", &self.body)
            .field("review", &self.review)
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
pub enum RegistryServerLifecycleActionBody {
    SubmitRequest,
    ApproveRequest {
        proposal_version: RegistryServerProposalVersion,
        effect_digest: RegistryServerEffectDigest,
    },
    RejectRequest {
        proposal_version: RegistryServerProposalVersion,
        effect_digest: RegistryServerEffectDigest,
    },
    RequestRevision {
        proposal_version: RegistryServerProposalVersion,
        effect_digest: RegistryServerEffectDigest,
    },
    ReviseRequest {
        rebase: bool,
    },
    CancelRequest,
    ApplyRequest {
        proposal_version: RegistryServerProposalVersion,
        effect_digest: RegistryServerEffectDigest,
    },
}

impl RegistryServerLifecycleActionBody {
    /// Returns the exact JSON object required by Registry Server.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::SubmitRequest | Self::CancelRequest => json!({}),
            Self::ReviseRequest { rebase } => json!({"rebase": rebase}),
            Self::ApproveRequest {
                proposal_version,
                effect_digest,
            }
            | Self::RejectRequest {
                proposal_version,
                effect_digest,
            }
            | Self::RequestRevision {
                proposal_version,
                effect_digest,
            }
            | Self::ApplyRequest {
                proposal_version,
                effect_digest,
            } => json!({
                "proposalVersion": proposal_version,
                "effectDigest": effect_digest,
            }),
        }
    }
}

impl fmt::Debug for RegistryServerLifecycleActionBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SubmitRequest => "RegistryServerLifecycleActionBody::SubmitRequest",
            Self::ApproveRequest { .. } => {
                "RegistryServerLifecycleActionBody::ApproveRequest(<redacted>)"
            }
            Self::RejectRequest { .. } => {
                "RegistryServerLifecycleActionBody::RejectRequest(<redacted>)"
            }
            Self::RequestRevision { .. } => {
                "RegistryServerLifecycleActionBody::RequestRevision(<redacted>)"
            }
            Self::ReviseRequest { .. } => {
                "RegistryServerLifecycleActionBody::ReviseRequest(<redacted>)"
            }
            Self::CancelRequest => "RegistryServerLifecycleActionBody::CancelRequest",
            Self::ApplyRequest { .. } => {
                "RegistryServerLifecycleActionBody::ApplyRequest(<redacted>)"
            }
        })
    }
}

impl Serialize for RegistryServerLifecycleActionBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_value().serialize(serializer)
    }
}

/// A distinct successful response for change-request actor actions.
#[derive(Clone, PartialEq)]
pub struct RegistryServerLifecycleActionReceipt {
    record_identifier: String,
    revision: u64,
    snapshot: String,
    request: RegistryServerLifecycleReceiptRequest,
}

impl RegistryServerLifecycleActionReceipt {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, RegistryServerLifecycleDecodeError> {
        let value = crate::strict_json::from_slice(bytes)
            .map_err(|_| RegistryServerLifecycleDecodeError::Json)?;
        Self::from_value(value)
    }

    pub fn from_value(value: Value) -> Result<Self, RegistryServerLifecycleDecodeError> {
        let mut object = exact_object(value, &["id", "revision", "snapshot", "request"], &[])?;
        let record_identifier = take_string(&mut object, "id")?;
        validate_canonical_uuid(&record_identifier)?;
        let revision = object
            .remove("revision")
            .and_then(|value| value.as_u64())
            .filter(|revision| *revision > 0)
            .ok_or(RegistryServerLifecycleDecodeError::Profile)?;
        let snapshot = take_string(&mut object, "snapshot")?;
        if snapshot.is_empty()
            || snapshot.len() > MAX_REGISTRY_SERVER_SNAPSHOT_REFERENCE_BYTES
            || snapshot.chars().any(char::is_control)
        {
            return Err(RegistryServerLifecycleDecodeError::Profile);
        }
        let request = decode_receipt_request(
            object
                .remove("request")
                .ok_or(RegistryServerLifecycleDecodeError::Profile)?,
        )?;
        Ok(Self {
            record_identifier,
            revision,
            snapshot,
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

    #[must_use]
    pub fn request(&self) -> &RegistryServerLifecycleReceiptRequest {
        &self.request
    }
}

impl fmt::Debug for RegistryServerLifecycleActionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerLifecycleActionReceipt")
            .field("record_identifier", &"<redacted>")
            .field("revision", &self.revision)
            .field("snapshot", &"<redacted>")
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct RegistryServerLifecycleReceiptRequest {
    server_state: RegistryServerRequestState,
    proposal_version: Option<RegistryServerProposalVersion>,
    effect_digest: Option<RegistryServerEffectDigest>,
    proposal: Option<RegistryServerRequestProposal>,
    application: Option<RegistryServerLifecycleReceiptApplication>,
}

impl RegistryServerLifecycleReceiptRequest {
    #[must_use]
    pub const fn server_state(&self) -> RegistryServerRequestState {
        self.server_state
    }

    #[must_use]
    pub const fn proposal_version(&self) -> Option<RegistryServerProposalVersion> {
        self.proposal_version
    }

    #[must_use]
    pub fn effect_digest(&self) -> Option<&RegistryServerEffectDigest> {
        self.effect_digest.as_ref()
    }

    #[must_use]
    pub fn proposal(&self) -> Option<&RegistryServerRequestProposal> {
        self.proposal.as_ref()
    }

    #[must_use]
    pub fn application(&self) -> Option<&RegistryServerLifecycleReceiptApplication> {
        self.application.as_ref()
    }
}

impl fmt::Debug for RegistryServerLifecycleReceiptRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryServerLifecycleReceiptRequest")
            .field("server_state", &self.server_state)
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

/// Coarse, value-free Registry Server lifecycle decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistryServerLifecycleDecodeError {
    #[error("Registry Server lifecycle response is not valid JSON")]
    Json,
    #[error("Registry Server lifecycle response does not conform")]
    Profile,
}

/// Coarse, value-free action promotion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistryServerLifecyclePromotionError {
    #[error("Registry Server lifecycle authority does not conform")]
    Authority,
    #[error("Registry Server lifecycle action is not bound to its authority and record")]
    Binding,
}

fn decode_review(
    value: Value,
) -> Result<RegistryServerRequestReview, RegistryServerLifecycleDecodeError> {
    let mut object = exact_object(value, &["targets"], &[])?;
    let targets = match object.remove("targets") {
        Some(Value::Array(targets)) if targets.len() <= MAX_REGISTRY_SERVER_REVIEW_TARGETS => {
            targets
                .into_iter()
                .map(decode_review_target)
                .collect::<Result<Vec<_>, _>>()?
        }
        _ => return Err(RegistryServerLifecycleDecodeError::Profile),
    };
    Ok(RegistryServerRequestReview { targets })
}

fn decode_proposal(
    value: Value,
) -> Result<RegistryServerRequestProposal, RegistryServerLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &["reviewMode", "applicationDisposition"],
        &["queueReason"],
    )?;
    let review_mode =
        RegistryServerRequestReviewMode::parse(&take_string(&mut object, "reviewMode")?)
            .ok_or(RegistryServerLifecycleDecodeError::Profile)?;
    let application_disposition = RegistryServerRequestApplicationDisposition::parse(&take_string(
        &mut object,
        "applicationDisposition",
    )?)
    .ok_or(RegistryServerLifecycleDecodeError::Profile)?;
    let queue_reason = match object.remove("queueReason") {
        None => None,
        Some(value) => Some(decode_queue_reason(value)?),
    };
    if matches!(
        application_disposition,
        RegistryServerRequestApplicationDisposition::Apply
    ) && queue_reason.is_some()
    {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    Ok(RegistryServerRequestProposal {
        review_mode,
        application_disposition,
        queue_reason,
    })
}

fn decode_queue_reason(
    value: Value,
) -> Result<RegistryServerRequestQueueReason, RegistryServerLifecycleDecodeError> {
    let mut object = exact_object(value, &["code", "label"], &[])?;
    let code = take_string(&mut object, "code")?;
    validate_identifier(&code)?;
    let label = take_string(&mut object, "label")?;
    if label.is_empty() || label.len() > MAX_IDENTIFIER_BYTES {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    Ok(RegistryServerRequestQueueReason { code, label })
}

fn decode_review_target(
    value: Value,
) -> Result<RegistryServerRequestReviewTarget, RegistryServerLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &[
            "entityId",
            "recordId",
            "operation",
            "baseRevision",
            "before",
            "after",
        ],
        &[],
    )?;
    let entity_identifier = take_string(&mut object, "entityId")?;
    validate_identifier(&entity_identifier)?;
    let record_identifier = take_string(&mut object, "recordId")?;
    validate_canonical_uuid(&record_identifier)?;
    let operation = match take_string(&mut object, "operation")?.as_str() {
        "create" => RegistryServerReviewOperation::Create,
        "patch" => RegistryServerReviewOperation::Patch,
        _ => return Err(RegistryServerLifecycleDecodeError::Profile),
    };
    let base_revision = match object.remove("baseRevision") {
        Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .filter(|revision| *revision > 0)
                .ok_or(RegistryServerLifecycleDecodeError::Profile)?,
        ),
        None => return Err(RegistryServerLifecycleDecodeError::Profile),
    };
    let before = match object.remove("before") {
        Some(Value::Null) => None,
        Some(Value::Object(value)) if value.len() <= MAX_REGISTRY_SERVER_REVIEW_OBJECT_MEMBERS => {
            Some(value.into_iter().collect())
        }
        _ => return Err(RegistryServerLifecycleDecodeError::Profile),
    };
    let after = match object.remove("after") {
        Some(Value::Object(value)) if value.len() <= MAX_REGISTRY_SERVER_REVIEW_OBJECT_MEMBERS => {
            value.into_iter().collect()
        }
        _ => return Err(RegistryServerLifecycleDecodeError::Profile),
    };
    if matches!(operation, RegistryServerReviewOperation::Create)
        && (base_revision.is_some() || before.is_some())
        || matches!(operation, RegistryServerReviewOperation::Patch)
            && (base_revision.is_none() || before.is_none())
    {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    Ok(RegistryServerRequestReviewTarget {
        entity_identifier,
        record_identifier,
        operation,
        base_revision,
        before,
        after,
    })
}

fn decode_retained_application(
    value: Value,
) -> Result<RegistryServerRetainedApplication, RegistryServerLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &["applicationId", "proposalVersion", "appliedAt"],
        &["effectDigest"],
    )?;
    let application_identifier = take_string(&mut object, "applicationId")?;
    validate_canonical_uuid(&application_identifier)?;
    let proposal_version = RegistryServerProposalVersion::from_value(
        &object
            .remove("proposalVersion")
            .ok_or(RegistryServerLifecycleDecodeError::Profile)?,
    )?;
    let effect_digest = take_optional_digest(&mut object, "effectDigest")?;
    let applied_at = take_string(&mut object, "appliedAt")?;
    validate_timestamp(&applied_at)?;
    Ok(RegistryServerRetainedApplication {
        application_identifier,
        proposal_version,
        effect_digest,
        applied_at,
    })
}

fn decode_receipt_application(
    value: Value,
) -> Result<RegistryServerLifecycleReceiptApplication, RegistryServerLifecycleDecodeError> {
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
    let proposal_version = RegistryServerProposalVersion::from_value(
        &object
            .remove("proposalVersion")
            .ok_or(RegistryServerLifecycleDecodeError::Profile)?,
    )?;
    let effect_digest =
        RegistryServerEffectDigest::parse(&take_string(&mut object, "effectDigest")?)?;
    let applied_at = take_string(&mut object, "appliedAt")?;
    validate_timestamp(&applied_at)?;
    Ok(RegistryServerLifecycleReceiptApplication {
        application_identifier,
        proposal_version,
        effect_digest,
        applied_at,
    })
}

fn decode_erased_application(
    value: Value,
) -> Result<RegistryServerErasedApplication, RegistryServerLifecycleDecodeError> {
    let mut object = exact_object(value, &["applicationId", "proposalVersion"], &[])?;
    let application_identifier = take_string(&mut object, "applicationId")?;
    validate_canonical_uuid(&application_identifier)?;
    let proposal_version = RegistryServerProposalVersion::from_value(
        &object
            .remove("proposalVersion")
            .ok_or(RegistryServerLifecycleDecodeError::Profile)?,
    )?;
    Ok(RegistryServerErasedApplication {
        application_identifier,
        proposal_version,
    })
}

fn decode_receipt_request(
    value: Value,
) -> Result<RegistryServerLifecycleReceiptRequest, RegistryServerLifecycleDecodeError> {
    let mut object = exact_object(
        value,
        &[
            "serverState",
            "proposalVersion",
            "effectDigest",
            "application",
        ],
        &["proposal"],
    )?;
    let server_state = RegistryServerRequestState::parse(&take_string(&mut object, "serverState")?)
        .ok_or(RegistryServerLifecycleDecodeError::Profile)?;
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
        None => return Err(RegistryServerLifecycleDecodeError::Profile),
    };
    Ok(RegistryServerLifecycleReceiptRequest {
        server_state,
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
) -> Result<Map<String, Value>, RegistryServerLifecycleDecodeError> {
    let Value::Object(object) = value else {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    };
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    Ok(object)
}

fn take_string(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<String, RegistryServerLifecycleDecodeError> {
    object
        .remove(member)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(RegistryServerLifecycleDecodeError::Profile)
}

fn take_optional_identifier(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<String>, RegistryServerLifecycleDecodeError> {
    match object.remove(member) {
        None => Ok(None),
        Some(Value::String(value)) => {
            validate_identifier(&value)?;
            Ok(Some(value))
        }
        Some(_) => Err(RegistryServerLifecycleDecodeError::Profile),
    }
}

fn take_optional_proposal_version(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<RegistryServerProposalVersion>, RegistryServerLifecycleDecodeError> {
    match object.remove(member) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => RegistryServerProposalVersion::from_value(&value).map(Some),
    }
}

fn take_optional_digest(
    object: &mut Map<String, Value>,
    member: &str,
) -> Result<Option<RegistryServerEffectDigest>, RegistryServerLifecycleDecodeError> {
    match object.remove(member) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => RegistryServerEffectDigest::parse(&value).map(Some),
        Some(_) => Err(RegistryServerLifecycleDecodeError::Profile),
    }
}

fn parse_operation(
    value: &str,
) -> Result<RegistryServerLifecycleOperation, RegistryServerLifecycleDecodeError> {
    RegistryServerLifecycleOperation::ALL
        .into_iter()
        .find(|operation| operation.identifier() == value)
        .ok_or(RegistryServerLifecycleDecodeError::Profile)
}

fn reject_duplicate_action_bindings(
    actions: &[InertRegistryServerLifecycleAction],
) -> Result<(), RegistryServerLifecycleDecodeError> {
    let mut keys = BTreeSet::new();
    for action in actions {
        if !keys.insert((action.operation, action.stage.clone())) {
            return Err(RegistryServerLifecycleDecodeError::Profile);
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
        && value.starts_with("\"rs-action-")
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

fn validate_identifier(value: &str) -> Result<(), RegistryServerLifecycleDecodeError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn validate_canonical_uuid(value: &str) -> Result<(), RegistryServerLifecycleDecodeError> {
    let parsed = Uuid::parse_str(value).map_err(|_| RegistryServerLifecycleDecodeError::Profile)?;
    if parsed.hyphenated().to_string() != value {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), RegistryServerLifecycleDecodeError> {
    if value.is_empty()
        || value.len() > MAX_TIMESTAMP_BYTES
        || !value.is_ascii()
        || value.chars().any(char::is_control)
        || !value.contains('T')
        || !(value.ends_with('Z')
            || value
                .rsplit_once(['+', '-'])
                .is_some_and(|(_, offset)| offset.len() == 5 && offset.as_bytes()[2] == b':'))
    {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn validate_relative_action_href(href: &str) -> Result<(), RegistryServerLifecycleDecodeError> {
    if href.is_empty()
        || href.len() > MAX_REGISTRY_SERVER_ACTION_HREF_BYTES
        || !href.starts_with('/')
        || href.starts_with("//")
        || href.chars().any(char::is_control)
    {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    let base = Url::parse("https://registry.invalid/")
        .map_err(|_| RegistryServerLifecycleDecodeError::Profile)?;
    let parsed = base
        .join(href)
        .map_err(|_| RegistryServerLifecycleDecodeError::Profile)?;
    if parsed.origin() != base.origin()
        || parsed.fragment().is_some()
        || parsed.username() != ""
        || parsed.password().is_some()
    {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    let mut query = parsed.query_pairs();
    let Some((name, value)) = query.next() else {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    };
    if name != "accessProfile" || value.is_empty() || query.next().is_some() {
        return Err(RegistryServerLifecycleDecodeError::Profile);
    }
    Ok(())
}

fn validate_route_template(path: &str) -> Result<(), RegistryServerLifecycleDecodeError> {
    if path.is_empty()
        || path.len() > MAX_REGISTRY_SERVER_ACTION_HREF_BYTES
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('?')
        || path.contains('#')
        || path.chars().any(char::is_control)
        || path.matches("{record_id}").count() != 1
        || path.contains("..")
    {
        return Err(RegistryServerLifecycleDecodeError::Profile);
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
