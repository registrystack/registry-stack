//! Governed binary slots on Base Registry Engine change requests.
//!
//! A slot is discovered from caller-filtered Registry Metadata, never from a
//! record. Slot values are engine owned: they are read from a record's
//! `domainData` and written only through the slot's own routes. Selection
//! promotes an inert descriptor into a source-bound [`BRegAttachmentSlot`],
//! which is the only handle this client accepts for an upload, a download, or
//! a removal.

use std::fmt;

use serde_json::{Map, Value};
use uuid::Uuid;

/// Largest slot capacity Base Registry Engine can compile.
pub const MAX_BREG_ATTACHMENT_BYTES: u64 = 16 * 1024 * 1024;
/// Largest number of accepted content types on one slot.
pub const MAX_BREG_ATTACHMENT_CONTENT_TYPES: usize = 16;
/// Largest number of slots one request entity can declare.
pub const MAX_BREG_ATTACHMENT_SLOTS: usize = 8;
/// Largest accepted concrete media type, matching the served slot schema.
pub const MAX_BREG_ATTACHMENT_CONTENT_TYPE_BYTES: usize = 255;

const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_ACTOR_REFERENCE_BYTES: usize = 512;
const SHA256_HEX_LENGTH: usize = 64;

/// Verification verdict Base Registry Engine records for one stored slot value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BRegAttachmentVerificationStatus {
    NotRequired,
    Pending,
    Approved,
    Rejected,
}

impl BRegAttachmentVerificationStatus {
    /// All verification statuses, in escalation order.
    pub const ALL: [Self; 4] = [
        Self::NotRequired,
        Self::Pending,
        Self::Approved,
        Self::Rejected,
    ];

    /// Exact wire member value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "notRequired",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    /// Whether the engine releases the stored bytes and accepts a submission.
    /// A pending or rejected value blocks both download and submit.
    #[must_use]
    pub const fn released(self) -> bool {
        matches!(self, Self::NotRequired | Self::Approved)
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
    }
}

/// A value-free reason that an attachment cannot be prepared or decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegAttachmentError {
    #[error("the Base Registry Engine attachment slot does not advertise an upload route")]
    UploadNotAdvertised,
    #[error("a Base Registry Engine attachment upload must contain at least one byte")]
    EmptyUpload,
    #[error("a Base Registry Engine attachment upload exceeds the slot maximum byte size")]
    UploadTooLarge,
    #[error(
        "a Base Registry Engine attachment content type is not a concrete lowercase media type"
    )]
    InvalidContentType,
    #[error("the Base Registry Engine attachment slot does not accept this content type")]
    ContentTypeNotAccepted,
    #[error("a Base Registry Engine attachment slot value does not match the served contract")]
    InvalidSlotValue,
}

impl BRegAttachmentError {
    /// Stable, value-free reason retained by client refusals.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::UploadNotAdvertised => {
                "the Base Registry Engine attachment slot does not advertise an upload route"
            }
            Self::EmptyUpload => {
                "a Base Registry Engine attachment upload must contain at least one byte"
            }
            Self::UploadTooLarge => {
                "a Base Registry Engine attachment upload exceeds the slot maximum byte size"
            }
            Self::InvalidContentType => {
                "a Base Registry Engine attachment content type is not a concrete lowercase media type"
            }
            Self::ContentTypeNotAccepted => {
                "the Base Registry Engine attachment slot does not accept this content type"
            }
            Self::InvalidSlotValue => {
                "a Base Registry Engine attachment slot value does not match the served contract"
            }
        }
    }
}

/// Entity-level facts shared by every slot promoted from one selection.
pub(crate) struct BRegAttachmentSource {
    pub(crate) registry_identifier: String,
    pub(crate) dataset_identifier: String,
    pub(crate) registry_revision: String,
    pub(crate) entity_identifier: String,
    pub(crate) access_profile: String,
    pub(crate) collection_path: String,
    pub(crate) source_binding: String,
}

/// One governed binary slot, bound to the client source that fetched its metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct BRegAttachmentSlot {
    registry_identifier: String,
    dataset_identifier: String,
    registry_revision: String,
    entity_identifier: String,
    access_profile: String,
    collection_path: String,
    source_binding: String,
    slot_identifier: String,
    required_for_submit: bool,
    maximum_bytes: u64,
    content_types: Vec<String>,
    download: bool,
    upload: bool,
    remove: bool,
}

impl BRegAttachmentSlot {
    /// Registry that compiled this slot.
    #[must_use]
    pub fn registry_identifier(&self) -> &str {
        &self.registry_identifier
    }

    /// Dataset owning the request entity that declares this slot.
    #[must_use]
    pub fn dataset_identifier(&self) -> &str {
        &self.dataset_identifier
    }

    /// Registry revision the selection was taken from.
    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }

    /// Request entity that declares this slot.
    #[must_use]
    pub fn entity_identifier(&self) -> &str {
        &self.entity_identifier
    }

    /// Exact access profile the slot routes were filtered for.
    #[must_use]
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }

    /// Slot identifier, used verbatim in the route and under `domainData`.
    #[must_use]
    pub fn slot_identifier(&self) -> &str {
        &self.slot_identifier
    }

    /// Whether submission refuses while this slot is empty.
    #[must_use]
    pub const fn required_for_submit(&self) -> bool {
        self.required_for_submit
    }

    /// Largest upload the engine accepts for this slot.
    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    /// Concrete content types the engine accepts for this slot, in served order.
    #[must_use]
    pub fn content_types(&self) -> &[String] {
        &self.content_types
    }

    /// Whether an upload with this exact content type would be accepted. A
    /// stored value may still carry a content type outside this list when the
    /// upload predates a narrower policy.
    #[must_use]
    pub fn accepts_content_type(&self, content_type: &str) -> bool {
        self.content_types
            .iter()
            .any(|accepted| accepted == content_type)
    }

    /// Whether the caller-filtered metadata advertised a download route.
    #[must_use]
    pub const fn can_download(&self) -> bool {
        self.download
    }

    /// Whether the caller-filtered metadata advertised an upload route.
    #[must_use]
    pub const fn can_upload(&self) -> bool {
        self.upload
    }

    /// Whether the caller-filtered metadata advertised a removal route.
    #[must_use]
    pub const fn can_remove(&self) -> bool {
        self.remove
    }

    /// Read this slot's engine-owned state out of one Registry Record.
    pub fn value_in(
        &self,
        record: &crate::RegistryRecord,
    ) -> Result<BRegAttachmentSlotValue, BRegAttachmentError> {
        match record.domain_data.get(&self.slot_identifier) {
            None => Ok(BRegAttachmentSlotValue::NotSelected),
            Some(Value::Null) => Ok(BRegAttachmentSlotValue::Empty),
            Some(value) => BRegAttachmentState::parse(&self.slot_identifier, value)
                .map(BRegAttachmentSlotValue::Filled),
        }
    }

    /// Bind a typed record UUID to this one exact slot route. This is not a
    /// general URI-template expander.
    #[must_use]
    pub(crate) fn path_for_record(&self, record_identifier: Uuid) -> String {
        format!(
            "{}/{record_identifier}/attachments/{}",
            self.collection_path, self.slot_identifier
        )
    }

    pub(crate) fn matches_source(&self, source: &str) -> bool {
        self.source_binding == source
    }

    /// Promote one served `x-registry-attachment` descriptor. The descriptor is
    /// inert response data until every member matches the engine contract.
    pub(crate) fn from_descriptor(
        source: &BRegAttachmentSource,
        slot_identifier: &str,
        descriptor: &Value,
    ) -> Result<Self, BRegAttachmentError> {
        let refuse = || BRegAttachmentError::InvalidSlotValue;
        let descriptor = descriptor.as_object().ok_or_else(refuse)?;
        let mut seen = 4;
        let required_for_submit = descriptor
            .get("requiredForSubmit")
            .and_then(Value::as_bool)
            .ok_or_else(refuse)?;
        let maximum_bytes = descriptor
            .get("maximumBytes")
            .and_then(Value::as_u64)
            .filter(|bytes| (1..=MAX_BREG_ATTACHMENT_BYTES).contains(bytes))
            .ok_or_else(refuse)?;
        let content_types = descriptor
            .get("contentTypes")
            .and_then(Value::as_array)
            .ok_or_else(refuse)?;
        if content_types.is_empty() || content_types.len() > MAX_BREG_ATTACHMENT_CONTENT_TYPES {
            return Err(refuse());
        }
        let content_types = content_types
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|value| valid_attachment_content_type(value))
                    .map(str::to_owned)
                    .ok_or_else(refuse)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut unique = content_types.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != content_types.len() {
            return Err(refuse());
        }
        exact_verification_policy(descriptor.get("verification").ok_or_else(refuse)?)?;

        let template = format!(
            "{}/{{record_id}}/attachments/{slot_identifier}",
            source.collection_path
        );
        let mut capability = |member: &str, method: &str| -> Result<bool, BRegAttachmentError> {
            let Some(value) = descriptor.get(member) else {
                return Ok(false);
            };
            seen += 1;
            exact_attachment_request(value, method, &template, &source.access_profile)?;
            Ok(true)
        };
        let download = capability("download", "GET")?;
        let upload = capability("upload", "PATCH")?;
        let remove = capability("remove", "DELETE")?;
        // The engine grants the removal route with the upload route or not at all.
        if upload != remove || descriptor.len() != seen {
            return Err(refuse());
        }

        Ok(Self {
            registry_identifier: source.registry_identifier.clone(),
            dataset_identifier: source.dataset_identifier.clone(),
            registry_revision: source.registry_revision.clone(),
            entity_identifier: source.entity_identifier.clone(),
            access_profile: source.access_profile.clone(),
            collection_path: source.collection_path.clone(),
            source_binding: source.source_binding.clone(),
            slot_identifier: slot_identifier.to_owned(),
            required_for_submit,
            maximum_bytes,
            content_types,
            download,
            upload,
            remove,
        })
    }
}

impl fmt::Debug for BRegAttachmentSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegAttachmentSlot")
            .field("required_for_submit", &self.required_for_submit)
            .field("maximum_bytes", &self.maximum_bytes)
            .field("content_type_count", &self.content_types.len())
            .field("download", &self.download)
            .field("upload", &self.upload)
            .field("remove", &self.remove)
            .finish_non_exhaustive()
    }
}

/// Bytes and one exact content type, refused before any request when the
/// selected slot cannot accept them.
#[derive(Clone, PartialEq, Eq)]
pub struct BRegAttachmentUpload {
    slot_identifier: String,
    content_type: String,
    bytes: Vec<u8>,
}

impl BRegAttachmentUpload {
    /// Bind exact bytes to one selected slot.
    ///
    /// This refuses an empty body, a body larger than the slot's
    /// `maximumBytes`, a content type outside the slot's `contentTypes`, and a
    /// slot whose caller-filtered metadata advertised no upload route.
    pub fn new(
        slot: &BRegAttachmentSlot,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Self, BRegAttachmentError> {
        if !slot.can_upload() {
            return Err(BRegAttachmentError::UploadNotAdvertised);
        }
        if bytes.is_empty() {
            return Err(BRegAttachmentError::EmptyUpload);
        }
        if bytes.len() as u64 > slot.maximum_bytes() {
            return Err(BRegAttachmentError::UploadTooLarge);
        }
        if !valid_attachment_content_type(content_type) {
            return Err(BRegAttachmentError::InvalidContentType);
        }
        if !slot.accepts_content_type(content_type) {
            return Err(BRegAttachmentError::ContentTypeNotAccepted);
        }
        Ok(Self {
            slot_identifier: slot.slot_identifier().to_owned(),
            content_type: content_type.to_owned(),
            bytes,
        })
    }

    /// Exact `Content-Type` this upload will send.
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Number of bytes this upload will send.
    #[must_use]
    pub fn byte_size(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn matches_slot(&self, slot: &BRegAttachmentSlot) -> bool {
        self.slot_identifier == slot.slot_identifier
    }
}

impl fmt::Debug for BRegAttachmentUpload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegAttachmentUpload")
            .field("content_type", &self.content_type)
            .field("byte_size", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// What one record projection says about one slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BRegAttachmentSlotValue {
    /// The projection did not select this slot. Nothing is known about it.
    NotSelected,
    /// The slot was selected and holds nothing.
    Empty,
    /// The slot was selected and holds one engine-owned value.
    Filled(BRegAttachmentState),
}

impl BRegAttachmentSlotValue {
    /// The engine-owned state, when the slot was selected and is filled.
    #[must_use]
    pub const fn filled(&self) -> Option<&BRegAttachmentState> {
        match self {
            Self::Filled(state) => Some(state),
            Self::NotSelected | Self::Empty => None,
        }
    }
}

/// Engine-owned state of one filled slot, read from a record's `domainData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BRegAttachmentState {
    slot_identifier: String,
    proposal_version: u32,
    erased: bool,
    byte_size: u64,
    sha256: String,
    content_type: Option<String>,
    uploaded_at: Option<String>,
    uploaded_by: Option<String>,
    verification_status: Option<BRegAttachmentVerificationStatus>,
}

impl BRegAttachmentState {
    /// Slot this value belongs to.
    #[must_use]
    pub fn slot_identifier(&self) -> &str {
        &self.slot_identifier
    }

    /// Proposal version the bytes were uploaded against.
    #[must_use]
    pub const fn proposal_version(&self) -> u32 {
        self.proposal_version
    }

    /// Whether retention has erased the bytes while keeping the record of them.
    #[must_use]
    pub const fn erased(&self) -> bool {
        self.erased
    }

    /// Server-computed byte size.
    #[must_use]
    pub const fn byte_size(&self) -> u64 {
        self.byte_size
    }

    /// Server-computed lowercase hexadecimal SHA-256 of the stored bytes.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Stored content type. Absent once the bytes are erased. A retained value
    /// may predate a narrower current upload policy.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Server-recorded upload timestamp. Absent once the bytes are erased.
    #[must_use]
    pub fn uploaded_at(&self) -> Option<&str> {
        self.uploaded_at.as_deref()
    }

    /// Server-recorded uploading actor. Absent once the bytes are erased.
    #[must_use]
    pub fn uploaded_by(&self) -> Option<&str> {
        self.uploaded_by.as_deref()
    }

    /// Verification verdict. Absent once the bytes are erased.
    #[must_use]
    pub const fn verification_status(&self) -> Option<BRegAttachmentVerificationStatus> {
        self.verification_status
    }

    fn parse(slot_identifier: &str, value: &Value) -> Result<Self, BRegAttachmentError> {
        let refuse = || BRegAttachmentError::InvalidSlotValue;
        let value = value.as_object().ok_or_else(refuse)?;
        if value.get("slotId").and_then(Value::as_str) != Some(slot_identifier)
            || value.get("filled").and_then(Value::as_bool) != Some(true)
        {
            return Err(refuse());
        }
        let proposal_version = value
            .get("proposalVersion")
            .and_then(Value::as_u64)
            .filter(|version| *version >= 1)
            .and_then(|version| u32::try_from(version).ok())
            .ok_or_else(refuse)?;
        let sha256 = value
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|digest| {
                digest.len() == SHA256_HEX_LENGTH
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
            .ok_or_else(refuse)?
            .to_owned();
        let byte_size = value
            .get("byteSize")
            .and_then(Value::as_u64)
            .filter(|size| (1..=MAX_BREG_ATTACHMENT_BYTES).contains(size))
            .ok_or_else(refuse)?;
        let erased = value
            .get("erased")
            .and_then(Value::as_bool)
            .ok_or_else(refuse)?;
        let live = [
            "contentType",
            "uploadedAt",
            "uploadedBy",
            "verificationStatus",
        ];
        if erased {
            if live.iter().any(|member| value.contains_key(*member)) || value.len() != 6 {
                return Err(refuse());
            }
            return Ok(Self {
                slot_identifier: slot_identifier.to_owned(),
                proposal_version,
                erased,
                byte_size,
                sha256,
                content_type: None,
                uploaded_at: None,
                uploaded_by: None,
                verification_status: None,
            });
        }
        if value.len() != 6 + live.len() {
            return Err(refuse());
        }
        let content_type = value
            .get("contentType")
            .and_then(Value::as_str)
            .filter(|value| valid_attachment_content_type(value))
            .ok_or_else(refuse)?
            .to_owned();
        let uploaded_at = bounded_text(value.get("uploadedAt"), MAX_TIMESTAMP_BYTES)?;
        let uploaded_by = bounded_text(value.get("uploadedBy"), MAX_ACTOR_REFERENCE_BYTES)?;
        let verification_status = value
            .get("verificationStatus")
            .and_then(Value::as_str)
            .and_then(BRegAttachmentVerificationStatus::parse)
            .ok_or_else(refuse)?;
        Ok(Self {
            slot_identifier: slot_identifier.to_owned(),
            proposal_version,
            erased,
            byte_size,
            sha256,
            content_type: Some(content_type),
            uploaded_at: Some(uploaded_at),
            uploaded_by: Some(uploaded_by),
            verification_status: Some(verification_status),
        })
    }
}

fn bounded_text(value: Option<&Value>, maximum: usize) -> Result<String, BRegAttachmentError> {
    value
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
        .ok_or(BRegAttachmentError::InvalidSlotValue)
}

/// The exact concrete media type grammar the engine compiles and serves: one
/// lowercase `type/subtype` pair with no parameters and no wildcard.
#[must_use]
pub fn valid_attachment_content_type(value: &str) -> bool {
    fn component(value: &str) -> bool {
        let mut bytes = value.bytes();
        (1..=127).contains(&value.len())
            && bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(
                        byte,
                        b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                    )
            })
    }
    value.len() <= MAX_BREG_ATTACHMENT_CONTENT_TYPE_BYTES
        && value
            .split_once('/')
            .is_some_and(|(kind, subtype)| component(kind) && component(subtype))
}

fn exact_verification_policy(value: &Value) -> Result<(), BRegAttachmentError> {
    let expected = serde_json::json!({
        "statusField": "verificationStatus",
        "allowedStatuses": ["notRequired", "approved"],
        "pendingOrRejectedBlocks": ["download", "submit"]
    });
    if value == &expected {
        return Ok(());
    }
    Err(BRegAttachmentError::InvalidSlotValue)
}

fn exact_attachment_request(
    value: &Value,
    method: &str,
    template: &str,
    access_profile: &str,
) -> Result<(), BRegAttachmentError> {
    let read = method == "GET";
    let mut expected = Map::from_iter([
        ("method".to_owned(), Value::from(method)),
        ("path".to_owned(), Value::from(template)),
        ("accessProfile".to_owned(), Value::from(access_profile)),
        (
            "authorizationOperation".to_owned(),
            Value::from(if read { "get" } else { "patch" }),
        ),
        (
            "queryParameters".to_owned(),
            if read {
                Value::from(vec!["proposalVersion"])
            } else {
                Value::Array(Vec::new())
            },
        ),
        (
            "body".to_owned(),
            Value::from(if method == "PATCH" { "binary" } else { "none" }),
        ),
        ("ifMatchRequired".to_owned(), Value::from(!read)),
        ("idempotencyKeyRequired".to_owned(), Value::from(!read)),
    ]);
    if read {
        expected.insert("proposalVersionRequired".to_owned(), Value::from(true));
    } else {
        expected.insert("requiredState".to_owned(), Value::from("draft"));
    }
    if value == &Value::Object(expected) {
        return Ok(());
    }
    Err(BRegAttachmentError::InvalidSlotValue)
}
