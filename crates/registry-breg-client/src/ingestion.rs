// SPDX-License-Identifier: Apache-2.0

//! Durable, resumable ingestion runs over one entity's compiled batch route.
//!
//! An ingestion run is the service-side account of one bulk import: the caller
//! announces the whole input once, submits one bounded chunk at a time, and can
//! re-read any committed chunk's receipt. The source bytes stay caller-owned;
//! only announced digests and one chunk at a time cross the wire. Chunk items
//! are the same batch items the entity's atomic batch route executes, and a
//! receipt holds exactly what that route answers the same authorized caller
//! with, erased together with the record history it describes.

use std::fmt;

use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::client::{access_profile_query, valid_breg_identifier, validate_entity_route};
use crate::mutation::{validate_json_values, MAXIMUM_BREG_MUTATION_BODY_BYTES};
use crate::{
    BRegBatchOperation, BRegComplete, BRegRawDocument, BaseRegistryClient, BaseRegistryClientError,
};

/// The chunk-planning algorithm this client derives chunk digests for. A run
/// refuses any other algorithm, so remaining source bytes are never
/// reinterpreted under a different chunking contract.
pub const BREG_INGESTION_CHUNK_ALGORITHM_VERSION: &str = "greedy-canonical-http-batch-v1";

const SHA256_HEX_LENGTH: usize = 64;
const MAXIMUM_BOUND_TEXT_BYTES: usize = 256;
const MAXIMUM_TIMESTAMP_BYTES: usize = 128;
const MAXIMUM_CURSOR_BYTES: usize = 4096;
const MAXIMUM_SNAPSHOT_REFERENCE_BYTES: usize = 4 * 1024;
/// Runs are operator-driven and few; one page stays explicitly bounded.
const MAXIMUM_RUN_PAGE_LIMIT: u32 = 100;

/// A value-free reason an ingestion-run exchange cannot be constructed or decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegIngestionError {
    #[error("the Base Registry Engine ingestion run binding is invalid")]
    InvalidBinding,
    #[error("the Base Registry Engine ingestion run announces an unsupported chunk algorithm")]
    UnsupportedChunkAlgorithm,
    #[error("a Base Registry Engine ingestion digest is not a lowercase SHA-256 value")]
    InvalidDigest,
    #[error("the Base Registry Engine ingestion page limit is invalid")]
    InvalidLimit,
    #[error("the Base Registry Engine ingestion page cursor is invalid")]
    InvalidCursor,
    #[error(
        "the Base Registry Engine ingestion chunk must contain at least one batch item object"
    )]
    EmptyChunk,
    #[error("a Base Registry Engine ingestion chunk item is not a valid batch item")]
    InvalidItem,
    #[error("the Base Registry Engine ingestion request body exceeds 2097152 encoded bytes")]
    BodyTooLarge,
    #[error("the Base Registry Engine ingestion request body could not be encoded")]
    BodyEncoding,
    #[error("the Base Registry Engine ingestion response does not match the run contract")]
    InvalidResponse,
    #[error("an erased Base Registry Engine chunk receipt is never answered with a receipt body")]
    ErasedReceipt,
}

/// Closed status of one durable ingestion run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegIngestionRunStatus {
    Open,
    Complete,
    Cancelled,
    Blocked,
}

impl BRegIngestionRunStatus {
    /// Every run status the wire contract names.
    pub const ALL: [Self; 4] = [Self::Open, Self::Complete, Self::Cancelled, Self::Blocked];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Blocked => "blocked",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
    }
}

impl Serialize for BRegIngestionRunStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// The one reason an open run refuses chunk submissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegIngestionBlockedReason {
    ActivePackageChanged,
}

impl BRegIngestionBlockedReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivePackageChanged => "activePackageChanged",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "activePackageChanged" => Some(Self::ActivePackageChanged),
            _ => None,
        }
    }
}

impl Serialize for BRegIngestionBlockedReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// The bounded, value-free classification of the last chunk attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BRegIngestionAttemptOutcome {
    Committed,
    Replayed,
    InvalidItem,
    Refused,
    BindingChanged,
    ChunkMismatch,
    RunNotOpen,
    Unavailable,
}

impl BRegIngestionAttemptOutcome {
    /// Every attempt outcome the wire contract names.
    pub const ALL: [Self; 8] = [
        Self::Committed,
        Self::Replayed,
        Self::InvalidItem,
        Self::Refused,
        Self::BindingChanged,
        Self::ChunkMismatch,
        Self::RunNotOpen,
        Self::Unavailable,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Replayed => "replayed",
            Self::InvalidItem => "invalidItem",
            Self::Refused => "refused",
            Self::BindingChanged => "bindingChanged",
            Self::ChunkMismatch => "chunkMismatch",
            Self::RunNotOpen => "runNotOpen",
            Self::Unavailable => "unavailable",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|outcome| outcome.as_str() == value)
    }
}

impl Serialize for BRegIngestionAttemptOutcome {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// The outcome of the most recent chunk attempt on one run.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegIngestionAttempt {
    outcome: BRegIngestionAttemptOutcome,
    chunk_index: Option<u64>,
}

impl BRegIngestionAttempt {
    #[must_use]
    pub const fn outcome(&self) -> BRegIngestionAttemptOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn chunk_index(&self) -> Option<u64> {
        self.chunk_index
    }

    fn from_value(value: &Value) -> Result<Self, BRegIngestionError> {
        let attempt = value
            .as_object()
            .ok_or(BRegIngestionError::InvalidResponse)?;
        if attempt.len() != 2
            || !attempt.contains_key("outcome")
            || !attempt.contains_key("chunkIndex")
        {
            return Err(BRegIngestionError::InvalidResponse);
        }
        let outcome = attempt["outcome"]
            .as_str()
            .and_then(BRegIngestionAttemptOutcome::parse)
            .ok_or(BRegIngestionError::InvalidResponse)?;
        let chunk_index = match &attempt["chunkIndex"] {
            Value::Null => None,
            value => Some(value.as_u64().ok_or(BRegIngestionError::InvalidResponse)?),
        };
        Ok(Self {
            outcome,
            chunk_index,
        })
    }
}

/// The durable, operational view of one ingestion run.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegIngestionRun {
    #[serde(serialize_with = "serialize_uuid")]
    run_id: Uuid,
    status: BRegIngestionRunStatus,
    blocked_reason: Option<BRegIngestionBlockedReason>,
    entity_id: String,
    operation: BRegBatchOperation,
    profile_id: String,
    package_revision: String,
    schema_fingerprint: String,
    input_digest: String,
    input_length: u64,
    item_count: u64,
    chunk_count: u64,
    chunk_algorithm_version: String,
    maximum_items: u64,
    maximum_bytes: u64,
    next_chunk_index: u64,
    committed_items: u64,
    committed_prefix_digest: String,
    last_attempt: Option<BRegIngestionAttempt>,
    created_at: String,
    updated_at: String,
    complete: bool,
}

impl BRegIngestionRun {
    #[must_use]
    pub const fn run_id(&self) -> Uuid {
        self.run_id
    }

    #[must_use]
    pub const fn status(&self) -> BRegIngestionRunStatus {
        self.status
    }

    #[must_use]
    pub const fn blocked_reason(&self) -> Option<BRegIngestionBlockedReason> {
        self.blocked_reason
    }

    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    #[must_use]
    pub const fn operation(&self) -> BRegBatchOperation {
        self.operation
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn package_revision(&self) -> &str {
        &self.package_revision
    }

    #[must_use]
    pub fn schema_fingerprint(&self) -> &str {
        &self.schema_fingerprint
    }

    #[must_use]
    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    #[must_use]
    pub const fn input_length(&self) -> u64 {
        self.input_length
    }

    #[must_use]
    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    #[must_use]
    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    #[must_use]
    pub fn chunk_algorithm_version(&self) -> &str {
        &self.chunk_algorithm_version
    }

    #[must_use]
    pub const fn maximum_items(&self) -> u64 {
        self.maximum_items
    }

    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    /// The next chunk the run expects; equals `chunk_count` once every chunk is committed.
    #[must_use]
    pub const fn next_chunk_index(&self) -> u64 {
        self.next_chunk_index
    }

    #[must_use]
    pub const fn committed_items(&self) -> u64 {
        self.committed_items
    }

    #[must_use]
    pub fn committed_prefix_digest(&self) -> &str {
        &self.committed_prefix_digest
    }

    #[must_use]
    pub const fn last_attempt(&self) -> Option<&BRegIngestionAttempt> {
        self.last_attempt.as_ref()
    }

    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    #[must_use]
    pub fn updated_at(&self) -> &str {
        &self.updated_at
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    fn from_value(value: Value) -> Result<Self, BRegIngestionError> {
        const MEMBERS: [&str; 22] = [
            "runId",
            "status",
            "blockedReason",
            "entityId",
            "operation",
            "profileId",
            "packageRevision",
            "schemaFingerprint",
            "inputDigest",
            "inputLength",
            "itemCount",
            "chunkCount",
            "chunkAlgorithmVersion",
            "maximumItems",
            "maximumBytes",
            "nextChunkIndex",
            "committedItems",
            "committedPrefixDigest",
            "lastAttempt",
            "createdAt",
            "updatedAt",
            "complete",
        ];
        let refuse = BRegIngestionError::InvalidResponse;
        let object = value.as_object().ok_or(refuse)?;
        if object.len() != MEMBERS.len()
            || MEMBERS.iter().any(|member| !object.contains_key(*member))
        {
            return Err(refuse);
        }
        let run_id = text_member(object, "runId")?;
        let run_id = Uuid::parse_str(run_id)
            .ok()
            .filter(|identifier| identifier.to_string() == run_id)
            .ok_or(refuse)?;
        let status = text_member(object, "status")?;
        let status = BRegIngestionRunStatus::parse(status).ok_or(refuse)?;
        let blocked_reason = match &object["blockedReason"] {
            Value::Null => None,
            value => Some(
                value
                    .as_str()
                    .and_then(BRegIngestionBlockedReason::parse)
                    .ok_or(refuse)?,
            ),
        };
        let entity_id = text_member(object, "entityId")?;
        if !valid_breg_identifier(entity_id) {
            return Err(refuse);
        }
        let operation = text_member(object, "operation")?;
        let operation = BRegBatchOperation::parse(operation).ok_or(refuse)?;
        let profile_id = text_member(object, "profileId")?;
        let package_revision = text_member(object, "packageRevision")?;
        let schema_fingerprint = text_member(object, "schemaFingerprint")?;
        if ![profile_id, package_revision, schema_fingerprint]
            .iter()
            .all(|value| bounded_text(value))
        {
            return Err(refuse);
        }
        let input_digest = text_member(object, "inputDigest")?;
        let committed_prefix_digest = text_member(object, "committedPrefixDigest")?;
        if !is_sha256_hex(input_digest) || !is_sha256_hex(committed_prefix_digest) {
            return Err(refuse);
        }
        let input_length = number_member(object, "inputLength")?;
        let item_count = number_member(object, "itemCount")?;
        let chunk_count = number_member(object, "chunkCount")?;
        let maximum_items = number_member(object, "maximumItems")?;
        let maximum_bytes = number_member(object, "maximumBytes")?;
        let next_chunk_index = number_member(object, "nextChunkIndex")?;
        let committed_items = number_member(object, "committedItems")?;
        if item_count == 0
            || chunk_count == 0
            || maximum_items == 0
            || maximum_bytes == 0
            || next_chunk_index > chunk_count
            || committed_items > item_count
        {
            return Err(refuse);
        }
        let chunk_algorithm_version = text_member(object, "chunkAlgorithmVersion")?;
        if !bounded_text(chunk_algorithm_version) {
            return Err(refuse);
        }
        let last_attempt = match &object["lastAttempt"] {
            Value::Null => None,
            value => Some(BRegIngestionAttempt::from_value(value)?),
        };
        let created_at = timestamp(text_member(object, "createdAt")?).ok_or(refuse)?;
        let updated_at = timestamp(text_member(object, "updatedAt")?).ok_or(refuse)?;
        let complete = object["complete"].as_bool().ok_or(refuse)?;
        // A blocked run always names its reason, and only a complete run
        // reports the run as complete.
        if blocked_reason.is_some() != (status == BRegIngestionRunStatus::Blocked)
            || complete != (status == BRegIngestionRunStatus::Complete)
        {
            return Err(refuse);
        }
        Ok(Self {
            run_id,
            status,
            blocked_reason,
            entity_id: entity_id.to_owned(),
            operation,
            profile_id: profile_id.to_owned(),
            package_revision: package_revision.to_owned(),
            schema_fingerprint: schema_fingerprint.to_owned(),
            input_digest: input_digest.to_owned(),
            input_length,
            item_count,
            chunk_count,
            chunk_algorithm_version: chunk_algorithm_version.to_owned(),
            maximum_items,
            maximum_bytes,
            next_chunk_index,
            committed_items,
            committed_prefix_digest: committed_prefix_digest.to_owned(),
            last_attempt,
            created_at: created_at.to_owned(),
            updated_at: updated_at.to_owned(),
            complete,
        })
    }
}

/// One page of a bounded ingestion-run listing.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegIngestionRunPage {
    runs: Vec<BRegIngestionRun>,
    has_more: bool,
    next_after: Option<String>,
}

impl BRegIngestionRunPage {
    #[must_use]
    pub fn runs(&self) -> &[BRegIngestionRun] {
        &self.runs
    }

    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    /// The opaque cursor for the next page, present exactly when more runs remain.
    #[must_use]
    pub fn next_after(&self) -> Option<&str> {
        self.next_after.as_deref()
    }

    fn from_members(object: &mut Map<String, Value>) -> Result<Self, BRegIngestionError> {
        let refuse = BRegIngestionError::InvalidResponse;
        let runs = take_member(object, "runs")?
            .as_array()
            .ok_or(refuse)?
            .iter()
            .cloned()
            .map(BRegIngestionRun::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = take_member(object, "hasMore")?.as_bool().ok_or(refuse)?;
        let next_after = match take_member(object, "nextAfter")? {
            Value::Null => None,
            value => Some(cursor_text(value.as_str().ok_or(refuse)?)?),
        };
        if has_more != next_after.is_some() || !object.is_empty() {
            return Err(refuse);
        }
        Ok(Self {
            runs,
            has_more,
            next_after,
        })
    }
}

/// One bounded batch answer retained by an ingestion run.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegIngestionChunkReceipt {
    chunk_index: u64,
    digest: String,
    replayed: bool,
    erased: bool,
    batch: BRegIngestionReceiptBatch,
}

impl BRegIngestionChunkReceipt {
    #[must_use]
    pub const fn chunk_index(&self) -> u64 {
        self.chunk_index
    }

    /// The chunk digest the committed body was bound to.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Whether the chunk had already been committed and was replayed.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Always false in a receipt body: an erased receipt answers with the
    /// `ingestion.receipt_erased` problem instead.
    #[must_use]
    pub const fn erased(&self) -> bool {
        self.erased
    }

    #[must_use]
    pub const fn batch(&self) -> &BRegIngestionReceiptBatch {
        &self.batch
    }

    fn from_value(value: Value) -> Result<Self, BRegIngestionError> {
        const MEMBERS: [&str; 5] = ["chunkIndex", "digest", "replayed", "erased", "batch"];
        let refuse = BRegIngestionError::InvalidResponse;
        let object = value.as_object().ok_or(refuse)?;
        if object.len() != MEMBERS.len()
            || MEMBERS.iter().any(|member| !object.contains_key(*member))
        {
            return Err(refuse);
        }
        let chunk_index = number_member(object, "chunkIndex")?;
        let digest = text_member(object, "digest")?;
        if !is_sha256_hex(digest) {
            return Err(refuse);
        }
        let replayed = object["replayed"].as_bool().ok_or(refuse)?;
        let erased = object["erased"].as_bool().ok_or(refuse)?;
        if erased {
            return Err(BRegIngestionError::ErasedReceipt);
        }
        let batch = BRegIngestionReceiptBatch::from_value(&object["batch"])?;
        Ok(Self {
            chunk_index,
            digest: digest.to_owned(),
            replayed,
            erased,
            batch,
        })
    }
}

/// The snapshot reference and final item states one committed chunk produced.
///
/// The results are the same members the entity's batch route answers the same
/// authorized caller with, preserved as inert values: the run receipt adds no
/// interpretation of its own.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegIngestionReceiptBatch {
    snapshot: String,
    results: Vec<Value>,
}

impl BRegIngestionReceiptBatch {
    #[must_use]
    pub fn snapshot(&self) -> &str {
        &self.snapshot
    }

    #[must_use]
    pub fn results(&self) -> &[Value] {
        &self.results
    }

    fn from_value(value: &Value) -> Result<Self, BRegIngestionError> {
        let refuse = BRegIngestionError::InvalidResponse;
        let object = value.as_object().ok_or(refuse)?;
        if object.len() != 2 || !object.contains_key("snapshot") || !object.contains_key("results")
        {
            return Err(refuse);
        }
        let snapshot = object["snapshot"]
            .as_str()
            .filter(|value| {
                value.len() <= MAXIMUM_SNAPSHOT_REFERENCE_BYTES
                    && value
                        .strip_prefix("breg1_")
                        .and_then(|value| {
                            Uuid::parse_str(value)
                                .ok()
                                .filter(|identifier| identifier.to_string() == value)
                        })
                        .is_some()
            })
            .ok_or(refuse)?
            .to_owned();
        let results = object["results"].as_array().ok_or(refuse)?.clone();
        Ok(Self { snapshot, results })
    }
}

/// A committed chunk together with the run state it left behind.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegIngestionChunkSubmission {
    run: BRegIngestionRun,
    receipt: BRegIngestionChunkReceipt,
}

impl BRegIngestionChunkSubmission {
    #[must_use]
    pub const fn run(&self) -> &BRegIngestionRun {
        &self.run
    }

    #[must_use]
    pub const fn receipt(&self) -> &BRegIngestionChunkReceipt {
        &self.receipt
    }

    fn from_members(object: &mut Map<String, Value>) -> Result<Self, BRegIngestionError> {
        let run = BRegIngestionRun::from_value(take_member(object, "run")?)?;
        let receipt = BRegIngestionChunkReceipt::from_value(take_member(object, "receipt")?)?;
        if !object.is_empty() {
            return Err(BRegIngestionError::InvalidResponse);
        }
        Ok(Self { run, receipt })
    }
}

/// The whole-input announcement that opens one ingestion run.
pub struct BRegIngestionRunRequest {
    body: Zeroizing<Vec<u8>>,
    operation: BRegBatchOperation,
    profile_id: String,
    package_revision: String,
    schema_fingerprint: String,
    input_digest: String,
    input_length: u64,
    item_count: u64,
    chunk_count: u64,
    chunk_algorithm_version: String,
}

impl BRegIngestionRunRequest {
    /// Start the announcement builder.
    #[must_use]
    pub fn builder() -> BRegIngestionRunRequestBuilder {
        BRegIngestionRunRequestBuilder::default()
    }

    #[must_use]
    pub const fn operation(&self) -> BRegBatchOperation {
        self.operation
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    #[must_use]
    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    #[must_use]
    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    /// Return the encoded body size without exposing its values.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

impl fmt::Debug for BRegIngestionRunRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegIngestionRunRequest")
            .field("body_bytes", &self.body.len())
            .field("operation", &self.operation)
            .field("item_count", &self.item_count)
            .field("chunk_count", &self.chunk_count)
            .finish_non_exhaustive()
    }
}

/// Builds the exact whole-input announcement body.
#[derive(Clone, Default)]
pub struct BRegIngestionRunRequestBuilder {
    operation: Option<BRegBatchOperation>,
    profile_id: Option<String>,
    package_revision: Option<String>,
    schema_fingerprint: Option<String>,
    input_digest: Option<String>,
    input_length: Option<u64>,
    item_count: Option<u64>,
    chunk_count: Option<u64>,
    chunk_algorithm_version: Option<String>,
}

impl BRegIngestionRunRequestBuilder {
    /// Select the one-shot operation every chunk's items use.
    pub fn operation(mut self, operation: BRegBatchOperation) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Name the access profile the run and its chunk submissions travel under.
    pub fn profile(mut self, value: impl Into<String>) -> Result<Self, BRegIngestionError> {
        self.profile_id = Some(bound_member(value)?);
        Ok(self)
    }

    /// Bind the run to one exact package revision.
    pub fn package_revision(
        mut self,
        value: impl Into<String>,
    ) -> Result<Self, BRegIngestionError> {
        self.package_revision = Some(bound_member(value)?);
        Ok(self)
    }

    /// Bind the run to one exact schema fingerprint.
    pub fn schema_fingerprint(
        mut self,
        value: impl Into<String>,
    ) -> Result<Self, BRegIngestionError> {
        self.schema_fingerprint = Some(bound_member(value)?);
        Ok(self)
    }

    /// Announce the lowercase SHA-256 of the complete source input.
    pub fn input_digest(mut self, value: impl Into<String>) -> Result<Self, BRegIngestionError> {
        let value = value.into();
        if !is_sha256_hex(&value) {
            return Err(BRegIngestionError::InvalidDigest);
        }
        self.input_digest = Some(value);
        Ok(self)
    }

    /// Announce the complete source input size in bytes.
    #[must_use]
    pub fn input_length(mut self, value: u64) -> Self {
        self.input_length = Some(value);
        self
    }

    /// Announce the total item count, which must be positive.
    pub fn item_count(mut self, value: u64) -> Result<Self, BRegIngestionError> {
        if value == 0 {
            return Err(BRegIngestionError::InvalidBinding);
        }
        self.item_count = Some(value);
        Ok(self)
    }

    /// Announce the planned chunk count, which must be positive.
    pub fn chunk_count(mut self, value: u64) -> Result<Self, BRegIngestionError> {
        if value == 0 {
            return Err(BRegIngestionError::InvalidBinding);
        }
        self.chunk_count = Some(value);
        Ok(self)
    }

    /// Announce the chunk algorithm. Only
    /// [`BREG_INGESTION_CHUNK_ALGORITHM_VERSION`] is supported, because it is
    /// the only algorithm this client can derive chunk digests for.
    pub fn chunk_algorithm_version(
        mut self,
        value: impl Into<String>,
    ) -> Result<Self, BRegIngestionError> {
        let value = value.into();
        if value != BREG_INGESTION_CHUNK_ALGORITHM_VERSION {
            return Err(BRegIngestionError::UnsupportedChunkAlgorithm);
        }
        self.chunk_algorithm_version = Some(value);
        Ok(self)
    }

    /// Finish the announcement after checking every member and body bound.
    pub fn build(self) -> Result<BRegIngestionRunRequest, BRegIngestionError> {
        let request = BRegIngestionRunRequest {
            operation: self.operation.ok_or(BRegIngestionError::InvalidBinding)?,
            profile_id: self.profile_id.ok_or(BRegIngestionError::InvalidBinding)?,
            package_revision: self
                .package_revision
                .ok_or(BRegIngestionError::InvalidBinding)?,
            schema_fingerprint: self
                .schema_fingerprint
                .ok_or(BRegIngestionError::InvalidBinding)?,
            input_digest: self
                .input_digest
                .ok_or(BRegIngestionError::InvalidBinding)?,
            input_length: self
                .input_length
                .ok_or(BRegIngestionError::InvalidBinding)?,
            item_count: self.item_count.ok_or(BRegIngestionError::InvalidBinding)?,
            chunk_count: self.chunk_count.ok_or(BRegIngestionError::InvalidBinding)?,
            chunk_algorithm_version: self
                .chunk_algorithm_version
                .ok_or(BRegIngestionError::InvalidBinding)?,
            body: Zeroizing::new(Vec::new()),
        };
        let body = serde_json::to_vec(&request).map_err(|_| BRegIngestionError::BodyEncoding)?;
        if body.len() > MAXIMUM_BREG_MUTATION_BODY_BYTES {
            return Err(BRegIngestionError::BodyTooLarge);
        }
        Ok(BRegIngestionRunRequest::with_body(request, body))
    }
}

impl BRegIngestionRunRequest {
    fn with_body(mut request: Self, body: Vec<u8>) -> Self {
        request.body = Zeroizing::new(body);
        request
    }
}

impl Serialize for BRegIngestionRunRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BRegIngestionRunRequest", 9)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("profileId", &self.profile_id)?;
        state.serialize_field("packageRevision", &self.package_revision)?;
        state.serialize_field("schemaFingerprint", &self.schema_fingerprint)?;
        state.serialize_field("inputDigest", &self.input_digest)?;
        state.serialize_field("inputLength", &self.input_length)?;
        state.serialize_field("itemCount", &self.item_count)?;
        state.serialize_field("chunkCount", &self.chunk_count)?;
        state.serialize_field("chunkAlgorithmVersion", &self.chunk_algorithm_version)?;
        state.end()
    }
}

/// One bounded, digest-bound chunk submission of an ingestion run.
///
/// The chunk digest is derived here from the exact items, so an encoded chunk
/// can never announce a digest its body does not hash to.
pub struct BRegIngestionChunk {
    body: Zeroizing<Vec<u8>>,
    chunk_index: u64,
    item_count: usize,
    digest: String,
    prefix_digest: String,
}

impl BRegIngestionChunk {
    /// Encode one chunk submission.
    ///
    /// `prefix_digest` is required: it is the lowercase SHA-256 of the
    /// complete raw source input through the end of this chunk, which
    /// [`ingestion_prefix_digest`] derives, and the encoded envelope always
    /// carries it. The chunk digest is derived from the exact canonical batch
    /// body the items hash to.
    pub fn new(
        chunk_index: u64,
        items: Vec<Value>,
        prefix_digest: impl Into<String>,
    ) -> Result<Self, BRegIngestionError> {
        if items.is_empty() {
            return Err(BRegIngestionError::EmptyChunk);
        }
        if items.iter().any(|item| !item.is_object()) {
            return Err(BRegIngestionError::InvalidItem);
        }
        validate_json_values(&items, 2).map_err(|_| BRegIngestionError::InvalidItem)?;
        let digest = ingestion_chunk_digest(&items)?;
        let prefix_digest = prefix_digest.into();
        if !is_sha256_hex(&prefix_digest) {
            return Err(BRegIngestionError::InvalidDigest);
        }
        let envelope = BRegIngestionChunkEnvelope {
            chunk_index,
            items: &items,
            digest: &digest,
            prefix_digest: &prefix_digest,
        };
        let body = serde_json::to_vec(&envelope).map_err(|_| BRegIngestionError::BodyEncoding)?;
        if body.len() > MAXIMUM_BREG_MUTATION_BODY_BYTES {
            return Err(BRegIngestionError::BodyTooLarge);
        }
        Ok(Self {
            body: Zeroizing::new(body),
            chunk_index,
            item_count: items.len(),
            digest,
            prefix_digest,
        })
    }

    #[must_use]
    pub const fn chunk_index(&self) -> u64 {
        self.chunk_index
    }

    #[must_use]
    pub const fn item_count(&self) -> usize {
        self.item_count
    }

    /// The derived lowercase SHA-256 of the chunk's canonical batch body.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn prefix_digest(&self) -> &str {
        &self.prefix_digest
    }

    /// Return the encoded body size without exposing its values.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

impl fmt::Debug for BRegIngestionChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegIngestionChunk")
            .field("body_bytes", &self.body.len())
            .field("chunk_index", &self.chunk_index)
            .field("item_count", &self.item_count)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BRegIngestionChunkEnvelope<'a> {
    chunk_index: u64,
    items: &'a [Value],
    digest: &'a str,
    prefix_digest: &'a str,
}

/// Bounded filters for one ingestion-run listing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BRegIngestionRunListQuery {
    access_profile: Option<String>,
    status: Option<BRegIngestionRunStatus>,
    input_digest: Option<String>,
    limit: Option<u32>,
    after: Option<String>,
}

impl BRegIngestionRunListQuery {
    /// List runs under one access profile, selected as the `accessProfile`
    /// query pair of every exchange the listing travels on.
    pub fn access_profile(mut self, value: impl Into<String>) -> Result<Self, BRegIngestionError> {
        self.access_profile = Some(bound_member(value)?);
        Ok(self)
    }

    /// List only runs in one status.
    #[must_use]
    pub fn status(mut self, status: BRegIngestionRunStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// List only runs announced with one input digest.
    pub fn input_digest(mut self, value: impl Into<String>) -> Result<Self, BRegIngestionError> {
        let value = value.into();
        if !is_sha256_hex(&value) {
            return Err(BRegIngestionError::InvalidDigest);
        }
        self.input_digest = Some(value);
        Ok(self)
    }

    /// Bound the page at 1 through [`MAXIMUM_RUN_PAGE_LIMIT`] runs.
    pub fn limit(mut self, value: u32) -> Result<Self, BRegIngestionError> {
        if value == 0 || value > MAXIMUM_RUN_PAGE_LIMIT {
            return Err(BRegIngestionError::InvalidLimit);
        }
        self.limit = Some(value);
        Ok(self)
    }

    /// Continue after the opaque cursor a previous page returned.
    pub fn after(mut self, value: impl Into<String>) -> Result<Self, BRegIngestionError> {
        let value = value.into();
        self.after = Some(cursor_text(&value)?);
        Ok(self)
    }

    fn query_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::with_capacity(5);
        if let Some(profile) = &self.access_profile {
            pairs.push(("accessProfile".to_owned(), profile.clone()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit".to_owned(), limit.to_string()));
        }
        if let Some(after) = &self.after {
            pairs.push(("after".to_owned(), after.clone()));
        }
        if let Some(status) = self.status {
            pairs.push(("status".to_owned(), status.as_str().to_owned()));
        }
        if let Some(digest) = &self.input_digest {
            pairs.push(("inputDigest".to_owned(), digest.clone()));
        }
        pairs
    }
}

/// Derive the digest a chunk of `items` must announce: the lowercase SHA-256
/// of the canonical JSON batch body `{"items":[...]}` the entity's batch route
/// executes.
pub fn ingestion_chunk_digest(items: &[Value]) -> Result<String, BRegIngestionError> {
    canonical_chunk_body(items).map(|(_, digest)| digest)
}

/// Derive the prefix digest a chunk ending at these source bytes must
/// announce: the lowercase SHA-256 of the complete raw input through the end
/// of the chunk. Callers accumulate the raw source bytes and pass everything
/// up to and including the current chunk; the digest of an empty prefix is
/// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. The
/// digest is never a chain over chunk digests: the server binds and stores it
/// as an opaque value and cannot re-derive the raw bytes.
#[must_use]
pub fn ingestion_prefix_digest(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// An incremental [`ingestion_prefix_digest`]: absorbs the raw source bytes of
/// one ingestion input chunk by chunk and derives each prefix digest from the
/// retained hash state alone, without retaining or re-hashing the bytes.
#[derive(Clone, Default)]
pub struct BRegIngestionPrefixDigest {
    state: Sha256,
}

impl BRegIngestionPrefixDigest {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb the next raw source bytes, typically one chunk's source extent.
    pub fn update(&mut self, bytes: &[u8]) {
        self.state.update(bytes);
    }

    /// The lowercase SHA-256 of every raw source byte absorbed so far, exactly
    /// the digest [`ingestion_prefix_digest`] derives over those bytes.
    /// Deriving leaves the accumulator open for further absorption.
    #[must_use]
    pub fn digest(&self) -> String {
        hex_lower(&self.state.clone().finalize())
    }
}

/// The canonical batch body and its digest for the items of one chunk. A run
/// binds and stores exactly these bytes.
fn canonical_chunk_body(items: &[Value]) -> Result<(Vec<u8>, String), BRegIngestionError> {
    let body = canonicalize_json(&Value::Object(
        [("items".to_owned(), Value::Array(items.to_vec()))]
            .into_iter()
            .collect(),
    ))
    .map_err(|_| BRegIngestionError::InvalidItem)?;
    let digest = sha256_hex(&body);
    Ok((body, digest))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(SHA256_HEX_LENGTH);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_BOUND_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn cursor_text(value: &str) -> Result<String, BRegIngestionError> {
    if value.is_empty()
        || value.len() > MAXIMUM_CURSOR_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(BRegIngestionError::InvalidCursor);
    }
    Ok(value.to_owned())
}

fn bound_member(value: impl Into<String>) -> Result<String, BRegIngestionError> {
    let value = value.into();
    if !bounded_text(&value) {
        return Err(BRegIngestionError::InvalidBinding);
    }
    Ok(value)
}

fn timestamp(value: &str) -> Option<&str> {
    (value.len() <= MAXIMUM_TIMESTAMP_BYTES && OffsetDateTime::parse(value, &Rfc3339).is_ok())
        .then_some(value)
}

fn text_member<'a>(
    object: &'a Map<String, Value>,
    member: &str,
) -> Result<&'a str, BRegIngestionError> {
    object
        .get(member)
        .and_then(Value::as_str)
        .ok_or(BRegIngestionError::InvalidResponse)
}

fn number_member(object: &Map<String, Value>, member: &str) -> Result<u64, BRegIngestionError> {
    object
        .get(member)
        .and_then(Value::as_u64)
        .ok_or(BRegIngestionError::InvalidResponse)
}

fn take_member(object: &mut Map<String, Value>, member: &str) -> Result<Value, BRegIngestionError> {
    object
        .remove(member)
        .ok_or(BRegIngestionError::InvalidResponse)
}

fn serialize_uuid<S: serde::Serializer>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

fn decode_envelope<T>(
    raw: BRegComplete<BRegRawDocument>,
    expected_status: u16,
    members: &[&str],
    decode: impl FnOnce(&mut Map<String, Value>) -> Result<T, BRegIngestionError>,
) -> Result<BRegComplete<T>, BaseRegistryClientError> {
    let refuse = || {
        BaseRegistryClientError::protocol(
            expected_status,
            crate::BRegProtocolFailure::Body,
            Some(raw.metadata.trace_id().clone()),
        )
    };
    let value = crate::strict_json::from_slice(raw.value.as_bytes()).map_err(|_| refuse())?;
    let mut object = value.as_object().cloned().ok_or_else(refuse)?;
    if object.len() != members.len() || members.iter().any(|member| !object.contains_key(*member)) {
        return Err(refuse());
    }
    let value = decode(&mut object).map_err(|_| refuse())?;
    Ok(BRegComplete {
        value,
        metadata: raw.metadata,
    })
}

impl BaseRegistryClient {
    /// Announce one whole input and open a durable ingestion run for it. The
    /// run request names the access profile the run travels under, and this
    /// exchange selects it as the `accessProfile` query pair.
    pub async fn create_ingestion_run(
        &self,
        entity_route: &str,
        request: &BRegIngestionRunRequest,
    ) -> Result<BRegComplete<BRegIngestionRun>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let pairs = access_profile_query(Some(request.profile_id()))?;
        let raw = self
            .ingestion_post_json(
                &["v1", "records", entity_route, "ingestion-runs"],
                &pairs,
                request.body().to_vec(),
                Some(crate::client::APPLICATION_JSON),
                reqwest::StatusCode::CREATED,
            )
            .await?;
        decode_envelope(
            raw,
            reqwest::StatusCode::CREATED.as_u16(),
            &["run"],
            |object| BRegIngestionRun::from_value(take_member(object, "run")?),
        )
    }

    /// Read one bounded page of ingestion runs for one entity route.
    pub async fn list_ingestion_runs(
        &self,
        entity_route: &str,
        query: &BRegIngestionRunListQuery,
    ) -> Result<BRegComplete<BRegIngestionRunPage>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let raw = self
            .ingestion_get_json(
                &["v1", "records", entity_route, "ingestion-runs"],
                &query.query_pairs(),
            )
            .await?;
        decode_envelope(
            raw,
            reqwest::StatusCode::OK.as_u16(),
            &["runs", "hasMore", "nextAfter"],
            BRegIngestionRunPage::from_members,
        )
    }

    /// Read the current durable state of one ingestion run. The access
    /// profile, when one is given, is selected as the `accessProfile` query
    /// pair; an absent profile leaves the route default selected.
    pub async fn read_ingestion_run(
        &self,
        entity_route: &str,
        run_id: Uuid,
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegIngestionRun>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let run_identifier = run_id.to_string();
        let pairs = access_profile_query(access_profile)?;
        let raw = self
            .ingestion_get_json(
                &[
                    "v1",
                    "records",
                    entity_route,
                    "ingestion-runs",
                    &run_identifier,
                ],
                &pairs,
            )
            .await?;
        decode_envelope(raw, reqwest::StatusCode::OK.as_u16(), &["run"], |object| {
            BRegIngestionRun::from_value(take_member(object, "run")?)
        })
    }

    /// Submit one bounded chunk of an open ingestion run under its run's
    /// access profile, selected as the `accessProfile` query pair. A
    /// resubmitted chunk replays its retained receipt instead of executing
    /// twice.
    pub async fn submit_ingestion_chunk(
        &self,
        entity_route: &str,
        run_id: Uuid,
        chunk: &BRegIngestionChunk,
        profile_id: &str,
    ) -> Result<BRegComplete<BRegIngestionChunkSubmission>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let run_identifier = run_id.to_string();
        let pairs = access_profile_query(Some(profile_id))?;
        let raw = self
            .ingestion_post_json(
                &[
                    "v1",
                    "records",
                    entity_route,
                    "ingestion-runs",
                    &run_identifier,
                    "chunks",
                ],
                &pairs,
                chunk.body().to_vec(),
                Some(crate::client::APPLICATION_JSON),
                reqwest::StatusCode::OK,
            )
            .await?;
        decode_envelope(
            raw,
            reqwest::StatusCode::OK.as_u16(),
            &["run", "receipt"],
            BRegIngestionChunkSubmission::from_members,
        )
    }

    /// Cancel an open ingestion run. Committed chunks stay committed.
    ///
    /// The request carries no body and no Content-Type header: the cancel
    /// route refuses any declared media type. The access profile, when one is
    /// given, is selected as the `accessProfile` query pair.
    pub async fn cancel_ingestion_run(
        &self,
        entity_route: &str,
        run_id: Uuid,
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegIngestionRun>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let run_identifier = run_id.to_string();
        let pairs = access_profile_query(access_profile)?;
        let raw = self
            .ingestion_post_json(
                &[
                    "v1",
                    "records",
                    entity_route,
                    "ingestion-runs",
                    &run_identifier,
                    "cancel",
                ],
                &pairs,
                Vec::new(),
                None,
                reqwest::StatusCode::OK,
            )
            .await?;
        decode_envelope(raw, reqwest::StatusCode::OK.as_u16(), &["run"], |object| {
            BRegIngestionRun::from_value(take_member(object, "run")?)
        })
    }

    /// Read the retained receipt of one committed chunk under its run's
    /// access profile, selected as the `accessProfile` query pair. An erased
    /// receipt answers with the `ingestion.receipt_erased` problem instead.
    pub async fn ingestion_chunk_receipt(
        &self,
        entity_route: &str,
        run_id: Uuid,
        chunk_index: u64,
        profile_id: &str,
    ) -> Result<BRegComplete<BRegIngestionChunkReceipt>, BaseRegistryClientError> {
        validate_entity_route(entity_route)?;
        let run_identifier = run_id.to_string();
        let chunk = chunk_index.to_string();
        let pairs = access_profile_query(Some(profile_id))?;
        let raw = self
            .ingestion_get_json(
                &[
                    "v1",
                    "records",
                    entity_route,
                    "ingestion-runs",
                    &run_identifier,
                    "chunks",
                    &chunk,
                    "receipt",
                ],
                &pairs,
            )
            .await?;
        decode_envelope(
            raw,
            reqwest::StatusCode::OK.as_u16(),
            &["receipt"],
            |object| BRegIngestionChunkReceipt::from_value(take_member(object, "receipt")?),
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const INPUT_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PREFIX_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const RUN_ID: &str = "00000000-0000-4000-8000-000000000001";

    fn run_wire() -> Value {
        json!({
            "runId": RUN_ID,
            "status": "open",
            "blockedReason": null,
            "entityId": "facility",
            "operation": "create",
            "profileId": "importer.v1",
            "packageRevision": "revision-1",
            "schemaFingerprint": "fingerprint-1",
            "inputDigest": INPUT_DIGEST,
            "inputLength": 4321,
            "itemCount": 10,
            "chunkCount": 3,
            "chunkAlgorithmVersion": BREG_INGESTION_CHUNK_ALGORITHM_VERSION,
            "maximumItems": 100,
            "maximumBytes": 1048576,
            "nextChunkIndex": 1,
            "committedItems": 4,
            "committedPrefixDigest": PREFIX_DIGEST,
            "lastAttempt": {"outcome": "committed", "chunkIndex": 0},
            "createdAt": "2026-09-19T00:00:00Z",
            "updatedAt": "2026-09-19T00:01:00Z",
            "complete": false
        })
    }

    fn receipt_wire() -> Value {
        json!({
            "chunkIndex": 0,
            "digest": "73b2e2a853c51aff25dafdf04d36e97d92a062c385fa2aa41f4a2b9814510aca",
            "replayed": false,
            "erased": false,
            "batch": {
                "snapshot": "breg1_00000000-0000-4000-8000-000000000002",
                "results": [
                    {"operation": "create", "id": RUN_ID, "revision": 1, "etag": "\"breg-record-v1-abcdef012345\"", "data": {"legalName": "Example Ltd"}}
                ]
            }
        })
    }

    fn decode_wire(value: &Value) -> Result<BRegIngestionRun, BRegIngestionError> {
        let bytes = serde_json::to_vec(value).expect("wire value encodes");
        let value = crate::strict_json::from_slice(&bytes)
            .expect("wire value carries no duplicate members");
        BRegIngestionRun::from_value(value)
    }

    fn metadata() -> crate::BRegResponseMetadata {
        crate::BRegResponseMetadata::new(
            registry_platform_httpsec::TraceId::parse("0123456789abcdef0123456789abcdef")
                .expect("a canonical trace identifier"),
            None,
        )
    }

    fn raw_document(wire: &Value) -> BRegComplete<BRegRawDocument> {
        BRegComplete {
            value: BRegRawDocument::new(
                "application/json".to_owned(),
                serde_json::to_vec(wire).expect("wire value encodes"),
            ),
            metadata: metadata(),
        }
    }

    #[test]
    fn run_round_trips_to_its_exact_wire_members() {
        let run = decode_wire(&run_wire()).expect("the contract run decodes");
        assert_eq!(serde_json::to_value(&run).unwrap(), run_wire());
        assert_eq!(run.run_id().to_string(), RUN_ID);
        assert_eq!(run.status(), BRegIngestionRunStatus::Open);
        assert_eq!(run.blocked_reason(), None);
        assert_eq!(run.operation(), BRegBatchOperation::Create);
        assert_eq!(run.entity_id(), "facility");
        assert_eq!(run.input_digest(), INPUT_DIGEST);
        assert_eq!(run.input_length(), 4321);
        assert_eq!(run.item_count(), 10);
        assert_eq!(run.chunk_count(), 3);
        assert_eq!(run.next_chunk_index(), 1);
        assert_eq!(run.committed_items(), 4);
        assert_eq!(run.committed_prefix_digest(), PREFIX_DIGEST);
        let attempt = run.last_attempt().expect("the run carried one attempt");
        assert_eq!(attempt.outcome(), BRegIngestionAttemptOutcome::Committed);
        assert_eq!(attempt.chunk_index(), Some(0));
        assert!(!run.complete());
    }

    #[test]
    fn blocked_and_complete_runs_round_trip_with_their_closed_reasons() {
        let mut wire = run_wire();
        wire["status"] = json!("blocked");
        wire["blockedReason"] = json!("activePackageChanged");
        let run = decode_wire(&wire).expect("a blocked run decodes");
        assert_eq!(run.status(), BRegIngestionRunStatus::Blocked);
        assert_eq!(
            run.blocked_reason(),
            Some(BRegIngestionBlockedReason::ActivePackageChanged)
        );
        assert_eq!(serde_json::to_value(&run).unwrap(), wire);

        let mut wire = run_wire();
        wire["status"] = json!("complete");
        wire["complete"] = json!(true);
        wire["nextChunkIndex"] = json!(3);
        wire["committedItems"] = json!(10);
        let run = decode_wire(&wire).expect("a complete run decodes");
        assert!(run.complete());
        assert_eq!(serde_json::to_value(&run).unwrap(), wire);
    }

    #[test]
    fn unknown_run_values_and_members_are_refused() {
        for mutate in [
            |wire: &mut Value| wire["status"] = json!("archived"),
            |wire: &mut Value| wire["status"] = json!(7),
            |wire: &mut Value| wire["blockedReason"] = json!("active_package_changed"),
            |wire: &mut Value| wire["operation"] = json!("delete"),
            |wire: &mut Value| wire["lastAttempt"]["outcome"] = json!("crashed"),
            |wire: &mut Value| {
                wire["lastAttempt"] = json!({"outcome": "committed", "chunkIndex": 0, "extra": 1})
            },
            |wire: &mut Value| wire["extra"] = json!("member"),
            |wire: &mut Value| wire["inputDigest"] = json!("AAAA"),
            |wire: &mut Value| wire["runId"] = json!("not-a-uuid"),
            |wire: &mut Value| wire["entityId"] = json!("Facility"),
            |wire: &mut Value| wire["itemCount"] = json!(0),
            |wire: &mut Value| wire["chunkCount"] = json!(0),
            |wire: &mut Value| wire["maximumItems"] = json!(0),
            |wire: &mut Value| wire["nextChunkIndex"] = json!(4),
            |wire: &mut Value| wire["committedItems"] = json!(11),
            |wire: &mut Value| wire["createdAt"] = json!("yesterday"),
            |wire: &mut Value| wire["complete"] = json!(true),
        ] {
            let mut wire = run_wire();
            mutate(&mut wire);
            let error = decode_wire(&wire).expect_err("the mutated run is refused");
            assert_eq!(error, BRegIngestionError::InvalidResponse);
        }

        // A blocked reason is carried exactly when the run is blocked, and the
        // complete flag is carried exactly when the run is complete.
        let mut wire = run_wire();
        wire["blockedReason"] = json!("activePackageChanged");
        assert_eq!(decode_wire(&wire), Err(BRegIngestionError::InvalidResponse));
        let mut wire = run_wire();
        wire["status"] = json!("complete");
        assert_eq!(decode_wire(&wire), Err(BRegIngestionError::InvalidResponse));
    }

    #[test]
    fn receipt_round_trips_and_refuses_an_erased_body() {
        let bytes = serde_json::to_vec(&receipt_wire()).unwrap();
        let value = crate::strict_json::from_slice(&bytes).unwrap();
        let receipt = BRegIngestionChunkReceipt::from_value(value).expect("the receipt decodes");
        assert_eq!(serde_json::to_value(&receipt).unwrap(), receipt_wire());
        assert_eq!(receipt.chunk_index(), 0);
        assert!(!receipt.replayed());
        assert!(!receipt.erased());
        assert_eq!(
            receipt.batch().snapshot(),
            "breg1_00000000-0000-4000-8000-000000000002"
        );
        assert_eq!(receipt.batch().results().len(), 1);

        for mutate in [
            |wire: &mut Value| wire["replayed"] = json!("yes"),
            |wire: &mut Value| wire["digest"] = json!(PREFIX_DIGEST.to_owned() + "0"),
            |wire: &mut Value| wire["extra"] = json!(1),
            |wire: &mut Value| wire["batch"]["snapshot"] = json!("snapshot-1"),
            |wire: &mut Value| wire["batch"]["results"] = json!("none"),
            |wire: &mut Value| wire["batch"]["extra"] = json!(1),
        ] {
            let mut wire = receipt_wire();
            mutate(&mut wire);
            let bytes = serde_json::to_vec(&wire).unwrap();
            let value = crate::strict_json::from_slice(&bytes).unwrap();
            let error = BRegIngestionChunkReceipt::from_value(value)
                .expect_err("the mutated receipt is refused");
            assert_eq!(error, BRegIngestionError::InvalidResponse);
        }

        // An erased receipt is a problem answer, never a receipt body.
        let mut wire = receipt_wire();
        wire["erased"] = json!(true);
        let bytes = serde_json::to_vec(&wire).unwrap();
        let value = crate::strict_json::from_slice(&bytes).unwrap();
        assert_eq!(
            BRegIngestionChunkReceipt::from_value(value),
            Err(BRegIngestionError::ErasedReceipt)
        );
    }

    #[test]
    fn submission_and_page_envelopes_decode_their_exact_members() {
        let run = run_wire();
        let receipt = receipt_wire();
        let submission = BRegIngestionChunkSubmission::from_members(
            json!({"run": run, "receipt": receipt})
                .as_object_mut()
                .expect("object"),
        )
        .expect("the submission decodes");
        assert_eq!(submission.run().run_id().to_string(), RUN_ID);
        assert_eq!(submission.receipt().chunk_index(), 0);
        for mutate in [
            |wire: &mut Value| {
                wire.as_object_mut()
                    .expect("object")
                    .insert("extra".to_owned(), json!(1));
            },
            |wire: &mut Value| drop(wire.as_object_mut().expect("object").remove("receipt")),
            |wire: &mut Value| drop(wire.as_object_mut().expect("object").remove("run")),
        ] {
            let mut wire = json!({"run": run_wire(), "receipt": receipt_wire()});
            mutate(&mut wire);
            assert!(BRegIngestionChunkSubmission::from_members(
                wire.as_object_mut().expect("object")
            )
            .is_err());
        }

        let mut page = json!({"runs": [run_wire()], "hasMore": true, "nextAfter": "cursor+/="});
        let decoded = BRegIngestionRunPage::from_members(page.as_object_mut().expect("object"))
            .expect("the page decodes");
        assert_eq!(decoded.runs().len(), 1);
        assert!(decoded.has_more());
        assert_eq!(decoded.next_after(), Some("cursor+/="));

        for mutate in [
            |wire: &mut Value| wire["hasMore"] = json!(false),
            |wire: &mut Value| wire["nextAfter"] = json!(Value::Null),
            |wire: &mut Value| wire["nextAfter"] = json!(""),
        ] {
            let mut wire = json!({"runs": [run_wire()], "hasMore": true, "nextAfter": "cursor"});
            mutate(&mut wire);
            assert!(
                BRegIngestionRunPage::from_members(wire.as_object_mut().expect("object")).is_err()
            );
        }
        let mut page = json!({"runs": [], "hasMore": false, "nextAfter": null});
        let decoded = BRegIngestionRunPage::from_members(page.as_object_mut().expect("object"))
            .expect("a final page decodes");
        assert!(decoded.runs().is_empty());
        assert_eq!(decoded.next_after(), None);
    }

    #[test]
    fn envelope_decode_maps_strict_failures_to_protocol_body_failures() {
        let error = decode_envelope(
            raw_document(&json!({"run": run_wire(), "extra": 1})),
            201,
            &["run"],
            |object| BRegIngestionRun::from_value(take_member(object, "run")?),
        )
        .expect_err("an envelope with an extra member is a protocol failure");
        let BaseRegistryClientError::Protocol { status, .. } = error else {
            panic!("a body mismatch is a protocol failure");
        };
        assert_eq!(status, 201);

        let complete = decode_envelope(
            raw_document(&json!({"run": run_wire()})),
            201,
            &["run"],
            |object| BRegIngestionRun::from_value(take_member(object, "run")?),
        )
        .expect("the run envelope decodes");
        assert_eq!(complete.value.run_id().to_string(), RUN_ID);
    }

    #[test]
    fn chunk_digest_vectors_match_canonical_json_sha256() {
        // RFC 8785 canonical bodies of {"items":[...]}, hashed with SHA-256.
        assert_eq!(
            ingestion_chunk_digest(&[]).unwrap(),
            "eef46741adfc3a9f76294d3b78f37a45f113092ac9d44ee77c7a038a88ff09a1"
        );
        assert_eq!(
            ingestion_chunk_digest(&[json!({"a": 1})]).unwrap(),
            "73b2e2a853c51aff25dafdf04d36e97d92a062c385fa2aa41f4a2b9814510aca"
        );
        // Object members are ordered canonically, not by submission order.
        assert_eq!(
            ingestion_chunk_digest(&[json!({"b": 1, "a": 2})]).unwrap(),
            "f023124ff0a9b778bfec80479486c8c7bd6a8fdc19c31151524c660779dcce4c"
        );
        // Numbers use the ECMAScript serialization: 1.0 hashes as 1.
        assert_eq!(
            ingestion_chunk_digest(&[json!({"n": 1.0})]).unwrap(),
            "77654be60bf17be846e8077058183ad394da04dc9d2970de349cb7e8aa0d8615"
        );
        assert_eq!(
            ingestion_prefix_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            ingestion_prefix_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_resuming_caller_accumulates_prefix_digests_over_raw_source_bytes() {
        // Chunks cut one source input at "abc" and then at "abcdefghij": each
        // prefix digest hashes the raw bytes through the end of the chunk, on
        // the empty digest base, never a chain over earlier chunk digests.
        let source: &[u8] = b"abcdefghij";
        let first_end = 3;
        assert_eq!(
            ingestion_prefix_digest(&source[..first_end]),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            ingestion_prefix_digest(source),
            "72399361da6a7754fec986dca5b7cbaf1c810a28ded4abaf56b2106d06cb78b0"
        );
        // An empty chunk boundary keeps the documented empty-input base.
        assert_eq!(
            ingestion_prefix_digest(&source[..0]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Each encoded chunk carries exactly the prefix digest its caller
        // accumulated; the digest is required and never defaulted.
        let chunk = BRegIngestionChunk::new(
            0,
            vec![json!({"operation": "create", "data": {"legalName": "Example Ltd"}})],
            ingestion_prefix_digest(&source[..first_end]),
        )
        .expect("chunk");
        assert_eq!(
            chunk.prefix_digest(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            serde_json::from_slice::<Value>(chunk.body()).unwrap()["prefixDigest"],
            json!(chunk.prefix_digest())
        );
    }

    #[test]
    fn a_chunk_encodes_the_exact_submission_body_and_derives_its_digest() {
        let items = vec![
            json!({"operation": "create", "data": {"legalName": "Example Ltd"}}),
            json!({"operation": "create", "data": {"legalName": "Other Ltd"}}),
        ];
        let chunk = BRegIngestionChunk::new(2, items.clone(), PREFIX_DIGEST).expect("chunk");
        assert_eq!(chunk.chunk_index(), 2);
        assert_eq!(chunk.item_count(), 2);
        assert_eq!(chunk.digest(), ingestion_chunk_digest(&items).unwrap());
        assert_eq!(chunk.prefix_digest(), PREFIX_DIGEST);
        assert_eq!(
            serde_json::from_slice::<Value>(chunk.body()).unwrap(),
            json!({
                "chunkIndex": 2,
                "items": items,
                "digest": ingestion_chunk_digest(&items).unwrap(),
                "prefixDigest": PREFIX_DIGEST
            })
        );

        assert_eq!(
            BRegIngestionChunk::new(0, Vec::new(), PREFIX_DIGEST).unwrap_err(),
            BRegIngestionError::EmptyChunk
        );
        assert_eq!(
            BRegIngestionChunk::new(0, vec![json!("not-an-object")], PREFIX_DIGEST).unwrap_err(),
            BRegIngestionError::InvalidItem
        );
        assert_eq!(
            BRegIngestionChunk::new(0, items.clone(), "not-a-digest").unwrap_err(),
            BRegIngestionError::InvalidDigest
        );
        // A digest the canonical body cannot be derived for is refused.
        let mut unrepresentable = serde_json::Map::new();
        unrepresentable.insert("large".to_owned(), json!(u64::MAX));
        assert_eq!(
            ingestion_chunk_digest(&[Value::Object(unrepresentable)]),
            Err(BRegIngestionError::InvalidItem)
        );
    }

    #[test]
    fn the_run_request_encodes_the_exact_announcement_body() {
        let request = BRegIngestionRunRequest::builder()
            .operation(BRegBatchOperation::Patch)
            .profile("importer.v1")
            .unwrap()
            .package_revision("revision-1")
            .unwrap()
            .schema_fingerprint("fingerprint-1")
            .unwrap()
            .input_digest(INPUT_DIGEST)
            .unwrap()
            .input_length(4321)
            .item_count(10)
            .unwrap()
            .chunk_count(3)
            .unwrap()
            .chunk_algorithm_version(BREG_INGESTION_CHUNK_ALGORITHM_VERSION)
            .unwrap()
            .build()
            .expect("the announcement builds");
        assert_eq!(
            serde_json::from_slice::<Value>(request.body()).unwrap(),
            json!({
                "operation": "patch",
                "profileId": "importer.v1",
                "packageRevision": "revision-1",
                "schemaFingerprint": "fingerprint-1",
                "inputDigest": INPUT_DIGEST,
                "inputLength": 4321,
                "itemCount": 10,
                "chunkCount": 3,
                "chunkAlgorithmVersion": "greedy-canonical-http-batch-v1"
            })
        );
        assert_eq!(request.operation(), BRegBatchOperation::Patch);
        assert_eq!(request.input_digest(), INPUT_DIGEST);

        let builder = BRegIngestionRunRequest::builder()
            .operation(BRegBatchOperation::Create)
            .profile("importer.v1")
            .unwrap()
            .package_revision("revision-1")
            .unwrap()
            .schema_fingerprint("fingerprint-1")
            .unwrap()
            .input_digest(INPUT_DIGEST)
            .unwrap()
            .input_length(1);
        assert!(matches!(
            builder.clone().build(),
            Err(BRegIngestionError::InvalidBinding)
        ));
        assert!(matches!(
            builder.clone().item_count(10).unwrap().chunk_count(0),
            Err(BRegIngestionError::InvalidBinding)
        ));
        assert!(matches!(
            builder
                .item_count(10)
                .unwrap()
                .chunk_count(1)
                .unwrap()
                .chunk_algorithm_version("greedy-canonical-http-batch-v2"),
            Err(BRegIngestionError::UnsupportedChunkAlgorithm)
        ));
        assert!(matches!(
            BRegIngestionRunRequest::builder().profile(""),
            Err(BRegIngestionError::InvalidBinding)
        ));
        assert!(matches!(
            BRegIngestionRunRequest::builder().input_digest("aabb"),
            Err(BRegIngestionError::InvalidDigest)
        ));
    }

    #[test]
    fn list_queries_encode_their_filters_in_contract_order() {
        assert_eq!(
            BRegIngestionRunListQuery::default().query_pairs(),
            Vec::new()
        );
        let query = BRegIngestionRunListQuery::default()
            .access_profile("importer.v1")
            .unwrap()
            .limit(25)
            .unwrap()
            .after("cursor+/=")
            .unwrap()
            .status(BRegIngestionRunStatus::Open)
            .input_digest(INPUT_DIGEST)
            .unwrap();
        assert_eq!(
            query.query_pairs(),
            vec![
                ("accessProfile".to_owned(), "importer.v1".to_owned()),
                ("limit".to_owned(), "25".to_owned()),
                ("after".to_owned(), "cursor+/=".to_owned()),
                ("status".to_owned(), "open".to_owned()),
                ("inputDigest".to_owned(), INPUT_DIGEST.to_owned()),
            ]
        );
        assert_eq!(
            BRegIngestionRunListQuery::default().limit(0),
            Err(BRegIngestionError::InvalidLimit)
        );
        assert_eq!(
            BRegIngestionRunListQuery::default().limit(MAXIMUM_RUN_PAGE_LIMIT + 1),
            Err(BRegIngestionError::InvalidLimit)
        );
        assert_eq!(
            BRegIngestionRunListQuery::default().input_digest("xyz"),
            Err(BRegIngestionError::InvalidDigest)
        );
        assert_eq!(
            BRegIngestionRunListQuery::default().after("cursor\n"),
            Err(BRegIngestionError::InvalidCursor)
        );
        // The selected access profile is carried as one bounded identifier.
        assert_eq!(
            BRegIngestionRunListQuery::default().access_profile(""),
            Err(BRegIngestionError::InvalidBinding)
        );
        assert_eq!(
            BRegIngestionRunListQuery::default().access_profile("profile\n"),
            Err(BRegIngestionError::InvalidBinding)
        );
    }

    #[test]
    fn the_prefix_digest_accumulator_matches_one_shot_prefix_digests() {
        // Incremental absorption at several split points, including the empty
        // input, derives exactly the one-shot digest of the same bytes, and
        // deriving twice keeps deriving it.
        let source: &[u8] = b"abcdefghij";
        for split in [0, 1, 3, source.len()] {
            let mut accumulator = BRegIngestionPrefixDigest::new();
            accumulator.update(&source[..split]);
            accumulator.update(&source[split..]);
            assert_eq!(accumulator.digest(), ingestion_prefix_digest(source));
            assert_eq!(accumulator.digest(), ingestion_prefix_digest(source));
        }
        let default = BRegIngestionPrefixDigest::default();
        assert_eq!(
            default.digest(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut three_way = BRegIngestionPrefixDigest::new();
        three_way.update(b"ab");
        three_way.update(b"");
        three_way.update(source);
        assert_eq!(three_way.digest(), ingestion_prefix_digest(b"ababcdefghij"));
    }

    #[test]
    fn every_ingestion_vocabulary_value_round_trips() {
        for status in BRegIngestionRunStatus::ALL {
            assert_eq!(BRegIngestionRunStatus::parse(status.as_str()), Some(status));
        }
        for outcome in BRegIngestionAttemptOutcome::ALL {
            assert_eq!(
                BRegIngestionAttemptOutcome::parse(outcome.as_str()),
                Some(outcome)
            );
        }
        assert_eq!(
            BRegIngestionBlockedReason::parse(
                BRegIngestionBlockedReason::ActivePackageChanged.as_str()
            ),
            Some(BRegIngestionBlockedReason::ActivePackageChanged)
        );
        for unknown in ["", "Open", "cancelled ", "archived"] {
            assert_eq!(BRegIngestionRunStatus::parse(unknown), None);
            assert_eq!(BRegIngestionAttemptOutcome::parse(unknown), None);
            assert_eq!(BRegIngestionBlockedReason::parse(unknown), None);
        }
    }
}
