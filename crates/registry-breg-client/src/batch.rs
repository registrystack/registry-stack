// SPDX-License-Identifier: Apache-2.0

//! Metadata-bound atomic same-entity batch mutations.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    BRegBatchBinding, BRegComplete, BRegCreateRequest, BRegEtag, BRegIdempotencyKey,
    BRegPatchRequest, BaseRegistryClient, BaseRegistryClientError,
};

const MAXIMUM_CHANGE_CONTEXT_BYTES: usize = 16 * 1024;
const MAXIMUM_REASON_CODE_BYTES: usize = 64;
const MAXIMUM_REASON_TEXT_BYTES: usize = 4 * 1024;
const MAXIMUM_SOURCE_REFERENCES: usize = 16;
const MAXIMUM_SOURCE_REFERENCE_BYTES: usize = 256;
const MAXIMUM_SNAPSHOT_REFERENCE_BYTES: usize = 4 * 1024;

/// A value-free reason that an atomic batch cannot be constructed or decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegBatchError {
    #[error("the Base Registry Engine batch binding does not permit that operation")]
    OperationNotPermitted,
    #[error("the Base Registry Engine batch item does not match the selected operation")]
    ItemContractMismatch,
    #[error("the Base Registry Engine batch must contain at least one item")]
    Empty,
    #[error("the Base Registry Engine batch has too many items")]
    TooManyItems,
    #[error("the Base Registry Engine batch body exceeds the selected operation bound")]
    BodyTooLarge,
    #[error("the Base Registry Engine correction reason code is invalid")]
    InvalidReasonCode,
    #[error("the Base Registry Engine change reason text is invalid")]
    InvalidReasonText,
    #[error("the Base Registry Engine change source reference is invalid")]
    InvalidSourceReference,
    #[error("the Base Registry Engine change context has too many source references")]
    TooManySourceReferences,
    #[error("the Base Registry Engine batch body could not be encoded")]
    BodyEncoding,
    #[error("the Base Registry Engine batch response does not match the selected operation")]
    InvalidResponse,
}

/// Why the records in one batch are being changed.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegChangeContext {
    kind: BRegChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_text: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source_references: Vec<String>,
}

impl fmt::Debug for BRegChangeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegChangeContext")
            .field("kind", &self.kind)
            .field("reason_code_present", &self.reason_code.is_some())
            .field("reason_text_present", &self.reason_text.is_some())
            .field("source_reference_count", &self.source_references.len())
            .finish()
    }
}

impl BRegChangeContext {
    /// Describe an ordinary coordinated change.
    #[must_use]
    pub fn change() -> Self {
        Self {
            kind: BRegChangeKind::Change,
            reason_code: None,
            reason_text: None,
            source_references: Vec::new(),
        }
    }

    /// Describe a correction. Corrections always carry a nonempty reason code.
    pub fn correction(reason_code: impl Into<String>) -> Result<Self, BRegBatchError> {
        let reason_code = reason_code.into();
        if !valid_bounded_text(&reason_code, MAXIMUM_REASON_CODE_BYTES, false) {
            return Err(BRegBatchError::InvalidReasonCode);
        }
        Ok(Self {
            kind: BRegChangeKind::Correction,
            reason_code: Some(reason_code),
            reason_text: None,
            source_references: Vec::new(),
        })
    }

    /// Attach bounded operator-facing reason text.
    pub fn reason_text(mut self, value: impl Into<String>) -> Result<Self, BRegBatchError> {
        let value = value.into();
        if !valid_bounded_text(&value, MAXIMUM_REASON_TEXT_BYTES, false) {
            return Err(BRegBatchError::InvalidReasonText);
        }
        self.reason_text = Some(value);
        Ok(self)
    }

    /// Attach one bounded source reference.
    pub fn source_reference(mut self, value: impl Into<String>) -> Result<Self, BRegBatchError> {
        if self.source_references.len() >= MAXIMUM_SOURCE_REFERENCES {
            return Err(BRegBatchError::TooManySourceReferences);
        }
        let value = value.into();
        if !valid_bounded_text(&value, MAXIMUM_SOURCE_REFERENCE_BYTES, false) {
            return Err(BRegBatchError::InvalidSourceReference);
        }
        self.source_references.push(value);
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BRegChangeKind {
    Change,
    Correction,
}

/// Builds one ordered atomic batch against one metadata-selected entity route.
pub struct BRegBatchBuilder<'a> {
    binding: &'a BRegBatchBinding,
    items: Vec<BRegBatchItem>,
    change_context: Option<BRegChangeContext>,
}

impl<'a> BRegBatchBuilder<'a> {
    /// Start a batch bound to one caller-filtered operation.
    #[must_use]
    pub fn new(binding: &'a BRegBatchBinding) -> Self {
        Self {
            binding,
            items: Vec::new(),
            change_context: None,
        }
    }

    /// Append a Create item after checking the selected batch's field grant.
    pub fn create(mut self, request: &BRegCreateRequest) -> Result<Self, BRegBatchError> {
        if !self.binding.allows_create() {
            return Err(BRegBatchError::OperationNotPermitted);
        }
        request
            .validate_fields(
                self.binding.create_writable_api_names(),
                self.binding.required_create_api_names(),
            )
            .map_err(|_| BRegBatchError::ItemContractMismatch)?;
        let envelope = crate::strict_json::from_slice(request.body())
            .map_err(|_| BRegBatchError::ItemContractMismatch)?;
        let data = envelope
            .as_object()
            .and_then(|object| object.get("data"))
            .and_then(Value::as_object)
            .cloned()
            .ok_or(BRegBatchError::ItemContractMismatch)?;
        self.push(BRegBatchItem::Create { data })?;
        Ok(self)
    }

    /// Append a PATCH item with the caller's original record condition.
    pub fn patch(
        mut self,
        record_identifier: Uuid,
        etag: &BRegEtag,
        request: &BRegPatchRequest,
    ) -> Result<Self, BRegBatchError> {
        if !self.binding.allows_patch() {
            return Err(BRegBatchError::OperationNotPermitted);
        }
        request
            .validate_fields(
                self.binding.readable_api_names(),
                self.binding.patch_writable_api_names(),
                self.binding.removable_api_names(),
            )
            .map_err(|_| BRegBatchError::ItemContractMismatch)?;
        let patch = crate::strict_json::from_slice(request.body())
            .ok()
            .and_then(|value| value.as_array().cloned())
            .ok_or(BRegBatchError::ItemContractMismatch)?;
        self.push(BRegBatchItem::Patch {
            record_id: record_identifier,
            if_match: etag.clone(),
            patch,
        })?;
        Ok(self)
    }

    /// Apply one shared context to all items in this batch.
    #[must_use]
    pub fn change_context(mut self, context: BRegChangeContext) -> Self {
        self.change_context = Some(context);
        self
    }

    /// Finish and enforce the operation's exact item and byte bounds.
    pub fn build(self) -> Result<BRegBatchRequest, BRegBatchError> {
        if self.items.is_empty() {
            return Err(BRegBatchError::Empty);
        }
        let envelope = BRegBatchEnvelope {
            items: &self.items,
            change_context: self.change_context.as_ref(),
        };
        let body = serde_json::to_vec(&envelope).map_err(|_| BRegBatchError::BodyEncoding)?;
        let maximum_bytes = usize::try_from(self.binding.maximum_bytes()).unwrap_or(usize::MAX);
        if body.len() > maximum_bytes {
            return Err(BRegBatchError::BodyTooLarge);
        }
        if self.change_context.as_ref().is_some_and(|context| {
            serde_json::to_vec(context).map_or(true, |v| v.len() > MAXIMUM_CHANGE_CONTEXT_BYTES)
        }) {
            return Err(BRegBatchError::BodyTooLarge);
        }
        Ok(BRegBatchRequest {
            body: Zeroizing::new(body),
            item_operations: self.items.iter().map(BRegBatchItem::kind).collect(),
            binding: self.binding.clone(),
            readable_api_names: self.binding.readable_api_names().clone(),
        })
    }

    fn push(&mut self, item: BRegBatchItem) -> Result<(), BRegBatchError> {
        let maximum_items = usize::try_from(self.binding.maximum_items()).unwrap_or(usize::MAX);
        if self.items.len() >= maximum_items {
            return Err(BRegBatchError::TooManyItems);
        }
        self.items.push(item);
        Ok(())
    }
}

impl fmt::Debug for BRegBatchBuilder<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegBatchBuilder")
            .field("item_count", &self.items.len())
            .field("has_change_context", &self.change_context.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "lowercase")]
enum BRegBatchItem {
    Create {
        data: Map<String, Value>,
    },
    Patch {
        #[serde(rename = "recordId")]
        #[serde(serialize_with = "serialize_uuid")]
        record_id: Uuid,
        #[serde(rename = "ifMatch")]
        if_match: BRegEtag,
        patch: Vec<Value>,
    },
}

impl BRegBatchItem {
    fn kind(&self) -> BRegBatchOperation {
        match self {
            Self::Create { .. } => BRegBatchOperation::Create,
            Self::Patch { .. } => BRegBatchOperation::Patch,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BRegBatchEnvelope<'a> {
    items: &'a [BRegBatchItem],
    #[serde(skip_serializing_if = "Option::is_none")]
    change_context: Option<&'a BRegChangeContext>,
}

/// An exact batch body already checked against its metadata-selected operation.
pub struct BRegBatchRequest {
    body: Zeroizing<Vec<u8>>,
    item_operations: Vec<BRegBatchOperation>,
    binding: BRegBatchBinding,
    readable_api_names: BTreeSet<String>,
}

impl BRegBatchRequest {
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.item_operations.len()
    }

    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

impl fmt::Debug for BRegBatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegBatchRequest")
            .field("body_bytes", &self.body.len())
            .field("item_count", &self.item_operations.len())
            .finish_non_exhaustive()
    }
}

/// Operation performed by one item in an atomic batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BRegBatchOperation {
    Create,
    Patch,
}

/// One final record state returned in batch item order.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegBatchResult {
    operation: BRegBatchOperation,
    #[serde(serialize_with = "serialize_uuid")]
    id: Uuid,
    revision: u64,
    etag: BRegEtag,
    data: Map<String, Value>,
}

impl BRegBatchResult {
    #[must_use]
    pub const fn operation(&self) -> BRegBatchOperation {
        self.operation
    }

    #[must_use]
    pub const fn record_identifier(&self) -> Uuid {
        self.id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn etag(&self) -> &BRegEtag {
        &self.etag
    }

    #[must_use]
    pub fn data(&self) -> &Map<String, Value> {
        &self.data
    }
}

/// Successful atomic batch receipt with one shared snapshot reference.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BRegBatchReceipt {
    snapshot: String,
    results: Vec<BRegBatchResult>,
}

impl BRegBatchReceipt {
    #[must_use]
    pub fn snapshot(&self) -> &str {
        &self.snapshot
    }

    #[must_use]
    pub fn results(&self) -> &[BRegBatchResult] {
        &self.results
    }
}

impl BaseRegistryClient {
    /// Execute one metadata-bound atomic batch without automatic retry.
    pub async fn batch_records(
        &self,
        operation: &BRegBatchBinding,
        request: &BRegBatchRequest,
        idempotency_key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegBatchReceipt>, BaseRegistryClientError> {
        if !operation.matches_source(&self.source_binding())
            || request.binding.source_binding() != self.source_binding()
            || request.binding != *operation
        {
            return Err(BaseRegistryClientError::invalid_request(
                "the Base Registry Engine batch request belongs to another selected operation",
            ));
        }
        let raw = self
            .execute_bound_json(
                &operation.path(),
                operation.access_profile(),
                request.body().to_vec(),
                Some(idempotency_key),
            )
            .await?;
        let receipt = decode_receipt(raw.value.as_bytes(), request).map_err(|_| {
            BaseRegistryClientError::protocol(
                200,
                crate::BRegProtocolFailure::Body,
                Some(raw.metadata.trace_id().clone()),
            )
        })?;
        Ok(BRegComplete {
            value: receipt,
            metadata: raw.metadata,
        })
    }
}

fn decode_receipt(
    bytes: &[u8],
    request: &BRegBatchRequest,
) -> Result<BRegBatchReceipt, BRegBatchError> {
    let value =
        crate::strict_json::from_slice(bytes).map_err(|_| BRegBatchError::InvalidResponse)?;
    let object = value.as_object().ok_or(BRegBatchError::InvalidResponse)?;
    if object.len() != 2 || !object.contains_key("snapshot") || !object.contains_key("results") {
        return Err(BRegBatchError::InvalidResponse);
    }
    let snapshot = object["snapshot"]
        .as_str()
        .filter(|value| {
            value
                .strip_prefix("breg1_")
                .and_then(|value| {
                    Uuid::parse_str(value)
                        .ok()
                        .filter(|identifier| identifier.to_string() == value)
                })
                .is_some()
                && value.len() <= MAXIMUM_SNAPSHOT_REFERENCE_BYTES
        })
        .ok_or(BRegBatchError::InvalidResponse)?
        .to_owned();
    let results = object["results"]
        .as_array()
        .filter(|items| items.len() == request.item_operations.len())
        .ok_or(BRegBatchError::InvalidResponse)?
        .iter()
        .zip(&request.item_operations)
        .map(|(value, expected)| decode_result(value, *expected, &request.readable_api_names))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BRegBatchReceipt { snapshot, results })
}

fn decode_result(
    value: &Value,
    expected: BRegBatchOperation,
    readable: &BTreeSet<String>,
) -> Result<BRegBatchResult, BRegBatchError> {
    let object = value.as_object().ok_or(BRegBatchError::InvalidResponse)?;
    if object.len() != 5
        || !["operation", "id", "revision", "etag", "data"]
            .iter()
            .all(|key| object.contains_key(*key))
    {
        return Err(BRegBatchError::InvalidResponse);
    }
    let operation = match object["operation"].as_str() {
        Some("create") => BRegBatchOperation::Create,
        Some("patch") => BRegBatchOperation::Patch,
        _ => return Err(BRegBatchError::InvalidResponse),
    };
    if operation != expected {
        return Err(BRegBatchError::InvalidResponse);
    }
    let id = object["id"]
        .as_str()
        .and_then(|value| {
            Uuid::parse_str(value)
                .ok()
                .filter(|id| id.to_string() == value)
        })
        .ok_or(BRegBatchError::InvalidResponse)?;
    let revision = object["revision"]
        .as_u64()
        .filter(|value| *value > 0 && *value <= i64::MAX as u64)
        .ok_or(BRegBatchError::InvalidResponse)?;
    let etag = object["etag"]
        .as_str()
        .and_then(|value| BRegEtag::parse(value).ok())
        .ok_or(BRegBatchError::InvalidResponse)?;
    let data = object["data"]
        .as_object()
        .filter(|data| data.keys().all(|field| readable.contains(field)))
        .cloned()
        .ok_or(BRegBatchError::InvalidResponse)?;
    Ok(BRegBatchResult {
        operation,
        id,
        revision,
        etag,
        data,
    })
}

fn valid_bounded_text(value: &str, maximum_bytes: usize, empty_allowed: bool) -> bool {
    (empty_allowed || !value.is_empty()) && value.len() <= maximum_bytes
}

fn serialize_uuid<S: Serializer>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn correction_context_uses_exact_wire_names_and_bounds() {
        let context = BRegChangeContext::correction("reason-code-secret-canary")
            .unwrap()
            .reason_text("reason-text-secret-canary")
            .unwrap()
            .source_reference("source-reference-secret-canary")
            .unwrap();
        assert_eq!(
            serde_json::to_value(&context).unwrap(),
            json!({
                "kind": "correction",
                "reasonCode": "reason-code-secret-canary",
                "reasonText": "reason-text-secret-canary",
                "sourceReferences": ["source-reference-secret-canary"]
            })
        );
        let diagnostic = format!("{context:?}");
        assert!(diagnostic.contains("reason_text_present: true"));
        assert!(diagnostic.contains("source_reference_count: 1"));
        assert!(!diagnostic.contains("reason-code-secret-canary"));
        assert!(!diagnostic.contains("reason-text-secret-canary"));
        assert!(!diagnostic.contains("source-reference-secret-canary"));
        assert!(matches!(
            BRegChangeContext::correction("x".repeat(65)),
            Err(BRegBatchError::InvalidReasonCode)
        ));
        assert!(matches!(
            BRegChangeContext::change().reason_text("x".repeat(MAXIMUM_REASON_TEXT_BYTES + 1)),
            Err(BRegBatchError::InvalidReasonText)
        ));
        assert!(matches!(
            BRegChangeContext::change().reason_text(""),
            Err(BRegBatchError::InvalidReasonText)
        ));
        assert!(matches!(
            BRegChangeContext::change()
                .source_reference("x".repeat(MAXIMUM_SOURCE_REFERENCE_BYTES + 1)),
            Err(BRegBatchError::InvalidSourceReference)
        ));
        assert!(matches!(
            BRegChangeContext::change().source_reference(""),
            Err(BRegBatchError::InvalidSourceReference)
        ));

        let mut references = BRegChangeContext::change();
        for index in 0..MAXIMUM_SOURCE_REFERENCES {
            references = references
                .source_reference(format!("source-{index}"))
                .unwrap();
        }
        assert!(matches!(
            references.source_reference("one-too-many"),
            Err(BRegBatchError::TooManySourceReferences)
        ));
    }
}
