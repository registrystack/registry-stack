// SPDX-License-Identifier: Apache-2.0

//! Bounded, value-safe request bodies for Base Registry Engine direct mutations.
//!
//! These types describe only the caller-owned portion of a mutation. A request
//! is executable only when the client combines it with a caller-filtered,
//! revision-bound operation handle from Registry metadata. In particular,
//! these builders do not accept a caller-supplied route or operation ID.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// Maximum encoded body accepted by Base Registry Engine mutation routes.
pub const MAXIMUM_BREG_MUTATION_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of operations in one Base Registry Engine JSON Patch document.
pub const MAXIMUM_BREG_PATCH_OPERATIONS: usize = 128;

const MAXIMUM_JSON_NESTING_DEPTH: usize = 128;
const MAXIMUM_API_FIELD_NAME_BYTES: usize = 64;

/// A caller-chosen Base Registry Engine idempotency key.
///
/// The client deliberately has no key generator and never retries a mutation
/// automatically. A caller may reuse this value only to replay the exact same
/// method, route, precondition, representation, and body after an uncertain
/// exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct BRegIdempotencyKey(Zeroizing<String>);

impl BRegIdempotencyKey {
    /// Parse the exact Base Registry Engine header grammar: 1 through 256 visible
    /// ASCII bytes, excluding comma and semicolon.
    pub fn parse(value: impl Into<String>) -> Result<Self, BRegIdempotencyKeyError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| matches!(byte, 0x21..=0x7e) && byte != b',' && byte != b';')
        {
            return Err(BRegIdempotencyKeyError);
        }
        Ok(Self(value))
    }

    /// Borrow the validated header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for BRegIdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BRegIdempotencyKey(<redacted>)")
    }
}

impl std::str::FromStr for BRegIdempotencyKey {
    type Err = BRegIdempotencyKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for BRegIdempotencyKey {
    type Error = BRegIdempotencyKeyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// A value-free refusal of an invalid idempotency key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Base Registry Engine idempotency key is invalid")]
pub struct BRegIdempotencyKeyError;

/// A value-free reason that a direct-mutation body cannot be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegMutationRequestError {
    #[error("a Base Registry Engine mutation field name is invalid")]
    InvalidFieldName,
    #[error("a Base Registry Engine mutation value is outside the supported I-JSON domain")]
    InvalidJsonValue,
    #[error("a Base Registry Engine patch has more than 128 operations")]
    TooManyPatchOperations,
    #[error("a Base Registry Engine patch must contain at least one mutating operation")]
    PatchRequiresMutation,
    #[error("a Base Registry Engine mutation body exceeds 2097152 encoded bytes")]
    BodyTooLarge,
    #[error("a Base Registry Engine mutation body could not be encoded")]
    BodyEncoding,
    #[error("a Base Registry Engine create field is not writable for the selected operation")]
    CreateFieldNotWritable,
    #[error("a Base Registry Engine create request is missing a required writable field")]
    RequiredCreateFieldMissing,
    #[error("a Base Registry Engine patch field is not readable for the selected operation")]
    PatchFieldNotReadable,
    #[error("a Base Registry Engine patch field is not writable for the selected operation")]
    PatchFieldNotWritable,
    #[error("a Base Registry Engine patch field is not removable for the selected operation")]
    PatchFieldNotRemovable,
}

/// An exact `{ "data": { ... } }` Base Registry Engine create body.
pub struct BRegCreateRequest {
    body: Zeroizing<Vec<u8>>,
    submitted_fields: BTreeSet<String>,
}

impl BRegCreateRequest {
    /// Construct an exact, bounded data envelope.
    ///
    /// Field names use Base Registry Engine's compiled API-name grammar. Governed
    /// field schemas, writable-field grants, and required fields are checked
    /// again when this request is bound to a metadata-derived operation.
    pub fn new(data: Map<String, Value>) -> Result<Self, BRegMutationRequestError> {
        if data.keys().any(|field| !valid_api_field_name(field)) {
            return Err(BRegMutationRequestError::InvalidFieldName);
        }
        validate_json_values(data.values(), 2)?;
        let body = encode_bounded(&CreateEnvelope { data: &data })?;
        Ok(Self {
            body: Zeroizing::new(body),
            submitted_fields: data.into_iter().map(|(field, _)| field).collect(),
        })
    }

    /// Return the encoded body size without exposing its values.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// Bind the caller fields to the exact caller-filtered operation grant.
    pub(crate) fn validate_fields(
        &self,
        writable: &BTreeSet<String>,
        required: &BTreeSet<String>,
    ) -> Result<(), BRegMutationRequestError> {
        if !self.submitted_fields.is_subset(writable) {
            return Err(BRegMutationRequestError::CreateFieldNotWritable);
        }
        if !required.is_subset(&self.submitted_fields) {
            return Err(BRegMutationRequestError::RequiredCreateFieldMissing);
        }
        Ok(())
    }
}

impl fmt::Debug for BRegCreateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegCreateRequest")
            .field("body_bytes", &self.body.len())
            .field("field_count", &self.submitted_fields.len())
            .finish()
    }
}

#[derive(Serialize)]
struct CreateEnvelope<'a> {
    data: &'a Map<String, Value>,
}

/// Builder for one ordered Base Registry Engine JSON Patch document.
#[derive(Default)]
pub struct BRegPatchBuilder {
    operations: Vec<BRegPatchOperation>,
    has_mutator: bool,
}

impl BRegPatchBuilder {
    /// Start an empty patch. [`Self::build`] refuses a test-only document.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an RFC 6902 `add` operation under `/data/`.
    pub fn add(
        mut self,
        field: impl Into<String>,
        value: Value,
    ) -> Result<Self, BRegMutationRequestError> {
        self.push_value(BRegPatchOperationKind::Add, field.into(), value)?;
        Ok(self)
    }

    /// Append an RFC 6902 `replace` operation under `/data/`.
    pub fn replace(
        mut self,
        field: impl Into<String>,
        value: Value,
    ) -> Result<Self, BRegMutationRequestError> {
        self.push_value(BRegPatchOperationKind::Replace, field.into(), value)?;
        Ok(self)
    }

    /// Append an RFC 6902 `remove` operation under `/data/`.
    ///
    /// Base Registry Engine interprets this as setting a removable field to null.
    pub fn remove(mut self, field: impl Into<String>) -> Result<Self, BRegMutationRequestError> {
        self.ensure_capacity()?;
        let field = checked_field(field.into())?;
        self.operations.push(BRegPatchOperation::Remove {
            path: patch_path(&field),
            field,
        });
        self.has_mutator = true;
        Ok(self)
    }

    /// Append an RFC 6902 `test` operation under `/data/`.
    pub fn test(
        mut self,
        field: impl Into<String>,
        value: Value,
    ) -> Result<Self, BRegMutationRequestError> {
        self.push_value(BRegPatchOperationKind::Test, field.into(), value)?;
        Ok(self)
    }

    /// Finish the ordered patch after checking operation and body bounds.
    pub fn build(self) -> Result<BRegPatchRequest, BRegMutationRequestError> {
        if !self.has_mutator {
            return Err(BRegMutationRequestError::PatchRequiresMutation);
        }
        let body = encode_bounded(&self.operations)?;
        Ok(BRegPatchRequest {
            body: Zeroizing::new(body),
            fields: self
                .operations
                .into_iter()
                .map(BRegPatchOperation::into_field_use)
                .collect(),
        })
    }

    fn push_value(
        &mut self,
        kind: BRegPatchOperationKind,
        field: String,
        value: Value,
    ) -> Result<(), BRegMutationRequestError> {
        self.ensure_capacity()?;
        let field = checked_field(field)?;
        validate_json_values(std::iter::once(&value), 2)?;
        let path = patch_path(&field);
        let operation = match kind {
            BRegPatchOperationKind::Add => {
                self.has_mutator = true;
                BRegPatchOperation::Add { path, value, field }
            }
            BRegPatchOperationKind::Replace => {
                self.has_mutator = true;
                BRegPatchOperation::Replace { path, value, field }
            }
            BRegPatchOperationKind::Test => BRegPatchOperation::Test { path, value, field },
        };
        self.operations.push(operation);
        Ok(())
    }

    fn ensure_capacity(&self) -> Result<(), BRegMutationRequestError> {
        if self.operations.len() >= MAXIMUM_BREG_PATCH_OPERATIONS {
            return Err(BRegMutationRequestError::TooManyPatchOperations);
        }
        Ok(())
    }
}

impl fmt::Debug for BRegPatchBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegPatchBuilder")
            .field("operation_count", &self.operations.len())
            .field("has_mutator", &self.has_mutator)
            .finish()
    }
}

/// An exact, bounded Base Registry Engine JSON Patch body.
pub struct BRegPatchRequest {
    body: Zeroizing<Vec<u8>>,
    fields: Vec<BRegPatchFieldUse>,
}

impl BRegPatchRequest {
    /// Start an ordered JSON Patch builder.
    #[must_use]
    pub fn builder() -> BRegPatchBuilder {
        BRegPatchBuilder::new()
    }

    /// Return the encoded body size without exposing its values.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Return the number of patch operations without exposing their values.
    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.fields.len()
    }

    pub(crate) fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// Bind every field use to the exact caller-filtered operation grant.
    pub(crate) fn validate_fields(
        &self,
        readable: &BTreeSet<String>,
        writable: &BTreeSet<String>,
        removable: &BTreeSet<String>,
    ) -> Result<(), BRegMutationRequestError> {
        for field in &self.fields {
            match field {
                BRegPatchFieldUse::Read(field) if !readable.contains(field) => {
                    return Err(BRegMutationRequestError::PatchFieldNotReadable);
                }
                BRegPatchFieldUse::Write(field) if !writable.contains(field) => {
                    return Err(BRegMutationRequestError::PatchFieldNotWritable);
                }
                BRegPatchFieldUse::Remove(field) if !removable.contains(field) => {
                    return Err(BRegMutationRequestError::PatchFieldNotRemovable);
                }
                BRegPatchFieldUse::Read(_)
                | BRegPatchFieldUse::Write(_)
                | BRegPatchFieldUse::Remove(_) => {}
            }
        }
        Ok(())
    }
}

impl fmt::Debug for BRegPatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BRegPatchRequest")
            .field("body_bytes", &self.body.len())
            .field("operation_count", &self.fields.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
enum BRegPatchOperationKind {
    Add,
    Replace,
    Test,
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum BRegPatchOperation {
    Add {
        path: String,
        value: Value,
        #[serde(skip)]
        field: String,
    },
    Replace {
        path: String,
        value: Value,
        #[serde(skip)]
        field: String,
    },
    Remove {
        path: String,
        #[serde(skip)]
        field: String,
    },
    Test {
        path: String,
        value: Value,
        #[serde(skip)]
        field: String,
    },
}

impl BRegPatchOperation {
    fn into_field_use(self) -> BRegPatchFieldUse {
        match self {
            Self::Add { field, .. } | Self::Replace { field, .. } => {
                BRegPatchFieldUse::Write(field)
            }
            Self::Remove { field, .. } => BRegPatchFieldUse::Remove(field),
            Self::Test { field, .. } => BRegPatchFieldUse::Read(field),
        }
    }
}

enum BRegPatchFieldUse {
    Read(String),
    Write(String),
    Remove(String),
}

fn checked_field(field: String) -> Result<String, BRegMutationRequestError> {
    if !valid_api_field_name(&field) {
        return Err(BRegMutationRequestError::InvalidFieldName);
    }
    Ok(field)
}

fn valid_api_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_API_FIELD_NAME_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn patch_path(field: &str) -> String {
    format!("/data/{}", encode_pointer_segment(field))
}

fn encode_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn validate_json_values<'a>(
    values: impl IntoIterator<Item = &'a Value>,
    initial_depth: usize,
) -> Result<(), BRegMutationRequestError> {
    let mut pending = values
        .into_iter()
        .map(|value| (value, initial_depth))
        .collect::<Vec<_>>();
    while let Some((value, depth)) = pending.pop() {
        if depth > MAXIMUM_JSON_NESTING_DEPTH {
            return Err(BRegMutationRequestError::InvalidJsonValue);
        }
        match value {
            Value::Number(number) if !number_is_exact_binary64(number) => {
                return Err(BRegMutationRequestError::InvalidJsonValue);
            }
            Value::Array(items) => pending.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(object) => {
                pending.extend(object.values().map(|item| (item, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn number_is_exact_binary64(number: &serde_json::Number) -> bool {
    if let Some(value) = number.as_i64() {
        return integer_magnitude_is_exact_binary64(value.unsigned_abs());
    }
    if let Some(value) = number.as_u64() {
        return integer_magnitude_is_exact_binary64(value);
    }
    number.as_f64().is_some_and(f64::is_finite)
}

fn integer_magnitude_is_exact_binary64(value: u64) -> bool {
    if value == 0 {
        return true;
    }
    let significant_bits = u64::BITS - value.leading_zeros();
    significant_bits <= 53 || value.trailing_zeros() >= significant_bits - 53
}

fn encode_bounded(value: &impl Serialize) -> Result<Vec<u8>, BRegMutationRequestError> {
    let body = serde_json::to_vec(value).map_err(|_| BRegMutationRequestError::BodyEncoding)?;
    if body.len() > MAXIMUM_BREG_MUTATION_BODY_BYTES {
        return Err(BRegMutationRequestError::BodyTooLarge);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn create_body_is_the_exact_data_envelope() {
        let request = BRegCreateRequest::new(
            json!({"legalName": "Example Ltd", "employeeCount": 42})
                .as_object()
                .expect("object")
                .clone(),
        )
        .expect("request");
        assert_eq!(
            serde_json::from_slice::<Value>(request.body()).expect("body"),
            json!({"data": {"legalName": "Example Ltd", "employeeCount": 42}})
        );
    }

    #[test]
    fn patch_body_preserves_order_and_exact_operation_shapes() {
        let request = BRegPatchRequest::builder()
            .test("status", json!("draft"))
            .unwrap()
            .add("legalName", json!("Example Ltd"))
            .unwrap()
            .replace("status", json!("active"))
            .unwrap()
            .remove("optionalCode")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(request.body()).expect("body"),
            json!([
                {"op": "test", "path": "/data/status", "value": "draft"},
                {"op": "add", "path": "/data/legalName", "value": "Example Ltd"},
                {"op": "replace", "path": "/data/status", "value": "active"},
                {"op": "remove", "path": "/data/optionalCode"}
            ])
        );
    }

    #[test]
    fn metadata_field_binding_fails_closed_by_operation_kind() {
        let create = BRegCreateRequest::new(
            json!({"legalName": "Example Ltd"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        assert_eq!(
            create.validate_fields(&BTreeSet::new(), &BTreeSet::new()),
            Err(BRegMutationRequestError::CreateFieldNotWritable)
        );
        assert_eq!(
            create.validate_fields(
                &BTreeSet::from(["legalName".into()]),
                &BTreeSet::from(["registrationDate".into()]),
            ),
            Err(BRegMutationRequestError::RequiredCreateFieldMissing)
        );

        let patch = BRegPatchRequest::builder()
            .test("status", json!("draft"))
            .unwrap()
            .replace("legalName", json!("Example Ltd"))
            .unwrap()
            .remove("optionalCode")
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            patch.validate_fields(
                &BTreeSet::new(),
                &BTreeSet::from(["legalName".into()]),
                &BTreeSet::from(["optionalCode".into()]),
            ),
            Err(BRegMutationRequestError::PatchFieldNotReadable)
        );
        assert_eq!(
            patch.validate_fields(
                &BTreeSet::from(["status".into()]),
                &BTreeSet::new(),
                &BTreeSet::from(["optionalCode".into()]),
            ),
            Err(BRegMutationRequestError::PatchFieldNotWritable)
        );
        assert_eq!(
            patch.validate_fields(
                &BTreeSet::from(["status".into()]),
                &BTreeSet::from(["legalName".into()]),
                &BTreeSet::new(),
            ),
            Err(BRegMutationRequestError::PatchFieldNotRemovable)
        );
    }
}
