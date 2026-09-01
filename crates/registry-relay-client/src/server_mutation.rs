// SPDX-License-Identifier: Apache-2.0

//! Bounded, value-safe request bodies for Registry Server direct mutations.
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

/// Maximum encoded body accepted by Registry Server mutation routes.
pub const MAXIMUM_SERVER_MUTATION_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of operations in one Registry Server JSON Patch document.
pub const MAXIMUM_SERVER_PATCH_OPERATIONS: usize = 128;

const MAXIMUM_JSON_NESTING_DEPTH: usize = 128;
const MAXIMUM_API_FIELD_NAME_BYTES: usize = 64;

/// A caller-chosen Registry Server idempotency key.
///
/// The client deliberately has no key generator and never retries a mutation
/// automatically. A caller may reuse this value only to replay the exact same
/// method, route, precondition, representation, and body after an uncertain
/// exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct RegistryServerIdempotencyKey(Zeroizing<String>);

impl RegistryServerIdempotencyKey {
    /// Parse the exact Registry Server header grammar: 1 through 256 visible
    /// ASCII bytes, excluding comma and semicolon.
    pub fn parse(value: impl Into<String>) -> Result<Self, RegistryServerIdempotencyKeyError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| matches!(byte, 0x21..=0x7e) && byte != b',' && byte != b';')
        {
            return Err(RegistryServerIdempotencyKeyError);
        }
        Ok(Self(value))
    }

    /// Borrow the validated header value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for RegistryServerIdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistryServerIdempotencyKey(<redacted>)")
    }
}

impl std::str::FromStr for RegistryServerIdempotencyKey {
    type Err = RegistryServerIdempotencyKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for RegistryServerIdempotencyKey {
    type Error = RegistryServerIdempotencyKeyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// A value-free refusal of an invalid idempotency key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Registry Server idempotency key is invalid")]
pub struct RegistryServerIdempotencyKeyError;

/// A value-free reason that a direct-mutation body cannot be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ServerMutationRequestError {
    #[error("a Registry Server mutation field name is invalid")]
    InvalidFieldName,
    #[error("a Registry Server mutation value is outside the supported I-JSON domain")]
    InvalidJsonValue,
    #[error("a Registry Server patch has more than 128 operations")]
    TooManyPatchOperations,
    #[error("a Registry Server patch must contain at least one mutating operation")]
    PatchRequiresMutation,
    #[error("a Registry Server mutation body exceeds 2097152 encoded bytes")]
    BodyTooLarge,
    #[error("a Registry Server mutation body could not be encoded")]
    BodyEncoding,
    #[error("a Registry Server create field is not writable for the selected operation")]
    CreateFieldNotWritable,
    #[error("a Registry Server create request is missing a required writable field")]
    RequiredCreateFieldMissing,
    #[error("a Registry Server patch field is not readable for the selected operation")]
    PatchFieldNotReadable,
    #[error("a Registry Server patch field is not writable for the selected operation")]
    PatchFieldNotWritable,
    #[error("a Registry Server patch field is not removable for the selected operation")]
    PatchFieldNotRemovable,
}

/// An exact `{ "data": { ... } }` Registry Server create body.
pub struct ServerCreateRequest {
    body: Zeroizing<Vec<u8>>,
    submitted_fields: BTreeSet<String>,
}

impl ServerCreateRequest {
    /// Construct an exact, bounded data envelope.
    ///
    /// Field names use Registry Server's compiled API-name grammar. Governed
    /// field schemas, writable-field grants, and required fields are checked
    /// again when this request is bound to a metadata-derived operation.
    pub fn new(data: Map<String, Value>) -> Result<Self, ServerMutationRequestError> {
        if data.keys().any(|field| !valid_api_field_name(field)) {
            return Err(ServerMutationRequestError::InvalidFieldName);
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
    ) -> Result<(), ServerMutationRequestError> {
        if !self.submitted_fields.is_subset(writable) {
            return Err(ServerMutationRequestError::CreateFieldNotWritable);
        }
        if !required.is_subset(&self.submitted_fields) {
            return Err(ServerMutationRequestError::RequiredCreateFieldMissing);
        }
        Ok(())
    }
}

impl fmt::Debug for ServerCreateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerCreateRequest")
            .field("body_bytes", &self.body.len())
            .field("field_count", &self.submitted_fields.len())
            .finish()
    }
}

#[derive(Serialize)]
struct CreateEnvelope<'a> {
    data: &'a Map<String, Value>,
}

/// Builder for one ordered Registry Server JSON Patch document.
#[derive(Default)]
pub struct ServerPatchBuilder {
    operations: Vec<ServerPatchOperation>,
    has_mutator: bool,
}

impl ServerPatchBuilder {
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
    ) -> Result<Self, ServerMutationRequestError> {
        self.push_value(ServerPatchOperationKind::Add, field.into(), value)?;
        Ok(self)
    }

    /// Append an RFC 6902 `replace` operation under `/data/`.
    pub fn replace(
        mut self,
        field: impl Into<String>,
        value: Value,
    ) -> Result<Self, ServerMutationRequestError> {
        self.push_value(ServerPatchOperationKind::Replace, field.into(), value)?;
        Ok(self)
    }

    /// Append an RFC 6902 `remove` operation under `/data/`.
    ///
    /// Registry Server interprets this as setting a removable field to null.
    pub fn remove(mut self, field: impl Into<String>) -> Result<Self, ServerMutationRequestError> {
        self.ensure_capacity()?;
        let field = checked_field(field.into())?;
        self.operations.push(ServerPatchOperation::Remove {
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
    ) -> Result<Self, ServerMutationRequestError> {
        self.push_value(ServerPatchOperationKind::Test, field.into(), value)?;
        Ok(self)
    }

    /// Finish the ordered patch after checking operation and body bounds.
    pub fn build(self) -> Result<ServerPatchRequest, ServerMutationRequestError> {
        if !self.has_mutator {
            return Err(ServerMutationRequestError::PatchRequiresMutation);
        }
        let body = encode_bounded(&self.operations)?;
        Ok(ServerPatchRequest {
            body: Zeroizing::new(body),
            fields: self
                .operations
                .into_iter()
                .map(ServerPatchOperation::into_field_use)
                .collect(),
        })
    }

    fn push_value(
        &mut self,
        kind: ServerPatchOperationKind,
        field: String,
        value: Value,
    ) -> Result<(), ServerMutationRequestError> {
        self.ensure_capacity()?;
        let field = checked_field(field)?;
        validate_json_values(std::iter::once(&value), 2)?;
        let path = patch_path(&field);
        let operation = match kind {
            ServerPatchOperationKind::Add => {
                self.has_mutator = true;
                ServerPatchOperation::Add { path, value, field }
            }
            ServerPatchOperationKind::Replace => {
                self.has_mutator = true;
                ServerPatchOperation::Replace { path, value, field }
            }
            ServerPatchOperationKind::Test => ServerPatchOperation::Test { path, value, field },
        };
        self.operations.push(operation);
        Ok(())
    }

    fn ensure_capacity(&self) -> Result<(), ServerMutationRequestError> {
        if self.operations.len() >= MAXIMUM_SERVER_PATCH_OPERATIONS {
            return Err(ServerMutationRequestError::TooManyPatchOperations);
        }
        Ok(())
    }
}

impl fmt::Debug for ServerPatchBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerPatchBuilder")
            .field("operation_count", &self.operations.len())
            .field("has_mutator", &self.has_mutator)
            .finish()
    }
}

/// An exact, bounded Registry Server JSON Patch body.
pub struct ServerPatchRequest {
    body: Zeroizing<Vec<u8>>,
    fields: Vec<ServerPatchFieldUse>,
}

impl ServerPatchRequest {
    /// Start an ordered JSON Patch builder.
    #[must_use]
    pub fn builder() -> ServerPatchBuilder {
        ServerPatchBuilder::new()
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
    ) -> Result<(), ServerMutationRequestError> {
        for field in &self.fields {
            match field {
                ServerPatchFieldUse::Read(field) if !readable.contains(field) => {
                    return Err(ServerMutationRequestError::PatchFieldNotReadable);
                }
                ServerPatchFieldUse::Write(field) if !writable.contains(field) => {
                    return Err(ServerMutationRequestError::PatchFieldNotWritable);
                }
                ServerPatchFieldUse::Remove(field) if !removable.contains(field) => {
                    return Err(ServerMutationRequestError::PatchFieldNotRemovable);
                }
                ServerPatchFieldUse::Read(_)
                | ServerPatchFieldUse::Write(_)
                | ServerPatchFieldUse::Remove(_) => {}
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ServerPatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerPatchRequest")
            .field("body_bytes", &self.body.len())
            .field("operation_count", &self.fields.len())
            .finish()
    }
}

#[derive(Clone, Copy)]
enum ServerPatchOperationKind {
    Add,
    Replace,
    Test,
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum ServerPatchOperation {
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

impl ServerPatchOperation {
    fn into_field_use(self) -> ServerPatchFieldUse {
        match self {
            Self::Add { field, .. } | Self::Replace { field, .. } => {
                ServerPatchFieldUse::Write(field)
            }
            Self::Remove { field, .. } => ServerPatchFieldUse::Remove(field),
            Self::Test { field, .. } => ServerPatchFieldUse::Read(field),
        }
    }
}

enum ServerPatchFieldUse {
    Read(String),
    Write(String),
    Remove(String),
}

fn checked_field(field: String) -> Result<String, ServerMutationRequestError> {
    if !valid_api_field_name(&field) {
        return Err(ServerMutationRequestError::InvalidFieldName);
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
) -> Result<(), ServerMutationRequestError> {
    let mut pending = values
        .into_iter()
        .map(|value| (value, initial_depth))
        .collect::<Vec<_>>();
    while let Some((value, depth)) = pending.pop() {
        if depth > MAXIMUM_JSON_NESTING_DEPTH {
            return Err(ServerMutationRequestError::InvalidJsonValue);
        }
        match value {
            Value::Number(number) if !number_is_exact_binary64(number) => {
                return Err(ServerMutationRequestError::InvalidJsonValue);
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

fn encode_bounded(value: &impl Serialize) -> Result<Vec<u8>, ServerMutationRequestError> {
    let body = serde_json::to_vec(value).map_err(|_| ServerMutationRequestError::BodyEncoding)?;
    if body.len() > MAXIMUM_SERVER_MUTATION_BODY_BYTES {
        return Err(ServerMutationRequestError::BodyTooLarge);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn create_body_is_the_exact_data_envelope() {
        let request = ServerCreateRequest::new(
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
        let request = ServerPatchRequest::builder()
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
        let create = ServerCreateRequest::new(
            json!({"legalName": "Example Ltd"})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        assert_eq!(
            create.validate_fields(&BTreeSet::new(), &BTreeSet::new()),
            Err(ServerMutationRequestError::CreateFieldNotWritable)
        );
        assert_eq!(
            create.validate_fields(
                &BTreeSet::from(["legalName".into()]),
                &BTreeSet::from(["registrationDate".into()]),
            ),
            Err(ServerMutationRequestError::RequiredCreateFieldMissing)
        );

        let patch = ServerPatchRequest::builder()
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
            Err(ServerMutationRequestError::PatchFieldNotReadable)
        );
        assert_eq!(
            patch.validate_fields(
                &BTreeSet::from(["status".into()]),
                &BTreeSet::new(),
                &BTreeSet::from(["optionalCode".into()]),
            ),
            Err(ServerMutationRequestError::PatchFieldNotWritable)
        );
        assert_eq!(
            patch.validate_fields(
                &BTreeSet::from(["status".into()]),
                &BTreeSet::from(["legalName".into()]),
                &BTreeSet::new(),
            ),
            Err(ServerMutationRequestError::PatchFieldNotRemovable)
        );
    }
}
