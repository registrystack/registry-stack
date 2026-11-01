// SPDX-License-Identifier: Apache-2.0
//! The BReg direct mutation family: create, patch, and tombstone.
//!
//! Prepared forms:
//!
//! * create stores the client's own inert `BRegPreparedCreate` evidence,
//!   which binds the request values, the caller's key, and the metadata
//!   binding identity.
//! * patch and tombstone store this module's sealed envelope: the exact
//!   operation list (or record identity and precondition), the entity tag,
//!   and the key. The client publishes no prepared form for them, so the
//!   envelope is the closed shape recovery rebuilds the request from,
//!   byte for byte.
//!
//! The patch input's closed shape (`breg.record.patch/v1`):
//!
//! ```json
//! {"record": "<uuid>", "etag": "\"breg-...\"",
//!  "operations": [{"op": "add" | "replace" | "test", "field": "<api name>", "value": ...},
//!                 {"op": "remove", "field": "<api name>"}]}
//! ```
//!
//! The tombstone input's closed shape (`breg.record.tombstone/v1`):
//! `{"record": "<uuid>", "etag": "\"breg-...\""}`. The create input's
//! closed shape (`breg.record.create/v1`): `{"data": { ... }}` with the
//! API field values.
//!
//! Every member is an exact-same-key replay: `send` and `recover` execute
//! the same prepared form under the same key; the client's bounded
//! same-key retry covers an in-flight unknown outcome, and a later pass
//! re-arms the evidence against freshly selected metadata. Observation
//! reads the record back.

use std::sync::{Arc, LazyLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use registry_breg_client::{
    BRegCreateRequest, BRegEtag, BRegIdempotencyKey, BRegPatchRequest, BRegPreparedCreate,
    BRegRecordFormat, BaseRegistryClientError,
};

use crate::operation::{
    BodyKind, CommandKey, ConnectorFault, CredentialRequirements, IdempotencyRule, InputSchema,
    MutationBehavior, NativeState, Observable, Operation, OperationDescriptor, PreparedAttempt,
    Product, RecoveryRule, SendOutcome,
};

use super::{classify, completed, fault};

fn descriptor(
    name: &'static str,
    shape: &'static str,
    mutation: MutationBehavior,
    body_kind: BodyKind,
    completion: &'static str,
    operator_authority: bool,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        product: Product::Breg,
        input_schema: InputSchema::ConnectorDefined {
            shape: shape.to_owned(),
        },
        body_kind,
        mutation,
        credentials: CredentialRequirements {
            credential_kinds: vec!["private-key-jwt".to_owned()],
            requires_task_grant: false,
            requires_operator_authority: operator_authority,
        },
        idempotency: IdempotencyRule::CallerKeyed {
            receipt_retention_days: Some(7),
        },
        recovery: RecoveryRule::ExactSameKey,
        completion,
        observable: false,
    }
}

/// A create mutates without preconditions beyond its binding and key.
pub static CREATE: LazyLock<OperationDescriptor> = LazyLock::new(|| {
    descriptor(
        "breg.record.create",
        "breg.record.create/v1",
        MutationBehavior::Unconditional,
        BodyKind::Json,
        "the destination committed the record and answered with its created receipt",
        false,
    )
});

/// A patch holds the record's entity tag as its precondition.
pub static PATCH: LazyLock<OperationDescriptor> = LazyLock::new(|| {
    descriptor(
        "breg.record.patch",
        "breg.record.patch/v1",
        MutationBehavior::Preconditioned,
        BodyKind::Json,
        "the destination committed the patch and answered with the patched receipt",
        false,
    )
});

/// A tombstone is destructive and preconditioned on the entity tag; it
/// runs only when the host opened the authority.
pub static TOMBSTONE: LazyLock<OperationDescriptor> = LazyLock::new(|| {
    descriptor(
        "breg.record.tombstone",
        "breg.record.tombstone/v1",
        MutationBehavior::Destructive,
        BodyKind::None,
        "the destination tombstoned the record and answered with the retained receipt",
        false,
    )
});

fn key_material(key: &CommandKey) -> Result<BRegIdempotencyKey, ConnectorFault> {
    BRegIdempotencyKey::parse(key.as_str()).map_err(|_| ConnectorFault::InvalidInput)
}

fn parse_record_identifier(input: &Value) -> Result<Uuid, ConnectorFault> {
    let text = input
        .get("record")
        .and_then(Value::as_str)
        .ok_or(ConnectorFault::InvalidInput)?;
    Uuid::parse_str(text).map_err(|_| ConnectorFault::InvalidInput)
}

fn parse_etag(input: &Value) -> Result<BRegEtag, ConnectorFault> {
    let text = input
        .get("etag")
        .and_then(Value::as_str)
        .ok_or(ConnectorFault::InvalidInput)?;
    BRegEtag::parse(text).map_err(|_| ConnectorFault::InvalidInput)
}

/// A prepare-time client refusal means the input did not satisfy the
/// selected binding; every other client fault keeps its mapping.
fn prepare_fault(error: &BaseRegistryClientError) -> ConnectorFault {
    match error {
        BaseRegistryClientError::InvalidRequest { .. } => ConnectorFault::InvalidInput,
        _ => fault(error),
    }
}

/// The exact, persistable create attempt: the client's inert evidence
/// plus the runner's command key.
pub struct PreparedCreate {
    evidence: BRegPreparedCreate,
    key: CommandKey,
}

impl PreparedCreate {
    /// Restore the stored bytes of one create attempt. The evidence
    /// carries its own key material; bytes from another operation or an
    /// earlier evidence version answer [`ConnectorFault::NotPrepared`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let evidence =
            BRegPreparedCreate::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
        // The client's create evidence names its member idempotency_key.
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
        let key = value
            .get("idempotency_key")
            .and_then(Value::as_str)
            .ok_or(ConnectorFault::NotPrepared)?;
        let key = CommandKey::new(key.to_owned());
        Ok(Self {
            evidence,
            key: key.map_err(|_| ConnectorFault::NotPrepared)?,
        })
    }
}

/// Read the command key back out of one stored envelope. The key stays
/// the runner's derived value; bytes without one are not this contract's.
fn envelope_key(bytes: &[u8]) -> Result<CommandKey, ConnectorFault> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
    let key = value
        .get("key")
        .and_then(Value::as_str)
        .ok_or(ConnectorFault::NotPrepared)?;
    CommandKey::new(key.to_owned())
}

impl std::fmt::Debug for PreparedCreate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedCreate(<redacted>)")
    }
}

impl std::fmt::Debug for PreparedPatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedPatch(<redacted>)")
    }
}

impl std::fmt::Debug for PreparedTombstone {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedTombstone(<redacted>)")
    }
}

impl PreparedAttempt for PreparedCreate {
    fn as_bytes(&self) -> &[u8] {
        self.evidence.as_bytes()
    }

    fn operation(&self) -> &'static str {
        "breg.record.create"
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub(crate) enum PatchOperation {
    Add { field: String, value: Value },
    Replace { field: String, value: Value },
    Remove { field: String },
    Test { field: String, value: Value },
}

#[derive(Serialize, Deserialize)]
struct PatchEnvelope {
    version: u8,
    operation: String,
    key: String,
    record: Uuid,
    etag: String,
    operations: Vec<PatchOperation>,
}

/// The exact, persistable patch attempt: the sealed operation list,
/// record identity, entity tag, and key.
pub struct PreparedPatch {
    envelope: Vec<u8>,
    key: CommandKey,
}

impl PreparedPatch {
    /// Restore the stored bytes of one patch attempt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let header: EnvelopeHeader =
            serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
        if header.version != ENVELOPE_VERSION || header.operation != "breg.record.patch" {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(Self {
            envelope: bytes.to_vec(),
            key: envelope_key(bytes)?,
        })
    }
}

impl PreparedAttempt for PreparedPatch {
    fn as_bytes(&self) -> &[u8] {
        &self.envelope
    }

    fn operation(&self) -> &'static str {
        "breg.record.patch"
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

#[derive(Serialize, Deserialize)]
struct TombstoneEnvelope {
    version: u8,
    operation: String,
    key: String,
    record: Uuid,
    etag: String,
}

/// The exact, persistable tombstone attempt.
pub struct PreparedTombstone {
    envelope: Vec<u8>,
    key: CommandKey,
}

impl PreparedTombstone {
    /// Restore the stored bytes of one tombstone attempt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let header: EnvelopeHeader =
            serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
        if header.version != ENVELOPE_VERSION || header.operation != "breg.record.tombstone" {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(Self {
            envelope: bytes.to_vec(),
            key: envelope_key(bytes)?,
        })
    }
}

impl PreparedAttempt for PreparedTombstone {
    fn as_bytes(&self) -> &[u8] {
        &self.envelope
    }

    fn operation(&self) -> &'static str {
        "breg.record.tombstone"
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

/// Build the exact patch request from the closed operation shapes; the
/// builder validates field grants and bounds deterministically.
pub(crate) fn build_patch(
    operations: &[PatchOperation],
) -> Result<BRegPatchRequest, ConnectorFault> {
    let mut builder = BRegPatchRequest::builder();
    for operation in operations {
        builder = match operation {
            PatchOperation::Add { field, value } => builder.add(field, value.clone()),
            PatchOperation::Replace { field, value } => builder.replace(field, value.clone()),
            PatchOperation::Remove { field } => builder.remove(field),
            PatchOperation::Test { field, value } => builder.test(field, value.clone()),
        }
        .map_err(|_| ConnectorFault::InvalidInput)?;
    }
    builder.build().map_err(|_| ConnectorFault::InvalidInput)
}

fn unseal<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    operation: &'static str,
) -> Result<T, ConnectorFault> {
    let envelope: EnvelopeHeader =
        serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
    if envelope.version != ENVELOPE_VERSION || envelope.operation != operation {
        return Err(ConnectorFault::NotPrepared);
    }
    serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)
}

const ENVELOPE_VERSION: u8 = 1;

#[derive(Deserialize)]
struct EnvelopeHeader {
    version: u8,
    operation: String,
}

/// The direct create over one connected connector.
pub struct RecordCreate {
    pub(crate) connector: Arc<super::BregConnector>,
}

impl Observable for RecordCreate {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        self.connector.observe_record(correlation)
    }
}

impl Operation for RecordCreate {
    type Prepared = PreparedCreate;

    fn describe(&self) -> &OperationDescriptor {
        &CREATE
    }

    fn prepare(&self, input: &Value, key: CommandKey) -> Result<PreparedCreate, ConnectorFault> {
        let data = input
            .get("data")
            .and_then(Value::as_object)
            .ok_or(ConnectorFault::InvalidInput)?
            .clone();
        let request = BRegCreateRequest::new(data).map_err(|_| ConnectorFault::InvalidInput)?;
        let evidence = self
            .connector
            .client()
            .prepare_create(
                self.connector.create_binding()?,
                &request,
                &key_material(&key)?,
                BRegRecordFormat::Json,
            )
            .map_err(|error| prepare_fault(&error))?;
        Ok(PreparedCreate { evidence, key })
    }

    fn send(&self, prepared: &PreparedCreate) -> Result<SendOutcome, ConnectorFault> {
        self.recover(prepared)
    }

    fn recover(&self, prepared: &PreparedCreate) -> Result<SendOutcome, ConnectorFault> {
        let binding = self.connector.create_binding()?;
        let (request, key, format) = self
            .connector
            .client()
            .recover_create(binding, &prepared.evidence)
            .map_err(|error| fault(&error))?;
        let answer = self.connector.block(
            self.connector
                .client()
                .create_record(binding, &request, &key, format),
        );
        match answer {
            Ok(record) => Ok(completed(record.value.data.record_identifier.clone())),
            Err(error) => classify(&error),
        }
    }
}

/// The direct patch over one connected connector.
pub struct RecordPatch {
    pub(crate) connector: Arc<super::BregConnector>,
}

impl Observable for RecordPatch {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        self.connector.observe_record(correlation)
    }
}

impl Operation for RecordPatch {
    type Prepared = PreparedPatch;

    fn describe(&self) -> &OperationDescriptor {
        &PATCH
    }

    fn prepare(&self, input: &Value, key: CommandKey) -> Result<PreparedPatch, ConnectorFault> {
        let record = parse_record_identifier(input)?;
        let etag = parse_etag(input)?;
        let operations: Vec<PatchOperation> = serde_json::from_value(
            input
                .get("operations")
                .cloned()
                .ok_or(ConnectorFault::InvalidInput)?,
        )
        .map_err(|_| ConnectorFault::InvalidInput)?;
        // Build once here so shape faults answer at prepare, with no I/O.
        build_patch(&operations)?;
        let envelope = PatchEnvelope {
            version: ENVELOPE_VERSION,
            operation: "breg.record.patch".to_owned(),
            key: key.as_str().to_owned(),
            record,
            etag: etag.as_str().to_owned(),
            operations,
        };
        Ok(PreparedPatch {
            envelope: serde_json::to_vec(&envelope).map_err(|_| ConnectorFault::InvalidInput)?,
            key,
        })
    }

    fn send(&self, prepared: &PreparedPatch) -> Result<SendOutcome, ConnectorFault> {
        self.recover(prepared)
    }

    fn recover(&self, prepared: &PreparedPatch) -> Result<SendOutcome, ConnectorFault> {
        let envelope: PatchEnvelope = unseal(&prepared.envelope, "breg.record.patch")?;
        let request = build_patch(&envelope.operations)?;
        let etag = BRegEtag::parse(&envelope.etag).map_err(|_| ConnectorFault::NotPrepared)?;
        let key =
            BRegIdempotencyKey::parse(&envelope.key).map_err(|_| ConnectorFault::NotPrepared)?;
        let answer = self.connector.block(self.connector.client().patch_record(
            self.connector.patch_binding()?,
            envelope.record,
            &etag,
            &request,
            &key,
            BRegRecordFormat::Json,
        ));
        match answer {
            Ok(record) => Ok(completed(record.value.data.record_identifier.clone())),
            Err(error) => classify(&error),
        }
    }
}

/// The destructive tombstone over one connected connector; it runs only
/// when the host opened the authority.
pub struct RecordTombstone {
    pub(crate) connector: Arc<super::BregConnector>,
}

impl Observable for RecordTombstone {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        self.connector.observe_record(correlation)
    }
}

impl Operation for RecordTombstone {
    type Prepared = PreparedTombstone;

    fn describe(&self) -> &OperationDescriptor {
        &TOMBSTONE
    }

    fn prepare(&self, input: &Value, key: CommandKey) -> Result<PreparedTombstone, ConnectorFault> {
        let record = parse_record_identifier(input)?;
        let etag = parse_etag(input)?;
        // Touch the binding so a disabled tombstone answers before any
        // bytes exist.
        self.connector.tombstone_binding()?;
        let envelope = TombstoneEnvelope {
            version: ENVELOPE_VERSION,
            operation: "breg.record.tombstone".to_owned(),
            key: key.as_str().to_owned(),
            record,
            etag: etag.as_str().to_owned(),
        };
        Ok(PreparedTombstone {
            envelope: serde_json::to_vec(&envelope).map_err(|_| ConnectorFault::InvalidInput)?,
            key,
        })
    }

    fn send(&self, prepared: &PreparedTombstone) -> Result<SendOutcome, ConnectorFault> {
        self.recover(prepared)
    }

    fn recover(&self, prepared: &PreparedTombstone) -> Result<SendOutcome, ConnectorFault> {
        let envelope: TombstoneEnvelope = unseal(&prepared.envelope, "breg.record.tombstone")?;
        let etag = BRegEtag::parse(&envelope.etag).map_err(|_| ConnectorFault::NotPrepared)?;
        let key =
            BRegIdempotencyKey::parse(&envelope.key).map_err(|_| ConnectorFault::NotPrepared)?;
        let answer = self
            .connector
            .block(self.connector.client().tombstone_record(
                self.connector.tombstone_binding()?,
                envelope.record,
                &etag,
                &key,
                BRegRecordFormat::Json,
            ));
        match answer {
            Ok(record) => Ok(completed(record.value.data.record_identifier.clone())),
            Err(error) => classify(&error),
        }
    }
}
