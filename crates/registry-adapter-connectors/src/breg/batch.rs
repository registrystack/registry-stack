// SPDX-License-Identifier: Apache-2.0
//! The BReg atomic batch family (`breg.batch.records`).
//!
//! One batch is one atomic same-entity create/patch exchange under the
//! metadata-selected batch binding. The client's builder enforces the
//! binding's own item and byte bounds, so an over-bound batch refuses at
//! `prepare` with [`ConnectorFault::InvalidInput`]; the runner chunks.
//!
//! The prepared form is this module's sealed envelope: the exact item
//! list and optional change context, and the key. The closed input shape
//! (`breg.batch.records/v1`):
//!
//! ```json
//! {"items": [{"operation": "create", "data": {...}},
//!            {"operation": "patch", "record": "<uuid>", "etag": "\"breg-...\"",
//!             "operations": [ ...same shape as breg.record.patch... ]}],
//!  "changeContext": {"kind": "change" | "correction", "reasonCode": "...",
//!                    "reasonText": "...", "sourceReference": "..."}}
//! ```
//!
//! `send` and `recover` rebuild the identical request and send it under
//! the same key. Observation reads the receipt's snapshot reference back
//! through the destination's own snapshot read.

use std::sync::{Arc, LazyLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use registry_breg_client::{
    BRegBatchBuilder, BRegBatchRequest, BRegChangeContext, BRegCreateRequest, BRegEtag,
    BRegIdempotencyKey, BRegSnapshotListRequest,
};

use crate::operation::{
    BodyKind, CommandKey, ConnectorFault, CredentialRequirements, IdempotencyRule, InputSchema,
    MutationBehavior, NativeState, Observable, Operation, OperationDescriptor, PreparedAttempt,
    Product, RecoveryRule, SendOutcome,
};

use super::{classify, completed, fault};

pub static RECORDS: LazyLock<OperationDescriptor> = LazyLock::new(|| OperationDescriptor {
    name: "breg.batch.records",
    product: Product::Breg,
    input_schema: InputSchema::ConnectorDefined {
        shape: "breg.batch.records/v1".to_owned(),
    },
    body_kind: BodyKind::Json,
    mutation: MutationBehavior::Preconditioned,
    credentials: CredentialRequirements {
        credential_kinds: vec!["private-key-jwt".to_owned()],
        requires_task_grant: false,
        requires_operator_authority: false,
    },
    idempotency: IdempotencyRule::CallerKeyed {
        receipt_retention_days: Some(7),
    },
    recovery: RecoveryRule::ExactSameKey,
    completion:
        "the destination committed every item atomically and answered with the batch receipt",
    observable: true,
});

const OPERATION: &str = "breg.batch.records";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "lowercase")]
enum BatchItem {
    Create {
        data: Value,
    },
    Patch {
        record: String,
        etag: String,
        #[serde(rename = "operations")]
        operations: Vec<super::mutation::PatchOperation>,
    },
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangeContextShape {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_reference: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BatchEnvelope {
    version: u8,
    operation: String,
    key: String,
    items: Vec<BatchItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    change_context: Option<ChangeContextShape>,
}

/// The exact, persistable batch attempt.
pub struct PreparedBatch {
    envelope: Vec<u8>,
    key: CommandKey,
}

impl PreparedBatch {
    /// Restore the stored bytes of one batch attempt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let envelope: BatchEnvelope =
            serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
        if envelope.version != 1 || envelope.operation != OPERATION {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(Self {
            envelope: bytes.to_vec(),
            key: CommandKey::new(envelope.key).map_err(|_| ConnectorFault::NotPrepared)?,
        })
    }
}

impl std::fmt::Debug for PreparedBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedBatch(<redacted>)")
    }
}

impl PreparedAttempt for PreparedBatch {
    fn as_bytes(&self) -> &[u8] {
        &self.envelope
    }

    fn operation(&self) -> &'static str {
        OPERATION
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

/// The atomic batch over one connected connector.
pub struct BatchRecords {
    pub(crate) connector: Arc<super::BregConnector>,
}

fn change_context(shape: &ChangeContextShape) -> Result<BRegChangeContext, ConnectorFault> {
    let context = match shape.kind.as_str() {
        "change" => BRegChangeContext::change(),
        "correction" => {
            let code = shape
                .reason_code
                .as_ref()
                .ok_or(ConnectorFault::InvalidInput)?;
            BRegChangeContext::correction(code.clone()).map_err(|_| ConnectorFault::InvalidInput)?
        }
        _ => return Err(ConnectorFault::InvalidInput),
    };
    let context = match &shape.reason_text {
        Some(text) => context
            .reason_text(text.clone())
            .map_err(|_| ConnectorFault::InvalidInput)?,
        None => context,
    };
    match &shape.source_reference {
        Some(reference) => context
            .source_reference(reference.clone())
            .map_err(|_| ConnectorFault::InvalidInput),
        None => Ok(context),
    }
}

impl BatchRecords {
    fn build_request(&self, envelope: &BatchEnvelope) -> Result<BRegBatchRequest, ConnectorFault> {
        let binding = self.connector.batch_binding()?;
        let mut builder = BRegBatchBuilder::new(binding);
        for item in &envelope.items {
            builder = match item {
                BatchItem::Create { data } => {
                    let data = data
                        .as_object()
                        .cloned()
                        .ok_or(ConnectorFault::InvalidInput)?;
                    let request =
                        BRegCreateRequest::new(data).map_err(|_| ConnectorFault::InvalidInput)?;
                    builder
                        .create(&request)
                        .map_err(|_| ConnectorFault::InvalidInput)?
                }
                BatchItem::Patch {
                    record,
                    etag,
                    operations,
                } => {
                    let record =
                        Uuid::parse_str(record).map_err(|_| ConnectorFault::InvalidInput)?;
                    let etag = BRegEtag::parse(etag).map_err(|_| ConnectorFault::InvalidInput)?;
                    let request = super::mutation::build_patch(operations)?;
                    builder
                        .patch(record, &etag, &request)
                        .map_err(|_| ConnectorFault::InvalidInput)?
                }
            };
        }
        if let Some(context) = &envelope.change_context {
            builder = builder.change_context(change_context(context)?);
        }
        // The builder enforces the binding's item and byte bounds here, so
        // an over-bound batch refuses at prepare and the runner chunks.
        builder.build().map_err(|_| ConnectorFault::InvalidInput)
    }
}

impl Observable for BatchRecords {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        let request = BRegSnapshotListRequest::default()
            .snapshot(correlation)
            .map_err(|_| ConnectorFault::InvalidInput)?
            .top(1)
            .map_err(|_| ConnectorFault::InvalidInput)?;
        let answer = self.connector.block(
            self.connector
                .client()
                .list_snapshot_records(self.connector.route(), &request),
        );
        match answer {
            Ok(page) => Ok(NativeState {
                state: "snapshot-readable".to_owned(),
                details: vec![
                    ("snapshot".to_owned(), page.value.snapshot.clone()),
                    ("items".to_owned(), page.value.value.items.len().to_string()),
                ],
            }),
            Err(error) => Err(fault(&error)),
        }
    }
}

impl Operation for BatchRecords {
    type Prepared = PreparedBatch;

    fn describe(&self) -> &OperationDescriptor {
        &RECORDS
    }

    fn prepare(&self, input: &Value, key: CommandKey) -> Result<PreparedBatch, ConnectorFault> {
        // Touch the binding so an absent batch grant answers at prepare.
        self.connector.batch_binding()?;
        let items: Vec<BatchItem> = serde_json::from_value(
            input
                .get("items")
                .cloned()
                .ok_or(ConnectorFault::InvalidInput)?,
        )
        .map_err(|_| ConnectorFault::InvalidInput)?;
        if items.is_empty() {
            return Err(ConnectorFault::InvalidInput);
        }
        let change_context: Option<ChangeContextShape> = match input.get("changeContext") {
            Some(value) => Some(
                serde_json::from_value(value.clone()).map_err(|_| ConnectorFault::InvalidInput)?,
            ),
            None => None,
        };
        let envelope = BatchEnvelope {
            version: 1,
            operation: OPERATION.to_owned(),
            key: key.as_str().to_owned(),
            items,
            change_context,
        };
        // Build once here so shape and bound faults answer at prepare,
        // with no I/O.
        self.build_request(&envelope)?;
        Ok(PreparedBatch {
            envelope: serde_json::to_vec(&envelope).map_err(|_| ConnectorFault::InvalidInput)?,
            key,
        })
    }

    fn send(&self, prepared: &PreparedBatch) -> Result<SendOutcome, ConnectorFault> {
        self.recover(prepared)
    }

    fn recover(&self, prepared: &PreparedBatch) -> Result<SendOutcome, ConnectorFault> {
        let envelope: BatchEnvelope =
            serde_json::from_slice(&prepared.envelope).map_err(|_| ConnectorFault::NotPrepared)?;
        if envelope.version != 1 || envelope.operation != OPERATION {
            return Err(ConnectorFault::NotPrepared);
        }
        let request = self.build_request(&envelope)?;
        let key =
            BRegIdempotencyKey::parse(&envelope.key).map_err(|_| ConnectorFault::NotPrepared)?;
        let answer = self.connector.block(self.connector.client().batch_records(
            self.connector.batch_binding()?,
            &request,
            &key,
        ));
        match answer {
            Ok(receipt) => Ok(completed(receipt.value.snapshot().to_owned())),
            Err(error) => classify(&error),
        }
    }
}
