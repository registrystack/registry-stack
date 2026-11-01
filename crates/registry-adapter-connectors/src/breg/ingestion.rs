// SPDX-License-Identifier: Apache-2.0
//! The BReg ingestion run family: `breg.ingestion.create-run` and
//! `breg.ingestion.submit-chunk`, the finite protocol one bulk import
//! follows, with the input digest, counts, and checkpoints surfaced.
//!
//! The family writes through the destination's operator-opened import
//! authority. The connector records the host's decision in
//! `BregConnectorConfig::allow_import_profile` (default off): with the
//! authority closed, both operations stay out of the catalog and
//! `prepare` answers [`ConnectorFault::AuthorityAbsent`].
//!
//! * Create run announces one whole input and opens a durable run. The
//!   destination takes no idempotency key here and allocates a fresh run
//!   id for every accepted request, so the descriptor's rule is
//!   read-then-decide: recovery lists the caller's open runs under the
//!   announced input digest and settles on what the destination proves;
//!   only when no run exists does recovery announce again, under the same
//!   ledger key and never under a destination key.
//! * Submit chunk is unkeyed and replay-safe by the destination's own
//!   protocol: a resubmitted chunk replays its retained receipt, which
//!   the outcome note names. Recovery resends the identical chunk.
//!
//! Closed input shapes: `breg.ingestion.create-run/v1` is
//! `{"profile": "...", "operation": "create" | "patch", "packageRevision":
//! "<sha256:...>", "schemaFingerprint": "<sha256:...>", "inputDigest":
//! "<64 hex>", "inputLength": <n>, "itemCount": <n>, "chunkCount": <n>}`;
//! `breg.ingestion.submit-chunk/v1` is `{"run": "<uuid>", "profile":
//! "...", "chunkIndex": <n>, "prefixDigest": "<64 hex>", "items": [
//! ...closed create-or-patch batch items... ]}`.

use std::sync::{Arc, LazyLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use registry_breg_client::{
    BRegBatchOperation, BRegIngestionChunk, BRegIngestionRun, BRegIngestionRunListQuery,
    BRegIngestionRunRequest, BRegIngestionRunStatus, BREG_INGESTION_CHUNK_ALGORITHM_VERSION,
};

use crate::operation::{
    BodyKind, CommandKey, ConnectorFault, CredentialRequirements, IdempotencyRule, InputSchema,
    MutationBehavior, NativeState, Observable, Operation, OperationDescriptor, OutcomeCategory,
    PreparedAttempt, Product, RecoveryRule, SendOutcome,
};

use super::{accepted, classify, completed, fault};

/// Announcing one whole input opens the durable run.
pub static CREATE_RUN: LazyLock<OperationDescriptor> = LazyLock::new(|| OperationDescriptor {
    name: "breg.ingestion.create-run",
    product: Product::Breg,
    input_schema: InputSchema::ConnectorDefined {
        shape: "breg.ingestion.create-run/v1".to_owned(),
    },
    body_kind: BodyKind::Json,
    mutation: MutationBehavior::Unconditional,
    credentials: CredentialRequirements {
        credential_kinds: vec!["private-key-jwt".to_owned()],
        requires_task_grant: false,
        requires_operator_authority: true,
    },
    // The destination takes no key for the announcement and never replays
    // one; recovery reads the caller's runs under the input digest.
    idempotency: IdempotencyRule::ReadBeforeRetry,
    recovery: RecoveryRule::ReadThenDecide,
    completion: "the destination opened the announced run and answered with its run id",
    observable: true,
});

/// One chunk of an open run commits atomically with the checkpoint
/// advance; a resubmission replays its retained receipt.
pub static SUBMIT_CHUNK: LazyLock<OperationDescriptor> = LazyLock::new(|| OperationDescriptor {
    name: "breg.ingestion.submit-chunk",
    product: Product::Breg,
    input_schema: InputSchema::ConnectorDefined {
        shape: "breg.ingestion.submit-chunk/v1".to_owned(),
    },
    body_kind: BodyKind::Json,
    mutation: MutationBehavior::Unconditional,
    credentials: CredentialRequirements {
        credential_kinds: vec!["private-key-jwt".to_owned()],
        requires_task_grant: false,
        requires_operator_authority: true,
    },
    idempotency: IdempotencyRule::DestinationReplay,
    recovery: RecoveryRule::IdempotentResend,
    completion: "the destination committed the chunk once and answered with its retained receipt",
    observable: true,
});

const CREATE_RUN_OPERATION: &str = "breg.ingestion.create-run";
const SUBMIT_CHUNK_OPERATION: &str = "breg.ingestion.submit-chunk";

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Serialize, Deserialize)]
struct CreateRunEnvelope {
    version: u8,
    operation: String,
    key: String,
    profile: String,
    operation_kind: String,
    package_revision: String,
    schema_fingerprint: String,
    input_digest: String,
    input_length: u64,
    item_count: u64,
    chunk_count: u64,
}

/// The exact, persistable run announcement.
pub struct PreparedCreateRun {
    envelope: Vec<u8>,
    key: CommandKey,
}

impl PreparedCreateRun {
    /// Restore the stored bytes of one announcement. The key is the
    /// runner's ledger key; the destination request carries none.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let envelope: CreateRunEnvelope =
            serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
        if envelope.version != 1 || envelope.operation != CREATE_RUN_OPERATION {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(Self {
            envelope: bytes.to_vec(),
            key: CommandKey::new(envelope.key).map_err(|_| ConnectorFault::NotPrepared)?,
        })
    }
}

impl std::fmt::Debug for PreparedCreateRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedCreateRun(<redacted>)")
    }
}

impl std::fmt::Debug for PreparedSubmitChunk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedSubmitChunk(<redacted>)")
    }
}

impl PreparedAttempt for PreparedCreateRun {
    fn as_bytes(&self) -> &[u8] {
        &self.envelope
    }

    fn operation(&self) -> &'static str {
        CREATE_RUN_OPERATION
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

#[derive(Serialize, Deserialize)]
struct SubmitChunkEnvelope {
    version: u8,
    operation: String,
    key: String,
    run: String,
    profile: String,
    chunk_index: u64,
    prefix_digest: String,
    items: Vec<Value>,
}

/// The exact, persistable chunk attempt.
pub struct PreparedSubmitChunk {
    envelope: Vec<u8>,
    key: CommandKey,
}

impl PreparedSubmitChunk {
    /// Restore the stored bytes of one chunk attempt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let envelope: SubmitChunkEnvelope =
            serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
        if envelope.version != 1 || envelope.operation != SUBMIT_CHUNK_OPERATION {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(Self {
            envelope: bytes.to_vec(),
            key: CommandKey::new(envelope.key).map_err(|_| ConnectorFault::NotPrepared)?,
        })
    }
}

impl PreparedAttempt for PreparedSubmitChunk {
    fn as_bytes(&self) -> &[u8] {
        &self.envelope
    }

    fn operation(&self) -> &'static str {
        SUBMIT_CHUNK_OPERATION
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

fn build_run_request(
    envelope: &CreateRunEnvelope,
) -> Result<BRegIngestionRunRequest, ConnectorFault> {
    BRegIngestionRunRequest::builder()
        .operation(operation_kind(envelope)?)
        .profile(envelope.profile.clone())
        .map_err(|_| ConnectorFault::InvalidInput)?
        .package_revision(envelope.package_revision.clone())
        .map_err(|_| ConnectorFault::InvalidInput)?
        .schema_fingerprint(envelope.schema_fingerprint.clone())
        .map_err(|_| ConnectorFault::InvalidInput)?
        .input_digest(envelope.input_digest.clone())
        .map_err(|_| ConnectorFault::InvalidInput)?
        .input_length(envelope.input_length)
        .item_count(envelope.item_count)
        .map_err(|_| ConnectorFault::InvalidInput)?
        .chunk_count(envelope.chunk_count)
        .map_err(|_| ConnectorFault::InvalidInput)?
        .chunk_algorithm_version(BREG_INGESTION_CHUNK_ALGORITHM_VERSION)
        .map_err(|_| ConnectorFault::InvalidInput)?
        .build()
        .map_err(|_| ConnectorFault::InvalidInput)
}

fn operation_kind(envelope: &CreateRunEnvelope) -> Result<BRegBatchOperation, ConnectorFault> {
    match envelope.operation_kind.as_str() {
        "create" => Ok(BRegBatchOperation::Create),
        "patch" => Ok(BRegBatchOperation::Patch),
        _ => Err(ConnectorFault::InvalidInput),
    }
}

/// Whether a listed run is the one this envelope announces: every member
/// the announcement states, not the input digest alone.
fn announces(
    run: &BRegIngestionRun,
    envelope: &CreateRunEnvelope,
    operation: BRegBatchOperation,
) -> bool {
    run.operation() == operation
        && run.profile_id() == envelope.profile
        && run.package_revision() == envelope.package_revision
        && run.schema_fingerprint() == envelope.schema_fingerprint
        && run.input_digest() == envelope.input_digest
        && run.input_length() == envelope.input_length
        && run.item_count() == envelope.item_count
        && run.chunk_count() == envelope.chunk_count
        && run.chunk_algorithm_version() == BREG_INGESTION_CHUNK_ALGORITHM_VERSION
}

fn require_opened(connector: &super::BregConnector) -> Result<(), ConnectorFault> {
    if connector.import_opened {
        Ok(())
    } else {
        Err(ConnectorFault::AuthorityAbsent)
    }
}

fn parse_digest(input: &Value, member: &str) -> Result<String, ConnectorFault> {
    let value = input
        .get(member)
        .and_then(Value::as_str)
        .ok_or(ConnectorFault::InvalidInput)?;
    if is_sha256_hex(value) {
        Ok(value.to_owned())
    } else {
        Err(ConnectorFault::InvalidInput)
    }
}

fn parse_count(input: &Value, member: &str) -> Result<u64, ConnectorFault> {
    let value = input.get(member).and_then(Value::as_u64);
    match value {
        Some(0) | None => Err(ConnectorFault::InvalidInput),
        Some(count) => Ok(count),
    }
}

/// The run announcement over one connected connector.
pub struct IngestionCreateRun {
    pub(crate) connector: Arc<super::BregConnector>,
}

impl IngestionCreateRun {
    fn unseal(&self, prepared: &PreparedCreateRun) -> Result<CreateRunEnvelope, ConnectorFault> {
        let envelope: CreateRunEnvelope =
            serde_json::from_slice(&prepared.envelope).map_err(|_| ConnectorFault::NotPrepared)?;
        if envelope.version != 1 || envelope.operation != CREATE_RUN_OPERATION {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(envelope)
    }

    fn announce(&self, envelope: &CreateRunEnvelope) -> Result<SendOutcome, ConnectorFault> {
        let request = build_run_request(envelope)?;
        let answer = self.connector.block(
            self.connector
                .client()
                .create_ingestion_run(self.connector.route(), &request),
        );
        match answer {
            Ok(run) => Ok(accepted(correlation(
                &run.value.run_id().to_string(),
                &envelope.profile,
            ))),
            Err(error) => classify(&error),
        }
    }
}

/// The family's correlation: `<run-id>/<profile>`, the identity a run
/// observation reads through.
fn correlation(run: &str, profile: &str) -> String {
    format!("{run}/{profile}")
}

fn split_correlation(correlation: &str) -> Result<(Uuid, &str), ConnectorFault> {
    let (run, profile) = correlation
        .split_once('/')
        .ok_or(ConnectorFault::InvalidInput)?;
    let run = Uuid::parse_str(run).map_err(|_| ConnectorFault::InvalidInput)?;
    Ok((run, profile))
}

impl Observable for IngestionCreateRun {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        observe_run(&self.connector, correlation)
    }
}

impl Operation for IngestionCreateRun {
    type Prepared = PreparedCreateRun;

    fn describe(&self) -> &OperationDescriptor {
        &CREATE_RUN
    }

    fn prepare(&self, input: &Value, key: CommandKey) -> Result<PreparedCreateRun, ConnectorFault> {
        require_opened(&self.connector)?;
        let member = |name: &str| -> Result<&str, ConnectorFault> {
            input
                .get(name)
                .and_then(Value::as_str)
                .ok_or(ConnectorFault::InvalidInput)
        };
        let envelope = CreateRunEnvelope {
            version: 1,
            operation: CREATE_RUN_OPERATION.to_owned(),
            key: key.as_str().to_owned(),
            profile: member("profile")?.to_owned(),
            operation_kind: member("operation")?.to_owned(),
            package_revision: member("packageRevision")?.to_owned(),
            schema_fingerprint: member("schemaFingerprint")?.to_owned(),
            input_digest: parse_digest(input, "inputDigest")?,
            input_length: parse_count(input, "inputLength")?,
            item_count: parse_count(input, "itemCount")?,
            chunk_count: parse_count(input, "chunkCount")?,
        };
        // Build once here so shape faults answer at prepare, with no I/O.
        build_run_request(&envelope)?;
        Ok(PreparedCreateRun {
            envelope: serde_json::to_vec(&envelope).map_err(|_| ConnectorFault::InvalidInput)?,
            key,
        })
    }

    fn send(&self, prepared: &PreparedCreateRun) -> Result<SendOutcome, ConnectorFault> {
        let envelope = self.unseal(prepared)?;
        self.announce(&envelope)
    }

    fn recover(&self, prepared: &PreparedCreateRun) -> Result<SendOutcome, ConnectorFault> {
        let envelope = self.unseal(prepared)?;
        let operation = operation_kind(&envelope).map_err(|_| ConnectorFault::NotPrepared)?;
        // Read what the destination proves: the caller's open runs under
        // the announced input digest. Only a run whose announcement matches
        // this envelope in every member is the outcome; a run another
        // announcement opened over the same input is not. No match announces
        // again, under the same ledger key and no destination key. More than
        // one match cannot be settled from here and stays uncertain.
        let query = BRegIngestionRunListQuery::default()
            .access_profile(envelope.profile.clone())
            .map_err(|_| ConnectorFault::NotPrepared)?
            .status(BRegIngestionRunStatus::Open)
            .input_digest(envelope.input_digest.clone())
            .map_err(|_| ConnectorFault::NotPrepared)?;
        let listed = self.connector.block(
            self.connector
                .client()
                .list_ingestion_runs(self.connector.route(), &query),
        );
        let page = match listed {
            Ok(page) => page,
            Err(error) => return classify(&error),
        };
        let mut matching = page
            .value
            .runs()
            .iter()
            .filter(|run| announces(run, &envelope, operation));
        match (matching.next(), matching.next()) {
            (Some(run), None) => Ok(accepted(correlation(
                &run.run_id().to_string(),
                &envelope.profile,
            ))),
            (None, _) => self.announce(&envelope),
            (Some(_), Some(_)) => Ok(SendOutcome {
                category: OutcomeCategory::Uncertain,
                native_problem: None,
                correlation: None,
                note: Some(
                    "more than one open ingestion run matches the announcement; settle it by reading the runs",
                ),
            }),
        }
    }
}

/// The chunk submission over one connected connector.
pub struct IngestionSubmitChunk {
    pub(crate) connector: Arc<super::BregConnector>,
}

impl IngestionSubmitChunk {
    fn unseal(
        &self,
        prepared: &PreparedSubmitChunk,
    ) -> Result<SubmitChunkEnvelope, ConnectorFault> {
        let envelope: SubmitChunkEnvelope =
            serde_json::from_slice(&prepared.envelope).map_err(|_| ConnectorFault::NotPrepared)?;
        if envelope.version != 1 || envelope.operation != SUBMIT_CHUNK_OPERATION {
            return Err(ConnectorFault::NotPrepared);
        }
        Ok(envelope)
    }

    fn submit(&self, envelope: &SubmitChunkEnvelope) -> Result<SendOutcome, ConnectorFault> {
        let run = Uuid::parse_str(&envelope.run).map_err(|_| ConnectorFault::NotPrepared)?;
        let chunk = BRegIngestionChunk::new(
            envelope.chunk_index,
            envelope.items.clone(),
            &envelope.prefix_digest,
        )
        .map_err(|_| ConnectorFault::NotPrepared)?;
        let answer = self
            .connector
            .block(self.connector.client().submit_ingestion_chunk(
                self.connector.route(),
                run,
                &chunk,
                &envelope.profile,
            ));
        match answer {
            Ok(submission) => {
                let receipt = submission.value.receipt();
                let mut outcome = completed(correlation(&envelope.run, &envelope.profile));
                if receipt.replayed() {
                    outcome.note =
                        Some("the destination replayed its retained receipt for this chunk");
                }
                Ok(outcome)
            }
            Err(error) => classify(&error),
        }
    }
}

impl Observable for IngestionSubmitChunk {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        observe_run(&self.connector, correlation)
    }
}

impl Operation for IngestionSubmitChunk {
    type Prepared = PreparedSubmitChunk;

    fn describe(&self) -> &OperationDescriptor {
        &SUBMIT_CHUNK
    }

    fn prepare(
        &self,
        input: &Value,
        key: CommandKey,
    ) -> Result<PreparedSubmitChunk, ConnectorFault> {
        require_opened(&self.connector)?;
        let run = input
            .get("run")
            .and_then(Value::as_str)
            .ok_or(ConnectorFault::InvalidInput)?;
        Uuid::parse_str(run).map_err(|_| ConnectorFault::InvalidInput)?;
        let profile = input
            .get("profile")
            .and_then(Value::as_str)
            .ok_or(ConnectorFault::InvalidInput)?;
        let chunk_index = input
            .get("chunkIndex")
            .and_then(Value::as_u64)
            .ok_or(ConnectorFault::InvalidInput)?;
        let prefix_digest = parse_digest(input, "prefixDigest")?;
        let items: Vec<Value> = serde_json::from_value(
            input
                .get("items")
                .cloned()
                .ok_or(ConnectorFault::InvalidInput)?,
        )
        .map_err(|_| ConnectorFault::InvalidInput)?;
        if items.is_empty() {
            return Err(ConnectorFault::InvalidInput);
        }
        // Encode once here so the closed item shape and the digest and
        // body bounds answer at prepare, with no I/O.
        BRegIngestionChunk::new(chunk_index, items.clone(), &prefix_digest)
            .map_err(|_| ConnectorFault::InvalidInput)?;
        let envelope = SubmitChunkEnvelope {
            version: 1,
            operation: SUBMIT_CHUNK_OPERATION.to_owned(),
            key: key.as_str().to_owned(),
            run: run.to_owned(),
            profile: profile.to_owned(),
            chunk_index,
            prefix_digest,
            items,
        };
        Ok(PreparedSubmitChunk {
            envelope: serde_json::to_vec(&envelope).map_err(|_| ConnectorFault::InvalidInput)?,
            key,
        })
    }

    fn send(&self, prepared: &PreparedSubmitChunk) -> Result<SendOutcome, ConnectorFault> {
        let envelope = self.unseal(prepared)?;
        self.submit(&envelope)
    }

    fn recover(&self, prepared: &PreparedSubmitChunk) -> Result<SendOutcome, ConnectorFault> {
        // The destination's own protocol replays a committed chunk, so the
        // identical resend is this operation's recovery.
        let envelope = self.unseal(prepared)?;
        self.submit(&envelope)
    }
}

/// Read one run's durable state as the family's native lifecycle: the
/// status word with the input digest, counts, and checkpoints the run
/// publishes.
fn observe_run(
    connector: &super::BregConnector,
    correlation: &str,
) -> Result<NativeState, ConnectorFault> {
    let (run, profile) = split_correlation(correlation)?;
    let answer = connector.block(connector.client().read_ingestion_run(
        connector.route(),
        run,
        Some(profile),
    ));
    match answer {
        Ok(read) => {
            let value = read.value;
            let mut details = vec![
                ("inputDigest".to_owned(), value.input_digest().to_owned()),
                ("itemCount".to_owned(), value.item_count().to_string()),
                ("chunkCount".to_owned(), value.chunk_count().to_string()),
                (
                    "nextChunkIndex".to_owned(),
                    value.next_chunk_index().to_string(),
                ),
                (
                    "committedItems".to_owned(),
                    value.committed_items().to_string(),
                ),
            ];
            if let Some(reason) = value.blocked_reason() {
                details.push(("blockedReason".to_owned(), reason.as_str().to_owned()));
            }
            Ok(NativeState {
                state: value.status().as_str().to_owned(),
                details,
            })
        }
        Err(error) => Err(fault(&error)),
    }
}
