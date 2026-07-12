// SPDX-License-Identifier: Apache-2.0
//! Atomic publication state for separately audited materialized snapshots.

use std::fmt;
use std::time::Duration;

use registry_platform_audit::{
    AuditEnvelope, DurableAuditPhase, DurableAuditStoredIdentity, DurableAuditStreamKind,
    DurableAuditWrite,
};
use serde_json::Value;
use thiserror::Error;
use tokio::time::Instant;
use tokio_postgres::{Error as PostgresError, Row};

use super::audit::PostgresDurableAuditStatePlane;
use super::migration::{validate_runtime_capability_v1, RuntimeCapabilityError};

const MAX_OPERATION_ELAPSED: Duration = Duration::from_secs(5);
const MAX_HEAD_CAS_ATTEMPTS: usize = 8;
const MAX_RECORD_JSON_BYTES: usize = 1_048_576;
const MAX_ENVELOPE_JSON_BYTES: usize = 1_310_720;

const PUBLICATION_SNAPSHOT_SQL: &str =
    "SELECT * FROM relay_state_api.materialization_publication_snapshot_v1(\
        $1,$2,$3,$4,$5,$6,$7,$8\
    )";
const PUBLICATION_CAS_SQL: &str =
    "SELECT * FROM relay_state_api.materialization_publication_cas_v1(\
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17\
    )";
const ACTIVE_PUBLICATION_SQL: &str =
    "SELECT * FROM relay_state_api.materialization_active_publication_v1($1,$2)";

/// Stable private profile/provider binding identity.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaterializationPublicationBindingId(Box<str>);

impl MaterializationPublicationBindingId {
    pub(crate) fn parse(value: &str) -> Result<Self, MaterializationPublicationError> {
        let Some(digest) = value.strip_prefix("sha256:") else {
            return Err(MaterializationPublicationError::InvalidInput);
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(MaterializationPublicationError::InvalidInput);
        }
        Ok(Self(value.into()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MaterializationPublicationBindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaterializationPublicationBindingId(sha256:<redacted>)")
    }
}

/// Server-generated immutable snapshot generation.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaterializationGenerationId(Box<str>);

impl MaterializationGenerationId {
    pub(crate) fn parse(value: &str) -> Result<Self, MaterializationPublicationError> {
        let generation = ulid::Ulid::from_string(value)
            .map_err(|_| MaterializationPublicationError::InvalidInput)?;
        if generation.to_string() != value {
            return Err(MaterializationPublicationError::InvalidInput);
        }
        Ok(Self(value.into()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MaterializationGenerationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MaterializationGenerationId")
            .field(&self.0)
            .finish()
    }
}

/// Restricted digest over the complete immutable snapshot bytes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RestrictedMaterializationContentDigest([u8; 32]);

impl RestrictedMaterializationContentDigest {
    pub(crate) const fn from_sha256(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RestrictedMaterializationContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RestrictedMaterializationContentDigest(sha256:<redacted>)")
    }
}

/// Safe, bounded source revision retained with publication provenance.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaterializationSourceRevision(Box<str>);

impl MaterializationSourceRevision {
    pub(crate) fn parse(value: &str) -> Result<Self, MaterializationPublicationError> {
        let mut bytes = value.bytes();
        let valid = value.len() <= 256
            && matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'))
            && bytes.all(|byte| {
                matches!(
                    byte,
                    b'A'..=b'Z'
                        | b'a'..=b'z'
                        | b'0'..=b'9'
                        | b'.'
                        | b'_'
                        | b':'
                        | b'-'
                )
            });
        valid
            .then(|| Self(value.into()))
            .ok_or(MaterializationPublicationError::InvalidInput)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MaterializationSourceRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaterializationSourceRevision(<redacted>)")
    }
}

/// Exact immutable candidate that may be published after its completion audit.
pub(crate) struct MaterializationPublicationRequest {
    binding_id: MaterializationPublicationBindingId,
    generation_id: MaterializationGenerationId,
    content_digest: RestrictedMaterializationContentDigest,
    source_revision: Option<MaterializationSourceRevision>,
    source_observed_at_unix_ms: Option<i64>,
}

impl MaterializationPublicationRequest {
    pub(crate) fn new(
        binding_id: MaterializationPublicationBindingId,
        generation_id: MaterializationGenerationId,
        content_digest: RestrictedMaterializationContentDigest,
        source_revision: Option<MaterializationSourceRevision>,
        source_observed_at_unix_ms: Option<i64>,
    ) -> Result<Self, MaterializationPublicationError> {
        if source_observed_at_unix_ms
            .is_some_and(|value| !(0..=9_007_199_254_740_991).contains(&value))
        {
            return Err(MaterializationPublicationError::InvalidInput);
        }
        Ok(Self {
            binding_id,
            generation_id,
            content_digest,
            source_revision,
            source_observed_at_unix_ms,
        })
    }

    pub(crate) const fn binding_id(&self) -> &MaterializationPublicationBindingId {
        &self.binding_id
    }

    pub(crate) const fn generation_id(&self) -> &MaterializationGenerationId {
        &self.generation_id
    }
}

impl fmt::Debug for MaterializationPublicationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializationPublicationRequest")
            .field("binding_id", &self.binding_id)
            .field("generation_id", &self.generation_id)
            .field("content_digest", &self.content_digest)
            .field("source_revision", &self.source_revision)
            .field(
                "source_observed_at_unix_ms",
                &self.source_observed_at_unix_ms,
            )
            .finish()
    }
}

/// PostgreSQL-authoritative active publication and its completion identity.
#[derive(Clone)]
pub(crate) struct ActiveMaterializationPublication {
    binding_id: MaterializationPublicationBindingId,
    publication_sequence: i64,
    generation_id: MaterializationGenerationId,
    content_digest: RestrictedMaterializationContentDigest,
    source_revision: Option<MaterializationSourceRevision>,
    source_observed_at_unix_ms: Option<i64>,
    published_at_unix_ms: i64,
    completion_operation_id: Box<str>,
    completion: DurableAuditStoredIdentity,
}

impl ActiveMaterializationPublication {
    pub(crate) const fn binding_id(&self) -> &MaterializationPublicationBindingId {
        &self.binding_id
    }

    pub(crate) const fn publication_sequence(&self) -> i64 {
        self.publication_sequence
    }

    pub(crate) const fn generation_id(&self) -> &MaterializationGenerationId {
        &self.generation_id
    }

    pub(crate) const fn content_digest(&self) -> &RestrictedMaterializationContentDigest {
        &self.content_digest
    }

    pub(crate) const fn source_revision(&self) -> Option<&MaterializationSourceRevision> {
        self.source_revision.as_ref()
    }

    pub(crate) const fn source_observed_at_unix_ms(&self) -> Option<i64> {
        self.source_observed_at_unix_ms
    }

    pub(crate) const fn published_at_unix_ms(&self) -> i64 {
        self.published_at_unix_ms
    }

    pub(crate) fn completion_operation_id(&self) -> &str {
        &self.completion_operation_id
    }

    pub(crate) const fn completion(&self) -> &DurableAuditStoredIdentity {
        &self.completion
    }

    pub(crate) fn matches_candidate(&self, candidate: &MaterializationPublicationRequest) -> bool {
        self.binding_id == candidate.binding_id
            && self.generation_id == candidate.generation_id
            && self.content_digest == candidate.content_digest
            && self.source_revision == candidate.source_revision
            && self.source_observed_at_unix_ms == candidate.source_observed_at_unix_ms
    }
}

impl fmt::Debug for ActiveMaterializationPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveMaterializationPublication")
            .field("binding_id", &self.binding_id)
            .field("publication_sequence", &self.publication_sequence)
            .field("generation_id", &self.generation_id)
            .field("content_digest", &self.content_digest)
            .field("source_revision", &self.source_revision)
            .field(
                "source_observed_at_unix_ms",
                &self.source_observed_at_unix_ms,
            )
            .field("published_at_unix_ms", &self.published_at_unix_ms)
            .field("completion_operation_id", &self.completion_operation_id)
            .field("completion", &self.completion)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum MaterializationPublicationOutcome {
    Inserted(ActiveMaterializationPublication),
    IdenticalDuplicate(ActiveMaterializationPublication),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum MaterializationPublicationError {
    #[error("materialization publication input is invalid")]
    InvalidInput,
    #[error("materialization completion audit is invalid")]
    InvalidCompletion,
    #[error("materialization publication replay conflicts with durable state")]
    ConflictingReplay,
    #[error("materialization snapshot generation was already used")]
    GenerationReused,
    #[error("materialization snapshot rollback was rejected")]
    RollbackRejected,
    #[error("materialization publication capability has drifted")]
    CapabilityDrift,
    #[error("materialization publication state is unavailable")]
    Unavailable,
}

impl PostgresDurableAuditStatePlane {
    /// Atomically write one materialization completion and advance its active pointer.
    pub(crate) async fn publish_materialization(
        &self,
        completion: &DurableAuditWrite,
        request: &MaterializationPublicationRequest,
    ) -> Result<MaterializationPublicationOutcome, MaterializationPublicationError> {
        if completion.key().stream_kind() != DurableAuditStreamKind::Materialization
            || completion.key().phase() != DurableAuditPhase::Completion
        {
            return Err(MaterializationPublicationError::InvalidCompletion);
        }
        let deadline = Instant::now() + MAX_OPERATION_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| MaterializationPublicationError::Unavailable)?;
        validate_runtime(deadline, &client, &self.chain_key_epoch_id).await?;

        for _ in 0..MAX_HEAD_CAS_ATTEMPTS {
            let snapshot = timeout_query(
                deadline,
                client.query_one(
                    PUBLICATION_SNAPSHOT_SQL,
                    &[
                        &completion.key().operation_id().as_str(),
                        &completion.payload_digest().as_bytes().as_slice(),
                        &request.binding_id.as_str(),
                        &request.generation_id.as_str(),
                        &request.content_digest.as_bytes().as_slice(),
                        &request
                            .source_revision
                            .as_ref()
                            .map(MaterializationSourceRevision::as_str),
                        &request.source_observed_at_unix_ms,
                        &self.chain_key_epoch_id.as_str(),
                    ],
                ),
            )
            .await?;
            match required_str(&snapshot, "outcome")? {
                "identical_duplicate" => {
                    return Ok(MaterializationPublicationOutcome::IdenticalDuplicate(
                        publication_from_snapshot_row(
                            request.binding_id.clone(),
                            completion.key().operation_id().as_str(),
                            &snapshot,
                        )?,
                    ));
                }
                "conflicting_duplicate" => {
                    return Err(MaterializationPublicationError::ConflictingReplay);
                }
                "generation_reused" => {
                    return Err(MaterializationPublicationError::GenerationReused);
                }
                "rollback_rejected" => {
                    return Err(MaterializationPublicationError::RollbackRejected);
                }
                "candidate" => {}
                _ => return Err(MaterializationPublicationError::CapabilityDrift),
            }

            let predecessor = optional_hash(&snapshot, "candidate_predecessor_hash")?;
            let candidate_generation = required_i64(&snapshot, "candidate_generation")?;
            ensure_before_deadline(deadline)?;
            let envelope = completion
                .build_envelope_at_chain_head(predecessor, &self.chain_hasher)
                .map_err(|_| MaterializationPublicationError::InvalidCompletion)?;
            let (attempt_envelope_id, attempt_record_hash) = completion_attempt(&envelope)?;
            let record_json = serde_json::to_string(&envelope.record)
                .map_err(|_| MaterializationPublicationError::InvalidCompletion)?;
            let envelope_json = serde_json::to_string(&envelope)
                .map_err(|_| MaterializationPublicationError::InvalidCompletion)?;
            if record_json.len() > MAX_RECORD_JSON_BYTES
                || envelope_json.len() > MAX_ENVELOPE_JSON_BYTES
            {
                return Err(MaterializationPublicationError::InvalidCompletion);
            }
            ensure_before_deadline(deadline)?;
            let cas = timeout_query(
                deadline,
                client.query_one(
                    PUBLICATION_CAS_SQL,
                    &[
                        &completion.key().operation_id().as_str(),
                        &completion.payload_digest().as_bytes().as_slice(),
                        &request.binding_id.as_str(),
                        &request.generation_id.as_str(),
                        &request.content_digest.as_bytes().as_slice(),
                        &request
                            .source_revision
                            .as_ref()
                            .map(MaterializationSourceRevision::as_str),
                        &request.source_observed_at_unix_ms,
                        &candidate_generation,
                        &predecessor.as_ref().map(<[u8; 32]>::as_slice),
                        &envelope.envelope_id,
                        &envelope.timestamp_unix_ms,
                        &record_json,
                        &envelope_json,
                        &envelope.record_hash.as_slice(),
                        &attempt_envelope_id,
                        &attempt_record_hash.as_slice(),
                        &self.chain_key_epoch_id.as_str(),
                    ],
                ),
            )
            .await?;
            match required_str(&cas, "outcome")? {
                "inserted" => {
                    let publication = publication_from_cas_row(
                        request.binding_id.clone(),
                        completion.key().operation_id().as_str(),
                        &cas,
                    )?;
                    if publication.completion.envelope_id() != envelope.envelope_id
                        || publication.completion.record_hash() != &envelope.record_hash
                    {
                        return Err(MaterializationPublicationError::CapabilityDrift);
                    }
                    return Ok(MaterializationPublicationOutcome::Inserted(publication));
                }
                "identical_duplicate" => {
                    return Ok(MaterializationPublicationOutcome::IdenticalDuplicate(
                        publication_from_cas_row(
                            request.binding_id.clone(),
                            completion.key().operation_id().as_str(),
                            &cas,
                        )?,
                    ));
                }
                "conflicting_duplicate" => {
                    return Err(MaterializationPublicationError::ConflictingReplay);
                }
                "generation_reused" => {
                    return Err(MaterializationPublicationError::GenerationReused);
                }
                "rollback_rejected" => {
                    return Err(MaterializationPublicationError::RollbackRejected);
                }
                "head_changed" => continue,
                _ => return Err(MaterializationPublicationError::CapabilityDrift),
            }
        }
        Err(MaterializationPublicationError::Unavailable)
    }

    /// Read the PostgreSQL-authoritative active pointer for restart reconciliation.
    pub(crate) async fn active_materialization(
        &self,
        binding_id: &MaterializationPublicationBindingId,
    ) -> Result<Option<ActiveMaterializationPublication>, MaterializationPublicationError> {
        let deadline = Instant::now() + MAX_OPERATION_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| MaterializationPublicationError::Unavailable)?;
        validate_runtime(deadline, &client, &self.chain_key_epoch_id).await?;
        let row = tokio::time::timeout_at(
            deadline,
            client.query_opt(
                ACTIVE_PUBLICATION_SQL,
                &[&binding_id.as_str(), &self.chain_key_epoch_id.as_str()],
            ),
        )
        .await
        .map_err(|_| MaterializationPublicationError::Unavailable)?
        .map_err(map_postgres_error)?;
        row.map(|row| publication_from_active_row(binding_id.clone(), &row))
            .transpose()
    }

    /// Reconcile one immutable candidate against the exact active publication.
    pub(crate) async fn reconcile_materialization(
        &self,
        candidate: &MaterializationPublicationRequest,
    ) -> Result<ActiveMaterializationPublication, MaterializationPublicationError> {
        self.active_materialization(candidate.binding_id())
            .await?
            .filter(|active| active.matches_candidate(candidate))
            .ok_or(MaterializationPublicationError::ConflictingReplay)
    }
}

async fn validate_runtime(
    deadline: Instant,
    client: &tokio_postgres::Client,
    chain_key_epoch_id: &super::AuditChainKeyEpochId,
) -> Result<(), MaterializationPublicationError> {
    tokio::time::timeout_at(
        deadline,
        validate_runtime_capability_v1(client, chain_key_epoch_id),
    )
    .await
    .map_err(|_| MaterializationPublicationError::Unavailable)?
    .map_err(|error| match error {
        RuntimeCapabilityError::Drift | RuntimeCapabilityError::WrongRuntimeIdentity => {
            MaterializationPublicationError::CapabilityDrift
        }
        RuntimeCapabilityError::Unavailable => MaterializationPublicationError::Unavailable,
    })
}

fn completion_attempt(
    envelope: &AuditEnvelope,
) -> Result<(String, [u8; 32]), MaterializationPublicationError> {
    let attempt = envelope
        .record
        .get("payload")
        .and_then(|payload| payload.get("attempt_event"))
        .and_then(Value::as_object)
        .ok_or(MaterializationPublicationError::InvalidCompletion)?;
    let envelope_id = attempt
        .get("envelope_id")
        .and_then(Value::as_str)
        .ok_or(MaterializationPublicationError::InvalidCompletion)?;
    let parsed = ulid::Ulid::from_string(envelope_id)
        .map_err(|_| MaterializationPublicationError::InvalidCompletion)?;
    if parsed.to_string() != envelope_id {
        return Err(MaterializationPublicationError::InvalidCompletion);
    }
    let chain_hash = attempt
        .get("chain_hash")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("registry-audit-chain-v1:"))
        .ok_or(MaterializationPublicationError::InvalidCompletion)
        .and_then(decode_hash)?;
    Ok((envelope_id.to_owned(), chain_hash))
}

fn publication_from_snapshot_row(
    binding_id: MaterializationPublicationBindingId,
    completion_operation_id: &str,
    row: &Row,
) -> Result<ActiveMaterializationPublication, MaterializationPublicationError> {
    publication_from_row(binding_id, completion_operation_id, row, "stored_")
}

fn publication_from_cas_row(
    binding_id: MaterializationPublicationBindingId,
    completion_operation_id: &str,
    row: &Row,
) -> Result<ActiveMaterializationPublication, MaterializationPublicationError> {
    publication_from_row(binding_id, completion_operation_id, row, "stored_")
}

fn publication_from_active_row(
    binding_id: MaterializationPublicationBindingId,
    row: &Row,
) -> Result<ActiveMaterializationPublication, MaterializationPublicationError> {
    let completion_operation_id = required_str(row, "completion_operation_id")?.into();
    build_publication(
        binding_id,
        required_i64(row, "publication_sequence")?,
        required_str(row, "generation_id")?,
        required_hash(row, "content_digest")?,
        optional_str(row, "source_revision")?,
        optional_i64(row, "source_observed_at_unix_ms")?,
        required_i64(row, "published_at_unix_ms")?,
        completion_operation_id,
        required_str(row, "completion_envelope_id")?,
        required_hash(row, "completion_record_hash")?,
    )
}

fn publication_from_row(
    binding_id: MaterializationPublicationBindingId,
    completion_operation_id: &str,
    row: &Row,
    prefix: &str,
) -> Result<ActiveMaterializationPublication, MaterializationPublicationError> {
    let sequence = format!("{prefix}publication_sequence");
    let generation = format!("{prefix}generation_id");
    let digest = format!("{prefix}content_digest");
    let revision = format!("{prefix}source_revision");
    let observed = format!("{prefix}source_observed_at_unix_ms");
    let published = format!("{prefix}published_at_unix_ms");
    let envelope = format!("{prefix}envelope_id");
    let hash = format!("{prefix}chain_hash");
    let completion_operation_id = completion_operation_id.to_owned().into_boxed_str();
    build_publication(
        binding_id,
        required_i64(row, &sequence)?,
        required_str(row, &generation)?,
        required_hash(row, &digest)?,
        optional_str(row, &revision)?,
        optional_i64(row, &observed)?,
        required_i64(row, &published)?,
        completion_operation_id,
        required_str(row, &envelope)?,
        required_hash(row, &hash)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_publication(
    binding_id: MaterializationPublicationBindingId,
    publication_sequence: i64,
    generation_id: &str,
    content_digest: [u8; 32],
    source_revision: Option<&str>,
    source_observed_at_unix_ms: Option<i64>,
    published_at_unix_ms: i64,
    completion_operation_id: Box<str>,
    completion_envelope_id: &str,
    completion_record_hash: [u8; 32],
) -> Result<ActiveMaterializationPublication, MaterializationPublicationError> {
    if !(1..=9_007_199_254_740_991).contains(&publication_sequence)
        || !(0..=9_007_199_254_740_991).contains(&published_at_unix_ms)
        || source_observed_at_unix_ms
            .is_some_and(|observed| !(0..=published_at_unix_ms).contains(&observed))
    {
        return Err(MaterializationPublicationError::CapabilityDrift);
    }
    let generation_id = MaterializationGenerationId::parse(generation_id)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)?;
    let completion_operation = ulid::Ulid::from_string(&completion_operation_id)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)?;
    if completion_operation.to_string() != completion_operation_id.as_ref() {
        return Err(MaterializationPublicationError::CapabilityDrift);
    }
    let source_revision = source_revision
        .map(MaterializationSourceRevision::parse)
        .transpose()
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)?;
    let envelope = AuditEnvelope {
        envelope_id: completion_envelope_id.to_owned(),
        timestamp_unix_ms: 0,
        prev_hash: None,
        record: Value::Null,
        record_hash: completion_record_hash,
    };
    let completion = DurableAuditStoredIdentity::from_envelope(&envelope)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)?;
    Ok(ActiveMaterializationPublication {
        binding_id,
        publication_sequence,
        generation_id,
        content_digest: RestrictedMaterializationContentDigest::from_sha256(content_digest),
        source_revision,
        source_observed_at_unix_ms,
        published_at_unix_ms,
        completion_operation_id,
        completion,
    })
}

async fn timeout_query<F>(
    deadline: Instant,
    future: F,
) -> Result<Row, MaterializationPublicationError>
where
    F: std::future::Future<Output = Result<Row, PostgresError>>,
{
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| MaterializationPublicationError::Unavailable)?
        .map_err(map_postgres_error)
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), MaterializationPublicationError> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(MaterializationPublicationError::Unavailable)
    }
}

fn map_postgres_error(error: PostgresError) -> MaterializationPublicationError {
    let Some(database) = error.as_db_error() else {
        return MaterializationPublicationError::Unavailable;
    };
    match database.code().code() {
        "22023" => MaterializationPublicationError::InvalidInput,
        "42501" | "55000" => MaterializationPublicationError::CapabilityDrift,
        code if code.starts_with("08")
            || code.starts_with("25")
            || code.starts_with("40")
            || code.starts_with("53")
            || code.starts_with("57")
            || code.starts_with("58") =>
        {
            MaterializationPublicationError::Unavailable
        }
        _ => MaterializationPublicationError::CapabilityDrift,
    }
}

fn required_str<'a>(
    row: &'a Row,
    column: &str,
) -> Result<&'a str, MaterializationPublicationError> {
    row.try_get(column)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)
}

fn optional_str<'a>(
    row: &'a Row,
    column: &str,
) -> Result<Option<&'a str>, MaterializationPublicationError> {
    row.try_get(column)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)
}

fn required_i64(row: &Row, column: &str) -> Result<i64, MaterializationPublicationError> {
    row.try_get(column)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)
}

fn optional_i64(row: &Row, column: &str) -> Result<Option<i64>, MaterializationPublicationError> {
    row.try_get(column)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)
}

fn required_hash(row: &Row, column: &str) -> Result<[u8; 32], MaterializationPublicationError> {
    row.try_get::<_, &[u8]>(column)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)?
        .try_into()
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)
}

fn optional_hash(
    row: &Row,
    column: &str,
) -> Result<Option<[u8; 32]>, MaterializationPublicationError> {
    row.try_get::<_, Option<&[u8]>>(column)
        .map_err(|_| MaterializationPublicationError::CapabilityDrift)?
        .map(|value| {
            value
                .try_into()
                .map_err(|_| MaterializationPublicationError::CapabilityDrift)
        })
        .transpose()
}

fn decode_hash(value: &str) -> Result<[u8; 32], MaterializationPublicationError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MaterializationPublicationError::InvalidCompletion);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = decode_nibble(pair[0])
            .and_then(|high| decode_nibble(pair[1]).map(|low| (high << 4) | low))
            .ok_or(MaterializationPublicationError::InvalidCompletion)?;
    }
    Ok(output)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_publication_inputs_are_strict_and_redacted() {
        let binding =
            MaterializationPublicationBindingId::parse(&format!("sha256:{}", "a".repeat(64)))
                .expect("binding");
        let generation =
            MaterializationGenerationId::parse("01J2D9W2G00000000000000000").expect("generation");
        let revision = MaterializationSourceRevision::parse("rev.2026-07:1").expect("revision");
        let request = MaterializationPublicationRequest::new(
            binding,
            generation,
            RestrictedMaterializationContentDigest::from_sha256([0xab; 32]),
            Some(revision),
            Some(1_720_612_800_000),
        )
        .expect("request");
        let diagnostic = format!("{request:?}");
        assert!(!diagnostic.contains(&"a".repeat(64)));
        assert!(!diagnostic.contains("abababab"));
        assert!(!diagnostic.contains("rev.2026-07:1"));
    }

    #[test]
    fn aliases_and_unsafe_revisions_fail_closed() {
        assert!(
            MaterializationPublicationBindingId::parse(&format!("SHA256:{}", "a".repeat(64)))
                .is_err()
        );
        assert!(MaterializationGenerationId::parse("01j2d9w2g00000000000000000").is_err());
        for revision in ["", " revision", "revision/1", "revision\n1"] {
            assert!(MaterializationSourceRevision::parse(revision).is_err());
        }
    }
}
