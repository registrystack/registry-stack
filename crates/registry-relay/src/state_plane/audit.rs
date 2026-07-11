// SPDX-License-Identifier: Apache-2.0
//! Atomic PostgreSQL implementation of the governed durable-audit contract.
//!
//! The database runtime credential is part of Relay's trusted computing base.
//! SQL cross-validates the operation key, payload digest, envelope structure,
//! predecessor, and completion reference, but PostgreSQL does not possess the
//! external HMAC key and cannot authenticate a caller-supplied chain hash. It
//! also cannot semantically identify arbitrary secret-shaped JSON values.
//! Restricted credentials, audit-safe payload construction, and keyed chain
//! verification are all required. Tests prove that a structurally valid but
//! arbitrary direct hash is detectable by keyed verification.
//!
//! Relay arms `statement_timeout` on the runtime connection before issuing an
//! outer SQL statement. PostgreSQL cannot retroactively arm that statement
//! from inside a called function. The functions still own lock limits, persist
//! the idle-transaction limit and synchronous-commit requirement, and reject a
//! result that completes past their elapsed-time guard. A holder of the trusted
//! runtime credential must not clear the caller-side session limits.

use std::time::Duration;

use async_trait::async_trait;
use registry_platform_audit::{
    AuditChainHasher, AuditEnvelope, DurableAuditPhase, DurableAuditSink,
    DurableAuditStoredIdentity, DurableAuditStreamKind, DurableAuditWrite, DurableAuditWriteError,
    DurableAuditWriteOutcome,
};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::{sync::Mutex, time::Instant};
use tokio_postgres::{Client, Error as PostgresError, Row};

use super::migration::{
    validate_runtime_pseudonym_capability_v1, AuditChainKeyEpochId, AuditPseudonymKeyringLockKey,
    RuntimeCapabilityError, RUNTIME_SESSION_LIMITS_SQL,
};
use super::pseudonym_keyring::ActiveAuditPseudonymWriteEpoch;

const SNAPSHOT_AUDIT_PHASE_SQL: &str = "SELECT * FROM relay_state_api.audit_phase_snapshot_v1(\
        $1, $2, $3, $4, $5, $6, $7, $8, $9\
    )";
const RECOVER_AUDIT_PHASE_DUPLICATE_SQL: &str =
    "SELECT * FROM relay_state_api.audit_phase_duplicate_v1($1, $2, $3, $4, $5, $6)";
const CAS_AUDIT_PHASE_SQL: &str = "SELECT * FROM relay_state_api.audit_phase_cas_v1(\
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18\
)";
const MAX_HEAD_CAS_ATTEMPTS: usize = 8;
const MAX_WRITE_ELAPSED: Duration = Duration::from_secs(5);
const MAX_RECORD_JSON_BYTES: usize = 1_048_576;
const MAX_ENVELOPE_JSON_BYTES: usize = 1_310_720;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CompletionAttemptReference {
    envelope_id: String,
    chain_hash: [u8; 32],
}

impl CompletionAttemptReference {
    pub(crate) fn from_stored_attempt(attempt: &DurableAuditStoredIdentity) -> Self {
        Self {
            envelope_id: attempt.envelope_id().to_owned(),
            chain_hash: *attempt.record_hash(),
        }
    }

    pub(crate) fn to_safe_payload_value(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "chain_hash": format!(
                "registry-audit-chain-v1:{}",
                encode_hex(&self.chain_hash)
            ),
        })
    }
}

impl std::fmt::Debug for CompletionAttemptReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletionAttemptReference")
            .field("envelope_id", &self.envelope_id)
            .field("chain_hash", &"registry-audit-chain-v1:<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum StatePlaneInitializationError {
    #[error("Relay state plane requires a keyed production audit chain")]
    UnkeyedAuditChain,
    #[error("Relay state-plane runtime identity is not bound")]
    WrongRuntimeIdentity,
    #[error("Relay state-plane capability has drifted")]
    CapabilityDrift,
    #[error("Relay state plane is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatePlaneReadiness {
    Ready,
    Unavailable,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PseudonymBoundDuplicateRecoveryOutcome {
    IdenticalDuplicate(DurableAuditStoredIdentity),
    ConflictingDuplicate(DurableAuditStoredIdentity),
    NotFound,
}

/// Crate-private execute-only state plane. No public API can obtain the raw
/// runtime database client or construct this value without attestation.
pub(crate) struct PostgresDurableAuditStatePlane {
    client: Mutex<Client>,
    chain_hasher: AuditChainHasher,
    chain_key_epoch_id: AuditChainKeyEpochId,
    keyring_lock_key: AuditPseudonymKeyringLockKey,
}

impl PostgresDurableAuditStatePlane {
    pub(crate) async fn connect(
        client: Client,
        chain_hasher: AuditChainHasher,
        chain_key_epoch_id: AuditChainKeyEpochId,
        keyring_lock_key: AuditPseudonymKeyringLockKey,
    ) -> Result<Self, StatePlaneInitializationError> {
        if matches!(chain_hasher, AuditChainHasher::UnkeyedDevOnly) {
            return Err(StatePlaneInitializationError::UnkeyedAuditChain);
        }
        Self::validated(client, chain_hasher, chain_key_epoch_id, keyring_lock_key).await
    }

    async fn validated(
        client: Client,
        chain_hasher: AuditChainHasher,
        chain_key_epoch_id: AuditChainKeyEpochId,
        keyring_lock_key: AuditPseudonymKeyringLockKey,
    ) -> Result<Self, StatePlaneInitializationError> {
        // A supplied Client may already be inside either a live or failed
        // explicit transaction. Never let a durable-write acknowledgement be
        // scoped to transaction state owned by the caller.
        client
            .batch_execute("ROLLBACK")
            .await
            .map_err(|_| StatePlaneInitializationError::Unavailable)?;
        client
            .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
            .await
            .map_err(|_| StatePlaneInitializationError::Unavailable)?;
        validate_runtime_pseudonym_capability_v1(&client, &chain_key_epoch_id, keyring_lock_key)
            .await
            .map_err(map_capability_initialization_error)?;
        // This attested connection is the future integration point for the
        // platform keyring's opaque current-authority proof. The state plane
        // must fetch it from persisted PostgreSQL state and trusted DB time;
        // no Relay/request-input constructor belongs here.
        Ok(Self {
            client: Mutex::new(client),
            chain_hasher,
            chain_key_epoch_id,
            keyring_lock_key,
        })
    }

    pub(crate) async fn readiness(&self) -> StatePlaneReadiness {
        let Ok(client) = self.client.try_lock() else {
            return StatePlaneReadiness::Unavailable;
        };
        if validate_runtime_pseudonym_capability_v1(
            &client,
            &self.chain_key_epoch_id,
            self.keyring_lock_key,
        )
        .await
        .is_ok()
        {
            StatePlaneReadiness::Ready
        } else {
            StatePlaneReadiness::Unavailable
        }
    }

    async fn write_phase_cas(
        &self,
        write: &DurableAuditWrite,
        pseudonym_authority: Option<&ActiveAuditPseudonymWriteEpoch>,
    ) -> Result<DurableAuditWriteOutcome, DurableAuditWriteError> {
        let deadline = Instant::now() + MAX_WRITE_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| DurableAuditWriteError::StoreUnavailable)?;
        tokio::time::timeout_at(
            deadline,
            validate_runtime_pseudonym_capability_v1(
                &client,
                &self.chain_key_epoch_id,
                self.keyring_lock_key,
            ),
        )
        .await
        .map_err(|_| DurableAuditWriteError::StoreUnavailable)?
        .map_err(|_| DurableAuditWriteError::StoreUnavailable)?;

        let (pseudonym_key_id, pseudonym_generation, pseudonym_digest): (
            Option<&str>,
            Option<i64>,
            Option<&[u8]>,
        ) = match pseudonym_authority {
            Some(authority) => {
                let (key_id, generation, digest, chain_key_epoch_id, keyring_lock_key) =
                    authority.postgres_binding();
                if chain_key_epoch_id != &self.chain_key_epoch_id
                    || keyring_lock_key != self.keyring_lock_key.as_i64()
                {
                    return Err(DurableAuditWriteError::StoreFailure);
                }
                (Some(key_id), Some(generation), Some(digest.as_slice()))
            }
            None => (None, None, None),
        };
        for _ in 0..MAX_HEAD_CAS_ATTEMPTS {
            let snapshot = timeout_query(
                deadline,
                client.query_one(
                    SNAPSHOT_AUDIT_PHASE_SQL,
                    &[
                        &write.key().stream_kind().as_str(),
                        &write.key().operation_id().as_str(),
                        &write.key().phase().as_str(),
                        &write.payload_digest().as_bytes().as_slice(),
                        &self.chain_key_epoch_id.as_str(),
                        &pseudonym_key_id,
                        &pseudonym_generation,
                        &pseudonym_digest,
                        &self.keyring_lock_key.as_i64(),
                    ],
                ),
            )
            .await?;
            match try_str(&snapshot, "outcome")? {
                "identical_duplicate" => {
                    return Ok(DurableAuditWriteOutcome::IdenticalDuplicate(
                        stored_identity_from_row(&snapshot)?,
                    ));
                }
                "conflicting_duplicate" => {
                    return Ok(DurableAuditWriteOutcome::ConflictingDuplicate(
                        stored_identity_from_row(&snapshot)?,
                    ));
                }
                "candidate" => {}
                _ => return Err(DurableAuditWriteError::StoreFailure),
            }

            let predecessor = optional_hash_from_row(&snapshot, "candidate_predecessor_hash")?;
            let generation = snapshot
                .try_get::<_, i64>("candidate_generation")
                .map_err(|_| DurableAuditWriteError::StoreFailure)?;
            // Every head change discards this candidate and rebuilds the HMAC
            // envelope against the new predecessor. This never repeats a source
            // operation; it retries only the durable audit insertion.
            ensure_before_deadline(deadline)?;
            let envelope = write
                .build_envelope_at_chain_head(predecessor, &self.chain_hasher)
                .map_err(|_| DurableAuditWriteError::StoreFailure)?;
            ensure_before_deadline(deadline)?;
            let completion_attempt =
                completion_attempt_from_envelope(&envelope, write.key().phase())?;
            let record_json = serde_json::to_string(&envelope.record)
                .map_err(|_| DurableAuditWriteError::StoreFailure)?;
            if record_json.len() > MAX_RECORD_JSON_BYTES {
                return Err(DurableAuditWriteError::StoreFailure);
            }
            ensure_before_deadline(deadline)?;
            let envelope_json = serde_json::to_string(&envelope)
                .map_err(|_| DurableAuditWriteError::StoreFailure)?;
            if envelope_json.len() > MAX_ENVELOPE_JSON_BYTES {
                return Err(DurableAuditWriteError::StoreFailure);
            }
            ensure_before_deadline(deadline)?;
            let (attempt_envelope_id, attempt_chain_hash): (Option<&str>, Option<&[u8]>) =
                match completion_attempt.as_ref() {
                    Some(reference) => (
                        Some(reference.envelope_id.as_str()),
                        Some(reference.chain_hash.as_slice()),
                    ),
                    None => (None, None),
                };
            let cas = timeout_query(
                deadline,
                client.query_one(
                    CAS_AUDIT_PHASE_SQL,
                    &[
                        &write.key().stream_kind().as_str(),
                        &write.key().operation_id().as_str(),
                        &write.key().phase().as_str(),
                        &write.payload_digest().as_bytes().as_slice(),
                        &generation,
                        &envelope.prev_hash.as_ref().map(<[u8; 32]>::as_slice),
                        &envelope.envelope_id,
                        &envelope.timestamp_unix_ms,
                        &record_json,
                        &envelope_json,
                        &envelope.record_hash.as_slice(),
                        &attempt_envelope_id,
                        &attempt_chain_hash,
                        &pseudonym_key_id,
                        &pseudonym_generation,
                        &pseudonym_digest,
                        &self.chain_key_epoch_id.as_str(),
                        &self.keyring_lock_key.as_i64(),
                    ],
                ),
            )
            .await?;
            match try_str(&cas, "outcome")? {
                "inserted" => {
                    let stored = stored_identity_from_row(&cas)?;
                    if stored.envelope_id() != envelope.envelope_id
                        || stored.record_hash() != &envelope.record_hash
                    {
                        return Err(DurableAuditWriteError::StoreFailure);
                    }
                    return Ok(DurableAuditWriteOutcome::Inserted(stored));
                }
                "identical_duplicate" => {
                    return Ok(DurableAuditWriteOutcome::IdenticalDuplicate(
                        stored_identity_from_row(&cas)?,
                    ));
                }
                "conflicting_duplicate" => {
                    return Ok(DurableAuditWriteOutcome::ConflictingDuplicate(
                        stored_identity_from_row(&cas)?,
                    ));
                }
                "head_changed" => continue,
                _ => return Err(DurableAuditWriteError::StoreFailure),
            }
        }
        Err(DurableAuditWriteError::StoreUnavailable)
    }

    /// Persist a consultation or pseudonym-bearing denial only while
    /// PostgreSQL atomically confirms that the consumed key epoch is still the
    /// current write binding and before its exclusive deadline. The SQL CAS
    /// holds the shared keyring transition barrier through the insert.
    pub(crate) async fn write_phase_with_pseudonym_authority(
        &self,
        write: &DurableAuditWrite,
        authority: ActiveAuditPseudonymWriteEpoch,
    ) -> Result<DurableAuditWriteOutcome, DurableAuditWriteError> {
        self.write_phase_cas(write, Some(&authority)).await
    }

    /// Resolve only a prior pseudonym-bound durable write after process or key
    /// rotation recovery. This operation has no candidate or insert outcome,
    /// so absence can never authorize a write without current key authority.
    pub(crate) async fn recover_pseudonym_bound_duplicate(
        &self,
        write: &DurableAuditWrite,
    ) -> Result<PseudonymBoundDuplicateRecoveryOutcome, DurableAuditWriteError> {
        if !matches!(
            write.key().stream_kind(),
            DurableAuditStreamKind::Consultation | DurableAuditStreamKind::Denial
        ) {
            return Err(DurableAuditWriteError::StoreFailure);
        }
        let deadline = Instant::now() + MAX_WRITE_ELAPSED;
        let client = tokio::time::timeout_at(deadline, self.client.lock())
            .await
            .map_err(|_| DurableAuditWriteError::StoreUnavailable)?;
        tokio::time::timeout_at(
            deadline,
            validate_runtime_pseudonym_capability_v1(
                &client,
                &self.chain_key_epoch_id,
                self.keyring_lock_key,
            ),
        )
        .await
        .map_err(|_| DurableAuditWriteError::StoreUnavailable)?
        .map_err(|_| DurableAuditWriteError::StoreUnavailable)?;
        let row = timeout_query(
            deadline,
            client.query_one(
                RECOVER_AUDIT_PHASE_DUPLICATE_SQL,
                &[
                    &write.key().stream_kind().as_str(),
                    &write.key().operation_id().as_str(),
                    &write.key().phase().as_str(),
                    &write.payload_digest().as_bytes().as_slice(),
                    &self.chain_key_epoch_id.as_str(),
                    &self.keyring_lock_key.as_i64(),
                ],
            ),
        )
        .await?;
        match try_str(&row, "outcome")? {
            "identical_duplicate" => {
                Ok(PseudonymBoundDuplicateRecoveryOutcome::IdenticalDuplicate(
                    stored_identity_from_row(&row)?,
                ))
            }
            "conflicting_duplicate" => Ok(
                PseudonymBoundDuplicateRecoveryOutcome::ConflictingDuplicate(
                    stored_identity_from_row(&row)?,
                ),
            ),
            "not_found" => {
                if row
                    .try_get::<_, Option<&str>>("stored_envelope_id")
                    .map_err(|_| DurableAuditWriteError::StoreFailure)?
                    .is_some()
                    || row
                        .try_get::<_, Option<&[u8]>>("stored_chain_hash")
                        .map_err(|_| DurableAuditWriteError::StoreFailure)?
                        .is_some()
                {
                    return Err(DurableAuditWriteError::StoreFailure);
                }
                Ok(PseudonymBoundDuplicateRecoveryOutcome::NotFound)
            }
            _ => Err(DurableAuditWriteError::StoreFailure),
        }
    }
}

fn ensure_before_deadline(deadline: Instant) -> Result<(), DurableAuditWriteError> {
    if Instant::now() >= deadline {
        Err(DurableAuditWriteError::StoreUnavailable)
    } else {
        Ok(())
    }
}

async fn timeout_query<F>(deadline: Instant, future: F) -> Result<Row, DurableAuditWriteError>
where
    F: std::future::Future<Output = Result<Row, PostgresError>>,
{
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(DurableAuditWriteError::StoreUnavailable);
    }
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| DurableAuditWriteError::StoreUnavailable)?
        .map_err(map_postgres_write_error)
}

#[async_trait]
impl DurableAuditSink for PostgresDurableAuditStatePlane {
    async fn write_phase(
        &self,
        write: &DurableAuditWrite,
    ) -> Result<DurableAuditWriteOutcome, DurableAuditWriteError> {
        if write.key().stream_kind() == DurableAuditStreamKind::Consultation {
            return Err(DurableAuditWriteError::StoreFailure);
        }
        self.write_phase_cas(write, None).await
    }
}

fn map_postgres_write_error(error: PostgresError) -> DurableAuditWriteError {
    if error.is_closed() {
        return DurableAuditWriteError::StoreUnavailable;
    }
    let Some(database_error) = error.as_db_error() else {
        return DurableAuditWriteError::StoreUnavailable;
    };
    if sqlstate_is_unavailable(database_error.code().code()) {
        DurableAuditWriteError::StoreUnavailable
    } else {
        DurableAuditWriteError::StoreFailure
    }
}

fn sqlstate_is_unavailable(code: &str) -> bool {
    code.starts_with("08")
        || code.starts_with("25")
        || code.starts_with("53")
        || code.starts_with("58")
        || matches!(
            code,
            "40001"
                | "40P01"
                | "42501"
                | "55000"
                | "55P03"
                | "57014"
                | "57P01"
                | "57P02"
                | "57P03"
                | "57P04"
                | "57P05"
        )
}

fn map_capability_initialization_error(
    error: RuntimeCapabilityError,
) -> StatePlaneInitializationError {
    match error {
        RuntimeCapabilityError::WrongRuntimeIdentity => {
            StatePlaneInitializationError::WrongRuntimeIdentity
        }
        RuntimeCapabilityError::Drift => StatePlaneInitializationError::CapabilityDrift,
        RuntimeCapabilityError::Unavailable => StatePlaneInitializationError::Unavailable,
    }
}

fn completion_attempt_from_envelope(
    envelope: &AuditEnvelope,
    phase: DurableAuditPhase,
) -> Result<Option<CompletionAttemptReference>, DurableAuditWriteError> {
    if phase != DurableAuditPhase::Completion {
        return Ok(None);
    }
    let attempt = envelope
        .record
        .get("payload")
        .and_then(|payload| payload.get("attempt_event"))
        .and_then(Value::as_object)
        .ok_or(DurableAuditWriteError::StoreFailure)?;
    let envelope_id = attempt
        .get("envelope_id")
        .and_then(Value::as_str)
        .ok_or(DurableAuditWriteError::StoreFailure)?;
    let canonical_id = ulid::Ulid::from_string(envelope_id)
        .map_err(|_| DurableAuditWriteError::StoreFailure)?
        .to_string();
    if canonical_id != envelope_id {
        return Err(DurableAuditWriteError::StoreFailure);
    }
    let chain_hash = attempt
        .get("chain_hash")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("registry-audit-chain-v1:"))
        .ok_or(DurableAuditWriteError::StoreFailure)
        .and_then(decode_hash)?;
    Ok(Some(CompletionAttemptReference {
        envelope_id: envelope_id.to_owned(),
        chain_hash,
    }))
}

fn stored_identity_from_row(
    row: &Row,
) -> Result<DurableAuditStoredIdentity, DurableAuditWriteError> {
    let envelope_id = row
        .try_get::<_, &str>("stored_envelope_id")
        .map_err(|_| DurableAuditWriteError::StoreFailure)?;
    let chain_hash = required_hash_from_row(row, "stored_chain_hash")?;
    let envelope = AuditEnvelope {
        envelope_id: envelope_id.to_owned(),
        timestamp_unix_ms: 0,
        prev_hash: None,
        record: Value::Null,
        record_hash: chain_hash,
    };
    DurableAuditStoredIdentity::from_envelope(&envelope)
        .map_err(|_| DurableAuditWriteError::StoreFailure)
}

fn try_str<'a>(row: &'a Row, column: &str) -> Result<&'a str, DurableAuditWriteError> {
    row.try_get(column)
        .map_err(|_| DurableAuditWriteError::StoreFailure)
}

fn required_hash_from_row(row: &Row, column: &str) -> Result<[u8; 32], DurableAuditWriteError> {
    let bytes = row
        .try_get::<_, &[u8]>(column)
        .map_err(|_| DurableAuditWriteError::StoreFailure)?;
    bytes
        .try_into()
        .map_err(|_| DurableAuditWriteError::StoreFailure)
}

fn optional_hash_from_row(
    row: &Row,
    column: &str,
) -> Result<Option<[u8; 32]>, DurableAuditWriteError> {
    row.try_get::<_, Option<&[u8]>>(column)
        .map_err(|_| DurableAuditWriteError::StoreFailure)?
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| DurableAuditWriteError::StoreFailure)
        })
        .transpose()
}

fn decode_hash(value: &str) -> Result<[u8; 32], DurableAuditWriteError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DurableAuditWriteError::StoreFailure);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0]).ok_or(DurableAuditWriteError::StoreFailure)?;
        let low = decode_hex_nibble(pair[1]).ok_or(DurableAuditWriteError::StoreFailure)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_audit::{
        DurableAuditOperationId, DurableAuditStreamKind, DurableAuditWrite,
    };
    use ulid::Ulid;

    fn attempt_identity() -> DurableAuditStoredIdentity {
        let envelope = AuditEnvelope {
            envelope_id: Ulid::new().to_string(),
            timestamp_unix_ms: 1,
            prev_hash: None,
            record: json!({"safe": true}),
            record_hash: [0xab; 32],
        };
        DurableAuditStoredIdentity::from_envelope(&envelope).expect("valid identity")
    }

    #[test]
    fn completion_reference_uses_neutral_chain_hash_type() {
        let value = CompletionAttemptReference::from_stored_attempt(&attempt_identity())
            .to_safe_payload_value();
        assert_eq!(
            value.get("chain_hash").and_then(Value::as_str),
            Some(
                "registry-audit-chain-v1:abababababababababababababababababababababababababababababababab"
            )
        );
        assert!(value.get("record_hash").is_none());
    }

    #[test]
    fn completion_requires_attempt_reference() {
        let write = DurableAuditWrite::new(
            DurableAuditStreamKind::Consultation,
            DurableAuditOperationId::from_ulid(Ulid::new()),
            DurableAuditPhase::Completion,
            json!({"outcome": "known_complete"}),
        )
        .expect("valid write");
        let envelope = write
            .build_envelope_at_chain_head(None, &AuditChainHasher::unkeyed_dev_only())
            .expect("envelope");
        assert_eq!(
            completion_attempt_from_envelope(&envelope, DurableAuditPhase::Completion),
            Err(DurableAuditWriteError::StoreFailure)
        );
    }

    #[test]
    fn timeout_connection_and_shutdown_sqlstates_are_unavailable() {
        for code in [
            "08006", "25006", "25P03", "40001", "40P01", "53300", "55000", "55P03", "57014",
            "57P01", "57P05", "58030",
        ] {
            assert!(sqlstate_is_unavailable(code));
        }
        for code in ["22023", "23503", "42601"] {
            assert!(!sqlstate_is_unavailable(code));
        }
    }
}
