// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL authority for audit-pseudonym key epoch metadata.
//!
//! The three clients below are intentionally disjoint. Relay runtime may only
//! obtain a candidate current epoch that PostgreSQL revalidates atomically at
//! durable audit persistence. A maintenance identity may initialize and apply
//! lifecycle transitions. An investigation reader may request only an opaque,
//! pre-authorized exact subset. PostgreSQL stores no key material, secret
//! source, selector, or secret-derived probe.

use std::{
    collections::BTreeSet,
    fmt::{self, Write as _},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use registry_platform_audit::pseudonym_keyring::{
    AuditPseudonymKeyId, AuditPseudonymKeyringError, AuditPseudonymKeyringMetadata,
    AuditPseudonymMetadataBinding, AuditPseudonymTime, RetainedAuditPseudonymKeyEpoch,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{sync::Mutex, time::Instant};
use tokio_postgres::{Client, GenericClient, Row, Transaction};

use super::migration::{
    validate_keyring_role_capability_v1, AuditChainKeyEpochId, AuditPseudonymKeyringLockKey,
    KeyringDatabaseRoleKind, RuntimeCapabilityError, RUNTIME_SESSION_LIMITS_SQL,
};

const KEYRING_SNAPSHOT_SQL: &str =
    "SELECT * FROM relay_state_api.audit_pseudonym_keyring_snapshot_v1($1, $2, $3, $4)";
const KEYRING_INITIALIZE_SQL: &str = "SELECT * FROM \
    relay_state_api.audit_pseudonym_keyring_initialize_v1(\
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12\
    )";
const KEYRING_ROTATE_SQL: &str = "SELECT * FROM \
    relay_state_api.audit_pseudonym_keyring_rotate_v1(\
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17\
    )";
const KEYRING_MAINTAIN_SQL: &str = "SELECT * FROM \
    relay_state_api.audit_pseudonym_keyring_maintain_v1(\
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17\
    )";
const DATABASE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const KEYRING_SCHEMA_V1: &str = "registry.audit-pseudonym-keyring/v1";
const HISTORY_DIGEST_DOMAIN_V1: &[u8] = b"registry.audit-pseudonym-key-id-history.v1";
const MAX_USED_KEY_IDS: usize = 4_096;
const MAX_USED_KEY_ID_BYTES: usize = 262_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyringReadiness {
    Ready,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyringInitializationOutcome {
    Initialized,
    Identical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum PostgresKeyringError {
    #[error("Relay audit-pseudonym keyring metadata is invalid")]
    InvalidMetadata,
    #[error("Relay audit-pseudonym keyring is not initialized")]
    Uninitialized,
    #[error("Relay audit-pseudonym keyring was already initialized differently")]
    AlreadyInitialized,
    #[error("Relay audit-pseudonym keyring metadata is not active yet")]
    NotActive,
    #[error("Relay audit-pseudonym active-write deadline was reached")]
    WriteDeadlineReached,
    #[error("Relay audit-pseudonym retained-epoch maintenance is overdue")]
    RetainedEpochExpired,
    #[error("Relay audit-pseudonym lookup subset is not authorized")]
    UnauthorizedLookupSubset,
    #[error("Relay audit-pseudonym expected generation or binding is stale")]
    StaleExpectedState,
    #[error("Relay audit-pseudonym used-key-id authority is incomplete")]
    IncompleteHistory,
    #[error("Relay audit-pseudonym key id was already used")]
    ReusedKeyId,
    #[error("Relay audit-pseudonym used-key-id history reached its protocol bound")]
    HistoryLimitReached,
    #[error("Relay audit-pseudonym rotation transition is invalid")]
    InvalidRotation,
    #[error("Relay audit-pseudonym maintenance transition is invalid")]
    InvalidMaintenance,
    #[error("Relay audit-pseudonym runtime identity is not bound")]
    WrongRuntimeIdentity,
    #[error("Relay audit-pseudonym PostgreSQL capability has drifted")]
    CapabilityDrift,
    #[error("Relay audit-pseudonym PostgreSQL protocol has drifted")]
    ProtocolDrift,
    #[error("Relay audit-pseudonym PostgreSQL authority is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AuthoritativeKeyringBinding {
    generation: i64,
    digest: [u8; 32],
}

impl fmt::Debug for AuthoritativeKeyringBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthoritativeKeyringBinding")
            .field("generation", &self.generation)
            .field("digest", &"sha256:<redacted>")
            .finish()
    }
}

/// Candidate epoch fetched from PostgreSQL. It is deliberately insufficient
/// to acknowledge a consultation audit event. The epoch returned by
/// `authorize_use` must later be consumed by
/// `PostgresDurableAuditStatePlane::write_phase_with_pseudonym_authority`,
/// whose SQL rechecks this exact binding and PostgreSQL time in the audit CAS.
#[must_use = "the candidate must be consumed by the pseudonym-bound audit path"]
pub(crate) struct AuditPseudonymWriteAuthority {
    active_key_id: AuditPseudonymKeyId,
    metadata_binding: AuthoritativeKeyringBinding,
    chain_key_epoch_id: AuditChainKeyEpochId,
    keyring_lock_key: AuditPseudonymKeyringLockKey,
    local_deadline: Instant,
}

impl AuditPseudonymWriteAuthority {
    pub(crate) fn authorize_use(
        self,
    ) -> Result<ActiveAuditPseudonymWriteEpoch, PostgresKeyringError> {
        if Instant::now() >= self.local_deadline {
            return Err(PostgresKeyringError::WriteDeadlineReached);
        }
        Ok(ActiveAuditPseudonymWriteEpoch {
            active_key_id: self.active_key_id,
            metadata_binding: self.metadata_binding,
            chain_key_epoch_id: self.chain_key_epoch_id,
            keyring_lock_key: self.keyring_lock_key,
        })
    }
}

impl fmt::Debug for AuditPseudonymWriteAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditPseudonymWriteAuthority(<candidate current binding>)")
    }
}

/// Non-cloneable epoch consumed by the atomic pseudonym-bound durable CAS.
#[must_use = "the epoch must be consumed by pseudonym-bound durable persistence"]
pub(crate) struct ActiveAuditPseudonymWriteEpoch {
    active_key_id: AuditPseudonymKeyId,
    metadata_binding: AuthoritativeKeyringBinding,
    chain_key_epoch_id: AuditChainKeyEpochId,
    keyring_lock_key: AuditPseudonymKeyringLockKey,
}

impl ActiveAuditPseudonymWriteEpoch {
    pub(crate) fn key_id(&self) -> &AuditPseudonymKeyId {
        &self.active_key_id
    }

    pub(crate) fn postgres_binding(&self) -> (&str, i64, &[u8; 32], &AuditChainKeyEpochId, i64) {
        (
            self.active_key_id.as_str(),
            self.metadata_binding.generation,
            &self.metadata_binding.digest,
            &self.chain_key_epoch_id,
            self.keyring_lock_key.as_i64(),
        )
    }
}

impl fmt::Debug for ActiveAuditPseudonymWriteEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveAuditPseudonymWriteEpoch(<CAS-bound authority>)")
    }
}

/// Opaque investigation authorization. There is intentionally no production
/// constructor until the configured reader-role and investigation-purpose
/// boundary is wired. Tests may construct reviewed exact subsets explicitly.
pub(crate) struct AuthorizedAuditPseudonymLookupSubset {
    key_ids: Vec<String>,
}

impl AuthorizedAuditPseudonymLookupSubset {
    #[cfg(test)]
    pub(crate) fn for_test<I>(key_ids: I) -> Result<Self, PostgresKeyringError>
    where
        I: IntoIterator<Item = AuditPseudonymKeyId>,
    {
        let mut key_ids = key_ids
            .into_iter()
            .map(|key_id| key_id.as_str().to_owned())
            .collect::<Vec<_>>();
        key_ids.sort();
        if key_ids.is_empty()
            || key_ids.len() > 32
            || key_ids.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(PostgresKeyringError::UnauthorizedLookupSubset);
        }
        Ok(Self { key_ids })
    }
}

impl fmt::Debug for AuthorizedAuditPseudonymLookupSubset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedAuditPseudonymLookupSubset")
            .field("key_id_count", &self.key_ids.len())
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuditPseudonymLookupEpoch {
    Active { key_id: AuditPseudonymKeyId },
    Retained(RetainedAuditPseudonymKeyEpoch),
}

impl AuditPseudonymLookupEpoch {
    pub(crate) fn key_id(&self) -> &AuditPseudonymKeyId {
        match self {
            Self::Active { key_id } => key_id,
            Self::Retained(epoch) => epoch.key_id(),
        }
    }
}

/// Exact, non-cloneable metadata-only lookup authorization consumed by the
/// external key loader.
#[must_use = "the exact lookup snapshot must be consumed by the external key loader"]
pub(crate) struct AuditPseudonymLookupSnapshot {
    metadata_binding: AuthoritativeKeyringBinding,
    epochs: Vec<AuditPseudonymLookupEpoch>,
}

impl AuditPseudonymLookupSnapshot {
    pub(crate) fn epochs(&self) -> &[AuditPseudonymLookupEpoch] {
        &self.epochs
    }
}

impl fmt::Debug for AuditPseudonymLookupSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditPseudonymLookupSnapshot")
            .field("metadata_binding", &self.metadata_binding)
            .field("epoch_count", &self.epochs.len())
            .finish()
    }
}

struct KeyringClient {
    client: Mutex<Client>,
    chain_key_epoch_id: AuditChainKeyEpochId,
    keyring_lock_key: AuditPseudonymKeyringLockKey,
    available: AtomicBool,
}

impl KeyringClient {
    async fn connect(
        client: Client,
        chain_key_epoch_id: AuditChainKeyEpochId,
        keyring_lock_key: AuditPseudonymKeyringLockKey,
        role_kind: KeyringDatabaseRoleKind,
    ) -> Result<Self, PostgresKeyringError> {
        client
            .batch_execute("ROLLBACK")
            .await
            .map_err(|_| PostgresKeyringError::Unavailable)?;
        client
            .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
            .await
            .map_err(|_| PostgresKeyringError::Unavailable)?;
        validate_keyring_role_capability_v1(
            &client,
            &chain_key_epoch_id,
            keyring_lock_key,
            role_kind,
        )
        .await
        .map_err(map_runtime_capability_error)?;
        Ok(Self {
            client: Mutex::new(client),
            chain_key_epoch_id,
            keyring_lock_key,
            available: AtomicBool::new(true),
        })
    }

    async fn lock_client(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Client>, PostgresKeyringError> {
        if !self.available.load(Ordering::Acquire) {
            return Err(PostgresKeyringError::Unavailable);
        }
        let client = tokio::time::timeout(DATABASE_OPERATION_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| PostgresKeyringError::Unavailable)?;
        if !self.available.load(Ordering::Acquire) {
            return Err(PostgresKeyringError::Unavailable);
        }
        Ok(client)
    }
}

/// Relay-runtime side. It cannot initialize, rotate, maintain, or investigate.
pub(crate) struct PostgresAuditPseudonymKeyringRuntime {
    inner: KeyringClient,
}

impl PostgresAuditPseudonymKeyringRuntime {
    pub(crate) async fn connect(
        client: Client,
        chain_key_epoch_id: AuditChainKeyEpochId,
        keyring_lock_key: AuditPseudonymKeyringLockKey,
    ) -> Result<Self, PostgresKeyringError> {
        Ok(Self {
            inner: KeyringClient::connect(
                client,
                chain_key_epoch_id,
                keyring_lock_key,
                KeyringDatabaseRoleKind::Runtime,
            )
            .await?,
        })
    }

    pub(crate) async fn readiness(&self) -> KeyringReadiness {
        match self.current_write_authority().await {
            Ok(_) => KeyringReadiness::Ready,
            Err(_) => KeyringReadiness::Unavailable,
        }
    }

    pub(crate) async fn current_write_authority(
        &self,
    ) -> Result<AuditPseudonymWriteAuthority, PostgresKeyringError> {
        let anchor = Instant::now();
        let snapshot = query_runtime_write_snapshot_locked(&self.inner).await?;
        let local_deadline =
            conservative_local_deadline(anchor, snapshot.active_write_remaining_ms)?;
        Ok(AuditPseudonymWriteAuthority {
            active_key_id: snapshot.active_key_id,
            metadata_binding: snapshot.binding,
            chain_key_epoch_id: self.inner.chain_key_epoch_id.clone(),
            keyring_lock_key: self.inner.keyring_lock_key,
            local_deadline,
        })
    }
}

fn conservative_local_deadline(
    anchor: Instant,
    remaining_ms: i64,
) -> Result<Instant, PostgresKeyringError> {
    let remaining_ms =
        u64::try_from(remaining_ms).map_err(|_| PostgresKeyringError::ProtocolDrift)?;
    anchor
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or(PostgresKeyringError::ProtocolDrift)
}

/// Maintenance-plane side. It cannot mint runtime write epochs or perform
/// investigation lookup.
pub(crate) struct PostgresAuditPseudonymKeyringMaintenance {
    inner: KeyringClient,
}

impl PostgresAuditPseudonymKeyringMaintenance {
    pub(crate) async fn connect(
        client: Client,
        chain_key_epoch_id: AuditChainKeyEpochId,
        keyring_lock_key: AuditPseudonymKeyringLockKey,
    ) -> Result<Self, PostgresKeyringError> {
        Ok(Self {
            inner: KeyringClient::connect(
                client,
                chain_key_epoch_id,
                keyring_lock_key,
                KeyringDatabaseRoleKind::Maintenance,
            )
            .await?,
        })
    }

    pub(crate) async fn initialize(
        &self,
        metadata: AuditPseudonymKeyringMetadata,
    ) -> Result<KeyringInitializationOutcome, PostgresKeyringError> {
        let encoded = EncodedMetadata::from_metadata(metadata)?;
        let client = self.inner.lock_client().await?;
        let mut uncertainty = KeyringUncertaintyGuard::new(&self.inner.available);
        let row = timeout_row(client.query_one(
            KEYRING_INITIALIZE_SQL,
            &[
                &encoded.generation,
                &encoded.digest.as_slice(),
                &encoded.canonical,
                &encoded.active_key_id,
                &encoded.active_since_unix_ms,
                &encoded.active_write_deadline_unix_ms,
                &encoded.audit_event_retention_ms,
                &encoded.retained_key_ids,
                &encoded.retained_retired_at_unix_ms,
                &encoded.retained_destroy_after_unix_ms,
                &self.inner.chain_key_epoch_id.as_str(),
                &self.inner.keyring_lock_key.as_i64(),
            ],
        ))
        .await?;
        let outcome = required_str(&row, "outcome")?;
        let result = match outcome {
            "initialized" | "identical" => {
                verify_transition_result(&row, encoded.generation, &encoded.digest)?;
                Ok(if outcome == "initialized" {
                    KeyringInitializationOutcome::Initialized
                } else {
                    KeyringInitializationOutcome::Identical
                })
            }
            "already_initialized" => Err(PostgresKeyringError::AlreadyInitialized),
            "not_active" => Err(PostgresKeyringError::NotActive),
            "deadline_reached" => Err(PostgresKeyringError::WriteDeadlineReached),
            "invalid" => Err(PostgresKeyringError::InvalidMetadata),
            _ => return Err(PostgresKeyringError::ProtocolDrift),
        };
        uncertainty.confirm();
        result
    }

    pub(crate) async fn rotate<F>(
        &self,
        expected: AuditPseudonymMetadataBinding,
        build_successor: F,
    ) -> Result<AuditPseudonymMetadataBinding, PostgresKeyringError>
    where
        F: FnOnce(
            &AuditPseudonymKeyringMetadata,
            AuditPseudonymTime,
        ) -> Result<AuditPseudonymKeyringMetadata, PostgresKeyringError>,
    {
        self.apply_transition("rotation", KEYRING_ROTATE_SQL, expected, build_successor)
            .await
    }

    pub(crate) async fn maintain<F>(
        &self,
        expected: AuditPseudonymMetadataBinding,
        build_successor: F,
    ) -> Result<AuditPseudonymMetadataBinding, PostgresKeyringError>
    where
        F: FnOnce(
            &AuditPseudonymKeyringMetadata,
            AuditPseudonymTime,
        ) -> Result<AuditPseudonymKeyringMetadata, PostgresKeyringError>,
    {
        self.apply_transition(
            "maintenance",
            KEYRING_MAINTAIN_SQL,
            expected,
            build_successor,
        )
        .await
    }

    async fn apply_transition<F>(
        &self,
        kind: &'static str,
        sql: &'static str,
        expected: AuditPseudonymMetadataBinding,
        build_successor: F,
    ) -> Result<AuditPseudonymMetadataBinding, PostgresKeyringError>
    where
        F: FnOnce(
            &AuditPseudonymKeyringMetadata,
            AuditPseudonymTime,
        ) -> Result<AuditPseudonymKeyringMetadata, PostgresKeyringError>,
    {
        let mut client = self.inner.lock_client().await?;
        let mut uncertainty = KeyringUncertaintyGuard::new(&self.inner.available);
        let transaction = tokio::time::timeout(DATABASE_OPERATION_TIMEOUT, client.transaction())
            .await
            .map_err(|_| PostgresKeyringError::Unavailable)?
            .map_err(map_postgres_error)?;
        let empty_lookup_ids = Vec::<String>::new();
        let row = timeout_row(transaction.query_one(
            KEYRING_SNAPSHOT_SQL,
            &[
                &kind,
                &empty_lookup_ids,
                &self.inner.chain_key_epoch_id.as_str(),
                &self.inner.keyring_lock_key.as_i64(),
            ],
        ))
        .await?;
        let snapshot = match parse_maintenance_snapshot_outcome(&row) {
            Ok(snapshot) => snapshot,
            Err(PostgresKeyringError::ProtocolDrift) => {
                return Err(PostgresKeyringError::ProtocolDrift);
            }
            Err(error) => {
                rollback_confirmed(transaction, &mut uncertainty).await?;
                return Err(error);
            }
        };
        if snapshot.binding != expected {
            rollback_confirmed(transaction, &mut uncertainty).await?;
            return Err(PostgresKeyringError::StaleExpectedState);
        }
        let successor = match build_successor(&snapshot.metadata, snapshot.authoritative_time) {
            Ok(successor) => successor,
            Err(error) => {
                rollback_confirmed(transaction, &mut uncertainty).await?;
                return Err(error);
            }
        };
        let contract_result = if kind == "rotation" {
            snapshot.metadata.validate_rotation_successor_values(
                &successor,
                &snapshot.used_key_ids,
                snapshot.authoritative_time,
            )
        } else {
            snapshot.metadata.validate_maintenance_successor_values(
                &successor,
                &snapshot.used_key_ids,
                snapshot.authoritative_time,
            )
        };
        if let Err(error) = contract_result {
            let mapped = if kind == "rotation" {
                map_rotation_contract_error(error)
            } else {
                map_maintenance_contract_error(error)
            };
            rollback_confirmed(transaction, &mut uncertainty).await?;
            return Err(mapped);
        }
        let successor = match EncodedMetadata::from_metadata(successor) {
            Ok(successor) => successor,
            Err(error) => {
                rollback_confirmed(transaction, &mut uncertainty).await?;
                return Err(error);
            }
        };
        let expected_generation = match i64::try_from(expected.generation()) {
            Ok(expected_generation) => expected_generation,
            Err(_) => {
                rollback_confirmed(transaction, &mut uncertainty).await?;
                return Err(PostgresKeyringError::InvalidMetadata);
            }
        };
        let row = timeout_row(transaction.query_one(
            sql,
            &[
                &expected_generation,
                &expected.digest().as_slice(),
                &snapshot.history_count,
                &snapshot.history_digest.as_slice(),
                &snapshot.authoritative_time.unix_ms(),
                &successor.generation,
                &successor.digest.as_slice(),
                &successor.canonical,
                &successor.active_key_id,
                &successor.active_since_unix_ms,
                &successor.active_write_deadline_unix_ms,
                &successor.audit_event_retention_ms,
                &successor.retained_key_ids,
                &successor.retained_retired_at_unix_ms,
                &successor.retained_destroy_after_unix_ms,
                &self.inner.chain_key_epoch_id.as_str(),
                &self.inner.keyring_lock_key.as_i64(),
            ],
        ))
        .await?;
        let outcome = required_str(&row, "outcome")?;
        let expected_success = if kind == "rotation" {
            "rotated"
        } else {
            "maintained"
        };
        if outcome != expected_success {
            let error = match outcome {
                "stale" => PostgresKeyringError::StaleExpectedState,
                "authority_incomplete" => PostgresKeyringError::IncompleteHistory,
                "history_full" if kind == "rotation" => PostgresKeyringError::HistoryLimitReached,
                "reused" if kind == "rotation" => PostgresKeyringError::ReusedKeyId,
                "deadline_reached" => PostgresKeyringError::WriteDeadlineReached,
                "invalid" if kind == "rotation" => PostgresKeyringError::InvalidRotation,
                "invalid" => PostgresKeyringError::InvalidMaintenance,
                _ => return Err(PostgresKeyringError::ProtocolDrift),
            };
            rollback_confirmed(transaction, &mut uncertainty).await?;
            return Err(error);
        }
        verify_transition_result(&row, successor.generation, &successor.digest)?;
        tokio::time::timeout(DATABASE_OPERATION_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| PostgresKeyringError::Unavailable)?
            .map_err(map_postgres_error)?;
        uncertainty.confirm();
        successor
            .metadata
            .binding()
            .map_err(|_| PostgresKeyringError::ProtocolDrift)
    }
}

/// Investigation-reader side. The caller still needs an opaque configured
/// proof for every exact subset.
pub(crate) struct PostgresAuditPseudonymKeyringReader {
    inner: KeyringClient,
}

impl PostgresAuditPseudonymKeyringReader {
    pub(crate) async fn connect(
        client: Client,
        chain_key_epoch_id: AuditChainKeyEpochId,
        keyring_lock_key: AuditPseudonymKeyringLockKey,
    ) -> Result<Self, PostgresKeyringError> {
        Ok(Self {
            inner: KeyringClient::connect(
                client,
                chain_key_epoch_id,
                keyring_lock_key,
                KeyringDatabaseRoleKind::Reader,
            )
            .await?,
        })
    }

    pub(crate) async fn lookup_snapshot(
        &self,
        authorized_subset: AuthorizedAuditPseudonymLookupSubset,
    ) -> Result<AuditPseudonymLookupSnapshot, PostgresKeyringError> {
        let snapshot =
            query_reader_lookup_snapshot_locked(&self.inner, &authorized_subset.key_ids).await?;
        Ok(AuditPseudonymLookupSnapshot {
            metadata_binding: snapshot.binding,
            epochs: snapshot.lookup_epochs,
        })
    }
}

async fn query_runtime_write_snapshot_locked(
    inner: &KeyringClient,
) -> Result<RuntimeWriteSnapshot, PostgresKeyringError> {
    let client = inner.lock_client().await?;
    let mut uncertainty = KeyringUncertaintyGuard::new(&inner.available);
    let empty_lookup_ids = Vec::<String>::new();
    let row = timeout_row(client.query_one(
        KEYRING_SNAPSHOT_SQL,
        &[
            &"write",
            &empty_lookup_ids,
            &inner.chain_key_epoch_id.as_str(),
            &inner.keyring_lock_key.as_i64(),
        ],
    ))
    .await?;
    let result = parse_runtime_write_snapshot_outcome(&row);
    if !matches!(result, Err(PostgresKeyringError::ProtocolDrift)) {
        uncertainty.confirm();
    }
    result
}

async fn query_reader_lookup_snapshot_locked(
    inner: &KeyringClient,
    expected_lookup_ids: &[String],
) -> Result<ReaderLookupSnapshot, PostgresKeyringError> {
    let client = inner.lock_client().await?;
    let mut uncertainty = KeyringUncertaintyGuard::new(&inner.available);
    let row = timeout_row(client.query_one(
        KEYRING_SNAPSHOT_SQL,
        &[
            &"lookup",
            &expected_lookup_ids,
            &inner.chain_key_epoch_id.as_str(),
            &inner.keyring_lock_key.as_i64(),
        ],
    ))
    .await?;
    let result = parse_reader_lookup_snapshot_outcome(&row, expected_lookup_ids);
    if !matches!(result, Err(PostgresKeyringError::ProtocolDrift)) {
        uncertainty.confirm();
    }
    result
}

fn snapshot_outcome_error(row: &Row) -> Result<Option<PostgresKeyringError>, PostgresKeyringError> {
    match required_str(row, "outcome")? {
        "ready" => Ok(None),
        "uninitialized" => Ok(Some(PostgresKeyringError::Uninitialized)),
        "not_active" => Ok(Some(PostgresKeyringError::NotActive)),
        "deadline_reached" => Ok(Some(PostgresKeyringError::WriteDeadlineReached)),
        "retained_expired" => Ok(Some(PostgresKeyringError::RetainedEpochExpired)),
        "unauthorized_lookup" => Ok(Some(PostgresKeyringError::UnauthorizedLookupSubset)),
        _ => Err(PostgresKeyringError::ProtocolDrift),
    }
}

async fn rollback_confirmed(
    transaction: Transaction<'_>,
    uncertainty: &mut KeyringUncertaintyGuard<'_>,
) -> Result<(), PostgresKeyringError> {
    tokio::time::timeout(DATABASE_OPERATION_TIMEOUT, transaction.rollback())
        .await
        .map_err(|_| PostgresKeyringError::Unavailable)?
        .map_err(map_postgres_error)?;
    uncertainty.confirm();
    Ok(())
}

async fn timeout_row<F>(future: F) -> Result<Row, PostgresKeyringError>
where
    F: std::future::Future<Output = Result<Row, tokio_postgres::Error>>,
{
    tokio::time::timeout(DATABASE_OPERATION_TIMEOUT, future)
        .await
        .map_err(|_| PostgresKeyringError::Unavailable)?
        .map_err(map_postgres_error)
}

struct KeyringUncertaintyGuard<'a> {
    available: &'a AtomicBool,
    confirmed: bool,
}

impl<'a> KeyringUncertaintyGuard<'a> {
    fn new(available: &'a AtomicBool) -> Self {
        Self {
            available,
            confirmed: false,
        }
    }

    fn confirm(&mut self) {
        self.confirmed = true;
    }
}

impl Drop for KeyringUncertaintyGuard<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.available.store(false, Ordering::Release);
        }
    }
}

struct EncodedMetadata {
    metadata: AuditPseudonymKeyringMetadata,
    generation: i64,
    digest: [u8; 32],
    canonical: String,
    active_key_id: String,
    active_since_unix_ms: i64,
    active_write_deadline_unix_ms: i64,
    audit_event_retention_ms: i64,
    retained_key_ids: Vec<String>,
    retained_retired_at_unix_ms: Vec<i64>,
    retained_destroy_after_unix_ms: Vec<i64>,
}

impl EncodedMetadata {
    fn from_metadata(
        metadata: AuditPseudonymKeyringMetadata,
    ) -> Result<Self, PostgresKeyringError> {
        let binding = metadata
            .binding()
            .map_err(|_| PostgresKeyringError::InvalidMetadata)?;
        let canonical = canonical_metadata(&metadata)?;
        let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        if digest != *binding.digest() {
            return Err(PostgresKeyringError::InvalidMetadata);
        }
        Ok(Self {
            generation: i64::try_from(metadata.generation())
                .map_err(|_| PostgresKeyringError::InvalidMetadata)?,
            digest,
            canonical,
            active_key_id: metadata.active_key_id().as_str().to_owned(),
            active_since_unix_ms: metadata.active_since_unix_ms(),
            active_write_deadline_unix_ms: metadata.active_write_deadline_unix_ms(),
            audit_event_retention_ms: metadata.audit_event_retention_ms(),
            retained_key_ids: metadata
                .retained_keys()
                .iter()
                .map(|epoch| epoch.key_id().as_str().to_owned())
                .collect(),
            retained_retired_at_unix_ms: metadata
                .retained_keys()
                .iter()
                .map(RetainedAuditPseudonymKeyEpoch::retired_at_unix_ms)
                .collect(),
            retained_destroy_after_unix_ms: metadata
                .retained_keys()
                .iter()
                .map(RetainedAuditPseudonymKeyEpoch::destroy_after_unix_ms)
                .collect(),
            metadata,
        })
    }
}

struct MaintenanceSnapshot {
    metadata: AuditPseudonymKeyringMetadata,
    binding: AuditPseudonymMetadataBinding,
    authoritative_time: AuditPseudonymTime,
    used_key_ids: BTreeSet<AuditPseudonymKeyId>,
    history_count: i64,
    history_digest: [u8; 32],
}

struct RuntimeWriteSnapshot {
    binding: AuthoritativeKeyringBinding,
    active_key_id: AuditPseudonymKeyId,
    active_write_remaining_ms: i64,
}

struct ReaderLookupSnapshot {
    binding: AuthoritativeKeyringBinding,
    lookup_epochs: Vec<AuditPseudonymLookupEpoch>,
}

fn parse_maintenance_snapshot_outcome(
    row: &Row,
) -> Result<MaintenanceSnapshot, PostgresKeyringError> {
    if let Some(error) = snapshot_outcome_error(row)? {
        return Err(error);
    }
    parse_maintenance_snapshot(row)
}

fn parse_runtime_write_snapshot_outcome(
    row: &Row,
) -> Result<RuntimeWriteSnapshot, PostgresKeyringError> {
    if let Some(error) = snapshot_outcome_error(row)? {
        return Err(error);
    }
    parse_runtime_write_snapshot(row)
}

fn parse_reader_lookup_snapshot_outcome(
    row: &Row,
    expected_lookup_ids: &[String],
) -> Result<ReaderLookupSnapshot, PostgresKeyringError> {
    if let Some(error) = snapshot_outcome_error(row)? {
        return Err(error);
    }
    parse_reader_lookup_snapshot(row, expected_lookup_ids)
}

fn parse_maintenance_snapshot(row: &Row) -> Result<MaintenanceSnapshot, PostgresKeyringError> {
    let generation = required_i64(row, "generation")?;
    let active_key_id = AuditPseudonymKeyId::parse(required_string(row, "active_key_id")?)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)?;
    let retained_key_ids = required_string_array(row, "retained_key_ids")?;
    let retained_retired = required_i64_array(row, "retained_retired_at_unix_ms")?;
    let retained_destroy = required_i64_array(row, "retained_destroy_after_unix_ms")?;
    let retained = retained_epochs(&retained_key_ids, &retained_retired, &retained_destroy)?;
    let metadata = AuditPseudonymKeyringMetadata::new(
        u64::try_from(generation).map_err(|_| PostgresKeyringError::ProtocolDrift)?,
        active_key_id,
        required_i64(row, "active_since_unix_ms")?,
        required_i64(row, "active_write_deadline_unix_ms")?,
        required_i64(row, "audit_event_retention_ms")?,
        retained,
    )
    .map_err(|_| PostgresKeyringError::ProtocolDrift)?;
    let encoded = EncodedMetadata::from_metadata(metadata)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)?;
    let binding = encoded
        .metadata
        .binding()
        .map_err(|_| PostgresKeyringError::ProtocolDrift)?;
    if required_hash(row, "metadata_digest")? != encoded.digest
        || required_str(row, "metadata_canonical")? != encoded.canonical
        || optional_i64(row, "active_write_remaining_ms")?.is_some()
        || !required_string_array(row, "lookup_key_ids")?.is_empty()
        || !required_optional_i64_array(row, "lookup_retired_at_unix_ms")?.is_empty()
        || !required_optional_i64_array(row, "lookup_destroy_after_unix_ms")?.is_empty()
    {
        return Err(PostgresKeyringError::ProtocolDrift);
    }

    let used_id_strings = required_string_array(row, "used_key_ids")?;
    if used_id_strings.len() > MAX_USED_KEY_IDS
        || used_id_strings.iter().map(String::len).sum::<usize>() > MAX_USED_KEY_ID_BYTES
        || used_id_strings
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(PostgresKeyringError::ProtocolDrift);
    }
    let used_key_ids = used_id_strings
        .iter()
        .map(|key_id| {
            AuditPseudonymKeyId::parse(key_id.clone())
                .map_err(|_| PostgresKeyringError::ProtocolDrift)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let history_count = required_i64(row, "used_key_id_count")?;
    let history_digest = required_hash(row, "used_key_ids_digest")?;
    if usize::try_from(history_count).ok() != Some(used_key_ids.len())
        || history_digest != used_key_id_history_digest(&used_id_strings)
        || !used_key_ids.contains(encoded.metadata.active_key_id())
        || encoded
            .metadata
            .retained_keys()
            .iter()
            .any(|epoch| !used_key_ids.contains(epoch.key_id()))
    {
        return Err(PostgresKeyringError::ProtocolDrift);
    }

    Ok(MaintenanceSnapshot {
        metadata: encoded.metadata,
        binding,
        authoritative_time: AuditPseudonymTime::from_unix_ms(required_i64(
            row,
            "authoritative_now_unix_ms",
        )?)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)?,
        used_key_ids,
        history_count,
        history_digest,
    })
}

fn parse_runtime_write_snapshot(row: &Row) -> Result<RuntimeWriteSnapshot, PostgresKeyringError> {
    let binding = parse_authoritative_binding(row)?;
    let authoritative_time = parse_authoritative_time(row)?;
    let active_key_id = AuditPseudonymKeyId::parse(required_string(row, "active_key_id")?)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)?;
    let active_since = AuditPseudonymTime::from_unix_ms(required_i64(row, "active_since_unix_ms")?)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)?;
    let active_deadline =
        AuditPseudonymTime::from_unix_ms(required_i64(row, "active_write_deadline_unix_ms")?)
            .map_err(|_| PostgresKeyringError::ProtocolDrift)?;
    let remaining = required_i64(row, "active_write_remaining_ms")?;
    if active_since > authoritative_time
        || active_deadline <= authoritative_time
        || remaining < 1
        || remaining > active_deadline.unix_ms() - authoritative_time.unix_ms()
        || optional_string(row, "metadata_canonical")?.is_some()
        || optional_i64(row, "audit_event_retention_ms")?.is_some()
        || !required_string_array(row, "retained_key_ids")?.is_empty()
        || !required_i64_array(row, "retained_retired_at_unix_ms")?.is_empty()
        || !required_i64_array(row, "retained_destroy_after_unix_ms")?.is_empty()
        || optional_i64(row, "used_key_id_count")?.is_some()
        || optional_hash(row, "used_key_ids_digest")?.is_some()
        || !required_string_array(row, "used_key_ids")?.is_empty()
        || !required_string_array(row, "lookup_key_ids")?.is_empty()
        || !required_optional_i64_array(row, "lookup_retired_at_unix_ms")?.is_empty()
        || !required_optional_i64_array(row, "lookup_destroy_after_unix_ms")?.is_empty()
    {
        return Err(PostgresKeyringError::ProtocolDrift);
    }
    Ok(RuntimeWriteSnapshot {
        binding,
        active_key_id,
        active_write_remaining_ms: remaining,
    })
}

fn parse_reader_lookup_snapshot(
    row: &Row,
    expected_lookup_ids: &[String],
) -> Result<ReaderLookupSnapshot, PostgresKeyringError> {
    let binding = parse_authoritative_binding(row)?;
    let authoritative_time = parse_authoritative_time(row)?;
    let lookup_key_ids = required_string_array(row, "lookup_key_ids")?;
    let lookup_retired = required_optional_i64_array(row, "lookup_retired_at_unix_ms")?;
    let lookup_destroy = required_optional_i64_array(row, "lookup_destroy_after_unix_ms")?;
    if lookup_key_ids != expected_lookup_ids
        || lookup_key_ids.len() != lookup_retired.len()
        || lookup_key_ids.len() != lookup_destroy.len()
        || optional_string(row, "metadata_canonical")?.is_some()
        || optional_string(row, "active_key_id")?.is_some()
        || optional_i64(row, "active_since_unix_ms")?.is_some()
        || optional_i64(row, "active_write_deadline_unix_ms")?.is_some()
        || optional_i64(row, "audit_event_retention_ms")?.is_some()
        || !required_string_array(row, "retained_key_ids")?.is_empty()
        || !required_i64_array(row, "retained_retired_at_unix_ms")?.is_empty()
        || !required_i64_array(row, "retained_destroy_after_unix_ms")?.is_empty()
        || optional_i64(row, "used_key_id_count")?.is_some()
        || optional_hash(row, "used_key_ids_digest")?.is_some()
        || !required_string_array(row, "used_key_ids")?.is_empty()
        || optional_i64(row, "active_write_remaining_ms")?.is_some()
    {
        return Err(PostgresKeyringError::ProtocolDrift);
    }
    let mut active_count = 0_usize;
    let mut lookup_epochs = Vec::with_capacity(lookup_key_ids.len());
    for ((key_id, retired), destroy) in lookup_key_ids
        .into_iter()
        .zip(lookup_retired)
        .zip(lookup_destroy)
    {
        let key_id =
            AuditPseudonymKeyId::parse(key_id).map_err(|_| PostgresKeyringError::ProtocolDrift)?;
        match (retired, destroy) {
            (None, None) => {
                active_count += 1;
                lookup_epochs.push(AuditPseudonymLookupEpoch::Active { key_id });
            }
            (Some(retired), Some(destroy)) => {
                let epoch = RetainedAuditPseudonymKeyEpoch::new(key_id, retired, destroy)
                    .map_err(|_| PostgresKeyringError::ProtocolDrift)?;
                if epoch.destroy_after_unix_ms() <= authoritative_time.unix_ms() {
                    return Err(PostgresKeyringError::ProtocolDrift);
                }
                lookup_epochs.push(AuditPseudonymLookupEpoch::Retained(epoch));
            }
            _ => return Err(PostgresKeyringError::ProtocolDrift),
        }
    }
    if active_count > 1 {
        return Err(PostgresKeyringError::ProtocolDrift);
    }
    Ok(ReaderLookupSnapshot {
        binding,
        lookup_epochs,
    })
}

fn parse_authoritative_binding(
    row: &Row,
) -> Result<AuthoritativeKeyringBinding, PostgresKeyringError> {
    let generation = required_i64(row, "generation")?;
    if !(1..=9_007_199_254_740_991).contains(&generation) {
        return Err(PostgresKeyringError::ProtocolDrift);
    }
    Ok(AuthoritativeKeyringBinding {
        generation,
        digest: required_hash(row, "metadata_digest")?,
    })
}

fn parse_authoritative_time(row: &Row) -> Result<AuditPseudonymTime, PostgresKeyringError> {
    AuditPseudonymTime::from_unix_ms(required_i64(row, "authoritative_now_unix_ms")?)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn retained_epochs(
    key_ids: &[String],
    retired_at: &[i64],
    destroy_after: &[i64],
) -> Result<Vec<RetainedAuditPseudonymKeyEpoch>, PostgresKeyringError> {
    if key_ids.len() != retired_at.len() || key_ids.len() != destroy_after.len() {
        return Err(PostgresKeyringError::ProtocolDrift);
    }
    key_ids
        .iter()
        .zip(retired_at)
        .zip(destroy_after)
        .map(|((key_id, retired_at), destroy_after)| {
            RetainedAuditPseudonymKeyEpoch::new(
                AuditPseudonymKeyId::parse(key_id.clone())
                    .map_err(|_| PostgresKeyringError::ProtocolDrift)?,
                *retired_at,
                *destroy_after,
            )
            .map_err(|_| PostgresKeyringError::ProtocolDrift)
        })
        .collect()
}

pub(super) fn canonical_metadata(
    metadata: &AuditPseudonymKeyringMetadata,
) -> Result<String, PostgresKeyringError> {
    let mut canonical = String::with_capacity(512);
    write!(
        canonical,
        "{{\"active_key_id\":\"{}\",\"active_since_unix_ms\":{},\
         \"active_write_deadline_unix_ms\":{},\"audit_event_retention_ms\":{},\
         \"generation\":{},\"retained_keys\":[",
        metadata.active_key_id().as_str(),
        metadata.active_since_unix_ms(),
        metadata.active_write_deadline_unix_ms(),
        metadata.audit_event_retention_ms(),
        metadata.generation(),
    )
    .map_err(|_| PostgresKeyringError::InvalidMetadata)?;
    for (index, epoch) in metadata.retained_keys().iter().enumerate() {
        if index > 0 {
            canonical.push(',');
        }
        write!(
            canonical,
            "{{\"destroy_after_unix_ms\":{},\"key_id\":\"{}\",\
             \"retired_at_unix_ms\":{}}}",
            epoch.destroy_after_unix_ms(),
            epoch.key_id().as_str(),
            epoch.retired_at_unix_ms(),
        )
        .map_err(|_| PostgresKeyringError::InvalidMetadata)?;
    }
    write!(canonical, "],\"schema\":\"{KEYRING_SCHEMA_V1}\"}}")
        .map_err(|_| PostgresKeyringError::InvalidMetadata)?;
    Ok(canonical)
}

fn used_key_id_history_digest(sorted_ids: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HISTORY_DIGEST_DOMAIN_V1);
    hasher.update([0]);
    hasher.update(
        u64::try_from(sorted_ids.len())
            .expect("bounded history count fits u64")
            .to_be_bytes(),
    );
    for key_id in sorted_ids {
        hasher.update(
            u16::try_from(key_id.len())
                .expect("validated key ids fit u16")
                .to_be_bytes(),
        );
        hasher.update(key_id.as_bytes());
    }
    hasher.finalize().into()
}

fn verify_transition_result(
    row: &Row,
    expected_generation: i64,
    expected_digest: &[u8; 32],
) -> Result<(), PostgresKeyringError> {
    if required_i64(row, "stored_generation")? != expected_generation
        || required_hash(row, "stored_metadata_digest")? != *expected_digest
    {
        return Err(PostgresKeyringError::ProtocolDrift);
    }
    Ok(())
}

fn required_str<'a>(row: &'a Row, column: &str) -> Result<&'a str, PostgresKeyringError> {
    row.try_get(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn required_string(row: &Row, column: &str) -> Result<String, PostgresKeyringError> {
    row.try_get(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn optional_string(row: &Row, column: &str) -> Result<Option<String>, PostgresKeyringError> {
    row.try_get(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn required_i64(row: &Row, column: &str) -> Result<i64, PostgresKeyringError> {
    row.try_get(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn optional_i64(row: &Row, column: &str) -> Result<Option<i64>, PostgresKeyringError> {
    row.try_get(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn required_hash(row: &Row, column: &str) -> Result<[u8; 32], PostgresKeyringError> {
    row.try_get::<_, &[u8]>(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)?
        .try_into()
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn optional_hash(row: &Row, column: &str) -> Result<Option<[u8; 32]>, PostgresKeyringError> {
    row.try_get::<_, Option<&[u8]>>(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)?
        .map(|digest| {
            digest
                .try_into()
                .map_err(|_| PostgresKeyringError::ProtocolDrift)
        })
        .transpose()
}

fn required_string_array(row: &Row, column: &str) -> Result<Vec<String>, PostgresKeyringError> {
    row.try_get(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn required_i64_array(row: &Row, column: &str) -> Result<Vec<i64>, PostgresKeyringError> {
    row.try_get(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn required_optional_i64_array(
    row: &Row,
    column: &str,
) -> Result<Vec<Option<i64>>, PostgresKeyringError> {
    row.try_get(column)
        .map_err(|_| PostgresKeyringError::ProtocolDrift)
}

fn map_rotation_contract_error(error: AuditPseudonymKeyringError) -> PostgresKeyringError {
    match error {
        AuditPseudonymKeyringError::IncompleteKeyIdHistory => {
            PostgresKeyringError::IncompleteHistory
        }
        AuditPseudonymKeyringError::ReusedKeyId => PostgresKeyringError::ReusedKeyId,
        _ => PostgresKeyringError::InvalidRotation,
    }
}

fn map_maintenance_contract_error(error: AuditPseudonymKeyringError) -> PostgresKeyringError {
    match error {
        AuditPseudonymKeyringError::IncompleteKeyIdHistory => {
            PostgresKeyringError::IncompleteHistory
        }
        _ => PostgresKeyringError::InvalidMaintenance,
    }
}

fn map_runtime_capability_error(error: RuntimeCapabilityError) -> PostgresKeyringError {
    match error {
        RuntimeCapabilityError::WrongRuntimeIdentity => PostgresKeyringError::WrongRuntimeIdentity,
        RuntimeCapabilityError::Drift => PostgresKeyringError::CapabilityDrift,
        RuntimeCapabilityError::Unavailable => PostgresKeyringError::Unavailable,
    }
}

fn map_postgres_error(error: tokio_postgres::Error) -> PostgresKeyringError {
    match error
        .as_db_error()
        .map(|database_error| database_error.code().code())
    {
        Some("42501") => PostgresKeyringError::WrongRuntimeIdentity,
        Some("54000") => PostgresKeyringError::HistoryLimitReached,
        Some("55000") => PostgresKeyringError::CapabilityDrift,
        _ => PostgresKeyringError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> AuditPseudonymKeyId {
        AuditPseudonymKeyId::parse(value).expect("valid test key id")
    }

    fn retained(key_id: &str, retired: i64, destroy: i64) -> RetainedAuditPseudonymKeyEpoch {
        RetainedAuditPseudonymKeyEpoch::new(id(key_id), retired, destroy)
            .expect("valid retained epoch")
    }

    fn metadata(
        generation: u64,
        active: &str,
        since: i64,
        deadline: i64,
        retention: i64,
        retained: Vec<RetainedAuditPseudonymKeyEpoch>,
    ) -> AuditPseudonymKeyringMetadata {
        AuditPseudonymKeyringMetadata::new(
            generation,
            id(active),
            since,
            deadline,
            retention,
            retained,
        )
        .expect("valid metadata")
    }

    #[test]
    fn canonical_metadata_matches_the_pure_binding() {
        let current = metadata(
            3,
            "epoch-3",
            3_000,
            9_000,
            2_000,
            vec![
                retained("epoch-1", 1_000, 5_000),
                retained("epoch-2", 3_000, 6_000),
            ],
        );
        let encoded = EncodedMetadata::from_metadata(current).expect("encoded");
        let calculated: [u8; 32] = Sha256::digest(encoded.canonical.as_bytes()).into();
        assert_eq!(calculated, encoded.digest);
    }

    #[test]
    fn history_digest_is_length_framed_and_detects_omission() {
        let left = used_key_id_history_digest(&["a".into(), "bc".into()]);
        let ambiguous_without_lengths = used_key_id_history_digest(&["ab".into(), "c".into()]);
        let omitted = used_key_id_history_digest(&["a".into()]);
        assert_ne!(left, ambiguous_without_lengths);
        assert_ne!(left, omitted);
    }

    #[test]
    fn lookup_proof_is_exact_bounded_and_redacted() {
        let proof = AuthorizedAuditPseudonymLookupSubset::for_test([id("epoch-2"), id("epoch-1")])
            .expect("proof");
        assert_eq!(proof.key_ids, ["epoch-1", "epoch-2"]);
        assert!(!format!("{proof:?}").contains("epoch-1"));
        assert!(AuthorizedAuditPseudonymLookupSubset::for_test([]).is_err());
    }

    #[test]
    fn candidate_and_epoch_debug_are_value_free() {
        let current = metadata(1, "sensitive-looking-id", 1_000, 2_000, 500, vec![]);
        let binding = current.binding().expect("binding");
        let authority = AuditPseudonymWriteAuthority {
            active_key_id: id("sensitive-looking-id"),
            metadata_binding: AuthoritativeKeyringBinding {
                generation: i64::try_from(binding.generation()).expect("generation"),
                digest: *binding.digest(),
            },
            chain_key_epoch_id: AuditChainKeyEpochId::parse("test-chain-epoch").expect("epoch"),
            keyring_lock_key: AuditPseudonymKeyringLockKey::new(7_221_091_443).expect("lock key"),
            local_deadline: Instant::now() + Duration::from_secs(1),
        };
        assert!(!format!("{authority:?}").contains("sensitive-looking-id"));
        let epoch = authority.authorize_use().expect("live");
        assert!(!format!("{epoch:?}").contains("sensitive-looking-id"));
    }

    #[test]
    fn local_deadline_conversion_uses_checked_platform_boundaries() {
        let anchor = Instant::now();
        assert_eq!(
            conservative_local_deadline(anchor, -1),
            Err(PostgresKeyringError::ProtocolDrift)
        );
        assert_eq!(
            conservative_local_deadline(anchor, i64::MAX),
            anchor
                .checked_add(Duration::from_millis(i64::MAX as u64))
                .ok_or(PostgresKeyringError::ProtocolDrift)
        );
    }
}
