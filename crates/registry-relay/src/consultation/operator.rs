// SPDX-License-Identifier: Apache-2.0
//! Bounded offline operator workflows for governed consultations.
//!
//! This module intentionally exposes one country-deployment bootstrap journey,
//! not a general migration framework. PostgreSQL databases and roles are
//! provisioned by the DBA. Relay only installs or attests its owned schema,
//! binds the pre-created authority identities, and initializes generation one
//! of the audit-pseudonym keyring.

use std::{collections::BTreeSet, fmt, future::Future, time::Duration};

use registry_platform_audit::pseudonym_keyring::AuditPseudonymKeyId;
use serde::Serialize;
use thiserror::Error;
use tokio_postgres::{Client, Row};

use crate::{
    config::{Config, ConsultationConfig},
    state_plane::{
        install_postgres_state_plane_v1, open_operator_connection, AuditChainKeyEpochId,
        AuditPseudonymKeyringLockKey, AuditPseudonymMaintenanceDatabaseRole,
        AuditPseudonymReaderDatabaseRole, ConsultationStatePlaneRuntimeError,
        KeyringInitializationOutcome, PostgresAuditPseudonymKeyringMaintenance,
        PostgresAuditPseudonymKeyringReader, PostgresAuditPseudonymKeyringRuntime,
        PostgresKeyringError, RuntimeDatabaseRole, ServingFenceLockKey, StatePlaneInstallError,
    },
};

const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;
const MAX_EXACT_JSON_INTEGER: i64 = 9_007_199_254_740_991;
const DATABASE_CHALLENGE_KEY_COUNT: usize = 2;
const DATABASE_CHALLENGE_ATTEMPTS: usize = 4;
const OPERATOR_DATABASE_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATOR_DATABASE_INSTALL_TIMEOUT: Duration = Duration::from_secs(35);

/// Complete input for the one supported state-plane bootstrap operation.
///
/// Database URL fields are environment-reference names. URL values are never
/// accepted by this API and are resolved only inside the bounded connector.
pub struct BootstrapStateRequest<'config> {
    pub config: &'config Config,
    pub migration_database_url_env: &'config str,
    pub owner_role: &'config str,
    pub keyring_maintenance_database_url_env: &'config str,
    pub keyring_reader_database_url_env: &'config str,
    pub active_key_id: &'config str,
    pub active_write_deadline_unix_ms: i64,
    pub audit_event_retention_ms: i64,
}

impl fmt::Debug for BootstrapStateRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapStateRequest")
            .field("config", &"<loaded>")
            .field("migration_database_url_env", &"<configured>")
            .field("owner_role", &"<configured>")
            .field("keyring_maintenance_database_url_env", &"<configured>")
            .field("keyring_reader_database_url_env", &"<configured>")
            .field("active_key_id", &"<configured>")
            .field("lifecycle", &"<configured>")
            .finish()
    }
}

/// Value-free JSON result for automation and runbooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BootstrapStateResult {
    pub schema: &'static str,
    pub state_plane: BootstrapStatePlaneStatus,
    pub keyring: BootstrapKeyringStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapStatePlaneStatus {
    InstalledOrAttested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapKeyringStatus {
    Initialized,
    Identical,
}

/// Closed bootstrap failures. No variant stores a path, URL, role, key id, or
/// environment-reference name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BootstrapStateError {
    #[error("Relay consultation bootstrap requires consultation configuration")]
    ConsultationDisabled,
    #[error("Relay consultation bootstrap input is invalid")]
    InvalidInput,
    #[error("Relay consultation bootstrap active key is not declared")]
    ActiveKeyNotDeclared,
    #[error("Relay consultation bootstrap database URL reference is unavailable")]
    DatabaseReferenceUnavailable,
    #[error("Relay consultation bootstrap database connection configuration was rejected")]
    DatabaseConfigurationRejected,
    #[error("Relay consultation bootstrap database is unavailable")]
    DatabaseUnavailable,
    #[error("Relay consultation bootstrap database identities are invalid")]
    InvalidDatabaseIdentity,
    #[error("Relay consultation bootstrap databases do not identify one state plane")]
    DatabaseMismatch,
    #[error("Relay consultation bootstrap authority roles must be distinct")]
    AuthorityRoleCollision,
    #[error("Relay consultation bootstrap database authority configuration was rejected")]
    AuthorityConfigurationRejected,
    #[error("Relay consultation state-plane installation was rejected")]
    InstallationRejected,
    #[error("Relay consultation state-plane capability has drifted")]
    CapabilityDrift,
    #[error("Relay consultation audit-pseudonym keyring differs from the requested bootstrap")]
    KeyringDrift,
    #[error("Relay consultation audit-pseudonym lifecycle is invalid")]
    InvalidKeyringLifecycle,
    #[error("Relay consultation audit-pseudonym keyring is unavailable")]
    KeyringUnavailable,
}

/// Install or attest the Relay-owned state plane and initialize its one active
/// audit-pseudonym epoch.
pub async fn bootstrap_state(
    request: BootstrapStateRequest<'_>,
) -> Result<BootstrapStateResult, BootstrapStateError> {
    let consultation = request
        .config
        .consultation
        .as_ref()
        .ok_or(BootstrapStateError::ConsultationDisabled)?;
    let validated = ValidatedBootstrapRequest::parse(consultation, &request)?;

    let (
        mut migration_connection,
        mut runtime_connection,
        mut maintenance_connection,
        mut reader_connection,
    ) = tokio::try_join!(
        open_operator_connection(
            &consultation.state_plane,
            request.migration_database_url_env,
        ),
        open_operator_connection(
            &consultation.state_plane,
            consultation.state_plane.database_url_env.as_str(),
        ),
        open_operator_connection(
            &consultation.state_plane,
            request.keyring_maintenance_database_url_env,
        ),
        open_operator_connection(
            &consultation.state_plane,
            request.keyring_reader_database_url_env,
        ),
    )
    .map_err(map_connection_error)?;

    let (migration_identity, runtime_identity, maintenance_identity, reader_identity) = tokio::try_join!(
        direct_login_identity(migration_connection.client()),
        direct_login_identity(runtime_connection.client()),
        direct_login_identity(maintenance_connection.client()),
        direct_login_identity(reader_connection.client()),
    )?;
    ensure_one_database([
        &migration_identity,
        &runtime_identity,
        &maintenance_identity,
        &reader_identity,
    ])?;
    let database_challenge = acquire_database_challenge(migration_connection.client()).await?;
    attest_database_challenge(runtime_connection.client(), database_challenge).await?;
    attest_database_challenge(maintenance_connection.client(), database_challenge).await?;
    attest_database_challenge(reader_connection.client(), database_challenge).await?;
    ensure_distinct_role_oids([
        runtime_identity.role_oid,
        maintenance_identity.role_oid,
        reader_identity.role_oid,
    ])?;

    let runtime_role = RuntimeDatabaseRole::parse(&runtime_identity.role_name)
        .map_err(|_| BootstrapStateError::InvalidDatabaseIdentity)?;
    let maintenance_role =
        AuditPseudonymMaintenanceDatabaseRole::parse(&maintenance_identity.role_name)
            .map_err(|_| BootstrapStateError::InvalidDatabaseIdentity)?;
    let reader_role = AuditPseudonymReaderDatabaseRole::parse(&reader_identity.role_name)
        .map_err(|_| BootstrapStateError::InvalidDatabaseIdentity)?;

    bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::AuthorityConfigurationRejected,
        migration_connection
            .client()
            .batch_execute(&format!("SET ROLE \"{}\"", request.owner_role)),
    )
    .await?
    .map_err(|_| BootstrapStateError::AuthorityConfigurationRejected)?;
    let owner_identity = current_role_identity(migration_connection.client()).await?;
    if owner_identity.role_name != request.owner_role {
        return Err(BootstrapStateError::InvalidDatabaseIdentity);
    }
    ensure_distinct_role_oids([
        owner_identity.role_oid,
        runtime_identity.role_oid,
        maintenance_identity.role_oid,
        reader_identity.role_oid,
    ])?;

    bounded_database_operation(
        OPERATOR_DATABASE_INSTALL_TIMEOUT,
        BootstrapStateError::DatabaseUnavailable,
        install_postgres_state_plane_v1(
            migration_connection.client_mut(),
            &runtime_role,
            &validated.chain_key_epoch_id,
            validated.serving_fence_lock_key,
            &maintenance_role,
            &reader_role,
            validated.keyring_lock_key,
        ),
    )
    .await?
    .map_err(map_install_error)?;
    bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::DatabaseUnavailable,
        migration_connection.client().batch_execute("RESET ROLE"),
    )
    .await?
    .map_err(|_| BootstrapStateError::DatabaseUnavailable)?;

    let runtime_keyring = bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::KeyringUnavailable,
        PostgresAuditPseudonymKeyringRuntime::connect(
            runtime_connection.take_client(),
            validated.chain_key_epoch_id.clone(),
            validated.keyring_lock_key,
        ),
    )
    .await?
    .map_err(map_keyring_error)?;
    let maintenance_keyring = bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::KeyringUnavailable,
        PostgresAuditPseudonymKeyringMaintenance::connect(
            maintenance_connection.take_client(),
            validated.chain_key_epoch_id.clone(),
            validated.keyring_lock_key,
        ),
    )
    .await?
    .map_err(map_keyring_error)?;
    let _reader_keyring = bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::KeyringUnavailable,
        PostgresAuditPseudonymKeyringReader::connect(
            reader_connection.take_client(),
            validated.chain_key_epoch_id,
            validated.keyring_lock_key,
        ),
    )
    .await?
    .map_err(map_keyring_error)?;

    let initialization = bounded_database_operation(
        OPERATOR_DATABASE_INSTALL_TIMEOUT,
        BootstrapStateError::KeyringUnavailable,
        maintenance_keyring.initialize_or_attest_from_postgres_time(
            validated.active_key_id.clone(),
            request.active_write_deadline_unix_ms,
            request.audit_event_retention_ms,
        ),
    )
    .await?
    .map_err(map_keyring_error)?;
    let current_epoch = bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::KeyringUnavailable,
        runtime_keyring.current_write_authority(),
    )
    .await?
    .and_then(|authority| authority.authorize_use())
    .map_err(map_keyring_error)?;
    if current_epoch.key_id() != &validated.active_key_id {
        return Err(BootstrapStateError::KeyringDrift);
    }
    release_database_challenge(migration_connection.client(), database_challenge).await?;

    Ok(BootstrapStateResult {
        schema: "registry.relay.consultation-bootstrap-state.v1",
        state_plane: BootstrapStatePlaneStatus::InstalledOrAttested,
        keyring: match initialization {
            KeyringInitializationOutcome::Initialized => BootstrapKeyringStatus::Initialized,
            KeyringInitializationOutcome::Identical => BootstrapKeyringStatus::Identical,
        },
    })
}

struct ValidatedBootstrapRequest {
    chain_key_epoch_id: AuditChainKeyEpochId,
    serving_fence_lock_key: ServingFenceLockKey,
    keyring_lock_key: AuditPseudonymKeyringLockKey,
    active_key_id: AuditPseudonymKeyId,
}

impl ValidatedBootstrapRequest {
    fn parse(
        consultation: &ConsultationConfig,
        request: &BootstrapStateRequest<'_>,
    ) -> Result<Self, BootstrapStateError> {
        if !is_portable_environment_name(request.migration_database_url_env)
            || !is_portable_environment_name(request.keyring_maintenance_database_url_env)
            || !is_portable_environment_name(request.keyring_reader_database_url_env)
            || !is_database_role_name(request.owner_role)
            || !(1..=MAX_EXACT_JSON_INTEGER).contains(&request.active_write_deadline_unix_ms)
            || !(1..=MAX_EXACT_JSON_INTEGER).contains(&request.audit_event_retention_ms)
        {
            return Err(BootstrapStateError::InvalidInput);
        }
        let active_key_id = AuditPseudonymKeyId::parse(request.active_key_id.to_owned())
            .map_err(|_| BootstrapStateError::InvalidInput)?;
        if !consultation
            .audit_pseudonym_materials
            .entries()
            .iter()
            .any(|entry| entry.key_id == active_key_id)
        {
            return Err(BootstrapStateError::ActiveKeyNotDeclared);
        }
        if consultation.state_plane.serving_fence_lock_key
            == consultation.state_plane.audit_pseudonym_keyring_lock_key
        {
            return Err(BootstrapStateError::InvalidInput);
        }
        Ok(Self {
            chain_key_epoch_id: AuditChainKeyEpochId::parse(
                &consultation.state_plane.chain_key_epoch_id,
            )
            .map_err(|_| BootstrapStateError::InvalidInput)?,
            serving_fence_lock_key: ServingFenceLockKey::new(
                consultation.state_plane.serving_fence_lock_key,
            )
            .map_err(|_| BootstrapStateError::InvalidInput)?,
            keyring_lock_key: AuditPseudonymKeyringLockKey::new(
                consultation.state_plane.audit_pseudonym_keyring_lock_key,
            )
            .map_err(|_| BootstrapStateError::InvalidInput)?,
            active_key_id,
        })
    }
}

struct DatabaseIdentity {
    role_name: String,
    role_oid: i64,
    database_oid: i64,
    database_name: String,
}

async fn direct_login_identity(client: &Client) -> Result<DatabaseIdentity, BootstrapStateError> {
    let row = bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::DatabaseUnavailable,
        client.query_one(
            "SELECT session_user::text AS session_role, current_user::text AS current_role, \
                    role_row.oid::bigint AS role_oid, database_row.oid::bigint AS database_oid, \
                    current_database()::text AS database_name \
             FROM pg_catalog.pg_roles AS role_row \
             JOIN pg_catalog.pg_database AS database_row \
               ON database_row.datname = current_database() \
             WHERE role_row.rolname = session_user",
            &[],
        ),
    )
    .await?
    .map_err(|_| BootstrapStateError::InvalidDatabaseIdentity)?;
    let session_role = required_string(&row, "session_role")?;
    if required_string(&row, "current_role")? != session_role {
        return Err(BootstrapStateError::InvalidDatabaseIdentity);
    }
    Ok(DatabaseIdentity {
        role_name: session_role,
        role_oid: required_i64(&row, "role_oid")?,
        database_oid: required_i64(&row, "database_oid")?,
        database_name: required_string(&row, "database_name")?,
    })
}

async fn current_role_identity(client: &Client) -> Result<DatabaseIdentity, BootstrapStateError> {
    let row = bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::DatabaseUnavailable,
        client.query_one(
            "SELECT current_user::text AS current_role, role_row.oid::bigint AS role_oid, \
                    database_row.oid::bigint AS database_oid, \
                    current_database()::text AS database_name \
             FROM pg_catalog.pg_roles AS role_row \
             JOIN pg_catalog.pg_database AS database_row \
               ON database_row.datname = current_database() \
             WHERE role_row.rolname = current_user",
            &[],
        ),
    )
    .await?
    .map_err(|_| BootstrapStateError::InvalidDatabaseIdentity)?;
    Ok(DatabaseIdentity {
        role_name: required_string(&row, "current_role")?,
        role_oid: required_i64(&row, "role_oid")?,
        database_oid: required_i64(&row, "database_oid")?,
        database_name: required_string(&row, "database_name")?,
    })
}

fn ensure_one_database(identities: [&DatabaseIdentity; 4]) -> Result<(), BootstrapStateError> {
    let database_oid = identities[0].database_oid;
    let database_name = &identities[0].database_name;
    if identities.iter().any(|identity| {
        identity.database_oid != database_oid || &identity.database_name != database_name
    }) {
        return Err(BootstrapStateError::DatabaseMismatch);
    }
    Ok(())
}

type DatabaseChallenge = [i64; DATABASE_CHALLENGE_KEY_COUNT];

async fn bounded_database_operation<F, T>(
    timeout: Duration,
    timeout_error: BootstrapStateError,
    future: F,
) -> Result<T, BootstrapStateError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| timeout_error)
}

async fn acquire_database_challenge(
    migration_client: &Client,
) -> Result<DatabaseChallenge, BootstrapStateError> {
    'attempt: for _ in 0..DATABASE_CHALLENGE_ATTEMPTS {
        let challenge = fresh_database_challenge()?;
        let mut acquired = Vec::with_capacity(DATABASE_CHALLENGE_KEY_COUNT);
        for key in challenge {
            if !try_advisory_lock(migration_client, key).await? {
                for acquired_key in acquired {
                    advisory_unlock(migration_client, acquired_key).await?;
                }
                continue 'attempt;
            }
            acquired.push(key);
        }
        return Ok(challenge);
    }
    Err(BootstrapStateError::DatabaseUnavailable)
}

async fn attest_database_challenge(
    client: &Client,
    challenge: DatabaseChallenge,
) -> Result<(), BootstrapStateError> {
    let mut mismatch = false;
    for key in challenge {
        if try_advisory_lock(client, key).await? {
            advisory_unlock(client, key).await?;
            mismatch = true;
        }
    }
    if mismatch {
        return Err(BootstrapStateError::DatabaseMismatch);
    }
    Ok(())
}

async fn release_database_challenge(
    migration_client: &Client,
    challenge: DatabaseChallenge,
) -> Result<(), BootstrapStateError> {
    for key in challenge {
        advisory_unlock(migration_client, key).await?;
    }
    Ok(())
}

async fn try_advisory_lock(client: &Client, key: i64) -> Result<bool, BootstrapStateError> {
    bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::DatabaseUnavailable,
        client.query_one(
            "SELECT pg_catalog.pg_try_advisory_lock($1) AS acquired",
            &[&key],
        ),
    )
    .await?
    .map_err(|_| BootstrapStateError::DatabaseUnavailable)?
    .try_get("acquired")
    .map_err(|_| BootstrapStateError::DatabaseUnavailable)
}

async fn advisory_unlock(client: &Client, key: i64) -> Result<(), BootstrapStateError> {
    let unlocked: bool = bounded_database_operation(
        OPERATOR_DATABASE_OPERATION_TIMEOUT,
        BootstrapStateError::DatabaseUnavailable,
        client.query_one(
            "SELECT pg_catalog.pg_advisory_unlock($1) AS unlocked",
            &[&key],
        ),
    )
    .await?
    .map_err(|_| BootstrapStateError::DatabaseUnavailable)?
    .try_get("unlocked")
    .map_err(|_| BootstrapStateError::DatabaseUnavailable)?;
    if !unlocked {
        return Err(BootstrapStateError::DatabaseUnavailable);
    }
    Ok(())
}

fn fresh_database_challenge() -> Result<DatabaseChallenge, BootstrapStateError> {
    for _ in 0..DATABASE_CHALLENGE_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| BootstrapStateError::DatabaseUnavailable)?;
        if let Some(challenge) = database_challenge_from_bytes(bytes) {
            return Ok(challenge);
        }
    }
    Err(BootstrapStateError::DatabaseUnavailable)
}

fn database_challenge_from_bytes(bytes: [u8; 16]) -> Option<DatabaseChallenge> {
    let first = i64::from_be_bytes(bytes[..8].try_into().expect("fixed first key width"));
    let second = i64::from_be_bytes(bytes[8..].try_into().expect("fixed second key width"));
    (first != second).then_some([first, second])
}

fn ensure_distinct_role_oids<const N: usize>(
    role_oids: [i64; N],
) -> Result<(), BootstrapStateError> {
    let distinct = role_oids.into_iter().collect::<BTreeSet<_>>();
    if distinct.len() != N {
        return Err(BootstrapStateError::AuthorityRoleCollision);
    }
    Ok(())
}

fn required_string(row: &Row, column: &str) -> Result<String, BootstrapStateError> {
    row.try_get(column)
        .map_err(|_| BootstrapStateError::InvalidDatabaseIdentity)
}

fn required_i64(row: &Row, column: &str) -> Result<i64, BootstrapStateError> {
    row.try_get(column)
        .map_err(|_| BootstrapStateError::InvalidDatabaseIdentity)
}

fn is_portable_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    value.len() <= MAX_ENVIRONMENT_NAME_BYTES
        && matches!(first, b'A'..=b'Z' | b'a'..=b'z' | b'_')
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn is_database_role_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    value.len() <= 63
        && (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

const fn map_connection_error(error: ConsultationStatePlaneRuntimeError) -> BootstrapStateError {
    match error {
        ConsultationStatePlaneRuntimeError::DatabaseUrlUnavailable => {
            BootstrapStateError::DatabaseReferenceUnavailable
        }
        ConsultationStatePlaneRuntimeError::InvalidDatabaseUrl
        | ConsultationStatePlaneRuntimeError::TlsRequired
        | ConsultationStatePlaneRuntimeError::InvalidRootCertificatePath
        | ConsultationStatePlaneRuntimeError::RootCertificateUnavailable
        | ConsultationStatePlaneRuntimeError::RootCertificateTooLarge
        | ConsultationStatePlaneRuntimeError::InvalidRootCertificate
        | ConsultationStatePlaneRuntimeError::InvalidTlsConfiguration => {
            BootstrapStateError::DatabaseConfigurationRejected
        }
        ConsultationStatePlaneRuntimeError::DatabaseUnavailable
        | ConsultationStatePlaneRuntimeError::InvalidChainKeyEpoch
        | ConsultationStatePlaneRuntimeError::InvalidServingFenceLockKey
        | ConsultationStatePlaneRuntimeError::InvalidPseudonymKeyringLockKey
        | ConsultationStatePlaneRuntimeError::LockKeyCollision
        | ConsultationStatePlaneRuntimeError::UnkeyedAuditChain
        | ConsultationStatePlaneRuntimeError::WrongRuntimeIdentity
        | ConsultationStatePlaneRuntimeError::CapabilityDrift
        | ConsultationStatePlaneRuntimeError::DurableAuditUnavailable
        | ConsultationStatePlaneRuntimeError::QuotaUnavailable
        | ConsultationStatePlaneRuntimeError::PseudonymKeyringUnavailable
        | ConsultationStatePlaneRuntimeError::PseudonymKeyringUninitialized
        | ConsultationStatePlaneRuntimeError::ServingFenceContended
        | ConsultationStatePlaneRuntimeError::ServingFenceUnavailable
        | ConsultationStatePlaneRuntimeError::TakeoverRecoveryFailed
        | ConsultationStatePlaneRuntimeError::ShutdownAlreadyStarted
        | ConsultationStatePlaneRuntimeError::ShutdownFailed => {
            BootstrapStateError::DatabaseUnavailable
        }
    }
}

const fn map_install_error(error: StatePlaneInstallError) -> BootstrapStateError {
    match error {
        StatePlaneInstallError::AuthorityRoleCollision => {
            BootstrapStateError::AuthorityRoleCollision
        }
        StatePlaneInstallError::CapabilityDrift => BootstrapStateError::CapabilityDrift,
        StatePlaneInstallError::InvalidRuntimeRole
        | StatePlaneInstallError::InvalidPseudonymMaintenanceRole
        | StatePlaneInstallError::InvalidPseudonymReaderRole => {
            BootstrapStateError::InvalidDatabaseIdentity
        }
        StatePlaneInstallError::InvalidPseudonymKeyringLockKey
        | StatePlaneInstallError::PseudonymKeyringLockKeyCollision
        | StatePlaneInstallError::InvalidChainKeyEpochId => BootstrapStateError::InvalidInput,
        StatePlaneInstallError::InvalidMigrationAuthority
        | StatePlaneInstallError::OwnerRoleNotIsolated
        | StatePlaneInstallError::RuntimeRoleNotIsolated
        | StatePlaneInstallError::PseudonymMaintenanceRoleNotIsolated
        | StatePlaneInstallError::PseudonymReaderRoleNotIsolated
        | StatePlaneInstallError::UnsafeDatabaseConfiguration => {
            BootstrapStateError::AuthorityConfigurationRejected
        }
        StatePlaneInstallError::Unavailable => BootstrapStateError::DatabaseUnavailable,
    }
}

const fn map_keyring_error(error: PostgresKeyringError) -> BootstrapStateError {
    match error {
        PostgresKeyringError::AlreadyInitialized => BootstrapStateError::KeyringDrift,
        PostgresKeyringError::WrongRuntimeIdentity => BootstrapStateError::InvalidDatabaseIdentity,
        PostgresKeyringError::CapabilityDrift | PostgresKeyringError::ProtocolDrift => {
            BootstrapStateError::CapabilityDrift
        }
        PostgresKeyringError::InvalidMetadata
        | PostgresKeyringError::NotActive
        | PostgresKeyringError::WriteDeadlineReached => {
            BootstrapStateError::InvalidKeyringLifecycle
        }
        PostgresKeyringError::Uninitialized
        | PostgresKeyringError::RetainedEpochExpired
        | PostgresKeyringError::UnauthorizedLookupSubset
        | PostgresKeyringError::StaleExpectedState
        | PostgresKeyringError::IncompleteHistory
        | PostgresKeyringError::ReusedKeyId
        | PostgresKeyringError::HistoryLimitReached
        | PostgresKeyringError::InvalidRotation
        | PostgresKeyringError::InvalidMaintenance => BootstrapStateError::KeyringDrift,
        PostgresKeyringError::Unavailable => BootstrapStateError::KeyringUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_references_and_role_names_are_closed() {
        assert!(is_portable_environment_name("RELAY_STATE_MIGRATION_URL"));
        assert!(!is_portable_environment_name(
            "postgresql://sentinel:secret@example.test/state"
        ));
        assert!(!is_portable_environment_name(&"A".repeat(129)));
        assert!(is_database_role_name("relay_state_owner"));
        assert!(!is_database_role_name("relay-state-owner"));
        assert!(!is_database_role_name("\"; SELECT sentinel"));
    }

    #[test]
    fn result_json_contains_statuses_only() {
        let result = BootstrapStateResult {
            schema: "registry.relay.consultation-bootstrap-state.v1",
            state_plane: BootstrapStatePlaneStatus::InstalledOrAttested,
            keyring: BootstrapKeyringStatus::Initialized,
        };
        let json = serde_json::to_string(&result).expect("result serializes");
        assert_eq!(
            json,
            "{\"schema\":\"registry.relay.consultation-bootstrap-state.v1\",\"state_plane\":\"installed_or_attested\",\"keyring\":\"initialized\"}"
        );
        for forbidden in [
            "postgresql://",
            "RELAY_STATE",
            "relay_state_owner",
            "epoch-1",
            "sentinel",
        ] {
            assert!(!json.contains(forbidden));
        }
    }

    #[test]
    fn database_challenge_requires_two_distinct_opaque_keys() {
        assert_eq!(database_challenge_from_bytes([0_u8; 16]), None);

        let mut bytes = [0_u8; 16];
        bytes[15] = 1;
        assert_eq!(database_challenge_from_bytes(bytes), Some([0, 1]));

        let challenge = fresh_database_challenge().expect("platform randomness is available");
        assert_ne!(challenge[0], challenge[1]);
    }

    #[tokio::test]
    async fn stalled_database_operation_maps_to_closed_timeout_error() {
        let error = bounded_database_operation(
            Duration::ZERO,
            BootstrapStateError::DatabaseUnavailable,
            std::future::pending::<()>(),
        )
        .await
        .expect_err("a stalled operation reaches its deadline");
        assert_eq!(error, BootstrapStateError::DatabaseUnavailable);
    }

    #[test]
    fn lower_level_failures_map_to_closed_actionable_categories() {
        assert_eq!(
            map_connection_error(ConsultationStatePlaneRuntimeError::DatabaseUrlUnavailable),
            BootstrapStateError::DatabaseReferenceUnavailable
        );
        assert_eq!(
            map_connection_error(ConsultationStatePlaneRuntimeError::TlsRequired),
            BootstrapStateError::DatabaseConfigurationRejected
        );
        assert_eq!(
            map_connection_error(ConsultationStatePlaneRuntimeError::DatabaseUnavailable),
            BootstrapStateError::DatabaseUnavailable
        );
        assert_eq!(
            map_install_error(StatePlaneInstallError::InvalidMigrationAuthority),
            BootstrapStateError::AuthorityConfigurationRejected
        );
        assert_eq!(
            map_install_error(StatePlaneInstallError::CapabilityDrift),
            BootstrapStateError::CapabilityDrift
        );
    }

    #[test]
    fn errors_are_value_free() {
        let errors = [
            BootstrapStateError::ConsultationDisabled,
            BootstrapStateError::InvalidInput,
            BootstrapStateError::ActiveKeyNotDeclared,
            BootstrapStateError::DatabaseReferenceUnavailable,
            BootstrapStateError::DatabaseConfigurationRejected,
            BootstrapStateError::DatabaseUnavailable,
            BootstrapStateError::InvalidDatabaseIdentity,
            BootstrapStateError::DatabaseMismatch,
            BootstrapStateError::AuthorityRoleCollision,
            BootstrapStateError::AuthorityConfigurationRejected,
            BootstrapStateError::InstallationRejected,
            BootstrapStateError::CapabilityDrift,
            BootstrapStateError::KeyringDrift,
            BootstrapStateError::InvalidKeyringLifecycle,
            BootstrapStateError::KeyringUnavailable,
        ];
        for error in errors {
            let rendered = format!("{error:?} {error}");
            for forbidden in ["postgresql://", "sentinel", "owner-role", "key-id"] {
                assert!(!rendered.contains(forbidden));
            }
        }
    }
}
