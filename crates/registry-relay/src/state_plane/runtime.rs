// SPDX-License-Identifier: Apache-2.0
//! Concrete PostgreSQL assembly for the consultation state plane.
//!
//! This module deliberately owns no migration or keyring-maintenance path.
//! Normal Relay startup can only attest the already-installed runtime
//! capabilities, acquire the serving fence, complete bounded takeover
//! recovery, and expose the resulting execute-only capabilities.

use std::{
    env, fmt,
    fs::File,
    io::Read,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};

use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use registry_platform_audit::AuditChainHasher;
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_postgres::{
    config::{SslMode, TargetSessionAttrs},
    Client, Config as PostgresConfig,
};
use zeroize::Zeroizing;

use crate::config::ConsultationStatePlaneConfig;

use super::{
    AuditChainKeyEpochId, AuditPseudonymKeyringLockKey, ConsultationPersistenceError,
    KeyringReadiness, PostgresAuditPseudonymKeyringRuntime, PostgresDurableAuditStatePlane,
    PostgresKeyringError, PostgresQuotaStatePlane, PostgresServingFence, QuotaError,
    QuotaReadiness, ServingFenceError, ServingFenceLockKey, ServingFenceReadiness,
    StatePlaneInitializationError, StatePlaneReadiness,
};

const MAX_ROOT_CERTIFICATE_PATH_BYTES: usize = 4 * 1024;
const MAX_ROOT_CERTIFICATE_BYTES: usize = 64 * 1024;
const DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CAPABILITY_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

type ConnectionDriver = JoinHandle<Result<(), tokio_postgres::Error>>;

/// Closed startup and shutdown failures. No variant retains a database URL,
/// trust-root path, driver error, or other deployment value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ConsultationStatePlaneRuntimeError {
    #[error("Relay consultation state-plane database URL is unavailable")]
    DatabaseUrlUnavailable,
    #[error("Relay consultation state-plane database URL is invalid")]
    InvalidDatabaseUrl,
    #[error("Relay consultation state-plane database must require TLS")]
    TlsRequired,
    #[error("Relay consultation state-plane root-certificate path is invalid")]
    InvalidRootCertificatePath,
    #[error("Relay consultation state-plane root certificate is unavailable")]
    RootCertificateUnavailable,
    #[error("Relay consultation state-plane root certificate exceeds its size bound")]
    RootCertificateTooLarge,
    #[error("Relay consultation state-plane root certificate is invalid")]
    InvalidRootCertificate,
    #[error("Relay consultation state-plane TLS configuration is invalid")]
    InvalidTlsConfiguration,
    #[error("Relay consultation state-plane chain-key epoch is invalid")]
    InvalidChainKeyEpoch,
    #[error("Relay consultation serving-fence lock key is invalid")]
    InvalidServingFenceLockKey,
    #[error("Relay consultation pseudonym-keyring lock key is invalid")]
    InvalidPseudonymKeyringLockKey,
    #[error("Relay consultation state-plane lock keys must be distinct")]
    LockKeyCollision,
    #[error("Relay consultation state-plane database is unavailable")]
    DatabaseUnavailable,
    #[error("Relay consultation state plane requires a keyed production audit chain")]
    UnkeyedAuditChain,
    #[error("Relay consultation state-plane runtime identity is not bound")]
    WrongRuntimeIdentity,
    #[error("Relay consultation state-plane capability has drifted")]
    CapabilityDrift,
    #[error("Relay consultation durable-audit state plane is unavailable")]
    DurableAuditUnavailable,
    #[error("Relay consultation quota state plane is unavailable")]
    QuotaUnavailable,
    #[error("Relay consultation pseudonym keyring is unavailable")]
    PseudonymKeyringUnavailable,
    #[error("Relay consultation pseudonym keyring is not initialized")]
    PseudonymKeyringUninitialized,
    #[error("Relay consultation serving fence is held by another instance")]
    ServingFenceContended,
    #[error("Relay consultation serving fence is unavailable")]
    ServingFenceUnavailable,
    #[error("Relay consultation takeover recovery failed")]
    TakeoverRecoveryFailed,
    #[error("Relay consultation state-plane shutdown has already started")]
    ShutdownAlreadyStarted,
    #[error("Relay consultation serving-fence shutdown failed")]
    ShutdownFailed,
}

/// One conservative readiness result for all capabilities required to admit a
/// consultation. Component detail remains private and does not become an
/// operator-visible partial-readiness contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsultationStatePlaneReadiness {
    Ready,
    Unavailable,
}

/// Opaque, execute-only consultation state-plane runtime.
///
/// The three ordinary connection drivers are retained here. The serving
/// fence owns its dedicated driver inside its actor so loss of that session
/// immediately closes admission.
pub(crate) struct ConsultationStatePlaneRuntime {
    audit: PostgresDurableAuditStatePlane,
    quota: PostgresQuotaStatePlane,
    pseudonym_keyring: PostgresAuditPseudonymKeyringRuntime,
    serving_fence: PostgresServingFence,
    drivers: Mutex<Option<ConnectionDrivers>>,
    shutdown_started: AtomicBool,
}

impl ConsultationStatePlaneRuntime {
    /// Attest and activate the exact configured PostgreSQL state plane.
    ///
    /// The database URL is read only from the configured process-environment
    /// reference and is zeroized after connection setup. Every connection is
    /// independent and requires TLS. Admission remains closed during takeover
    /// recovery and opens only after every orphan has a durable terminal
    /// completion.
    pub(crate) async fn connect(
        config: &ConsultationStatePlaneConfig,
        chain_hasher: AuditChainHasher,
    ) -> Result<Self, ConsultationStatePlaneRuntimeError> {
        let identity = StatePlaneIdentity::parse(config)?;
        let database_url = Zeroizing::new(
            env::var(config.database_url_env.as_str())
                .map_err(|_| ConsultationStatePlaneRuntimeError::DatabaseUrlUnavailable)?,
        );
        let postgres_config = parse_database_config(database_url.as_str())?;
        let tls_connector = build_tls_connector(config)?;

        // Establish all independent sessions together. `OpenedConnection`
        // aborts an already-started driver if any peer connection fails.
        let (audit_connection, quota_connection, keyring_connection, fence_connection) = tokio::try_join!(
            open_connection(&postgres_config, &tls_connector),
            open_connection(&postgres_config, &tls_connector),
            open_connection(&postgres_config, &tls_connector),
            open_connection(&postgres_config, &tls_connector),
        )?;

        let mut drivers = ConnectionDrivers::default();

        let (audit_client, audit_driver) = audit_connection.into_parts();
        drivers.push(audit_driver);
        let audit = tokio::time::timeout(
            CAPABILITY_OPERATION_TIMEOUT,
            PostgresDurableAuditStatePlane::connect(
                audit_client,
                chain_hasher,
                identity.chain_key_epoch_id.clone(),
                identity.pseudonym_keyring_lock_key,
            ),
        )
        .await
        .map_err(|_| ConsultationStatePlaneRuntimeError::DurableAuditUnavailable)?
        .map_err(map_audit_initialization_error)?;

        let (quota_client, quota_driver) = quota_connection.into_parts();
        drivers.push(quota_driver);
        let quota = tokio::time::timeout(
            CAPABILITY_OPERATION_TIMEOUT,
            PostgresQuotaStatePlane::connect(quota_client, identity.chain_key_epoch_id.clone()),
        )
        .await
        .map_err(|_| ConsultationStatePlaneRuntimeError::QuotaUnavailable)?
        .map_err(map_quota_initialization_error)?;

        let (keyring_client, keyring_driver) = keyring_connection.into_parts();
        drivers.push(keyring_driver);
        let pseudonym_keyring = tokio::time::timeout(
            CAPABILITY_OPERATION_TIMEOUT,
            PostgresAuditPseudonymKeyringRuntime::connect(
                keyring_client,
                identity.chain_key_epoch_id.clone(),
                identity.pseudonym_keyring_lock_key,
            ),
        )
        .await
        .map_err(|_| ConsultationStatePlaneRuntimeError::PseudonymKeyringUnavailable)?
        .map_err(map_keyring_initialization_error)?;
        let (fence_client, fence_driver) = fence_connection.into_parts();
        let mut serving_fence = PostgresServingFence::acquire(
            fence_client,
            fence_driver,
            &identity.chain_key_epoch_id,
            identity.serving_fence_lock_key,
        )
        .await
        .map_err(map_fence_initialization_error)?;

        let mut takeover_recovery = serving_fence.take_takeover_recovery_authority();
        if let Some(recovery) = takeover_recovery.as_mut() {
            while recovery.remaining() != 0 {
                audit
                    .recover_orphaned_consultation(recovery)
                    .await
                    .map_err(map_takeover_recovery_error)?;
            }
        }

        // Runtime role/schema attestation alone does not prove that an active
        // write epoch exists. Check after potentially long takeover recovery,
        // immediately before admission can become externally reachable.
        drop(
            tokio::time::timeout(
                CAPABILITY_OPERATION_TIMEOUT,
                pseudonym_keyring.current_write_authority(),
            )
            .await
            .map_err(|_| ConsultationStatePlaneRuntimeError::PseudonymKeyringUnavailable)?
            .map_err(map_keyring_initialization_error)?,
        );

        if let Some(recovery) = takeover_recovery {
            serving_fence
                .open_after_takeover_recovery(recovery)
                .await
                .map_err(map_takeover_fence_error)?;
        }

        Ok(Self {
            audit,
            quota,
            pseudonym_keyring,
            serving_fence,
            drivers: Mutex::new(Some(drivers)),
            shutdown_started: AtomicBool::new(false),
        })
    }

    pub(crate) fn audit(&self) -> &PostgresDurableAuditStatePlane {
        &self.audit
    }

    pub(crate) fn quota(&self) -> &PostgresQuotaStatePlane {
        &self.quota
    }

    pub(crate) fn pseudonym_keyring(&self) -> &PostgresAuditPseudonymKeyringRuntime {
        &self.pseudonym_keyring
    }

    pub(crate) fn serving_fence(&self) -> &PostgresServingFence {
        &self.serving_fence
    }

    /// Readiness is a conservative admission signal, not a component-liveness
    /// diagnostic. No route is ready unless every state-plane capability,
    /// including the currently held serving fence, is immediately ready.
    pub(crate) async fn readiness(&self) -> ConsultationStatePlaneReadiness {
        if self.shutdown_started.load(Ordering::Acquire) {
            return ConsultationStatePlaneReadiness::Unavailable;
        }
        let Ok((audit, quota, keyring, fence)) =
            tokio::time::timeout(CAPABILITY_OPERATION_TIMEOUT, async {
                tokio::join!(
                    self.audit.readiness(),
                    self.quota.readiness(),
                    self.pseudonym_keyring.readiness(),
                    self.serving_fence.readiness(),
                )
            })
            .await
        else {
            return ConsultationStatePlaneReadiness::Unavailable;
        };
        if matches!(audit, StatePlaneReadiness::Ready)
            && matches!(quota, QuotaReadiness::Ready)
            && matches!(keyring, KeyringReadiness::Ready)
            && matches!(fence, ServingFenceReadiness::Ready)
        {
            ConsultationStatePlaneReadiness::Ready
        } else {
            ConsultationStatePlaneReadiness::Unavailable
        }
    }

    /// Close admission, explicitly release the serving fence, then terminate
    /// the remaining connection drivers. This transition can run only once.
    pub(crate) async fn shutdown(&self) -> Result<(), ConsultationStatePlaneRuntimeError> {
        if self
            .shutdown_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ConsultationStatePlaneRuntimeError::ShutdownAlreadyStarted);
        }

        // If shutdown is cancelled, dropping this guard still terminates the
        // ordinary connection drivers. `PostgresServingFence::release` owns
        // the corresponding fail-closed cancellation behavior for its actor.
        let drivers = AbortDriversOnDrop(&self.drivers);
        let release = self
            .serving_fence
            .release()
            .await
            .map_err(|_| ConsultationStatePlaneRuntimeError::ShutdownFailed);
        drop(drivers);
        release
    }
}

impl fmt::Debug for ConsultationStatePlaneRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsultationStatePlaneRuntime")
            .field("capabilities", &"<execute-only>")
            .field(
                "shutdown_started",
                &self.shutdown_started.load(Ordering::Acquire),
            )
            .finish()
    }
}

impl Drop for ConsultationStatePlaneRuntime {
    fn drop(&mut self) {
        self.shutdown_started.store(true, Ordering::Release);
        let drivers = self
            .drivers
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(drivers) = drivers.take() {
            drop(drivers);
        }
        // The concrete serving fence then aborts its actor and dedicated
        // connection if explicit release was not completed.
    }
}

struct AbortDriversOnDrop<'a>(&'a Mutex<Option<ConnectionDrivers>>);

impl Drop for AbortDriversOnDrop<'_> {
    fn drop(&mut self) {
        let mut drivers = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(drivers) = drivers.take() {
            drop(drivers);
        }
    }
}

struct StatePlaneIdentity {
    chain_key_epoch_id: AuditChainKeyEpochId,
    serving_fence_lock_key: ServingFenceLockKey,
    pseudonym_keyring_lock_key: AuditPseudonymKeyringLockKey,
}

impl StatePlaneIdentity {
    fn parse(
        config: &ConsultationStatePlaneConfig,
    ) -> Result<Self, ConsultationStatePlaneRuntimeError> {
        if config.serving_fence_lock_key == config.audit_pseudonym_keyring_lock_key {
            return Err(ConsultationStatePlaneRuntimeError::LockKeyCollision);
        }
        Ok(Self {
            chain_key_epoch_id: AuditChainKeyEpochId::parse(&config.chain_key_epoch_id)
                .map_err(|_| ConsultationStatePlaneRuntimeError::InvalidChainKeyEpoch)?,
            serving_fence_lock_key: ServingFenceLockKey::new(config.serving_fence_lock_key)
                .map_err(|_| ConsultationStatePlaneRuntimeError::InvalidServingFenceLockKey)?,
            pseudonym_keyring_lock_key: AuditPseudonymKeyringLockKey::new(
                config.audit_pseudonym_keyring_lock_key,
            )
            .map_err(|_| ConsultationStatePlaneRuntimeError::InvalidPseudonymKeyringLockKey)?,
        })
    }
}

#[derive(Default)]
struct ConnectionDrivers(Vec<ConnectionDriver>);

impl ConnectionDrivers {
    fn push(&mut self, driver: ConnectionDriver) {
        self.0.push(driver);
    }
}

impl Drop for ConnectionDrivers {
    fn drop(&mut self) {
        for driver in self.0.drain(..) {
            driver.abort();
        }
    }
}

pub(crate) struct OpenedConnection {
    client: Option<Client>,
    driver: Option<ConnectionDriver>,
}

impl OpenedConnection {
    fn into_parts(mut self) -> (Client, ConnectionDriver) {
        let client = self.client.take().expect("opened connection has a client");
        let driver = self.driver.take().expect("opened connection has a driver");
        (client, driver)
    }

    pub(crate) fn client(&self) -> &Client {
        self.client
            .as_ref()
            .expect("opened connection retains its client")
    }

    pub(crate) fn client_mut(&mut self) -> &mut Client {
        self.client
            .as_mut()
            .expect("opened connection retains its client")
    }

    /// Transfer the client to a typed capability while retaining ownership of
    /// the connection driver in this guard.
    pub(crate) fn take_client(&mut self) -> Client {
        self.client
            .take()
            .expect("opened connection transfers its client once")
    }
}

impl Drop for OpenedConnection {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

fn parse_database_config(
    database_url: &str,
) -> Result<PostgresConfig, ConsultationStatePlaneRuntimeError> {
    let mut config = database_url
        .parse::<PostgresConfig>()
        .map_err(|_| ConsultationStatePlaneRuntimeError::InvalidDatabaseUrl)?;
    if config.get_ssl_mode() != SslMode::Require {
        return Err(ConsultationStatePlaneRuntimeError::TlsRequired);
    }
    // All four capabilities must attach to the writable state-plane primary.
    // A deployment URL may name an HA endpoint, but no session may silently
    // land on a read-only replica while the serving fence is held elsewhere.
    config.target_session_attrs(TargetSessionAttrs::ReadWrite);
    Ok(config)
}

fn build_tls_connector(
    config: &ConsultationStatePlaneConfig,
) -> Result<TlsConnector, ConsultationStatePlaneRuntimeError> {
    let mut builder = TlsConnector::builder();
    if let Some(path) = config.root_certificate_path.as_deref() {
        if path.as_os_str().as_encoded_bytes().len() > MAX_ROOT_CERTIFICATE_PATH_BYTES {
            return Err(ConsultationStatePlaneRuntimeError::InvalidRootCertificatePath);
        }
        let certificate_bytes = read_bounded_root_certificate(path)?;
        let certificate = native_tls::Certificate::from_pem(&certificate_bytes)
            .map_err(|_| ConsultationStatePlaneRuntimeError::InvalidRootCertificate)?;
        builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|_| ConsultationStatePlaneRuntimeError::InvalidTlsConfiguration)
}

fn read_bounded_root_certificate(
    path: &std::path::Path,
) -> Result<Vec<u8>, ConsultationStatePlaneRuntimeError> {
    let file = File::open(path)
        .map_err(|_| ConsultationStatePlaneRuntimeError::RootCertificateUnavailable)?;
    let mut limited = file.take((MAX_ROOT_CERTIFICATE_BYTES + 1) as u64);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| ConsultationStatePlaneRuntimeError::RootCertificateUnavailable)?;
    if bytes.len() > MAX_ROOT_CERTIFICATE_BYTES {
        return Err(ConsultationStatePlaneRuntimeError::RootCertificateTooLarge);
    }
    Ok(bytes)
}

async fn open_connection(
    config: &PostgresConfig,
    tls_connector: &TlsConnector,
) -> Result<OpenedConnection, ConsultationStatePlaneRuntimeError> {
    let connector = MakeTlsConnector::new(tls_connector.clone());
    let (client, connection) =
        tokio::time::timeout(DATABASE_CONNECT_TIMEOUT, config.connect(connector))
            .await
            .map_err(|_| ConsultationStatePlaneRuntimeError::DatabaseUnavailable)?
            .map_err(|_| ConsultationStatePlaneRuntimeError::DatabaseUnavailable)?;
    Ok(OpenedConnection {
        client: Some(client),
        driver: Some(tokio::spawn(connection)),
    })
}

/// Open one bounded, TLS-required state-plane session for the offline
/// bootstrap command.
///
/// The URL is resolved only from the supplied environment reference and is
/// zeroized after the PostgreSQL configuration has been parsed. Reusing the
/// runtime connector here keeps bootstrap subject to the same trust-root,
/// primary-selection, timeout, and TLS requirements as normal serving.
pub(crate) async fn open_operator_connection(
    config: &ConsultationStatePlaneConfig,
    database_url_env: &str,
) -> Result<OpenedConnection, ConsultationStatePlaneRuntimeError> {
    let database_url = Zeroizing::new(
        env::var(database_url_env)
            .map_err(|_| ConsultationStatePlaneRuntimeError::DatabaseUrlUnavailable)?,
    );
    let postgres_config = parse_database_config(database_url.as_str())?;
    let tls_connector = build_tls_connector(config)?;
    open_connection(&postgres_config, &tls_connector).await
}

const fn map_audit_initialization_error(
    error: StatePlaneInitializationError,
) -> ConsultationStatePlaneRuntimeError {
    match error {
        StatePlaneInitializationError::UnkeyedAuditChain => {
            ConsultationStatePlaneRuntimeError::UnkeyedAuditChain
        }
        StatePlaneInitializationError::WrongRuntimeIdentity => {
            ConsultationStatePlaneRuntimeError::WrongRuntimeIdentity
        }
        StatePlaneInitializationError::CapabilityDrift => {
            ConsultationStatePlaneRuntimeError::CapabilityDrift
        }
        StatePlaneInitializationError::Unavailable => {
            ConsultationStatePlaneRuntimeError::DurableAuditUnavailable
        }
    }
}

const fn map_quota_initialization_error(error: QuotaError) -> ConsultationStatePlaneRuntimeError {
    match error {
        QuotaError::WrongRuntimeIdentity => {
            ConsultationStatePlaneRuntimeError::WrongRuntimeIdentity
        }
        QuotaError::CapabilityDrift | QuotaError::ProtocolDrift => {
            ConsultationStatePlaneRuntimeError::CapabilityDrift
        }
        QuotaError::InvalidPublicLimits
        | QuotaError::InvalidEffectiveLimits
        | QuotaError::LimitMismatch
        | QuotaError::ClockAnomaly
        | QuotaError::Unavailable => ConsultationStatePlaneRuntimeError::QuotaUnavailable,
    }
}

const fn map_keyring_initialization_error(
    error: PostgresKeyringError,
) -> ConsultationStatePlaneRuntimeError {
    match error {
        PostgresKeyringError::Uninitialized => {
            ConsultationStatePlaneRuntimeError::PseudonymKeyringUninitialized
        }
        PostgresKeyringError::WrongRuntimeIdentity => {
            ConsultationStatePlaneRuntimeError::WrongRuntimeIdentity
        }
        PostgresKeyringError::CapabilityDrift | PostgresKeyringError::ProtocolDrift => {
            ConsultationStatePlaneRuntimeError::CapabilityDrift
        }
        PostgresKeyringError::InvalidMetadata
        | PostgresKeyringError::AlreadyInitialized
        | PostgresKeyringError::NotActive
        | PostgresKeyringError::WriteDeadlineReached
        | PostgresKeyringError::RetainedEpochExpired
        | PostgresKeyringError::UnauthorizedLookupSubset
        | PostgresKeyringError::StaleExpectedState
        | PostgresKeyringError::IncompleteHistory
        | PostgresKeyringError::ReusedKeyId
        | PostgresKeyringError::HistoryLimitReached
        | PostgresKeyringError::InvalidRotation
        | PostgresKeyringError::InvalidMaintenance
        | PostgresKeyringError::Unavailable => {
            ConsultationStatePlaneRuntimeError::PseudonymKeyringUnavailable
        }
    }
}

const fn map_fence_initialization_error(
    error: ServingFenceError,
) -> ConsultationStatePlaneRuntimeError {
    match error {
        ServingFenceError::Contended => ConsultationStatePlaneRuntimeError::ServingFenceContended,
        ServingFenceError::WrongRuntimeIdentity => {
            ConsultationStatePlaneRuntimeError::WrongRuntimeIdentity
        }
        ServingFenceError::CapabilityDrift | ServingFenceError::ProtocolDrift => {
            ConsultationStatePlaneRuntimeError::CapabilityDrift
        }
        ServingFenceError::InvalidLockKey
        | ServingFenceError::InvalidOperationId
        | ServingFenceError::InvalidPermitBudget
        | ServingFenceError::InvalidPermitManifest
        | ServingFenceError::AdmissionClosed
        | ServingFenceError::OwnershipLost
        | ServingFenceError::PermitConflict
        | ServingFenceError::SourceOperationNotAuthorized
        | ServingFenceError::SourceOperationAlreadyUsed
        | ServingFenceError::PermitUnknown
        | ServingFenceError::PermitExpired
        | ServingFenceError::PermitCompleted
        | ServingFenceError::PermitAlreadyDispatched
        | ServingFenceError::PermitOrderViolation
        | ServingFenceError::PermitAbandoned
        | ServingFenceError::PermitUncertain
        | ServingFenceError::StaleGeneration
        | ServingFenceError::TakeoverTimedOut
        | ServingFenceError::RecoveryIncomplete
        | ServingFenceError::Unavailable => {
            ConsultationStatePlaneRuntimeError::ServingFenceUnavailable
        }
    }
}

const fn map_takeover_recovery_error(
    _error: ConsultationPersistenceError,
) -> ConsultationStatePlaneRuntimeError {
    ConsultationStatePlaneRuntimeError::TakeoverRecoveryFailed
}

const fn map_takeover_fence_error(_error: ServingFenceError) -> ConsultationStatePlaneRuntimeError {
    ConsultationStatePlaneRuntimeError::TakeoverRecoveryFailed
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, future::pending};

    use super::*;

    const SECRET_URL: &str =
        "postgresql://sentinel-user:sentinel-password@sentinel-host/state?sslmode=disable";

    #[test]
    fn database_url_failures_do_not_retain_or_display_values() {
        let error = parse_database_config(SECRET_URL).expect_err("plaintext fallback is rejected");
        assert_eq!(error, ConsultationStatePlaneRuntimeError::TlsRequired);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("sentinel"));

        let invalid = parse_database_config("sentinel-not-a-database-url")
            .expect_err("invalid URL is rejected");
        let rendered = format!("{invalid:?} {invalid}");
        assert!(!rendered.contains("sentinel"));

        let secure = parse_database_config(
            "postgresql://sentinel-user:sentinel-password@sentinel-host/state?sslmode=require",
        )
        .expect("TLS-required URL parses");
        assert_eq!(
            secure.get_target_session_attrs(),
            TargetSessionAttrs::ReadWrite
        );
    }

    #[test]
    fn root_certificate_read_is_bounded_and_path_is_not_disclosed() {
        let path = env::temp_dir().join(format!(
            "registry-relay-state-plane-sentinel-{}.pem",
            ulid::Ulid::new()
        ));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("unique temporary file opens");
        file.set_len((MAX_ROOT_CERTIFICATE_BYTES + 1) as u64)
            .expect("temporary file is extended");

        let error = read_bounded_root_certificate(&path)
            .expect_err("oversized root certificate is rejected");
        std::fs::remove_file(&path).expect("temporary file is removed");
        assert_eq!(
            error,
            ConsultationStatePlaneRuntimeError::RootCertificateTooLarge
        );
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(path.to_string_lossy().as_ref()));
    }

    #[tokio::test]
    async fn owned_connection_drivers_are_aborted_on_drop() {
        let driver = tokio::spawn(async {
            pending::<()>().await;
            Ok::<(), tokio_postgres::Error>(())
        });
        let abort = driver.abort_handle();
        let mut drivers = ConnectionDrivers::default();
        drivers.push(driver);
        drop(drivers);
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
    }

    #[test]
    fn runtime_errors_are_closed_and_value_free() {
        let errors = [
            ConsultationStatePlaneRuntimeError::DatabaseUrlUnavailable,
            ConsultationStatePlaneRuntimeError::InvalidDatabaseUrl,
            ConsultationStatePlaneRuntimeError::TlsRequired,
            ConsultationStatePlaneRuntimeError::InvalidRootCertificatePath,
            ConsultationStatePlaneRuntimeError::RootCertificateUnavailable,
            ConsultationStatePlaneRuntimeError::RootCertificateTooLarge,
            ConsultationStatePlaneRuntimeError::InvalidRootCertificate,
            ConsultationStatePlaneRuntimeError::InvalidTlsConfiguration,
            ConsultationStatePlaneRuntimeError::InvalidChainKeyEpoch,
            ConsultationStatePlaneRuntimeError::InvalidServingFenceLockKey,
            ConsultationStatePlaneRuntimeError::InvalidPseudonymKeyringLockKey,
            ConsultationStatePlaneRuntimeError::LockKeyCollision,
            ConsultationStatePlaneRuntimeError::DatabaseUnavailable,
            ConsultationStatePlaneRuntimeError::UnkeyedAuditChain,
            ConsultationStatePlaneRuntimeError::WrongRuntimeIdentity,
            ConsultationStatePlaneRuntimeError::CapabilityDrift,
            ConsultationStatePlaneRuntimeError::DurableAuditUnavailable,
            ConsultationStatePlaneRuntimeError::QuotaUnavailable,
            ConsultationStatePlaneRuntimeError::PseudonymKeyringUnavailable,
            ConsultationStatePlaneRuntimeError::PseudonymKeyringUninitialized,
            ConsultationStatePlaneRuntimeError::ServingFenceContended,
            ConsultationStatePlaneRuntimeError::ServingFenceUnavailable,
            ConsultationStatePlaneRuntimeError::TakeoverRecoveryFailed,
            ConsultationStatePlaneRuntimeError::ShutdownAlreadyStarted,
            ConsultationStatePlaneRuntimeError::ShutdownFailed,
        ];
        for error in errors {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("sentinel"));
            assert!(!rendered.contains("postgresql://"));
        }
    }
}
