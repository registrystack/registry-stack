// SPDX-License-Identifier: Apache-2.0
//! Bounded PostgreSQL connection and session lifecycle for Notary state.
//!
//! Schema installation and domain transactions live in sibling modules. This
//! module owns only TLS-required connection setup, runtime attestation, bounded
//! execution, reconnectable sessions, and driver shutdown.

use std::{
    collections::HashMap,
    env, fmt,
    fs::File,
    future::Future,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use deadpool::managed::{Manager, Metrics, Object, Pool, PoolError, RecycleError, RecycleResult};
use hmac::{Hmac, KeyInit, Mac};
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use registry_notary_core::{StatePostgresqlConfig, STATE_POSTGRESQL_MAX_CONNECTIONS};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::MissedTickBehavior;
use tokio_postgres::{
    config::{SslMode, TargetSessionAttrs},
    Client, Config as TokioPostgresConfig,
};
use zeroize::Zeroizing;

use super::{
    attest_postgres_state_plane_v1, PostgresStatePlaneAttestation, StatePlaneMigrationError,
};

const MAX_ROOT_CERTIFICATE_PATH_BYTES: usize = 4 * 1024;
const MAX_ROOT_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Each serving replica prunes at most this many expired rows per state table
/// per pass. The fixed database function rejects larger batches.
const RETENTION_MAINTENANCE_BATCH_SIZE: i32 = 1_000;
/// Cleanup is deliberately less frequent than request-path state operations;
/// expiry checks remain authoritative even between maintenance passes.
const RETENTION_MAINTENANCE_CADENCE: Duration = Duration::from_secs(60);
/// A catch-up sequence releases its pooled session between transactions and
/// backs off before the next batch so request traffic retains pool access.
const RETENTION_CATCH_UP_INITIAL_BACKOFF: Duration = Duration::from_millis(10);
const RETENTION_CATCH_UP_MAX_BACKOFF: Duration = Duration::from_millis(100);
const RETENTION_PRUNE_QUERY: &str =
    "SELECT deleted_count, batch_saturated FROM registry_notary_api.retention_prune_v1($1)";

type ConnectionDriver = JoinHandle<Result<(), tokio_postgres::Error>>;
type CredentialGeneration = [u8; 32];
type PostgresSessionPool = Pool<ConnectionFactory>;
type PooledPostgresSession = Object<ConnectionFactory>;

/// TLS and timeout policy for the Notary-owned PostgreSQL state plane.
///
/// The environment variable name and root-certificate path are redacted from
/// `Debug`. The URL value is loaded only while opening a session.
#[derive(Clone, PartialEq, Eq)]
pub struct PostgresStatePlaneConfig {
    database_url_env: String,
    root_certificate_path: Option<PathBuf>,
    connect_timeout: Duration,
    operation_timeout: Duration,
    max_connections: usize,
}

impl PostgresStatePlaneConfig {
    pub fn new(
        database_url_env: impl Into<String>,
        root_certificate_path: Option<PathBuf>,
        connect_timeout: Duration,
        operation_timeout: Duration,
        max_connections: usize,
    ) -> Result<Self, NotaryPostgresStatePlaneError> {
        let database_url_env = database_url_env.into();
        if database_url_env.trim().is_empty() {
            return Err(NotaryPostgresStatePlaneError::InvalidConfiguration);
        }
        if connect_timeout.is_zero() || operation_timeout.is_zero() {
            return Err(NotaryPostgresStatePlaneError::InvalidTimeout);
        }
        if !(1..=STATE_POSTGRESQL_MAX_CONNECTIONS).contains(&max_connections) {
            return Err(NotaryPostgresStatePlaneError::InvalidConfiguration);
        }
        if root_certificate_path.as_ref().is_some_and(|path| {
            path.as_os_str().is_empty()
                || path.as_os_str().as_encoded_bytes().len() > MAX_ROOT_CERTIFICATE_PATH_BYTES
        }) {
            return Err(NotaryPostgresStatePlaneError::InvalidRootCertificatePath);
        }
        Ok(Self {
            database_url_env,
            root_certificate_path,
            connect_timeout,
            operation_timeout,
            max_connections,
        })
    }

    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    #[must_use]
    pub fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    #[must_use]
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }
}

impl TryFrom<&StatePostgresqlConfig> for PostgresStatePlaneConfig {
    type Error = NotaryPostgresStatePlaneError;

    fn try_from(config: &StatePostgresqlConfig) -> Result<Self, Self::Error> {
        Self::new(
            config.url_env.clone(),
            config.root_certificate_path.clone(),
            Duration::from_millis(config.connect_timeout_ms),
            Duration::from_millis(config.operation_timeout_ms),
            config.max_connections,
        )
    }
}

impl fmt::Debug for PostgresStatePlaneConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresStatePlaneConfig")
            .field("database_url_env", &"<redacted>")
            .field(
                "custom_root_certificate",
                &self.root_certificate_path.is_some(),
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

/// Closed runtime failures. No variant retains a URL, path, role, SQL text,
/// driver error, or stored identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NotaryPostgresStatePlaneError {
    #[error("Notary PostgreSQL state configuration is invalid")]
    InvalidConfiguration,
    #[error("Notary PostgreSQL state timeout is invalid")]
    InvalidTimeout,
    #[error("Notary PostgreSQL database URL is unavailable")]
    DatabaseUrlUnavailable,
    #[error("Notary PostgreSQL database URL is invalid")]
    InvalidDatabaseUrl,
    #[error("Notary PostgreSQL database must require TLS")]
    TlsRequired,
    #[error("Notary PostgreSQL root-certificate path is invalid")]
    InvalidRootCertificatePath,
    #[error("Notary PostgreSQL root certificate is unavailable")]
    RootCertificateUnavailable,
    #[error("Notary PostgreSQL root certificate exceeds its size bound")]
    RootCertificateTooLarge,
    #[error("Notary PostgreSQL root certificate is invalid")]
    InvalidRootCertificate,
    #[error("Notary PostgreSQL TLS configuration is invalid")]
    InvalidTlsConfiguration,
    #[error("Notary PostgreSQL database is unavailable")]
    DatabaseUnavailable,
    #[error("Notary PostgreSQL server major is unsupported")]
    UnsupportedServerMajor,
    #[error("Notary PostgreSQL database is read-only or recovering")]
    DatabaseNotWritable,
    #[error("Notary PostgreSQL durability settings are unsafe")]
    UnsafeDurability,
    #[error("Notary PostgreSQL state schema is incompatible")]
    SchemaIncompatible,
    #[error("Notary PostgreSQL runtime role is incompatible")]
    RoleIncompatible,
    #[error("Notary PostgreSQL state operation is unavailable")]
    OperationUnavailable,
    #[error("Notary PostgreSQL state runtime is shut down")]
    Shutdown,
}

/// Stable, value-free readiness result suitable for probe and posture mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotaryPostgresStatePlaneReadiness {
    Ready,
    ConfigurationInvalid,
    DatabaseUnavailable,
    UnsupportedServerMajor,
    DatabaseNotWritable,
    UnsafeDurability,
    SchemaIncompatible,
    RoleIncompatible,
    Shutdown,
}

impl NotaryPostgresStatePlaneReadiness {
    #[must_use]
    pub const fn from_error(error: NotaryPostgresStatePlaneError) -> Self {
        readiness_from_error(error)
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::DatabaseUnavailable => "database_unavailable",
            Self::UnsupportedServerMajor => "database_unsupported",
            Self::DatabaseNotWritable => "database_read_only",
            Self::UnsafeDurability => "database_durability_unsafe",
            Self::SchemaIncompatible => "schema_incompatible",
            Self::RoleIncompatible => "role_incompatible",
            Self::Shutdown => "shutdown",
        }
    }

    /// Coarse, value-free component code used by the operator CLI. Detailed
    /// database posture remains available through [`Self::code`] without
    /// widening the command's stable error contract.
    #[must_use]
    pub const fn doctor_component_code(self) -> &'static str {
        match self {
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::SchemaIncompatible => "schema_incompatible",
            Self::RoleIncompatible => "role_incompatible",
            Self::Ready
            | Self::DatabaseUnavailable
            | Self::UnsupportedServerMajor
            | Self::DatabaseNotWritable
            | Self::UnsafeDurability
            | Self::Shutdown => "database_unavailable",
        }
    }
}

/// Reconnectable PostgreSQL runtime for Notary-owned correctness state.
///
/// Each domain obtains a bounded lease from a Notary-specific physical session
/// pool. Physical connections reload the named URL environment variable and
/// enter the pool only after complete attestation. A process-keyed generation
/// tag evicts old connections when the URL changes without retaining its value.
pub struct NotaryPostgresStatePlaneRuntime {
    connections: PostgresSessionPool,
    sessions: Arc<SessionRegistry>,
    #[cfg(test)]
    retention_attempts: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetentionPruneOutcome {
    batch_saturated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetentionCatchUpOutcome {
    CaughtUp,
    Shutdown,
}

/// One PostgreSQL-serving retention worker. It owns no state values and is
/// stopped by the serving state-plane handle before runtime connections close.
pub(crate) struct PostgresRetentionMaintenance {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// TLS-required owner connection used only by the explicit state installer.
pub struct NotaryPostgresOperatorConnection {
    client: Client,
    driver: Option<ConnectionDriver>,
}

impl NotaryPostgresOperatorConnection {
    pub async fn connect(
        runtime_config: &PostgresStatePlaneConfig,
        database_url_env: &str,
    ) -> Result<Self, NotaryPostgresStatePlaneError> {
        if database_url_env.trim().is_empty() {
            return Err(NotaryPostgresStatePlaneError::InvalidConfiguration);
        }
        let database_url = load_database_url(database_url_env)?;
        let postgres_config = parse_database_config(database_url.as_str())?;
        let tls_connector = build_tls_connector(runtime_config.root_certificate_path.as_deref())?;
        let (client, connection) = tokio::time::timeout(
            runtime_config.connect_timeout,
            postgres_config.connect(MakeTlsConnector::new(tls_connector)),
        )
        .await
        .map_err(|_| NotaryPostgresStatePlaneError::DatabaseUnavailable)?
        .map_err(|_| NotaryPostgresStatePlaneError::DatabaseUnavailable)?;
        Ok(Self {
            client,
            driver: Some(tokio::spawn(connection)),
        })
    }

    pub fn client_mut(&mut self) -> &mut Client {
        &mut self.client
    }
}

impl fmt::Debug for NotaryPostgresOperatorConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotaryPostgresOperatorConnection")
            .finish_non_exhaustive()
    }
}

impl Drop for NotaryPostgresOperatorConnection {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

impl NotaryPostgresStatePlaneRuntime {
    /// Activate the state plane and prove a fully attested runtime session can
    /// be opened before the caller binds a listener.
    pub async fn connect(
        config: &PostgresStatePlaneConfig,
    ) -> Result<Self, NotaryPostgresStatePlaneError> {
        let sessions = Arc::new(SessionRegistry::default());
        let manager = ConnectionFactory::new(config, Arc::clone(&sessions))?;
        let connections = PostgresSessionPool::builder(manager)
            .max_size(config.max_connections)
            .wait_timeout(Some(config.operation_timeout))
            .runtime(deadpool::Runtime::Tokio1)
            .build()
            .map_err(|_| NotaryPostgresStatePlaneError::InvalidConfiguration)?;
        let runtime = Self {
            connections,
            sessions,
            #[cfg(test)]
            retention_attempts: AtomicU64::new(0),
        };
        drop(runtime.open_domain_session().await?);
        Ok(runtime)
    }

    /// Lease a bounded, fully attested session for one typed state-domain
    /// adapter. Pool wait time is bounded by the operation timeout.
    pub(crate) async fn open_domain_session(
        &self,
    ) -> Result<NotaryPostgresSession, NotaryPostgresStatePlaneError> {
        if self.sessions.is_shutdown() {
            return Err(NotaryPostgresStatePlaneError::Shutdown);
        }
        let session = self.connections.get().await.map_err(map_pool_error)?;
        if self.sessions.is_shutdown() || self.connections.is_closed() {
            session.poisoned.store(true, Ordering::Release);
            drop(session);
            return Err(NotaryPostgresStatePlaneError::Shutdown);
        }
        Ok(NotaryPostgresSession { session })
    }

    /// Re-attest a pooled runtime session and return bounded version
    /// information suitable for operator diagnostics.
    pub async fn attestation(
        &self,
    ) -> Result<PostgresStatePlaneAttestation, NotaryPostgresStatePlaneError> {
        let session = self.open_domain_session().await?;
        session.attest().await
    }

    /// Probe the complete schema and role contract. A failed probe poisons its
    /// physical session, so recovery must reconnect and re-attest before the
    /// next probe can report ready.
    pub async fn readiness(&self) -> NotaryPostgresStatePlaneReadiness {
        match self.open_domain_session().await {
            Ok(session) => match session.attest().await {
                Ok(_) => NotaryPostgresStatePlaneReadiness::Ready,
                Err(error) => readiness_from_error(error),
            },
            Err(error) => readiness_from_error(error),
        }
    }

    /// Invoke one fixed, bounded retention transaction. Maintenance errors use
    /// the same value-free state-plane error contract as requests and are not
    /// retained as readiness state.
    async fn prune_expired_rows(
        &self,
    ) -> Result<RetentionPruneOutcome, NotaryPostgresStatePlaneError> {
        #[cfg(test)]
        self.retention_attempts.fetch_add(1, Ordering::Relaxed);
        let session = self.open_domain_session().await?;
        let row = session
            .run_operation(
                session
                    .client()
                    .query_one(RETENTION_PRUNE_QUERY, &[&RETENTION_MAINTENANCE_BATCH_SIZE]),
            )
            .await?;
        let deleted_count: i64 = row
            .try_get("deleted_count")
            .map_err(|_| NotaryPostgresStatePlaneError::OperationUnavailable)?;
        let batch_saturated: bool = row
            .try_get("batch_saturated")
            .map_err(|_| NotaryPostgresStatePlaneError::OperationUnavailable)?;
        let maximum_deleted = i64::from(RETENTION_MAINTENANCE_BATCH_SIZE) * 9;
        if !(0..=maximum_deleted).contains(&deleted_count)
            || (batch_saturated && deleted_count < i64::from(RETENTION_MAINTENANCE_BATCH_SIZE))
        {
            return Err(NotaryPostgresStatePlaneError::OperationUnavailable);
        }
        Ok(RetentionPruneOutcome { batch_saturated })
    }

    /// Stop admission of new sessions and abort every active connection
    /// driver. Repeated shutdown calls are safe.
    pub fn shutdown(&self) {
        self.connections.close();
        self.sessions.shutdown();
    }

    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.sessions.is_shutdown()
    }

    #[cfg(test)]
    pub(crate) fn pool_status(&self) -> deadpool::Status {
        self.connections.status()
    }

    #[cfg(test)]
    pub(crate) fn created_session_count(&self) -> u64 {
        self.sessions.next_session_id.load(Ordering::Acquire)
    }
}

pub(crate) fn start_postgres_retention_maintenance(
    runtime: Arc<NotaryPostgresStatePlaneRuntime>,
) -> PostgresRetentionMaintenance {
    start_postgres_retention_maintenance_with_cadence(runtime, RETENTION_MAINTENANCE_CADENCE)
}

fn start_postgres_retention_maintenance_with_cadence(
    runtime: Arc<NotaryPostgresStatePlaneRuntime>,
    cadence: Duration,
) -> PostgresRetentionMaintenance {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(run_postgres_retention_maintenance(
        runtime,
        shutdown_rx,
        cadence,
    ));
    PostgresRetentionMaintenance { shutdown, task }
}

async fn run_postgres_retention_maintenance(
    runtime: Arc<NotaryPostgresStatePlaneRuntime>,
    mut shutdown: watch::Receiver<bool>,
    cadence: Duration,
) {
    let first_pass = tokio::time::Instant::now() + cadence;
    let mut interval = tokio::time::interval_at(first_pass, cadence);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                let prune_runtime = Arc::clone(&runtime);
                let result = catch_up_postgres_retention(
                    &mut shutdown,
                    RETENTION_CATCH_UP_INITIAL_BACKOFF,
                    RETENTION_CATCH_UP_MAX_BACKOFF,
                    move || {
                        let runtime = Arc::clone(&prune_runtime);
                        async move { runtime.prune_expired_rows().await }
                    },
                )
                .await;
                match result {
                    Ok(RetentionCatchUpOutcome::CaughtUp) => {}
                    Ok(RetentionCatchUpOutcome::Shutdown) => return,
                    Err(NotaryPostgresStatePlaneError::Shutdown) => return,
                    Err(_) => tracing::warn!(
                        target: "registry_notary::state_plane",
                        "PostgreSQL retention maintenance was unavailable; serving continues"
                    ),
                }
            }
        }
    }
}

async fn catch_up_postgres_retention<Prune, PruneFuture>(
    shutdown: &mut watch::Receiver<bool>,
    initial_backoff: Duration,
    maximum_backoff: Duration,
    mut prune: Prune,
) -> Result<RetentionCatchUpOutcome, NotaryPostgresStatePlaneError>
where
    Prune: FnMut() -> PruneFuture,
    PruneFuture: Future<Output = Result<RetentionPruneOutcome, NotaryPostgresStatePlaneError>>,
{
    let mut backoff = initial_backoff;
    loop {
        if *shutdown.borrow() {
            return Ok(RetentionCatchUpOutcome::Shutdown);
        }
        let outcome = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(RetentionCatchUpOutcome::Shutdown);
                }
                continue;
            }
            outcome = prune() => outcome?,
        };
        if !outcome.batch_saturated {
            return Ok(RetentionCatchUpOutcome::CaughtUp);
        }

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(RetentionCatchUpOutcome::Shutdown);
                }
            }
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff.saturating_mul(2).min(maximum_backoff);
    }
}

impl PostgresRetentionMaintenance {
    /// Signal cooperative shutdown and abort the task without blocking. The
    /// owning handle's synchronous `Drop` cannot await a join; aborting drops
    /// any in-flight prune future, after which runtime shutdown closes every
    /// registered connection driver.
    pub(crate) fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

impl Drop for PostgresRetentionMaintenance {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl fmt::Debug for NotaryPostgresStatePlaneRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotaryPostgresStatePlaneRuntime")
            .field("shutdown", &self.is_shutdown())
            .finish_non_exhaustive()
    }
}

impl Drop for NotaryPostgresStatePlaneRuntime {
    fn drop(&mut self) {
        self.connections.close();
        self.sessions.shutdown();
    }
}

/// One independently driven, attested PostgreSQL session.
///
/// Domain modules use the typed `Client` interface to invoke their fixed API
/// functions. This wrapper intentionally offers no key-value operations.
pub(crate) struct NotaryPostgresSession {
    session: PooledPostgresSession,
}

/// One physical PostgreSQL connection. It enters the pool only after complete
/// configuration and attestation, and is discarded after any operation error.
struct PhysicalPostgresSession {
    client: Client,
    driver: Option<ConnectionDriver>,
    session_id: u64,
    sessions: Arc<SessionRegistry>,
    operation_timeout: Duration,
    credential_generation: CredentialGeneration,
    poisoned: AtomicBool,
}

/// A cancelled adapter future must not return a connection with an in-flight
/// PostgreSQL request to the pool. Successful completion explicitly disarms
/// this guard; every other drop path poisons the physical session.
struct PoisonSessionOnDrop<'a> {
    poisoned: &'a AtomicBool,
    armed: bool,
}

impl<'a> PoisonSessionOnDrop<'a> {
    fn new(poisoned: &'a AtomicBool) -> Self {
        Self {
            poisoned,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PoisonSessionOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.poisoned.store(true, Ordering::Release);
        }
    }
}

impl NotaryPostgresSession {
    pub(crate) fn client(&self) -> &Client {
        &self.session.client
    }

    /// Apply the runtime operation deadline to a typed client or transaction
    /// future without accepting an untyped storage operation.
    pub(crate) async fn run_operation<T>(
        &self,
        operation: impl Future<Output = Result<T, tokio_postgres::Error>>,
    ) -> Result<T, NotaryPostgresStatePlaneError> {
        let mut poison_on_drop = PoisonSessionOnDrop::new(&self.session.poisoned);
        match tokio::time::timeout(self.session.operation_timeout, operation).await {
            Ok(Ok(value)) => {
                poison_on_drop.disarm();
                Ok(value)
            }
            Ok(Err(_)) | Err(_) => Err(NotaryPostgresStatePlaneError::OperationUnavailable),
        }
    }

    async fn attest(&self) -> Result<PostgresStatePlaneAttestation, NotaryPostgresStatePlaneError> {
        let mut poison_on_drop = PoisonSessionOnDrop::new(&self.session.poisoned);
        match self.session.attest().await {
            Ok(attestation) => {
                poison_on_drop.disarm();
                Ok(attestation)
            }
            Err(error) => Err(error),
        }
    }
}

impl PhysicalPostgresSession {
    async fn configure(&self) -> Result<(), NotaryPostgresStatePlaneError> {
        let timeout = duration_as_postgres_milliseconds(self.operation_timeout);
        tokio::time::timeout(
            self.operation_timeout,
            self.client.query_one(
                "SELECT pg_catalog.set_config('statement_timeout', $1, false),\n\
                        pg_catalog.set_config('lock_timeout', $1, false),\n\
                        pg_catalog.set_config('idle_in_transaction_session_timeout', $1, false),\n\
                        pg_catalog.set_config('synchronous_commit', 'on', false),\n\
                        pg_catalog.set_config('search_path', 'pg_catalog', false),\n\
                        pg_catalog.set_config('client_encoding', 'UTF8', false),\n\
                        pg_catalog.set_config('standard_conforming_strings', 'on', false),\n\
                        pg_catalog.set_config(\n\
                            'default_transaction_isolation', 'read committed', false\n\
                        )",
                &[&timeout],
            ),
        )
        .await
        .map_err(|_| NotaryPostgresStatePlaneError::DatabaseUnavailable)?
        .map_err(|_| NotaryPostgresStatePlaneError::DatabaseUnavailable)?;
        Ok(())
    }

    async fn attest(&self) -> Result<PostgresStatePlaneAttestation, NotaryPostgresStatePlaneError> {
        tokio::time::timeout(
            self.operation_timeout,
            attest_postgres_state_plane_v1(&self.client),
        )
        .await
        .map_err(|_| NotaryPostgresStatePlaneError::DatabaseUnavailable)?
        .map_err(map_attestation_error)
    }
}

impl fmt::Debug for NotaryPostgresSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotaryPostgresSession")
            .finish_non_exhaustive()
    }
}

impl Drop for PhysicalPostgresSession {
    fn drop(&mut self) {
        self.sessions.unregister(self.session_id);
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

struct ConnectionFactory {
    database_url_env: String,
    tls_connector: TlsConnector,
    connect_timeout: Duration,
    operation_timeout: Duration,
    credential_tag_key: Zeroizing<[u8; 32]>,
    sessions: Arc<SessionRegistry>,
}

impl ConnectionFactory {
    fn new(
        config: &PostgresStatePlaneConfig,
        sessions: Arc<SessionRegistry>,
    ) -> Result<Self, NotaryPostgresStatePlaneError> {
        let mut credential_tag_key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(credential_tag_key.as_mut())
            .map_err(|_| NotaryPostgresStatePlaneError::InvalidConfiguration)?;
        Ok(Self {
            database_url_env: config.database_url_env.clone(),
            tls_connector: build_tls_connector(config.root_certificate_path.as_deref())?,
            connect_timeout: config.connect_timeout,
            operation_timeout: config.operation_timeout,
            credential_tag_key,
            sessions,
        })
    }

    fn credential_generation(
        &self,
        database_url: &str,
    ) -> Result<CredentialGeneration, NotaryPostgresStatePlaneError> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.credential_tag_key.as_ref())
            .map_err(|_| NotaryPostgresStatePlaneError::InvalidConfiguration)?;
        mac.update(b"registry-notary-postgresql-credential-generation-v1\0");
        mac.update(database_url.as_bytes());
        let mut generation = [0_u8; 32];
        generation.copy_from_slice(&mac.finalize().into_bytes());
        Ok(generation)
    }

    async fn open_physical_session(
        &self,
    ) -> Result<PhysicalPostgresSession, NotaryPostgresStatePlaneError> {
        if self.sessions.is_shutdown() {
            return Err(NotaryPostgresStatePlaneError::Shutdown);
        }
        let database_url = load_database_url(&self.database_url_env)?;
        let credential_generation = self.credential_generation(database_url.as_str())?;
        let postgres_config = parse_database_config(database_url.as_str())?;
        drop(database_url);
        let connector = MakeTlsConnector::new(self.tls_connector.clone());
        let (client, connection) =
            tokio::time::timeout(self.connect_timeout, postgres_config.connect(connector))
                .await
                .map_err(|_| NotaryPostgresStatePlaneError::DatabaseUnavailable)?
                .map_err(|_| NotaryPostgresStatePlaneError::DatabaseUnavailable)?;
        drop(postgres_config);

        let driver = tokio::spawn(connection);
        let session_id = self.sessions.register(driver.abort_handle())?;
        let session = PhysicalPostgresSession {
            client,
            driver: Some(driver),
            session_id,
            sessions: Arc::clone(&self.sessions),
            operation_timeout: self.operation_timeout,
            credential_generation,
            poisoned: AtomicBool::new(false),
        };
        session.configure().await?;
        session.attest().await?;
        if self.sessions.is_shutdown() {
            return Err(NotaryPostgresStatePlaneError::Shutdown);
        }
        if session
            .driver
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err(NotaryPostgresStatePlaneError::DatabaseUnavailable);
        }
        Ok(session)
    }
}

impl Manager for ConnectionFactory {
    type Type = PhysicalPostgresSession;
    type Error = NotaryPostgresStatePlaneError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        self.open_physical_session().await
    }

    async fn recycle(
        &self,
        session: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        if self.sessions.is_shutdown() {
            return Err(RecycleError::Backend(
                NotaryPostgresStatePlaneError::Shutdown,
            ));
        }
        if session.poisoned.load(Ordering::Acquire)
            || session.client.is_closed()
            || session
                .driver
                .as_ref()
                .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err(RecycleError::Backend(
                NotaryPostgresStatePlaneError::DatabaseUnavailable,
            ));
        }
        let database_url = load_database_url(&self.database_url_env)?;
        let current_generation = self.credential_generation(database_url.as_str())?;
        drop(database_url);
        if !bool::from(session.credential_generation.ct_eq(&current_generation)) {
            return Err(RecycleError::Backend(
                NotaryPostgresStatePlaneError::DatabaseUnavailable,
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct SessionRegistry {
    shutdown: AtomicBool,
    next_session_id: AtomicU64,
    drivers: Mutex<HashMap<u64, AbortHandle>>,
}

impl SessionRegistry {
    fn register(&self, driver: AbortHandle) -> Result<u64, NotaryPostgresStatePlaneError> {
        if self.is_shutdown() {
            driver.abort();
            return Err(NotaryPostgresStatePlaneError::Shutdown);
        }
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let mut drivers = self
            .drivers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.is_shutdown() {
            driver.abort();
            return Err(NotaryPostgresStatePlaneError::Shutdown);
        }
        drivers.insert(session_id, driver);
        Ok(session_id)
    }

    fn unregister(&self, session_id: u64) {
        self.drivers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&session_id);
    }

    fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        let drivers = {
            let mut registered = self
                .drivers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *registered)
        };
        for driver in drivers.into_values() {
            driver.abort();
        }
    }

    fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

fn load_database_url(
    database_url_env: &str,
) -> Result<Zeroizing<String>, NotaryPostgresStatePlaneError> {
    let value = Zeroizing::new(
        env::var(database_url_env)
            .map_err(|_| NotaryPostgresStatePlaneError::DatabaseUrlUnavailable)?,
    );
    if value.trim().is_empty() {
        return Err(NotaryPostgresStatePlaneError::DatabaseUrlUnavailable);
    }
    Ok(value)
}

fn parse_database_config(
    database_url: &str,
) -> Result<TokioPostgresConfig, NotaryPostgresStatePlaneError> {
    let mut config = database_url
        .parse::<TokioPostgresConfig>()
        .map_err(|_| NotaryPostgresStatePlaneError::InvalidDatabaseUrl)?;
    if config.get_ssl_mode() != SslMode::Require {
        return Err(NotaryPostgresStatePlaneError::TlsRequired);
    }
    config.target_session_attrs(TargetSessionAttrs::ReadWrite);
    Ok(config)
}

fn build_tls_connector(
    root_certificate_path: Option<&Path>,
) -> Result<TlsConnector, NotaryPostgresStatePlaneError> {
    let mut builder = TlsConnector::builder();
    if let Some(path) = root_certificate_path {
        let certificate_bytes = read_bounded_root_certificate(path)?;
        let certificate = native_tls::Certificate::from_pem(&certificate_bytes)
            .map_err(|_| NotaryPostgresStatePlaneError::InvalidRootCertificate)?;
        builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|_| NotaryPostgresStatePlaneError::InvalidTlsConfiguration)
}

fn read_bounded_root_certificate(path: &Path) -> Result<Vec<u8>, NotaryPostgresStatePlaneError> {
    if path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > MAX_ROOT_CERTIFICATE_PATH_BYTES
    {
        return Err(NotaryPostgresStatePlaneError::InvalidRootCertificatePath);
    }
    let file =
        File::open(path).map_err(|_| NotaryPostgresStatePlaneError::RootCertificateUnavailable)?;
    let mut limited = file.take((MAX_ROOT_CERTIFICATE_BYTES + 1) as u64);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| NotaryPostgresStatePlaneError::RootCertificateUnavailable)?;
    if bytes.len() > MAX_ROOT_CERTIFICATE_BYTES {
        return Err(NotaryPostgresStatePlaneError::RootCertificateTooLarge);
    }
    Ok(bytes)
}

fn duration_as_postgres_milliseconds(duration: Duration) -> String {
    format!("{}ms", duration.as_millis())
}

fn map_pool_error(
    error: PoolError<NotaryPostgresStatePlaneError>,
) -> NotaryPostgresStatePlaneError {
    match error {
        PoolError::Backend(error) => error,
        PoolError::Closed => NotaryPostgresStatePlaneError::Shutdown,
        PoolError::Timeout(_) => NotaryPostgresStatePlaneError::OperationUnavailable,
        PoolError::NoRuntimeSpecified | PoolError::PostCreateHook(_) => {
            NotaryPostgresStatePlaneError::InvalidConfiguration
        }
    }
}

const fn map_attestation_error(error: StatePlaneMigrationError) -> NotaryPostgresStatePlaneError {
    match error {
        StatePlaneMigrationError::UnsupportedServerMajor => {
            NotaryPostgresStatePlaneError::UnsupportedServerMajor
        }
        StatePlaneMigrationError::DatabaseNotWritable => {
            NotaryPostgresStatePlaneError::DatabaseNotWritable
        }
        StatePlaneMigrationError::UnsafeDurability => {
            NotaryPostgresStatePlaneError::UnsafeDurability
        }
        StatePlaneMigrationError::PartialInstallation
        | StatePlaneMigrationError::CapabilityDrift => {
            NotaryPostgresStatePlaneError::SchemaIncompatible
        }
        StatePlaneMigrationError::InvalidRuntimeRole
        | StatePlaneMigrationError::InvalidOwnerRole
        | StatePlaneMigrationError::OwnerRoleUnavailable
        | StatePlaneMigrationError::InvalidRuntimeRoleContract
        | StatePlaneMigrationError::RoleCollision => {
            NotaryPostgresStatePlaneError::RoleIncompatible
        }
        StatePlaneMigrationError::Unavailable => NotaryPostgresStatePlaneError::DatabaseUnavailable,
    }
}

const fn readiness_from_error(
    error: NotaryPostgresStatePlaneError,
) -> NotaryPostgresStatePlaneReadiness {
    match error {
        NotaryPostgresStatePlaneError::InvalidConfiguration
        | NotaryPostgresStatePlaneError::InvalidTimeout
        | NotaryPostgresStatePlaneError::InvalidRootCertificatePath
        | NotaryPostgresStatePlaneError::RootCertificateUnavailable
        | NotaryPostgresStatePlaneError::RootCertificateTooLarge
        | NotaryPostgresStatePlaneError::InvalidRootCertificate
        | NotaryPostgresStatePlaneError::InvalidTlsConfiguration => {
            NotaryPostgresStatePlaneReadiness::ConfigurationInvalid
        }
        NotaryPostgresStatePlaneError::DatabaseUrlUnavailable
        | NotaryPostgresStatePlaneError::InvalidDatabaseUrl
        | NotaryPostgresStatePlaneError::TlsRequired
        | NotaryPostgresStatePlaneError::DatabaseUnavailable
        | NotaryPostgresStatePlaneError::OperationUnavailable => {
            NotaryPostgresStatePlaneReadiness::DatabaseUnavailable
        }
        NotaryPostgresStatePlaneError::UnsupportedServerMajor => {
            NotaryPostgresStatePlaneReadiness::UnsupportedServerMajor
        }
        NotaryPostgresStatePlaneError::DatabaseNotWritable => {
            NotaryPostgresStatePlaneReadiness::DatabaseNotWritable
        }
        NotaryPostgresStatePlaneError::UnsafeDurability => {
            NotaryPostgresStatePlaneReadiness::UnsafeDurability
        }
        NotaryPostgresStatePlaneError::SchemaIncompatible => {
            NotaryPostgresStatePlaneReadiness::SchemaIncompatible
        }
        NotaryPostgresStatePlaneError::RoleIncompatible => {
            NotaryPostgresStatePlaneReadiness::RoleIncompatible
        }
        NotaryPostgresStatePlaneError::Shutdown => NotaryPostgresStatePlaneReadiness::Shutdown,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, future::pending};

    use super::*;

    const SECRET_URL: &str =
        "postgresql://sentinel-user:sentinel-password@sentinel-host/state?sslmode=disable";

    fn config() -> PostgresStatePlaneConfig {
        PostgresStatePlaneConfig::new(
            "SENTINEL_DATABASE_URL",
            Some(PathBuf::from("/sentinel/root.pem")),
            Duration::from_secs(5),
            Duration::from_secs(2),
            16,
        )
        .expect("test configuration is valid")
    }

    #[test]
    fn database_url_policy_requires_tls_and_primary_selection() {
        let error = parse_database_config(SECRET_URL).expect_err("plaintext fallback is rejected");
        assert_eq!(error, NotaryPostgresStatePlaneError::TlsRequired);
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
    fn runtime_configuration_debug_redacts_environment_and_path() {
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains("SENTINEL_DATABASE_URL"));
        assert!(!rendered.contains("/sentinel/root.pem"));
        assert!(rendered.contains("custom_root_certificate"));
    }

    #[test]
    fn credential_generation_changes_without_retaining_url_material() {
        let config = PostgresStatePlaneConfig::new(
            "SENTINEL_DATABASE_URL",
            None,
            Duration::from_secs(5),
            Duration::from_secs(2),
            16,
        )
        .expect("test configuration is valid");
        let factory = ConnectionFactory::new(&config, Arc::new(SessionRegistry::default()))
            .expect("connection factory is valid");
        let first = factory
            .credential_generation("postgresql://sentinel:first@localhost/state?sslmode=require")
            .expect("first generation is available");
        let second = factory
            .credential_generation("postgresql://sentinel:second@localhost/state?sslmode=require")
            .expect("second generation is available");
        assert_ne!(first, second);
        let rendered = format!("{first:?} {second:?}");
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("postgresql://"));
    }

    #[test]
    fn cancelled_operation_guard_poisons_only_armed_sessions() {
        let cancelled = AtomicBool::new(false);
        drop(PoisonSessionOnDrop::new(&cancelled));
        assert!(cancelled.load(Ordering::Acquire));

        let completed = AtomicBool::new(false);
        {
            let mut guard = PoisonSessionOnDrop::new(&completed);
            guard.disarm();
        }
        assert!(!completed.load(Ordering::Acquire));
    }

    #[test]
    fn zero_timeouts_fail_closed() {
        assert_eq!(
            PostgresStatePlaneConfig::new(
                "DATABASE_URL",
                None,
                Duration::ZERO,
                Duration::from_secs(1),
                16,
            ),
            Err(NotaryPostgresStatePlaneError::InvalidTimeout)
        );
        assert_eq!(
            PostgresStatePlaneConfig::new(
                "DATABASE_URL",
                None,
                Duration::from_secs(1),
                Duration::from_secs(1),
                0,
            ),
            Err(NotaryPostgresStatePlaneError::InvalidConfiguration)
        );
    }

    #[test]
    fn root_certificate_read_is_bounded_and_path_is_not_disclosed() {
        let path = env::temp_dir().join(format!(
            "registry-notary-state-plane-sentinel-{}.pem",
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
            NotaryPostgresStatePlaneError::RootCertificateTooLarge
        );
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains(path.to_string_lossy().as_ref()));
    }

    #[test]
    fn retention_maintenance_uses_the_fixed_bounded_contract() {
        assert_eq!(RETENTION_MAINTENANCE_BATCH_SIZE, 1_000);
        assert_eq!(RETENTION_MAINTENANCE_CADENCE, Duration::from_secs(60));
        assert_eq!(
            RETENTION_CATCH_UP_INITIAL_BACKOFF,
            Duration::from_millis(10)
        );
        assert_eq!(RETENTION_CATCH_UP_MAX_BACKOFF, Duration::from_millis(100));
        assert_eq!(
            RETENTION_PRUNE_QUERY,
            "SELECT deleted_count, batch_saturated FROM registry_notary_api.retention_prune_v1($1)"
        );
    }

    #[tokio::test]
    async fn retention_catch_up_repeats_saturated_batches_until_short() {
        let attempts = Arc::new(AtomicU64::new(0));
        let prune_attempts = Arc::clone(&attempts);
        let (_shutdown, mut shutdown_rx) = watch::channel(false);

        let outcome = catch_up_postgres_retention(
            &mut shutdown_rx,
            Duration::ZERO,
            Duration::ZERO,
            move || {
                let attempt = prune_attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    Ok(RetentionPruneOutcome {
                        batch_saturated: attempt < 2,
                    })
                }
            },
        )
        .await
        .expect("successful retention batches catch up");

        assert_eq!(outcome, RetentionCatchUpOutcome::CaughtUp);
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn retention_catch_up_observes_shutdown_already_signaled() {
        let attempts = Arc::new(AtomicU64::new(0));
        let prune_attempts = Arc::clone(&attempts);
        let (shutdown, mut shutdown_rx) = watch::channel(false);
        shutdown.send(true).expect("shutdown receiver remains open");

        let outcome = catch_up_postgres_retention(
            &mut shutdown_rx,
            RETENTION_CATCH_UP_INITIAL_BACKOFF,
            RETENTION_CATCH_UP_MAX_BACKOFF,
            move || {
                prune_attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    Ok(RetentionPruneOutcome {
                        batch_saturated: true,
                    })
                }
            },
        )
        .await
        .expect("shutdown is not a maintenance failure");

        assert_eq!(outcome, RetentionCatchUpOutcome::Shutdown);
        assert_eq!(attempts.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn retention_maintenance_retries_value_free_failures_and_stops_cleanly() {
        let config = PostgresStatePlaneConfig::new(
            "REGISTRY_NOTARY_RETENTION_TEST_DATABASE_URL_MUST_BE_UNSET",
            None,
            Duration::from_millis(10),
            Duration::from_millis(10),
            1,
        )
        .expect("test configuration is valid");
        let sessions = Arc::new(SessionRegistry::default());
        let manager = ConnectionFactory::new(&config, Arc::clone(&sessions))
            .expect("test connection policy is valid");
        let connections = PostgresSessionPool::builder(manager)
            .max_size(config.max_connections())
            .wait_timeout(Some(config.operation_timeout()))
            .runtime(deadpool::Runtime::Tokio1)
            .build()
            .expect("test connection pool is valid");
        let runtime = Arc::new(NotaryPostgresStatePlaneRuntime {
            connections,
            sessions,
            retention_attempts: AtomicU64::new(0),
        });
        let maintenance = start_postgres_retention_maintenance_with_cadence(
            Arc::clone(&runtime),
            Duration::from_millis(5),
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            while runtime.retention_attempts.load(Ordering::Relaxed) < 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("maintenance retries after a value-free transient failure");
        assert!(
            !maintenance.task.is_finished(),
            "maintenance failure must not stop the serving worker"
        );
        assert!(
            !runtime.is_shutdown(),
            "maintenance failure must not poison the request runtime"
        );
        assert_eq!(
            runtime.readiness().await,
            NotaryPostgresStatePlaneReadiness::DatabaseUnavailable,
            "readiness must still perform its own database attestation"
        );

        maintenance.shutdown();
        tokio::task::yield_now().await;
        assert!(maintenance.task.is_finished());
        let attempts_after_shutdown = runtime.retention_attempts.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            runtime.retention_attempts.load(Ordering::Relaxed),
            attempts_after_shutdown,
            "stopped maintenance must not retry or open another connection"
        );
        drop(maintenance);
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&runtime), 1);
        runtime.shutdown();
    }

    #[tokio::test]
    async fn shutdown_aborts_registered_drivers_and_rejects_registration() {
        let registry = SessionRegistry::default();
        let driver = tokio::spawn(async {
            pending::<()>().await;
            Ok::<(), tokio_postgres::Error>(())
        });
        let abort = driver.abort_handle();
        let session_id = registry
            .register(abort.clone())
            .expect("driver registers before shutdown");
        assert_eq!(session_id, 0);

        registry.shutdown();
        tokio::task::yield_now().await;
        assert!(abort.is_finished());

        let late_driver = tokio::spawn(async {
            pending::<()>().await;
            Ok::<(), tokio_postgres::Error>(())
        });
        let late_abort = late_driver.abort_handle();
        assert_eq!(
            registry.register(late_abort.clone()),
            Err(NotaryPostgresStatePlaneError::Shutdown)
        );
        tokio::task::yield_now().await;
        assert!(late_abort.is_finished());

        driver.abort();
        late_driver.abort();
    }

    #[test]
    fn readiness_codes_and_errors_are_value_free() {
        let readiness = [
            NotaryPostgresStatePlaneReadiness::Ready,
            NotaryPostgresStatePlaneReadiness::ConfigurationInvalid,
            NotaryPostgresStatePlaneReadiness::DatabaseUnavailable,
            NotaryPostgresStatePlaneReadiness::UnsupportedServerMajor,
            NotaryPostgresStatePlaneReadiness::DatabaseNotWritable,
            NotaryPostgresStatePlaneReadiness::UnsafeDurability,
            NotaryPostgresStatePlaneReadiness::SchemaIncompatible,
            NotaryPostgresStatePlaneReadiness::RoleIncompatible,
            NotaryPostgresStatePlaneReadiness::Shutdown,
        ];
        for state in readiness {
            let rendered = format!("{state:?} {}", state.code());
            assert!(!rendered.contains("sentinel"));
            assert!(!rendered.contains("postgresql://"));
        }

        let errors = [
            NotaryPostgresStatePlaneError::InvalidConfiguration,
            NotaryPostgresStatePlaneError::InvalidTimeout,
            NotaryPostgresStatePlaneError::DatabaseUrlUnavailable,
            NotaryPostgresStatePlaneError::InvalidDatabaseUrl,
            NotaryPostgresStatePlaneError::TlsRequired,
            NotaryPostgresStatePlaneError::InvalidRootCertificatePath,
            NotaryPostgresStatePlaneError::RootCertificateUnavailable,
            NotaryPostgresStatePlaneError::RootCertificateTooLarge,
            NotaryPostgresStatePlaneError::InvalidRootCertificate,
            NotaryPostgresStatePlaneError::InvalidTlsConfiguration,
            NotaryPostgresStatePlaneError::DatabaseUnavailable,
            NotaryPostgresStatePlaneError::UnsupportedServerMajor,
            NotaryPostgresStatePlaneError::DatabaseNotWritable,
            NotaryPostgresStatePlaneError::UnsafeDurability,
            NotaryPostgresStatePlaneError::SchemaIncompatible,
            NotaryPostgresStatePlaneError::RoleIncompatible,
            NotaryPostgresStatePlaneError::OperationUnavailable,
            NotaryPostgresStatePlaneError::Shutdown,
        ];
        for error in errors {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("sentinel"));
            assert!(!rendered.contains("postgresql://"));
        }
    }

    #[test]
    fn runtime_errors_map_to_closed_doctor_component_codes() {
        let cases = [
            (
                NotaryPostgresStatePlaneError::InvalidConfiguration,
                "configuration_invalid",
            ),
            (
                NotaryPostgresStatePlaneError::DatabaseUnavailable,
                "database_unavailable",
            ),
            (
                NotaryPostgresStatePlaneError::SchemaIncompatible,
                "schema_incompatible",
            ),
            (
                NotaryPostgresStatePlaneError::RoleIncompatible,
                "role_incompatible",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(
                NotaryPostgresStatePlaneReadiness::from_error(error).doctor_component_code(),
                expected
            );
        }
    }
}
