// SPDX-License-Identifier: Apache-2.0
//! Startup ordering gate for one verified Registry package.

use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::{middleware, Router};
use registry_platform_audit::AuditProfile;
use registry_platform_oidc::JwksFetcher;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio_postgres::{Client, GenericClient};
use tracing_subscriber::filter::LevelFilter;

use crate::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use crate::auth::RegistryAuthenticator;
#[cfg(all(feature = "runtime", feature = "tooling"))]
use crate::model::CompiledRegistry;
use crate::package::{load_package, PackageIntent, PackageLoadContext, VerifiedPackage};
use crate::postgres::{
    verify_catalog_identity_for_catalog, ExpectedManagedCatalog, ExpectedRegistryIdentity,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    RegistryLockKey, RuntimePool, SqlIdentifier,
};
use crate::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};
use crate::webhook::{WebhookDeliveryService, WebhookWorker};

/// Value-free startup refusal. Package paths, database values, and physical
/// catalog details are intentionally unavailable through Display and Debug.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum StartupError {
    #[error("the Registry runtime configuration was refused")]
    RuntimeConfig,
    #[error("the Registry package was refused")]
    PackageRefused,
    #[error("the Registry database connection was refused")]
    DatabaseConnection,
    #[error("the Registry database is not ready for this package")]
    DatabaseUnready,
    #[error("the Registry audit profile was refused")]
    Audit,
    #[error("the Registry cursor profile was refused")]
    Cursor,
    #[error("the Registry OIDC key source was refused")]
    Oidc,
    #[error("the Registry authentication profile was refused")]
    Authentication,
    #[error("the Registry event destination bindings were refused")]
    EventDestinations,
    #[error("the Registry listener could not be started")]
    Listener,
    #[error("the Registry shutdown signal failed")]
    Shutdown,
    #[error("the Registry operational log level was refused")]
    Logging,
}

pub type Result<T> = std::result::Result<T, StartupError>;

/// The closed severity vocabulary emitted by Registry Server operational
/// events. Audit and Registry provenance use separate channels and types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalLogLevel {
    Info,
    Warn,
    Error,
}

/// Closed webhook state-transition failure codes. These codes identify only
/// the failed transition class and never carry destination or event values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookStateTransitionCode {
    ClaimIdentityRefused,
    ClaimRecoveryFailed,
    ClaimSelectFailed,
    ClaimPolicyRefused,
    ClaimUpdateFailed,
    ClaimAuditFailed,
    ClaimCommitFailed,
}

impl WebhookStateTransitionCode {
    /// Every allowed state-transition code, used by exhaustive operational-log
    /// contract tests.
    pub const ALL: [Self; 7] = [
        Self::ClaimIdentityRefused,
        Self::ClaimRecoveryFailed,
        Self::ClaimSelectFailed,
        Self::ClaimPolicyRefused,
        Self::ClaimUpdateFailed,
        Self::ClaimAuditFailed,
        Self::ClaimCommitFailed,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimIdentityRefused => "webhook.claim.identity_refused",
            Self::ClaimRecoveryFailed => "webhook.claim.recovery_failed",
            Self::ClaimSelectFailed => "webhook.claim.select_failed",
            Self::ClaimPolicyRefused => "webhook.claim.policy_refused",
            Self::ClaimUpdateFailed => "webhook.claim.update_failed",
            Self::ClaimAuditFailed => "webhook.claim.audit_failed",
            Self::ClaimCommitFailed => "webhook.claim.commit_failed",
        }
    }
}

/// A rendered operational event. Its fields are an allowlist of low-cardinality,
/// value-free process state. It is deliberately unrelated to Registry audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalLogRecord {
    level: OperationalLogLevel,
    target: &'static str,
    message: &'static str,
    error: Option<&'static str>,
    code: Option<&'static str>,
}

impl OperationalLogRecord {
    #[must_use]
    pub const fn level(self) -> OperationalLogLevel {
        self.level
    }

    #[must_use]
    pub const fn target(self) -> &'static str {
        self.target
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }

    #[must_use]
    pub const fn error(self) -> Option<&'static str> {
        self.error
    }

    #[must_use]
    pub const fn code(self) -> Option<&'static str> {
        self.code
    }
}

/// The complete production operational-event vocabulary. Variants accept only
/// closed errors or codes, so request, record, SQL, secret, path, destination,
/// payload, upstream, and caller trace values cannot reach the renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalEvent {
    StartupBegan,
    Listening,
    Stopped,
    StoppedWithError(StartupError),
    WebhookWorkerIterationFailed,
    WebhookStateTransitionFailed(WebhookStateTransitionCode),
}

impl OperationalEvent {
    #[must_use]
    pub const fn record(self) -> OperationalLogRecord {
        match self {
            Self::StartupBegan => OperationalLogRecord {
                level: OperationalLogLevel::Info,
                target: "registry_server::startup",
                message: "Registry Server startup began",
                error: None,
                code: None,
            },
            Self::Listening => OperationalLogRecord {
                level: OperationalLogLevel::Info,
                target: "registry_server::startup",
                message: "Registry Server is listening",
                error: None,
                code: None,
            },
            Self::Stopped => OperationalLogRecord {
                level: OperationalLogLevel::Error,
                target: "registry_server::startup",
                message: "Registry Server stopped",
                error: None,
                code: None,
            },
            Self::StoppedWithError(error) => OperationalLogRecord {
                level: OperationalLogLevel::Error,
                target: "registry_server::startup",
                message: "Registry Server stopped",
                error: Some(error.operational_message()),
                code: None,
            },
            Self::WebhookWorkerIterationFailed => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_server::webhook",
                message: "webhook worker iteration failed",
                error: None,
                code: Some("webhook.worker.iteration_failed"),
            },
            Self::WebhookStateTransitionFailed(code) => OperationalLogRecord {
                level: OperationalLogLevel::Warn,
                target: "registry_server::webhook",
                message: "webhook state transition failed",
                error: None,
                code: Some(code.as_str()),
            },
        }
    }

    /// Emit one record through the production JSON tracing subscriber. This is
    /// the only production tracing entry point in Registry Server.
    pub fn emit(self) {
        let record = self.record();
        match self {
            Self::StartupBegan | Self::Listening => {
                tracing::info!(target: "registry_server::startup", message = record.message);
            }
            Self::Stopped => {
                tracing::error!(target: "registry_server::startup", message = record.message);
            }
            Self::StoppedWithError(_) => {
                let error = record
                    .error
                    .expect("stopped-with-error records have a closed error");
                tracing::error!(target: "registry_server::startup", error, message = record.message);
            }
            Self::WebhookWorkerIterationFailed | Self::WebhookStateTransitionFailed(_) => {
                let code = record.code.expect("webhook warning records have a code");
                tracing::warn!(target: "registry_server::webhook", code, message = record.message);
            }
        }
    }
}

impl StartupError {
    const fn operational_message(self) -> &'static str {
        match self {
            Self::RuntimeConfig => "the Registry runtime configuration was refused",
            Self::PackageRefused => "the Registry package was refused",
            Self::DatabaseConnection => "the Registry database connection was refused",
            Self::DatabaseUnready => "the Registry database is not ready for this package",
            Self::Audit => "the Registry audit profile was refused",
            Self::Cursor => "the Registry cursor profile was refused",
            Self::Oidc => "the Registry OIDC key source was refused",
            Self::Authentication => "the Registry authentication profile was refused",
            Self::EventDestinations => "the Registry event destination bindings were refused",
            Self::Listener => "the Registry listener could not be started",
            Self::Shutdown => "the Registry shutdown signal failed",
            Self::Logging => "the Registry operational log level was refused",
        }
    }
}

/// Unforgeable listener gate produced only after package closure and database
/// readiness verification. Listener construction must consume this object.
pub struct VerifiedStartup {
    package: VerifiedPackage,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    lock_key: RegistryLockKey,
}

impl VerifiedStartup {
    pub fn package(&self) -> &VerifiedPackage {
        &self.package
    }

    pub fn into_package(self) -> VerifiedPackage {
        self.package
    }

    pub fn expected_identity(&self) -> &ExpectedRegistryIdentity {
        &self.expected
    }

    pub fn expected_catalog(&self) -> &ExpectedManagedCatalog {
        &self.expected_catalog
    }

    pub fn lock_key(&self) -> RegistryLockKey {
        self.lock_key
    }
}

/// Fully verified server state. Fields are private so production listeners can
/// only be created by consuming this value through [`serve`].
pub struct PreparedServer {
    bind: SocketAddr,
    app: Router,
    shutdown_grace: Duration,
    webhook_worker: Option<WebhookWorker>,
    #[cfg(all(feature = "postgres-test", feature = "tooling"))]
    fixture_pool: Option<RuntimePool>,
}

impl PreparedServer {
    pub fn app(&self) -> Router {
        self.app.clone()
    }

    #[must_use]
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Return the Router and PostgreSQL pool only when both were assembled by
    /// the verified startup path. Raw test-part constructors deliberately
    /// carry no such capability, so fixture receipt code cannot attest canned
    /// Routers or a caller-selected database.
    #[cfg(all(feature = "postgres-test", feature = "tooling"))]
    pub(crate) fn fixture_runtime(&self) -> Option<(Router, RuntimePool)> {
        self.fixture_pool
            .as_ref()
            .map(|pool| (self.app.clone(), pool.clone()))
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_parts_for_test(bind: SocketAddr, app: Router, shutdown_grace: Duration) -> Self {
        Self {
            bind,
            app,
            shutdown_grace,
            webhook_worker: None,
            #[cfg(feature = "tooling")]
            fixture_pool: None,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_parts_with_webhook_worker_for_test(
        bind: SocketAddr,
        app: Router,
        shutdown_grace: Duration,
        webhook_worker: WebhookWorker,
    ) -> Self {
        Self {
            bind,
            app,
            shutdown_grace,
            webhook_worker: Some(webhook_worker),
            #[cfg(feature = "tooling")]
            fixture_pool: None,
        }
    }
}

/// Production startup. The package is verified before any secret resolution,
/// database connection, OIDC discovery, audit profile, or listener bind.
pub async fn prepare(config_path: &Path) -> Result<PreparedServer> {
    let config = load_runtime_config(config_path).map_err(map_runtime_config_error)?;
    let package_root = config.package().root().to_path_buf();
    let package = {
        let package_context = config.package_load_context();
        load_package(&package_root, &package_context).map_err(|_| StartupError::PackageRefused)?
    };
    let connection = config
        .runtime_database_connection_config()
        .map_err(map_runtime_config_error)?;
    prepare_verified_package_with_connection(config, package, connection).await
}

/// Prepare the clean database capability consumed by the production pre-sign
/// schema-test executor. This is not a serving path and returns no listener,
/// router, pool, or client.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub async fn prepare_schema_test_database(
    config: &RuntimeConfig,
    candidate: &crate::package::PreparedPackage,
) -> Result<crate::postgres::PreparedSchemaTestDatabase> {
    validate_schema_test_candidate_binding(config, candidate)?;
    let migration = config
        .migration_database_connection_config()
        .map_err(map_runtime_config_error)?;
    let runtime = config
        .runtime_database_connection_config()
        .map_err(map_runtime_config_error)?;
    prepare_schema_test_database_with_connection_configs(config, candidate, &migration, &runtime)
        .await
}

/// Rehearse the managed schema fingerprint for one production-compiled
/// Registry using the configured migration and runtime roles. This boundary
/// validates deployment bindings before resolving database secrets and returns
/// only the measured fingerprint.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub async fn rehearse_schema_fingerprint(
    config: &RuntimeConfig,
    registry: &CompiledRegistry,
) -> Result<String> {
    validate_rehearsal_registry_binding(config, registry)?;
    let migration = config
        .migration_database_connection_config()
        .map_err(map_runtime_config_error)?;
    rehearse_schema_fingerprint_with_connection_config(config, registry, &migration).await
}

#[cfg(all(feature = "runtime", feature = "tooling", feature = "postgres-test"))]
#[doc(hidden)]
pub async fn rehearse_schema_fingerprint_with_connection_config_for_test(
    config: &RuntimeConfig,
    registry: &CompiledRegistry,
    migration: &crate::postgres::ConnectionConfig,
) -> Result<String> {
    validate_rehearsal_registry_binding(config, registry)?;
    rehearse_schema_fingerprint_with_connection_config(config, registry, migration).await
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
async fn rehearse_schema_fingerprint_with_connection_config(
    config: &RuntimeConfig,
    registry: &CompiledRegistry,
    migration: &crate::postgres::ConnectionConfig,
) -> Result<String> {
    crate::postgres::rehearse_schema_fingerprint_with_connection(
        migration,
        config.database().roles().migration(),
        config.database().roles().runtime(),
        registry,
    )
    .await
    .map_err(|_| StartupError::DatabaseUnready)
}

#[cfg(all(feature = "runtime", feature = "tooling", feature = "postgres-test"))]
#[doc(hidden)]
pub async fn prepare_schema_test_database_with_connection_configs_for_test(
    config: &RuntimeConfig,
    candidate: &crate::package::PreparedPackage,
    migration: &crate::postgres::ConnectionConfig,
    runtime: &crate::postgres::ConnectionConfig,
) -> Result<crate::postgres::PreparedSchemaTestDatabase> {
    validate_schema_test_candidate_binding(config, candidate)?;
    prepare_schema_test_database_with_connection_configs(config, candidate, migration, runtime)
        .await
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
async fn prepare_schema_test_database_with_connection_configs(
    config: &RuntimeConfig,
    candidate: &crate::package::PreparedPackage,
    migration: &crate::postgres::ConnectionConfig,
    runtime: &crate::postgres::ConnectionConfig,
) -> Result<crate::postgres::PreparedSchemaTestDatabase> {
    let manifest = candidate.manifest();
    crate::postgres::prepare_schema_test_database_with_connections(
        migration,
        runtime,
        config.database().roles().migration(),
        config.database().roles().runtime(),
        candidate.registry(),
        crate::postgres::SchemaTestDatabaseIdentity {
            environment: &manifest.environment,
            instance_id: &manifest.instance_id,
            database_id: &manifest.database_id,
            active_package_revision: &manifest.package_revision,
            active_sequence: manifest.sequence,
        },
    )
    .await
    .map_err(|_| StartupError::DatabaseUnready)
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
fn validate_schema_test_candidate_binding(
    config: &RuntimeConfig,
    candidate: &crate::package::PreparedPackage,
) -> Result<()> {
    let manifest = candidate.manifest();
    if config.identity().environment() != manifest.environment
        || config.identity().instance_id() != manifest.instance_id
        || config.identity().database_id() != manifest.database_id
        || config.package().compiler_source_revision() != manifest.compiler.source_revision
        || candidate.registry().registry_id() != manifest.package_id
    {
        return Err(StartupError::PackageRefused);
    }
    Ok(())
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
fn validate_rehearsal_registry_binding(
    config: &RuntimeConfig,
    registry: &CompiledRegistry,
) -> Result<()> {
    let package = registry.package().ok_or(StartupError::PackageRefused)?;
    if config.identity().environment() != package.environment
        || config.identity().instance_id() != package.instance_id
        || config.package().compiler_source_revision() != package.source_revision
    {
        return Err(StartupError::PackageRefused);
    }
    Ok(())
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn prepare_with_connection_config_for_test(
    config_path: &Path,
    connection: crate::postgres::ConnectionConfig,
) -> Result<PreparedServer> {
    let config = load_runtime_config(config_path).map_err(map_runtime_config_error)?;
    let package_root = config.package().root().to_path_buf();
    let package = {
        let package_context = config.package_load_context();
        load_package(&package_root, &package_context).map_err(|_| StartupError::PackageRefused)?
    };
    prepare_verified_package_with_connection(config, package, connection).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn prepare_with_connection_and_key_source_for_test(
    config_path: &Path,
    connection: crate::postgres::ConnectionConfig,
    key_source: Arc<JwksFetcher>,
) -> Result<PreparedServer> {
    let config = load_runtime_config(config_path).map_err(map_runtime_config_error)?;
    let package_root = config.package().root().to_path_buf();
    let package = {
        let package_context = config.package_load_context();
        load_package(&package_root, &package_context).map_err(|_| StartupError::PackageRefused)?
    };
    prepare_verified_package_with_key_source(config, package, connection, key_source).await
}

async fn prepare_verified_package_with_connection(
    config: RuntimeConfig,
    package: VerifiedPackage,
    connection: crate::postgres::ConnectionConfig,
) -> Result<PreparedServer> {
    let (pool, startup) = prepare_database_startup(
        package,
        &connection,
        config.database().roles().migration(),
        config.database().roles().runtime(),
    )
    .await?;
    let audit_profile = config.audit_profile().map_err(|_| StartupError::Audit)?;
    let cursor_codec = Arc::new(config.cursor_codec().map_err(|_| StartupError::Cursor)?);
    let key_source = config
        .oidc_key_source()
        .await
        .map_err(map_runtime_config_error)?;
    finish_prepared_server(
        config,
        startup,
        pool,
        key_source,
        audit_profile,
        cursor_codec,
    )
    .await
}

#[cfg(feature = "postgres-test")]
async fn prepare_verified_package_with_key_source(
    config: RuntimeConfig,
    package: VerifiedPackage,
    connection: crate::postgres::ConnectionConfig,
    key_source: Arc<JwksFetcher>,
) -> Result<PreparedServer> {
    let (pool, startup) = prepare_database_startup(
        package,
        &connection,
        config.database().roles().migration(),
        config.database().roles().runtime(),
    )
    .await?;
    let audit_profile = config.audit_profile().map_err(|_| StartupError::Audit)?;
    let cursor_codec = Arc::new(config.cursor_codec().map_err(|_| StartupError::Cursor)?);
    finish_prepared_server(
        config,
        startup,
        pool,
        key_source,
        audit_profile,
        cursor_codec,
    )
    .await
}

async fn prepare_database_startup(
    package: VerifiedPackage,
    connection: &crate::postgres::ConnectionConfig,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<(RuntimePool, VerifiedStartup)> {
    let pool = connection
        .build_pool()
        .map_err(|_| StartupError::DatabaseConnection)?;
    let mut client = pool
        .get()
        .await
        .map_err(|_| StartupError::DatabaseConnection)?;
    let startup = verify_opened_startup(package, &mut client, migration_role, runtime_role).await?;
    drop(client);
    Ok((pool, startup))
}

async fn finish_prepared_server(
    config: RuntimeConfig,
    startup: VerifiedStartup,
    pool: RuntimePool,
    key_source: Arc<JwksFetcher>,
    audit_profile: AuditProfile,
    cursor_codec: Arc<crate::cursor::CursorCodec>,
) -> Result<PreparedServer> {
    let oidc = config.authentication().oidc();
    key_source
        .ensure_key_set()
        .await
        .map_err(|_| StartupError::Oidc)?;

    let registry = Arc::new(startup.package().registry().clone());
    #[cfg(all(feature = "postgres-test", feature = "tooling"))]
    let fixture_pool = pool.clone();
    let event_destinations = Arc::new(
        config
            .activate_event_destinations(&registry)
            .map_err(|_| StartupError::EventDestinations)?,
    );
    let authenticator = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            oidc.token_verifier_config(),
            Arc::clone(&key_source),
            config.authentication().authority_claim_config(),
        )
        .map_err(|_| StartupError::Authentication)?,
    );
    let expected = startup.expected_identity().clone();
    let expected_catalog = startup.expected_catalog().clone();
    let lock_key = startup.lock_key();
    let readiness = Arc::new(DynamicRuntimeReadiness::new(
        pool.clone(),
        expected.clone(),
        expected_catalog.clone(),
        config.database().roles().migration().clone(),
        config.database().roles().runtime().clone(),
        lock_key,
        Arc::clone(&key_source),
    ));
    if !readiness.is_ready().await {
        return Err(StartupError::DatabaseUnready);
    }

    let records = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        expected.clone(),
        lock_key,
        config.operational_timeouts().record_lock,
        audit_profile.clone(),
        Arc::clone(&cursor_codec),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: expected.package_revision.clone(),
        schema_fingerprint: expected.schema_fingerprint.clone(),
    };
    let revisions = Arc::new(PostgresRevisionReadService::new(
        pool.clone(),
        Arc::clone(&registry),
        expected.clone(),
        lock_key,
        config.operational_timeouts().record_lock,
        audit_profile.clone(),
    ));
    let webhook_delivery = WebhookDeliveryService::new(
        pool.clone(),
        Arc::clone(&event_destinations),
        expected.clone(),
        lock_key,
        config.operational_timeouts().record_lock,
        audit_profile.clone(),
    );
    webhook_delivery
        .verify_retained_bindings()
        .await
        .map_err(|_| StartupError::EventDestinations)?;
    // The worker also owns payload expiry, so it runs even when the active
    // package declares no events. Compatible retained work is checked above.
    let webhook_worker = Some(WebhookWorker::new(webhook_delivery));
    let mutations = Arc::new(PostgresRecordMutationService::new_with_event_destinations(
        pool,
        Arc::clone(&registry),
        expected,
        lock_key,
        config.operational_timeouts().record_lock,
        audit_profile,
        Some(event_destinations),
    ));
    let service = Arc::new(
        HttpService::new(registry, read_identity, records, readiness, cursor_codec)
            .with_postgres_revisions(revisions)
            .with_postgres_mutations(mutations),
    );
    let app = with_request_timeout(
        authenticated_router(service, authenticator),
        config.operational_timeouts().http_request,
    );
    Ok(PreparedServer {
        bind: config.listener().bind(),
        app,
        shutdown_grace: config.operational_timeouts().shutdown_grace,
        webhook_worker,
        #[cfg(all(feature = "postgres-test", feature = "tooling"))]
        fixture_pool: Some(fixture_pool),
    })
}

fn map_runtime_config_error(error: RuntimeConfigError) -> StartupError {
    match error {
        RuntimeConfigError::InvalidDatabase | RuntimeConfigError::Secret => {
            StartupError::DatabaseConnection
        }
        RuntimeConfigError::InvalidAudit => StartupError::Audit,
        RuntimeConfigError::InvalidCursor => StartupError::Cursor,
        RuntimeConfigError::InvalidOidc => StartupError::Oidc,
        _ => StartupError::RuntimeConfig,
    }
}

#[doc(hidden)]
pub fn with_request_timeout_for_test(app: Router, timeout: Duration) -> Router {
    with_request_timeout(app, timeout)
}

fn with_request_timeout(app: Router, timeout: Duration) -> Router {
    app.layer(middleware::from_fn_with_state(timeout, request_timeout))
}

async fn request_timeout(
    axum::extract::State(timeout): axum::extract::State<Duration>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let method = crate::correlation::method_name(request.method());
    let started = std::time::Instant::now();
    let (correlation, owns_boundary) = crate::correlation::begin_request(&mut request);
    let response = match tokio::time::timeout(timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => timeout_problem(),
    };
    if owns_boundary {
        crate::correlation::finish_response(response, &correlation, method, started)
    } else {
        response
    }
}

fn timeout_problem() -> Response {
    crate::correlation::problem_response(
        StatusCode::GATEWAY_TIMEOUT,
        "urn:registry-server:problem:request.timeout",
        "Gateway Timeout",
        "The request timed out.",
        "request.timeout",
    )
}

/// Bind and serve a previously prepared server. Binding consumes the
/// preparation gate, which prevents production from accepting an externally
/// opened database connection before package verification.
pub async fn serve(prepared: PreparedServer) -> Result<()> {
    serve_until_shutdown(prepared, shutdown_signal()).await
}

pub async fn serve_until_shutdown(
    prepared: PreparedServer,
    shutdown: impl Future<Output = Result<()>>,
) -> Result<()> {
    let listener = TcpListener::bind(prepared.bind)
        .await
        .map_err(|_| StartupError::Listener)?;
    OperationalEvent::Listening.emit();
    let (worker_shutdown_tx, worker_shutdown_rx) = watch::channel(false);
    let mut worker = prepared
        .webhook_worker
        .map(|worker| tokio::spawn(worker.run(worker_shutdown_rx)));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, prepared.app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let exit = tokio::select! {
        result = &mut server => ServeExit::Server(result),
        signal = shutdown => ServeExit::Signal(signal),
    };
    let mut server_joined = matches!(exit, ServeExit::Server(_));
    let _ = worker_shutdown_tx.send(true);
    let _ = shutdown_tx.send(());
    let graceful = async {
        let result = match exit {
            ServeExit::Server(result) => map_server_result(result),
            ServeExit::Signal(signal) => {
                let server_result = map_server_result((&mut server).await);
                server_joined = true;
                signal.and(server_result)
            }
        };
        if let Some(worker) = worker.as_mut() {
            let _ = worker.await;
        }
        result
    };
    match tokio::time::timeout(prepared.shutdown_grace, graceful).await {
        Ok(result) => result,
        Err(_) => {
            if !server_joined {
                server.abort();
                let _ = (&mut server).await;
            }
            if let Some(worker) = worker.as_mut() {
                worker.abort();
                let _ = worker.await;
            }
            Err(StartupError::Shutdown)
        }
    }
}

enum ServeExit {
    Server(std::result::Result<std::result::Result<(), std::io::Error>, tokio::task::JoinError>),
    Signal(Result<()>),
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| StartupError::Shutdown)?;
        first_shutdown_signal(tokio::signal::ctrl_c(), terminate.recv()).await
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|_| StartupError::Shutdown)
    }
}

#[cfg(unix)]
async fn first_shutdown_signal<C, T, E>(ctrl_c: C, terminate: T) -> Result<()>
where
    C: Future<Output = std::result::Result<(), E>>,
    T: Future<Output = Option<()>>,
{
    tokio::select! {
        result = ctrl_c => result.map_err(|_| StartupError::Shutdown),
        result = terminate => result.ok_or(StartupError::Shutdown),
    }
}

fn map_server_result(
    result: std::result::Result<std::result::Result<(), std::io::Error>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        _ => Err(StartupError::Listener),
    }
}

pub fn operational_log_level(value: Option<&str>) -> Result<LevelFilter> {
    match value.unwrap_or("info") {
        "error" => Ok(LevelFilter::ERROR),
        "warn" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        _ => Err(StartupError::Logging),
    }
}

/// Verify the complete local package first, then require the exact active
/// package, schema fingerprint, sequence, ready maintenance state, ownership,
/// RLS, and ACL catalog before returning a listener gate.
pub async fn prepare_startup(
    package_root: &Path,
    context: &PackageLoadContext<'_>,
    client: &mut Client,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<VerifiedStartup> {
    if !matches!(context.intent, PackageIntent::Startup { .. }) {
        return Err(StartupError::PackageRefused);
    }
    // Ordering is security-relevant: no database call precedes package closure,
    // signature, binding, and compiler-derivation verification.
    let package = load_package(package_root, context).map_err(|_| StartupError::PackageRefused)?;
    verify_opened_startup(package, client, migration_role, runtime_role).await
}

async fn verify_opened_startup(
    package: VerifiedPackage,
    client: &mut Client,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<VerifiedStartup> {
    let expected = expected_identity(&package)?;
    let expected_catalog = ExpectedManagedCatalog::compiled(package.registry());
    let lock_key =
        RegistryLockKey::derive(&expected.package_id).map_err(|_| StartupError::DatabaseUnready)?;
    let transaction = client
        .transaction()
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    transaction
        .batch_execute("SET LOCAL lock_timeout = '5s'")
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    crate::postgres::verify_postgres_15_or_newer(&transaction)
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared($1)",
            &[&lock_key.get()],
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    verify_configured_runtime_role(&transaction, migration_role, runtime_role)
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    let maintenance = transaction
        .query_opt(
            "SELECT maintenance_status
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?
        .ok_or(StartupError::DatabaseUnready)?
        .get::<_, String>(0);
    if maintenance != "ready" {
        return Err(StartupError::DatabaseUnready);
    }
    verify_catalog_identity_for_catalog(
        &transaction,
        &expected,
        &expected_catalog,
        migration_role,
        runtime_role,
    )
    .await
    .map_err(|_| StartupError::DatabaseUnready)?;
    transaction
        .commit()
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    Ok(VerifiedStartup {
        package,
        expected,
        expected_catalog,
        lock_key,
    })
}

fn expected_identity(package: &VerifiedPackage) -> Result<ExpectedRegistryIdentity> {
    let manifest = package.manifest();
    let sequence = i64::try_from(manifest.sequence).map_err(|_| StartupError::DatabaseUnready)?;
    Ok(ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        environment: manifest.environment.clone(),
        instance_id: manifest.instance_id.clone(),
        database_id: manifest.database_id.clone(),
        package_revision: manifest.package_revision.clone(),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
        package_sequence: sequence,
    })
}

struct DynamicRuntimeReadiness {
    pool: RuntimePool,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_key: RegistryLockKey,
    key_source: Arc<JwksFetcher>,
}

impl DynamicRuntimeReadiness {
    fn new(
        pool: RuntimePool,
        expected: ExpectedRegistryIdentity,
        expected_catalog: ExpectedManagedCatalog,
        migration_role: SqlIdentifier,
        runtime_role: SqlIdentifier,
        lock_key: RegistryLockKey,
        key_source: Arc<JwksFetcher>,
    ) -> Self {
        Self {
            pool,
            expected,
            expected_catalog,
            migration_role,
            runtime_role,
            lock_key,
            key_source,
        }
    }

    async fn check(&self) -> Result<()> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        transaction
            .batch_execute("SET LOCAL lock_timeout = '5s'")
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        crate::postgres::verify_postgres_15_or_newer(&*transaction)
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        verify_configured_runtime_role(&*transaction, &self.migration_role, &self.runtime_role)
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        let maintenance = transaction
            .query_opt(
                "SELECT maintenance_status
                 FROM registry_internal.registry_state
                 WHERE singleton",
                &[],
            )
            .await
            .map_err(|_| StartupError::DatabaseUnready)?
            .ok_or(StartupError::DatabaseUnready)?
            .get::<_, String>(0);
        if maintenance != "ready" {
            return Err(StartupError::DatabaseUnready);
        }
        verify_catalog_identity_for_catalog(
            &*transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
        transaction
            .commit()
            .await
            .map_err(|_| StartupError::DatabaseUnready)?;
        self.key_source
            .ensure_key_set()
            .await
            .map_err(|_| StartupError::Oidc)?;
        Ok(())
    }
}

impl ReadinessProbe for DynamicRuntimeReadiness {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async move { self.check().await.is_ok() })
    }
}

async fn verify_configured_runtime_role(
    client: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    let row = client
        .query_one(
            "SELECT current_user,
                    rolsuper,
                    rolbypassrls,
                    rolcreatedb,
                    rolcreaterole,
                    current_user = $1,
                    pg_has_role(current_user, $1, 'MEMBER'),
                    has_database_privilege(current_user, current_database(), 'CREATE'),
                    has_schema_privilege(current_user, 'registry_internal', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_data', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_source', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_derived', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_context', 'CREATE'),
                    EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_class c
                        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname IN (
                            'registry_internal',
                            'registry_data',
                            'registry_source',
                            'registry_derived',
                            'registry_context'
                        )
                          AND c.relowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
                    )
             FROM pg_catalog.pg_roles
             WHERE rolname = current_user",
            &[&migration_role.as_str()],
        )
        .await
        .map_err(|_| StartupError::DatabaseUnready)?;
    let actual_role: String = row.get(0);
    if actual_role != runtime_role.as_str() {
        return Err(StartupError::DatabaseUnready);
    }
    if (1..=13).any(|index| row.get::<_, bool>(index)) {
        return Err(StartupError::DatabaseUnready);
    }
    Ok(())
}
