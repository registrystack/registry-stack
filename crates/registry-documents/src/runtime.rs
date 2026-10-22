// SPDX-License-Identifier: Apache-2.0

//! Service assembly: `documents serve` loads and checks the runtime
//! configuration, confirms the database answers over the runtime
//! credential and that its activation ledger names the deployed package
//! for this deployment, opens the audit journal, activates content storage and the
//! content verifier, suspends every version verified under another
//! verifier binding, loads the token issuer's signing keys, binds the
//! listener, and serves the HTTP surface beside the content verification
//! worker, the erasure worker, and the cleanup pass.
//!
//! Every step that can refuse a deployment runs before the listener binds,
//! so a mis-provisioned deployment never answers a request.
//!
//! On SIGTERM or SIGINT, `serve` stops accepting, finishes the requests it
//! is answering, and exits 0.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::{Arg, Command};
use registry_documents_core::AccessProfiles;
use registry_platform_audit::{AuditDestination, AuditProfile, AuditWriter};
use registry_platform_dispatch::postgres::{DispatchWorker, Dispatcher, WorkerConfig};
use registry_platform_yaml::Report;
use thiserror::Error;
use tokio::sync::watch;
use tracing_subscriber::filter::LevelFilter;

use crate::activation::{self, ActivationError, ApplyRequest};
use crate::audit::DocumentsAudit;
use crate::auth::DocumentsAuthenticator;
use crate::config::{
    describe_secret_failure, startup_report, Erasure, RuntimeConfig, RuntimeConfigError,
};
use crate::content::{pinned_storage, ContentStorage, StorageError};
use crate::erasure::{
    cleanup_once, erasure_status, CleanupPass, ErasureStatus, ErasureStore, ErasureTransport,
    ORPHAN_MARGIN,
};
use crate::hooks::{
    ActivatedHooks, HookActivationError, HookDeliveryService, HookRuntimeIdentity, ScopedHook,
};
use crate::http::{router, DocumentRoutes};
use crate::package::{load_package, LoadedPackage, PackageLoadError};
use crate::service::{DocumentService, ServiceSettings};
use crate::store::{PostgresStore, StoreError};
use crate::transfer::{TransferBudget, TransferDeadline};
use crate::verification::{
    activate_verifier, dead_letters, dispatcher, job_table, replay, sweep_bindings, DeadLetter,
    Graces, ReplayError, ReplayFailure, ReplayRefusal, Replayed, VerdictSource, VerificationStore,
    VerificationTransport,
};

/// The most verification attempts one process runs at once.
const WORKER_CONCURRENCY: NonZeroUsize = match NonZeroUsize::new(4) {
    Some(value) => value,
    None => panic!("the worker concurrency is not zero"),
};

/// How long the verification worker waits after it finds no due job.
const WORKER_IDLE_POLL: Duration = Duration::from_secs(5);

/// The time between two cleanup passes.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

#[must_use]
pub fn command() -> Command {
    Command::new("documents")
        .version(registry_platform_buildinfo::DISPLAY_VERSION)
        .about("Run the Registry Stack Document Store")
        .arg(
            Arg::new("runtime-config")
                .long("runtime-config")
                .value_name("ABSOLUTE_FILE")
                .help("Runtime configuration file")
                .required(true),
        )
        .subcommand_required(true)
        .subcommand(Command::new("serve").about("Run the Document Store HTTP service"))
}

/// The operational log level, read from `DOCUMENTS_LOG`. The variable
/// accepts exactly `error`, `warn`, or `info`, and the level applies to the
/// Document Store crates only. Any other value, including a tracing
/// directive that would enable a dependency's own debug or trace logging,
/// is refused rather than silently accepted.
pub fn operational_log_level(value: Option<&str>) -> Result<LevelFilter, RuntimeError> {
    match value.unwrap_or("info") {
        "error" => Ok(LevelFilter::ERROR),
        "warn" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        _ => Err(RuntimeError::Logging),
    }
}

/// Run the parsed command.
pub async fn run(matches: &clap::ArgMatches) -> Result<(), RuntimeError> {
    let path = matches
        .get_one::<String>("runtime-config")
        .ok_or(RuntimeError::Arguments)?;
    match matches.subcommand_name() {
        Some("serve") => {
            let shutdown = shutdown_signal()?;
            prepare(path).await?.serve_until(shutdown).await
        }
        _ => Err(RuntimeError::Arguments),
    }
}

/// Resolve on the first SIGTERM or SIGINT. The SIGTERM handler is
/// installed here, before anything is served, so a failure to install it
/// refuses startup.
fn shutdown_signal() -> Result<impl std::future::Future<Output = ()>, RuntimeError> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(RuntimeError::Signal)?;
    Ok(async move {
        let interrupt = tokio::signal::ctrl_c();
        #[cfg(unix)]
        tokio::select! {
            _ = interrupt => {}
            _ = terminate.recv() => {}
        }
        #[cfg(not(unix))]
        if let Err(error) = interrupt.await {
            tracing::error!(error = %error, "the Document Store interrupt handler failed; shutting down");
        }
    })
}

/// The runtime document at `path`, or a refusal that reports every rule it
/// breaks, each at its position, rather than only the first.
fn load_config(path: &Path) -> Result<RuntimeConfig, RuntimeError> {
    RuntimeConfig::load(path).map_err(|error| match startup_report(path, &error) {
        Some(report) => RuntimeError::ConfigurationRefused(report),
        None => RuntimeError::Config(error),
    })
}

/// A runtime that passed every startup check and holds its bound listener.
pub struct Prepared {
    listener: tokio::net::TcpListener,
    routes: DocumentRoutes,
    dispatcher: Dispatcher<VerificationStore>,
    transport: Arc<VerificationTransport>,
    cleanup: Cleanup,
    hook_delivery: HookDeliveryService,
}

/// What the erasure worker and the cleanup pass run over.
struct Cleanup {
    store: PostgresStore,
    storage: Arc<ContentStorage>,
    audit: DocumentsAudit,
    erasure: Erasure,
    orphan_age: Duration,
    dispatcher: Dispatcher<ErasureStore>,
    transport: Arc<ErasureTransport>,
}

impl Cleanup {
    async fn pass(&self) -> Result<CleanupPass, crate::erasure::CleanupError> {
        cleanup_once(
            &self.store,
            &self.storage,
            &self.audit,
            self.erasure,
            self.orphan_age,
        )
        .await
    }

    /// The erasure worker, only while erasure is active. The serving
    /// runtime and the test sweep both start it through here, so a paused
    /// deployment runs no erasure job, even one armed before the pause.
    fn worker_if_active(&self) -> Option<DispatchWorker<ErasureStore, ErasureTransport>> {
        (self.erasure == Erasure::Active).then(|| self.worker())
    }

    fn worker(&self) -> DispatchWorker<ErasureStore, ErasureTransport> {
        DispatchWorker::new(
            self.dispatcher.clone(),
            Arc::clone(&self.transport),
            WorkerConfig {
                concurrency: WORKER_CONCURRENCY,
                idle_poll: WORKER_IDLE_POLL,
            },
        )
    }

    /// Run a cleanup pass every [`CLEANUP_INTERVAL`] until `stopped` is
    /// set. A failed pass is logged and the next one runs on schedule.
    async fn run(self: Arc<Self>, mut stopped: watch::Receiver<bool>) {
        loop {
            match self.pass().await {
                Ok(pass) if pass != CleanupPass::default() => {
                    tracing::info!(
                        expired_uploads = pass.expired_uploads,
                        armed_erasures = pass.armed_erasures,
                        erased_orphans = pass.erased_orphans,
                        failed_orphans = pass.failed_orphans,
                        "a cleanup pass finished"
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(error = %error, "a cleanup pass failed; the next pass retries");
                }
            }
            tokio::select! {
                () = tokio::time::sleep(CLEANUP_INTERVAL) => {}
                changed = stopped.changed() => {
                    if changed.is_err() || *stopped.borrow() {
                        return;
                    }
                }
            }
        }
    }
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Prepared")
            .field("listener", &self.listener)
            .finish_non_exhaustive()
    }
}

/// Load and check the runtime document at `path` and the package it names,
/// confirm the database answers over the runtime credential, names this
/// package active for this deployment, and carries exactly this release's
/// schema, open the audit journal, activate content
/// storage and the verifier, and bind the listener.
pub async fn prepare(path: impl AsRef<Path>) -> Result<Prepared, RuntimeError> {
    prepare_with(path.as_ref(), None).await
}

/// As [`prepare`], with the content verifier replaced by `verifier`, so a
/// suite can drive approval, rejection, and an unavailable verifier.
#[cfg(feature = "postgres-test")]
pub async fn prepare_with_verifier(
    path: impl AsRef<Path>,
    verifier: Arc<dyn VerdictSource>,
) -> Result<Prepared, RuntimeError> {
    prepare_with(path.as_ref(), Some(verifier)).await
}

async fn prepare_with(
    path: &Path,
    verifier: Option<Arc<dyn VerdictSource>>,
) -> Result<Prepared, RuntimeError> {
    let config = load_config(path)?;
    let secrets = Arc::new(config.secret_resolver()?);
    let package = load_package(&config)?;
    let store = PostgresStore::connect_runtime(&config.database, &secrets).map_err(|source| {
        RuntimeError::Database {
            stage: "runtime database configuration",
            source,
        }
    })?;
    store
        .ping()
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "runtime database connection",
            source,
        })?;
    let database_id = database_id(&config)?;
    activation::check_runtime(&store, &database_id, &package.digest).await?;
    let audit = open_audit(&config, &secrets, None).await?;
    let ceiling = config.storage.maximum_document_bytes();
    let storage = Arc::new(
        ContentStorage::activate(&config.storage, &database_id, Arc::clone(&secrets))
            .await
            .map_err(RuntimeError::Storage)?,
    );
    check_storage_pin(&store, &storage).await?;
    let verifier = match verifier {
        Some(verifier) => verifier,
        None => activate_verifier(&config.content_verification, ceiling, &secrets)
            .map_err(|error| RuntimeError::Verifier(error.to_string()))?,
    };
    let suspended = sweep_bindings(&store, verifier.binding_digest())
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "verifier binding sweep",
            source,
        })?;
    if suspended > 0 {
        tracing::warn!(
            suspended,
            "versions verified under another verifier binding were suspended for verification again"
        );
    }
    let schema = store
        .current_schema()
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "schema lookup",
            source,
        })?;
    // Resolve and validate every hook destination, its signing material
    // included, before the listener binds, and prove every retained
    // delivery can still use the exact destination binding captured for
    // it. A deployment may keep extra bindings while old deliveries drain.
    let hooks = activate_hooks(&config, &package, &secrets, &database_id, schema.clone())?;
    let hook_delivery = hooks.delivery_service(store.clone(), audit.clone());
    hook_delivery
        .verify_retained_bindings()
        .await
        .map_err(|_| RuntimeError::HookDelivery)?;
    let jobs = job_table(&schema).map_err(|error| RuntimeError::Dispatch(error.to_string()))?;
    let erasure_dispatcher = crate::erasure::dispatcher(ErasureStore::new(
        store.clone(),
        schema.clone(),
        audit.clone(),
    ))
    .map_err(|error| RuntimeError::Dispatch(error.to_string()))?;
    let dispatcher = dispatcher(VerificationStore::new(
        store.clone(),
        schema,
        audit.clone(),
        Graces::of(&package.project),
        hooks.clone(),
    ))
    .map_err(|error| RuntimeError::Dispatch(error.to_string()))?;
    let deadline = TransferDeadline::new(&config.transfers);
    let cleanup = Cleanup {
        store: store.clone(),
        storage: Arc::clone(&storage),
        audit: audit.clone(),
        erasure: config.cleanup.erasure,
        orphan_age: deadline.for_length(ceiling) + ORPHAN_MARGIN,
        dispatcher: erasure_dispatcher,
        transport: Arc::new(ErasureTransport::new(store.clone(), Arc::clone(&storage))),
    };
    let budget = TransferBudget::new(ceiling);
    let transport = Arc::new(VerificationTransport::new(
        store.clone(),
        Arc::clone(&storage),
        Arc::clone(&verifier),
        budget.clone(),
    ));
    let project = Arc::new(package.project);
    let keys = config.jwks_fetcher(&secrets).await?;
    let authenticator = Arc::new(DocumentsAuthenticator::new(
        config.verifier_profile(),
        keys,
        AccessProfiles::new(&project),
        config.binds_assertion_issuers(),
    ));
    let service = Arc::new(DocumentService::new(
        store,
        project,
        storage,
        jobs,
        audit,
        ServiceSettings {
            verifier_binding: verifier.binding_digest().to_owned(),
            ceiling,
            budget,
            deadline,
            idempotency_days: config.retention.receipt_retention_days.get(),
        },
        hooks,
    ));
    let listener = tokio::net::TcpListener::bind(config.listener.bind.socket_addr())
        .await
        .map_err(RuntimeError::Listen)?;
    Ok(Prepared {
        listener,
        routes: DocumentRoutes {
            service,
            authenticator,
        },
        dispatcher,
        transport,
        cleanup,
        hook_delivery,
    })
}

/// The operator process name companion audit journals are written under.
const OPERATOR_PROCESS: &str = "documentsctl";

fn runtime_store(
    config: &RuntimeConfig,
    secrets: &registry_platform_config::SecretResolver,
) -> Result<PostgresStore, RuntimeError> {
    PostgresStore::connect_runtime(&config.database, secrets).map_err(|source| {
        RuntimeError::Database {
            stage: "runtime database configuration",
            source,
        }
    })
}

/// What `documentsctl apply` would change for the package `config` names,
/// read over the runtime credential in a read-only transaction. It writes
/// nothing.
pub async fn activation_plan(
    config: &RuntimeConfig,
) -> Result<activation::ActivationPlan, RuntimeError> {
    let package = load_package(config)?;
    let database_id = database_id(config)?;
    let secrets = config.secret_resolver()?;
    let store = runtime_store(config, &secrets)?;
    Ok(activation::plan(&store, &database_id, &package.digest).await?)
}

/// The activation ledger and schema version, read over the runtime
/// credential in a read-only transaction.
pub async fn activation_status(
    config: &RuntimeConfig,
) -> Result<activation::ActivationStatus, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let store = runtime_store(config, &secrets)?;
    Ok(activation::status(&store).await?)
}

/// Apply the schema over the migration credential and record the package
/// `config` names as active, granting the runtime role what it serves with
/// when the two credentials are different roles. The package is loaded and
/// checked exactly as `serve` loads it, pinned digest included.
pub async fn apply_activation(
    config: &RuntimeConfig,
    request: &ApplyRequest,
) -> Result<activation::ActivationApplied, RuntimeError> {
    let package = load_package(config)?;
    let database_id = database_id(config)?;
    let secrets = config.secret_resolver()?;
    let runtime = runtime_store(config, &secrets)?;
    let runtime_role = runtime
        .current_user()
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "runtime role read",
            source,
        })?;
    let migration =
        PostgresStore::connect_migration(&config.database, &secrets).map_err(|source| {
            RuntimeError::Database {
                stage: "migration database configuration",
                source,
            }
        })?;
    let audit = open_audit(config, &secrets, Some(OPERATOR_PROCESS)).await?;
    Ok(activation::apply(
        &migration,
        &runtime_role,
        &database_id,
        &package.digest,
        request,
        &audit,
    )
    .await?)
}

/// The runtime store over a database the ledger names this package and
/// deployment active in, as `serve` would find it.
async fn activated_store(
    config: &RuntimeConfig,
    secrets: &registry_platform_config::SecretResolver,
) -> Result<PostgresStore, RuntimeError> {
    let package = load_package(config)?;
    let database_id = database_id(config)?;
    let store = runtime_store(config, secrets)?;
    activation::check_runtime(&store, &database_id, &package.digest).await?;
    Ok(store)
}

/// The oldest `limit` dead-lettered content verification jobs, read over
/// the runtime credential from an activated database.
pub async fn dead_lettered_verifications(
    config: &RuntimeConfig,
    limit: u16,
) -> Result<Vec<DeadLetter>, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let store = activated_store(config, &secrets).await?;
    dead_letters(&store, limit)
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "dead letter listing",
            source,
        })
}

/// Return the dead-lettered content verification job of `version_id` to
/// pending, when its generation is `expected_generation`. Only an operator
/// reaches this: it runs over the runtime credential against an activated
/// database, and the dispatcher records the replay in the operator's
/// companion audit journal before and after it commits. No HTTP route
/// replays a job.
pub async fn replay_verification(
    config: &RuntimeConfig,
    version_id: uuid::Uuid,
    expected_generation: i64,
) -> Result<Replayed, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let store = activated_store(config, &secrets).await?;
    let schema = store
        .current_schema()
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "schema lookup",
            source,
        })?;
    let audit = open_audit(config, &secrets, Some(OPERATOR_PROCESS)).await?;
    let package = load_package(config)?;
    let hooks = activate_hooks(
        config,
        &package,
        &secrets,
        &database_id(config)?,
        schema.clone(),
    )?;
    let graces = Graces::of(&package.project);
    let verification = VerificationStore::new(store.clone(), schema, audit, graces, hooks);
    replay(&store, verification, version_id, expected_generation)
        .await
        .map_err(|error| match error {
            ReplayError::Refused(refusal) => RuntimeError::Replay(refusal),
            ReplayError::Failed(failure) => RuntimeError::ReplayFailed(failure),
            ReplayError::Store(source) => RuntimeError::Database {
                stage: "verification replay",
                source,
            },
            ReplayError::Dispatch(error) => RuntimeError::Dispatch(error.to_string()),
        })
}

/// The erasure setting and how many versions wait for erasure, read over
/// the runtime credential from an activated database.
pub async fn erasure_report(config: &RuntimeConfig) -> Result<ErasureStatus, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let store = activated_store(config, &secrets).await?;
    erasure_status(&store, config.cleanup.erasure)
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "erasure status",
            source,
        })
}

/// The oldest `limit` dead-lettered erasure jobs, read over the runtime
/// credential from an activated database.
pub async fn dead_lettered_erasures(
    config: &RuntimeConfig,
    limit: u16,
) -> Result<Vec<DeadLetter>, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let store = activated_store(config, &secrets).await?;
    crate::erasure::dead_letters(&store, limit)
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "erasure dead letter listing",
            source,
        })
}

/// Return the dead-lettered erasure job of `version_id` to pending, when
/// its generation is `expected_generation`, exactly as
/// [`replay_verification`] does for a content verification job. The sweep
/// never arms a second erasure job for the version, so this is the only
/// way its erasure runs again.
pub async fn replay_erasure(
    config: &RuntimeConfig,
    version_id: uuid::Uuid,
    expected_generation: i64,
) -> Result<Replayed, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let store = activated_store(config, &secrets).await?;
    let schema = store
        .current_schema()
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "schema lookup",
            source,
        })?;
    let audit = open_audit(config, &secrets, Some(OPERATOR_PROCESS)).await?;
    let erasure = ErasureStore::new(store.clone(), schema, audit);
    crate::erasure::replay(&store, erasure, version_id, expected_generation)
        .await
        .map_err(|error| match error {
            ReplayError::Refused(refusal) => RuntimeError::ErasureReplay(refusal),
            ReplayError::Failed(failure) => RuntimeError::ErasureReplayFailed(failure),
            ReplayError::Store(source) => RuntimeError::Database {
                stage: "erasure replay",
                source,
            },
            ReplayError::Dispatch(error) => RuntimeError::Dispatch(error.to_string()),
        })
}

/// The hooks the deployed package declares, activated against the
/// destinations `config` binds and the database schema `schema`, after
/// every signing secret they name resolves.
pub fn activated_hooks(
    config: &RuntimeConfig,
    schema: String,
) -> Result<ActivatedHooks, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let package = load_package(config)?;
    activate_hooks(config, &package, &secrets, &database_id(config)?, schema)
}

fn activate_hooks(
    config: &RuntimeConfig,
    package: &LoadedPackage,
    secrets: &registry_platform_config::SecretResolver,
    database_id: &str,
    schema: String,
) -> Result<ActivatedHooks, RuntimeError> {
    Ok(ActivatedHooks::activate(
        &ScopedHook::of(&package.project),
        &config.destinations.hooks,
        secrets,
        HookRuntimeIdentity {
            project_id: package.project.project.id.as_str().to_owned(),
            package_digest: package.digest.clone(),
            database_id: database_id.to_owned(),
        },
        schema,
        Duration::from_secs(
            u64::from(config.retention.hook_payload_retention_days.get()) * 24 * 60 * 60,
        ),
    )?)
}

/// The logical database id the runtime document names. A document without
/// one is refused with the findings that name the missing key.
fn database_id(config: &RuntimeConfig) -> Result<String, RuntimeError> {
    config
        .identity
        .as_ref()
        .map(|identity| identity.database_id.as_str().to_owned())
        .ok_or_else(|| RuntimeError::Config(RuntimeConfigError::Refused(config.findings())))
}

/// Open the audit journal the runtime document names, keyed by its audit
/// secret.
/// An operator command passes its own `process` name and writes to its
/// companion journal, so it never contends for the running service's
/// journal.
async fn open_audit(
    config: &RuntimeConfig,
    secrets: &registry_platform_config::SecretResolver,
    process: Option<&str>,
) -> Result<DocumentsAudit, RuntimeError> {
    let reference = config.audit.key.hash_key_ref.as_str();
    let secret = secrets.resolve(reference).map_err(|error| {
        RuntimeError::AuditSecret(describe_secret_failure(
            "audit.hashKeyRef",
            reference,
            &error,
        ))
    })?;
    let profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        secret.expose_secret().to_vec(),
    ))
    .map_err(|error| RuntimeError::AuditJournal(error.to_string()))?;
    let mut destination = AuditDestination::from_settings(
        config.audit.destination,
        config.audit.path.clone(),
        None,
        None,
    )
    .map_err(|error| RuntimeError::AuditJournal(error.to_string()))?;
    if let Some(process) = process {
        destination = destination
            .for_process(process)
            .map_err(|error| RuntimeError::AuditJournal(error.to_string()))?;
    }
    let writer = AuditWriter::open(destination)
        .await
        .map_err(|error| RuntimeError::AuditJournal(error.to_string()))?;
    Ok(DocumentsAudit::new(writer, profile.key_hasher()))
}

/// Refuse a start whose storage is not the one the deployment pinned at
/// its first write. A deployment that never wrote has no pin yet.
async fn check_storage_pin(
    store: &PostgresStore,
    storage: &ContentStorage,
) -> Result<(), RuntimeError> {
    let client = store
        .client()
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "storage pin read",
            source,
        })?;
    let pinned = pinned_storage(&**client)
        .await
        .map_err(|error| RuntimeError::Storage(StorageError::Query(error)))?;
    match pinned {
        Some((backend, binding))
            if backend != storage.backend() || binding != storage.binding() =>
        {
            Err(RuntimeError::StorageBindingChanged)
        }
        _ => Ok(()),
    }
}

impl Prepared {
    /// The address the listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, RuntimeError> {
        self.listener.local_addr().map_err(RuntimeError::Listen)
    }

    /// The document operations this runtime serves.
    #[must_use]
    pub fn service(&self) -> Arc<DocumentService> {
        Arc::clone(&self.routes.service)
    }

    /// This runtime with its document routes writing to `audit`.
    #[cfg(feature = "postgres-test")]
    #[must_use]
    pub fn with_audit(mut self, audit: crate::audit::DocumentsAudit) -> Self {
        self.routes.service = Arc::new(self.routes.service.with_audit(audit));
        self
    }

    /// The router this runtime serves, authentication included.
    pub fn router(&self) -> axum::Router {
        router(self.routes.clone())
    }

    /// Run every due content verification attempt now and return how many
    /// jobs moved.
    #[cfg(feature = "postgres-test")]
    pub async fn verify_due(&self) -> usize {
        let (_sender, shutdown) = watch::channel(false);
        self.worker().drain(&shutdown).await
    }

    /// Run one cleanup pass alone and return what it answered.
    #[cfg(feature = "postgres-test")]
    pub async fn cleanup_pass(&self) -> Result<CleanupPass, crate::erasure::CleanupError> {
        self.cleanup.pass().await
    }

    /// Run one cleanup pass and then every due erasure attempt, as the
    /// serving runtime would, and return the pass. Erasure attempts run only
    /// while erasure is active.
    #[cfg(feature = "postgres-test")]
    pub async fn sweep_due(&self) -> CleanupPass {
        let pass = self.cleanup_pass().await.expect("the cleanup pass runs");
        if let Some(worker) = self.cleanup.worker_if_active() {
            let (_sender, shutdown) = watch::channel(false);
            worker.drain(&shutdown).await;
        }
        pass
    }

    /// Run one hook delivery pass now: claim the next due delivery, if
    /// any, attempt it, and record its outcome.
    #[cfg(feature = "postgres-test")]
    pub async fn deliver_hooks_once(
        &self,
    ) -> Result<
        registry_platform_hooks::delivery::DeliveryOutcome,
        registry_platform_hooks::delivery::DeliveryError,
    > {
        self.hook_delivery.deliver_once().await
    }

    fn worker(&self) -> DispatchWorker<VerificationStore, VerificationTransport> {
        DispatchWorker::new(
            self.dispatcher.clone(),
            Arc::clone(&self.transport),
            WorkerConfig {
                concurrency: WORKER_CONCURRENCY,
                idle_poll: WORKER_IDLE_POLL,
            },
        )
    }

    /// Serve until `shutdown` resolves, then finish the requests in flight
    /// and stop the verification worker, the hook delivery worker, the
    /// erasure worker, and the cleanup pass. A background task that ends
    /// while serving stops the runtime with [`RuntimeError::Stopped`].
    pub async fn serve_until(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), RuntimeError> {
        if let Ok(address) = self.listener.local_addr() {
            tracing::info!(address = %address, "the Document Store is serving");
        }
        let (stop, stopped) = watch::channel(false);
        let mut tasks = vec![
            (
                "content verification worker",
                tokio::spawn(self.worker().run(stopped.clone())),
            ),
            (
                "hook delivery worker",
                tokio::spawn(self.hook_delivery.worker().run(stopped.clone())),
            ),
        ];
        match self.cleanup.worker_if_active() {
            Some(erasure) => {
                tasks.push(("erasure worker", tokio::spawn(erasure.run(stopped.clone()))))
            }
            None => {
                tracing::warn!(
                    "cleanup.erasure is paused: no erasure runs and no orphaned object is erased until it is active again"
                );
            }
        }
        tasks.push((
            "cleanup pass",
            tokio::spawn(Arc::new(self.cleanup).run(stopped.clone())),
        ));
        let (listener, routes) = (self.listener, self.routes);
        let served = async move {
            axum::serve(listener, router(routes))
                .with_graceful_shutdown(stop_requested(stopped))
                .await
                .map_err(RuntimeError::Listen)
        };
        supervise(served, shutdown, stop, tasks).await
    }
}

/// Resolve once `stopped` turns true. The sender outlives every listener,
/// so the channel closing is not a stop request.
async fn stop_requested(mut stopped: watch::Receiver<bool>) {
    if stopped.wait_for(|stop| *stop).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Run `served` beside the background `tasks` until `shutdown` resolves,
/// the listener ends, or a task ends, then ask everything to stop through
/// `stop` and wait for it. Every task runs until it is asked to stop, so a
/// task that ends first, by returning or by panicking, has left the
/// runtime without work it promises: it is logged and the runtime stops
/// with [`RuntimeError::Stopped`] rather than serve without it.
async fn supervise(
    served: impl std::future::Future<Output = Result<(), RuntimeError>>,
    shutdown: impl std::future::Future<Output = ()>,
    stop: watch::Sender<bool>,
    tasks: Vec<(&'static str, tokio::task::JoinHandle<()>)>,
) -> Result<(), RuntimeError> {
    use futures::StreamExt as _;

    let mut tasks = tasks
        .into_iter()
        .map(|(task, handle)| async move { (task, handle.await) })
        .collect::<futures::stream::FuturesUnordered<_>>();
    tokio::pin!(served, shutdown);
    let mut listener = None;
    let mut stopped = None;
    tokio::select! {
        result = &mut served => listener = Some(result),
        () = &mut shutdown => {}
        Some((task, joined)) = tasks.next() => {
            match joined {
                Ok(()) => tracing::error!(task, "a Document Store background task ended while serving; stopping"),
                Err(error) => tracing::error!(task, error = %error, "a Document Store background task failed while serving; stopping"),
            }
            stopped = Some(task);
        }
    }
    stop.send_replace(true);
    let served = match listener {
        Some(result) => result,
        None => served.await,
    };
    while let Some((task, joined)) = tasks.next().await {
        if let Err(error) = joined {
            tracing::error!(task, error = %error, "a Document Store background task failed");
        }
    }
    match stopped {
        Some(task) => Err(RuntimeError::Stopped { task }),
        None => served,
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The database is not activated for this package and deployment, or
    /// an activation step was refused.
    #[error(transparent)]
    Activation(#[from] ActivationError),
    /// A project hook or its deployment destination binding was refused.
    #[error(transparent)]
    HookActivation(#[from] HookActivationError),
    /// A retained hook delivery can no longer use the destination binding
    /// it was captured with, or the delivery tables could not be read.
    #[error("a retained hook delivery no longer matches its destination binding in destinations.hooks, or the hook delivery tables are unavailable")]
    HookDelivery,
    /// An operator replay of a content verification job was refused.
    #[error("the content verification replay was refused: {0}")]
    Replay(ReplayRefusal),
    /// An operator replay of a content verification job did not finish.
    #[error("the content verification replay did not finish: {0}")]
    ReplayFailed(ReplayFailure),
    /// An operator replay of an erasure job was refused.
    #[error("the erasure replay was refused: {0}")]
    ErasureReplay(ReplayRefusal),
    /// An operator replay of an erasure job did not finish.
    #[error("the erasure replay did not finish: {0}")]
    ErasureReplayFailed(ReplayFailure),
    #[error("the documents command arguments are invalid")]
    Arguments,
    #[error("DOCUMENTS_LOG must be one of error, warn, or info")]
    Logging,
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),
    /// The runtime document was refused, with every rule it breaks.
    #[error("the Document Store runtime configuration was refused\n{}", .0.render_human().trim_end())]
    ConfigurationRefused(Report),
    /// A database step of startup failed. The step is named because the
    /// remedies differ: a malformed credential and an unreachable server are
    /// different operator tasks.
    #[error("the Document Store {stage} failed: {source}")]
    Database {
        stage: &'static str,
        #[source]
        source: StoreError,
    },
    /// The deployed package was refused.
    #[error("the Document Store package was refused ({}): {}", .0.code(), .0)]
    Package(#[from] PackageLoadError),
    #[error("the Document Store listener could not bind or serve: {0}")]
    Listen(#[source] std::io::Error),
    /// A background task ended while the runtime was serving.
    #[error("the Document Store {task} stopped while serving")]
    Stopped { task: &'static str },
    #[error("the Document Store shutdown signal handler could not be installed: {0}")]
    Signal(#[source] std::io::Error),
    #[error("the Document Store audit key could not be read: {0}")]
    AuditSecret(String),
    #[error("the Document Store audit journal could not be opened: {0}")]
    AuditJournal(String),
    #[error("the Document Store content storage could not be activated: {0}")]
    Storage(#[source] StorageError),
    /// The configured storage is not the one the deployment pinned at its
    /// first write. Content is never read from or written to another
    /// backend, bucket, or scope.
    #[error(
        "the Document Store content storage is not the storage this deployment pinned at its first write"
    )]
    StorageBindingChanged,
    #[error("the Document Store content verifier could not be activated: {0}")]
    Verifier(String),
    #[error("the Document Store verification worker could not be configured: {0}")]
    Dispatch(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A background task that runs until the runtime asks it to stop.
    fn until_stopped(mut stopped: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let _ = stopped.wait_for(|stop| *stop).await;
        })
    }

    /// A background task that ends while the runtime is serving stops the
    /// listener and the other tasks and ends the process with an error,
    /// rather than leaving it serving without the task.
    #[tokio::test]
    async fn a_background_task_that_ends_while_serving_stops_the_runtime() {
        let (stop, stopped) = watch::channel(false);
        let served = {
            let stopped = stopped.clone();
            async move {
                stop_requested(stopped).await;
                Ok(())
            }
        };
        let survivor = until_stopped(stopped.clone());
        let survivor_done = survivor.abort_handle();
        let result = supervise(
            served,
            std::future::pending(),
            stop,
            vec![
                ("content verification worker", survivor),
                ("erasure worker", tokio::spawn(async {})),
            ],
        )
        .await;
        assert!(
            matches!(
                result,
                Err(RuntimeError::Stopped {
                    task: "erasure worker"
                })
            ),
            "{result:?}"
        );
        assert!(survivor_done.is_finished());
    }

    /// Shutdown stops every background task and answers the listener's
    /// own outcome.
    #[tokio::test]
    async fn shutdown_stops_every_background_task() {
        let (stop, stopped) = watch::channel(false);
        let served = {
            let stopped = stopped.clone();
            async move {
                stop_requested(stopped).await;
                Ok(())
            }
        };
        let worker = until_stopped(stopped.clone());
        let worker_done = worker.abort_handle();
        let result = supervise(
            served,
            std::future::ready(()),
            stop,
            vec![("content verification worker", worker)],
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert!(worker_done.is_finished());
    }

    #[test]
    fn the_log_level_is_one_of_three_words() {
        assert_eq!(operational_log_level(None).unwrap(), LevelFilter::INFO);
        assert_eq!(
            operational_log_level(Some("warn")).unwrap(),
            LevelFilter::WARN
        );
        assert_eq!(
            operational_log_level(Some("error")).unwrap(),
            LevelFilter::ERROR
        );
        for refused in ["debug", "trace", "registry_documents=debug", ""] {
            assert!(matches!(
                operational_log_level(Some(refused)),
                Err(RuntimeError::Logging)
            ));
        }
    }

    #[test]
    fn serve_requires_a_runtime_configuration() {
        assert!(command()
            .try_get_matches_from(["documents", "serve"])
            .is_err());
        assert!(command()
            .try_get_matches_from(["documents", "--runtime-config", "/etc/documents.yaml"])
            .is_err());
        let matches = command()
            .try_get_matches_from([
                "documents",
                "--runtime-config",
                "/etc/documents.yaml",
                "serve",
            ])
            .unwrap();
        assert_eq!(matches.subcommand_name(), Some("serve"));
    }

    /// A document without `identity.databaseId` is a configuration
    /// refusal that names the missing key, never an argument error.
    #[test]
    fn a_missing_database_id_is_a_configuration_refusal() {
        let mut config = RuntimeConfig::loader()
            .parse_str::<RuntimeConfig>(crate::config::tests::STARTER_RUNTIME, |_| None)
            .unwrap()
            .config;
        assert_eq!(
            database_id(&config).unwrap(),
            "registry-documents-production"
        );
        config.identity = None;
        let error = database_id(&config).unwrap_err();
        assert!(
            matches!(
                &error,
                RuntimeError::Config(RuntimeConfigError::Refused(findings))
                    if findings.iter().any(|finding| finding.code == "documents.runtime.missing-identity")
            ),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("identity.databaseId is required"),
            "{error}"
        );
    }

    #[test]
    fn the_command_tree_is_well_formed() {
        command().debug_assert();
    }

    #[tokio::test]
    async fn a_refused_document_reports_every_finding_before_anything_binds() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = directory.path().join("runtime.yaml");
        let text = crate::config::tests::STARTER_RUNTIME
            .replace(
                "  # The one database this deployment owns.\n  databaseId: registry-documents-production\n",
                "",
            )
            .replace("identity:\n", "")
            .replace(
                "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]",
                "allowedClients: unrestricted",
            );
        std::fs::write(&path, text).unwrap();
        let error = prepare(&path).await.unwrap_err();
        let RuntimeError::ConfigurationRefused(report) = error else {
            panic!("a configuration refusal, got {error}");
        };
        let rendered = report.render_human();
        assert!(
            rendered.contains("documents.runtime.missing-identity"),
            "{rendered}"
        );
        assert!(
            rendered.contains("documents.runtime.allowed-clients-required"),
            "{rendered}"
        );
    }
}
