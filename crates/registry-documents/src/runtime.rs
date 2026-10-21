// SPDX-License-Identifier: Apache-2.0

//! Service assembly: `documents serve` loads and checks the runtime
//! configuration, confirms the database answers over the runtime
//! credential, opens the audit journal, activates content storage and the
//! content verifier, suspends every version verified under another
//! verifier binding, binds the listener, and serves the HTTP surface beside
//! the content verification worker.
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
use registry_platform_audit::{AuditDestination, AuditProfile, AuditWriter};
use registry_platform_dispatch::postgres::{DispatchWorker, Dispatcher, WorkerConfig};
use registry_platform_yaml::Report;
use thiserror::Error;
use tokio::sync::watch;
use tracing_subscriber::filter::LevelFilter;

use crate::audit::DocumentsAudit;
use crate::config::{describe_secret_failure, startup_report, RuntimeConfig, RuntimeConfigError};
use crate::content::{pinned_storage, ContentStorage, StorageError};
use crate::http::router;
use crate::package::{load_package, PackageLoadError};
use crate::service::DocumentService;
use crate::store::{PostgresStore, StoreError};
use crate::verification::{
    activate_verifier, dispatcher, job_table, sweep_bindings, VerdictSource, VerificationStore,
    VerificationTransport,
};

/// The most verification attempts one process runs at once.
const WORKER_CONCURRENCY: NonZeroUsize = match NonZeroUsize::new(4) {
    Some(value) => value,
    None => panic!("the worker concurrency is not zero"),
};

/// How long the verification worker waits after it finds no due job.
const WORKER_IDLE_POLL: Duration = Duration::from_secs(5);

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
    service: Arc<DocumentService>,
    dispatcher: Dispatcher<VerificationStore>,
    transport: Arc<VerificationTransport>,
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
/// confirm the database answers over the runtime credential and carries
/// exactly this release's schema, open the audit journal, activate content
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
    store
        .ready()
        .await
        .map_err(|source| RuntimeError::Database {
            stage: "runtime database schema check",
            source,
        })?;
    let audit = open_audit(&config, &secrets).await?;
    let database_id = database_id(&config)?;
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
    let jobs = job_table(&schema).map_err(|error| RuntimeError::Dispatch(error.to_string()))?;
    let dispatcher = dispatcher(VerificationStore::new(store.clone(), schema, audit.clone()))
        .map_err(|error| RuntimeError::Dispatch(error.to_string()))?;
    let transport = Arc::new(VerificationTransport::new(
        store.clone(),
        Arc::clone(&storage),
        Arc::clone(&verifier),
    ));
    let service = Arc::new(DocumentService::new(
        store,
        Arc::new(package.project),
        storage,
        verifier.binding_digest().to_owned(),
        jobs,
        audit,
        ceiling,
    ));
    let listener = tokio::net::TcpListener::bind(config.listener.bind.socket_addr())
        .await
        .map_err(RuntimeError::Listen)?;
    Ok(Prepared {
        listener,
        service,
        dispatcher,
        transport,
    })
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
async fn open_audit(
    config: &RuntimeConfig,
    secrets: &registry_platform_config::SecretResolver,
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
    let destination = AuditDestination::from_settings(
        config.audit.destination,
        config.audit.path.clone(),
        None,
        None,
    )
    .map_err(|error| RuntimeError::AuditJournal(error.to_string()))?;
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
        Arc::clone(&self.service)
    }

    /// Run every due content verification attempt now and return how many
    /// jobs moved.
    #[cfg(feature = "postgres-test")]
    pub async fn verify_due(&self) -> usize {
        let (_sender, shutdown) = watch::channel(false);
        self.worker().drain(&shutdown).await
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
    /// and stop the verification worker.
    pub async fn serve_until(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), RuntimeError> {
        if let Ok(address) = self.listener.local_addr() {
            tracing::info!(address = %address, "the Document Store is serving");
        }
        let (stop, stopped) = watch::channel(false);
        let worker = tokio::spawn(self.worker().run(stopped));
        let served = axum::serve(self.listener, router())
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(RuntimeError::Listen);
        if stop.send(true).is_err() {
            tracing::warn!("the content verification worker had already stopped");
        }
        if let Err(error) = worker.await {
            tracing::error!(error = %error, "the content verification worker failed");
        }
        served
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
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
