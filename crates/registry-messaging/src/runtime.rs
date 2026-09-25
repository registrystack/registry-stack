// SPDX-License-Identifier: Apache-2.0

//! Service assembly: `messaging migrate` applies the schema with the
//! migration credential, and `messaging serve` loads the configuration and
//! the package, checks the store and the package ledger, keys the audit
//! journal, and serves the public listener beside the optional
//! operator-private metrics listener.
//!
//! The runtime serves only the package the ledger names active. A changed
//! package on disk is refused at startup until `messagingctl apply` records
//! it, and a recorded package takes effect when the runtime restarts.
//!
//! Every step that can refuse a deployment runs before either listener
//! binds, so a mis-provisioned deployment never answers a request.
//!
//! Beside the listeners, `serve` runs the dispatch worker, which sends
//! accepted messages through the transports registered for their
//! providers, the audit publisher, which appends the outbox to the
//! journal, and the retention sweep, which erases what the retention
//! periods say has expired. Any one of them stopping is a runtime failure,
//! as a listener stopping is.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::{Arg, Command};
use registry_platform_audit::{AuditError, AuditProfile};
use registry_platform_config::{ProtectedSecret, SecretResolver};
use registry_platform_dispatch::postgres::{DispatchWorker, WorkerConfig};
use serde::Serialize;
use thiserror::Error;
use tracing_subscriber::filter::LevelFilter;

use crate::audit::AuditJournal;
use crate::auth::MessagingAuthenticator;
use crate::config::{describe_secret_failure, RetentionConfig, RuntimeConfig, RuntimeConfigError};
use crate::dispatch::{dispatcher, MessageDispatcher, MessageSender, Transports};
use crate::http::{metrics_router, router, HttpState, Readiness};
use crate::limits::CallerLimits;
use crate::messages::{MessageService, MessageStore};
use crate::metrics::Metrics;
use crate::outbox::Publisher;
use crate::providers::{activate_providers, ProviderActivationError};
use crate::retention::{
    erase_expired, RetentionActor, RetentionError, RetentionReport, RetentionSweep, SWEEP_INTERVAL,
};
use crate::store::{PostgresStore, StoreError};

/// The event the journal records when a runtime starts serving.
const RUNTIME_STARTED_EVENT: &str = "messaging.runtime.started";

/// The most sends the worker runs at once.
const WORKER_CONCURRENCY: NonZeroUsize = NonZeroUsize::new(8).expect("eight is not zero");

/// How long the worker waits after a pass finds no due message.
const WORKER_IDLE_POLL: Duration = Duration::from_secs(1);

/// How often the publisher appends the audit outbox to the journal.
const PUBLICATION_INTERVAL: Duration = Duration::from_secs(1);

#[must_use]
pub fn command() -> Command {
    Command::new("messaging")
        .version(registry_platform_buildinfo::DISPLAY_VERSION)
        .about("Run and maintain Registry Messaging")
        .arg(
            Arg::new("runtime-config")
                .long("runtime-config")
                .value_name("FILE")
                .help("Absolute path to the runtime configuration file.")
                .required(true),
        )
        .subcommand_required(true)
        .subcommand(Command::new("migrate").about("Apply Messaging database migrations"))
        .subcommand(Command::new("serve").about("Run the Messaging HTTP service"))
}

/// The operational log level, read from `MESSAGING_LOG`. The variable
/// accepts exactly `error`, `warn`, or `info`, and the level applies to the
/// Messaging crates only. Any other value, including a tracing directive
/// that would enable a dependency's own debug or trace logging, is refused
/// rather than silently accepted.
pub fn operational_log_level(value: Option<&str>) -> Result<LevelFilter, RuntimeError> {
    match value.unwrap_or("info") {
        "error" => Ok(LevelFilter::ERROR),
        "warn" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        _ => Err(RuntimeError::Logging),
    }
}

/// Run the parsed command. `serve` sends through `transports`, the
/// transport registered for each provider id, beside the transport it
/// activates for each provider the runtime configuration connects.
pub async fn run(matches: &clap::ArgMatches, transports: Transports) -> Result<(), RuntimeError> {
    let path = matches
        .get_one::<String>("runtime-config")
        .ok_or(RuntimeError::Arguments)?;
    match matches.subcommand_name() {
        Some("migrate") => migrate_from_path(path).await,
        Some("serve") => serve_from_path(path, transports).await,
        _ => Err(RuntimeError::Arguments),
    }
}

/// Name the provisioning or startup act a store failure happened in.
fn database_step(stage: &'static str) -> impl Fn(StoreError) -> RuntimeError {
    move |source| RuntimeError::Database { stage, source }
}

pub async fn migrate_from_path(path: impl AsRef<Path>) -> Result<(), RuntimeError> {
    let config = RuntimeConfig::load(path)?;
    let secrets = config.secret_resolver()?;
    let store = PostgresStore::connect_migration(&config.database, &secrets)
        .map_err(database_step("migration database configuration"))?;
    store
        .migrate()
        .await
        .map_err(database_step("schema migration"))?;
    Ok(())
}

/// What applying the package on disk would change in the ledger, and
/// whether this call recorded it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageApply {
    /// The digest of the package on disk.
    pub package_digest: String,
    /// The digest the ledger names active, if any.
    pub active_digest: Option<String>,
    pub change: PackageChange,
    /// Whether this call recorded the package in the ledger.
    pub applied: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageChange {
    /// The ledger already names this package active.
    None,
    /// Recording the package makes it the one the runtime serves after its
    /// next restart.
    Activate,
}

/// Compare the package on disk with the ledger, and with `apply` record it
/// as active. The package is loaded and checked exactly as `serve` loads it,
/// pinned digest included, and the ledger is reached with the migration
/// credential. A running runtime keeps serving its package until restarted.
pub async fn apply_package(
    config: &RuntimeConfig,
    apply: bool,
) -> Result<PackageApply, RuntimeError> {
    let loaded = config.load_package()?;
    let secrets = config.secret_resolver()?;
    let store = PostgresStore::connect_migration(&config.database, &secrets)
        .map_err(database_step("migration database configuration"))?;
    store
        .ready()
        .await
        .map_err(database_step("schema readiness check"))?;
    let active_digest = store
        .active_package_digest()
        .await
        .map_err(database_step("package ledger read"))?;
    let package_digest = loaded.package.digest().to_owned();
    let change = if active_digest.as_deref() == Some(package_digest.as_str()) {
        PackageChange::None
    } else {
        PackageChange::Activate
    };
    let applied = if apply && change == PackageChange::Activate {
        store
            .apply_package(
                &package_digest,
                registry_platform_buildinfo::DISPLAY_VERSION,
            )
            .await
            .map_err(database_step("package ledger write"))?
    } else {
        false
    };
    Ok(PackageApply {
        package_digest,
        active_digest,
        change,
        applied,
    })
}

/// The message store `messagingctl messages` reads and acts on, reached
/// with the runtime credential. It sends nothing: its dispatcher has no
/// transport, and every transition it makes writes its audit record into
/// the outbox the running runtime publishes.
pub async fn message_store(config: &RuntimeConfig) -> Result<MessageStore, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let store = PostgresStore::connect_runtime(&config.database, &secrets)
        .map_err(database_step("runtime database configuration"))?;
    store
        .ready()
        .await
        .map_err(database_step("schema readiness check"))?;
    let schema = store
        .current_schema()
        .await
        .map_err(database_step("schema lookup"))?;
    let dispatcher = dispatcher(store.clone(), &schema, Arc::new(Transports::new()))
        .map_err(|error| RuntimeError::Dispatch(error.to_string()))?;
    Ok(MessageStore::new(store, dispatcher))
}

/// Count what expired by `before` under the configured retention, and with
/// `apply` erase it, as the operator tool. The store is reached with the
/// migration credential, like `apply_package`, so an operator can erase
/// with the runtime stopped; the run takes the same lock the runtime's
/// sweep takes, so the two never interleave.
pub async fn erase_expired_as_operator(
    config: &RuntimeConfig,
    before: std::time::SystemTime,
    apply: bool,
) -> Result<RetentionReport, RuntimeError> {
    let secrets = config.secret_resolver()?;
    let store = PostgresStore::connect_migration(&config.database, &secrets)
        .map_err(database_step("migration database configuration"))?;
    store
        .ready()
        .await
        .map_err(database_step("schema readiness check"))?;
    erase_expired(
        &store,
        config.retention,
        Some(before),
        apply,
        RetentionActor::OperatorTool,
    )
    .await
    .map_err(|error| match error {
        RetentionError::Store(source) => RuntimeError::Database {
            stage: "retention run",
            source,
        },
        refused => RuntimeError::Retention(refused),
    })
}

pub async fn serve_from_path(
    path: impl AsRef<Path>,
    transports: Transports,
) -> Result<(), RuntimeError> {
    let config = RuntimeConfig::load(path)?;
    let listeners = Listeners::bind(&config).await?;
    let app = assemble(&config, transports).await?;
    tracing::info!(
        listener = %config.listener.bind,
        metrics_listener = config.metrics_listener.is_some(),
        "serving Registry Messaging"
    );
    listeners.serve(app).await
}

/// The assembled service: the routers both listeners serve, and the
/// dispatch worker, audit publisher, and retention sweep that run beside
/// them.
pub struct Assembled {
    public: axum::Router,
    metrics: axum::Router,
    worker: DispatchWorker<crate::dispatch::MessageDispatchStore, MessageSender>,
    publisher: Publisher,
    retention: RetentionSweep,
}

/// Build everything `serve` needs from a checked configuration: the
/// package the ledger names active, the store, every configured provider
/// activated into `transports` with its callback receiver, the
/// authenticator, the keyed audit journal, the dispatcher, and the audit
/// publisher, then record the start.
pub async fn assemble(
    config: &RuntimeConfig,
    transports: Transports,
) -> Result<Assembled, RuntimeError> {
    let loaded = config.load_package()?;
    let secrets = config.secret_resolver()?;
    let store = PostgresStore::connect_runtime(&config.database, &secrets)
        .map_err(database_step("runtime database configuration"))?;
    store
        .ready()
        .await
        .map_err(database_step("schema readiness check"))?;
    let active = store
        .active_package_digest()
        .await
        .map_err(database_step("package ledger read"))?;
    check_active_package(active.as_deref(), loaded.package.digest())?;

    let mut transports = transports;
    let callbacks = Arc::new(activate_providers(
        config,
        &loaded,
        &secrets,
        &mut transports,
    )?);

    let keys = config.jwks_fetcher(&secrets).await?;
    let authenticator = Arc::new(MessagingAuthenticator::new(
        config.verifier_profile(),
        keys,
        loaded.package.access_profiles().clone(),
        config.binds_assertion_issuers(),
    ));

    let audit_secret = resolve_audit_secret(&secrets, &config.audit.hash_key_ref)?;
    // One master secret, two HKDF-derived sub-keys: the chain integrity key
    // and the identifier-hash key never share key material.
    let audit_profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        audit_secret.expose_secret().to_vec(),
    ))
    .map_err(|error| RuntimeError::AuditJournal(error.to_string()))?;
    let audit = Arc::new(
        AuditJournal::open(&config.audit.path, &audit_profile)
            .await
            .map_err(|error| RuntimeError::AuditJournal(describe_audit_failure(&error)))?,
    );
    // The publisher first confirms the last outbox record the journal held
    // when it was opened, authenticated against the verified chain, so a
    // record a crash left unmarked is not appended twice.
    let publisher = Publisher::new(store.clone(), Arc::clone(&audit));
    let schema = store
        .current_schema()
        .await
        .map_err(database_step("schema lookup"))?;
    let transports = Arc::new(transports);
    let dispatcher: MessageDispatcher = dispatcher(store.clone(), &schema, Arc::clone(&transports))
        .map_err(|error| RuntimeError::Dispatch(error.to_string()))?;
    let metrics = Arc::new(Metrics::default());
    let worker = DispatchWorker::new(
        dispatcher.clone(),
        Arc::new(MessageSender::new(
            dispatcher.clone(),
            transports,
            Arc::clone(&metrics),
        )),
        WorkerConfig {
            concurrency: WORKER_CONCURRENCY,
            idle_poll: WORKER_IDLE_POLL,
        },
    );
    let messages = MessageService::new(
        MessageStore::new(store.clone(), dispatcher),
        Arc::clone(&audit),
        config.retention,
        loaded.receipt_providers(),
    );
    audit
        .append(RuntimeStarted::new(
            config.retention,
            loaded.package.digest().to_owned(),
        ))
        .await
        .map_err(|error| RuntimeError::AuditJournal(describe_audit_failure(&error)))?;

    let limits = Arc::new(
        CallerLimits::new(loaded.package.access_profiles())
            .map_err(|error| RuntimeError::Limits(error.to_string()))?,
    );
    Ok(Assembled {
        public: router(HttpState {
            authenticator,
            readiness: Readiness::Store {
                store: store.clone(),
                package_digest: loaded.package.digest().to_owned(),
            },
            metrics: Arc::clone(&metrics),
            limits,
            package: Arc::new(loaded.package),
            audit,
            messages: Some(Arc::new(messages)),
            callbacks,
        }),
        metrics: metrics_router(Arc::clone(&metrics), Some(store.clone())),
        worker,
        publisher,
        retention: RetentionSweep::new(store, config.retention, metrics),
    })
}

/// The bound sockets. Both bind before the service is assembled, so a
/// configured address that is already taken is refused before anything is
/// written to the journal.
pub struct Listeners {
    public: tokio::net::TcpListener,
    metrics: Option<tokio::net::TcpListener>,
}

impl Listeners {
    pub async fn bind(config: &RuntimeConfig) -> Result<Self, RuntimeError> {
        let public = tokio::net::TcpListener::bind(config.listener.bind)
            .await
            .map_err(|source| RuntimeError::Listen {
                listener: "listener",
                source,
            })?;
        let metrics = match &config.metrics_listener {
            Some(metrics) => Some(tokio::net::TcpListener::bind(metrics.bind).await.map_err(
                |source| RuntimeError::Listen {
                    listener: "metricsListener",
                    source,
                },
            )?),
            None => None,
        };
        Ok(Self { public, metrics })
    }

    /// Serve both listeners beside the worker, the publisher, and the
    /// retention sweep until any of them stops. Each one stopping is a
    /// failure: a runtime that answers requests but not its operator's
    /// metrics, or accepts messages it no longer sends, audits, or erases,
    /// is not the deployment that was configured.
    pub async fn serve(self, app: Assembled) -> Result<(), RuntimeError> {
        // Nothing turns the signal: the worker, the publisher, and the
        // sweep run for the life of the process, and the sender is held so
        // they never observe it closing.
        let (_shutdown, stopped) = tokio::sync::watch::channel(false);
        let worker = app.worker.run(stopped.clone());
        let publisher = app.publisher.run(PUBLICATION_INTERVAL, stopped.clone());
        let retention = app.retention.run(SWEEP_INTERVAL, stopped);
        let public = axum::serve(self.public, app.public);
        let listeners = async move {
            match self.metrics {
                Some(listener) => {
                    let metrics = axum::serve(listener, app.metrics);
                    tokio::select! {
                        served = public => served.map_err(|source| RuntimeError::Listen {
                            listener: "listener",
                            source,
                        }),
                        served = metrics => served.map_err(|source| RuntimeError::Listen {
                            listener: "metricsListener",
                            source,
                        }),
                    }
                }
                None => public.await.map_err(|source| RuntimeError::Listen {
                    listener: "listener",
                    source,
                }),
            }
        };
        tokio::select! {
            served = listeners => served,
            () = worker => Err(RuntimeError::Stopped { task: "dispatch worker" }),
            () = publisher => Err(RuntimeError::Stopped { task: "audit publisher" }),
            () = retention => Err(RuntimeError::Stopped { task: "retention sweep" }),
        }
    }
}

/// Refuse to serve a package the ledger does not name active: none was
/// ever applied, or the package on disk changed since the last apply.
fn check_active_package(active: Option<&str>, package: &str) -> Result<(), RuntimeError> {
    match active {
        None => Err(RuntimeError::PackageNotApplied {
            package: package.to_owned(),
        }),
        Some(active) if active != package => Err(RuntimeError::PackageLedgerMismatch {
            active: active.to_owned(),
            package: package.to_owned(),
        }),
        Some(_) => Ok(()),
    }
}

/// The start record: the runtime version, the active package digest, and
/// the retention periods this deployment enforces. It names no principal,
/// contact, or secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeStarted {
    event: &'static str,
    runtime_version: &'static str,
    package_digest: String,
    retention: RetentionConfig,
}

impl RuntimeStarted {
    fn new(retention: RetentionConfig, package_digest: String) -> Self {
        Self {
            event: RUNTIME_STARTED_EVENT,
            runtime_version: registry_platform_buildinfo::DISPLAY_VERSION,
            package_digest,
            retention,
        }
    }
}

/// The audit error's own account. Audit errors describe paths, permissions,
/// and chain integrity; they never carry the keying secret.
fn describe_audit_failure(error: &AuditError) -> String {
    error.to_string()
}

/// Resolve the audit journal's keying secret, naming the reference on
/// refusal and never the key bytes.
fn resolve_audit_secret(
    secrets: &SecretResolver,
    reference: &str,
) -> Result<ProtectedSecret, RuntimeError> {
    secrets.resolve(reference).map_err(|error| {
        RuntimeError::AuditSecret(describe_secret_failure(
            "audit.hashKeyRef",
            reference,
            &error,
        ))
    })
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("the messaging command arguments are invalid")]
    Arguments,
    #[error(
        "the Messaging package ledger names no active package; record package {package} with \
         messagingctl apply before serving"
    )]
    PackageNotApplied { package: String },
    #[error(
        "the Messaging package on disk ({package}) is not the package the ledger names active \
         ({active}); record it with messagingctl apply, then restart"
    )]
    PackageLedgerMismatch { active: String, package: String },
    #[error("MESSAGING_LOG must be one of error, warn, or info")]
    Logging,
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),
    #[error("the Messaging audit journal could not be opened or extended: {0}")]
    AuditJournal(String),
    #[error("{0}")]
    AuditSecret(String),
    /// A database step of provisioning or startup failed. The step is named
    /// because the remedies differ: an unreachable server, a database nobody
    /// migrated, and a refused credential are different operator tasks.
    #[error("the Messaging {stage} failed: {source}")]
    Database {
        stage: &'static str,
        #[source]
        source: StoreError,
    },
    #[error("the Messaging {listener} could not bind or serve: {source}")]
    Listen {
        listener: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("the Messaging dispatcher could not be configured: {0}")]
    Dispatch(String),
    #[error("the Messaging limits could not be configured: {0}")]
    Limits(String),
    #[error(transparent)]
    Retention(RetentionError),
    #[error("the Messaging {0}")]
    Provider(#[from] ProviderActivationError),
    #[error("the Messaging {task} stopped")]
    Stopped { task: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn operational_log_level_is_a_closed_vocabulary() {
        assert_eq!(operational_log_level(None).unwrap(), LevelFilter::INFO);
        assert_eq!(
            operational_log_level(Some("info")).unwrap(),
            LevelFilter::INFO
        );
        assert_eq!(
            operational_log_level(Some("warn")).unwrap(),
            LevelFilter::WARN
        );
        assert_eq!(
            operational_log_level(Some("error")).unwrap(),
            LevelFilter::ERROR
        );
        for refused in ["debug", "trace", "registry_messaging=trace", "", "INFO"] {
            assert!(
                matches!(
                    operational_log_level(Some(refused)),
                    Err(RuntimeError::Logging)
                ),
                "{refused} was accepted"
            );
        }
    }

    #[test]
    fn the_command_requires_a_runtime_config_and_a_subcommand() {
        assert!(command()
            .try_get_matches_from(["messaging", "serve"])
            .is_err());
        assert!(command()
            .try_get_matches_from(["messaging", "--runtime-config", "/etc/messaging.yaml"])
            .is_err());
        for subcommand in ["migrate", "serve"] {
            let matches = command()
                .try_get_matches_from([
                    "messaging",
                    "--runtime-config",
                    "/etc/messaging.yaml",
                    subcommand,
                ])
                .unwrap();
            assert_eq!(matches.subcommand_name(), Some(subcommand));
        }
        assert!(command()
            .try_get_matches_from([
                "messaging",
                "--runtime-config",
                "/etc/messaging.yaml",
                "send"
            ])
            .is_err());
    }

    #[test]
    fn the_start_record_names_only_the_version_and_retention() {
        let record = serde_json::to_value(RuntimeStarted::new(
            RetentionConfig::default(),
            format!("sha256:{}", "a".repeat(64)),
        ))
        .unwrap();
        let object = record.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["event", "packageDigest", "retention", "runtimeVersion"]
        );
        assert_eq!(object["event"], RUNTIME_STARTED_EVENT);
    }

    #[tokio::test]
    async fn the_journal_records_the_start_under_the_keyed_chain() {
        let directory = tempfile::tempdir().unwrap();
        let audit = directory.path().join("audit").join("messaging.jsonl");
        let profile =
            AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(vec![7u8; 32]))
                .unwrap();
        let journal = AuditJournal::open(&audit, &profile).await.unwrap();
        journal
            .append(RuntimeStarted::new(
                RetentionConfig::default(),
                format!("sha256:{}", "a".repeat(64)),
            ))
            .await
            .unwrap();
        drop(journal);
        let written = std::fs::read_to_string(&audit).unwrap();
        assert_eq!(written.lines().count(), 1);
        assert!(written.contains(RUNTIME_STARTED_EVENT));
        let reopened = AuditJournal::open(&audit, &profile).await.unwrap();
        reopened.append(json!({"event": "second"})).await.unwrap();
        drop(reopened);
        // The reopened chain continues the first record's chain rather than
        // starting a second genesis.
        let written = std::fs::read_to_string(&audit).unwrap();
        let second: serde_json::Value =
            serde_json::from_str(written.lines().nth(1).unwrap()).unwrap();
        assert!(!second["prev_hash"].is_null(), "{second}");
    }

    #[test]
    fn the_runtime_serves_only_the_package_the_ledger_names_active() {
        let package = format!("sha256:{}", "a".repeat(64));
        let other = format!("sha256:{}", "b".repeat(64));
        assert!(check_active_package(Some(&package), &package).is_ok());
        let error = check_active_package(None, &package).unwrap_err();
        assert!(matches!(error, RuntimeError::PackageNotApplied { .. }));
        assert!(error.to_string().contains("messagingctl apply"));
        let error = check_active_package(Some(&other), &package).unwrap_err();
        assert!(matches!(error, RuntimeError::PackageLedgerMismatch { .. }));
        let message = error.to_string();
        assert!(
            message.contains(&package) && message.contains(&other),
            "{message}"
        );
    }
}
