// SPDX-License-Identifier: Apache-2.0

//! Service assembly: `messaging migrate` applies the schema with the
//! migration credential, and `messaging serve` loads the configuration and
//! the access profiles, checks the store, keys the audit journal, and serves
//! the public listener beside the optional operator-private metrics
//! listener.
//!
//! Every step that can refuse a deployment runs before either listener
//! binds, so a mis-provisioned deployment never answers a request.

use std::path::Path;
use std::sync::Arc;

use clap::{Arg, Command};
use registry_platform_audit::{AuditError, AuditProfile, ChainState, DurableSegmentedJsonlSink};
use registry_platform_config::{ProtectedSecret, SecretResolver};
use serde::Serialize;
use thiserror::Error;
use tracing_subscriber::filter::LevelFilter;

use crate::auth::MessagingAuthenticator;
use crate::config::{describe_secret_failure, RetentionConfig, RuntimeConfig, RuntimeConfigError};
use crate::http::{metrics_router, router, HttpState, Readiness};
use crate::metrics::Metrics;
use crate::store::{PostgresStore, StoreError};

/// The largest active audit segment before the sink seals it and opens the
/// next one.
const MAXIMUM_AUDIT_SEGMENT_BYTES: u64 = 10 * 1024 * 1024;

/// The event the journal records when a runtime starts serving.
const RUNTIME_STARTED_EVENT: &str = "messaging.runtime.started";

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

pub async fn run(matches: &clap::ArgMatches) -> Result<(), RuntimeError> {
    let path = matches
        .get_one::<String>("runtime-config")
        .ok_or(RuntimeError::Arguments)?;
    match matches.subcommand_name() {
        Some("migrate") => migrate_from_path(path).await,
        Some("serve") => serve_from_path(path).await,
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

pub async fn serve_from_path(path: impl AsRef<Path>) -> Result<(), RuntimeError> {
    let config = RuntimeConfig::load(path)?;
    let listeners = Listeners::bind(&config).await?;
    let app = assemble(&config).await?;
    tracing::info!(
        listener = %config.listener.bind,
        metrics_listener = config.metrics_listener.is_some(),
        "serving Registry Messaging"
    );
    listeners.serve(app).await
}

/// The assembled service: the routers both listeners serve.
pub struct Assembled {
    public: axum::Router,
    metrics: axum::Router,
}

/// Build everything `serve` needs from a checked configuration: the store,
/// the authenticator, and the keyed audit journal, then record the start.
pub async fn assemble(config: &RuntimeConfig) -> Result<Assembled, RuntimeError> {
    let profiles = config.load_package()?;
    let secrets = config.secret_resolver()?;
    let store = PostgresStore::connect_runtime(&config.database, &secrets)
        .map_err(database_step("runtime database configuration"))?;
    store
        .ready()
        .await
        .map_err(database_step("schema readiness check"))?;

    let keys = config.jwks_fetcher(&secrets).await?;
    let authenticator = Arc::new(MessagingAuthenticator::new(
        config.verifier_profile(),
        keys,
        profiles,
        config.binds_assertion_issuers(),
    ));

    let audit_secret = resolve_audit_secret(&secrets, &config.audit.hash_key_ref)?;
    // One master secret, two HKDF-derived sub-keys: the chain integrity key
    // and the identifier-hash key never share key material.
    let audit_profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        audit_secret.expose_secret().to_vec(),
    ))
    .map_err(|error| RuntimeError::AuditJournal(error.to_string()))?;
    let (sink, chain) = open_audit_journal(&config.audit.path, &audit_profile).await?;
    chain
        .append(sink.as_ref(), RuntimeStarted::new(config.retention))
        .await
        .map_err(|error| RuntimeError::AuditJournal(describe_audit_failure(&error)))?;

    let metrics = Arc::new(Metrics::default());
    Ok(Assembled {
        public: router(HttpState {
            authenticator,
            readiness: Readiness::Store(store),
            metrics: Arc::clone(&metrics),
        }),
        metrics: metrics_router(metrics),
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

    /// Serve both listeners until either stops. A listener that stops is a
    /// failure: a runtime that answers requests but not its operator's
    /// metrics, or the reverse, is not the deployment that was configured.
    pub async fn serve(self, app: Assembled) -> Result<(), RuntimeError> {
        let public = axum::serve(self.public, app.public);
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
    }
}

/// The start record: the runtime version and the retention periods this
/// deployment enforces. It names no principal, contact, or secret.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeStarted {
    event: &'static str,
    runtime_version: &'static str,
    retention: RetentionConfig,
}

impl RuntimeStarted {
    fn new(retention: RetentionConfig) -> Self {
        Self {
            event: RUNTIME_STARTED_EVENT,
            runtime_version: registry_platform_buildinfo::DISPLAY_VERSION,
            retention,
        }
    }
}

async fn open_audit_journal(
    path: &Path,
    profile: &AuditProfile,
) -> Result<(Arc<DurableSegmentedJsonlSink>, ChainState), RuntimeError> {
    let sink = Arc::new(
        DurableSegmentedJsonlSink::open(path, MAXIMUM_AUDIT_SEGMENT_BYTES)
            .map_err(|error| RuntimeError::AuditJournal(describe_audit_failure(&error)))?,
    );
    let chain = profile
        .bootstrap_or_start_empty(sink.as_ref())
        .await
        .map_err(|error| RuntimeError::AuditJournal(describe_audit_failure(&error)))?;
    Ok((sink, chain))
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let record = serde_json::to_value(RuntimeStarted::new(RetentionConfig::default())).unwrap();
        let object = record.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["event", "retention", "runtimeVersion"]);
        assert_eq!(object["event"], RUNTIME_STARTED_EVENT);
    }

    #[tokio::test]
    async fn the_journal_records_the_start_under_the_keyed_chain() {
        let directory = tempfile::tempdir().unwrap();
        let audit = directory.path().join("audit").join("messaging.jsonl");
        let profile =
            AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(vec![7u8; 32]))
                .unwrap();
        let (sink, chain) = open_audit_journal(&audit, &profile).await.unwrap();
        chain
            .append(
                sink.as_ref(),
                RuntimeStarted::new(RetentionConfig::default()),
            )
            .await
            .unwrap();
        drop(sink);
        let written = std::fs::read_to_string(&audit).unwrap();
        assert_eq!(written.lines().count(), 1);
        assert!(written.contains(RUNTIME_STARTED_EVENT));
        let (_sink, reopened) = open_audit_journal(&audit, &profile).await.unwrap();
        assert!(reopened.last_hash().await.is_some());
    }
}
