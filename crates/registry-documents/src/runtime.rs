// SPDX-License-Identifier: Apache-2.0

//! Service assembly: `documents serve` loads and checks the runtime
//! configuration, confirms the database answers over the runtime
//! credential, binds the listener, and serves the HTTP surface.
//!
//! Every step that can refuse a deployment runs before the listener binds,
//! so a mis-provisioned deployment never answers a request.
//!
//! On SIGTERM or SIGINT, `serve` stops accepting, finishes the requests it
//! is answering, and exits 0.

use std::net::SocketAddr;
use std::path::Path;

use clap::{Arg, Command};
use registry_platform_yaml::Report;
use thiserror::Error;
use tracing_subscriber::filter::LevelFilter;

use crate::config::{startup_report, RuntimeConfig, RuntimeConfigError};
use crate::http::router;
use crate::package::{load_package, PackageLoadError};
use crate::store::{PostgresStore, StoreError};

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
#[derive(Debug)]
pub struct Prepared {
    listener: tokio::net::TcpListener,
}

/// Load and check the runtime document at `path` and the package it names,
/// confirm the database answers over the runtime credential and carries
/// exactly this release's schema, and bind the listener.
pub async fn prepare(path: impl AsRef<Path>) -> Result<Prepared, RuntimeError> {
    let config = load_config(path.as_ref())?;
    let secrets = config.secret_resolver()?;
    let _package = load_package(&config)?;
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
    let listener = tokio::net::TcpListener::bind(config.listener.bind.socket_addr())
        .await
        .map_err(RuntimeError::Listen)?;
    Ok(Prepared { listener })
}

impl Prepared {
    /// The address the listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, RuntimeError> {
        self.listener.local_addr().map_err(RuntimeError::Listen)
    }

    /// Serve until `shutdown` resolves, then finish the requests in flight.
    pub async fn serve_until(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), RuntimeError> {
        if let Ok(address) = self.listener.local_addr() {
            tracing::info!(address = %address, "the Document Store is serving");
        }
        axum::serve(self.listener, router())
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(RuntimeError::Listen)
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
