// SPDX-License-Identifier: Apache-2.0
//! data_gate binary entry point.
//!
//! Wires the V1 gateway into a runnable HTTP server:
//! 1. Initialise structured JSON tracing on stderr.
//! 2. Load and validate the YAML config from `--config <path>`, the
//!    `DATAGATE_CONFIG` env var, or `./config/example.yaml` (in that
//!    order of precedence).
//! 3. Build the `ApiKeyAuth` provider from `auth.api_keys[]`: read each
//!    `hash_env` env var (validated for presence and PHC shape by the
//!    config loader) and construct an `ApiKeyEntry` per configured id.
//!    The keyring lives inside `ApiKeyAuth` and is immutable for the
//!    lifetime of the process.
//! 4. Build the configured audit sink: stdout, file, or syslog, with
//!    optional audit-chain envelopes.
//! 5. Build ingest, readiness, entity registry, row-query, and aggregate
//!    query state, then compose the public data-plane router.
//! 6. Bind on `config.server.bind`, optionally bind the admin router on
//!    `config.server.admin_bind`, serve, and shut down cleanly on
//!    `SIGINT`/`Ctrl-C`.
//!
//! ## Error handling
//!
//! `main` propagates failures as [`crate::error::Error`]. The error
//! taxonomy already covers config parsing and binding failures; the
//! process exit code is non-zero on any error and the failing line is
//! also emitted via `tracing::error!` so operators can correlate.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use data_gate::audit::{AuditSink, ChainingSink, FileSink, StdoutSink, SyslogSink};
use data_gate::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use data_gate::auth::ScopeSet;
use data_gate::config::{self, ApiKeyConfig, AuditSinkConfig, Config};
use data_gate::entity::EntityRegistry;
use data_gate::error::{ConfigError, Error};
use data_gate::format::FormatRegistry;
use data_gate::ingest::{IngestRegistry, ReadinessSnapshot};
use data_gate::query::{AggregateQueryEngine, EntityQueryEngine};
use datafusion::execution::context::SessionContext;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// CLI flag for the config path. Kept minimal: a single `--config
/// <path>` positional plus the `DATAGATE_CONFIG` env var fallback.
const CONFIG_FLAG: &str = "--config";

/// Last-resort default config path. Mirrors the architect's exit
/// criteria (`config/example.yaml`).
const DEFAULT_CONFIG_PATH: &str = "./config/example.yaml";

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // The error itself has already been logged at the failing
            // site (config loader logs operator context; bind/serve
            // failures are logged here). The exit code is the only
            // surface left.
            error!(error = %err, "data_gate exiting with failure");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_path = resolve_config_path();
    info!(path = %config_path.display(), "loading data_gate config");

    let config = Arc::new(config::load(&config_path)?);

    let auth = Arc::new(build_auth(&config)?);
    let audit_sink = build_audit_sink(&config);
    let bind: SocketAddr = config.server.bind;
    let admin_bind: Option<SocketAddr> = config.server.admin_bind;
    let audit_kind = audit_sink_kind(&config);
    let df_ctx = Arc::new(SessionContext::new());
    let formats = Arc::new(FormatRegistry::with_v1_defaults());
    let cache_root = Arc::from(config.server.cache_dir.as_path());
    let ingest = Arc::new(IngestRegistry::from_config(
        &config,
        formats,
        cache_root,
        Arc::clone(&df_ctx),
    )?);
    let entity_registry = Arc::new(EntityRegistry::from_config(&config)?);
    let query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&df_ctx),
        Arc::clone(&entity_registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&df_ctx),
        Arc::clone(&entity_registry),
        Arc::clone(&config),
    ));
    let initial_snapshot = ingest.snapshot();
    let (readiness_tx, readiness_rx) = watch::channel::<ReadinessSnapshot>(initial_snapshot);

    ingest.run_initial_ingest(readiness_tx.clone()).await;
    let (mut refresh_tasks, refresh_shutdown) =
        Arc::clone(&ingest).spawn_refresh_tasks_with_config(&config, readiness_tx);

    let dataset_count = config.datasets.len();
    let keyring_size = auth.len();
    let app = data_gate::server::build_app_with_entity_query(
        Arc::clone(&config),
        Arc::clone(&auth),
        Arc::clone(&audit_sink),
        readiness_rx.clone(),
        entity_registry,
        query,
        aggregate_query,
    );

    let listener = TcpListener::bind(bind).await.map_err(|err| {
        error!(error = %err, bind = %bind, "failed to bind listener");
        err
    })?;

    info!(
        bind = %bind,
        admin_bind = ?admin_bind,
        datasets = dataset_count,
        api_keys = keyring_size,
        audit_sink = audit_kind,
        "data_gate listening"
    );

    let admin_listener = match admin_bind {
        Some(addr) => Some(TcpListener::bind(addr).await.map_err(|err| {
            error!(error = %err, bind = %addr, "failed to bind admin listener");
            err
        })?),
        None => None,
    };

    let main_serve =
        axum::serve(listener, app.into_make_service()).with_graceful_shutdown(shutdown_signal());

    // Run both servers concurrently. `tokio::select!` is the natural
    // fit because either listener exiting (clean or not) tears down
    // the other.
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
        if let Some(admin_listener) = admin_listener {
            let admin_app = data_gate::server::build_admin_app(
                Arc::clone(&config),
                Arc::clone(&auth),
                Arc::clone(&audit_sink),
                readiness_rx.clone(),
                Arc::clone(&ingest),
            );
            let admin_serve = axum::serve(admin_listener, admin_app.into_make_service())
                .with_graceful_shutdown(shutdown_signal());
            tokio::select! {
                r = main_serve => r.map_err(Into::into),
                r = admin_serve => r.map_err(Into::into),
            }
        } else {
            main_serve.await.map_err(Into::into)
        };

    // Best-effort audit flush on the way out, regardless of which
    // listener tripped the shutdown.
    if let Err(err) = audit_sink.flush().await {
        warn!(error = %err, "audit flush on shutdown failed");
    }

    refresh_shutdown.cancel();
    while let Some(joined) = refresh_tasks.join_next().await {
        if let Err(err) = joined {
            warn!(error = %err, "refresh task failed during shutdown");
        }
    }

    result
}

/// Resolve the config path from (in order):
/// * the first non-flag positional after `--config`
/// * the `DATAGATE_CONFIG` env var
/// * the project-relative default `./config/example.yaml`
fn resolve_config_path() -> PathBuf {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == CONFIG_FLAG {
            if let Some(p) = args.next() {
                return PathBuf::from(p);
            }
        } else if let Some(rest) = arg.strip_prefix(&format!("{CONFIG_FLAG}=")) {
            return PathBuf::from(rest);
        }
    }
    if let Ok(p) = env::var("DATAGATE_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(DEFAULT_CONFIG_PATH)
}

/// Build the V1 API-key provider from `auth.api_keys[]`.
///
/// The config validator (`crate::config::validate`) already enforced
/// that every `hash_env` is set and parses as an Argon2id PHC string,
/// so the only failures we expect here are TOCTOU env var removals
/// between validation and now. Those propagate as
/// `ConfigError::MissingSecret` so the binary exits with the same
/// stable code as the validator does.
///
/// The keyring is immutable for the process lifetime. Key rotation is a
/// restart operation unless a future provider adds live keyring reload.
fn build_auth(config: &Config) -> Result<ApiKeyAuth, Error> {
    let mut entries = Vec::with_capacity(config.auth.api_keys.len());
    for key in &config.auth.api_keys {
        let entry = build_api_key_entry(key)?;
        entries.push(entry);
    }
    Ok(ApiKeyAuth::new(entries))
}

/// Resolve one `ApiKeyConfig` into an `ApiKeyEntry`.
///
/// Pulls the PHC string from the env var named by `hash_env`,
/// collects scopes into a `ScopeSet`, and validates the PHC via
/// `ApiKeyEntry::new` (which re-parses defensively even though the
/// config validator already accepted it).
fn build_api_key_entry(key: &ApiKeyConfig) -> Result<ApiKeyEntry, Error> {
    let phc = env::var(&key.hash_env).map_err(|_| {
        tracing::error!(
            code = "config.missing_secret",
            api_key_id = %key.id,
            hash_env = %key.hash_env,
            "hash_env environment variable is not set at auth build time"
        );
        Error::from(ConfigError::MissingSecret)
    })?;
    let scopes: ScopeSet = key.scopes.iter().cloned().collect();
    ApiKeyEntry::new(key.id.clone(), scopes, phc).map_err(|reason| {
        tracing::error!(
            code = "config.validation_error",
            api_key_id = %key.id,
            hash_env = %key.hash_env,
            reason = %reason,
            "failed to construct ApiKeyEntry from configured hash_env"
        );
        Error::from(ConfigError::ValidationError)
    })
}

/// Instantiate the configured audit sink.
fn build_audit_sink(config: &Config) -> Arc<dyn AuditSink> {
    let sink: Arc<dyn AuditSink> = match &config.audit.sink {
        AuditSinkConfig::Stdout {} => Arc::new(StdoutSink::new()),
        AuditSinkConfig::File { path, rotate } => {
            match FileSink::new(path, rotate.max_size_mb, rotate.max_files) {
                Ok(sink) => Arc::new(sink),
                Err(err) => {
                    warn!(
                        error = %err,
                        requested = "file",
                        "audit file sink unavailable; falling back to stdout"
                    );
                    Arc::new(StdoutSink::new())
                }
            }
        }
        AuditSinkConfig::Syslog {} => Arc::new(SyslogSink::new()),
        _ => {
            warn!("unknown audit sink variant; falling back to stdout");
            Arc::new(StdoutSink::new())
        }
    };
    if config.audit.chain {
        Arc::new(ChainingSink::new(sink))
    } else {
        sink
    }
}

fn audit_sink_kind(config: &Config) -> &'static str {
    match &config.audit.sink {
        AuditSinkConfig::Stdout {} => "stdout",
        AuditSinkConfig::File { .. } => "file",
        AuditSinkConfig::Syslog {} => "syslog",
        _ => "unknown (fallback: stdout)",
    }
}

/// Initialise structured JSON tracing on stderr. `RUST_LOG` controls
/// the filter; defaults to `info` per architect decision #9.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer().json().with_writer(std::io::stderr);
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

/// Wait for `Ctrl-C` so axum can drain in-flight requests cleanly.
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("received shutdown signal; draining"),
        Err(err) => {
            error!(error = %err, "failed to install ctrl-c handler");
        }
    }
}
