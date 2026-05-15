// SPDX-License-Identifier: Apache-2.0
//! data_gate binary entry point.
//!
//! Wires Wave 0's parts into a runnable HTTP server:
//! 1. Initialise structured JSON tracing on stderr (architect decision
//!    #9: logs to stderr only in V1).
//! 2. Load and validate the YAML config from `--config <path>`, the
//!    `DATAGATE_CONFIG` env var, or `./config/example.yaml` (in that
//!    order of precedence).
//! 3. Build the `ApiKeyAuth` provider from `auth.api_keys[]`: read each
//!    `hash_env` env var (validated for presence and PHC shape by the
//!    config loader) and construct an `ApiKeyEntry` per configured id.
//!    The keyring lives inside `ApiKeyAuth` and is immutable for the
//!    lifetime of the process; rotation lands in Wave 4.
//! 4. Build the audit sink. Wave 0 supports only `stdout`; other sink
//!    variants are flagged in the operational log and fall back to
//!    stdout so the gateway starts. Wave 4 lands `file` and `syslog`.
//! 5. Compose the axum router via [`data_gate::server::build_app`].
//! 6. Bind on `config.server.bind`, optionally bind a second listener
//!    on `config.server.admin_bind`, serve, and shut down both cleanly
//!    on `SIGINT`/`Ctrl-C`.
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

use data_gate::audit::{AuditSink, StdoutSink};
use data_gate::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use data_gate::auth::ScopeSet;
use data_gate::config::{self, ApiKeyConfig, AuditSinkConfig, Config};
use data_gate::error::{ConfigError, Error};
use tokio::net::TcpListener;
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

    let dataset_count = config.datasets.len();
    let keyring_size = auth.len();
    let app = data_gate::server::build_app(
        Arc::clone(&config),
        Arc::clone(&auth),
        Arc::clone(&audit_sink),
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
            let admin_app =
                data_gate::server::build_admin_app(Arc::clone(&config), Arc::clone(&audit_sink));
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
/// Wave 4 will extend this with key rotation: a watcher reloads the
/// keyring when an operator rotates a hash, and the `ApiKeyAuth`
/// internals swap to an `ArcSwap` keyring. The Wave 0 surface
/// (`ApiKeyAuth::new(Vec<ApiKeyEntry>)`) does not change.
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

/// Instantiate the configured audit sink. Wave 0 supports `stdout`
/// only; the other variants log a warning and fall back to stdout so
/// the gateway still starts. Wave 4 implements `file` and `syslog`.
fn build_audit_sink(config: &Config) -> Arc<dyn AuditSink> {
    match &config.audit.sink {
        AuditSinkConfig::Stdout {} => Arc::new(StdoutSink::new()),
        AuditSinkConfig::File { .. } => {
            warn!(
                requested = "file",
                "audit sink not implemented in Wave 0; falling back to stdout"
            );
            Arc::new(StdoutSink::new())
        }
        AuditSinkConfig::Syslog {} => {
            warn!(
                requested = "syslog",
                "audit sink not implemented in Wave 0; falling back to stdout"
            );
            Arc::new(StdoutSink::new())
        }
        // `AuditSinkConfig` is `#[non_exhaustive]`; future variants
        // fall back to stdout with an explicit warning until their
        // wave implements them.
        _ => {
            warn!("unknown audit sink variant; falling back to stdout");
            Arc::new(StdoutSink::new())
        }
    }
}

fn audit_sink_kind(config: &Config) -> &'static str {
    match &config.audit.sink {
        AuditSinkConfig::Stdout {} => "stdout",
        AuditSinkConfig::File { .. } => "file (fallback: stdout)",
        AuditSinkConfig::Syslog {} => "syslog (fallback: stdout)",
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
