// SPDX-License-Identifier: Apache-2.0
//! registry-relay binary entry point.
//!
//! Wires the V1 gateway into a runnable HTTP server:
//! 1. Initialise operational tracing on stderr.
//! 2. Load and validate the YAML config from `--config <path>`, the
//!    `REGISTRY_RELAY_CONFIG` env var, or `./config/example.yaml` (in that
//!    order of precedence).
//! 3. Build the `ApiKeyAuth` provider from `auth.api_keys[]`: read each
//!    `hash_env` env var (validated for presence and fingerprint shape by the
//!    config loader) and construct an `ApiKeyEntry` per configured id.
//!    The keyring lives inside `ApiKeyAuth` and is immutable for the
//!    lifetime of the process.
//! 4. Build the configured audit sink: stdout, file, or syslog, with
//!    platform tamper-evident envelopes.
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

use datafusion::execution::context::SessionContext;
use registry_relay::audit::{AuditPipeline, FileSink, StdoutSink, SyslogSink};
use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use registry_relay::auth::middleware::AuthProviderRef;
use registry_relay::auth::oidc::{OidcAuth, ReqwestJwksFetcher};
use registry_relay::auth::ScopeSet;
use registry_relay::config::{self, ApiKeyConfig, AuditSinkConfig, Config, OidcConfig};
use registry_relay::entity::EntityRegistry;
use registry_relay::error::{ConfigError, Error};
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot};
use registry_relay::observability::RequestMetrics;
use registry_relay::provenance::{
    build_resolved_provenance_config, publicschema::build_publicschema_registry, ProvenanceState,
    ResolvedProvenanceConfig,
};
use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
#[cfg(feature = "spdci-api-standards")]
use registry_relay::spdci::build_spdci_response_mapper;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// CLI flag for the config path. Kept minimal: a single `--config
/// <path>` positional plus the `REGISTRY_RELAY_CONFIG` env var fallback.
const CONFIG_FLAG: &str = "--config";

/// Last-resort default config path.
const DEFAULT_CONFIG_PATH: &str = "./config/example.yaml";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationalLogFormat {
    Text,
    Json,
}

impl OperationalLogFormat {
    fn from_env() -> Self {
        env::var("REGISTRY_RELAY_LOG_FORMAT")
            .map(|value| Self::parse(&value))
            .unwrap_or(Self::Text)
    }

    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" | "jsonl" => Self::Json,
            _ => Self::Text,
        }
    }
}

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
            error!(error = %err, "registry-relay exiting with failure");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_path = resolve_config_path();
    info!(path = %config_path.display(), "loading registry-relay config");

    let loaded = config::load_with_metadata(&config_path)?;
    let compiled_metadata = loaded.metadata.map(Arc::new);
    let config = Arc::new(loaded.runtime);

    let auth = build_auth(&config).await?;
    let audit_sink = build_audit_sink(&config)?;
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
        Arc::clone(&ingest).spawn_refresh_tasks_with_config(&config, readiness_tx.clone());

    let dataset_count = config.datasets.len();
    // Operational startup log: a per-mode size hint. For `api_key` this
    // is the configured key count; for `oidc` it is 0 (the real signal
    // is the issuer URL, logged separately when the provider is wired).
    // Read off the config rather than the provider so the wiring layer
    // doesn't need a `len()` method on the trait.
    let auth_size_hint = match config.auth.mode {
        config::AuthMode::ApiKey => config.auth.api_keys.len(),
        config::AuthMode::Oidc => 0,
    };
    // Build provenance state from the parsed config.
    // `build_resolved_provenance_config` returns:
    //   * `Ok(None)` when the operator omitted the `provenance:` block
    //     or set `enabled: false`, leaving the binary unchanged and
    //     requiring no signing secrets.
    //   * `Ok(Some(_))` only when provenance is enabled and signer
    //     material has loaded successfully.
    let provenance_state: Option<Arc<ProvenanceState>> =
        build_resolved_provenance_config(config.provenance.as_ref())?
            .map(|resolved: ResolvedProvenanceConfig| Arc::new(ProvenanceState::new(resolved)));
    let publicschema_registry = build_publicschema_registry(&config)?.map(Arc::new);
    #[cfg(feature = "spdci-api-standards")]
    let spdci_response_mapper = build_spdci_response_mapper(&config)?.map(Arc::new);
    let provenance_state_for_log = provenance_state.as_ref().map(|state| {
        let cfg = state.config();
        (state.is_enabled(), cfg.mode, cfg.issuer_did.clone())
    });
    let metrics = RequestMetrics::shared();
    let mut app =
        registry_relay::server::build_app_with_entity_query_metadata_provenance_and_metrics(
            Arc::clone(&config),
            Arc::clone(&auth),
            Arc::clone(&audit_sink),
            readiness_rx.clone(),
            entity_registry,
            query,
            aggregate_query,
            compiled_metadata,
            provenance_state.clone(),
            Arc::clone(&metrics),
        )?;
    if let Some(publicschema_registry) = publicschema_registry {
        app = app.layer(axum::Extension(publicschema_registry));
    }
    #[cfg(feature = "spdci-api-standards")]
    if let Some(spdci_response_mapper) = spdci_response_mapper {
        app = app.layer(axum::Extension(spdci_response_mapper));
    }

    let listener = TcpListener::bind(bind).await.map_err(|err| {
        error!(error = %err, bind = %bind, "failed to bind listener");
        err
    })?;

    match provenance_state_for_log.as_ref() {
        Some((enabled, mode, issuer_did)) => {
            info!(
                bind = %bind,
                admin_bind = ?admin_bind,
                datasets = dataset_count,
                api_keys = auth_size_hint,
                audit_sink = audit_kind,
                provenance_enabled = *enabled,
                provenance_mode = ?mode,
                provenance_issuer_did = %issuer_did,
                "registry-relay listening"
            );
        }
        None => {
            info!(
                bind = %bind,
                admin_bind = ?admin_bind,
                datasets = dataset_count,
                api_keys = auth_size_hint,
                audit_sink = audit_kind,
                provenance_enabled = false,
                "registry-relay listening"
            );
        }
    }

    let admin_listener = match admin_bind {
        Some(addr) => Some(TcpListener::bind(addr).await.map_err(|err| {
            error!(error = %err, bind = %addr, "failed to bind admin listener");
            err
        })?),
        None => None,
    };

    let main_serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    // Run both servers concurrently. `tokio::select!` is the natural
    // fit because either listener exiting (clean or not) tears down
    // the other.
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
        if let Some(admin_listener) = admin_listener {
            let admin_app = registry_relay::server::build_admin_app_with_metrics(
                Arc::clone(&config),
                Arc::clone(&auth),
                Arc::clone(&audit_sink),
                readiness_rx.clone(),
                readiness_tx.clone(),
                Arc::clone(&ingest),
                Arc::clone(&metrics),
            )?;
            let admin_serve = axum::serve(
                admin_listener,
                admin_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
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
/// * the `REGISTRY_RELAY_CONFIG` env var
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
    if let Ok(p) = env::var("REGISTRY_RELAY_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(DEFAULT_CONFIG_PATH)
}

/// Build the configured authentication provider.
///
/// Returns an [`AuthProviderRef`] so the same call site serves both
/// the V1 API-key provider and future OIDC provider without further
/// branching at the wiring layer. Today only [`ApiKeyAuth`] is wired;
/// OIDC will land as an additional arm on [`config::AuthMode`].
///
/// The config validator (`crate::config::validate`) already enforced
/// that every `hash_env` is set and parses as a SHA-256 API key
/// fingerprint, so the only failures we expect here are TOCTOU env var
/// removals between validation and now. Those propagate as
/// `ConfigError::MissingSecret` so the binary exits with the same
/// stable code as the validator does.
///
/// The provider is immutable for the process lifetime. Key/JWKS
/// rotation is a restart operation unless a future provider adds live
/// reload.
async fn build_auth(config: &Config) -> Result<AuthProviderRef, Error> {
    match config.auth.mode {
        config::AuthMode::ApiKey => {
            let mut entries = Vec::with_capacity(config.auth.api_keys.len());
            for key in &config.auth.api_keys {
                let entry = build_api_key_entry(key)?;
                entries.push(entry);
            }
            Ok(Arc::new(ApiKeyAuth::new(entries)))
        }
        config::AuthMode::Oidc => {
            let oidc = config.auth.oidc.as_ref().ok_or_else(|| {
                tracing::error!(
                    code = "config.validation_error",
                    "auth.mode = oidc but no oidc block resolved"
                );
                Error::from(ConfigError::ValidationError)
            })?;
            build_oidc_auth(oidc).await
        }
    }
}

/// Build the [`OidcAuth`] provider from its config block.
///
/// Resolves the JWKS URL from `discovery_url` if set; otherwise uses
/// the explicit `jwks_url`. The discovery fetch happens once at startup
/// and is not retried: a failure here aborts the binary so an operator
/// sees the IdP wiring problem instead of a process that runs but
/// silently rejects every token. The JWKS document itself is fetched
/// lazily by the cache on first verify, so a transient JWKS outage at
/// boot does not block startup.
async fn build_oidc_auth(oidc: &OidcConfig) -> Result<AuthProviderRef, Error> {
    let fetcher = match (oidc.jwks_url.as_deref(), oidc.discovery_url.as_deref()) {
        (Some(jwks_url), None) => ReqwestJwksFetcher::from_jwks_url(jwks_url).map_err(|err| {
            tracing::error!(
                code = "config.validation_error",
                error = %err,
                "failed to build OIDC JWKS HTTP client"
            );
            Error::from(ConfigError::ValidationError)
        })?,
        (None, Some(discovery_url)) => {
            ReqwestJwksFetcher::from_discovery_url(discovery_url, &oidc.issuer)
                .await
                .map_err(|err| {
                    tracing::error!(
                        code = "config.validation_error",
                        error = %err,
                        "failed to resolve OIDC discovery document"
                    );
                    Error::from(ConfigError::ValidationError)
                })?
        }
        _ => {
            tracing::error!(
                code = "config.validation_error",
                "auth.oidc must declare exactly one of jwks_url or discovery_url"
            );
            return Err(Error::from(ConfigError::ValidationError));
        }
    };
    let jwks_url = fetcher.jwks_url().to_string();
    let provider = OidcAuth::new(oidc, Arc::new(fetcher));
    tracing::info!(
        issuer = %oidc.issuer,
        jwks_url = %jwks_url,
        algorithms = ?oidc.algorithms,
        "oidc auth provider wired"
    );
    Ok(Arc::new(provider))
}

/// Resolve one `ApiKeyConfig` into an `ApiKeyEntry`.
///
/// Pulls the fingerprint from the env var named by `hash_env`,
/// collects scopes into a `ScopeSet`, and validates the fingerprint via
/// `ApiKeyEntry::new` (which re-parses defensively even though the
/// config validator already accepted it).
fn build_api_key_entry(key: &ApiKeyConfig) -> Result<ApiKeyEntry, Error> {
    let fingerprint = env::var(&key.hash_env).map_err(|_| {
        tracing::error!(
            code = "config.missing_secret",
            api_key_id = %key.id,
            hash_env = %key.hash_env,
            "hash_env environment variable is not set at auth build time"
        );
        Error::from(ConfigError::MissingSecret)
    })?;
    let scopes: ScopeSet = key.scopes.iter().cloned().collect();
    ApiKeyEntry::new(key.id.clone(), scopes, fingerprint).map_err(|reason| {
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
fn build_audit_sink(config: &Config) -> Result<Arc<AuditPipeline>, Error> {
    let sink: Arc<dyn registry_platform_audit::AuditSink> = match &config.audit.sink {
        AuditSinkConfig::Stdout {} => Arc::new(StdoutSink::new()),
        AuditSinkConfig::File { path, rotate } => {
            match FileSink::new(path, rotate.max_size_mb, rotate.max_files) {
                Ok(sink) => Arc::new(sink),
                Err(err) => {
                    error!(
                        error = %err,
                        requested = "file",
                        path = %path.display(),
                        "configured audit file sink is unavailable"
                    );
                    return Err(Error::from(ConfigError::ValidationError));
                }
            }
        }
        AuditSinkConfig::Syslog {} => Arc::new(SyslogSink::new()),
        _ => {
            error!("unknown audit sink variant");
            return Err(Error::from(ConfigError::ValidationError));
        }
    };
    if !config.audit.chain {
        info!(
            "audit.chain is accepted for config compatibility; platform audit envelopes are always chained"
        );
    }
    Ok(Arc::new(AuditPipeline::new(sink)))
}

fn audit_sink_kind(config: &Config) -> &'static str {
    match &config.audit.sink {
        AuditSinkConfig::Stdout {} => "stdout",
        AuditSinkConfig::File { .. } => "file",
        AuditSinkConfig::Syslog {} => "syslog",
        _ => "unknown (fallback: stdout)",
    }
}

/// Initialise operational tracing on stderr. `RUST_LOG` controls the
/// filter and defaults to `info`. `REGISTRY_RELAY_LOG_FORMAT=json`
/// switches the default human-readable terminal output back to JSONL
/// for machine collection or redirected files.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match OperationalLogFormat::from_env() {
        OperationalLogFormat::Text => {
            let fmt_layer = fmt::layer()
                .compact()
                .with_target(false)
                .with_writer(std::io::stderr);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
        }
        OperationalLogFormat::Json => {
            let fmt_layer = fmt::layer().json().with_writer(std::io::stderr);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
        }
    }
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

#[cfg(test)]
mod tests {
    use super::OperationalLogFormat;

    #[test]
    fn operational_log_format_defaults_to_text_for_empty_or_unknown_values() {
        assert_eq!(OperationalLogFormat::parse(""), OperationalLogFormat::Text);
        assert_eq!(
            OperationalLogFormat::parse("text"),
            OperationalLogFormat::Text
        );
        assert_eq!(
            OperationalLogFormat::parse("compact"),
            OperationalLogFormat::Text
        );
        assert_eq!(
            OperationalLogFormat::parse("xml"),
            OperationalLogFormat::Text
        );
    }

    #[test]
    fn operational_log_format_accepts_json_aliases() {
        assert_eq!(
            OperationalLogFormat::parse("json"),
            OperationalLogFormat::Json
        );
        assert_eq!(
            OperationalLogFormat::parse(" JSONL "),
            OperationalLogFormat::Json
        );
    }
}
