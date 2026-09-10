use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::{Arg, Command};
use registry_casework_core::{CaseworkProject, SourceAdapter};
use registry_platform_audit::{AuditProfile, JsonlFileSink};
use registry_platform_config::{SecretProvider, SecretResolver};
use thiserror::Error;

use crate::{
    router, CaseworkAuthenticator, CaseworkService, HttpState, PostgresStore, RuntimeConfig,
};

#[must_use]
pub fn command() -> Command {
    Command::new("casework")
        .version(registry_platform_buildinfo::DISPLAY_VERSION)
        .about("Run and maintain Registry Casework")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("FILE")
                .help("Operator configuration file.")
                .required(true),
        )
        .subcommand_required(true)
        .subcommand(Command::new("migrate").about("Apply Casework database migrations"))
        .subcommand(Command::new("serve").about("Run the Casework HTTP service"))
}

pub async fn run(matches: &clap::ArgMatches) -> Result<(), RuntimeError> {
    let path = matches
        .get_one::<String>("config")
        .ok_or(RuntimeError::Arguments)?;
    match matches.subcommand_name() {
        Some("migrate") => migrate_from_path(path).await,
        Some("serve") => serve_from_path(path).await,
        _ => Err(RuntimeError::Arguments),
    }
}

pub async fn migrate_from_path(path: impl AsRef<Path>) -> Result<(), RuntimeError> {
    let config = RuntimeConfig::load(path)?;
    let secrets = secret_resolver(&config)?;
    let store = PostgresStore::connect_migration(&config.database, &secrets)?;
    store.migrate().await?;
    Ok(())
}

pub async fn serve_from_path(path: impl AsRef<Path>) -> Result<(), RuntimeError> {
    let config = RuntimeConfig::load(path)?;
    let project = CaseworkProject::load(&config.project)?;
    let secrets = secret_resolver(&config)?;
    let store = PostgresStore::connect_runtime(&config.database, &secrets)?;
    store.ready().await?;

    let project_root = config.project.parent().unwrap_or_else(|| Path::new("."));
    let mut adapters: Vec<Arc<dyn SourceAdapter>> = Vec::new();
    for source in &project.sources {
        let binding = config
            .sources
            .get(&source.id)
            .ok_or(RuntimeError::SourceConfiguration)?;
        let adapter = binding
            .build_adapter(source, project_root, &secrets)
            .map_err(|_| RuntimeError::SourceConfiguration)?;
        store
            .register_source_generation(&source.id, adapter.binding_generation())
            .await?;
        adapters.push(Arc::new(adapter));
    }
    if config.sources.len() != adapters.len() {
        return Err(RuntimeError::SourceConfiguration);
    }

    let (verifier, keys) = config.oidc_verifier(&secrets).await?;
    let authenticator = Arc::new(CaseworkAuthenticator::new(
        &project,
        verifier,
        keys,
        config.authentication.oidc.human_identity.clone(),
    ));
    let service = CaseworkService::new(store.clone(), project.clone(), adapters)?;

    let audit_secret = secrets
        .resolve(&config.audit.secret_ref)
        .map_err(|_| RuntimeError::Audit)?;
    let audit_profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        audit_secret.expose_secret().to_vec(),
    ))
    .map_err(|_| RuntimeError::Audit)?;
    let audit_sink = Arc::new(JsonlFileSink::new(&config.audit.path));
    let audit_chain = Arc::new(
        audit_profile
            .bootstrap_or_start_empty(audit_sink.as_ref())
            .await
            .map_err(|_| RuntimeError::Audit)?,
    );

    let worker_service = service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            if let Err(error) = worker_service.synchronize_pending(100).await {
                tracing::warn!(error = %error, "Casework synchronization pass did not complete");
            }
        }
    });
    let source_ids = config.sources.keys().cloned().collect::<Vec<_>>();
    for source_id in source_ids {
        let reconciliation = service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(error) = reconciliation.reconcile_source(&source_id).await {
                    tracing::warn!(source_id, error = %error, "Casework reconciliation pass did not complete");
                }
            }
        });
    }
    let audit_store = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let Ok(records) = audit_store.pending_audit(100).await else {
                continue;
            };
            for (event_id, record) in records {
                if audit_chain
                    .append(audit_sink.as_ref(), record)
                    .await
                    .is_err()
                {
                    break;
                }
                if audit_store.mark_audit_published(event_id).await.is_err() {
                    break;
                }
            }
        }
    });

    let app = router(HttpState {
        service,
        authenticator,
        project: Arc::new(project),
    });
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(RuntimeError::Listen)?;
    axum::serve(listener, app)
        .await
        .map_err(RuntimeError::Listen)
}

pub fn secret_resolver(config: &RuntimeConfig) -> Result<SecretResolver, RuntimeError> {
    SecretResolver::new(
        [SecretProvider::Environment, SecretProvider::File],
        &config.secret_providers.file.root,
    )
    .map_err(|_| RuntimeError::SecretConfiguration)
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("the Casework command arguments are invalid")]
    Arguments,
    #[error(transparent)]
    Config(#[from] crate::RuntimeConfigError),
    #[error("the Casework project is invalid")]
    Project(#[from] registry_casework_core::ConfigLoadError),
    #[error("the Casework secret-provider configuration is invalid")]
    SecretConfiguration,
    #[error("the Casework source binding is invalid")]
    SourceConfiguration,
    #[error("the Casework audit journal could not be initialized")]
    Audit,
    #[error(transparent)]
    Store(#[from] crate::StoreError),
    #[error(transparent)]
    Service(#[from] crate::ServiceError),
    #[error("the Casework listener failed")]
    Listen(#[source] std::io::Error),
}
