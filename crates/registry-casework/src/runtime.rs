use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use clap::{Arg, Command};
use registry_casework_core::{CaseworkProject, SourceAdapter};
use registry_platform_audit::{AuditProfile, ChainState, JsonlFileSink};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uuid::Uuid;

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
    match config.policy_package_digest()? {
        Some(digest) => tracing::info!(
            policy_package_digest = %digest,
            "verified Casework policy package"
        ),
        None => tracing::info!("loading authored Casework policy for loopback development"),
    }
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

    let (worker_stopped, worker_stops) = mpsc::channel(WORKER_STOP_CAPACITY);
    let mut workers = Vec::new();
    let worker_service = service.clone();
    workers.push(supervise("maintenance", worker_stopped.clone(), async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        let mut retention_ticks = 0_u8;
        loop {
            interval.tick().await;
            if let Err(error) = worker_service.synchronize_pending(100).await {
                tracing::warn!(error = %error, "Casework synchronization pass did not complete");
            }
            if let Err(error) = worker_service.process_due_clocks(100).await {
                tracing::warn!(error = %error, "Casework clock pass did not complete");
            }
            retention_ticks = (retention_ticks + 1) % 30;
            if retention_ticks == 0 {
                if let Err(error) = worker_service.erase_expired_hosted().await {
                    tracing::warn!(error = %error, "Casework hosted retention pass did not complete");
                }
                if let Err(error) = worker_service.erase_expired_cursors().await {
                    tracing::warn!(error = %error, "Casework inbox cursor retention pass did not complete");
                }
                if let Err(error) = worker_service.erase_expired_assignment_cursors().await {
                    tracing::warn!(error = %error, "Casework assignment cursor retention pass did not complete");
                }
                if let Err(error) = worker_service
                    .erase_expired_directory_target_cursors()
                    .await
                {
                    tracing::warn!(error = %error, "Casework directory target cursor retention pass did not complete");
                }
                if let Err(error) = worker_service.erase_expired_source_history_cursors().await {
                    tracing::warn!(error = %error, "Casework source history cursor retention pass did not complete");
                }
                if let Err(error) = worker_service.reconcile_ineligible_assignments(100).await {
                    tracing::warn!(error = %error, "Casework assignment eligibility pass did not complete");
                }
                if let Err(error) = worker_service.erase_expired_clock_previews().await {
                    tracing::warn!(error = %error, "Casework clock preview retention pass did not complete");
                }
            }
        }
    }));
    let source_ids = config.sources.keys().cloned().collect::<Vec<_>>();
    for source_id in source_ids {
        let reconciliation = service.clone();
        workers.push(supervise(
            "source reconciliation",
            worker_stopped.clone(),
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    if let Err(error) = reconciliation.reconcile_source(&source_id).await {
                        tracing::warn!(source_id, error = %error, "Casework reconciliation pass did not complete");
                    }
                }
            },
        ));
    }
    let audit_publisher = RuntimeAuditPublisher {
        store,
        chain: audit_chain,
        sink: audit_sink,
    };
    let audit_health = service.audit_publisher_health();
    workers.push(supervise("audit publication", worker_stopped, async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut failed_stage = None;
        loop {
            interval.tick().await;
            update_audit_health(
                &audit_health,
                &mut failed_stage,
                publish_audit_pass(&audit_publisher).await,
            );
        }
    }));

    let app = router(HttpState {
        service,
        authenticator,
        project: Arc::new(project),
    });
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(RuntimeError::Listen)?;
    let served = serve_until_worker_stops(listener, app, worker_stops).await;
    for worker in workers {
        worker.abort();
    }
    served
}

/// Serve until a supervised background loop stops. The listener never stops on
/// its own, so a clean return means a worker stopped, and the process reports
/// that as a failure for whatever supervises it to restart.
async fn serve_until_worker_stops(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    stops: mpsc::Receiver<&'static str>,
) -> Result<(), RuntimeError> {
    axum::serve(listener, app)
        .with_graceful_shutdown(worker_stop(stops))
        .await
        .map_err(RuntimeError::Listen)?;
    Err(RuntimeError::WorkerStopped)
}

/// One slot per supervised loop, so a stopping worker never blocks on the
/// listener reading its report.
const WORKER_STOP_CAPACITY: usize = 16;

/// Run a background loop under a task that outlives it. The loops never return
/// on their own, so a supervised task that finishes carries a panic, and its
/// name travels to the listener.
fn supervise(
    name: &'static str,
    stopped: mpsc::Sender<&'static str>,
    worker: impl Future<Output = ()> + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        match tokio::spawn(worker).await {
            Ok(()) => tracing::error!(worker = name, "a Casework background worker returned"),
            Err(error) => {
                tracing::error!(worker = name, error = %error, "a Casework background worker panicked");
            }
        }
        if stopped.send(name).await.is_err() {
            tracing::debug!(worker = name, "the Casework listener had already stopped");
        }
    })
}

/// Resolve once a supervised background loop has stopped. A process whose
/// clocks no longer fire keeps neither its listener nor its readiness.
async fn worker_stop(mut stopped: mpsc::Receiver<&'static str>) {
    match stopped.recv().await {
        Some(worker) => tracing::error!(
            worker,
            "stopping the Casework listener after a background worker stopped"
        ),
        None => {
            tracing::error!("stopping the Casework listener after every background worker stopped")
        }
    }
}

pub fn secret_resolver(config: &RuntimeConfig) -> Result<SecretResolver, RuntimeError> {
    SecretResolver::new(
        [SecretProvider::Environment, SecretProvider::File],
        &config.secret_providers.file.root,
    )
    .map_err(|_| RuntimeError::SecretConfiguration)
}

struct RuntimeAuditPublisher {
    store: PostgresStore,
    chain: Arc<ChainState>,
    sink: Arc<JsonlFileSink>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditPublicationFailure {
    PendingRead,
    SinkAppend,
    PublishedMark,
}

impl AuditPublicationFailure {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PendingRead => "pending-read",
            Self::SinkAppend => "sink-append",
            Self::PublishedMark => "published-mark",
        }
    }
}

#[async_trait]
trait AuditPublicationBackend: Send + Sync {
    async fn pending(&self, maximum: i64) -> Result<Vec<(Uuid, Value)>, ()>;
    async fn append(&self, record: Value) -> Result<(), ()>;
    async fn mark_published(&self, event_id: Uuid) -> Result<(), ()>;
}

#[async_trait]
impl AuditPublicationBackend for RuntimeAuditPublisher {
    async fn pending(&self, maximum: i64) -> Result<Vec<(Uuid, Value)>, ()> {
        self.store.pending_audit(maximum).await.map_err(|_| ())
    }

    async fn append(&self, record: Value) -> Result<(), ()> {
        self.chain
            .append(self.sink.as_ref(), record)
            .await
            .map(|_| ())
            .map_err(|_| ())
    }

    async fn mark_published(&self, event_id: Uuid) -> Result<(), ()> {
        self.store
            .mark_audit_published(event_id)
            .await
            .map_err(|_| ())
    }
}

async fn publish_audit_pass(
    publisher: &impl AuditPublicationBackend,
) -> Result<(), AuditPublicationFailure> {
    let records = publisher
        .pending(100)
        .await
        .map_err(|()| AuditPublicationFailure::PendingRead)?;
    for (event_id, record) in records {
        publisher
            .append(record)
            .await
            .map_err(|()| AuditPublicationFailure::SinkAppend)?;
        publisher
            .mark_published(event_id)
            .await
            .map_err(|()| AuditPublicationFailure::PublishedMark)?;
    }
    Ok(())
}

fn update_audit_health(
    health: &crate::service::AuditPublisherHealth,
    failed_stage: &mut Option<AuditPublicationFailure>,
    result: Result<(), AuditPublicationFailure>,
) {
    match result {
        Ok(()) => {
            health.mark_recovered();
            if failed_stage.take().is_some() {
                tracing::info!("Casework audit publication recovered");
            }
        }
        Err(failure) => {
            health.mark_failed();
            if *failed_stage != Some(failure) {
                tracing::warn!(
                    stage = failure.as_str(),
                    "Casework audit publication pass did not complete"
                );
                *failed_stage = Some(failure);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::Mutex;

    use super::*;
    use crate::service::AuditPublisherHealth;

    struct FakeAuditPublisher {
        state: Mutex<FakeAuditPublisherState>,
    }

    struct FakeAuditPublisherState {
        failure: Option<AuditPublicationFailure>,
        pending: Option<(Uuid, Value)>,
    }

    impl FakeAuditPublisher {
        fn failing_at(failure: AuditPublicationFailure) -> Self {
            Self {
                state: Mutex::new(FakeAuditPublisherState {
                    failure: Some(failure),
                    pending: Some((Uuid::new_v4(), serde_json::json!({"synthetic": true}))),
                }),
            }
        }

        async fn recover(&self) {
            self.state.lock().await.failure = None;
        }
    }

    #[async_trait]
    impl AuditPublicationBackend for FakeAuditPublisher {
        async fn pending(&self, _maximum: i64) -> Result<Vec<(Uuid, Value)>, ()> {
            let state = self.state.lock().await;
            if state.failure == Some(AuditPublicationFailure::PendingRead) {
                return Err(());
            }
            Ok(state.pending.clone().into_iter().collect())
        }

        async fn append(&self, _record: Value) -> Result<(), ()> {
            let state = self.state.lock().await;
            if state.failure == Some(AuditPublicationFailure::SinkAppend) {
                return Err(());
            }
            Ok(())
        }

        async fn mark_published(&self, event_id: Uuid) -> Result<(), ()> {
            let mut state = self.state.lock().await;
            if state.failure == Some(AuditPublicationFailure::PublishedMark) {
                return Err(());
            }
            if state.pending.as_ref().map(|record| record.0) != Some(event_id) {
                return Err(());
            }
            state.pending = None;
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_panicking_background_worker_stops_the_listener() {
        let (stopped, mut stops) = mpsc::channel(2);
        supervise("clock", stopped.clone(), async {
            panic!("the clock worker panicked")
        })
        .await
        .expect("the supervisor outlives the worker panic");
        supervise("synchronization", stopped, async {})
            .await
            .expect("the supervisor outlives a worker that returns");
        assert_eq!(stops.recv().await, Some("clock"));
        tokio::time::timeout(Duration::from_secs(5), worker_stop(stops))
            .await
            .expect("the listener stops after a background worker stops");
    }

    #[tokio::test]
    async fn a_stopped_worker_ends_the_process_with_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local listener");
        let (stopped, stops) = mpsc::channel(1);
        stopped
            .send("clock")
            .await
            .expect("report a stopped worker");
        let served = tokio::time::timeout(
            Duration::from_secs(5),
            serve_until_worker_stops(listener, axum::Router::new(), stops),
        )
        .await
        .expect("the listener stops after a background worker stops");
        assert!(matches!(served, Err(RuntimeError::WorkerStopped)));
    }

    #[tokio::test]
    async fn audit_publication_failure_degrades_health_until_a_pass_recovers() {
        for failure in [
            AuditPublicationFailure::PendingRead,
            AuditPublicationFailure::SinkAppend,
            AuditPublicationFailure::PublishedMark,
        ] {
            let publisher = FakeAuditPublisher::failing_at(failure);
            let health = AuditPublisherHealth::default();
            let mut failed_stage = None;

            let failed = publish_audit_pass(&publisher).await;
            assert_eq!(failed, Err(failure));
            update_audit_health(&health, &mut failed_stage, failed);
            assert!(!health.is_ready());
            assert_eq!(failed_stage, Some(failure));

            publisher.recover().await;
            let recovered = publish_audit_pass(&publisher).await;
            recovered.expect("recovered publication pass");
            update_audit_health(&health, &mut failed_stage, recovered);
            assert!(health.is_ready());
            assert_eq!(failed_stage, None);
        }
    }
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
    #[error("a Casework background worker stopped")]
    WorkerStopped,
}
