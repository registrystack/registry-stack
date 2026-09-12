use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use clap::{Arg, Command};
use registry_casework_breg::BregBinding;
use registry_casework_core::{CaseworkProject, SourceAdapter};
use registry_platform_audit::{AuditEnvelope, AuditProfile, ChainState, JsonlFileSink};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Interval, MissedTickBehavior};
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
            Arg::new("runtime-config")
                .long("runtime-config")
                .value_name("FILE")
                .help("Absolute path to the runtime configuration file.")
                .required(true),
        )
        .subcommand_required(true)
        .subcommand(Command::new("migrate").about("Apply Casework database migrations"))
        .subcommand(Command::new("serve").about("Run the Casework HTTP service"))
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
    let project_path = config.policy_path();
    let project = CaseworkProject::load(&project_path)?;
    let secrets = secret_resolver(&config)?;
    let store = PostgresStore::connect_runtime(&config.database, &secrets)?;
    store.ready().await?;

    let project_root = config.package.root.as_path();
    let mut adapters: Vec<Arc<dyn SourceAdapter>> = Vec::new();
    for source in &project.sources {
        let binding = config
            .sources
            .get(&source.id)
            .ok_or_else(|| RuntimeError::SourceConfiguration(source.id.clone()))?;
        let adapter = binding
            .build_adapter(source, project_root, &secrets)
            .map_err(|_| RuntimeError::SourceConfiguration(source.id.clone()))?;
        store
            .register_source_generation(&source.id, adapter.binding_generation())
            .await?;
        adapters.push(Arc::new(adapter));
    }
    if config.sources.len() != adapters.len() {
        let unmatched = config
            .sources
            .keys()
            .find(|id| !project.sources.iter().any(|source| &&source.id == id))
            .cloned()
            .unwrap_or_default();
        return Err(RuntimeError::SourceConfiguration(unmatched));
    }

    let (verifier, keys) = config.oidc_verifier(&secrets).await?;
    let authenticator = Arc::new(CaseworkAuthenticator::new(
        &project,
        verifier,
        keys,
        config.authentication.oidc.human_identity.clone(),
    ));
    let service = CaseworkService::new(store.clone(), project.clone(), adapters)?;

    let audit_secret = resolve_audit_secret(&secrets, &config.audit.hash_key_ref)?;
    let audit_profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        audit_secret.expose_secret().to_vec(),
    ))
    .map_err(|_| RuntimeError::Audit)?;
    let audit_sink = Arc::new(
        JsonlFileSink::new_single_writer(&config.audit.path).map_err(|_| RuntimeError::Audit)?,
    );
    let audit_chain = Arc::new(
        audit_profile
            .bootstrap_or_start_empty(audit_sink.as_ref())
            .await
            .map_err(|_| RuntimeError::Audit)?,
    );
    // The keyed bootstrap above authenticates the retained chain before its
    // tail identity is used to reconcile a possible append/mark crash gap.
    let mut audit_publication_state = AuditPublicationState::from_verified_tail(
        audit_sink
            .last_envelope()
            .await
            .map_err(|_| RuntimeError::Audit)?
            .as_ref(),
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
                if let Err(error) = worker_service.erase_expired_absence_cursors().await {
                    tracing::warn!(error = %error, "Casework absence cursor retention pass did not complete");
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
    for (source_id, binding) in &config.sources {
        let reconciliation = service.clone();
        let source_id = source_id.clone();
        let interval_duration = reconciliation_interval(binding);
        workers.push(supervise(
            "source reconciliation",
            worker_stopped.clone(),
            async move {
                let mut interval = reconciliation_timer(interval_duration);
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
                publish_audit_pass(&audit_publisher, &mut audit_publication_state).await,
            );
        }
    }));

    let app = router(HttpState {
        service,
        authenticator,
        project: Arc::new(project),
    });
    let listener = tokio::net::TcpListener::bind(config.listener.bind)
        .await
        .map_err(RuntimeError::Listen)?;
    let served = serve_until_worker_stops(listener, app, worker_stops).await;
    for worker in workers {
        worker.abort();
    }
    served
}

/// The interval between reconciliation passes for one bound source, taken
/// directly from its operator-configured binding.
fn reconciliation_interval(binding: &BregBinding) -> Duration {
    Duration::from_millis(binding.reconciliation_interval_milliseconds)
}

fn reconciliation_timer(period: Duration) -> Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
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

/// Resolve the audit journal's keying secret, naming the reference on refusal.
///
/// The journal is keyed before the listener binds, so this refusal is the
/// first line an operator sees on a mis-provisioned deployment. It carries a
/// valid configured reference and the rule that broke, never the key bytes.
fn resolve_audit_secret(
    secrets: &SecretResolver,
    reference: &str,
) -> Result<registry_platform_config::ProtectedSecret, RuntimeError> {
    secrets.resolve(reference).map_err(|error| {
        RuntimeError::AuditSecret(crate::describe_secret_failure(
            "audit.hashKeyRef",
            reference,
            &error,
        ))
    })
}

pub fn secret_resolver(config: &RuntimeConfig) -> Result<SecretResolver, RuntimeError> {
    let mut providers = Vec::new();
    if config.secret_providers.file.is_some() {
        providers.push(SecretProvider::File);
    }
    if config.secret_providers.environment.is_some() {
        providers.push(SecretProvider::Environment);
    }
    SecretResolver::new(
        providers,
        config
            .secret_providers
            .file
            .as_ref()
            .map_or_else(|| Path::new(""), |file| file.root.as_path()),
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
    RecordIdentity,
    SinkAppend,
    PublishedMark,
}

impl AuditPublicationFailure {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PendingRead => "pending-read",
            Self::RecordIdentity => "record-identity",
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

#[derive(Default)]
struct AuditPublicationState {
    unconfirmed: Option<Uuid>,
}

impl AuditPublicationState {
    fn from_verified_tail(tail: Option<&AuditEnvelope>) -> Self {
        let unconfirmed = tail
            .and_then(|envelope| envelope.record.as_object())
            .and_then(|record| record.get("eventId"))
            .and_then(Value::as_str)
            .and_then(|event_id| Uuid::parse_str(event_id).ok());
        Self { unconfirmed }
    }
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
    state: &mut AuditPublicationState,
) -> Result<(), AuditPublicationFailure> {
    if let Some(event_id) = state.unconfirmed {
        publisher
            .mark_published(event_id)
            .await
            .map_err(|()| AuditPublicationFailure::PublishedMark)?;
        state.unconfirmed = None;
    }
    let records = publisher
        .pending(100)
        .await
        .map_err(|()| AuditPublicationFailure::PendingRead)?;
    for (event_id, record) in records {
        let record = audit_record_with_event_id(event_id, record)
            .map_err(|()| AuditPublicationFailure::RecordIdentity)?;
        publisher
            .append(record)
            .await
            .map_err(|()| AuditPublicationFailure::SinkAppend)?;
        state.unconfirmed = Some(event_id);
        publisher
            .mark_published(event_id)
            .await
            .map_err(|()| AuditPublicationFailure::PublishedMark)?;
        state.unconfirmed = None;
    }
    Ok(())
}

fn audit_record_with_event_id(event_id: Uuid, mut record: Value) -> Result<Value, ()> {
    let fields = record.as_object_mut().ok_or(())?;
    let event_id = event_id.to_string();
    match fields.get("eventId") {
        Some(Value::String(existing)) if existing == &event_id => {}
        Some(_) => return Err(()),
        None => {
            fields.insert("eventId".to_owned(), Value::String(event_id));
        }
    }
    Ok(record)
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

    #[cfg(unix)]
    #[test]
    fn a_refused_audit_secret_names_its_reference_and_the_rule_it_broke() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temporary secret root");
        std::fs::write(root.path().join("casework-audit-key"), b"key-material")
            .expect("write audit secret");
        std::fs::set_permissions(
            root.path().join("casework-audit-key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("set mode");
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).expect("resolver");

        let error = resolve_audit_secret(&secrets, "secret:file/casework-audit-key")
            .expect_err("a group-readable audit secret is refused");

        let message = error.to_string();
        assert!(
            message.contains("secret:file/casework-audit-key"),
            "the failure does not name the reference: {message}"
        );
        assert!(
            message.contains("0400 or 0600"),
            "the failure does not name the mode rule: {message}"
        );
        assert!(
            !message.contains("key-material"),
            "the failure echoes the resolved secret: {message}"
        );
    }

    #[test]
    fn a_literal_audit_secret_is_redacted_while_the_field_and_grammar_are_named() {
        let root = tempfile::tempdir().expect("temporary secret root");
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).expect("resolver");
        let literal_secret = "literal-audit-credential-canary";

        let error = resolve_audit_secret(&secrets, literal_secret)
            .expect_err("a literal credential is not a secret reference");

        let message = error.to_string();
        assert!(
            message.contains("audit.hashKeyRef")
                && message.contains("secret:env/NAME or secret:file/name"),
            "the failure does not name the field and reference grammar: {message}"
        );
        assert!(
            !message.contains(literal_secret),
            "the failure renders the literal credential: {message}"
        );
    }

    struct FakeAuditPublisher {
        state: Mutex<FakeAuditPublisherState>,
    }

    struct FakeAuditPublisherState {
        failure: Option<AuditPublicationFailure>,
        pending: Option<(Uuid, Value)>,
        pending_read_count: usize,
        append_count: usize,
    }

    impl FakeAuditPublisher {
        fn failing_at(failure: AuditPublicationFailure) -> Self {
            let record = if failure == AuditPublicationFailure::RecordIdentity {
                Value::Null
            } else {
                serde_json::json!({"synthetic": true})
            };
            Self {
                state: Mutex::new(FakeAuditPublisherState {
                    failure: Some(failure),
                    pending: Some((Uuid::new_v4(), record)),
                    pending_read_count: 0,
                    append_count: 0,
                }),
            }
        }

        async fn recover(&self) {
            let mut state = self.state.lock().await;
            if state.failure == Some(AuditPublicationFailure::RecordIdentity) {
                if let Some((_, record)) = state.pending.as_mut() {
                    *record = serde_json::json!({"synthetic": true});
                }
            }
            state.failure = None;
        }
    }

    struct FileAuditPublisher {
        database: Arc<Mutex<FileAuditState>>,
        chain: Arc<ChainState>,
        sink: Arc<JsonlFileSink>,
    }

    struct FileAuditState {
        fail_marks: bool,
        pending: Vec<(Uuid, Value)>,
    }

    #[async_trait]
    impl AuditPublicationBackend for FileAuditPublisher {
        async fn pending(&self, _maximum: i64) -> Result<Vec<(Uuid, Value)>, ()> {
            let state = self.database.lock().await;
            Ok(state.pending.clone())
        }

        async fn append(&self, record: Value) -> Result<(), ()> {
            self.chain
                .append(self.sink.as_ref(), record)
                .await
                .map(|_| ())
                .map_err(|_| ())
        }

        async fn mark_published(&self, event_id: Uuid) -> Result<(), ()> {
            let mut state = self.database.lock().await;
            if state.fail_marks {
                return Err(());
            }
            if let Some(index) = state
                .pending
                .iter()
                .position(|(pending_id, _)| *pending_id == event_id)
            {
                state.pending.remove(index);
            }
            Ok(())
        }
    }

    #[async_trait]
    impl AuditPublicationBackend for FakeAuditPublisher {
        async fn pending(&self, _maximum: i64) -> Result<Vec<(Uuid, Value)>, ()> {
            let mut state = self.state.lock().await;
            if state.failure == Some(AuditPublicationFailure::PendingRead) {
                return Err(());
            }
            state.pending_read_count += 1;
            Ok(state.pending.clone().into_iter().collect())
        }

        async fn append(&self, _record: Value) -> Result<(), ()> {
            let mut state = self.state.lock().await;
            if state.failure == Some(AuditPublicationFailure::SinkAppend) {
                return Err(());
            }
            state.append_count += 1;
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
            AuditPublicationFailure::RecordIdentity,
            AuditPublicationFailure::SinkAppend,
            AuditPublicationFailure::PublishedMark,
        ] {
            let publisher = FakeAuditPublisher::failing_at(failure);
            let health = AuditPublisherHealth::default();
            let mut failed_stage = None;
            let mut publication_state = AuditPublicationState::default();

            let failed = publish_audit_pass(&publisher, &mut publication_state).await;
            assert_eq!(failed, Err(failure));
            update_audit_health(&health, &mut failed_stage, failed);
            assert!(!health.is_ready());
            assert_eq!(failed_stage, Some(failure));

            if failure == AuditPublicationFailure::PublishedMark {
                assert_eq!(
                    publish_audit_pass(&publisher, &mut publication_state).await,
                    Err(AuditPublicationFailure::PublishedMark)
                );
                let state = publisher.state.lock().await;
                assert_eq!(state.append_count, 1);
                assert_eq!(state.pending_read_count, 1);
            }

            publisher.recover().await;
            let recovered = publish_audit_pass(&publisher, &mut publication_state).await;
            recovered.expect("recovered publication pass");
            update_audit_health(&health, &mut failed_stage, recovered);
            assert!(health.is_ready());
            assert_eq!(failed_stage, None);
            let state = publisher.state.lock().await;
            assert_eq!(state.append_count, 1);
        }
    }

    #[tokio::test]
    async fn audit_publication_reconciles_a_real_file_tail_after_restart() {
        let directory = tempfile::tempdir().expect("audit directory");
        let path = directory.path().join("casework.jsonl");
        let event_id =
            Uuid::parse_str("ffffffff-ffff-4fff-8fff-ffffffffffff").expect("high event id");
        let earlier_event_id =
            Uuid::parse_str("00000000-0000-4000-8000-000000000000").expect("low event id");
        let database = Arc::new(Mutex::new(FileAuditState {
            fail_marks: true,
            pending: vec![(event_id, serde_json::json!({"event":"casework.synthetic"}))],
        }));
        let profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
            b"casework-audit-restart-secret-32-bytes".to_vec(),
        ))
        .expect("audit profile");

        let sink = Arc::new(JsonlFileSink::new_single_writer(&path).expect("first writer lock"));
        let chain = Arc::new(
            profile
                .bootstrap_or_start_empty(sink.as_ref())
                .await
                .expect("first keyed bootstrap"),
        );
        let publisher = FileAuditPublisher {
            database: Arc::clone(&database),
            chain,
            sink: Arc::clone(&sink),
        };
        let mut publication_state = AuditPublicationState::default();

        assert_eq!(
            publish_audit_pass(&publisher, &mut publication_state).await,
            Err(AuditPublicationFailure::PublishedMark)
        );
        assert_eq!(publication_state.unconfirmed, Some(event_id));
        assert!(matches!(
            JsonlFileSink::new_single_writer(&path),
            Err(registry_platform_audit::AuditError::SinkLocked { .. })
        ));
        drop(publisher);
        drop(sink);

        {
            let mut database = database.lock().await;
            database.fail_marks = false;
            database.pending.insert(
                0,
                (
                    earlier_event_id,
                    serde_json::json!({"event":"casework.earlier"}),
                ),
            );
        }
        let sink = Arc::new(JsonlFileSink::new_single_writer(&path).expect("restart writer lock"));
        let chain = Arc::new(
            profile
                .bootstrap_or_start_empty(sink.as_ref())
                .await
                .expect("restart keyed bootstrap"),
        );
        let tail = sink.last_envelope().await.expect("verified file tail");
        let mut publication_state = AuditPublicationState::from_verified_tail(tail.as_ref());
        let publisher = FileAuditPublisher {
            database: Arc::clone(&database),
            chain,
            sink,
        };

        publish_audit_pass(&publisher, &mut publication_state)
            .await
            .expect("restart reconciles without append");
        assert_eq!(publication_state.unconfirmed, None);
        assert!(database.lock().await.pending.is_empty());
        let envelopes = std::fs::read_to_string(&path)
            .expect("audit journal")
            .lines()
            .map(|line| serde_json::from_str::<AuditEnvelope>(line).expect("audit envelope"))
            .collect::<Vec<_>>();
        assert_eq!(envelopes.len(), 2);
        assert_eq!(envelopes[0].record["eventId"], event_id.to_string());
        assert_eq!(envelopes[1].record["eventId"], earlier_event_id.to_string());
    }

    #[test]
    fn audit_publication_owns_and_checks_the_event_identity() {
        let event_id = Uuid::new_v4();
        let populated =
            audit_record_with_event_id(event_id, serde_json::json!({"event":"casework.synthetic"}))
                .expect("publisher adds the authoritative identity");
        assert_eq!(populated["eventId"], event_id.to_string());

        assert!(audit_record_with_event_id(
            event_id,
            serde_json::json!({"eventId":Uuid::new_v4()})
        )
        .is_err());
        assert!(audit_record_with_event_id(event_id, Value::Null).is_err());

        let legacy_tail = AuditEnvelope::new_with_hasher(
            serde_json::json!({"event":"casework.legacy"}),
            None,
            &registry_platform_audit::AuditChainHasher::unkeyed_dev_only(),
        )
        .expect("legacy envelope");
        assert_eq!(
            AuditPublicationState::from_verified_tail(Some(&legacy_tail)).unconfirmed,
            None
        );
    }

    fn breg_binding(reconciliation_interval_milliseconds: u64) -> BregBinding {
        BregBinding {
            base_url: "https://registry.example.test".into(),
            reader_profile: "casework-reader".into(),
            token_endpoint: "https://identity.example.test/token".into(),
            client_id_ref: "secret:file/client-id".into(),
            client_assertion_key_ref: "secret:file/client-key".into(),
            webhook_secret_ref: "secret:file/webhook".into(),
            event_source: "urn:registrystack:registry:professional:instance:pilot".into(),
            event_type: "casework-lifecycle-v1".into(),
            trusted_root_certificates_ref: None,
            request_timeout_milliseconds: 30_000,
            connect_timeout_milliseconds: 10_000,
            reconciliation_interval_milliseconds,
        }
    }

    #[test]
    fn reconciliation_interval_uses_the_bindings_configured_milliseconds() {
        assert_eq!(
            reconciliation_interval(&breg_binding(60_000)),
            Duration::from_secs(60)
        );
        assert_eq!(
            reconciliation_interval(&breg_binding(120_000)),
            Duration::from_millis(120_000)
        );
    }

    #[tokio::test]
    async fn reconciliation_skips_ticks_missed_during_a_slow_pass() {
        let interval = reconciliation_timer(Duration::from_secs(1));
        assert_eq!(interval.period(), Duration::from_secs(1));
        assert_eq!(interval.missed_tick_behavior(), MissedTickBehavior::Skip);
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
    #[error(
        "the Casework secret-provider configuration is invalid; \
         secretProviders.file.root must be an absolute path"
    )]
    SecretConfiguration,
    #[error("the Casework source binding for source {0} is invalid")]
    SourceConfiguration(String),
    #[error("the Casework audit journal could not be initialized")]
    Audit,
    #[error("the Casework audit journal could not be initialized: {0}")]
    AuditSecret(String),
    #[error(transparent)]
    Store(#[from] crate::StoreError),
    #[error(transparent)]
    Service(#[from] crate::ServiceError),
    #[error("the Casework listener failed")]
    Listen(#[source] std::io::Error),
    #[error("a Casework background worker stopped")]
    WorkerStopped,
}
