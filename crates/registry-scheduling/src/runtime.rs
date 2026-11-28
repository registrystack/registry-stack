// SPDX-License-Identifier: Apache-2.0

//! Service assembly and the supervised background loops: `scheduling serve`
//! builds the store connection, the authenticator, the audit writer, and the
//! scheduling service, then runs the HTTP listener beside four workers: hold
//! expiry, reminder-intent dispatch, hook delivery, and retention sweeps.
//! A worker that dies stops the process rather than letting the runtime keep
//! selling capacity its clocks no longer guard.
//!
//! Reminder dispatch and declared appointment observers are the places the
//! runtime speaks to another system. Reminder dispatch renders due intents;
//! observer delivery sends canonical envelopes captured with the appointment
//! transaction and can never mutate Scheduling from a receiver's response.
//!
//! For reminders,
//! each due outbox intent is rendered as one shared hook envelope in canonical
//! JSON and POSTed with `content-type: application/json` to the
//! operator-configured URL for its purpose through the platform dispatch core.
//! Delivery attempts may repeat after a destination accepts an event whose
//! outcome the runtime cannot record; receivers deduplicate by the event's
//! stable identifier, and a signed delivery also carries a stable idempotency
//! key. The transport and notification bus remain external (INT-02). When no
//! destination is configured the outbox is the boundary: intents are recorded
//! and set aside as local, never pretended delivered.
//!
//! A cancellation or reschedule cancels the appointment's reminders no
//! attempt has started on inside its own transaction. A reminder a
//! dispatcher already holds is checked under its lease immediately before
//! the send and set aside when its appointment was cancelled or moved. A
//! cancel or reschedule that commits between that check and the send still
//! sends the stale reminder, and the receiver gets no ordering promise
//! across processes: that is inherent to at-least-once delivery.

use registry_platform_config::DeclaredPosture;
use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use clap::{Arg, Command};
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_config::{ProtectedSecret, SecretReference, SecretResolver};
use registry_platform_crypto::delivery_signature::{
    distinct_delivery_keys, sign, DeliveryKey, DeliveryKeys,
};
use registry_platform_dispatch::postgres::{DispatchOutcome, DispatchWorker, WorkerConfig};
use registry_platform_hooks::delivery::ActivatedUrlHookDestinations;
use registry_platform_hooks::{Causation, EnvelopeLimits, EventSubject, HookEnvelope};
use registry_platform_httputil::destination::{
    DataDestinationPolicy, DataDestinationRequest, DataDestinationRequestTemplate,
    DestinationAuthorizationTemplate, DestinationBodyTemplate, DestinationMethod,
    DestinationProfile, DestinationRequestError, FixedDestinationPolicy,
};
use registry_platform_oidc::task_grant::TaskGrantStatusRegistry;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Interval, MissedTickBehavior};

use crate::audit::SchedulingAudit;
use crate::auth::SchedulingAuthenticator;
use crate::config::{
    reminder_destination_origin_and_path, same_reminder_destination_origin,
    ReminderDestinationConfig, RuntimeConfig, RuntimeConfigError, TaskGrantStatus,
};
use crate::hooks::{
    invalid_delivery_key, repeated_delivery_key, repeated_rotation_key, ActivatedHooks,
    HookActivationError, HookRuntimeIdentity, CURRENT_KEY_MEMBER, PREVIOUS_KEY_MEMBER,
};
use crate::http::{metrics_router, router, HttpState};
use crate::metrics::{count_requests, Metrics, Worker};
use crate::service::SchedulingService;
use crate::store::{OutboxRow, PostgresStore, RoleMode, StoreError, SINGLE_ROLE_STATEMENT};

mod intents;

/// How often each background loop wakes. The intervals are fixed constants,
/// not configuration: they are internal mechanics of one deployment, not an
/// operator-tunable contract.
const WORKER_INTERVAL: Duration = Duration::from_secs(2);
/// Retention sweeps run every thirtieth maintenance tick.
const RETENTION_TICKS: u8 = 30;
/// How many holds one expiry pass may retire.
const HOLD_EXPIRY_BATCH: i64 = 100;
/// The most intents one test dispatch pass carries before it stops.
const INTENT_DRAIN_LIMIT: usize = 1024;
/// One rendered reminder event is bounded, as is the whole request.
const REMINDER_MAXIMUM_BODY_BYTES: usize = 16 * 1024;
const REMINDER_MAXIMUM_REQUEST_BYTES: usize = 32 * 1024;
const REMINDER_CONFIG_PATH: &str = "destinations.reminders";

#[must_use]
pub fn command() -> Command {
    Command::new("scheduling")
        .version(registry_platform_buildinfo::DISPLAY_VERSION)
        .about("Run and maintain Registry Scheduling")
        .arg(
            Arg::new("runtime-config")
                .long("runtime-config")
                .value_name("ABSOLUTE_FILE")
                .help("Runtime configuration file")
                .required(true),
        )
        .arg(
            Arg::new("posture")
                .long("posture")
                .global(true)
                .value_name("POSTURE")
                .help("Declared posture: development or production. Unset means production."),
        )
        .subcommand_required(true)
        .subcommand(Command::new("serve").about("Run the Scheduling HTTP service"))
}

pub async fn run(
    matches: &clap::ArgMatches,
    declared: DeclaredPosture,
) -> Result<(), RuntimeError> {
    let path = matches
        .get_one::<String>("runtime-config")
        .ok_or(RuntimeError::Arguments)?;
    match matches.subcommand_name() {
        Some("serve") => serve_from_path(path, declared).await,
        _ => Err(RuntimeError::Arguments),
    }
}

/// Name the provisioning or startup act a store failure happened in.
fn database_step(stage: &'static str) -> impl Fn(StoreError) -> RuntimeError {
    move |source| match source {
        StoreError::DatabaseTransport(error) => RuntimeError::DatabaseTransport(error),
        StoreError::PostureMismatch { message, action } => {
            RuntimeError::PostureMismatch { message, action }
        }
        source => RuntimeError::Database { stage, source },
    }
}

pub async fn serve_from_path(
    path: impl AsRef<Path>,
    declared: DeclaredPosture,
) -> Result<(), RuntimeError> {
    let path = path.as_ref();
    let config =
        RuntimeConfig::load(path, declared).map_err(
            |error| match crate::config::startup_report(path, &error, declared) {
                Some(report) => RuntimeError::ConfigurationRefused(report),
                None => RuntimeError::Config(error),
            },
        )?;
    config.posture_report().log_startup();
    let loaded = config.load_policy()?;
    let package_digest = loaded.package_digest;
    tracing::info!(package_digest = %package_digest, "verified Scheduling package");
    let policy = loaded.policy;
    let scheduling_id = policy.project.id.to_string();
    let policy_digest = policy.policy_digest();
    let secrets = secret_resolver(&config)?;
    let store =
        PostgresStore::connect_runtime(&config.database, &secrets, config.development_witness())
            .map_err(database_step("runtime database configuration"))?
            .with_busy_source_profiles(&config.authentication.oidc.busy_import_profiles);
    store
        .ready()
        .await
        .map_err(database_step("schema readiness check"))?;

    // The activation ledger names the package `schedulingctl apply` accepted
    // for this database. Startup serves only that package, on the database
    // the ledger recorded, and writes no activation state of its own.
    let active = store
        .check_active_package(&crate::store::ActivePackage {
            posture: declared.posture,
            database_id: config.database_id(),
            package_digest: &package_digest,
        })
        .await
        .map_err(database_step("activation check"))?;
    match store
        .effective_role_mode()
        .await
        .and_then(|mode| mode.ok_or(StoreError::Corrupt))
        .map_err(database_step("role mode check"))?
    {
        // A ledger that recorded split mode for a credential that can now
        // write it means a grant or a membership was added after the apply.
        // An object the runtime role owns or a schema CREATE privilege
        // survives a reapply, so it is named with the statement that removes
        // it rather than as drift the next apply's grants correct.
        RoleMode::Single if active.role_mode == RoleMode::Split => {
            let refusal = store
                .split_weakness()
                .await
                .map_err(database_step("role mode check"))?
                .unwrap_or(StoreError::RoleModeDrift);
            return Err(database_step("role mode check")(refusal));
        }
        RoleMode::Single => tracing::warn!(role_mode = "single", "{SINGLE_ROLE_STATEMENT}"),
        RoleMode::Split => {
            if let Some(refusal) = store
                .split_weakness()
                .await
                .map_err(database_step("role mode check"))?
            {
                return Err(database_step("role mode check")(refusal));
            }
            if let Some(refusal) = store
                .missing_runtime_grants()
                .await
                .map_err(database_step("role mode check"))?
            {
                return Err(database_step("role mode check")(refusal));
            }
            tracing::info!(
                role_mode = "split",
                "the runtime credential cannot write the Scheduling activation ledger"
            )
        }
    }

    // The accepted package's policy is the one apply published, under the
    // stored revision and the scheduling id apply adopted.
    let (stored_id, policy_revision, stored_digest) = store
        .scheduling_meta()
        .await
        .map_err(database_step("deployment identity read"))?;
    if stored_id != scheduling_id {
        return Err(RuntimeError::DeploymentIdentity);
    }
    if stored_digest != policy_digest {
        return Err(database_step("activation check")(StoreError::Corrupt));
    }
    let database_schema = store
        .schema_name()
        .await
        .map_err(database_step("hook schema discovery"))?;
    let hook_payload_retention =
        Duration::from_secs(u64::from(config.retention.hook_payload_retention_days) * 24 * 60 * 60);

    // Resolve and validate every destination, including its signing material,
    // before the listener binds.
    let hooks = ActivatedHooks::activate(
        &policy.hook_declarations(),
        &config.destinations.hooks,
        &secrets,
        HookRuntimeIdentity {
            posture: declared.posture,
            database_id: config.database_id().to_owned(),
            package_digest: package_digest.clone(),
            scheduling_id: scheduling_id.clone(),
            policy_revision,
            policy_digest: policy_digest.clone(),
        },
        database_schema,
        hook_payload_retention,
    )?;

    let reminders = activate_reminder_delivery(
        config.destinations.reminders.as_ref(),
        hooks.destination_bindings(),
        &secrets,
    )
    .map_err(RuntimeError::Destination)?;

    // The audit destination is keyed and opened before the listener binds,
    // so a mis-provisioned deployment never serves a request it cannot hold
    // to account.
    let (audit_hasher, audit) = open_audit(&config, &secrets, None).await?;

    // Prove that every retained event can still use the exact destination
    // binding captured for it. A deployment may retain extra explicit
    // bindings while old deliveries drain.
    let hook_delivery = hooks.delivery_service(store.clone(), audit.clone());
    hook_delivery
        .verify_retained_bindings()
        .await
        .map_err(|_| RuntimeError::HookDelivery)?;

    let (verifier, keys) = config.oidc_verifier(&secrets).await?;
    let peer_policy = match declared.posture {
        registry_platform_config::Posture::Production => {
            registry_platform_httputil::PeerPolicy::RefuseDevelopmentPeer
        }
        registry_platform_config::Posture::Development => {
            registry_platform_httputil::PeerPolicy::AcceptDevelopmentPeer
        }
    };
    let authenticator = Arc::new(
        SchedulingAuthenticator::new(&config.authentication.oidc, verifier, keys)
            .with_peer_policy(peer_policy),
    );

    // A deployment that lists status authorities resolves every commitment
    // through that exact registry. An unlisted source therefore fails closed
    // instead of falling back to the short-lived offline path, which only
    // `unchecked-final-fifteen-minutes` selects. Loading refuses a file that
    // states neither, so an absent member is never read as the offline path.
    let task_grant_status = match &config.task_grant_status {
        Some(TaskGrantStatus::UncheckedFinalFifteenMinutes) => None,
        Some(TaskGrantStatus::Authorities(authorities)) => Some(Arc::new(
            TaskGrantStatusRegistry::activate(
                &crate::config::task_grant_status_endpoints(authorities),
                &config.authentication.oidc.provider.audience,
                &secrets,
                peer_policy,
            )
            .map_err(|_| RuntimeError::TaskGrantStatus)?,
        )),
        None => return Err(RuntimeError::TaskGrantStatus),
    };

    let service = Arc::new(
        SchedulingService::new(
            store.clone(),
            policy,
            scheduling_id.clone(),
            policy_revision,
            policy_digest,
            audit_hasher,
            audit,
            config.retention.receipt_retention_days,
        )
        .with_hooks(hooks)
        .with_task_grant_status(task_grant_status),
    );

    let (worker_stopped, worker_stops) = mpsc::channel(WORKER_STOP_CAPACITY);
    let mut workers = Vec::new();
    let metrics = Arc::new(Metrics::default().with_refusals(Arc::clone(authenticator.refusals())));

    let expiry_store = store.clone();
    let expiry_metrics = Arc::clone(&metrics);
    workers.push(supervise(
        "hold expiry",
        worker_stopped.clone(),
        async move {
            let mut interval = worker_timer();
            loop {
                interval.tick().await;
                let now = expiry_store.observed_now();
                match expiry_store.expire_due_holds(now, HOLD_EXPIRY_BATCH).await {
                    Ok(expired) => {
                        expiry_metrics.record_worker_success(Worker::HoldExpiry);
                        if expired > 0 {
                            tracing::info!(
                                expired,
                                "Scheduling hold expiry pass retired due holds"
                            );
                        }
                    }
                    Err(error) => tracing::warn!(
                        error = %error,
                        "Scheduling hold expiry pass did not complete"
                    ),
                }
            }
        },
    ));

    // One lane, so each intent is leased and sent in turn, as the outbox
    // was always drained.
    let intent_dispatcher = intents::intent_dispatcher(store.clone())
        .await
        .map_err(database_step("delivery intent dispatcher"))?;
    let intent_worker = DispatchWorker::new(
        intent_dispatcher.clone(),
        Arc::new(intents::IntentTransport::new(
            intent_dispatcher,
            scheduling_id.clone(),
            reminders.map(Arc::new),
        )),
        WorkerConfig {
            concurrency: NonZeroUsize::MIN,
            idle_poll: WORKER_INTERVAL,
        },
    );
    let (intent_shutdown, intent_shutdown_rx) = tokio::sync::watch::channel(false);
    workers.push(supervise(
        "reminder dispatch",
        worker_stopped.clone(),
        async move {
            // Keep the sender for the lifetime of the supervised worker. Runtime
            // shutdown aborts this future and releases the dispatch loop.
            let _keepalive = intent_shutdown;
            intent_worker.run(intent_shutdown_rx).await;
        },
    ));

    let (hook_shutdown, hook_shutdown_rx) = tokio::sync::watch::channel(false);
    workers.push(supervise(
        "hook delivery",
        worker_stopped.clone(),
        async move {
            // Keep the sender for the lifetime of the supervised worker. Runtime
            // shutdown aborts this future and releases the shared delivery loop.
            let _keepalive = hook_shutdown;
            hook_delivery.worker().run(hook_shutdown_rx).await;
        },
    ));

    // Receipt, cursor and owner retention have separate clocks. Claim rows,
    // history and the audit journal remain intact; terminal dispatch metadata
    // uses the receipt period and preserves active/replayable work.
    let claim_owner_retention_days = config.retention.claim_owner_retention_days;
    let receipt_retention_days = config.retention.receipt_retention_days;
    let retention_store = store.clone();
    let retention_metrics = Arc::clone(&metrics);
    workers.push(supervise("retention", worker_stopped, async move {
        let mut interval = worker_timer();
        let mut ticks = 0_u8;
        loop {
            interval.tick().await;
            ticks = (ticks + 1) % RETENTION_TICKS;
            if ticks != 0 {
                continue;
            }
            let now = retention_store.observed_now();
            let mut completed = true;
            if let Err(error) = retention_store.erase_expired_cursors(now).await {
                completed = false;
                tracing::warn!(error = %error, "Scheduling cursor retention pass did not complete");
            }
            if let Err(error) = retention_store
                .erase_expired_claim_owners(now, claim_owner_retention_days)
                .await
            {
                completed = false;
                tracing::warn!(error = %error, "Scheduling claim owner retention pass did not complete");
            }
            if let Err(error) = retention_store.erase_terminal_dispatch(now, receipt_retention_days).await {
                completed = false;
                tracing::warn!(error = %error, "Scheduling terminal dispatch retention pass did not complete");
            }
            if let Err(error) = retention_store.erase_expired_attempts(now).await {
                completed = false;
                tracing::warn!(
                    error = %error,
                    "Scheduling attempt receipt retention pass did not complete"
                );
            }
            if completed {
                retention_metrics.record_worker_success(Worker::Retention);
            }
        }
    }));

    let app = router(HttpState {
        posture: config.posture_report().clone(),
        service,
        authenticator,
    })
    .layer(axum::middleware::from_fn_with_state(
        Arc::clone(&metrics),
        count_requests,
    ));
    let listener = tokio::net::TcpListener::bind(config.listener.bind.socket_addr()).await?;
    // Both sockets bind before either serves, so a metrics address already in
    // use refuses startup rather than leaving a runtime nobody can scrape.
    let metrics_listener = match &config.metrics_listener {
        Some(metrics_listener) => Some((
            tokio::net::TcpListener::bind(metrics_listener.bind.socket_addr()).await?,
            metrics_router(metrics, store.clone(), config.posture_report().posture()),
        )),
        None => None,
    };
    tracing::info!(
        metrics_listener = metrics_listener.is_some(),
        "Scheduling listeners bound"
    );
    let served = serve_until_worker_stops(listener, app, metrics_listener, worker_stops).await;
    for worker in workers {
        worker.abort();
    }
    served
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("{}: {}\n  next: {}", .0.code(), .0, .0.suggested_action())]
    DatabaseTransport(registry_platform_config::DatabaseTransportError),
    #[error("{}: {message}\n  next: {action}", crate::store::POSTURE_MISMATCH)]
    PostureMismatch {
        message: &'static str,
        action: &'static str,
    },
    #[error("the scheduling command arguments are invalid")]
    Arguments,
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),
    /// The runtime file or its packaged policy refused at startup, with
    /// every finding at its position in the file.
    #[error("the Scheduling runtime configuration was refused")]
    ConfigurationRefused(registry_platform_yaml::Report),
    #[error("the Scheduling secret configuration is invalid")]
    SecretConfiguration,
    #[error("the Scheduling audit key could not be derived")]
    Audit,
    #[error("{0}")]
    AuditSecret(String),
    #[error("the Scheduling audit destination is unavailable: {0}")]
    AuditDestination(String),
    /// A database step of provisioning or startup failed. The step is named
    /// because a bare store error says the database refused and not which
    /// act it refused, and the acts have different remedies: an unreachable
    /// server, a database nobody migrated, an identity nobody adopted, and a
    /// policy that cannot be published are four different operator tasks.
    #[error("the Scheduling {stage} failed: {source}")]
    Database {
        stage: &'static str,
        #[source]
        source: StoreError,
    },
    #[error("the Scheduling listener could not bind or serve")]
    Listen(#[from] std::io::Error),
    #[error("the Scheduling reminder destination is invalid: {0}")]
    Destination(String),
    #[error("the Scheduling task-grant status configuration is invalid")]
    TaskGrantStatus,
    #[error(transparent)]
    HookActivation(#[from] HookActivationError),
    #[error("the Scheduling retained hook delivery bindings are unavailable")]
    HookDelivery,
    #[error("a Scheduling background worker stopped")]
    WorkerStopped,
    #[error("the deployment's scheduling id does not match the authored policy")]
    DeploymentIdentity,
    #[error("a due reminder intent could not be rendered as an event")]
    ReminderEvent,
}

impl RuntimeError {
    /// The reader's report when startup refused the runtime file or the
    /// packaged policy, so `scheduling` prints its CFG-DIAG-2 lines
    /// unchanged after its own one-sentence refusal.
    #[must_use]
    pub fn configuration_report(&self) -> Option<&registry_platform_yaml::Report> {
        match self {
            Self::ConfigurationRefused(report)
            | Self::Config(RuntimeConfigError::Policy(report)) => Some(report),
            _ => None,
        }
    }
}

/// Serve until a supervised background loop stops. The listener never stops on
/// its own, so a clean return means a worker stopped, and the process reports
/// that as a failure for whatever supervises it to restart.
async fn serve_until_worker_stops(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    metrics: Option<(tokio::net::TcpListener, axum::Router)>,
    stops: mpsc::Receiver<&'static str>,
) -> Result<(), RuntimeError> {
    let (stopped, mut metrics_stop) = tokio::sync::watch::channel(());
    let metrics = metrics.map(|(listener, app)| {
        tokio::spawn(async move {
            // A listener that fails while the runtime serves is reported when
            // it fails, not at shutdown. The API listener keeps serving.
            if let Err(error) = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = metrics_stop.changed().await;
                })
                .await
            {
                tracing::error!(error = %error, "the Scheduling metrics listener failed");
            }
        })
    });
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(worker_stop(stops))
        .await;
    drop(stopped);
    if let Some(metrics) = metrics {
        if let Err(error) = metrics.await {
            tracing::error!(error = %error, "the Scheduling metrics listener stopped unexpectedly");
        }
    }
    served?;
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
            Ok(()) => tracing::error!(worker = name, "a Scheduling background worker returned"),
            Err(error) => {
                tracing::error!(worker = name, error = %error, "a Scheduling background worker panicked");
            }
        }
        if stopped.send(name).await.is_err() {
            tracing::debug!(worker = name, "the Scheduling listener had already stopped");
        }
    })
}

/// Resolve once a supervised background loop has stopped. A process whose
/// clocks no longer fire keeps neither its listener nor its readiness.
async fn worker_stop(mut stopped: mpsc::Receiver<&'static str>) {
    match stopped.recv().await {
        Some(worker) => tracing::error!(
            worker,
            "stopping the Scheduling listener after a background worker stopped"
        ),
        None => {
            tracing::error!(
                "stopping the Scheduling listener after every background worker stopped"
            )
        }
    }
}

fn worker_timer() -> Interval {
    let mut interval = tokio::time::interval(WORKER_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
}

/// Derive the identifier-hash key and open the audit destination: the
/// runtime's own, or the sibling `process` names beside it for a companion
/// command, which never shares the runtime's single-writer file.
pub async fn open_audit(
    config: &RuntimeConfig,
    secrets: &SecretResolver,
    process: Option<&str>,
) -> Result<(registry_platform_audit::AuditKeyHasher, SchedulingAudit), RuntimeError> {
    let audit_secret = resolve_audit_secret(secrets, config.audit.key.hash_key_ref.as_str())?;
    let audit_profile =
        AuditProfile::production_from_secret_bytes(audit_secret.expose_secret().to_vec().into())
            .map_err(|_| RuntimeError::Audit)?;
    let mut destination = config
        .audit
        .destination()
        .map_err(|error| RuntimeError::AuditDestination(error.to_string()))?;
    if let Some(process) = process {
        destination = destination
            .for_process(process)
            .map_err(|error| RuntimeError::AuditDestination(error.to_string()))?;
    }
    let writer = AuditWriter::open(destination, config.posture_report().posture())
        .await
        .map_err(|error| RuntimeError::AuditDestination(error.operator_description()))?;
    Ok((audit_profile.key_hasher(), SchedulingAudit::new(writer)))
}

/// Resolve the audit key, naming the reference on refusal.
/// The audit destination is keyed before the listener binds, so this refusal is the
/// first line an operator sees on a mis-provisioned deployment. It carries a
/// valid configured reference and the rule that broke, never the key bytes.
fn resolve_audit_secret(
    secrets: &SecretResolver,
    reference: &str,
) -> Result<ProtectedSecret, RuntimeError> {
    secrets.resolve(reference).map_err(|error| {
        RuntimeError::AuditSecret(crate::config::describe_secret_failure(
            "audit.hashKeyRef",
            reference,
            &error,
        ))
    })
}

pub fn secret_resolver(config: &RuntimeConfig) -> Result<SecretResolver, RuntimeError> {
    config
        .secret_providers
        .resolver()
        .map_err(|_| RuntimeError::SecretConfiguration)
}

// ---------------------------------------------------------------------------
// Reminder dispatch
// ---------------------------------------------------------------------------

/// The frozen outbound transport for due reminder intents: one fixed origin
/// and a signed request template and key set per configured destination.
///
/// Public, with its fields kept private, so the database suite can point a
/// dispatch pass at a local destination it controls. What the deployment
/// sends, and how it reads each answer back, is only observable against a
/// destination that answers.
pub struct ReminderTransport {
    policy: DataDestinationPolicy,
    fallback: ReminderRequestTarget,
    purposes: BTreeMap<&'static str, ReminderRequestTarget>,
}

struct ReminderRequestTarget {
    template: DataDestinationRequestTemplate,
    keys: DeliveryKeys,
}

impl ReminderRequestTarget {
    fn render(
        &self,
        event: RenderedReminderEvent,
        attempt_started_at: SystemTime,
    ) -> Result<DataDestinationRequest, DestinationRequestError> {
        let timestamp = attempt_started_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| DestinationRequestError::InvalidHeaderValue)?
            .as_secs();
        let signature = sign(&self.keys, &event.id, timestamp, &event.body)
            .map_err(|_| DestinationRequestError::InvalidHeaderValue)?;
        self.template.render(
            &[],
            &[
                b"application/json",
                b"application/json",
                event.id.as_bytes(),
                timestamp.to_string().as_bytes(),
                signature.as_bytes(),
            ],
            None,
            Some(event.body),
        )
    }
}

impl ReminderTransport {
    fn target_for_purpose(&self, purpose: &str) -> Option<&ReminderRequestTarget> {
        match purpose {
            "confirmation" | "change" | "cancellation" | "reminder" => {
                Some(self.purposes.get(purpose).unwrap_or(&self.fallback))
            }
            _ => None,
        }
    }
}

fn resolve_delivery_key(
    secrets: &SecretResolver,
    path: &str,
    reference: &SecretReference,
) -> Result<DeliveryKey, String> {
    let secret = secrets
        .resolve_binary_reference(reference)
        .map_err(|error| {
            format!(
                "{path} could not be resolved: {error}. {}",
                error.suggested_action()
            )
        })?;
    let bytes = secret.expose_secret();
    DeliveryKey::new(bytes)
        .map_err(|error| invalid_delivery_key(path, bytes.len(), bytes.ends_with(b"\n"), error))
}

fn key_members(keys: &DeliveryKeys) -> impl Iterator<Item = (&'static str, &DeliveryKey)> {
    std::iter::once((CURRENT_KEY_MEMBER, keys.current()))
        .chain(keys.previous().map(|key| (PREVIOUS_KEY_MEMBER, key)))
}

fn check_delivery_keys(
    reminders: &ReminderTransport,
    hooks: &ActivatedUrlHookDestinations,
) -> Result<(), String> {
    let keys = key_members(&reminders.fallback.keys)
        .map(|(member, key)| (format!("{REMINDER_CONFIG_PATH}.{member}"), key))
        .chain(reminders.purposes.iter().flat_map(|(purpose, target)| {
            key_members(&target.keys).map(move |(member, key)| {
                (
                    format!("{REMINDER_CONFIG_PATH}.purposes.{purpose}.{member}"),
                    key,
                )
            })
        }))
        .chain(hooks.bindings.iter().flat_map(|(id, destination)| {
            key_members(destination.keys())
                .map(move |(member, key)| (format!("destinations.hooks.{id}.{member}"), key))
        }))
        .collect::<Vec<_>>();
    distinct_delivery_keys(keys.iter().map(|(path, key)| (path.as_str(), *key)))
        .map_err(|error| repeated_delivery_key(error.first(), error.second()))
}

/// Activate the reminder transport and refuse any key reused among reminders
/// and the already activated observer destinations.
///
/// # Errors
/// Returns the configuration paths and operator action without key values.
pub fn activate_reminder_delivery(
    destination: Option<&ReminderDestinationConfig>,
    hooks: &ActivatedUrlHookDestinations,
    secrets: &SecretResolver,
) -> Result<Option<ReminderTransport>, String> {
    let Some(destination) = destination else {
        return Ok(None);
    };
    let transport = reminder_transport(destination, secrets)?;
    check_delivery_keys(&transport, hooks)?;
    Ok(Some(transport))
}

/// Compile the fallback and every configured purpose destination into the
/// frozen transport the dispatch loop sends through.
///
/// # Errors
/// Returns the operator-facing refusal for a destination that cannot activate.
pub fn reminder_transport(
    destination: &ReminderDestinationConfig,
    secrets: &SecretResolver,
) -> Result<ReminderTransport, String> {
    let (origin, _) = reminder_destination_origin_and_path(&destination.url)
        .ok_or_else(|| "destinations.reminders.url is not a safe destination URL".to_owned())?;
    let profile = if origin.starts_with("https://") {
        DestinationProfile::ProductionHttps
    } else {
        DestinationProfile::LoopbackHttp
    };
    let policy = FixedDestinationPolicy::new("scheduling-reminders", &origin, profile, &[])
        .map_err(|_| "the destination could not be frozen as a fixed origin".to_owned())?;
    let compile_target = |config_path: &str,
                          url: &str,
                          reference: &SecretReference,
                          previous: Option<&SecretReference>| {
        let (_, path) = reminder_destination_origin_and_path(url)
            .ok_or_else(|| format!("{config_path}.url is not a safe destination URL"))?;
        if !same_reminder_destination_origin(&destination.url, url) {
            return Err(format!(
                "{config_path}.url must use the fallback URL origin"
            ));
        }
        let current_path = format!("{config_path}.{CURRENT_KEY_MEMBER}");
        let previous_path = format!("{config_path}.{PREVIOUS_KEY_MEMBER}");
        let current = resolve_delivery_key(secrets, &current_path, reference)?;
        let previous = previous
            .map(|reference| resolve_delivery_key(secrets, &previous_path, reference))
            .transpose()?;
        let keys = DeliveryKeys::new(current, previous)
            .map_err(|_| repeated_rotation_key(&previous_path, &current_path))?;
        let template = DataDestinationRequestTemplate::new(
            DestinationMethod::ReviewedReadOnlyPost,
            &path,
            &[],
            &[
                ("accept", 16),
                ("content-type", 16),
                ("webhook-id", 256),
                ("webhook-timestamp", 20),
                ("webhook-signature", 256),
            ],
            DestinationAuthorizationTemplate::Forbidden,
            DestinationBodyTemplate::Required {
                max_bytes: REMINDER_MAXIMUM_BODY_BYTES,
            },
            REMINDER_MAXIMUM_REQUEST_BYTES,
        )
        .map_err(|error| {
            format!("{config_path}.url could not be compiled as a signed reminder request: {error}")
        })?;
        Ok(ReminderRequestTarget { template, keys })
    };
    let fallback = compile_target(
        REMINDER_CONFIG_PATH,
        &destination.url,
        &destination.hmac_sha256_key_ref,
        destination.previous_hmac_sha256_key_ref.as_ref(),
    )?;
    let purposes = destination
        .purposes
        .iter()
        .map(|(purpose, entry)| {
            compile_target(
                &format!("{REMINDER_CONFIG_PATH}.purposes.{purpose}"),
                &entry.url,
                &entry.hmac_sha256_key_ref,
                entry.previous_hmac_sha256_key_ref.as_ref(),
            )
            .map(|target| (purpose, target))
        })
        .collect::<Result<_, _>>()?;
    Ok(ReminderTransport {
        policy,
        fallback,
        purposes,
    })
}

/// Render one due intent as the shared hook envelope in canonical JSON, the
/// same envelope an observer delivery carries: the intent's own id, the
/// deployment it came from, the purpose it was minted under, the instant it
/// fell due, the appointment and revision it concerns, and the payload the
/// runtime committed.
struct RenderedReminderEvent {
    id: String,
    body: Vec<u8>,
}

fn reminder_event(
    scheduling_id: &str,
    row: &OutboxRow,
) -> Result<RenderedReminderEvent, RuntimeError> {
    let id = row.outbox_id.to_string();
    let envelope = HookEnvelope {
        id: id.clone(),
        event_type: format!("org.registrystack.scheduling.{}", row.purpose),
        source: format!("urn:registrystack:scheduling:{scheduling_id}"),
        time: SystemTime::from(row.due_at).into(),
        subject: EventSubject::record(
            format!("/v1/appointments/{}", row.claim_id),
            row.appointment_revision,
        ),
        dataschema: format!("urn:registrystack:scheduling:reminder-data:{}", row.purpose),
        data: row.payload.clone(),
        causation: Causation::root(&id),
    };
    let body = envelope
        .to_canonical_bytes(&EnvelopeLimits::tightened_to(REMINDER_MAXIMUM_BODY_BYTES))
        .map_err(|_| RuntimeError::ReminderEvent)?;
    Ok(RenderedReminderEvent {
        id: envelope.id,
        body,
    })
}

/// How one dispatch attempt's outcome is held, before it is written back.
enum Delivery {
    /// The destination took the event.
    Delivered,
    /// The attempt proved nothing either way: try again after a backoff.
    Transient,
    /// The destination refused the event outright: hold it for the operator
    /// instead of retrying a refusal forever.
    Refused,
}

fn delivery_of(status: u16) -> Delivery {
    match status {
        200..=299 => Delivery::Delivered,
        408 | 429 | 500..=599 => Delivery::Transient,
        _ => Delivery::Refused,
    }
}

/// Carry every due intent through one dispatch attempt, one at a time,
/// until none is due. A transport failure proves nothing and schedules a
/// retry on the frozen schedule; a refusal outside the retry classes, a
/// payload that cannot become an event, and an exhausted attempt budget set
/// the intent aside as failed for the operator; with no destination
/// configured the intent is set aside as local: recorded, never pretended
/// delivered. A claimed reminder whose appointment was cancelled or moved to
/// a newer revision is set aside without a send.
///
/// The runtime runs the same dispatch as a supervised worker; this pass is
/// the bounded form the database suite drives.
/// When a destination accepts a send but its outcome is unrecorded, lease
/// recovery counts an uncertain attempt and schedules a retry. Receivers
/// deduplicate repeated events by their stable envelope identifier.
///
/// # Errors
///
/// Returns the store failure that stopped the pass. A destination's answer,
/// whatever it is, is an outcome written back and not an error.
pub async fn dispatch_due_intents(
    store: &PostgresStore,
    scheduling_id: &str,
    transport: Option<Arc<ReminderTransport>>,
) -> Result<(), StoreError> {
    let dispatcher = intents::intent_dispatcher(store.clone()).await?;
    let transport =
        intents::IntentTransport::new(dispatcher.clone(), scheduling_id.to_owned(), transport);
    for _ in 0..INTENT_DRAIN_LIMIT {
        match dispatcher.dispatch_once(&transport).await {
            Ok(DispatchOutcome::Idle) => return Ok(()),
            Ok(_) => {}
            Err(_) => return Err(StoreError::IntentDispatch),
        }
    }
    Ok(())
}

/// One leased delivery intent, held by a test between its claim and its
/// finish.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub struct IntentLeaseForTest(registry_platform_dispatch::postgres::LeasedJob<OutboxRow>);

#[cfg(feature = "postgres-test")]
impl IntentLeaseForTest {
    #[must_use]
    pub fn outbox_id(&self) -> uuid::Uuid {
        self.0.job.outbox_id
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.0.job.purpose
    }

    #[must_use]
    pub fn claim_id(&self) -> uuid::Uuid {
        self.0.job.claim_id
    }

    #[must_use]
    pub fn payload(&self) -> &serde_json::Value {
        &self.0.job.payload
    }

    #[must_use]
    pub fn attempt(&self) -> i16 {
        self.0.attempt
    }
}

/// Lease the next due intent as the dispatch worker would, without sending
/// it.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn claim_due_intent_for_test(
    store: &PostgresStore,
) -> Result<Option<IntentLeaseForTest>, StoreError> {
    let dispatcher = intents::intent_dispatcher(store.clone()).await?;
    let claim = dispatcher
        .claim()
        .await
        .map_err(|_| StoreError::IntentDispatch)?;
    Ok(claim.leased().map(IntentLeaseForTest))
}

/// Record the outcome of a leased intent under its lease: delivered, or a
/// transient failure.
///
/// # Errors
///
/// Returns [`StoreError::IntentDispatch`] when the lease no longer owns the
/// intent.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn finish_intent_for_test(
    store: &PostgresStore,
    lease: &IntentLeaseForTest,
    delivered: bool,
) -> Result<(), StoreError> {
    let dispatcher = intents::intent_dispatcher(store.clone()).await?;
    let outcome = if delivered {
        registry_platform_dispatch::SendOutcome::Accepted {
            receiver_reference: None,
        }
    } else {
        registry_platform_dispatch::SendOutcome::Transient { retry_after: None }
    };
    dispatcher
        .finish(
            &lease.0,
            registry_platform_dispatch::Sent {
                outcome,
                detail: (),
            },
        )
        .await
        .map_err(|_| StoreError::IntentDispatch)?;
    Ok(())
}

/// Send one leased intent as the dispatch worker would, under its lease,
/// and record the outcome the send returned.
///
/// # Errors
///
/// Returns [`StoreError::IntentDispatch`] when the send started nothing
/// because the lease no longer owns the intent, or when the outcome could
/// not be recorded under it.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn send_claimed_intent_for_test(
    store: &PostgresStore,
    scheduling_id: &str,
    transport: Option<Arc<ReminderTransport>>,
    lease: &IntentLeaseForTest,
) -> Result<(), StoreError> {
    use registry_platform_dispatch::postgres::DispatchTransport as _;

    let dispatcher = intents::intent_dispatcher(store.clone()).await?;
    let transport =
        intents::IntentTransport::new(dispatcher.clone(), scheduling_id.to_owned(), transport);
    let sent = transport
        .send(&lease.0)
        .await
        .map_err(|_| StoreError::IntentDispatch)?;
    dispatcher
        .finish(&lease.0, sent)
        .await
        .map_err(|_| StoreError::IntentDispatch)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone as _, Utc};
    use registry_platform_config::SecretProvider;
    use serde_json::Value;
    use uuid::Uuid;

    fn intent(purpose: &str) -> OutboxRow {
        let due = Utc.with_ymd_and_hms(2026, 10, 5, 8, 0, 0).unwrap();
        OutboxRow {
            outbox_id: Uuid::new_v4(),
            purpose: purpose.to_owned(),
            claim_id: Uuid::new_v4(),
            appointment_revision: 3,
            due_at: due,
            payload: serde_json::json!({"appointment": "a-1", "minutesBefore": 60}),
        }
    }

    #[test]
    fn a_due_intent_renders_as_the_shared_hook_envelope() {
        let row = intent("reminder");
        let rendered = reminder_event("registry-north", &row).unwrap();
        let event: Value = serde_json::from_slice(&rendered.body).unwrap();
        assert_eq!(event["id"], row.outbox_id.to_string());
        assert_eq!(
            event["source"],
            "urn:registrystack:scheduling:registry-north"
        );
        assert_eq!(event["type"], "org.registrystack.scheduling.reminder");
        assert_eq!(event["time"], "2026-10-05T08:00:00Z");
        assert_eq!(
            event["subject"],
            serde_json::json!({
                "recordReference": format!("/v1/appointments/{}", row.claim_id),
                "recordRevision": 3,
            })
        );
        assert_eq!(
            event["dataschema"],
            "urn:registrystack:scheduling:reminder-data:reminder"
        );
        assert_eq!(event["data"]["minutesBefore"], 60);
        assert_eq!(event["causation"]["root"], row.outbox_id.to_string());
        assert!(event.get("specversion").is_none());
        // The receiver parses the bytes with the same decoder an observer
        // delivery goes through.
        let decoded = registry_platform_hooks::HookEnvelope::from_canonical_bytes(
            &rendered.body,
            &registry_platform_hooks::EnvelopeLimits::tightened_to(REMINDER_MAXIMUM_BODY_BYTES),
        )
        .unwrap();
        assert_eq!(decoded.id, row.outbox_id.to_string());
    }

    fn reminder_secrets(keys: &[(&str, &[u8])]) -> (tempfile::TempDir, SecretResolver) {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        for (name, bytes) in keys {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let resolver = SecretResolver::new([SecretProvider::File], directory.path()).unwrap();
        (directory, resolver)
    }

    fn reminder_destination(origin: &str) -> ReminderDestinationConfig {
        serde_json::from_value(serde_json::json!({
            "url": format!("{origin}/fallback"),
            "hmacSha256KeyRef": "secret:file/current"
        }))
        .unwrap()
    }

    #[test]
    fn invalid_reminder_keys_name_the_path_size_newline_and_action_once() {
        let mut overlong = [0x5a; 65];
        overlong[64] = b'\n';
        let mut encoded = [0x5a; 32];
        encoded[..6].copy_from_slice(b"whsec_");
        let cases: &[(&[u8], &str)] = &[
            (&[0x5a; 31], "31 bytes (trailing newline: false). Supply 32 to 64 exact key bytes."),
            (&overlong, "65 bytes (trailing newline: true). Supply 32 to 64 exact key bytes."),
            (&encoded, "32 bytes (trailing newline: false). Supply the exact key bytes without the whsec_ encoding."),
        ];
        for (key, detail) in cases {
            let (_directory, secrets) = reminder_secrets(&[("current", key)]);
            let error = reminder_transport(&reminder_destination("http://127.0.0.1:1"), &secrets)
                .err()
                .expect("invalid signing material is refused");
            assert_eq!(
                error,
                format!("destinations.reminders.hmacSha256KeyRef has {detail}")
            );
        }
    }

    #[test]
    fn unavailable_and_empty_reminder_keys_include_the_secret_reason_and_action() {
        use registry_platform_config::SecretError;

        for (keys, reason) in [
            (&[][..], SecretError::Unavailable),
            (&[("current", &[][..])][..], SecretError::InvalidValue),
        ] {
            let (_directory, secrets) = reminder_secrets(keys);
            let error = reminder_transport(&reminder_destination("http://127.0.0.1:1"), &secrets)
                .err()
                .expect("unavailable or empty signing material is refused");
            assert_eq!(
                error,
                format!(
                    "destinations.reminders.hmacSha256KeyRef could not be resolved: {reason}. {}",
                    reason.suggested_action()
                )
            );
        }
    }

    #[test]
    fn a_reminder_key_equal_to_an_activated_observer_key_is_refused_after_its_file_is_removed() {
        use registry_platform_hooks::delivery::activate_url_hook_destinations;

        for (observer_current, observer_previous, duplicate_member) in [
            (TEST_CURRENT, None, "hmacSha256KeyRef"),
            (
                TEST_PREVIOUS,
                Some("secret:file/observer-previous"),
                "previousHmacSha256KeyRef",
            ),
        ] {
            let (directory, secrets) = reminder_secrets(&[
                ("current", &TEST_CURRENT),
                ("observer", &observer_current),
                ("observer-previous", &TEST_CURRENT),
            ]);
            let transport =
                reminder_transport(&reminder_destination("http://127.0.0.1:1"), &secrets).unwrap();
            let mut hook = serde_json::json!({
                "url": "https://events.example.test/hook",
                "hmacSha256KeyRef": "secret:file/observer"
            });
            if let Some(previous) = observer_previous {
                hook["previousHmacSha256KeyRef"] = serde_json::json!(previous);
            }
            let hooks =
                serde_json::from_value(serde_json::json!({"appointment-events": hook})).unwrap();
            let activated = activate_url_hook_destinations("test", &hooks, &secrets, 1024).unwrap();
            std::fs::remove_file(directory.path().join("observer")).unwrap();
            std::fs::remove_file(directory.path().join("observer-previous")).unwrap();
            let error = check_delivery_keys(&transport, &activated).unwrap_err();
            let first = "destinations.reminders.hmacSha256KeyRef";
            let second = format!("destinations.hooks.appointment-events.{duplicate_member}");
            assert_eq!(error, format!(
                "{first} and {second} resolve to the same key bytes. Give {second} its own key by writing 32 new random bytes to another secret and referencing it there."
            ));
        }
    }

    #[test]
    fn a_reminder_previous_key_equal_to_its_current_key_names_both_paths_and_rotation() {
        let (_directory, secrets) = reminder_secrets(&[("current", &TEST_CURRENT)]);
        let mut destination = reminder_destination("http://127.0.0.1:1");
        destination.previous_hmac_sha256_key_ref = Some(destination.hmac_sha256_key_ref.clone());
        let error = reminder_transport(&destination, &secrets).err().unwrap();
        let previous = "destinations.reminders.previousHmacSha256KeyRef";
        let current = "destinations.reminders.hmacSha256KeyRef";
        assert_eq!(error, format!(
            "{previous} holds the same bytes as {current}. To rotate, write 32 new random bytes to the secret {current} references and keep the old bytes behind {previous}."
        ));
    }

    const TEST_CURRENT: [u8; 32] = [0x5a; 32];
    const TEST_PURPOSE: [u8; 32] = [0x5b; 32];
    const TEST_PREVIOUS: [u8; 32] = [0x5c; 32];

    async fn capture_reminders(
        purposes: &[&str],
        times: &[SystemTime],
    ) -> (OutboxRow, Vec<wiremock::Request>) {
        use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;
        let (_directory, secrets) = reminder_secrets(&[
            ("current", &TEST_CURRENT),
            ("purpose", &TEST_PURPOSE),
            ("previous", &TEST_PREVIOUS),
        ]);
        let mut destination = reminder_destination(&server.uri());
        destination.previous_hmac_sha256_key_ref =
            Some(SecretReference::parse("secret:file/previous").unwrap());
        destination.purposes.confirmation = Some(
            serde_json::from_value(serde_json::json!({
                "url": format!("{}/confirmed", server.uri()),
                "hmacSha256KeyRef": "secret:file/purpose"
            }))
            .unwrap(),
        );
        let transport = reminder_transport(&destination, &secrets).unwrap();
        assert!(transport.target_for_purpose("unknown").is_none());
        let row = intent("confirmation");
        for (&purpose, &time) in purposes.iter().zip(times) {
            let request = transport
                .target_for_purpose(purpose)
                .unwrap()
                .render(reminder_event("registry-north", &row).unwrap(), time)
                .unwrap();
            transport
                .policy
                .send(request, Duration::from_secs(5))
                .await
                .unwrap();
        }
        (row, server.received_requests().await.unwrap())
    }

    fn captured_header<'a>(request: &'a wiremock::Request, name: &str) -> &'a str {
        request.headers[name].to_str().unwrap()
    }

    fn signed_content(
        request: &wiremock::Request,
    ) -> registry_platform_crypto::delivery_signature::SignedContent<'_> {
        registry_platform_crypto::delivery_signature::SignedContent {
            id: captured_header(request, "webhook-id"),
            timestamp: captured_header(request, "webhook-timestamp"),
            signature: captured_header(request, "webhook-signature"),
            body: &request.body,
        }
    }

    #[tokio::test]
    async fn reminders_use_the_fallback_or_the_selected_purpose_url() {
        let (_, requests) = capture_reminders(
            &["confirmation", "change", "cancellation", "reminder"],
            &[SystemTime::UNIX_EPOCH; 4],
        )
        .await;
        assert_eq!(
            requests
                .iter()
                .map(|request| request.url.path())
                .collect::<Vec<_>>(),
            ["/confirmed", "/fallback", "/fallback", "/fallback"]
        );
    }

    #[tokio::test]
    async fn a_reminder_purpose_signs_with_its_own_key() {
        use registry_platform_crypto::delivery_signature::verify_authenticity;

        let (_, requests) = capture_reminders(&["confirmation"], &[SystemTime::UNIX_EPOCH]).await;
        let keys = |key: &[u8]| DeliveryKeys::new(DeliveryKey::new(key).unwrap(), None).unwrap();
        verify_authenticity(&keys(&TEST_PURPOSE), signed_content(&requests[0])).unwrap();
        assert!(verify_authenticity(&keys(&TEST_CURRENT), signed_content(&requests[0])).is_err());
    }

    #[tokio::test]
    async fn reminders_use_the_outbox_id_as_webhook_id() {
        let (row, requests) = capture_reminders(
            &["confirmation"; 2],
            &[
                SystemTime::UNIX_EPOCH,
                SystemTime::UNIX_EPOCH + Duration::from_secs(30),
            ],
        )
        .await;
        for request in &requests {
            let envelope: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(
                captured_header(request, "webhook-id"),
                row.outbox_id.to_string()
            );
            assert_eq!(envelope["id"], row.outbox_id.to_string());
        }
        assert_ne!(
            captured_header(&requests[0], "webhook-signature"),
            captured_header(&requests[1], "webhook-signature")
        );
    }

    #[tokio::test]
    async fn reminder_rendering_converts_the_given_instant_to_unix_seconds() {
        let lease = SystemTime::UNIX_EPOCH + Duration::from_millis(1_788_048_001_123);
        let (_, requests) = capture_reminders(&["reminder"], &[lease]).await;
        assert_eq!(
            captured_header(&requests[0], "webhook-timestamp"),
            "1788048001"
        );
    }

    #[tokio::test]
    async fn a_previous_reminder_key_adds_a_second_entry_after_the_current_one() {
        let (_, requests) = capture_reminders(&["reminder"], &[SystemTime::UNIX_EPOCH]).await;
        let content = signed_content(&requests[0]);
        let signature = |key: &[u8]| {
            let keys = DeliveryKeys::new(DeliveryKey::new(key).unwrap(), None).unwrap();
            sign(&keys, content.id, 0, content.body).unwrap()
        };
        assert_eq!(
            content.signature,
            format!("{} {}", signature(&TEST_CURRENT), signature(&TEST_PREVIOUS))
        );
    }

    #[test]
    fn the_delivery_verdict_partitions_the_status_line() {
        assert!(matches!(delivery_of(200), Delivery::Delivered));
        assert!(matches!(delivery_of(204), Delivery::Delivered));
        assert!(matches!(delivery_of(408), Delivery::Transient));
        assert!(matches!(delivery_of(429), Delivery::Transient));
        assert!(matches!(delivery_of(503), Delivery::Transient));
        assert!(matches!(delivery_of(301), Delivery::Refused));
        assert!(matches!(delivery_of(401), Delivery::Refused));
        assert!(matches!(delivery_of(422), Delivery::Refused));
    }

    #[test]
    fn a_destination_url_splits_into_origin_and_fixed_path() {
        let (origin, path) =
            reminder_destination_origin_and_path("https://bus.example/reminders").unwrap();
        assert_eq!(origin, "https://bus.example/");
        assert_eq!(path, "/reminders");
        let (origin, path) =
            reminder_destination_origin_and_path("http://127.0.0.1:9000/outbox").unwrap();
        assert_eq!(origin, "http://127.0.0.1:9000/");
        assert_eq!(path, "/outbox");
        let (_, path) =
            reminder_destination_origin_and_path("https://bus.example/alpha/../reminders").unwrap();
        assert_eq!(path, "/reminders");
        assert!(reminder_destination_origin_and_path("https://bus.example/r?wide=1").is_none());
        assert!(reminder_destination_origin_and_path("https://bus.example/r#f").is_none());
        assert!(reminder_destination_origin_and_path("not a url").is_none());
    }

    #[test]
    fn the_offering_pool_anchors_are_collected_without_duplicates() {
        use registry_platform_yaml::{LocalId, ProjectIdentity};
        use registry_scheduling_core::{
            ArrivalOffering, ExactTimeOffering, HoldPolicy, OfferingPolicy, SchedulingMode,
            SchedulingPolicy, ServicePolicy,
        };
        let exact_time = || {
            Some(ExactTimeOffering {
                party_counts: Default::default(),
                duration_minutes: 30,
                duration_selection: None,
                opening_coverage: registry_scheduling_core::OpeningCoverage::ServiceInterval,
                allow_resource_selection: false,
                buffer_before_minutes: 5,
                buffer_after_minutes: 5,
                lead_time_minutes: 60,
                horizon_days: 30,
                pool: "north".to_owned(),
                start_increment_minutes: 30,
                maximum_recipients: 1,
            })
        };
        let offering =
            |id: &str, exact: Option<ExactTimeOffering>, arrival: Option<ArrivalOffering>| {
                OfferingPolicy {
                    id: id.to_owned(),
                    service: "s1".to_owned(),
                    label: id.to_owned(),
                    mode: if exact.is_some() {
                        SchedulingMode::ExactTime
                    } else {
                        SchedulingMode::ArrivalWindow
                    },
                    location: "l1".to_owned(),
                    because: "test".to_owned(),
                    exact_time: exact,
                    arrival,
                    cancellation_cutoff_minutes: 240,
                    reminders: Vec::new(),
                    duplicate_active_key: None,
                    requires_capabilities: Vec::new(),
                    prerequisites: Vec::new(),
                }
            };
        let policy = SchedulingPolicy {
            api_version: "test".to_owned(),
            kind: "test".to_owned(),
            project: ProjectIdentity::new(LocalId::new("standalone").unwrap(), "1".to_owned()),
            services: vec![ServicePolicy {
                id: "s1".to_owned(),
                label: "Service".to_owned(),
            }],
            offerings: vec![
                offering("o1", exact_time(), None),
                // The same pool again: one anchor, not two.
                offering("o2", exact_time(), None),
                offering(
                    "o3",
                    None,
                    Some(ArrivalOffering {
                        window: Some("w-morning".to_owned()),
                        lead_time_minutes: 60,
                        horizon_days: 30,
                    }),
                ),
            ],
            holiday_sets: Vec::new(),
            openings: Vec::new(),
            channels: Vec::new(),
            hold_policy: HoldPolicy {
                ttl_minutes: 10,
                maximum_per_caller: 2,
                because: "test".to_owned(),
            },
            hooks: Vec::new(),
        };
        assert_eq!(
            crate::store::policy_pool_ids(&policy),
            vec!["north".to_owned()]
        );
    }

    #[test]
    fn production_reminder_transport_accepts_only_loopback_plaintext() {
        let secrets =
            SecretResolver::new([registry_platform_config::SecretProvider::Environment], "")
                .unwrap();
        for (host, accepted) in [("127.0.0.1", true), ("10.0.0.5", false)] {
            let destination = ReminderDestinationConfig {
                url: format!("http://{host}:8080/reminders"),
                purpose_urls: Default::default(),
                bearer_token_ref: None,
                hmac_sha256_key_ref: None,
            };
            assert_eq!(reminder_transport(&destination, &secrets).is_ok(), accepted);
        }
    }

    #[test]
    fn serve_is_the_only_command_and_any_other_name_is_a_usage_error() {
        let subcommands: Vec<_> = command()
            .get_subcommands()
            .map(|subcommand| subcommand.get_name().to_owned())
            .collect();
        assert_eq!(subcommands, vec!["serve".to_owned()]);

        let error = command()
            .try_get_matches_from([
                "scheduling",
                "--runtime-config",
                "/nonexistent/runtime.yaml",
                "migrate",
            ])
            .expect_err("serve is the only command");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidSubcommand);
        assert_eq!(error.exit_code(), 2);
    }
}
