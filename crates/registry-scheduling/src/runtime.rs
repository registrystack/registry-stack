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
//! each due outbox intent is rendered as one CloudEvents 1.0 JSON event and
//! POSTed to the operator-configured destination, exactly once per claim, with
//! the transport and the notification bus wholly external (INT-02). When no
//! destination is configured the outbox is the boundary: intents are recorded
//! and marked local, never pretended delivered.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use clap::{Arg, Command};
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{ProtectedSecret, SecretResolver};
use registry_platform_httputil::destination::{
    DataDestinationPolicy, DataDestinationRequestTemplate, DestinationAuthorizationTemplate,
    DestinationAuthorizationValue, DestinationBodyTemplate, DestinationMethod, DestinationProfile,
    FixedDestinationPolicy,
};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Interval, MissedTickBehavior};
use url::Url;

use crate::audit::SchedulingAudit;
use crate::auth::SchedulingAuthenticator;
use crate::config::{ReminderDestinationConfig, RuntimeConfig, RuntimeConfigError};
use crate::hooks::{ActivatedHooks, HookActivationError, HookRuntimeIdentity};
use crate::http::{router, HttpState};
use crate::service::SchedulingService;
use crate::store::{
    OutboxRow, PostgresStore, RoleMode, StoreError, REMINDER_SEND_TIMEOUT, SINGLE_ROLE_STATEMENT,
};

/// How often each background loop wakes. The intervals are fixed constants,
/// not configuration: they are internal mechanics of one deployment, not an
/// operator-tunable contract.
const WORKER_INTERVAL: Duration = Duration::from_secs(2);
/// Retention sweeps run every thirtieth maintenance tick.
const RETENTION_TICKS: u8 = 30;
/// How many holds one expiry pass may retire, and how many intents one
/// dispatch pass may claim.
const HOLD_EXPIRY_BATCH: i64 = 100;
const REMINDER_BATCH: i64 = 100;
/// The delivery attempts an intent may consume before it is held as failed for
/// the operator to see.
const REMINDER_ATTEMPTS_CEILING: i32 = 8;
/// Exponential backoff between reminder attempts, from half a minute to an
/// hour.
const REMINDER_RETRY_BASE_SECONDS: i64 = 30;
const REMINDER_RETRY_MAX_SECONDS: i64 = 3600;
/// The lease one dispatch pass holds its claimed intents for. The worst
/// case of one whole claimed batch is every intent sending to its full
/// timeout, 100 x 5 s = 500 s, plus the database round trips around each
/// send; 600 s covers both, so a second dispatcher never re-sends what a
/// slow first one still owns, and a dispatcher that dies delays its
/// intents by exactly one lease.
const INTENT_DISPATCH_LEASE_SECONDS: i64 = 600;
/// One rendered reminder event is bounded, as is the whole request.
const REMINDER_MAXIMUM_BODY_BYTES: usize = 16 * 1024;
const REMINDER_MAXIMUM_REQUEST_BYTES: usize = 32 * 1024;
const REMINDER_BEARER_MAXIMUM_BYTES: usize = 8192;

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
        .subcommand_required(true)
        // Kept only to refuse by name: `schedulingctl apply` migrates now.
        .subcommand(
            Command::new("migrate")
                .about("Removed; run `schedulingctl plan` then `schedulingctl apply`")
                .hide(true),
        )
        .subcommand(Command::new("serve").about("Run the Scheduling HTTP service"))
}

/// The refusal for a removed `scheduling` subcommand named in `args` (the
/// arguments after the program name), found before the command line is
/// parsed so it answers even without the otherwise required
/// `--runtime-config`.
#[must_use]
pub fn removed_command_refusal<I, S>(args: I) -> Option<RuntimeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.as_ref();
        if arg == "--runtime-config" {
            args.next();
            continue;
        }
        if arg.to_string_lossy().starts_with('-') {
            continue;
        }
        return (arg == "migrate").then_some(RuntimeError::RemovedCommand);
    }
    None
}

pub async fn run(matches: &clap::ArgMatches) -> Result<(), RuntimeError> {
    let path = matches
        .get_one::<String>("runtime-config")
        .ok_or(RuntimeError::Arguments)?;
    match matches.subcommand_name() {
        Some("migrate") => Err(RuntimeError::RemovedCommand),
        Some("serve") => serve_from_path(path).await,
        _ => Err(RuntimeError::Arguments),
    }
}

/// Name the provisioning or startup act a store failure happened in.
fn database_step(stage: &'static str) -> impl Fn(StoreError) -> RuntimeError {
    move |source| RuntimeError::Database { stage, source }
}

pub async fn serve_from_path(path: impl AsRef<Path>) -> Result<(), RuntimeError> {
    let path = path.as_ref();
    let config =
        RuntimeConfig::load(path).map_err(|error| {
            match crate::config::startup_report(path, &error) {
                Some(report) => RuntimeError::ConfigurationRefused(report),
                None => RuntimeError::Config(error),
            }
        })?;
    let loaded = config.load_policy()?;
    let package_digest = loaded.package_digest;
    tracing::info!(package_digest = %package_digest, "verified Scheduling package");
    let policy = loaded.policy;
    let scheduling_id = policy.project.id.to_string();
    let policy_digest = policy.policy_digest();
    let secrets = secret_resolver(&config)?;
    let store = PostgresStore::connect_runtime(&config.database, &secrets)
        .map_err(database_step("runtime database configuration"))?;
    store
        .ready()
        .await
        .map_err(database_step("schema readiness check"))?;

    // The activation ledger names the package `schedulingctl apply` accepted
    // for this database. Startup serves only that package, on the database
    // the ledger recorded, and writes no activation state of its own.
    let active = store
        .check_active_package(&crate::store::ActivePackage {
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
            scheduling_id: scheduling_id.clone(),
            policy_revision,
            policy_digest: policy_digest.clone(),
        },
        database_schema,
        hook_payload_retention,
    )?;

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
    let authenticator = Arc::new(SchedulingAuthenticator::new(
        &config.authentication.oidc,
        verifier,
        keys,
    ));

    let reminders = match &config.destinations.reminders {
        Some(destination) => {
            Some(reminder_transport(destination, &secrets).map_err(RuntimeError::Destination)?)
        }
        None => None,
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
            config.retention.attempt_receipt_retention_days,
        )
        .with_hooks(hooks),
    );

    let (worker_stopped, worker_stops) = mpsc::channel(WORKER_STOP_CAPACITY);
    let mut workers = Vec::new();

    let expiry_store = store.clone();
    workers.push(supervise(
        "hold expiry",
        worker_stopped.clone(),
        async move {
            let mut interval = worker_timer();
            loop {
                interval.tick().await;
                let now = expiry_store.observed_now();
                match expiry_store.expire_due_holds(now, HOLD_EXPIRY_BATCH).await {
                    Ok(expired) if expired > 0 => {
                        tracing::info!(expired, "Scheduling hold expiry pass retired due holds");
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(
                        error = %error,
                        "Scheduling hold expiry pass did not complete"
                    ),
                }
            }
        },
    ));

    let dispatch_store = store.clone();
    let dispatch_id = scheduling_id.clone();
    let dispatch_destination = reminders;
    workers.push(supervise(
        "reminder dispatch",
        worker_stopped.clone(),
        async move {
            let mut interval = worker_timer();
            loop {
                interval.tick().await;
                if let Err(error) = dispatch_due_intents(
                    &dispatch_store,
                    &dispatch_id,
                    dispatch_destination.as_ref(),
                )
                .await
                {
                    tracing::warn!(
                        error = %error,
                        "Scheduling reminder dispatch pass did not complete"
                    );
                }
            }
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

    // The whole of retention, and deliberately not all of retention. This
    // sweep erases two things: idempotency attempt receipts, with the raw
    // caller and key they were filed under, after the configured
    // `retention.attemptReceiptRetentionDays`, and listing cursors, after
    // the fifteen minutes the listing contract gives them. Appointments,
    // their history, and the delivery outbox are never swept, by decision
    // and not by omission: committed scheduling data has
    // no retention period in this milestone, and one knob must not read as a
    // promise to sweep it. A future period for those is new configuration and
    // new passes here, not a wider reading of this one.
    let retention_store = store.clone();
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
            if let Err(error) = retention_store.erase_expired_cursors(now).await {
                tracing::warn!(error = %error, "Scheduling cursor retention pass did not complete");
            }
            if let Err(error) = retention_store.erase_expired_attempts(now).await {
                tracing::warn!(
                    error = %error,
                    "Scheduling attempt receipt retention pass did not complete"
                );
            }
        }
    }));

    let app = router(HttpState {
        service,
        authenticator,
        store,
    });
    let listener = tokio::net::TcpListener::bind(config.listener.bind.socket_addr()).await?;
    let served = serve_until_worker_stops(listener, app, worker_stops).await;
    for worker in workers {
        worker.abort();
    }
    served
}

#[derive(Debug, Error)]
pub enum RuntimeError {
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
    #[error(transparent)]
    HookActivation(#[from] HookActivationError),
    #[error("the Scheduling retained hook delivery bindings are unavailable")]
    HookDelivery,
    #[error("a Scheduling background worker stopped")]
    WorkerStopped,
    #[error(
        "`scheduling migrate` is removed; run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`"
    )]
    RemovedCommand,
    #[error("the deployment's scheduling id does not match the authored policy")]
    DeploymentIdentity,
    #[error("a due reminder intent could not be rendered as an event")]
    ReminderEvent,
}

impl RuntimeError {
    /// The process exit code: 2 for a command line the binary no longer
    /// accepts, 1 for every other refusal or failure.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::RemovedCommand => 2,
            _ => 1,
        }
    }

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
    stops: mpsc::Receiver<&'static str>,
) -> Result<(), RuntimeError> {
    axum::serve(listener, app)
        .with_graceful_shutdown(worker_stop(stops))
        .await?;
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
    let writer = AuditWriter::open(destination)
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

/// The frozen outbound transport for due reminder intents: one fixed
/// destination, one reviewed request shape, and an operator-configured bearer
/// credential that never reaches a log line.
///
/// Public, with its fields kept private, so the database suite can point a
/// dispatch pass at a local destination it controls. What the deployment
/// sends, and how it reads each answer back, is only observable against a
/// destination that answers.
pub struct ReminderTransport {
    policy: DataDestinationPolicy,
    template: DataDestinationRequestTemplate,
    bearer: Option<ProtectedSecret>,
}

/// Split an operator-configured destination URL into the origin a frozen
/// destination policy holds and the fixed path its request template compiles.
/// A URL carrying a query or fragment is refused: the destination is one
/// reviewed endpoint, not a template a configuration value may widen.
fn destination_origin_and_path(configured: &str) -> Result<(String, String), &'static str> {
    let parsed = Url::parse(configured).map_err(|_| "the destination URL does not parse")?;
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("the destination URL may not carry a query or fragment");
    }
    let path = parsed.path().to_owned();
    let mut origin = parsed;
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    Ok((origin.to_string(), path))
}

/// Compile one operator-configured destination into the frozen transport the
/// dispatch loop sends through.
///
/// # Errors
///
/// Returns the operator-facing sentence naming what about the configured
/// destination could not be frozen.
pub fn reminder_transport(
    destination: &ReminderDestinationConfig,
    secrets: &SecretResolver,
) -> Result<ReminderTransport, String> {
    let (origin, path) =
        destination_origin_and_path(&destination.url).map_err(|detail| detail.to_owned())?;
    let scheme = origin
        .split_once("://")
        .map(|(scheme, _)| scheme.to_owned())
        .unwrap_or_default();
    // The configuration check already confines plain http to loopback hosts;
    // the transport pins the same rule into the frozen policy.
    let profile = match scheme.as_str() {
        "https" => DestinationProfile::ProductionHttps,
        "http" => DestinationProfile::LoopbackDevelopmentHttp,
        _ => return Err("the destination URL scheme is not http(s)".to_owned()),
    };
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };
    let policy = FixedDestinationPolicy::new("scheduling-reminders", &origin, profile, &[])
        .map_err(|_| "the destination could not be frozen as a fixed origin".to_owned())?;
    let authorization = match &destination.bearer_token_ref {
        Some(reference) => {
            let secret = secrets.resolve(reference).map_err(|error| {
                crate::config::describe_secret_failure(
                    "destinations.reminders.bearerTokenRef",
                    reference,
                    &error,
                )
            })?;
            return Ok(ReminderTransport {
                policy,
                template: reminder_template(
                    &path,
                    DestinationAuthorizationTemplate::Bearer {
                        max_value_bytes: REMINDER_BEARER_MAXIMUM_BYTES,
                    },
                )?,
                bearer: Some(secret),
            });
        }
        None => DestinationAuthorizationTemplate::Forbidden,
    };
    Ok(ReminderTransport {
        policy,
        template: reminder_template(&path, authorization)?,
        bearer: None,
    })
}

fn reminder_template(
    path: &str,
    authorization: DestinationAuthorizationTemplate,
) -> Result<DataDestinationRequestTemplate, String> {
    DataDestinationRequestTemplate::new_with_exact_headers(
        DestinationMethod::ReviewedReadOnlyPost,
        path,
        &[],
        &[
            ("accept", b"application/json".as_slice()),
            ("content-type", b"application/cloudevents+json".as_slice()),
        ],
        authorization,
        DestinationBodyTemplate::Required {
            max_bytes: REMINDER_MAXIMUM_BODY_BYTES,
        },
        REMINDER_MAXIMUM_REQUEST_BYTES,
    )
    .map_err(|_| "the reminder request shape could not be compiled".to_owned())
}

/// Render one due intent as a CloudEvents 1.0 event in canonical JSON: the
/// intent's own id, the deployment it came from, the purpose it was minted
/// under, the instant it fell due, and the payload the runtime committed.
fn reminder_event(scheduling_id: &str, row: &OutboxRow) -> Result<Vec<u8>, RuntimeError> {
    let event = serde_json::json!({
        "specversion": "1.0",
        "id": row.outbox_id.to_string(),
        "source": scheduling_id,
        "type": format!("org.registrystack.scheduling.{}", row.purpose),
        "time": row.due_at.to_rfc3339(),
        "data": row.payload,
    });
    canonicalize_json(&event).map_err(|_| RuntimeError::ReminderEvent)
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

/// The backoff before the next attempt of one intent, exponential from the
/// base and capped at the hour, counted from `now`.
fn next_attempt(now: DateTime<Utc>, attempts: i32) -> DateTime<Utc> {
    let shift = (attempts.max(1) - 1).min(7) as u32;
    let seconds = (REMINDER_RETRY_BASE_SECONDS << shift).min(REMINDER_RETRY_MAX_SECONDS);
    now + TimeDelta::seconds(seconds)
}

/// Claim every due intent and give each one dispatch attempt. A transport
/// failure proves nothing and schedules a retry; a refusal outside the retry
/// classes is held as failed for the operator; with no destination
/// configured the intent is marked local: recorded, never pretended
/// delivered.
///
/// A claimed intent is leased for the pass that claimed it and fenced by
/// its attempt number, so a concurrent or restarted dispatcher cannot
/// re-send it or overwrite a newer outcome. Reminders whose appointment has
/// been cancelled or moved to a newer revision are skipped before the send
/// rather than delivered against a decision the caller already changed; the
/// residual race, a suppression landing while the send itself is in flight,
/// is reported as a lost outcome rather than erased, and the destination
/// deduplicates by the event's stable identifier.
///
/// # Errors
///
/// Returns the store failure that stopped the pass. A destination's answer,
/// whatever it is, is an outcome written back and not an error.
pub async fn dispatch_due_intents(
    store: &PostgresStore,
    scheduling_id: &str,
    transport: Option<&ReminderTransport>,
) -> Result<(), StoreError> {
    let now = store.observed_now();
    let lease = TimeDelta::seconds(INTENT_DISPATCH_LEASE_SECONDS);
    for row in store.claim_due_intents(now, REMINDER_BATCH, lease).await? {
        let Some(transport) = transport else {
            let owned = store.hold_intent_local(row.outbox_id, row.attempts).await?;
            if !owned {
                // Nothing was sent: no destination exists. The intent was
                // suppressed or taken over between the claim and this write,
                // and its owner holds the record.
                tracing::warn!(
                    outbox_id = %row.outbox_id,
                    attempts = row.attempts,
                    "a local hold arrived after its attempt lost the intent; nothing was sent"
                );
            }
            continue;
        };
        // The claim's own liveness: a suppressed reminder, or one whose
        // appointment moved to a newer revision, is not sent.
        if !store
            .intent_still_dispatchable(row.outbox_id, row.attempts)
            .await?
        {
            tracing::info!(
                outbox_id = %row.outbox_id,
                "a claimed intent was suppressed or superseded before its dispatch"
            );
            continue;
        }
        let body = match reminder_event(scheduling_id, &row) {
            Ok(body) => body,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    outbox_id = %row.outbox_id,
                    "a due reminder intent could not be rendered"
                );
                // An unrenderable intent is held, not retried: no amount of
                // retrying fixes a payload that cannot become an event.
                store
                    .retry_intent(
                        row.outbox_id,
                        next_attempt(store.observed_now(), row.attempts),
                        row.attempts,
                        row.attempts,
                    )
                    .await?;
                continue;
            }
        };
        let authorization = transport
            .bearer
            .as_ref()
            .map(|secret| DestinationAuthorizationValue::bearer(secret.expose_secret().to_vec()))
            .transpose();
        let request = match authorization {
            Ok(authorization) => transport.template.render(&[], &[], authorization, Some(body)),
            Err(_) => Err(registry_platform_httputil::destination::DestinationRequestError::InvalidAuthorization),
        };
        let outcome = match request {
            Ok(request) => match transport.policy.send(request, REMINDER_SEND_TIMEOUT).await {
                Ok(response) => Some(delivery_of(response.status().as_u16())),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        outbox_id = %row.outbox_id,
                        "a reminder delivery attempt did not reach a verdict"
                    );
                    Some(Delivery::Transient)
                }
            },
            Err(error) => {
                tracing::error!(
                    error = %error,
                    outbox_id = %row.outbox_id,
                    "a reminder delivery request could not be rendered"
                );
                None
            }
        };
        match outcome.unwrap_or(Delivery::Transient) {
            Delivery::Delivered => {
                let owned = store
                    .mark_intent_delivered(row.outbox_id, row.attempts)
                    .await?;
                if !owned {
                    // The send completed, but suppression or a superseding
                    // attempt owns the row now. The row records its own
                    // state; this line is the delivery's accounting.
                    report_lost_outcome(&row);
                }
            }
            Delivery::Transient => {
                // A retry write that loses its claim needs no report: the
                // attempt that took the intent over writes the outcome that
                // counts, and a back-off nobody owes is nobody's news.
                store
                    .retry_intent(
                        row.outbox_id,
                        next_attempt(store.observed_now(), row.attempts),
                        REMINDER_ATTEMPTS_CEILING,
                        row.attempts,
                    )
                    .await?;
            }
            // A refusal the retry classes do not cover (an authorization
            // refusal, a routing refusal) is terminal: the ceiling set to the
            // attempt count holds the intent as failed on this very write.
            Delivery::Refused => {
                tracing::warn!(
                    outbox_id = %row.outbox_id,
                    status = row.attempts,
                    "a reminder destination refused an intent outright"
                );
                store
                    .retry_intent(
                        row.outbox_id,
                        next_attempt(store.observed_now(), row.attempts),
                        row.attempts,
                        row.attempts,
                    )
                    .await?;
            }
        }
    }
    Ok(())
}

/// Report an outcome write that landed on nobody: the intent was
/// suppressed, or a superseding attempt took it over, while this attempt
/// was in flight. The row keeps the state its owner left it in; what this
/// records is that a send this attempt made may have reached a destination
/// that no outbox state will name.
fn report_lost_outcome(row: &OutboxRow) {
    tracing::warn!(
        outbox_id = %row.outbox_id,
        attempts = row.attempts,
        "a dispatch outcome arrived after its attempt lost the intent; a send may have completed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
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
            attempts: 1,
            payload: serde_json::json!({"appointment": "a-1", "minutesBefore": 60}),
        }
    }

    #[test]
    fn a_due_intent_renders_as_one_canonical_cloudevents_event() {
        let row = intent("reminder-60");
        let body = reminder_event("registry-north", &row).unwrap();
        let event: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(event["specversion"], "1.0");
        assert_eq!(event["id"], row.outbox_id.to_string());
        assert_eq!(event["source"], "registry-north");
        assert_eq!(event["type"], "org.registrystack.scheduling.reminder-60");
        assert_eq!(event["time"], "2026-10-05T08:00:00+00:00");
        assert_eq!(event["data"]["minutesBefore"], 60);
        // Canonical JSON carries no insignificant whitespace.
        assert!(!String::from_utf8(body.clone()).unwrap().contains(' '));
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
    fn retry_backoff_grows_exponentially_and_caps_at_the_hour() {
        let now = Utc::now();
        let first = next_attempt(now, 1)
            .signed_duration_since(now)
            .num_seconds();
        let second = next_attempt(now, 2)
            .signed_duration_since(now)
            .num_seconds();
        let ceiling = next_attempt(now, 50)
            .signed_duration_since(now)
            .num_seconds();
        assert_eq!(first, REMINDER_RETRY_BASE_SECONDS);
        assert_eq!(second, 2 * REMINDER_RETRY_BASE_SECONDS);
        assert_eq!(ceiling, REMINDER_RETRY_MAX_SECONDS);
    }

    #[test]
    fn a_destination_url_splits_into_origin_and_fixed_path() {
        let (origin, path) = destination_origin_and_path("https://bus.example/reminders").unwrap();
        assert_eq!(origin, "https://bus.example/");
        assert_eq!(path, "/reminders");
        let (origin, path) = destination_origin_and_path("http://127.0.0.1:9000/outbox").unwrap();
        assert_eq!(origin, "http://127.0.0.1:9000/");
        assert_eq!(path, "/outbox");
        assert!(destination_origin_and_path("https://bus.example/r?wide=1").is_err());
        assert!(destination_origin_and_path("https://bus.example/r#f").is_err());
        assert!(destination_origin_and_path("not a url").is_err());
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
                duration_minutes: 30,
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
            project: ProjectIdentity {
                id: LocalId::new("standalone").unwrap(),
                version: "1".to_owned(),
            },
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
                        window: "w-morning".to_owned(),
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

    #[tokio::test]
    async fn the_removed_migrate_command_refuses_as_usage_naming_plan_then_apply() {
        let command = command();
        let visible: Vec<_> = command
            .get_subcommands()
            .filter(|subcommand| !subcommand.is_hide_set())
            .map(|subcommand| subcommand.get_name().to_owned())
            .collect();
        assert_eq!(visible, vec!["serve".to_owned()]);

        // The path is never read: the refusal comes before any configuration.
        let matches = command
            .try_get_matches_from([
                "scheduling",
                "--runtime-config",
                "/nonexistent/runtime.yaml",
                "migrate",
            ])
            .expect("the removed command still parses so it can refuse by name");
        let error = run(&matches).await.expect_err("migrate is removed");
        assert!(matches!(error, RuntimeError::RemovedCommand), "{error:?}");
        assert_eq!(error.exit_code(), 2);
        assert_eq!(
            error.to_string(),
            "`scheduling migrate` is removed; run `schedulingctl plan --runtime-config FILE` then `schedulingctl apply --runtime-config FILE`"
        );
    }
}
