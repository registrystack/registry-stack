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
use registry_platform_audit::{AuditError, AuditProfile, AuditWriter};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{ProtectedSecret, SecretProvider, SecretResolver};
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
use crate::store::{OutboxRow, PostgresStore, StoreError, REMINDER_SEND_TIMEOUT};

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
                .value_name("FILE")
                .help("Absolute path to the runtime configuration file.")
                .required(true),
        )
        .subcommand_required(true)
        .subcommand(Command::new("migrate").about("Apply Scheduling database migrations"))
        .subcommand(Command::new("serve").about("Run the Scheduling HTTP service"))
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
    let policy = config.load_policy()?;
    let secrets = secret_resolver(&config)?;
    let store = PostgresStore::connect_migration(&config.database, &secrets)
        .map_err(database_step("migration database configuration"))?;
    store
        .migrate()
        .await
        .map_err(database_step("schema migration"))?;
    // Migrations leave the deployment identity unset; adopting it here is the
    // provisioning act that binds this database to the policy's scheduling
    // id, which every serve verifies before it writes anything.
    store
        .adopt(&policy.scheduling.id)
        .await
        .map_err(database_step("deployment adoption"))?;
    Ok(())
}

pub async fn serve_from_path(path: impl AsRef<Path>) -> Result<(), RuntimeError> {
    let config = RuntimeConfig::load(path)?;
    match config.policy_package_digest()? {
        Some(digest) => tracing::info!(
            policy_package_digest = %digest,
            "verified Scheduling policy package"
        ),
        None => tracing::info!("loading authored Scheduling policy for loopback development"),
    }
    let policy = config.load_policy()?;
    let scheduling_id = policy.scheduling.id.clone();
    let policy_digest = policy.policy_digest();
    let secrets = secret_resolver(&config)?;
    let store = PostgresStore::connect_runtime(&config.database, &secrets)
        .map_err(database_step("runtime database configuration"))?;
    store
        .ready()
        .await
        .map_err(database_step("schema readiness check"))?;

    // The deployment identity is read before anything is written: the store
    // refuses to apply a policy under a scheduling id the deployment does not
    // carry, and an empty one is a deployment that has not been adopted yet.
    let (stored_id, stored_revision, stored_digest) = store
        .scheduling_meta()
        .await
        .map_err(database_step("deployment identity read"))?;
    if stored_id.is_empty() {
        return Err(RuntimeError::Unbootstrapped);
    }
    if stored_id != scheduling_id {
        return Err(RuntimeError::DeploymentIdentity);
    }
    let database_schema = store
        .schema_name()
        .await
        .map_err(database_step("hook schema discovery"))?;
    let hook_payload_retention =
        Duration::from_secs(u64::from(config.retention.hook_payload_days) * 24 * 60 * 60);
    let expected_policy_revision = if stored_digest == policy_digest {
        stored_revision
    } else {
        stored_revision
            .checked_add(1)
            .ok_or(RuntimeError::HookActivation(
                HookActivationError::InvalidIdentity,
            ))?
    };

    // Resolve and validate every destination, including its signing material,
    // before policy publication. A first start with a bad secret must not
    // advance the durable policy revision and then fail to serve it.
    let hooks = ActivatedHooks::activate(
        &policy.hooks,
        &config.destinations.hooks,
        &secrets,
        HookRuntimeIdentity {
            scheduling_id: scheduling_id.clone(),
            policy_revision: expected_policy_revision,
            policy_digest: policy_digest.clone(),
        },
        database_schema.clone(),
        hook_payload_retention,
    )?;

    // The audit destination is keyed and opened before the policy revision
    // can move, so a mis-provisioned deployment never advances state it
    // cannot hold to account.
    let (audit_hasher, audit) = open_audit(&config, &secrets, None).await?;

    // Before publishing a changed policy, prove that every retained event can
    // still use the exact destination binding captured for it. A deployment
    // may retain extra explicit bindings while old deliveries drain.
    if stored_revision > 0 && !stored_digest.is_empty() {
        let retained_hooks = ActivatedHooks::activate(
            &policy.hooks,
            &config.destinations.hooks,
            &secrets,
            HookRuntimeIdentity {
                scheduling_id: stored_id.clone(),
                policy_revision: stored_revision,
                policy_digest: stored_digest.clone(),
            },
            database_schema.clone(),
            hook_payload_retention,
        )?;
        retained_hooks
            .delivery_service(store.clone(), audit.clone())
            .verify_retained_bindings()
            .await
            .map_err(|_| RuntimeError::HookDelivery)?;
    }

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

    // Publishing a policy may bump the revision every process start only when
    // the digest changed; the anchors the policy names must exist for any
    // offering to resolve supply.
    let pool_ids = offering_pool_ids(&policy);
    let policy_revision = store
        .apply_policy(&scheduling_id, &policy_digest, &pool_ids, &policy)
        .await
        .map_err(database_step("policy publication"))?;

    if policy_revision != expected_policy_revision {
        return Err(RuntimeError::HookActivation(
            HookActivationError::InvalidIdentity,
        ));
    }
    let hook_delivery = hooks.delivery_service(store.clone(), audit.clone());
    hook_delivery
        .verify_retained_bindings()
        .await
        .map_err(|_| RuntimeError::HookDelivery)?;

    let service = Arc::new(
        SchedulingService::new(
            store.clone(),
            policy,
            scheduling_id.clone(),
            policy_revision,
            policy_digest,
            audit_hasher,
            audit,
            config.retention.attempt_receipt_days,
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
                let now = Utc::now();
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
    // sweep erases two things: idempotency attempt receipts, after the
    // configured `retention.attemptReceiptDays`, and listing cursors, after
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
            let now = Utc::now();
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
    let listener = tokio::net::TcpListener::bind(config.listener.bind).await?;
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
        "the deployment identity is unset: adopt this database before serving, by running \
         `scheduling migrate` with this runtime configuration"
    )]
    Unbootstrapped,
    #[error("the deployment's scheduling id does not match the authored policy")]
    DeploymentIdentity,
    #[error("a due reminder intent could not be rendered as an event")]
    ReminderEvent,
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
    let audit_secret = resolve_audit_secret(secrets, &config.audit.hash_key_ref)?;
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
    let writer = AuditWriter::open(destination).await.map_err(|error| {
        RuntimeError::AuditDestination(describe_audit_destination_failure(&error))
    })?;
    Ok((audit_profile.key_hasher(), SchedulingAudit::new(writer)))
}

/// Name the rule an audit destination refusal broke, without a record or a
/// path the operator did not configure.
fn describe_audit_destination_failure(error: &AuditError) -> String {
    match error {
        // A companion destination's lock can only be held by another
        // invocation of that same one-shot command; the running service
        // never opens this sibling file.
        AuditError::SinkLocked {
            role: Some(role), ..
        } => format!(
            "another {role} invocation holds the single-writer lock on its companion audit \
             file; wait for it to finish before starting this one"
        ),
        AuditError::SinkLocked { role: None, .. } => "another process holds the single-writer \
             lock beside audit.path; stop it before starting this one"
            .to_owned(),
        AuditError::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => format!(
            "{io}; the audit directory must belong to the runtime user and not be group- or \
             world-writable, and audit.path must belong to that user with mode 0600"
        ),
        AuditError::Io(io) => format!("the audit file could not be opened ({})", io.kind()),
        _ => "the audit file could not be opened".to_owned(),
    }
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

/// The pool anchors the policy's exact-time offerings name.
fn offering_pool_ids(policy: &registry_scheduling_core::SchedulingPolicy) -> Vec<String> {
    let mut ids: Vec<String> = policy
        .offerings
        .iter()
        .filter_map(|offering| offering.exact_time.as_ref().map(|exact| exact.pool.clone()))
        .collect();
    ids.sort();
    ids.dedup();
    ids
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
/// base and capped at the hour.
fn next_attempt(attempts: i32) -> DateTime<Utc> {
    let shift = (attempts.max(1) - 1).min(7) as u32;
    let seconds = (REMINDER_RETRY_BASE_SECONDS << shift).min(REMINDER_RETRY_MAX_SECONDS);
    Utc::now() + TimeDelta::seconds(seconds)
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
    let now = Utc::now();
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
                        next_attempt(row.attempts),
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
                        next_attempt(row.attempts),
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
                        next_attempt(row.attempts),
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
        let first = next_attempt(1).signed_duration_since(now).num_seconds();
        let second = next_attempt(2).signed_duration_since(now).num_seconds();
        let ceiling = next_attempt(50).signed_duration_since(now).num_seconds();
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
        use registry_scheduling_core::{
            ArrivalOffering, ExactTimeOffering, HoldPolicy, OfferingPolicy, PolicyIdentity,
            SchedulingMode, SchedulingPolicy, ServicePolicy,
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
                max_recipients: 1,
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
            scheduling: PolicyIdentity {
                id: "standalone".to_owned(),
                version: 1,
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
                max_per_caller: 2,
                because: "test".to_owned(),
            },
            hooks: Vec::new(),
        };
        assert_eq!(offering_pool_ids(&policy), vec!["north".to_owned()]);
    }

    #[test]
    fn a_companion_lock_collision_names_the_colliding_role_and_says_to_wait() {
        let error = AuditError::SinkLocked {
            path: "/var/lib/scheduling/audit.schedulingctl.jsonl.lock".to_owned(),
            role: Some("schedulingctl".to_owned()),
        };
        let message = describe_audit_destination_failure(&error);
        assert!(message.contains("schedulingctl"), "{message}");
        assert!(message.contains("wait"), "{message}");
        assert!(!message.contains("stop it"), "{message}");
    }

    #[test]
    fn a_service_lock_collision_says_to_stop_the_other_process() {
        let error = AuditError::SinkLocked {
            path: "/var/lib/scheduling/audit.jsonl.lock".to_owned(),
            role: None,
        };
        let message = describe_audit_destination_failure(&error);
        assert!(message.contains("stop it"), "{message}");
    }
}
