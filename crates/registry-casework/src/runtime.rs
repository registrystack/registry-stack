use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use clap::{Arg, Command};
use registry_casework_core::ReviewContextProvider;
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_config::{
    DeclaredPosture, Posture, SecretError, SecretReference, SecretResolver,
};
use registry_platform_crypto::delivery_signature::{self, DeliveryKey, DeliveryKeys};
#[cfg(feature = "postgres-test")]
use registry_platform_dispatch::postgres::DispatchOutcome;
use registry_platform_dispatch::postgres::{DispatchWorker, Disposition, WorkerConfig};
use registry_platform_httputil::OutboundClientBuilder;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing_subscriber::filter::LevelFilter;

mod completion;
pub use completion::CompletionBacklog;

use crate::{
    router, CaseworkAuthenticator, CaseworkService, HttpState, PostgresStore, RuntimeConfig,
};

pub(crate) struct ReviewCompletionTarget {
    url: String,
    keys: DeliveryKeys,
    timeout: Duration,
    maximum_attempts: u32,
    retry: Duration,
}

fn completion_key_path(id: &str, member: &str) -> String {
    format!("reviewCompletionDestinations.{id}.{member}")
}

fn resolve_completion_key(
    secrets: &SecretResolver,
    path: &str,
    reference: &SecretReference,
) -> Result<DeliveryKey, CompletionKeyError> {
    let secret = secrets
        .resolve_binary_reference(reference)
        .map_err(|reason| CompletionKeyError::Unavailable {
            path: path.to_owned(),
            reason,
        })?;
    let bytes = secret.expose_secret();
    DeliveryKey::new(bytes).map_err(|source| CompletionKeyError::Invalid {
        path: path.to_owned(),
        length: bytes.len(),
        trailing_newline: bytes.ends_with(b"\n"),
        source,
    })
}

/// Resolve every configured completion destination and its signing keys.
pub(crate) fn review_completion_targets(
    configured: &BTreeMap<String, crate::ReviewCompletionRuntimeConfig>,
    secrets: &SecretResolver,
) -> Result<BTreeMap<String, Arc<ReviewCompletionTarget>>, Vec<CompletionKeyError>> {
    use crate::config::{CURRENT_COMPLETION_KEY, PREVIOUS_COMPLETION_KEY};

    let mut targets = BTreeMap::new();
    let mut errors = Vec::new();
    for (id, target) in configured {
        let current_path = completion_key_path(id, CURRENT_COMPLETION_KEY);
        let previous_path = completion_key_path(id, PREVIOUS_COMPLETION_KEY);
        let current = resolve_completion_key(secrets, &current_path, &target.hmac_sha256_key_ref);
        let previous = target
            .previous_hmac_sha256_key_ref
            .as_ref()
            .map(|reference| resolve_completion_key(secrets, &previous_path, reference))
            .transpose();
        let current = current.map_err(|error| errors.push(error));
        let previous = previous.map_err(|error| errors.push(error));
        let (Ok(current), Ok(previous)) = (current, previous) else {
            continue;
        };
        let Ok(keys) = DeliveryKeys::new(current, previous) else {
            errors.push(CompletionKeyError::PreviousEqualsCurrent {
                current: current_path,
                previous: previous_path,
            });
            continue;
        };
        targets.insert(
            id.clone(),
            Arc::new(ReviewCompletionTarget {
                url: target.url.clone(),
                keys,
                timeout: Duration::from_millis(target.attempt_timeout_milliseconds),
                maximum_attempts: target.maximum_attempts,
                retry: Duration::from_secs(target.retry_delay_seconds),
            }),
        );
    }
    let labeled_keys = targets
        .iter()
        .flat_map(|(id, target)| {
            std::iter::once((
                completion_key_path(id, CURRENT_COMPLETION_KEY),
                target.keys.current(),
            ))
            .chain(
                target
                    .keys
                    .previous()
                    .map(|key| (completion_key_path(id, PREVIOUS_COMPLETION_KEY), key)),
            )
        })
        .collect::<Vec<_>>();
    if let Err(error) = delivery_signature::distinct_delivery_keys(
        labeled_keys.iter().map(|(path, key)| (path.as_str(), *key)),
    ) {
        errors.push(CompletionKeyError::Repeated {
            first: error.first().to_owned(),
            second: error.second().to_owned(),
        });
    }
    if errors.is_empty() {
        Ok(targets)
    } else {
        Err(errors)
    }
}

fn review_completion_client() -> Result<reqwest::Client, RuntimeError> {
    OutboundClientBuilder::new()
        .try_build()
        .map_err(|_| RuntimeError::CompletionConfiguration)
}

/// The completion delivery worker: one lane, so each delivery is leased
/// immediately before its remote call and a slow receiver never holds a
/// lease on the rows behind it.
async fn review_completion_worker(
    store: PostgresStore,
    targets: BTreeMap<String, Arc<ReviewCompletionTarget>>,
) -> Result<
    DispatchWorker<completion::CompletionStore, completion::CompletionTransport>,
    RuntimeError,
> {
    let targets = Arc::new(targets);
    let dispatcher = completion::completion_dispatcher(store, Arc::clone(&targets)).await?;
    let transport = completion::CompletionTransport::new(review_completion_client()?, targets);
    Ok(DispatchWorker::new(
        dispatcher,
        Arc::new(transport),
        WorkerConfig {
            concurrency: NonZeroUsize::MIN,
            idle_poll: Duration::from_secs(1),
        },
    ))
}

fn completion_failure_diagnostic(destination: &str, attempt: i32, disposition: Disposition) {
    tracing::warn!(
        destination,
        attempt,
        failure_class = "delivery_failed",
        "Casework completion attempt failed"
    );
    if matches!(
        disposition,
        Disposition::DeadLettered | Disposition::Expired
    ) {
        tracing::warn!(
            destination,
            attempt,
            terminal_state = disposition.as_str(),
            "Casework completion delivery exhausted"
        );
    }
}

async fn validate_retained_completion_destinations(
    store: &PostgresStore,
    configured: &BTreeMap<String, crate::ReviewCompletionRuntimeConfig>,
) -> Result<(), RuntimeError> {
    let client = store.client().await?;
    let retained = client
        .query(
            "SELECT DISTINCT destination_id
               FROM casework_review_completion_outbox
              WHERE state IN ('pending','leased')
                AND retained_until>transaction_timestamp()",
            &[],
        )
        .await
        .map_err(crate::StoreError::Postgres)?;
    if retained
        .iter()
        .map(|row| row.get::<_, String>(0))
        .any(|destination| !configured.contains_key(&destination))
    {
        return Err(RuntimeError::CompletionConfiguration);
    }
    Ok(())
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn validate_retained_completion_destinations_for_test(
    store: &PostgresStore,
    destination_ids: &[&str],
) -> Result<(), RuntimeError> {
    let configured = destination_ids
        .iter()
        .map(|id| {
            (
                (*id).to_owned(),
                crate::ReviewCompletionRuntimeConfig {
                    url: "http://127.0.0.1/completion".to_owned(),
                    hmac_sha256_key_ref: SecretReference::parse("secret:env/TEST").unwrap(),
                    previous_hmac_sha256_key_ref: None,
                    attempt_timeout_milliseconds: 1_000,
                    maximum_attempts: 1,
                    retry_delay_seconds: 1,
                },
            )
        })
        .collect();
    validate_retained_completion_destinations(store, &configured).await
}

#[cfg(feature = "postgres-test")]
fn test_completion_targets(
    destination_id: &str,
    url: String,
    signing_key: &str,
    maximum_attempts: u32,
) -> Result<completion::CompletionTargets, crate::ReviewRuntimeError> {
    Ok(Arc::new(BTreeMap::from([(
        destination_id.to_owned(),
        Arc::new(ReviewCompletionTarget {
            url,
            keys: DeliveryKeys::new(
                DeliveryKey::new(signing_key.as_bytes())
                    .map_err(|_| crate::ReviewRuntimeError::Invalid)?,
                None,
            )
            .expect("one validated key"),
            timeout: Duration::from_secs(30),
            maximum_attempts,
            retry: Duration::from_secs(1),
        }),
    )])))
}

/// Deliver due completions to one destination until none is due, one at a
/// time, as the worker's single lane does.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn dispatch_review_completions_once_for_test(
    store: PostgresStore,
    destination_id: &str,
    url: String,
    signing_key: &str,
) -> Result<(), crate::ReviewRuntimeError> {
    let targets = test_completion_targets(destination_id, url, signing_key, 3)?;
    let dispatcher = completion::completion_dispatcher(store, Arc::clone(&targets)).await?;
    let client = review_completion_client().map_err(|_| crate::ReviewRuntimeError::Invalid)?;
    let transport = completion::CompletionTransport::new(client, targets);
    for _ in 0..50 {
        match dispatcher.dispatch_once(&transport).await {
            Ok(DispatchOutcome::Idle) => break,
            Ok(_) => {}
            Err(_) => return Err(crate::StoreError::Unavailable.into()),
        }
    }
    Ok(())
}

/// One leased completion delivery, held by a test between its claim and
/// its finish.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub struct ReviewCompletionLeaseForTest(
    registry_platform_dispatch::postgres::LeasedJob<crate::LeasedReviewCompletion>,
);

#[cfg(feature = "postgres-test")]
impl ReviewCompletionLeaseForTest {
    #[must_use]
    pub fn attempt(&self) -> i16 {
        self.0.attempt
    }

    #[must_use]
    pub fn event(&self) -> &registry_casework_core::ReviewCompletion {
        &self.0.job.event
    }

    #[must_use]
    pub fn destination_id(&self) -> &str {
        &self.0.job.destination_id
    }

    #[must_use]
    pub fn recipient_binding(&self) -> &str {
        &self.0.job.recipient_binding
    }
}

/// Lease the next due completion delivery as a worker configured with only
/// `destination_id`, allowing `maximum_attempts`, would, without sending it.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn claim_review_completion_for_test(
    store: PostgresStore,
    destination_id: &str,
    maximum_attempts: u32,
) -> Result<Option<ReviewCompletionLeaseForTest>, crate::ReviewRuntimeError> {
    let targets = test_completion_targets(
        destination_id,
        "http://127.0.0.1/completion".to_owned(),
        "synthetic-test-key-not-for-use!!",
        maximum_attempts,
    )?;
    let dispatcher = completion::completion_dispatcher(store, targets).await?;
    let claim = dispatcher
        .claim()
        .await
        .map_err(|_| crate::StoreError::Unavailable)?;
    Ok(claim.leased().map(ReviewCompletionLeaseForTest))
}

/// Record the outcome of a leased completion delivery under its lease.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn finish_review_completion_for_test(
    store: PostgresStore,
    destination_id: &str,
    maximum_attempts: u32,
    lease: &ReviewCompletionLeaseForTest,
    delivered: bool,
) -> Result<(), crate::ReviewRuntimeError> {
    let targets = test_completion_targets(
        destination_id,
        "http://127.0.0.1/completion".to_owned(),
        "synthetic-test-key-not-for-use!!",
        maximum_attempts,
    )?;
    let dispatcher = completion::completion_dispatcher(store, targets).await?;
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
        .map_err(|_| crate::StoreError::Unavailable)?;
    Ok(())
}

async fn deliver_review_completion(
    client: &reqwest::Client,
    target: &ReviewCompletionTarget,
    delivery: &crate::LeasedReviewCompletion,
) -> bool {
    let Ok(body) = serde_json::to_vec(&delivery.event) else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) else {
        return false;
    };
    let timestamp = now.as_secs();
    let id = delivery.event.event_id.to_string();
    let Ok(signature) = delivery_signature::sign(&target.keys, &id, timestamp, &body) else {
        return false;
    };
    let Ok(response) = client
        .post(&target.url)
        .timeout(target.timeout)
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .header("webhook-id", id)
        .header("webhook-timestamp", timestamp.to_string())
        .header("webhook-signature", signature)
        .header("registry-recipient-binding", &delivery.recipient_binding)
        .body(body)
        .send()
        .await
    else {
        return false;
    };
    // Acknowledgement is decided from the status line. Dropping the response
    // avoids buffering a receiver body or waiting for it to finish streaming.
    completion_acknowledged(response.status())
}

fn completion_acknowledged(status: reqwest::StatusCode) -> bool {
    status.is_success()
}

#[must_use]
pub fn command() -> Command {
    Command::new("casework")
        .version(registry_platform_buildinfo::DISPLAY_VERSION)
        .about("Run and maintain Registry Casework")
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
                .value_name("POSTURE")
                .help("Declared posture: development or production. Unset means production."),
        )
        .subcommand_required(true)
        .subcommand(Command::new("serve").about("Run the Casework HTTP service"))
}

/// `CASEWORK_LOG` is a closed vocabulary, not a tracing filter directive: it
/// accepts exactly `error`, `warn`, or `info`, and the level applies to the
/// Casework crates only. Any other value, including a tracing directive that
/// would otherwise enable a dependency's own debug or trace logging, is
/// refused rather than silently accepted.
pub fn operational_log_level(value: Option<&str>) -> Result<LevelFilter, RuntimeError> {
    match value.unwrap_or("info") {
        "error" => Ok(LevelFilter::ERROR),
        "warn" => Ok(LevelFilter::WARN),
        "info" => Ok(LevelFilter::INFO),
        _ => Err(RuntimeError::Logging),
    }
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

/// Build the read-only providers the package declares from exact captured exports.
pub fn build_context_providers(
    config: &RuntimeConfig,
    package: &crate::LoadedCaseworkPackage,
    secrets: &SecretResolver,
    posture: Posture,
) -> Result<Vec<Arc<dyn ReviewContextProvider>>, RuntimeError> {
    let project = package.project();
    let mut providers: Vec<Arc<dyn ReviewContextProvider>> = Vec::new();
    for provider in &project.context_providers {
        let Some(binding) = config.context_providers.get(&provider.deployment_ref) else {
            continue;
        };
        let unserved = registry_casework_breg::unserved_capabilities(project, provider);
        if !unserved.is_empty() {
            return Err(RuntimeError::UnservedContextCapability(
                unserved
                    .iter()
                    .map(|finding| {
                        format!(
                            "\n  {}\n  next: {}",
                            finding.message, finding.suggested_action
                        )
                    })
                    .collect(),
            ));
        }
        let description = provider
            .description
            .as_deref()
            .and_then(|path| package.context_export(path))
            .ok_or_else(|| RuntimeError::ContextProviderConfiguration(provider.id.clone()))?;
        let built = registry_casework_breg::build_provider(
            binding,
            provider,
            description,
            secrets,
            posture,
        )
        .map_err(|_| RuntimeError::ContextProviderConfiguration(provider.id.clone()))?;
        providers.push(Arc::new(built));
    }
    if config.context_providers.keys().any(|deployment| {
        !project
            .context_providers
            .iter()
            .any(|provider| &provider.deployment_ref == deployment)
    }) {
        return Err(RuntimeError::ContextProviderConfiguration(String::new()));
    }
    Ok(providers)
}

/// Refuse to serve a database whose activation ledger does not name this
/// configuration: no package applied, another database's identity, another
/// package, or a split-role activation whose runtime credential can now write the ledger,
/// or a runtime credential that cannot write the ledger and does not hold
/// the grants a split-role apply issues it.
/// It only reads, and returns the role mode the runtime credential has.
pub async fn check_activation(
    store: &PostgresStore,
    database_id: &str,
    package_digest: &str,
    posture: Posture,
) -> Result<crate::RoleMode, RuntimeError> {
    let active = store
        .active_activation()
        .await?
        .ok_or(RuntimeError::NotActivated)?;
    if active.database_id != database_id {
        return Err(RuntimeError::DatabaseIdMismatch);
    }
    if active.package_digest != package_digest {
        return Err(RuntimeError::PackageNotActive {
            active: active.package_digest,
            configured: package_digest.to_owned(),
        });
    }
    if active.posture != posture {
        return Err(RuntimeError::ActivationPostureMismatch(active.posture));
    }
    let (role_mode, grants_current) = store
        .effective_role()
        .await?
        .ok_or(RuntimeError::NotActivated)?;
    if active.role_mode == crate::RoleMode::Split && role_mode == crate::RoleMode::Single {
        return Err(RuntimeError::RoleModeWeakened {
            fix: store.role_mode_weakened_fix().await?,
        });
    }
    // The credential decides the mode, not the ledger row: a single-role
    // activation whose runtime credential was rotated to a separate role is
    // split, and serves only once apply has issued that role its grants.
    if role_mode == crate::RoleMode::Split && !grants_current {
        return Err(RuntimeError::RuntimeGrantsMissing);
    }
    Ok(role_mode)
}

/// Refuse to serve a package that strands in-flight work pinned under an
/// earlier package.
/// `apply` makes the same comparison, but a process still serving the
/// earlier package may admit work between that apply and this start, so the
/// runtime repeats it read-only before it serves.
pub async fn check_pinned_work(
    store: &PostgresStore,
    project: &registry_casework_core::CaseworkProject,
    providers: &[&dyn ReviewContextProvider],
    package_digest: &str,
) -> Result<(), RuntimeError> {
    let conflicts = crate::stranded_pinned_work(store, project, providers).await?;
    match crate::pinned_work_verdict(&conflicts, package_digest) {
        crate::PinnedWorkVerdict::Clear => Ok(()),
        crate::PinnedWorkVerdict::Refused => Err(RuntimeError::StrandedPinnedWork(
            crate::stranded_work_refusal(&conflicts, package_digest),
        )),
    }
}

pub async fn serve_from_path(
    path: impl AsRef<Path>,
    declared: DeclaredPosture,
) -> Result<(), RuntimeError> {
    let path = path.as_ref();
    let loaded =
        RuntimeConfig::load(path, declared).map_err(
            |error| match crate::config::startup_report(path, &error, declared) {
                Some(report) => RuntimeError::ConfigurationRefused(report),
                None => RuntimeError::Config(error),
            },
        )?;
    loaded.posture.log_startup();
    let config = loaded.config;
    let package = config.load_package()?;
    let package_digest = package.digest().to_owned();
    tracing::info!(package_digest = %package_digest, "verified Casework package");
    let project = package.project();
    let secrets = secret_resolver(&config)?;
    let audit = open_audit(&config, &secrets, None, declared.posture).await?;
    let store =
        PostgresStore::connect_runtime(&config.database, &secrets, loaded.development.as_ref())?
            .with_audit(audit.clone());
    store.ready().await?;
    validate_retained_completion_destinations(&store, &config.review_completion_destinations)
        .await?;

    let providers = build_context_providers(&config, &package, &secrets, declared.posture)?;
    let provider_refs = providers
        .iter()
        .map(|provider| provider.as_ref())
        .collect::<Vec<_>>();
    let role_mode = check_activation(
        &store,
        config.database_id(),
        &package_digest,
        declared.posture,
    )
    .await?;
    check_pinned_work(&store, project, &provider_refs, &package_digest).await?;
    if role_mode == crate::RoleMode::Single {
        tracing::warn!(
            role_mode = role_mode.as_str(),
            "{}",
            crate::SINGLE_ROLE_STATEMENT
        );
    } else {
        tracing::info!(role_mode = role_mode.as_str(), "Casework runtime role mode");
    }

    let (verifier, keys) = config
        .oidc_verifier(&secrets, loaded.development.as_ref())
        .await?;
    let authenticator = Arc::new(
        CaseworkAuthenticator::new(
            project,
            verifier,
            keys,
            config.authentication.oidc.human_identity.clone(),
        )
        .with_human_source_audiences(config.human_source_audiences(project))
        .with_delegated_staff_readers(
            config
                .authentication
                .oidc
                .delegated_staff_readers
                .clone()
                .unwrap_or_default(),
        ),
    );
    let task_authority = config
        .task_authority
        .as_ref()
        .map(|authority| {
            crate::task_grants::TaskAuthority::load(
                authority,
                &secrets,
                audit.identifiers(),
                declared.posture,
            )
        })
        .transpose()?;
    let service = CaseworkService::new(store.clone(), project.clone(), providers)?
        .with_task_authority(task_authority);
    let completion_worker = review_completion_worker(
        store.clone(),
        review_completion_targets(&config.review_completion_destinations, &secrets).map_err(
            |errors| {
                errors
                    .into_iter()
                    .next()
                    .expect("completion target refusal")
            },
        )?,
    )
    .await?;

    let (worker_stopped, worker_stops) = mpsc::channel(WORKER_STOP_CAPACITY);
    let mut workers = Vec::new();
    let worker_service = service.clone();
    workers.push(supervise("maintenance", worker_stopped.clone(), async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        let mut retention_ticks = 0_u8;
        loop {
            interval.tick().await;
            if let Err(error) = worker_service.process_due_review_clocks(100).await {
                tracing::warn!(error = %error, "Casework review clock pass did not complete");
            }
            retention_ticks = (retention_ticks + 1) % 30;
            if retention_ticks == 0 {
                if let Err(error) = worker_service.erase_expired_reviews().await {
                    tracing::warn!(error = %error, "Casework review retention pass did not complete");
                }
                if let Err(error) = worker_service.erase_expired_review_staffing().await {
                    tracing::warn!(error = %error, "Casework review staffing retention pass did not complete");
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
                if let Err(error) = worker_service.reconcile_review_absences(100).await {
                    tracing::warn!(error = %error, "Casework review absence-cover pass did not complete");
                }
            }
        }
    }));
    workers.push(supervise(
        "review completion delivery",
        worker_stopped.clone(),
        async move {
            // The worker runs until its shutdown sender closes, so the task
            // holds the sender for as long as it runs.
            let (_shutdown, shutdown) = tokio::sync::watch::channel(false);
            completion_worker.run(shutdown).await;
        },
    ));
    drop(worker_stopped);
    let metrics_state = crate::metrics::MetricsState::new(
        store,
        project
            .context_providers
            .iter()
            .map(|provider| provider.id.clone())
            .collect(),
        package_digest.clone(),
    );
    let app = router(HttpState {
        posture: loaded.posture,
        service,
        authenticator,
        project: Arc::new(project.clone()),
    });
    // Both sockets bind before either serves, so a metrics address already in
    // use refuses startup instead of leaving an API without its telemetry.
    let metrics = match &config.metrics_listener {
        Some(metrics_listener) => Some((
            tokio::net::TcpListener::bind(metrics_listener.bind.socket_addr())
                .await
                .map_err(RuntimeError::MetricsListen)?,
            crate::metrics::metrics_router(metrics_state, declared.posture),
        )),
        None => None,
    };
    let listener = tokio::net::TcpListener::bind(config.listener.bind.socket_addr())
        .await
        .map_err(RuntimeError::Listen)?;
    let served = serve_until_worker_stops(listener, app, metrics, worker_stops).await;
    for worker in workers {
        worker.abort();
    }
    served
}

/// Serve until a supervised background loop stops. The listener never stops on
/// its own, so a clean return means a worker stopped, and the process reports
/// that as a failure for whatever supervises it to restart. The optional
/// operator-private metrics listener serves beside it and stops with it.
async fn serve_until_worker_stops(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    metrics: Option<(tokio::net::TcpListener, axum::Router)>,
    stops: mpsc::Receiver<&'static str>,
) -> Result<(), RuntimeError> {
    let (api_stopped, mut metrics_stop) = tokio::sync::watch::channel(());
    let metrics = metrics.map(|(metrics_listener, metrics_app)| {
        tokio::spawn(async move {
            axum::serve(metrics_listener, metrics_app)
                .with_graceful_shutdown(async move {
                    let _ = metrics_stop.changed().await;
                })
                .await
        })
    });
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(worker_stop(stops))
        .await;
    drop(api_stopped);
    if let Some(metrics) = metrics {
        match metrics.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(error = %error, "the Casework metrics listener failed");
            }
            Err(error) => {
                tracing::error!(error = %error, "the Casework metrics listener stopped unexpectedly");
            }
        }
    }
    served.map_err(RuntimeError::Listen)?;
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

/// Open the Casework audit destination the runtime configuration names.
///
/// The service passes no `process`. A companion process (operator tooling or
/// a one-shot subcommand) that writes audit while the service may hold the
/// destination passes its role, and writes to the sibling file
/// [`registry_platform_audit::AuditDestination::for_process`] names under its
/// own single-writer lock, or to stderr when the destination is `stdout`.
pub async fn open_audit(
    config: &RuntimeConfig,
    secrets: &SecretResolver,
    process: Option<&str>,
    posture: Posture,
) -> Result<crate::CaseworkAudit, RuntimeError> {
    let audit_secret = resolve_audit_secret(secrets, config.audit.key.hash_key_ref.as_str())?;
    let audit_profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        audit_secret.expose_secret().to_vec(),
    ))
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
    let writer = AuditWriter::open(destination, posture)
        .await
        .map_err(|error| RuntimeError::AuditDestination(error.operator_description()))?;
    Ok(crate::CaseworkAudit::new(
        writer,
        audit_profile.key_hasher(),
    ))
}

/// Resolve the audit key, naming the reference on refusal.
///
/// The audit destination is keyed before the listener binds, so this refusal is the
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
    config
        .secret_providers
        .resolver()
        .map_err(|_| RuntimeError::SecretConfiguration)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone as _, Utc};
    use registry_platform_config::SecretProvider;
    use uuid::Uuid;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn completion_test_keys() -> DeliveryKeys {
        DeliveryKeys::new(DeliveryKey::new(&[b'k'; 32]).unwrap(), None).unwrap()
    }

    fn completion_config(
        current: &str,
        previous: Option<&str>,
    ) -> crate::ReviewCompletionRuntimeConfig {
        let mut value = serde_json::json!({
            "url": "https://receiver.example.test/completions",
            "hmacSha256KeyRef": current,
        });
        if let Some(previous) = previous {
            value["previousHmacSha256KeyRef"] = serde_json::json!(previous);
        }
        serde_json::from_value(value).unwrap()
    }

    fn completion_key_file(root: &Path, name: &str, bytes: &[u8]) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    #[test]
    fn completion_destinations_cannot_share_a_current_or_previous_signing_key() {
        let root = tempfile::tempdir().unwrap();
        completion_key_file(root.path(), "current", &[0; 32]);
        completion_key_file(root.path(), "other", &[1; 32]);
        completion_key_file(root.path(), "previous", &[0; 32]);
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).unwrap();
        let current_path = "reviewCompletionDestinations.first.hmacSha256KeyRef";
        for (destinations, second_path) in [
            (
                BTreeMap::from([
                    (
                        "first".to_owned(),
                        completion_config("secret:file/current", None),
                    ),
                    (
                        "second".to_owned(),
                        completion_config("secret:file/other", Some("secret:file/previous")),
                    ),
                ]),
                "reviewCompletionDestinations.second.previousHmacSha256KeyRef",
            ),
            (
                BTreeMap::from([
                    (
                        "first".to_owned(),
                        completion_config("secret:file/current", None),
                    ),
                    (
                        "second".to_owned(),
                        completion_config("secret:file/previous", None),
                    ),
                ]),
                "reviewCompletionDestinations.second.hmacSha256KeyRef",
            ),
        ] {
            let errors = review_completion_targets(&destinations, &secrets)
                .err()
                .unwrap();
            let [error] = errors.as_slice() else {
                panic!("expected one completion key refusal");
            };
            assert_eq!(
                error.to_string(),
                format!("{current_path} and {second_path} resolve to the same key bytes. Give {second_path} its own key by writing 32 new random bytes to another secret and referencing it there.")
            );
        }

        let previous_path = "reviewCompletionDestinations.first.previousHmacSha256KeyRef";
        let destinations = BTreeMap::from([(
            "first".to_owned(),
            completion_config("secret:file/current", Some("secret:file/previous")),
        )]);
        let errors = review_completion_targets(&destinations, &secrets)
            .err()
            .unwrap();
        let [error] = errors.as_slice() else {
            panic!("expected one completion key refusal");
        };
        assert_eq!(
            error.to_string(),
            format!("{previous_path} holds the same bytes as {current_path}. To rotate, write 32 new random bytes to the secret {current_path} references and keep the old bytes behind {previous_path}.")
        );
    }

    #[test]
    fn missing_completion_signing_key_reports_its_resolution_failure() {
        assert_completion_secret_failure(
            "missing",
            registry_platform_config::SecretError::Unavailable,
        );
    }

    #[test]
    fn empty_completion_signing_key_reports_its_resolution_failure() {
        assert_completion_secret_failure(
            "empty",
            registry_platform_config::SecretError::InvalidValue,
        );
    }

    fn assert_completion_secret_failure(name: &str, reason: registry_platform_config::SecretError) {
        let root = tempfile::tempdir().unwrap();
        completion_key_file(root.path(), "empty", b"");
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).unwrap();
        let destinations = BTreeMap::from([(
            "receiver".to_owned(),
            completion_config(&format!("secret:file/{name}"), None),
        )]);
        let errors = review_completion_targets(&destinations, &secrets)
            .err()
            .unwrap();
        let [error] = errors.as_slice() else {
            panic!("expected one completion key refusal");
        };
        assert_eq!(
            error.to_string(),
            format!("could not resolve reviewCompletionDestinations.receiver.hmacSha256KeyRef: {reason}. {}", reason.suggested_action())
        );
    }

    #[test]
    fn a_65_byte_completion_signing_key_reports_its_length_and_trailing_newline() {
        let root = tempfile::tempdir().unwrap();
        let mut bytes = [b'k'; 65];
        bytes[64] = b'\n';
        completion_key_file(root.path(), "oversized", &bytes);
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).unwrap();
        let destinations = BTreeMap::from([(
            "receiver".to_owned(),
            completion_config("secret:file/oversized", None),
        )]);
        let errors = review_completion_targets(&destinations, &secrets)
            .err()
            .unwrap();
        let [error] = errors.as_slice() else {
            panic!("expected one completion key refusal");
        };
        assert!(matches!(error, CompletionKeyError::Invalid { .. }));
        let message = error.to_string();
        assert!(message.contains("reviewCompletionDestinations.receiver.hmacSha256KeyRef"));
        assert!(message.contains("65 bytes"));
        assert!(message.contains("trailing newline: true"));
    }

    #[tokio::test]
    async fn completion_acknowledgement_does_not_read_an_unfinished_body() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        for status in [200, 202, 204] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 8192];
                assert!(stream.read(&mut buffer).await.unwrap() > 0);
                stream
                    .write_all(
                        format!("HTTP/1.1 {status} Accepted\r\nContent-Length: 99999999\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                std::future::pending::<()>().await;
            });
            let target = ReviewCompletionTarget {
                url: format!("http://{address}/completion"),
                keys: completion_test_keys(),
                timeout: Duration::from_secs(5),
                maximum_attempts: 3,
                retry: Duration::from_secs(1),
            };
            let delivery = crate::LeasedReviewCompletion {
                event: registry_casework_core::ReviewCompletion {
                    event_type: registry_casework_core::ReviewCompletionType::ReviewCompleted,
                    event_id: Uuid::new_v4(),
                    request_id: Uuid::new_v4(),
                    result_id: Uuid::new_v4(),
                    completed_at: Utc::now(),
                },
                destination_id: "receiver".to_owned(),
                recipient_binding: "canary-subject".to_owned(),
            };
            let client = OutboundClientBuilder::new().try_build().unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                deliver_review_completion(&client, &target, &delivery),
            )
            .await;
            server.abort();
            assert!(
                result.unwrap(),
                "status {status} must acknowledge without reading the body"
            );
        }
    }
    #[tokio::test]
    async fn review_completion_delivery_is_signed_and_stable_after_lost_ack() {
        let server = MockServer::start().await;
        let event = registry_casework_core::ReviewCompletion {
            event_type: registry_casework_core::ReviewCompletionType::ReviewCompleted,
            event_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("event id"),
            request_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                .expect("request id"),
            result_id: Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("result id"),
            completed_at: Utc
                .with_ymd_and_hms(2026, 9, 19, 12, 34, 56)
                .single()
                .expect("completion timestamp"),
        };
        Mock::given(method("POST"))
            .and(path("/completion"))
            .and(header("webhook-id", "11111111-1111-4111-8111-111111111111"))
            .and(header("registry-recipient-binding", "registry-service"))
            .and(body_json(&event))
            .respond_with(ResponseTemplate::new(503))
            .with_priority(1)
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/completion"))
            .and(header("webhook-id", "11111111-1111-4111-8111-111111111111"))
            .and(header("registry-recipient-binding", "registry-service"))
            .and(body_json(&event))
            .respond_with(ResponseTemplate::new(204))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;
        let client = OutboundClientBuilder::new()
            .try_build()
            .expect("completion client");
        let target = ReviewCompletionTarget {
            url: format!("{}/completion", server.uri()),
            keys: completion_test_keys(),
            timeout: Duration::from_secs(1),
            maximum_attempts: 3,
            retry: Duration::from_secs(1),
        };
        let delivery = crate::LeasedReviewCompletion {
            event,
            destination_id: "registry-completion".to_owned(),
            recipient_binding: "registry-service".to_owned(),
        };

        assert!(!deliver_review_completion(&client, &target, &delivery).await);
        assert!(deliver_review_completion(&client, &target, &delivery).await);

        let attempts = server.received_requests().await.expect("recorded requests");
        let [first, second] = attempts.as_slice() else {
            panic!("expected exactly two completion attempts");
        };
        assert_eq!(first.headers["webhook-id"], second.headers["webhook-id"]);
        assert_eq!(first.body, second.body);
        for attempt in [first, second] {
            let header = |name: &str| attempt.headers[name].to_str().unwrap();
            delivery_signature::verify(
                &target.keys,
                delivery_signature::SignedContent {
                    id: header("webhook-id"),
                    timestamp: header("webhook-timestamp"),
                    signature: header("webhook-signature"),
                    body: &attempt.body,
                },
                SystemTime::now(),
                delivery_signature::DELIVERY_TOLERANCE,
            )
            .unwrap();
        }

        Mock::given(method("POST"))
            .and(path("/nonempty-success"))
            .respond_with(ResponseTemplate::new(200).set_body_string("accepted"))
            .expect(1)
            .mount(&server)
            .await;
        let nonempty_success_target = ReviewCompletionTarget {
            url: format!("{}/nonempty-success", server.uri()),
            keys: completion_test_keys(),
            timeout: Duration::from_secs(1),
            maximum_attempts: 3,
            retry: Duration::from_secs(1),
        };
        assert!(
            deliver_review_completion(&client, &nonempty_success_target, &delivery).await,
            "any 2xx acknowledges completion regardless of its body"
        );
        for status in [200, 202, 204, 299] {
            assert!(completion_acknowledged(
                reqwest::StatusCode::from_u16(status).unwrap()
            ));
        }

        Mock::given(method("POST"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/redirect-target", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/redirect-target"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        let redirect_target = ReviewCompletionTarget {
            url: format!("{}/redirect", server.uri()),
            keys: completion_test_keys(),
            timeout: Duration::from_secs(1),
            maximum_attempts: 3,
            retry: Duration::from_secs(1),
        };
        assert!(!deliver_review_completion(&client, &redirect_target, &delivery).await);
    }

    #[tokio::test]
    async fn review_completion_signs_the_exact_bytes_it_sends() {
        use registry_platform_crypto::delivery_signature::{
            verify, SignedContent, DELIVERY_TOLERANCE,
        };

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/completion"))
            .and(header("webhook-id", "11111111-1111-4111-8111-111111111111"))
            .and(header("registry-recipient-binding", "registry-service"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let client = OutboundClientBuilder::new()
            .try_build()
            .expect("completion client");
        let root = tempfile::tempdir().unwrap();
        let current_bytes = [0; 32];
        let previous_bytes = [0xff; 32];
        completion_key_file(root.path(), "current", &current_bytes);
        completion_key_file(root.path(), "previous", &previous_bytes);
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).unwrap();
        let mut configured = completion_config("secret:file/current", Some("secret:file/previous"));
        configured.url = format!("{}/completion", server.uri());
        let targets = review_completion_targets(
            &BTreeMap::from([("receiver".to_owned(), configured)]),
            &secrets,
        )
        .unwrap();
        let target = &targets["receiver"];
        let delivery = crate::LeasedReviewCompletion {
            event: registry_casework_core::ReviewCompletion {
                event_type: registry_casework_core::ReviewCompletionType::ReviewCompleted,
                event_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111")
                    .expect("event id"),
                request_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                    .expect("request id"),
                result_id: Uuid::parse_str("33333333-3333-4333-8333-333333333333")
                    .expect("result id"),
                completed_at: Utc
                    .with_ymd_and_hms(2026, 9, 19, 12, 34, 56)
                    .single()
                    .expect("completion timestamp"),
            },
            destination_id: "registry-completion".to_owned(),
            recipient_binding: "registry-service".to_owned(),
        };

        assert!(deliver_review_completion(&client, target, &delivery).await);
        let received = server.received_requests().await.expect("recorded requests");
        assert_eq!(received.len(), 1);
        let request = &received[0];
        let header = |name: &str| request.headers[name].to_str().unwrap();
        let content = SignedContent {
            id: header("webhook-id"),
            timestamp: header("webhook-timestamp"),
            signature: header("webhook-signature"),
            body: &request.body,
        };
        let entries: Vec<_> = content.signature.split(' ').collect();
        assert_eq!(entries.len(), 2);
        for (signature, key_bytes) in entries.into_iter().zip([current_bytes, previous_bytes]) {
            let keys = DeliveryKeys::new(DeliveryKey::new(&key_bytes).unwrap(), None).unwrap();
            verify(
                &keys,
                SignedContent {
                    signature,
                    ..content
                },
                SystemTime::now(),
                DELIVERY_TOLERANCE,
            )
            .unwrap();
        }
        assert_eq!(header("webhook-id"), delivery.event.event_id.to_string());
        assert_eq!(header("accept"), "application/json");
        assert_eq!(header("content-type"), "application/json");
        let names: std::collections::BTreeSet<_> = request
            .headers
            .keys()
            .map(|name| name.as_str())
            .filter(|name| !matches!(*name, "host" | "content-length" | "connection"))
            .collect();
        assert_eq!(
            names,
            std::collections::BTreeSet::from([
                "accept",
                "content-type",
                "registry-recipient-binding",
                "webhook-id",
                "webhook-signature",
                "webhook-timestamp",
            ])
        );
        assert!(verify(
            &completion_test_keys(),
            content,
            SystemTime::now(),
            DELIVERY_TOLERANCE,
        )
        .is_err());
    }

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
            !message.contains("secret:file/casework-audit-key"),
            "the failure repeats the reference: {message}"
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
            serve_until_worker_stops(listener, axum::Router::new(), None, stops),
        )
        .await
        .expect("the listener stops after a background worker stops");
        assert!(matches!(served, Err(RuntimeError::WorkerStopped)));
    }

    #[tokio::test]
    async fn the_metrics_listener_serves_beside_the_api_and_stops_with_it() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local listener");
        let metrics = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local metrics listener");
        let metrics_address = metrics.local_addr().expect("metrics address");
        let metrics_app =
            axum::Router::new().route("/version", axum::routing::get(|| async { "ok" }));
        let (stopped, stops) = mpsc::channel(1);
        let served = tokio::spawn(serve_until_worker_stops(
            listener,
            axum::Router::new(),
            Some((metrics, metrics_app)),
            stops,
        ));

        let mut stream = tokio::net::TcpStream::connect(metrics_address)
            .await
            .expect("reach the metrics listener");
        stream
            .write_all(b"GET /version HTTP/1.1\r\nhost: metrics\r\nconnection: close\r\n\r\n")
            .await
            .expect("send a request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read the response");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("ok"), "{response}");

        stopped
            .send("clock")
            .await
            .expect("report a stopped worker");
        let served = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the listeners stop after a background worker stops")
            .expect("the serving task completes");
        assert!(matches!(served, Err(RuntimeError::WorkerStopped)));
        assert!(
            tokio::net::TcpStream::connect(metrics_address)
                .await
                .is_err(),
            "the metrics listener closes with the API listener"
        );
    }

    #[test]
    fn serve_is_the_only_subcommand() {
        let command = command();
        let names: Vec<&str> = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        assert_eq!(names, ["serve"]);
    }

    #[test]
    fn operational_log_level_is_a_closed_vocabulary() {
        assert_eq!(
            operational_log_level(None).expect("default log level"),
            LevelFilter::INFO
        );
        assert_eq!(
            operational_log_level(Some("info")).expect("info level"),
            LevelFilter::INFO
        );
        assert_eq!(
            operational_log_level(Some("warn")).expect("warn level"),
            LevelFilter::WARN
        );
        assert_eq!(
            operational_log_level(Some("error")).expect("error level"),
            LevelFilter::ERROR
        );
        assert!(operational_log_level(Some("debug")).is_err());
        assert!(operational_log_level(Some("trace")).is_err());
        assert!(operational_log_level(Some("registry_casework=trace")).is_err());
        assert!(operational_log_level(Some("")).is_err());
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("[platform.activation.posture-mismatch] {}\n  next: {}", crate::activation::posture_mismatch(*.0).0, crate::activation::posture_mismatch(*.0).1)]
    ActivationPostureMismatch(Posture),
    #[error("the Casework command arguments are invalid")]
    Arguments,
    #[error(transparent)]
    Config(#[from] crate::RuntimeConfigError),
    /// The runtime file refused at startup, with every finding at its
    /// position in the file.
    #[error("the Casework runtime configuration was refused")]
    ConfigurationRefused(registry_platform_yaml::Report),
    #[error("the Casework project is invalid")]
    Project(#[from] registry_casework_core::ConfigLoadError),
    #[error(
        "the Casework secret-provider configuration is invalid; \
         secretProviders.file.root must be an absolute path"
    )]
    SecretConfiguration,
    #[error("the Casework review-context provider {0} is not configured for its declared capability and export")]
    ContextProviderConfiguration(String),
    /// Each line pair names what needs the capability and how to fix it.
    #[error("the Casework project needs review context its BReg source does not serve{0}")]
    UnservedContextCapability(String),
    #[error(
        "no Casework package has been applied to this database; run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`"
    )]
    NotActivated,
    #[error("{}", crate::database_id_mismatch_message())]
    DatabaseIdMismatch,
    #[error(
        "the active Casework package in this database is {active}, not the configured package {configured}; run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`"
    )]
    PackageNotActive { active: String, configured: String },
    #[error("{0}")]
    StrandedPinnedWork(String),
    /// `fix` names what to do: reassign the objects, revoke the privileges,
    /// or drop the triggers that give the runtime role that authority, or,
    /// when a privilege apply issues or revokes gives it, rerun apply.
    #[error(
        "the active Casework package was applied split-role, but the runtime credential can now write the activation ledger; {fix}"
    )]
    RoleModeWeakened { fix: String },
    /// Reassigning a Casework object back to the migration role also takes
    /// away the grants apply issued the runtime role on it, and a runtime
    /// credential rotated to a separate role since the last apply holds none.
    #[error(
        "the Casework runtime role cannot write the activation ledger but does not hold the grants a split-role apply issues it; run `caseworkctl apply --runtime-config FILE` to issue them"
    )]
    RuntimeGrantsMissing,
    #[error("the Casework audit destination could not be initialized")]
    Audit,
    #[error("the Casework audit destination could not be initialized: {0}")]
    AuditSecret(String),
    #[error("the Casework audit destination could not be opened: {0}")]
    AuditDestination(String),
    #[error("the Casework review completion destination configuration is invalid")]
    CompletionConfiguration,
    #[error(transparent)]
    CompletionKey(#[from] CompletionKeyError),
    #[error("the CASEWORK_LOG level is invalid; it must be one of error, warn, or info")]
    Logging,
    #[error(transparent)]
    Store(#[from] crate::StoreError),
    #[error(transparent)]
    Service(#[from] crate::ServiceError),
    #[error("the Casework listener failed")]
    Listen(#[source] std::io::Error),
    #[error("the Casework metrics listener at metricsListener.bind failed")]
    MetricsListen(#[source] std::io::Error),
    #[error("a Casework background worker stopped")]
    WorkerStopped,
}

/// A value-free refusal of a configured completion signing key.
#[derive(Debug, Error)]
pub enum CompletionKeyError {
    #[error("could not resolve {path}: {reason}. {}", reason.suggested_action())]
    Unavailable {
        path: String,
        #[source]
        reason: SecretError,
    },
    #[error("{path} has {length} bytes (trailing newline: {trailing_newline}). {source}")]
    Invalid {
        path: String,
        length: usize,
        trailing_newline: bool,
        source: delivery_signature::DeliveryKeyError,
    },
    #[error("{first} and {second} resolve to the same key bytes. Give {second} its own key by writing 32 new random bytes to another secret and referencing it there.")]
    Repeated { first: String, second: String },
    #[error("{previous} holds the same bytes as {current}. To rotate, write 32 new random bytes to the secret {current} references and keep the old bytes behind {previous}.")]
    PreviousEqualsCurrent { current: String, previous: String },
}

impl RuntimeError {
    /// The reader's report when startup refused the runtime file or the
    /// Casework project, so `casework` prints its CFG-DIAG-2 lines unchanged
    /// after its own one-sentence refusal.
    #[must_use]
    pub fn configuration_report(&self) -> Option<&registry_platform_yaml::Report> {
        match self {
            Self::ConfigurationRefused(report)
            | Self::Project(registry_casework_core::ConfigLoadError::Refused(report))
            | Self::Config(crate::RuntimeConfigError::Project(
                registry_casework_core::ConfigLoadError::Refused(report),
            )) => Some(report),
            _ => None,
        }
    }
}
