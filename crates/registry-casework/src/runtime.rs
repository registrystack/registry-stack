use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::{Arg, Command};
use registry_casework_breg::BregBinding;
use registry_casework_core::SourceAdapter;
use registry_platform_audit::{AuditProfile, AuditWriter};
use registry_platform_config::SecretResolver;
use registry_platform_httputil::{read_bounded, BearerToken, OutboundClientBuilder};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Interval, MissedTickBehavior};
use tracing_subscriber::filter::LevelFilter;

use crate::{
    router, CaseworkAuthenticator, CaseworkService, HttpState, PostgresStore, RuntimeConfig,
};

struct ReviewCompletionTarget {
    url: String,
    credential: ReviewCompletionCredential,
    timeout: Duration,
    maximum_attempts: u32,
    retry: Duration,
}

const MAXIMUM_COMPLETION_SECRET_BYTES: usize = 8 * 1024;

/// The secret a completion destination presents on every wake-up.
enum ReviewCompletionCredential {
    Bearer(BearerToken),
    Header {
        name: reqwest::header::HeaderName,
        value: reqwest::header::HeaderValue,
    },
}

impl ReviewCompletionCredential {
    fn from_config(header: Option<&str>, secret: &[u8]) -> Result<Self, RuntimeError> {
        let Some(header) = header else {
            return completion_bearer_token(secret).map(Self::Bearer);
        };
        let name = reqwest::header::HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| RuntimeError::CompletionConfiguration)?;
        // The same header-safe subset a bearer credential is held to: visible
        // ASCII only, so the secret cannot fold or inject a header.
        if secret.is_empty()
            || secret.len() > MAXIMUM_COMPLETION_SECRET_BYTES
            || !secret.iter().all(u8::is_ascii_graphic)
        {
            return Err(RuntimeError::CompletionConfiguration);
        }
        let mut value = reqwest::header::HeaderValue::from_bytes(secret)
            .map_err(|_| RuntimeError::CompletionConfiguration)?;
        value.set_sensitive(true);
        Ok(Self::Header { name, value })
    }

    fn header(&self) -> (reqwest::header::HeaderName, reqwest::header::HeaderValue) {
        match self {
            Self::Bearer(token) => (
                reqwest::header::AUTHORIZATION,
                token.authorization_header_value(),
            ),
            Self::Header { name, value } => (name.clone(), value.clone()),
        }
    }
}

struct ReviewCompletionDispatcher {
    store: PostgresStore,
    client: reqwest::Client,
    targets: BTreeMap<String, Arc<ReviewCompletionTarget>>,
}

struct OwnedReviewCompletion {
    delivery: crate::LeasedReviewCompletion,
    attempt_count: i32,
    lease_until: chrono::DateTime<chrono::Utc>,
}

impl ReviewCompletionDispatcher {
    fn new(
        store: PostgresStore,
        configured: &BTreeMap<String, crate::ReviewCompletionRuntimeConfig>,
        secrets: &SecretResolver,
    ) -> Result<Self, RuntimeError> {
        let mut targets = BTreeMap::new();
        for (id, target) in configured {
            let reference = target
                .secret_ref()
                .ok_or(RuntimeError::CompletionConfiguration)?;
            let secret = secrets
                .resolve(reference)
                .map_err(|_| RuntimeError::CompletionConfiguration)?;
            let credential = ReviewCompletionCredential::from_config(
                target.secret_header(),
                secret.expose_secret(),
            )?;
            targets.insert(
                id.clone(),
                Arc::new(ReviewCompletionTarget {
                    url: target.url.clone(),
                    credential,
                    timeout: Duration::from_millis(target.attempt_timeout_milliseconds),
                    maximum_attempts: target.maximum_attempts,
                    retry: Duration::from_secs(target.retry_delay_seconds),
                }),
            );
        }
        Ok(Self {
            store,
            client: OutboundClientBuilder::new()
                .try_build()
                .map_err(|_| RuntimeError::CompletionConfiguration)?,
            targets,
        })
    }

    async fn pass(&self) -> Result<(), crate::ReviewRuntimeError> {
        // Lease immediately before each remote call. Pre-leasing the whole pass
        // would let later rows expire while earlier receivers are still slow.
        for _ in 0..50 {
            let Some(owned) = self.lease_one().await? else {
                break;
            };
            let Some(target) = self.targets.get(&owned.delivery.destination_id) else {
                self.finish(&owned, false, 1, chrono::Utc::now()).await?;
                continue;
            };
            let delivered = deliver_review_completion(&self.client, target, &owned.delivery).await;
            let retry_at = chrono::Utc::now()
                + chrono::TimeDelta::from_std(target.retry)
                    .unwrap_or_else(|_| chrono::TimeDelta::seconds(30));
            self.finish(&owned, delivered, target.maximum_attempts, retry_at)
                .await?;
        }
        Ok(())
    }

    async fn lease_one(&self) -> Result<Option<OwnedReviewCompletion>, crate::ReviewRuntimeError> {
        let client = self.store.client().await?;
        // Runtime validation caps receiver timeouts at 30 seconds. The longer
        // lease avoids ordinary timeout overlap; the finish fence below still
        // protects a replacement owner after a process stall or lease recovery.
        let row = client
            .query_opt(
                "WITH due AS (
                    SELECT event_id FROM casework_review_completion_outbox
                    WHERE retained_until>transaction_timestamp()
                      AND next_attempt_at<=transaction_timestamp()
                      AND (state='pending' OR
                           (state='leased' AND lease_until<=transaction_timestamp()))
                    ORDER BY next_attempt_at,event_id LIMIT 1 FOR UPDATE SKIP LOCKED
                 ), leased AS (
                    UPDATE casework_review_completion_outbox o
                    SET state='leased',
                        lease_until=transaction_timestamp()+interval '60 seconds',
                        attempt_count=attempt_count+1
                    FROM due WHERE o.event_id=due.event_id
                    RETURNING o.event_id,o.destination_id,o.recipient_binding,
                              o.attempt_count,o.lease_until
                 )
                 SELECT l.event_id,e.request_id,e.result_id,e.completed_at,
                        l.destination_id,l.recipient_binding,l.attempt_count,l.lease_until
                 FROM leased l JOIN casework_review_terminal_events e ON e.event_id=l.event_id",
                &[],
            )
            .await?;
        Ok(row.map(|row| OwnedReviewCompletion {
            delivery: crate::LeasedReviewCompletion {
                event: registry_casework_core::ReviewCompletion {
                    event_type: registry_casework_core::ReviewCompletionType::ReviewCompleted,
                    event_id: row.get(0),
                    request_id: row.get(1),
                    result_id: row.get(2),
                    completed_at: row.get(3),
                },
                destination_id: row.get(4),
                recipient_binding: row.get(5),
            },
            attempt_count: row.get(6),
            lease_until: row.get(7),
        }))
    }

    async fn finish(
        &self,
        owned: &OwnedReviewCompletion,
        delivered: bool,
        maximum_attempts: u32,
        retry_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::ReviewRuntimeError> {
        let client = self.store.client().await?;
        if delivered {
            client
                .execute(
                    "UPDATE casework_review_completion_outbox
                     SET state='delivered',delivered_at=transaction_timestamp(),
                         lease_until=NULL,last_failure_class=NULL
                     WHERE event_id=$1 AND state='leased'
                       AND attempt_count=$2 AND lease_until=$3",
                    &[
                        &owned.delivery.event.event_id,
                        &owned.attempt_count,
                        &owned.lease_until,
                    ],
                )
                .await?;
        } else {
            client
                .execute(
                    "UPDATE casework_review_completion_outbox
                     SET state=CASE WHEN attempt_count >= $2 OR $3>=retained_until
                                    THEN 'exhausted' ELSE 'pending' END,
                         next_attempt_at=LEAST($3,retained_until - interval '1 microsecond'),
                         lease_until=NULL,last_failure_class='delivery_failed'
                     WHERE event_id=$1 AND state='leased'
                       AND attempt_count=$4 AND lease_until=$5",
                    &[
                        &owned.delivery.event.event_id,
                        &i32::try_from(maximum_attempts)
                            .map_err(|_| crate::ReviewRuntimeError::Invalid)?,
                        &retry_at,
                        &owned.attempt_count,
                        &owned.lease_until,
                    ],
                )
                .await?;
        }
        Ok(())
    }
}

fn completion_bearer_token(bytes: &[u8]) -> Result<BearerToken, RuntimeError> {
    let token = std::str::from_utf8(bytes).map_err(|_| RuntimeError::CompletionConfiguration)?;
    BearerToken::new(token.to_owned()).map_err(|_| RuntimeError::CompletionConfiguration)
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
                    bearer_token_ref: Some("secret:env/TEST".to_owned()),
                    auth: None,
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
#[doc(hidden)]
pub async fn dispatch_review_completions_once_for_test(
    store: PostgresStore,
    destination_id: &str,
    url: String,
    bearer_token: &str,
) -> Result<(), crate::ReviewRuntimeError> {
    let dispatcher = ReviewCompletionDispatcher {
        store,
        client: OutboundClientBuilder::new()
            .try_build()
            .expect("build test review completion client"),
        targets: BTreeMap::from([(
            destination_id.to_owned(),
            Arc::new(ReviewCompletionTarget {
                url,
                credential: ReviewCompletionCredential::Bearer(
                    BearerToken::new(bearer_token.to_owned())
                        .map_err(|_| crate::ReviewRuntimeError::Invalid)?,
                ),
                timeout: Duration::from_secs(30),
                maximum_attempts: 3,
                retry: Duration::from_secs(1),
            }),
        )]),
    };
    dispatcher.pass().await
}

async fn deliver_review_completion(
    client: &reqwest::Client,
    target: &ReviewCompletionTarget,
    delivery: &crate::LeasedReviewCompletion,
) -> bool {
    let (credential_name, credential_value) = target.credential.header();
    let Ok(response) = client
        .post(&target.url)
        .timeout(target.timeout)
        .header(credential_name, credential_value)
        .header("idempotency-key", delivery.event.event_id.to_string())
        .header("registry-recipient-binding", &delivery.recipient_binding)
        .json(&delivery.event)
        .send()
        .await
    else {
        return false;
    };
    let status = response.status();
    let body_is_empty = read_bounded(response, 0)
        .await
        .is_ok_and(|body| body.is_empty());
    completion_acknowledged(status, body_is_empty)
}

fn completion_acknowledged(status: reqwest::StatusCode, body_is_empty: bool) -> bool {
    status == reqwest::StatusCode::NO_CONTENT && body_is_empty
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
        .subcommand_required(true)
        .subcommand(
            Command::new("migrate")
                .hide(true)
                .about("Removed; apply a package with caseworkctl plan and apply")
                .arg(
                    Arg::new("ignored")
                        .num_args(0..)
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true),
                ),
        )
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

/// The sentence a removed `casework` subcommand refuses with.
pub const REMOVED_MIGRATE_MESSAGE: &str = "casework migrate was removed; database changes are applied with a package activation: run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`";

/// The refusal for a removed `casework` subcommand named in `args` (the
/// arguments after the program name), found before the runtime
/// configuration is read so it answers even without `--runtime-config`.
#[must_use]
pub fn removed_command_refusal<I, S>(args: I) -> Option<&'static str>
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
        return (arg == "migrate").then_some(REMOVED_MIGRATE_MESSAGE);
    }
    None
}

pub async fn run(matches: &clap::ArgMatches) -> Result<(), RuntimeError> {
    let path = matches
        .get_one::<String>("runtime-config")
        .ok_or(RuntimeError::Arguments)?;
    match matches.subcommand_name() {
        Some("migrate") => Err(RuntimeError::RemovedCommand(REMOVED_MIGRATE_MESSAGE)),
        Some("serve") => serve_from_path(path).await,
        _ => Err(RuntimeError::Arguments),
    }
}

/// Build the source adapters the package declares from their runtime
/// bindings, refusing a binding the package does not declare.
pub fn build_source_adapters(
    config: &RuntimeConfig,
    package: &crate::LoadedCaseworkPackage,
    secrets: &SecretResolver,
) -> Result<Vec<Arc<dyn SourceAdapter>>, RuntimeError> {
    let project = package.project();
    let mut adapters: Vec<Arc<dyn SourceAdapter>> = Vec::new();
    for source in &project.sources {
        let binding = config
            .sources
            .get(&source.id)
            .ok_or_else(|| RuntimeError::SourceConfiguration(source.id.clone()))?;
        let adapter = binding
            .build_adapter_from_description(
                source,
                package
                    .source_description(&source.description)
                    .ok_or_else(|| RuntimeError::SourceConfiguration(source.id.clone()))?,
                secrets,
            )
            .map_err(|_| RuntimeError::SourceConfiguration(source.id.clone()))?;
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
    Ok(adapters)
}

/// Refuse to serve a database whose activation ledger does not name this
/// configuration: no package applied, another database's identity, another
/// package, a source binding generation the last apply did not record, or a
/// split-role activation whose runtime credential can now write the ledger,
/// or a runtime credential that cannot write the ledger and does not hold
/// the grants a split-role apply issues it.
/// It only reads, and returns the role mode the runtime credential has.
pub async fn check_activation(
    store: &PostgresStore,
    database_id: &str,
    package_digest: &str,
    adapters: &[&dyn SourceAdapter],
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
    for adapter in adapters {
        if !store
            .source_generation_registered(adapter.source_id(), adapter.binding_generation())
            .await?
        {
            return Err(RuntimeError::SourceGenerationNotActive(
                adapter.source_id().to_owned(),
            ));
        }
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
/// earlier package, unless the operator acknowledged that exact package.
/// `apply` makes the same comparison, but a process still serving the
/// earlier package may admit work between that apply and this start, so the
/// runtime repeats it read-only before it serves.
pub async fn check_pinned_work(
    store: &PostgresStore,
    project: &registry_casework_core::CaseworkProject,
    adapters: &[&dyn SourceAdapter],
    package_digest: &str,
    acknowledged: Option<&str>,
) -> Result<(), RuntimeError> {
    let conflicts = crate::stranded_pinned_work(store, project, adapters).await?;
    match crate::pinned_work_verdict(&conflicts, package_digest, acknowledged) {
        crate::PinnedWorkVerdict::Clear => Ok(()),
        crate::PinnedWorkVerdict::Acknowledged => {
            tracing::warn!(
                stranded = %crate::describe_stranded_work(&conflicts),
                "serving an acknowledged Casework policy package that strands pinned work"
            );
            Ok(())
        }
        crate::PinnedWorkVerdict::Refused => Err(RuntimeError::StrandedPinnedWork(
            crate::stranded_work_refusal(&conflicts, package_digest),
        )),
    }
}

/// Refuse a source whose imported description pins a revision the source no
/// longer serves. A source that cannot be read now is not refused here: its
/// reads refuse the same drift once it answers.
pub async fn check_source_revisions(adapters: &[&dyn SourceAdapter]) -> Result<(), RuntimeError> {
    for adapter in adapters {
        match adapter.source_revision_pin().await {
            Ok(Some(pin)) if pin.pinned != pin.served => {
                return Err(RuntimeError::SourceRevisionStale {
                    source_id: adapter.source_id().to_owned(),
                    pinned: pin.pinned,
                    served: pin.served,
                });
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(
                source_id = adapter.source_id(),
                error = %error,
                "the pinned source revision could not be compared with the source at startup"
            ),
        }
    }
    Ok(())
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
    let package = config.load_package()?;
    let package_digest = package.digest().to_owned();
    tracing::info!(package_digest = %package_digest, "verified Casework package");
    let project = package.project();
    let secrets = secret_resolver(&config)?;
    let audit = open_audit(&config, &secrets, None).await?;
    let store =
        PostgresStore::connect_runtime(&config.database, &secrets)?.with_audit(audit.clone());
    store.ready().await?;
    validate_retained_completion_destinations(&store, &config.review_completion_destinations)
        .await?;

    let adapters = build_source_adapters(&config, &package, &secrets)?;
    let adapter_refs = adapters
        .iter()
        .map(|adapter| adapter.as_ref())
        .collect::<Vec<_>>();
    let role_mode =
        check_activation(&store, config.database_id(), &package_digest, &adapter_refs).await?;
    check_pinned_work(
        &store,
        project,
        &adapter_refs,
        &package_digest,
        config.package.acknowledge_stranded_work.as_deref(),
    )
    .await?;
    check_source_revisions(&adapter_refs).await?;
    if role_mode == crate::RoleMode::Single {
        tracing::warn!(
            role_mode = role_mode.as_str(),
            "{}",
            crate::SINGLE_ROLE_STATEMENT
        );
    } else {
        tracing::info!(role_mode = role_mode.as_str(), "Casework runtime role mode");
    }

    let (verifier, keys) = config.oidc_verifier(&secrets).await?;
    let authenticator = Arc::new(CaseworkAuthenticator::new(
        project,
        verifier,
        keys,
        config.authentication.oidc.human_identity.clone(),
    ));
    let task_authority = config
        .task_authority
        .as_ref()
        .map(|authority| {
            crate::task_grants::TaskAuthority::load(authority, &secrets, audit.identifiers())
        })
        .transpose()?;
    let service = CaseworkService::new(store.clone(), project.clone(), adapters)?
        .with_task_authority(task_authority)
        .with_reconciliation_intervals(
            config
                .sources
                .iter()
                .map(|(source_id, binding)| (source_id.clone(), reconciliation_interval(binding))),
        );
    let completion_dispatcher = Arc::new(ReviewCompletionDispatcher::new(
        store.clone(),
        &config.review_completion_destinations,
        &secrets,
    )?);

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
            if let Err(error) = worker_service.process_due_review_clocks(100).await {
                tracing::warn!(error = %error, "Casework review clock pass did not complete");
            }
            retention_ticks = (retention_ticks + 1) % 30;
            if retention_ticks == 0 {
                if let Err(error) = worker_service.erase_expired_reviews().await {
                    tracing::warn!(error = %error, "Casework review retention pass did not complete");
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
                if let Err(error) = worker_service.reconcile_review_absences(100).await {
                    tracing::warn!(error = %error, "Casework review absence-cover pass did not complete");
                }
                if let Err(error) = worker_service.erase_expired_clock_previews().await {
                    tracing::warn!(error = %error, "Casework clock preview retention pass did not complete");
                }
            }
        }
    }));
    let completion_worker = Arc::clone(&completion_dispatcher);
    workers.push(supervise(
        "review completion delivery",
        worker_stopped.clone(),
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(error) = completion_worker.pass().await {
                    tracing::warn!(error = %error, "Casework review completion pass did not complete");
                }
            }
        },
    ));
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
    drop(worker_stopped);
    let metrics_state = crate::metrics::MetricsState::new(
        Arc::new(store),
        config.sources.keys().cloned().collect(),
        package_digest.clone(),
    );
    let app = router(HttpState {
        service,
        authenticator,
        project: Arc::new(project.clone()),
    });
    // Both sockets bind before either serves, so a metrics address already in
    // use refuses startup instead of leaving an API without its telemetry.
    let metrics = match &config.metrics_listener {
        Some(metrics_listener) => Some((
            tokio::net::TcpListener::bind(metrics_listener.bind)
                .await
                .map_err(RuntimeError::MetricsListen)?,
            crate::metrics::metrics_router(metrics_state),
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
    let writer = AuditWriter::open(destination)
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
    use registry_casework_core::SourceAdapterError;

    struct Pinned(Result<Option<registry_casework_core::SourceRevisionPin>, SourceAdapterError>);

    #[async_trait::async_trait]
    impl SourceAdapter for Pinned {
        fn source_id(&self) -> &str {
            "registry"
        }

        fn binding_generation(&self) -> &str {
            "generation"
        }

        async fn source_revision_pin(
            &self,
        ) -> Result<Option<registry_casework_core::SourceRevisionPin>, SourceAdapterError> {
            self.0.clone()
        }

        async fn verify_transition(
            &self,
            _request: registry_casework_core::EventRequest,
        ) -> Result<registry_casework_core::TransitionHint, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn read_authoritative(
            &self,
            _subject: &registry_casework_core::SubjectRef,
        ) -> Result<registry_casework_core::AuthoritativeObservation, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn discover_active(
            &self,
            _cursor: Option<&registry_casework_core::DiscoveryCursor>,
            _limit: usize,
        ) -> Result<registry_casework_core::ActiveSubjectsPage, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn read_for_caller(
            &self,
            _subject: &registry_casework_core::SubjectRef,
            _source_profile_id: &str,
            _credential: registry_casework_core::EphemeralCredential<'_>,
        ) -> Result<registry_casework_core::CallerSubjectView, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn prepare_action(
            &self,
            _request: registry_casework_core::PrepareActionRequest<'_>,
        ) -> Result<registry_casework_core::PreparedSourceAttempt, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }

        async fn execute_prepared(
            &self,
            _request: registry_casework_core::ExecutePreparedRequest<'_>,
        ) -> Result<registry_casework_core::SourceReceipt, SourceAdapterError> {
            Err(SourceAdapterError::Invalid)
        }
    }

    fn pin(pinned: &str, served: &str) -> Pinned {
        Pinned(Ok(Some(registry_casework_core::SourceRevisionPin {
            pinned: pinned.to_owned(),
            served: served.to_owned(),
        })))
    }

    #[tokio::test]
    async fn startup_refuses_a_pinned_source_revision_the_source_no_longer_serves() {
        let stale = pin("sha256:pinned", "sha256:served");
        let error = check_source_revisions(&[&stale])
            .await
            .expect_err("a stale pin is refused");
        assert!(matches!(
            &error,
            RuntimeError::SourceRevisionStale { source_id, pinned, served }
                if source_id == "registry" && pinned == "sha256:pinned" && served == "sha256:served"
        ));
        let message = error.to_string();
        assert!(
            message.contains(
                "`caseworkctl check PROJECT --against-breg-package DIR --source-id registry`"
            ) && message.contains(
                "`caseworkctl source add BREG_PROJECT --project PROJECT --source-id registry --apply`"
            ),
            "{message}"
        );
    }

    #[tokio::test]
    async fn startup_accepts_a_current_pin_an_unpinned_source_and_an_unreachable_source() {
        let current = pin("sha256:same", "sha256:same");
        let unpinned = Pinned(Ok(None));
        let unreachable = Pinned(Err(SourceAdapterError::Unavailable));
        check_source_revisions(&[&current, &unpinned, &unreachable])
            .await
            .expect("only a pin the source contradicts is refused");
    }

    #[tokio::test]
    async fn review_completion_delivery_is_minimal_authenticated_and_stable_after_lost_ack() {
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
            .and(header("authorization", "Bearer dispatch-secret"))
            .and(header(
                "idempotency-key",
                "11111111-1111-4111-8111-111111111111",
            ))
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
            .and(header("authorization", "Bearer dispatch-secret"))
            .and(header(
                "idempotency-key",
                "11111111-1111-4111-8111-111111111111",
            ))
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
            credential: ReviewCompletionCredential::Bearer(
                BearerToken::new("dispatch-secret").expect("completion token"),
            ),
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

        Mock::given(method("POST"))
            .and(path("/nonempty-success"))
            .respond_with(ResponseTemplate::new(200).set_body_string("accepted"))
            .expect(1)
            .mount(&server)
            .await;
        let nonempty_success_target = ReviewCompletionTarget {
            url: format!("{}/nonempty-success", server.uri()),
            credential: ReviewCompletionCredential::Bearer(
                BearerToken::new("dispatch-secret").expect("completion token"),
            ),
            timeout: Duration::from_secs(1),
            maximum_attempts: 3,
            retry: Duration::from_secs(1),
        };
        assert!(
            !deliver_review_completion(&client, &nonempty_success_target, &delivery).await,
            "only an empty 204 acknowledges completion"
        );
        assert!(!completion_acknowledged(reqwest::StatusCode::OK, true));
        assert!(!completion_acknowledged(
            reqwest::StatusCode::NO_CONTENT,
            false
        ));

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
            credential: ReviewCompletionCredential::Bearer(
                BearerToken::new("dispatch-secret").expect("completion token"),
            ),
            timeout: Duration::from_secs(1),
            maximum_attempts: 3,
            retry: Duration::from_secs(1),
        };
        assert!(!deliver_review_completion(&client, &redirect_target, &delivery).await);
    }

    #[tokio::test]
    async fn review_completion_presents_its_secret_in_a_configured_header_without_authorization() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/completion"))
            .and(header("x-api-key", "dispatch-key"))
            .and(header(
                "idempotency-key",
                "11111111-1111-4111-8111-111111111111",
            ))
            .and(header("registry-recipient-binding", "registry-service"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let client = OutboundClientBuilder::new()
            .try_build()
            .expect("completion client");
        let target = ReviewCompletionTarget {
            url: format!("{}/completion", server.uri()),
            credential: ReviewCompletionCredential::from_config(Some("X-Api-Key"), b"dispatch-key")
                .expect("header credential"),
            timeout: Duration::from_secs(1),
            maximum_attempts: 3,
            retry: Duration::from_secs(1),
        };
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

        assert!(deliver_review_completion(&client, &target, &delivery).await);
        let received = server.received_requests().await.expect("recorded requests");
        assert_eq!(received.len(), 1);
        assert!(
            !received[0].headers.contains_key("authorization"),
            "a configured header replaces Authorization"
        );

        let (name, value) = ReviewCompletionCredential::from_config(None, b"dispatch-secret")
            .expect("default credential")
            .header();
        assert_eq!(name, reqwest::header::AUTHORIZATION);
        assert_eq!(value, "Bearer dispatch-secret");
        assert!(value.is_sensitive());
        let (_, value) =
            ReviewCompletionCredential::from_config(Some("x-api-key"), b"dispatch-key")
                .expect("header credential")
                .header();
        assert_eq!(value, "dispatch-key");
        assert!(value.is_sensitive());
        for invalid in [
            b"".as_slice(),
            b"dispatch key",
            b"dispatch-key\r\nhost: other",
            &[0xff],
            &[b'k'; MAXIMUM_COMPLETION_SECRET_BYTES + 1],
        ] {
            assert!(matches!(
                ReviewCompletionCredential::from_config(Some("x-api-key"), invalid),
                Err(RuntimeError::CompletionConfiguration)
            ));
        }
    }

    #[test]
    fn review_completion_bearer_tokens_are_validated_before_dispatch() {
        assert!(completion_bearer_token(b"dispatch-secret").is_ok());
        for invalid in [b"dispatch-secret\n".as_slice(), &[0xff]] {
            assert!(matches!(
                completion_bearer_token(invalid),
                Err(RuntimeError::CompletionConfiguration)
            ));
        }
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

    fn breg_binding(reconciliation_interval_milliseconds: u64) -> BregBinding {
        BregBinding {
            base_url: "https://registry.example.test".into(),
            reader_profile: "casework-reader".into(),
            token_endpoint: "https://identity.example.test/token".into(),
            client_assertion_audience: Some("https://identity.example.test".into()),
            resource: Some("urn:example:registry".into()),
            scopes: Some(vec!["casework:source-reader".into()]),
            client_id_ref: "secret:file/client-id".into(),
            client_assertion_key_ref: "secret:file/client-key".into(),
            webhook_secret_ref: "secret:file/webhook".into(),
            event_source: "urn:registrystack:registry:professional:instance:pilot".into(),
            trusted_root_certificates_ref: None,
            attempt_timeout_milliseconds: 30_000,
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

    #[test]
    fn the_removed_migrate_command_names_plan_then_apply() {
        for args in [
            &["migrate"][..],
            &["--runtime-config", "/etc/casework/runtime.yaml", "migrate"],
            &[
                "--runtime-config=/etc/casework/runtime.yaml",
                "migrate",
                "--extra",
            ],
        ] {
            let refusal = removed_command_refusal(args).expect("migrate is refused");
            assert!(refusal.contains("caseworkctl plan --runtime-config FILE"));
            assert!(refusal.contains("caseworkctl apply --runtime-config FILE"));
            assert!(
                refusal.find("caseworkctl plan") < refusal.find("caseworkctl apply"),
                "plan is named before apply"
            );
        }
        assert_eq!(
            removed_command_refusal(["--runtime-config", "migrate", "serve"]),
            None
        );
        assert_eq!(removed_command_refusal(["serve"]), None);
        assert_eq!(removed_command_refusal(Vec::<&str>::new()), None);
    }

    #[test]
    fn the_removed_migrate_command_is_hidden_from_help() {
        let help = command().render_help().to_string();
        assert!(help.contains("serve"));
        assert!(!help.contains("migrate"), "{help}");
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
    #[error("the Casework source binding for source {0} is invalid")]
    SourceConfiguration(String),
    #[error("{0}")]
    RemovedCommand(&'static str),
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
    #[error(
        "the binding of source {0} differs from the one the active package was applied with; run `caseworkctl plan --runtime-config FILE` then `caseworkctl apply --runtime-config FILE`"
    )]
    SourceGenerationNotActive(String),
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
    #[error(
        "source {source_id} pins sourceRevision {pinned}, but the source serves registry revision {served}; run `caseworkctl check PROJECT --against-breg-package DIR --source-id {source_id}` with the BReg package the source serves, repin with `caseworkctl source add BREG_PROJECT --project PROJECT --source-id {source_id} --apply`, then `caseworkctl package PROJECT --output DIRECTORY`, `caseworkctl plan --runtime-config FILE`, and `caseworkctl apply --runtime-config FILE`"
    )]
    SourceRevisionStale {
        source_id: String,
        pinned: String,
        served: String,
    },
    #[error("the Casework audit destination could not be initialized")]
    Audit,
    #[error("the Casework audit destination could not be initialized: {0}")]
    AuditSecret(String),
    #[error("the Casework audit destination could not be opened: {0}")]
    AuditDestination(String),
    #[error("the Casework review completion destination configuration is invalid")]
    CompletionConfiguration,
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
