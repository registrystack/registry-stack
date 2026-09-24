use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use clap::{Arg, Command};
use registry_casework_breg::BregBinding;
use registry_casework_core::{CaseworkProject, SourceAdapter};
use registry_platform_audit::{AuditEnvelope, AuditProfile, ChainState, DurableSegmentedJsonlSink};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::{read_bounded, BearerToken, OutboundClientBuilder};
use serde_json::Value;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Interval, MissedTickBehavior};
use tracing_subscriber::filter::LevelFilter;
use uuid::Uuid;

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

/// Audit segments seal at this size and are retained, never deleted; an
/// operator ships or prunes closed segments out of band.
const MAXIMUM_AUDIT_SEGMENT_BYTES: u64 = 10 * 1024 * 1024;

/// Sealed segments carry an eight-digit sequence suffix; any other numeric
/// suffix beside the audit file is the rotating layout of an earlier release.
const AUDIT_SEGMENT_SEQUENCE_DIGITS: usize = 8;

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
                    timeout: Duration::from_millis(target.timeout_milliseconds),
                    maximum_attempts: target.maximum_attempts,
                    retry: Duration::from_secs(target.retry_seconds),
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
                    timeout_milliseconds: 1_000,
                    maximum_attempts: 1,
                    retry_seconds: 1,
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
                .value_name("FILE")
                .help("Absolute path to the runtime configuration file.")
                .required(true),
        )
        .subcommand_required(true)
        .subcommand(Command::new("migrate").about("Apply Casework database migrations"))
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
    validate_retained_completion_destinations(&store, &config.review_completion_destinations)
        .await?;

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
    let audit_secret = resolve_audit_secret(&secrets, &config.audit.hash_key_ref)?;
    let audit_profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        audit_secret.expose_secret().to_vec(),
    ))
    .map_err(|_| RuntimeError::Audit)?;
    let task_authority = config
        .task_authority
        .as_ref()
        .map(|authority| {
            crate::task_grants::TaskAuthority::load(authority, &secrets, audit_profile.key_hasher())
        })
        .transpose()?;
    let service = CaseworkService::new(store.clone(), project.clone(), adapters)?
        .with_task_authority(task_authority);
    let completion_dispatcher = Arc::new(ReviewCompletionDispatcher::new(
        store.clone(),
        &config.review_completion_destinations,
        &secrets,
    )?);

    let (audit_sink, audit_chain, mut audit_publication_state) =
        open_audit_journal(&config.audit.path, &audit_profile).await?;

    // A bad signing key or audit configuration must not retire the live
    // instance's task templates before this instance can serve requests.
    store
        .activate_task_templates(&project.task_templates)
        .await?;
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
    let audit_publisher = RuntimeAuditPublisher {
        store,
        chain: audit_chain,
        sink: audit_sink,
        identifiers: audit_profile.key_hasher(),
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

/// Open the audit journal, authenticate its retained chain, and recover the
/// publication state its tail implies.
async fn open_audit_journal(
    path: &Path,
    profile: &AuditProfile,
) -> Result<
    (
        Arc<DurableSegmentedJsonlSink>,
        Arc<ChainState>,
        AuditPublicationState,
    ),
    RuntimeError,
> {
    refuse_rotated_audit_layout(path)?;
    let sink = Arc::new(
        DurableSegmentedJsonlSink::open(path, MAXIMUM_AUDIT_SEGMENT_BYTES)
            .map_err(|error| RuntimeError::AuditJournal(describe_audit_journal_failure(&error)))?,
    );
    let chain = Arc::new(
        profile
            .bootstrap_or_start_empty(sink.as_ref())
            .await
            .map_err(|error| RuntimeError::AuditJournal(describe_audit_journal_failure(&error)))?,
    );
    // The keyed bootstrap above authenticates the retained chain before its
    // tail identity is used to reconcile a possible append/mark crash gap.
    let publication_state =
        AuditPublicationState::from_verified_tail(newest_segmented_audit_envelope(path)?.as_ref());
    Ok((sink, chain, publication_state))
}

/// Refuse the numbered layout the rotating sink of earlier Casework releases
/// left beside the audit file.
///
/// That sink renamed a full file to `<path>.1` and shifted older ones up to
/// `<path>.49`, so its active file begins in the middle of the chain. The
/// durable sink reads none of those files and would either refuse the active
/// file or start a second chain beside them, so the operator archives the set
/// once, by hand, before this release writes to the path.
fn refuse_rotated_audit_layout(path: &Path) -> Result<(), RuntimeError> {
    let (Some(directory), Some(active)) = (
        path.parent(),
        path.file_name().and_then(|name| name.to_str()),
    ) else {
        return Ok(());
    };
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(RuntimeError::AuditJournal(format!(
                "the audit directory could not be read ({})",
                error.kind()
            )))
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            RuntimeError::AuditJournal(format!(
                "the audit directory could not be read ({})",
                error.kind()
            ))
        })?;
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_owned());
        }
    }
    match lowest_rotated_audit_file(active, names.iter().map(String::as_str)) {
        Some(name) => Err(RuntimeError::AuditJournal(format!(
            "{name} beside audit.path was rotated by an earlier Casework release, and this \
             release neither reads nor continues that layout; stop every earlier process, \
             move audit.path and each numbered file beside it into an archive directory, \
             and start again"
        ))),
        None => Ok(()),
    }
}

/// The rotated file a refusal names, independent of directory order: the
/// lowest-numbered `<active>.<n>`, which the rotating sink wrote most recently.
fn lowest_rotated_audit_file<'a>(
    active: &str,
    names: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
    names
        .filter_map(|name| {
            let suffix = name.strip_prefix(active)?.strip_prefix('.')?;
            let rotated = !suffix.is_empty()
                && suffix.len() != AUDIT_SEGMENT_SEQUENCE_DIGITS
                && suffix.bytes().all(|byte| byte.is_ascii_digit());
            rotated.then_some((suffix.len(), suffix, name))
        })
        .min()
        .map(|(_, _, name)| name)
}

/// Name the rule an audit journal refusal broke, without a record, a hash,
/// or a path the operator did not configure.
fn describe_audit_journal_failure(error: &registry_platform_audit::AuditError) -> String {
    use registry_platform_audit::{AuditError, OptionalHashHex};

    match error {
        AuditError::SinkLocked { .. } => "another process holds the single-writer lock beside \
             audit.path; stop it before starting this one"
            .to_owned(),
        AuditError::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => format!(
            "{io}; the audit directory must belong to the runtime user with mode 0700, and \
             audit.path and its lock file must belong to that user with mode 0600 and one link"
        ),
        AuditError::ChainForkDetected {
            expected: OptionalHashHex(None),
            ..
        } => "the retained audit file does not begin at the first record of its chain, as a \
             file rotated by an earlier Casework release does; stop every earlier process, move \
             audit.path and each numbered file beside it into an archive directory, and start \
             again"
            .to_owned(),
        AuditError::SegmentMissing { .. } => error.to_string(),
        AuditError::ChainForkDetected { .. }
        | AuditError::ChainVerification(_)
        | AuditError::HashMismatch => {
            "the retained audit chain does not verify under audit.hashKeyRef".to_owned()
        }
        AuditError::Io(io) => format!("the audit file could not be opened or read ({})", io.kind()),
        _ => "the audit file could not be opened or read".to_owned(),
    }
}

/// Read the most recently written audit envelope straight off disk.
///
/// [`DurableSegmentedJsonlSink`] exposes a keyed tail hash but not the tail
/// record itself, so restart reconciliation (which needs the retained
/// `eventId`) reads the segment files directly. The active segment is checked
/// first; a fallback to the newest sealed segment covers a restart that lands
/// immediately after a rotation with no subsequent write, so the check stays
/// correct without a false positive on a legitimately just-rotated set. This
/// does not verify the chain: the keyed bootstrap that runs alongside it is
/// what authenticates the retained history.
fn newest_segmented_audit_envelope(path: &Path) -> Result<Option<AuditEnvelope>, RuntimeError> {
    let candidates =
        registry_platform_audit::segmented_audit_paths(path).map_err(|_| RuntimeError::Audit)?;
    for candidate in candidates.into_iter().rev() {
        let contents = match std::fs::read_to_string(&candidate) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(RuntimeError::Audit),
        };
        let Some(last_line) = contents.lines().next_back() else {
            continue;
        };
        let envelope =
            serde_json::from_str::<AuditEnvelope>(last_line).map_err(|_| RuntimeError::Audit)?;
        return Ok(Some(envelope));
    }
    Ok(None)
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
    sink: Arc<DurableSegmentedJsonlSink>,
    identifiers: registry_platform_audit::AuditKeyHasher,
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
        let record = published_audit_record(record, &self.identifiers)?;
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

/// The database outbox is protected accountability data. The external journal
/// carries only event metadata and keyed references, never source selectors,
/// free-text reasons, receipts, or issuer/subject identities.
fn published_audit_record(
    record: Value,
    identifiers: &registry_platform_audit::AuditKeyHasher,
) -> Result<Value, ()> {
    let raw = record.as_object().ok_or(())?;
    let mut published = serde_json::Map::new();
    for field in [
        "event",
        "eventId",
        "profileId",
        "itemRevision",
        "directoryRevision",
        "actorRef",
        "accountabilityEventId",
    ] {
        if let Some(value) = raw.get(field) {
            published.insert(field.to_owned(), value.clone());
        }
    }
    for (field, output) in [
        ("itemId", "itemPseudonym"),
        ("grantId", "grantPseudonym"),
        ("teamId", "teamPseudonym"),
        ("queueId", "queuePseudonym"),
    ] {
        if let Some(value) = raw.get(field) {
            let value = value.as_str().ok_or(())?;
            let hash = identifiers
                .audit_reference_hash("casework-reference-v1", field, value)
                .map_err(|_| ())?;
            published.insert(output.to_owned(), Value::String(hash));
        }
    }
    if let Some(actor) = raw.get("actor").filter(|value| !value.is_null()) {
        let issuer = actor.get("issuer").and_then(Value::as_str).ok_or(())?;
        let subject = actor.get("subject").and_then(Value::as_str).ok_or(())?;
        let canonical = serde_json::to_string(&(issuer, subject)).map_err(|_| ())?;
        let hash = identifiers
            .audit_reference_hash("casework-principal-v1", "", &canonical)
            .map_err(|_| ())?;
        published.insert("principalPseudonym".to_owned(), Value::String(hash));
    }
    Ok(Value::Object(published))
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
    use chrono::{TimeZone as _, Utc};
    use registry_platform_audit::JsonlFileSink;
    use tokio::sync::Mutex;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::service::AuditPublisherHealth;

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

    #[cfg(unix)]
    #[test]
    fn audit_publication_separates_protected_identity_and_source_data() {
        let hasher = registry_platform_audit::AuditKeyHasher::unkeyed_dev_only();
        let raw = serde_json::json!({"event":"casework.task_approved", "eventId":"event", "actor":{"issuer":"https://issuer.test","subject":"raw-human"}, "itemId":"raw-item", "grantId":"raw-grant", "detail":{"person_reference":"raw-person"}, "reason":"private reason", "sourceReceipt":{"body":"private body"}, "profileId":"staff"});
        let published = published_audit_record(raw.clone(), &hasher).unwrap();
        let serialized = published.to_string();
        for secret in [
            "raw-human",
            "https://issuer.test",
            "raw-item",
            "raw-grant",
            "raw-person",
            "private reason",
            "private body",
        ] {
            assert!(!serialized.contains(secret));
        }
        assert_eq!(published["eventId"], "event");
        assert_eq!(published["profileId"], "staff");
        assert!(published["principalPseudonym"].as_str().is_some());
        assert_ne!(published["itemPseudonym"], published["grantPseudonym"]);
        assert_eq!(published, published_audit_record(raw, &hasher).unwrap());
        assert!(published_audit_record(
            serde_json::json!({"actor":{"subject":"missing-issuer"}}),
            &hasher
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
        sink: Arc<DurableSegmentedJsonlSink>,
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
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("audit directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict audit directory");
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

        let sink = Arc::new(
            DurableSegmentedJsonlSink::open(&path, MAXIMUM_AUDIT_SEGMENT_BYTES)
                .expect("first writer lock"),
        );
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
            DurableSegmentedJsonlSink::open(&path, MAXIMUM_AUDIT_SEGMENT_BYTES),
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
        let sink = Arc::new(
            DurableSegmentedJsonlSink::open(&path, MAXIMUM_AUDIT_SEGMENT_BYTES)
                .expect("restart writer lock"),
        );
        let chain = Arc::new(
            profile
                .bootstrap_or_start_empty(sink.as_ref())
                .await
                .expect("restart keyed bootstrap"),
        );
        let tail = newest_segmented_audit_envelope(&path).expect("verified file tail");
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

    #[tokio::test]
    async fn audit_publication_never_loses_a_record_past_the_rotation_limit() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("audit directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict audit directory");
        let path = directory.path().join("casework.jsonl");
        let pending: Vec<(Uuid, Value)> = (0..12)
            .map(|index| {
                (
                    Uuid::new_v4(),
                    serde_json::json!({
                        "event": "casework.synthetic",
                        "index": index,
                        "padding": "x".repeat(160),
                    }),
                )
            })
            .collect();
        let oldest_event_id = pending.first().expect("seeded records").0;
        let database = Arc::new(Mutex::new(FileAuditState {
            fail_marks: false,
            pending,
        }));
        let profile = AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
            b"casework-audit-rotation-secret-32-bytes".to_vec(),
        ))
        .expect("audit profile");

        let sink = Arc::new(
            DurableSegmentedJsonlSink::open(&path, 900).expect("small-segment sink opens"),
        );
        let chain = Arc::new(
            profile
                .bootstrap_or_start_empty(sink.as_ref())
                .await
                .expect("keyed bootstrap"),
        );
        let publisher = FileAuditPublisher {
            database: Arc::clone(&database),
            chain,
            sink: Arc::clone(&sink),
        };
        let mut publication_state = AuditPublicationState::default();

        publish_audit_pass(&publisher, &mut publication_state)
            .await
            .expect("every pending record publishes");
        assert!(database.lock().await.pending.is_empty());

        let mut audit_files: Vec<_> = std::fs::read_dir(directory.path())
            .expect("audit directory")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("casework.jsonl") && !name.ends_with(".lock")
                    })
            })
            .collect();
        audit_files.sort();
        assert!(
            audit_files.len() > 1,
            "the rotation limit was not exercised by this fixture"
        );
        let mut event_ids = Vec::new();
        for file in &audit_files {
            for line in std::fs::read_to_string(file)
                .expect("segment contents")
                .lines()
            {
                let envelope = serde_json::from_str::<AuditEnvelope>(line).expect("audit envelope");
                event_ids.push(
                    envelope.record["eventId"]
                        .as_str()
                        .expect("event id")
                        .to_owned(),
                );
            }
        }
        assert_eq!(
            event_ids.len(),
            12,
            "a record must remain readable after rotation, never deleted"
        );
        assert!(
            event_ids.contains(&oldest_event_id.to_string()),
            "the oldest record must not be deleted once its segment rotates out of the active file"
        );
    }

    fn upgrade_audit_profile() -> AuditProfile {
        AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
            b"casework-audit-upgrade-secret-32-bytes".to_vec(),
        ))
        .expect("audit profile")
    }

    /// An audit directory the way an operator or the container image
    /// provisions it, beside a sibling directory an archive may use.
    fn audit_directory_with_mode(mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("deployment root");
        let audit = root.path().join("audit");
        std::fs::create_dir(&audit).expect("audit directory");
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(mode))
            .expect("audit directory mode");
        (root, audit)
    }

    /// Write keyed records through the rotating sink every Casework release
    /// up to and including 0.33.0 opened, and return their event ids.
    async fn write_with_rotating_sink(
        sink: &JsonlFileSink,
        profile: &AuditProfile,
        records: usize,
    ) -> Vec<String> {
        let chain = profile
            .bootstrap_or_start_empty(sink)
            .await
            .expect("rotating sink keyed bootstrap");
        let mut event_ids = Vec::new();
        for index in 0..records {
            let event_id = Uuid::new_v4().to_string();
            chain
                .append(
                    sink,
                    serde_json::json!({
                        "eventId": event_id,
                        "event": "casework.synthetic",
                        "index": index,
                        "padding": "x".repeat(160),
                    }),
                )
                .await
                .expect("rotating sink append");
            event_ids.push(event_id);
        }
        event_ids
    }

    fn synthetic_pending(records: usize) -> Vec<(Uuid, Value)> {
        (0..records)
            .map(|index| {
                (
                    Uuid::new_v4(),
                    serde_json::json!({"event": "casework.synthetic", "index": index}),
                )
            })
            .collect()
    }

    async fn publish_into(
        sink: Arc<DurableSegmentedJsonlSink>,
        chain: Arc<ChainState>,
        state: &mut AuditPublicationState,
        pending: Vec<(Uuid, Value)>,
    ) {
        let database = Arc::new(Mutex::new(FileAuditState {
            fail_marks: false,
            pending,
        }));
        let publisher = FileAuditPublisher {
            database: Arc::clone(&database),
            chain,
            sink,
        };
        publish_audit_pass(&publisher, state)
            .await
            .expect("pending records publish");
        assert!(database.lock().await.pending.is_empty());
    }

    fn event_ids_in(files: &[std::path::PathBuf]) -> Vec<String> {
        files
            .iter()
            .flat_map(|file| {
                std::fs::read_to_string(file)
                    .expect("audit segment")
                    .lines()
                    .map(|line| {
                        let envelope =
                            serde_json::from_str::<AuditEnvelope>(line).expect("audit envelope");
                        envelope.record["eventId"]
                            .as_str()
                            .expect("event id")
                            .to_owned()
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[tokio::test]
    async fn an_audit_file_from_the_rotating_sink_continues_its_chain_after_upgrade() {
        let (_root, audit) = audit_directory_with_mode(0o700);
        let audit_path = audit.join("casework.jsonl");
        let profile = upgrade_audit_profile();
        let earlier = {
            let sink = JsonlFileSink::new_single_writer(&audit_path).expect("earlier writer");
            write_with_rotating_sink(&sink, &profile, 3).await
        };
        assert!(
            audit.join("casework.jsonl.lock").exists(),
            "the earlier writer leaves its lock file behind"
        );

        let (sink, chain, mut state) = open_audit_journal(&audit_path, &profile)
            .await
            .expect("the upgraded runtime opens an audit file the rotating sink never rotated");
        assert_eq!(
            state.unconfirmed.map(|event_id| event_id.to_string()),
            earlier.last().cloned(),
            "restart reconciliation reads the earlier writer's tail"
        );
        publish_into(sink, chain, &mut state, synthetic_pending(2)).await;

        let summary = registry_platform_audit::verify_segmented_audit_chain(
            &audit_path,
            &profile.chain_hasher(),
        )
        .expect("the whole history verifies as one chain");
        assert_eq!(summary.records, 5);
        assert_eq!(summary.segments, 1);
        assert!(summary.active_verified);
        let event_ids = event_ids_in(std::slice::from_ref(&audit_path));
        assert_eq!(event_ids[..3], earlier[..]);

        // Once the earlier writer's file fills, the durable sink seals it
        // under the first sequence and the chain crosses the seam.
        let small = Arc::new(
            DurableSegmentedJsonlSink::open(&audit_path, 900).expect("small-segment sink"),
        );
        let chain = Arc::new(
            profile
                .bootstrap_or_start_empty(small.as_ref())
                .await
                .expect("keyed bootstrap"),
        );
        let mut state = AuditPublicationState::default();
        publish_into(small, chain, &mut state, synthetic_pending(6)).await;
        let summary = registry_platform_audit::verify_segmented_audit_chain(
            &audit_path,
            &profile.chain_hasher(),
        )
        .expect("the sealed earlier file and its successors verify as one chain");
        assert_eq!(summary.records, 11);
        assert_eq!(summary.first_sequence, Some(1));
        assert!(summary.segments > 1);
        let files =
            registry_platform_audit::segmented_audit_paths(&audit_path).expect("segment listing");
        assert_eq!(event_ids_in(&files)[..3], earlier[..]);
    }

    #[test]
    fn the_rotated_layout_refusal_names_the_lowest_numbered_file_in_any_directory_order() {
        let names = [
            "casework.jsonl.5",
            "casework.jsonl",
            "casework.jsonl.12",
            "casework.jsonl.00000001",
            "casework.jsonl.1",
            "casework.jsonl.lock",
            "other.jsonl.0",
        ];
        for order in [names.to_vec(), names.iter().rev().copied().collect()] {
            assert_eq!(
                lowest_rotated_audit_file("casework.jsonl", order.into_iter()),
                Some("casework.jsonl.1")
            );
        }
        assert_eq!(
            lowest_rotated_audit_file("casework.jsonl", ["casework.jsonl"].into_iter()),
            None
        );
    }

    #[tokio::test]
    async fn an_audit_file_the_rotating_sink_already_rotated_is_refused_with_the_upgrade_step() {
        let (root, audit) = audit_directory_with_mode(0o700);
        let audit_path = audit.join("casework.jsonl");
        let profile = upgrade_audit_profile();
        let earlier = {
            let sink = JsonlFileSink::with_rotation_single_writer(&audit_path, 900, 50)
                .expect("earlier writer");
            write_with_rotating_sink(&sink, &profile, 12).await
        };
        assert!(audit.join("casework.jsonl.1").exists());
        assert!(audit.join("casework.jsonl.2").exists());

        // The durable layout's verifier reads none of the numbered files and
        // refuses an active file that starts in the middle of the chain.
        assert!(matches!(
            registry_platform_audit::verify_segmented_audit_chain(
                &audit_path,
                &profile.chain_hasher()
            ),
            Err(registry_platform_audit::AuditError::ChainForkDetected { .. })
        ));

        let error = open_audit_journal(&audit_path, &profile)
            .await
            .err()
            .expect("the upgraded runtime refuses the rotated layout")
            .to_string();
        assert!(
            error.contains("casework.jsonl.1") && error.contains("earlier Casework release"),
            "the refusal names the rotated file and where it came from: {error}"
        );
        assert!(
            error.contains("archive"),
            "the refusal names the step that clears it: {error}"
        );

        // The documented step: move the active file and its numbered
        // siblings into an archive together, then start again.
        let archive = root.path().join("audit-archive");
        std::fs::create_dir(&archive).expect("archive directory");
        let mut archived = Vec::new();
        for entry in std::fs::read_dir(&audit).expect("audit directory") {
            let name = entry.expect("audit entry").file_name();
            let name = name.to_str().expect("utf-8 name").to_owned();
            if name == "casework.jsonl"
                || name
                    .strip_prefix("casework.jsonl.")
                    .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_digit()))
            {
                std::fs::rename(audit.join(&name), archive.join(&name)).expect("archive file");
                archived.push(name);
            }
        }
        assert!(archived.len() > 2);

        let (sink, chain, mut state) = open_audit_journal(&audit_path, &profile)
            .await
            .expect("a fresh chain starts once the rotated set is archived");
        assert_eq!(state.unconfirmed, None);
        publish_into(sink, chain, &mut state, synthetic_pending(2)).await;
        let summary = registry_platform_audit::verify_segmented_audit_chain(
            &audit_path,
            &profile.chain_hasher(),
        )
        .expect("the fresh chain verifies");
        assert_eq!(summary.records, 2);

        // The archived set still authenticates under the same key, read the
        // way the earlier release's own keyed bootstrap read it.
        let archived_sink = JsonlFileSink::with_rotation(archive.join("casework.jsonl"), 900, 50);
        assert!(profile
            .bootstrap_or_start_empty(&archived_sink)
            .await
            .expect("the archived history verifies under the audit key")
            .last_hash()
            .await
            .is_some());
        let mut archived_files: Vec<_> = (1..50)
            .rev()
            .map(|index| archive.join(format!("casework.jsonl.{index}")))
            .filter(|file| file.exists())
            .collect();
        archived_files.push(archive.join("casework.jsonl"));
        assert_eq!(event_ids_in(&archived_files), earlier);
    }

    #[tokio::test]
    async fn an_audit_file_that_starts_mid_chain_is_refused_with_the_upgrade_step() {
        let (_root, audit) = audit_directory_with_mode(0o700);
        let audit_path = audit.join("casework.jsonl");
        let profile = upgrade_audit_profile();
        {
            let sink = JsonlFileSink::with_rotation_single_writer(&audit_path, 900, 50)
                .expect("earlier writer");
            write_with_rotating_sink(&sink, &profile, 12).await;
        }
        // An operator already pruned the numbered files under their own
        // retention policy, leaving an active file that begins mid-chain.
        for index in 1..50 {
            let rotated = audit.join(format!("casework.jsonl.{index}"));
            if rotated.exists() {
                std::fs::remove_file(rotated).expect("prune rotated file");
            }
        }

        let error = open_audit_journal(&audit_path, &profile)
            .await
            .err()
            .expect("the upgraded runtime refuses a mid-chain audit file")
            .to_string();
        assert!(
            error.contains("does not begin at the first record")
                && error.contains("earlier Casework release"),
            "the refusal explains the mid-chain start: {error}"
        );
    }

    #[tokio::test]
    async fn an_audit_directory_the_rotating_sink_accepted_is_refused_until_it_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        for mode in [0o755, 0o750] {
            let (_root, audit) = audit_directory_with_mode(mode);
            let audit_path = audit.join("casework.jsonl");
            let profile = upgrade_audit_profile();
            {
                let sink = JsonlFileSink::new_single_writer(&audit_path)
                    .expect("the earlier writer accepts a group-readable directory");
                write_with_rotating_sink(&sink, &profile, 2).await;
            }

            let error = open_audit_journal(&audit_path, &profile)
                .await
                .err()
                .expect("the upgraded runtime refuses a directory other users can read")
                .to_string();
            assert!(
                error.contains("audit directory must be owner-only") && error.contains("0700"),
                "the refusal names the mode the directory needs: {error}"
            );

            std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o700))
                .expect("restrict audit directory");
            std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o640))
                .expect("loosen audit file");
            let error = open_audit_journal(&audit_path, &profile)
                .await
                .err()
                .expect("the upgraded runtime refuses an audit file other users can read")
                .to_string();
            assert!(
                error.contains("owner-only") && error.contains("0600"),
                "the refusal names the mode the audit file needs: {error}"
            );

            std::fs::set_permissions(&audit_path, std::fs::Permissions::from_mode(0o600))
                .expect("restrict audit file");
            open_audit_journal(&audit_path, &profile)
                .await
                .expect("the journal opens once the directory and file are owner-only");
        }
    }

    #[tokio::test]
    async fn the_rotating_sink_and_the_durable_sink_share_one_writer_lock() {
        let (_root, audit) = audit_directory_with_mode(0o700);
        let audit_path = audit.join("casework.jsonl");
        let profile = upgrade_audit_profile();

        let earlier = JsonlFileSink::new_single_writer(&audit_path).expect("earlier writer");
        write_with_rotating_sink(&earlier, &profile, 1).await;
        let error = open_audit_journal(&audit_path, &profile)
            .await
            .err()
            .expect("an overlapping earlier process keeps the lock")
            .to_string();
        assert!(
            error.contains("single-writer lock"),
            "the refusal names the lock: {error}"
        );
        drop(earlier);

        let journal = open_audit_journal(&audit_path, &profile)
            .await
            .expect("the lock file an earlier process left behind does not block");
        assert!(matches!(
            JsonlFileSink::new_single_writer(&audit_path),
            Err(registry_platform_audit::AuditError::SinkLocked { .. })
        ));
        drop(journal);
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
            client_assertion_audience: Some("https://identity.example.test".into()),
            resource: Some("urn:example:registry".into()),
            scopes: Some(vec!["casework:source-reader".into()]),
            client_id_ref: "secret:file/client-id".into(),
            client_assertion_key_ref: "secret:file/client-key".into(),
            webhook_secret_ref: "secret:file/webhook".into(),
            event_source: "urn:registrystack:registry:professional:instance:pilot".into(),
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
    #[error("the Casework audit journal could not be initialized: {0}")]
    AuditJournal(String),
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
    #[error("a Casework background worker stopped")]
    WorkerStopped,
}
