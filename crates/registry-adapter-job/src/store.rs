// SPDX-License-Identifier: Apache-2.0

//! The item table and the job state row
//! (`products/adapter/CONCEPT.md` section 17.2): the PostgreSQL store of
//! the governed-ingestion job host. One row per item carries identity
//! and progress and no payload; one row per job carries the opaque
//! source position, the lease, and the schedule counters. Every write is
//! stamped from the runtime clock or the database clock, never a
//! default, and every failure names its cause without repeating a
//! connection string or a value.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr as _;
use std::time::{Duration, SystemTime};

use deadpool_postgres::{
    GenericClient, Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime,
};
use registry_platform_config::SecretResolver;
use serde_json::Value;
use tokio_postgres::Error as PgError;

/// Every schema version, in the order it is applied. Each later
/// migration takes the next number.
pub(crate) const MIGRATIONS: [(i64, &str); 1] =
    [(100, include_str!("store/migrations/0100_job_items.sql"))];

/// The newest schema version this release applies.
pub(crate) const SUPPORTED_SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;

/// Shared advisory-lock key for schema migration. Its ASCII bytes spell
/// "ajobstat", distinct from every other migration lock in the product.
pub(crate) const MIGRATION_LOCK_KEY: i64 = 0x616a_6f62_7374_6174;

/// Why a store write, read, or migration failed. Neither the pool nor
/// the driver repeats the connection string in its message, so naming
/// the cause costs no credential; no message repeats an item value.
#[derive(Debug)]
pub enum StoreError {
    /// The database holds a job schema newer than this release applies.
    SchemaNewer {
        /// The newest version the database applied.
        found: i64,
        /// The newest version this release supports.
        supported: i64,
    },
    /// The migration lock was not held when it was released.
    MigrationLock,
    /// A pool or connection could not be built or reached.
    Pool(String),
    /// The driver's own account of what went wrong.
    Query(PgError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::SchemaNewer { found, supported } => write!(
                formatter,
                "the adapter job database holds schema version {found}, newer than the version {supported} this release applies; this release cannot serve it"
            ),
            StoreError::MigrationLock => write!(
                formatter,
                "the adapter job migration lock was not held when it was released"
            ),
            StoreError::Pool(reason) => write!(
                formatter,
                "the adapter job database pool failed: {reason}"
            ),
            StoreError::Query(error) => {
                write!(formatter, "the adapter job store query failed: {error}")
            }
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::SchemaNewer { .. } | StoreError::MigrationLock | StoreError::Pool(_) => {
                None
            }
            StoreError::Query(error) => Some(error),
        }
    }
}

impl From<PgError> for StoreError {
    fn from(error: PgError) -> Self {
        StoreError::Query(error)
    }
}

/// Apply every pending job-store migration under the shared advisory
/// lock, refusing a database this release cannot serve. Running it
/// again, or twice at once, applies nothing twice. The migration table
/// is this crate's own, so the job host's schema versions move beside,
/// never against, the facade journal's.
///
/// # Errors
///
/// A newer schema, a failed migration, or a lost lock refuses.
pub async fn migrate(client: &impl GenericClient) -> Result<(), StoreError> {
    client
        .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await?;
    let applied = apply_migrations(client).await;
    let released = client
        .query_one("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
        .await;
    applied?;
    if released?.get::<_, bool>(0) {
        Ok(())
    } else {
        Err(StoreError::MigrationLock)
    }
}

async fn apply_migrations(client: &impl GenericClient) -> Result<(), StoreError> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS adapter_job_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL)",
        )
        .await?;
    let applied = client
        .query("SELECT version FROM adapter_job_schema_migrations", &[])
        .await?
        .into_iter()
        .map(|row| row.get::<_, i64>(0))
        .collect::<Vec<_>>();
    if let Some(found) = applied.iter().copied().max() {
        if found > SUPPORTED_SCHEMA_VERSION {
            return Err(StoreError::SchemaNewer {
                found,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
    }
    for (version, migration) in MIGRATIONS {
        if applied.contains(&version) {
            continue;
        }
        client.batch_execute(migration).await?;
        client
            .execute(
                "INSERT INTO adapter_job_schema_migrations(version,applied_at) VALUES($1,now())",
                &[&version],
            )
            .await?;
    }
    Ok(())
}

/// The job store block of the operator runtime config (`store:`): the
/// item table's single connection reference. The job store runs its
/// migrations on the same connection it serves from, so the block
/// carries no separate migration member; the facade's database block
/// (journal and idempotency pools) is a facade member the job document
/// refuses. Secret references only, resolved by the host, never a URL
/// in the document.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobStoreConfig {
    /// The runtime connection reference of the item table's database.
    pub runtime_url_ref: registry_platform_yaml::SecretReference,
    /// The root certificate the connection trusts beside the platform
    /// roots; absent, the platform roots alone.
    #[serde(default)]
    pub trusted_root_certificate_ref: Option<registry_platform_yaml::SecretReference>,
    /// Plaintext connections for the loopback test database only;
    /// refused in any build without this crate's `postgres-test`
    /// feature, the way the facade database refuses it.
    #[serde(default)]
    pub test_only_plaintext: bool,
}

/// Build the connection pool the way the facade's serving runtime does:
/// the URL resolved from the operator runtime config's secret reference,
/// TLS required, and plaintext allowed only where the facade allows it,
/// in a build with this crate's `postgres-test` feature and the
/// operator's `testOnlyPlaintext` member. The same pool carries the
/// store's migrations and its passes.
///
/// # Errors
///
/// An unresolvable reference, an invalid URL, or an unbuildable pool
/// refuses, naming the block and never the URL.
pub fn build_pool(config: &JobStoreConfig, resolver: &SecretResolver) -> Result<Pool, StoreError> {
    let invalid = |what: &str| StoreError::Pool(format!("store: {what}"));
    let reference = &config.runtime_url_ref;
    let protected = resolver
        .resolve(reference.as_str())
        .map_err(|_| invalid("a connection reference could not be resolved"))?;
    let url = std::str::from_utf8(protected.expose_secret())
        .map_err(|_| invalid("the connection url is not text"))?;
    let mut postgres = tokio_postgres::Config::from_str(url)
        .map_err(|_| invalid("the connection url is invalid"))?;
    if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
        return Err(invalid("the connection url names no user or database"));
    }
    let manager_config = ManagerConfig {
        recycling_method: RecyclingMethod::Verified,
    };
    #[cfg(feature = "postgres-test")]
    let manager = if config.test_only_plaintext {
        postgres.ssl_mode(tokio_postgres::config::SslMode::Disable);
        Manager::from_config(postgres, tokio_postgres::NoTls, manager_config)
    } else {
        postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
        Manager::from_config(postgres, tls_connector(config, resolver)?, manager_config)
    };
    #[cfg(not(feature = "postgres-test"))]
    let manager = {
        if config.test_only_plaintext {
            return Err(invalid("plaintext connections are refused in this build"));
        }
        postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
        Manager::from_config(postgres, tls_connector(config, resolver)?, manager_config)
    };
    Pool::builder(manager)
        .max_size(4)
        .wait_timeout(Some(Duration::from_secs(5)))
        .create_timeout(Some(Duration::from_secs(5)))
        .recycle_timeout(Some(Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|error| invalid(&format!("the pool could not be built: {error}")))
}

/// The TLS connector for the job host's database connections: the
/// configured root certificate when the store block names one, the
/// platform's own roots otherwise.
fn tls_connector(
    config: &JobStoreConfig,
    resolver: &SecretResolver,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, StoreError> {
    let invalid = |what: &str| StoreError::Pool(format!("store: {what}"));
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Some(reference) = &config.trusted_root_certificate_ref else {
        let (connector, warnings) =
            tokio_postgres_rustls::MakeRustlsConnect::with_native_certs()
                .map_err(|_| invalid("no platform root certificate could be loaded"))?;
        for warning in warnings {
            tracing::warn!("a platform root certificate was skipped: {warning}");
        }
        return Ok(connector);
    };
    let protected = resolver
        .resolve(reference.as_str())
        .map_err(|_| invalid("a certificate reference could not be resolved"))?;
    let mut roots = rustls::RootCertStore::empty();
    use rustls::pki_types::pem::PemObject as _;
    for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(protected.expose_secret())
    {
        roots
            .add(certificate.map_err(|_| invalid("a trusted certificate is unreadable"))?)
            .map_err(|_| invalid("a trusted certificate is unusable"))?;
    }
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client))
}

/// The last hand-off's outcome, the closed status set of the item table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemStatus {
    /// Handed off, the answer not yet recorded.
    Pending,
    /// The destination accepted the item.
    Acknowledged,
    /// The destination refused the item with its own code.
    Refused,
}

impl ItemStatus {
    /// The wire spelling of the status, the operator output's.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ItemStatus::Pending => "pending",
            ItemStatus::Acknowledged => "acknowledged",
            ItemStatus::Refused => "refused",
        }
    }

    fn from_str(status: &str) -> Option<Self> {
        match status {
            "pending" => Some(ItemStatus::Pending),
            "acknowledged" => Some(ItemStatus::Acknowledged),
            "refused" => Some(ItemStatus::Refused),
            _ => None,
        }
    }
}

/// One stored item row, the fields the pass and the operator surface
/// read. There is no payload member: the table holds none.
#[derive(Clone, Debug)]
pub struct ItemRecord {
    /// The source item's key.
    pub key: String,
    /// The plain digest of the last hand-off's bytes.
    pub last_digest: String,
    /// The change count, from 1.
    pub sequence: i64,
    /// The last hand-off's outcome.
    pub status: ItemStatus,
    /// The destination's item-scoped refusal code, for a refused row.
    pub code: Option<String>,
    /// The destination's reference for this digest's hand-off.
    pub run_id: Option<String>,
    /// The destination's reference for a previous, different-digest
    /// hand-off of this key.
    pub prior_run_id: Option<String>,
    /// Whether an earlier digest's receipt may have been lost.
    pub admitted_before: bool,
    /// When the row first appeared.
    pub first_seen: SystemTime,
    /// When the row was last written.
    pub last_seen: SystemTime,
}

/// What the pass stages before a delivery: the decision, made against
/// the stored row, that this hand-off is new, changed, or a re-delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Decision {
    /// No row existed: sequence 1.
    DeliverNew,
    /// The digest changed: the sequence advances, the prior hand-off's
    /// reference moves beside the row.
    DeliverChanged,
    /// The same digest hands off again: a still-pending row, or a
    /// refused row a rescan retries. The sequence does not move.
    DeliverRedelivery,
    /// The item is unchanged and settled or refused outside a rescan.
    Skip,
}

/// The stored state a decision reads.
#[derive(Clone, Debug)]
pub(crate) struct PriorRow {
    /// The stored digest.
    pub last_digest: String,
    /// The stored change count.
    pub sequence: i64,
    /// The stored status.
    pub status: ItemStatus,
    /// The stored reference.
    pub run_id: Option<String>,
    /// Whether an earlier digest's receipt may have been lost.
    pub admitted_before: bool,
}

/// The pass's decision for one item against its stored row: a new item
/// or a changed digest delivers; the same digest on a pending row
/// re-delivers identical bytes; the same digest on an acknowledged row
/// skips, and on a refused row skips unless this pass is a rescan, the
/// only pass that retries refused items.
pub(crate) fn decide(prior: Option<&PriorRow>, digest: &str, retry_refused: bool) -> Decision {
    match prior {
        None => Decision::DeliverNew,
        Some(prior) if prior.last_digest == digest => match prior.status {
            ItemStatus::Pending => Decision::DeliverRedelivery,
            ItemStatus::Acknowledged => Decision::Skip,
            ItemStatus::Refused if retry_refused => Decision::DeliverRedelivery,
            ItemStatus::Refused => Decision::Skip,
        },
        Some(_) => Decision::DeliverChanged,
    }
}

/// The store's answer to staging one item: what the pass delivers and
/// how the report classifies it.
#[derive(Clone, Debug)]
pub struct StagedItem {
    /// The item's key.
    pub key: String,
    /// The change count after staging: 1 for a new item, the prior count
    /// plus one for a changed digest, the prior count for a re-delivery.
    pub sequence: i64,
    /// The plain digest this hand-off carries.
    pub digest: String,
    /// The prior hand-off's reference, moved beside the row on a change.
    pub prior_run_id: Option<String>,
    /// Whether a prior digest's receipt may have been lost.
    pub admitted_before: bool,
    /// How the staged delivery classifies in the report.
    pub classification: StagedClassification,
}

/// How one staged delivery classifies in the pass report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedClassification {
    /// The item had no row.
    New,
    /// The digest changed.
    Changed,
    /// The same digest re-delivered.
    Redelivered,
}

/// Stage one item for delivery: make the decision and, when it
/// delivers, write the row `pending` in one transaction before the
/// caller touches the destination. A crash after this call and before
/// the destination's answer leaves a pending row whose next pass
/// re-delivers identical bytes; that is the pass's at-least-once
/// hand-off, and the destination's dedup duty follows from the retry
/// identity of the seam.
///
/// # Errors
///
/// A failed read, write, or commit refuses; the caller treats the item
/// as undelivered.
pub async fn stage_item(
    client: &mut Object,
    job_id: &str,
    key: &str,
    digest: &str,
    retry_refused: bool,
    now: SystemTime,
) -> Result<Option<StagedItem>, StoreError> {
    let tx = client.transaction().await?;
    let prior = read_prior(&tx, job_id, key, true).await?;
    let decision = decide(prior.as_ref(), digest, retry_refused);
    let staged = match decision {
        Decision::Skip => None,
        Decision::DeliverNew => {
            tx.execute(
                "INSERT INTO adapter_job_items \
                 (job_id, item_key, last_digest, sequence, status, first_seen, last_seen) \
                 VALUES ($1, $2, $3, 1, 'pending', $4, $4)",
                &[&job_id, &key, &digest, &now],
            )
            .await?;
            Some(StagedItem {
                key: key.to_string(),
                sequence: 1,
                digest: digest.to_string(),
                prior_run_id: None,
                admitted_before: false,
                classification: StagedClassification::New,
            })
        }
        Decision::DeliverChanged => {
            let prior = prior
                .as_ref()
                .expect("a changed digest implies a prior row");
            let admitted_before = prior.admitted_before
                || matches!(prior.status, ItemStatus::Pending | ItemStatus::Acknowledged);
            let row = tx
                .execute(
                    "UPDATE adapter_job_items SET \
                     last_digest = $3, sequence = sequence + 1, status = 'pending', \
                     code = NULL, run_id = NULL, prior_run_id = run_id, \
                     admitted_before = $4, last_seen = $5 \
                     WHERE job_id = $1 AND item_key = $2",
                    &[&job_id, &key, &digest, &admitted_before, &now],
                )
                .await?;
            if row != 1 {
                return Err(StoreError::Pool(
                    "the item row the stage transaction read was not the one it wrote".to_string(),
                ));
            }
            Some(StagedItem {
                key: key.to_string(),
                sequence: prior.sequence + 1,
                digest: digest.to_string(),
                prior_run_id: prior.run_id.clone(),
                admitted_before,
                classification: StagedClassification::Changed,
            })
        }
        Decision::DeliverRedelivery => {
            let prior = prior.as_ref().expect("a re-delivery implies a prior row");
            tx.execute(
                "UPDATE adapter_job_items SET status = 'pending', code = NULL, last_seen = $3 \
                 WHERE job_id = $1 AND item_key = $2",
                &[&job_id, &key, &now],
            )
            .await?;
            Some(StagedItem {
                key: key.to_string(),
                sequence: prior.sequence,
                digest: digest.to_string(),
                prior_run_id: prior.run_id.clone(),
                admitted_before: prior.admitted_before,
                classification: StagedClassification::Redelivered,
            })
        }
    };
    tx.commit().await?;
    Ok(staged)
}

/// Read one item's decision without writing anything, the dry-run's
/// read-only stage. The answer matches [`stage_item`]'s exactly, so a
/// preview reports what a real pass would stage.
///
/// # Errors
///
/// A failed read refuses.
pub async fn peek_item(
    client: &impl GenericClient,
    job_id: &str,
    key: &str,
    digest: &str,
    retry_refused: bool,
) -> Result<Option<StagedItem>, StoreError> {
    let prior = read_prior(client, job_id, key, false).await?;
    let decision = decide(prior.as_ref(), digest, retry_refused);
    Ok(match (decision, prior) {
        // A new item has no row to read; the preview still names the
        // hand-off a real pass would stage, at sequence 1.
        (Decision::DeliverNew, _) => Some(StagedItem {
            key: key.to_string(),
            sequence: 1,
            digest: digest.to_string(),
            prior_run_id: None,
            admitted_before: false,
            classification: StagedClassification::New,
        }),
        (Decision::Skip, _) => None,
        (Decision::DeliverChanged, Some(prior)) => Some(StagedItem {
            key: key.to_string(),
            sequence: prior.sequence + 1,
            digest: digest.to_string(),
            prior_run_id: prior.run_id.clone(),
            admitted_before: prior.admitted_before
                || matches!(prior.status, ItemStatus::Pending | ItemStatus::Acknowledged),
            classification: StagedClassification::Changed,
        }),
        (Decision::DeliverRedelivery, Some(prior)) => Some(StagedItem {
            key: key.to_string(),
            sequence: prior.sequence,
            digest: digest.to_string(),
            prior_run_id: prior.run_id.clone(),
            admitted_before: prior.admitted_before,
            classification: StagedClassification::Redelivered,
        }),
        // A changed digest or re-delivery implies a prior row; the
        // primary key forbids the miss.
        (Decision::DeliverChanged, None) | (Decision::DeliverRedelivery, None) => None,
    })
}

async fn read_prior(
    client: &impl GenericClient,
    job_id: &str,
    key: &str,
    for_update: bool,
) -> Result<Option<PriorRow>, StoreError> {
    let query = if for_update {
        "SELECT last_digest, sequence, status, run_id, admitted_before \
         FROM adapter_job_items WHERE job_id = $1 AND item_key = $2 FOR UPDATE"
    } else {
        "SELECT last_digest, sequence, status, run_id, admitted_before \
         FROM adapter_job_items WHERE job_id = $1 AND item_key = $2"
    };
    let row = client.query_opt(query, &[&job_id, &key]).await?;
    Ok(row.map(|row| PriorRow {
        last_digest: row.get(0),
        sequence: row.get(1),
        status: ItemStatus::from_str(row.get(2)).expect("the status check admits three values"),
        run_id: row.get(3),
        admitted_before: row.get(4),
    }))
}

/// Record an acknowledged hand-off: the row settles, the destination's
/// reference is stored, and the key counts as admitted from here on.
///
/// # Errors
///
/// A failed write refuses; the caller treats the item as undelivered and
/// a later pass re-delivers.
pub async fn record_acknowledged(
    client: &impl GenericClient,
    job_id: &str,
    key: &str,
    run_id: Option<&str>,
    now: SystemTime,
) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE adapter_job_items SET status = 'acknowledged', run_id = $3, code = NULL, \
             admitted_before = true, last_seen = $4 WHERE job_id = $1 AND item_key = $2",
            &[&job_id, &key, &run_id, &now],
        )
        .await?;
    Ok(())
}

/// Record an item-scoped refusal: the code is stored, the row stays
/// identified, and the pass continues.
///
/// # Errors
///
/// A failed write refuses; the caller treats the item as undelivered and
/// a later pass re-delivers.
pub async fn record_refused(
    client: &impl GenericClient,
    job_id: &str,
    key: &str,
    code: &str,
    now: SystemTime,
) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE adapter_job_items SET status = 'refused', code = $3, run_id = NULL, \
             last_seen = $4 WHERE job_id = $1 AND item_key = $2",
            &[&job_id, &key, &code, &now],
        )
        .await?;
    Ok(())
}

/// Create the job's state row when the job's first pass or first status
/// read needs it; existing rows are untouched.
///
/// # Errors
///
/// A failed write refuses.
pub async fn ensure_state(client: &impl GenericClient, job_id: &str) -> Result<(), StoreError> {
    client
        .execute(
            "INSERT INTO adapter_job_state (job_id) VALUES ($1) ON CONFLICT (job_id) DO NOTHING",
            &[&job_id],
        )
        .await?;
    Ok(())
}

/// The job state row, everything the pass, the schedule, and the
/// operator surface read.
#[derive(Clone, Debug, Default)]
pub struct JobStateRow {
    /// The opaque page cursor; absent at a finite end or before the
    /// first settled pass.
    pub position: Option<Value>,
    /// The projection digest the last pass ran under.
    pub projection_digest: Option<String>,
    /// When the lease expires; a held lease refuses a new pass.
    pub lease_expires: Option<SystemTime>,
    /// When the last pass ran.
    pub last_pass_at: Option<SystemTime>,
    /// Why the last pass stopped, value-free.
    pub last_pass_stop: Option<String>,
    /// When the last rescan pass ran.
    pub last_rescan_at: Option<SystemTime>,
    /// Consecutive completed passes that read no items.
    pub idle_streak: i64,
    /// Consecutive passes that stopped before the page settled.
    pub error_streak: i64,
}

/// Read the job's state row, absent before the job's first write.
///
/// # Errors
///
/// A failed read refuses.
pub async fn read_state(
    client: &impl GenericClient,
    job_id: &str,
) -> Result<Option<JobStateRow>, StoreError> {
    let row = client
        .query_opt(
            "SELECT position, projection_digest, lease_expires, last_pass_at, last_pass_stop, \
             last_rescan_at, idle_streak, error_streak \
             FROM adapter_job_state WHERE job_id = $1",
            &[&job_id],
        )
        .await?;
    Ok(row.map(|row| JobStateRow {
        position: row.get(0),
        projection_digest: row.get(1),
        lease_expires: row.get(2),
        last_pass_at: row.get(3),
        last_pass_stop: row.get(4),
        last_rescan_at: row.get(5),
        idle_streak: row.get(6),
        error_streak: row.get(7),
    }))
}

/// Take the job's pass lease under the database clock: one pass at a
/// time per job. The lease refuses while another pass's lease is live
/// and grants when it is free, expired, or absent.
///
/// # Errors
///
/// A failed write refuses; an error is never a held lease, which is the
/// `false` answer.
pub async fn take_lease(
    client: &impl GenericClient,
    job_id: &str,
    ttl: Duration,
) -> Result<bool, StoreError> {
    // make_interval's secs member is double precision.
    let ttl = ttl.as_secs().min(i64::MAX as u64) as f64;
    let granted = client
        .query_opt(
            "UPDATE adapter_job_state SET lease_expires = now() + make_interval(secs => $2) \
             WHERE job_id = $1 AND (lease_expires IS NULL OR lease_expires <= now()) \
             RETURNING job_id",
            &[&job_id, &ttl],
        )
        .await?;
    Ok(granted.is_some())
}

/// Bring the state row's projection digest to the job's current one, so
/// a projection edit is visible in status. The items re-flag through
/// their own digests: a new projection digests differently.
///
/// # Errors
///
/// A failed write refuses.
pub async fn sync_projection_digest(
    client: &impl GenericClient,
    job_id: &str,
    digest: &str,
) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE adapter_job_state SET projection_digest = $2 WHERE job_id = $1",
            &[&job_id, &digest],
        )
        .await?;
    Ok(())
}

/// Settle a completed pass: save the page's next cursor, or clear the
/// position at a finite end, stamp the pass, count the pass into the
/// schedule streaks, and release the lease. A rescan pass stamps its
/// own completion, which starts the source's declared delay.
///
/// # Errors
///
/// A failed write refuses.
pub async fn complete_pass(
    client: &impl GenericClient,
    job_id: &str,
    position: Option<&Value>,
    idle: bool,
    rescan: bool,
    now: SystemTime,
) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE adapter_job_state SET \
             position = $2, last_pass_at = $3, last_pass_stop = NULL, lease_expires = NULL, \
             last_rescan_at = CASE WHEN $4 THEN $3 ELSE last_rescan_at END, \
             idle_streak = CASE WHEN $5 THEN idle_streak + 1 ELSE 0 END, \
             error_streak = 0 \
             WHERE job_id = $1",
            &[&job_id, &position, &now, &rescan, &idle],
        )
        .await?;
    Ok(())
}

/// Record why a pass stopped and release the lease. The position is
/// untouched: a stopped pass leaves the source exactly where the last
/// settled pass left it.
///
/// # Errors
///
/// A failed write refuses.
pub async fn stop_pass(
    client: &impl GenericClient,
    job_id: &str,
    stop_code: &str,
    now: SystemTime,
) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE adapter_job_state SET \
             last_pass_at = $2, last_pass_stop = $3, lease_expires = NULL, \
             error_streak = error_streak + 1, idle_streak = 0 \
             WHERE job_id = $1",
            &[&job_id, &now, &stop_code],
        )
        .await?;
    Ok(())
}

/// Mark a rescan due now, so the next pass runs from the first page
/// regardless of the declared delay.
///
/// # Errors
///
/// A failed write refuses.
pub async fn mark_rescan_due(client: &impl GenericClient, job_id: &str) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE adapter_job_state SET last_rescan_at = NULL WHERE job_id = $1",
            &[&job_id],
        )
        .await?;
    Ok(())
}

/// The status read: how many items sit in each status, and how the
/// refusals distribute over the destinations' codes.
#[derive(Clone, Debug, Default)]
pub struct StatusCounts {
    /// Rows whose hand-off answer is not yet recorded.
    pub pending: u64,
    /// Rows the destination accepted.
    pub acknowledged: u64,
    /// Rows the destination refused.
    pub refused: u64,
    /// Refused rows by the destination's own code.
    pub refusals_by_code: BTreeMap<String, u64>,
}

/// Count the job's items by status and refusal code.
///
/// # Errors
///
/// A failed read refuses.
pub async fn item_counts(
    client: &impl GenericClient,
    job_id: &str,
) -> Result<StatusCounts, StoreError> {
    let mut counts = StatusCounts::default();
    for row in client
        .query(
            "SELECT status, count(*) FROM adapter_job_items WHERE job_id = $1 GROUP BY status",
            &[&job_id],
        )
        .await?
    {
        let count: i64 = row.get(1);
        match ItemStatus::from_str(row.get(0)) {
            Some(ItemStatus::Pending) => counts.pending = count.max(0) as u64,
            Some(ItemStatus::Acknowledged) => counts.acknowledged = count.max(0) as u64,
            Some(ItemStatus::Refused) => counts.refused = count.max(0) as u64,
            None => {}
        }
    }
    for row in client
        .query(
            "SELECT code, count(*) FROM adapter_job_items \
             WHERE job_id = $1 AND status = 'refused' AND code IS NOT NULL GROUP BY code",
            &[&job_id],
        )
        .await?
    {
        let code: String = row.get(0);
        let count: i64 = row.get(1);
        counts.refusals_by_code.insert(code, count.max(0) as u64);
    }
    Ok(counts)
}

/// Read one item's row for the operator's inspect surface.
///
/// # Errors
///
/// A failed read refuses.
pub async fn inspect_item(
    client: &impl GenericClient,
    job_id: &str,
    key: &str,
) -> Result<Option<ItemRecord>, StoreError> {
    let row = client
        .query_opt(
            "SELECT item_key, last_digest, sequence, status, code, run_id, prior_run_id, \
             admitted_before, first_seen, last_seen \
             FROM adapter_job_items WHERE job_id = $1 AND item_key = $2",
            &[&job_id, &key],
        )
        .await?;
    Ok(row.map(|row| ItemRecord {
        key: row.get(0),
        last_digest: row.get(1),
        sequence: row.get(2),
        status: ItemStatus::from_str(row.get(3)).expect("the status check admits three values"),
        code: row.get(4),
        run_id: row.get(5),
        prior_run_id: row.get(6),
        admitted_before: row.get(7),
        first_seen: row.get(8),
        last_seen: row.get(9),
    }))
}
