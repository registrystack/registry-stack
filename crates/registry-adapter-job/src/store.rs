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
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::Error as PgError;
use tokio_postgres::Socket;

/// Every schema version, in the order it is applied. Each later
/// migration takes the next number.
pub(crate) const MIGRATIONS: [(i64, &str); 4] = [
    (100, include_str!("store/migrations/0100_job_items.sql")),
    (101, include_str!("store/migrations/0101_rescan_active.sql")),
    (102, include_str!("store/migrations/0102_held_items.sql")),
    (
        103,
        include_str!("store/migrations/0103_coordinator_delivery_identity.sql"),
    ),
];

/// The newest schema version this release applies.
pub const SUPPORTED_SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;

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
    /// The database holds no job schema, or one older than this release
    /// applies; only a migrating command brings it current.
    SchemaBehind {
        /// The newest version the database applied, when it applied any.
        found: Option<i64>,
        /// The newest version this release supports.
        supported: i64,
    },
    /// The migration lock was not held when it was released.
    MigrationLock,
    /// A pass holds the job's lease, so an operator write that would
    /// move its traversal refuses until the pass ends or its lease
    /// expires.
    LeaseHeld,
    /// The pass's lease was no longer held when a write reached the
    /// store: another pass owns the job, and this pass's writes stop.
    LeaseLost,
    /// A legacy pending row predates persisted receiver identity, so the
    /// process cannot prove that retrying it reaches the same authority.
    ReceiverIdentityUnknown,
    /// A pending retry selected a different public receiver identity than
    /// the one frozen before its earlier delivery attempt.
    ReceiverIdentityChanged,
    /// A legacy pending row predates the persisted canonical body digest.
    CanonicalBodyIdentityUnknown,
    /// A pending retry produced canonical envelope bytes other than those
    /// frozen before its earlier delivery attempt.
    CanonicalBodyIdentityChanged,
    /// A pending delivery attempt reached the durable positive bigint bound.
    DeliveryAttemptExhausted,
    /// A file/SFTP item identity changed, or legacy state already contains
    /// traversal/item progress that cannot be attributed to the current read semantics.
    ItemIdentityMigrationRequired,
    /// The position to save is longer, serialized compactly, than the
    /// engine's `next` cursor bound.
    PositionBound {
        /// The compact serialized length of the position.
        bytes: usize,
        /// The engine's bound.
        maximum: usize,
    },
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
            StoreError::SchemaBehind {
                found: None,
                supported,
            } => write!(
                formatter,
                "the adapter job database holds no job schema; this release applies version {supported}"
            ),
            StoreError::SchemaBehind {
                found: Some(found),
                supported,
            } => write!(
                formatter,
                "the adapter job database holds schema version {found}, behind the version {supported} this release applies"
            ),
            StoreError::LeaseHeld => write!(
                formatter,
                "a pass holds the job's lease; retry after it ends or its lease expires"
            ),
            StoreError::MigrationLock => write!(
                formatter,
                "the adapter job migration lock was not held when it was released"
            ),
            StoreError::LeaseLost => write!(
                formatter,
                "the pass lease was no longer held; another pass owns the job"
            ),
            StoreError::ReceiverIdentityUnknown => write!(
                formatter,
                "the pending delivery predates stored receiver identity; retry requires explicit recovery"
            ),
            StoreError::ReceiverIdentityChanged => write!(
                formatter,
                "the selected receiver identity changed while a delivery remains pending"
            ),
            StoreError::CanonicalBodyIdentityUnknown => write!(
                formatter,
                "the pending delivery predates its stored canonical body identity; retry requires explicit recovery"
            ),
            StoreError::CanonicalBodyIdentityChanged => write!(
                formatter,
                "the canonical event body changed while a delivery remains pending"
            ),
            StoreError::DeliveryAttemptExhausted => write!(
                formatter,
                "the pending delivery attempt reached the supported bigint bound"
            ),
            StoreError::ItemIdentityMigrationRequired => write!(
                formatter,
                "the file or SFTP item identity changed or predates its durable binding; an explicit migration is required"
            ),
            StoreError::PositionBound { bytes, maximum } => write!(
                formatter,
                "the position to save is {bytes} bytes serialized, over the {maximum}-byte cursor bound"
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

impl StoreError {
    /// A closed, value-free token naming what refused: the store condition,
    /// or for a refused query the PostgreSQL SQLSTATE (`sqlstate-42501`), so
    /// an operator can tell a missing grant from a dropped connection without
    /// the driver's prose.
    #[must_use]
    pub fn cause(&self) -> String {
        let token = match self {
            StoreError::SchemaNewer { .. } => "schema-newer",
            StoreError::SchemaBehind { .. } => "schema-behind",
            StoreError::MigrationLock => "migration-lock",
            StoreError::LeaseHeld => "lease-held",
            StoreError::LeaseLost => "lease-lost",
            StoreError::ReceiverIdentityUnknown => "receiver-identity-unknown",
            StoreError::ReceiverIdentityChanged => "receiver-identity-changed",
            StoreError::CanonicalBodyIdentityUnknown => "body-identity-unknown",
            StoreError::CanonicalBodyIdentityChanged => "body-identity-changed",
            StoreError::DeliveryAttemptExhausted => "delivery-attempt-exhausted",
            StoreError::ItemIdentityMigrationRequired => "item-identity-migration-required",
            StoreError::PositionBound { .. } => "position-bound",
            StoreError::Pool(_) => "pool",
            StoreError::Query(error) => return query_cause(error),
        };
        token.to_owned()
    }
}

/// The closed cause token of a driver error: its SQLSTATE when the server
/// answered, `connection-closed` when the connection dropped, `query`
/// otherwise.
#[must_use]
pub fn query_cause(error: &PgError) -> String {
    if let Some(code) = error.code() {
        format!("sqlstate-{}", code.code())
    } else if error.is_closed() {
        "connection-closed".to_owned()
    } else {
        "query".to_owned()
    }
}

/// The closed cause token of a pool checkout failure.
#[must_use]
pub fn pool_cause(error: &deadpool_postgres::PoolError) -> String {
    match error {
        deadpool_postgres::PoolError::Backend(error) => query_cause(error),
        deadpool_postgres::PoolError::Timeout(_) => "pool-timeout".to_owned(),
        _ => "pool".to_owned(),
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::SchemaNewer { .. }
            | StoreError::SchemaBehind { .. }
            | StoreError::MigrationLock
            | StoreError::LeaseHeld
            | StoreError::LeaseLost
            | StoreError::ReceiverIdentityUnknown
            | StoreError::ReceiverIdentityChanged
            | StoreError::CanonicalBodyIdentityUnknown
            | StoreError::CanonicalBodyIdentityChanged
            | StoreError::DeliveryAttemptExhausted
            | StoreError::ItemIdentityMigrationRequired
            | StoreError::PositionBound { .. }
            | StoreError::Pool(_) => None,
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

/// Refuse a database whose job schema is not the one this release
/// applies, without writing anything: the read-only check of the
/// commands that must not migrate, such as a dry run.
///
/// # Errors
///
/// A missing, older, or newer schema refuses, as does a failed read.
pub async fn schema_current(client: &impl GenericClient) -> Result<(), StoreError> {
    let present = client
        .query_one(
            "SELECT to_regclass('adapter_job_schema_migrations') IS NOT NULL",
            &[],
        )
        .await?
        .get::<_, bool>(0);
    let found = if present {
        client
            .query_one(
                "SELECT max(version) FROM adapter_job_schema_migrations",
                &[],
            )
            .await?
            .get::<_, Option<i64>>(0)
    } else {
        None
    };
    match found {
        Some(found) if found > SUPPORTED_SCHEMA_VERSION => Err(StoreError::SchemaNewer {
            found,
            supported: SUPPORTED_SCHEMA_VERSION,
        }),
        Some(SUPPORTED_SCHEMA_VERSION) => Ok(()),
        found => Err(StoreError::SchemaBehind {
            found,
            supported: SUPPORTED_SCHEMA_VERSION,
        }),
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
        // One simple-query batch carries the migration and its version
        // row: PostgreSQL runs a multi-statement simple query as one
        // implicit transaction, so a failure anywhere in it, the version
        // insert included, leaves neither, and the next run applies the
        // whole migration again. The version is this crate's own integer
        // constant, never input.
        client
            .batch_execute(&format!(
                "{migration}\n;INSERT INTO adapter_job_schema_migrations(version,applied_at) \
                 VALUES({version},now())"
            ))
            .await?;
    }
    Ok(())
}

/// The job store block of the operator runtime config (`store:`), read
/// by the one job runtime reader the compile path shares.
pub use registry_adapter_engine::job_sources::JobStoreConfig;

/// The margin the pass lease carries beside the profile's page
/// deadline, renewed at every fenced write, so an operator sees a
/// stalled pass in status before the lease frees.
pub const LEASE_MARGIN_SECONDS: u64 = 60;

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
    #[cfg(feature = "postgres-test")]
    let pool = if config.test_only_plaintext {
        postgres.ssl_mode(tokio_postgres::config::SslMode::Disable);
        build_verified_pool(postgres, tokio_postgres::NoTls, 4)
    } else {
        postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
        build_verified_pool(postgres, tls_connector(config, resolver)?, 4)
    };
    #[cfg(not(feature = "postgres-test"))]
    let pool = {
        if config.test_only_plaintext {
            return Err(invalid("plaintext connections are refused in this build"));
        }
        postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
        build_verified_pool(postgres, tls_connector(config, resolver)?, 4)
    };
    pool.map_err(|error| invalid(&error))
}

/// Build one finite verified PostgreSQL pool. The store and every source pool
/// share the same connection-health check and acquisition deadlines; callers
/// still choose their own connection config and TLS posture.
pub(crate) fn build_verified_pool<T>(
    postgres: tokio_postgres::Config,
    tls: T,
    maximum_connections: usize,
) -> Result<Pool, String>
where
    T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
    T::Stream: Sync + Send,
    T::TlsConnect: Sync + Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    let manager = Manager::from_config(
        postgres,
        tls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        },
    );
    Pool::builder(manager)
        .max_size(maximum_connections)
        .wait_timeout(Some(Duration::from_secs(5)))
        .create_timeout(Some(Duration::from_secs(5)))
        .recycle_timeout(Some(Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|error| format!("the pool could not be built: {error}"))
}

/// The TLS connector for the job host's database connections: the
/// configured root certificate when the store block names one, the
/// platform's own roots otherwise.
fn tls_connector(
    config: &JobStoreConfig,
    resolver: &SecretResolver,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, StoreError> {
    let invalid = |what: &str| StoreError::Pool(format!("store: {what}"));
    let Some(reference) = &config.trusted_root_certificate_ref else {
        return native_postgres_tls()
            .map_err(|_| invalid("no platform root certificate could be loaded"));
    };
    let protected = resolver
        .resolve(reference.as_str())
        .map_err(|_| invalid("a certificate reference could not be resolved"))?;
    postgres_tls_from_pem(protected.expose_secret())
        .map_err(|_| invalid("a trusted certificate is unreadable or unusable"))
}

/// TLS using the platform's native roots, including the existing value-free
/// warning for a root the platform skipped.
pub(crate) fn native_postgres_tls() -> Result<tokio_postgres_rustls::MakeRustlsConnect, ()> {
    let (connector, warnings) =
        tokio_postgres_rustls::MakeRustlsConnect::with_native_certs().map_err(|_| ())?;
    for warning in warnings {
        tracing::warn!("a platform root certificate was skipped: {warning}");
    }
    Ok(connector)
}

/// TLS over a caller-supplied bounded PEM bundle. Crypto-provider selection
/// remains the store's existing ring selection and is reused by source pools.
pub(crate) fn postgres_tls_from_pem(
    pem: &[u8],
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, ()> {
    postgres_tls_from_root_store(postgres_root_store_from_pem(pem)?)
}

/// TLS over the platform roots plus a caller-supplied bounded PEM bundle.
/// Source connections use this additive trust posture; the job store keeps
/// its existing configured-root replacement behavior above.
#[cfg(feature = "job-postgres")]
pub(crate) fn postgres_tls_from_native_and_pem(
    pem: &[u8],
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, ()> {
    let mut roots = native_postgres_root_store()?;
    if add_pem_roots(&mut roots, pem)? == 0 {
        return Err(());
    }
    postgres_tls_from_root_store(roots)
}

fn postgres_root_store_from_pem(pem: &[u8]) -> Result<rustls::RootCertStore, ()> {
    let mut roots = rustls::RootCertStore::empty();
    let _ = add_pem_roots(&mut roots, pem)?;
    Ok(roots)
}

fn add_pem_roots(roots: &mut rustls::RootCertStore, pem: &[u8]) -> Result<usize, ()> {
    use rustls::pki_types::pem::PemObject as _;
    let mut count = 0_usize;
    for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(pem) {
        roots.add(certificate.map_err(|_| ())?).map_err(|_| ())?;
        count += 1;
    }
    Ok(count)
}

#[cfg(feature = "job-postgres")]
fn native_postgres_root_store() -> Result<rustls::RootCertStore, ()> {
    let native = rustls_native_certs::load_native_certs();
    for _ in native.errors {
        tracing::warn!("a platform root certificate was skipped");
    }
    if native.certs.is_empty() {
        return Err(());
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(native.certs);
    Ok(roots)
}

fn postgres_tls_from_root_store(
    roots: rustls::RootCertStore,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, ()> {
    #[cfg(feature = "job-rabbitmq")]
    crate::tls_provider::initialize().map_err(|_| ())?;
    #[cfg(not(feature = "job-rabbitmq"))]
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client))
}

#[cfg(all(test, feature = "job-postgres"))]
mod postgres_tls_tests {
    use super::*;

    const PRIVATE_ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
MIIBnzCCAUWgAwIBAgIUGSkZVSD93tTafMYk9zXkW+9N+VcwCgYIKoZIzj0EAwIw\n\
JTEjMCEGA1UEAwwaUmVnaXN0cnkgQWRhcHRlciBUZXN0IFJvb3QwHhcNMjYxMDMw\n\
MDQ1NDIwWhcNMzYxMDI3MDQ1NDIwWjAlMSMwIQYDVQQDDBpSZWdpc3RyeSBBZGFw\n\
dGVyIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIDV7zIjqChx\n\
97aw2DaQUGi02tuThFuNl5IKP4RFr+5lxRclqsvlNfhU0Y4JnNLDuxdToqXgVKz6\n\
DnA2hpkMqZyjUzBRMB0GA1UdDgQWBBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAfBgNV\n\
HSMEGDAWgBSPV2C1/cYwPYf/YYcSqJMvbWT8OjAPBgNVHRMBAf8EBTADAQH/MAoG\n\
CCqGSM49BAMCA0gAMEUCIQDE6ceiEQLBfR3wcAbPoXkClwMWZCs+QRHpi9asKR6w\n\
GwIgG/WsmuvsVVNeDynYVj92+B5SNtyVRK2+p3eo97VtmF0=\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn source_private_roots_are_additive_while_store_private_roots_replace() {
        let native = native_postgres_root_store().expect("the test host has platform roots");
        let replacement =
            postgres_root_store_from_pem(PRIVATE_ROOT).expect("the private root parses");
        let mut additive = native_postgres_root_store().expect("the platform roots reload");
        let added = add_pem_roots(&mut additive, PRIVATE_ROOT).expect("the private root appends");
        assert_eq!(added, 1);
        assert_eq!(
            replacement.len(),
            1,
            "the store's custom roots still replace"
        );
        assert!(
            additive.len() > native.len(),
            "the source keeps platform roots and adds its private root"
        );
    }
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
    /// Delivery cannot safely continue without an operator's decision.
    Held,
}

impl ItemStatus {
    /// The wire spelling of the status, the operator output's.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ItemStatus::Pending => "pending",
            ItemStatus::Acknowledged => "acknowledged",
            ItemStatus::Refused => "refused",
            ItemStatus::Held => "held",
        }
    }

    fn from_str(status: &str) -> Option<Self> {
        match status {
            "pending" => Some(ItemStatus::Pending),
            "acknowledged" => Some(ItemStatus::Acknowledged),
            "refused" => Some(ItemStatus::Refused),
            "held" => Some(ItemStatus::Held),
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
    /// The saved reference of the last accepted hand-off, carried while
    /// a changed delivery is pending or refused.
    pub prior_run_id: Option<String>,
    /// Whether an earlier digest's receipt may have been lost.
    pub admitted_before: bool,
    /// The persisted event identity time for this item key.
    pub first_seen: SystemTime,
    /// The frozen signed-event time for the current sequence.
    pub event_time: SystemTime,
    /// The latest delivery attempt persisted for the current sequence.
    pub delivery_attempt: i64,
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
            ItemStatus::Held => Decision::Skip,
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
    /// When the key first entered the item table, used for status age.
    pub first_seen: SystemTime,
    /// The frozen event time for this sequence. A retry receives the exact
    /// same value, while a changed digest receives a new sequence time.
    pub event_time: SystemTime,
    /// The positive delivery attempt for this sequence. A same-sequence
    /// re-delivery advances it only after receiver identity agrees.
    pub delivery_attempt: i64,
    /// Whether this is a retry of a pending hand-off whose receipt may have
    /// been lost. Only this state is governed by BReg's receipt horizon.
    pub receipt_uncertain: bool,
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
#[allow(clippy::too_many_arguments)]
pub async fn stage_item(
    client: &mut Object,
    job_id: &str,
    key: &str,
    digest: &str,
    retry_refused: bool,
    now: SystemTime,
    token: i64,
    ttl: Duration,
) -> Result<Option<StagedItem>, StoreError> {
    let now = storage_time(now);
    let tx = client.transaction().await?;
    renew_lease(&tx, job_id, token, ttl).await?;
    let prior = read_prior(&tx, job_id, key, true).await?;
    let decision = decide(prior.as_ref(), digest, retry_refused);
    let staged = match decision {
        Decision::Skip => None,
        Decision::DeliverNew => {
            tx.execute(
                "INSERT INTO adapter_job_items \
                 (job_id, item_key, last_digest, sequence, status, first_seen, last_seen, \
                  event_time, delivery_attempt, receiver_identity_known, canonical_body_identity_known) \
                 VALUES ($1, $2, $3, 1, 'pending', $4, $4, $4, 1, true, true)",
                &[&job_id, &key, &digest, &now],
            )
            .await?;
            Some(StagedItem {
                key: key.to_string(),
                sequence: 1,
                digest: digest.to_string(),
                prior_run_id: None,
                admitted_before: false,
                first_seen: now,
                event_time: now,
                delivery_attempt: 1,
                receipt_uncertain: false,
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
                     code = NULL, run_id = NULL, prior_run_id = COALESCE(run_id, prior_run_id), \
                     admitted_before = $4, last_seen = $5, event_time = $5, \
                     delivery_attempt = 1, receiver_identity = NULL, receiver_identity_known = true, \
                     canonical_body_identity = NULL, canonical_body_identity_known = true \
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
                prior_run_id: prior.run_id.clone().or_else(|| prior.prior_run_id.clone()),
                admitted_before,
                first_seen: prior.first_seen,
                event_time: now,
                delivery_attempt: 1,
                receipt_uncertain: false,
                classification: StagedClassification::Changed,
            })
        }
        Decision::DeliverRedelivery => {
            let prior = prior.as_ref().expect("a re-delivery implies a prior row");
            let delivery_attempt = prior
                .delivery_attempt
                .checked_add(1)
                .ok_or(StoreError::DeliveryAttemptExhausted)?;
            // A rescan of a refused row clears the frozen receiver and body
            // identities: the refusal answered the latest attempt, and
            // `admitted_before` carries any earlier attempt that may have
            // been admitted. A pending row keeps them, because its latest
            // attempt may still be outstanding under them.
            let refused = prior.status == ItemStatus::Refused;
            tx.execute(
                "UPDATE adapter_job_items SET status = 'pending', code = NULL, last_seen = $3, \
                 receiver_identity = CASE WHEN $4 THEN NULL ELSE receiver_identity END, \
                 receiver_identity_known = receiver_identity_known OR $4, \
                 canonical_body_identity = CASE WHEN $4 THEN NULL ELSE canonical_body_identity END, \
                 canonical_body_identity_known = canonical_body_identity_known OR $4 \
                 WHERE job_id = $1 AND item_key = $2",
                &[&job_id, &key, &now, &refused],
            )
            .await?;
            Some(StagedItem {
                key: key.to_string(),
                sequence: prior.sequence,
                digest: digest.to_string(),
                prior_run_id: prior.run_id.clone().or_else(|| prior.prior_run_id.clone()),
                admitted_before: prior.admitted_before,
                first_seen: prior.first_seen,
                event_time: prior.event_time,
                delivery_attempt,
                receipt_uncertain: prior.status == ItemStatus::Pending,
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
    now: SystemTime,
) -> Result<Option<StagedItem>, StoreError> {
    let now = storage_time(now);
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
            first_seen: now,
            event_time: now,
            delivery_attempt: 1,
            receipt_uncertain: false,
            classification: StagedClassification::New,
        }),
        (Decision::Skip, _) => None,
        (Decision::DeliverChanged, Some(prior)) => Some(StagedItem {
            key: key.to_string(),
            sequence: prior.sequence + 1,
            digest: digest.to_string(),
            prior_run_id: prior.run_id.clone().or_else(|| prior.prior_run_id.clone()),
            admitted_before: prior.admitted_before
                || matches!(prior.status, ItemStatus::Pending | ItemStatus::Acknowledged),
            first_seen: prior.first_seen,
            event_time: now,
            delivery_attempt: 1,
            receipt_uncertain: false,
            classification: StagedClassification::Changed,
        }),
        (Decision::DeliverRedelivery, Some(prior)) => Some(StagedItem {
            key: key.to_string(),
            sequence: prior.sequence,
            digest: digest.to_string(),
            prior_run_id: prior.run_id.clone().or_else(|| prior.prior_run_id.clone()),
            admitted_before: prior.admitted_before,
            first_seen: prior.first_seen,
            event_time: prior.event_time,
            delivery_attempt: prior
                .delivery_attempt
                .checked_add(1)
                .ok_or(StoreError::DeliveryAttemptExhausted)?,
            receipt_uncertain: prior.status == ItemStatus::Pending,
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
        "SELECT last_digest, sequence, status, run_id, prior_run_id, admitted_before, first_seen, \
         event_time, delivery_attempt \
         FROM adapter_job_items WHERE job_id = $1 AND item_key = $2 FOR UPDATE"
    } else {
        "SELECT last_digest, sequence, status, run_id, prior_run_id, admitted_before, first_seen, \
         event_time, delivery_attempt \
         FROM adapter_job_items WHERE job_id = $1 AND item_key = $2"
    };
    let row = client.query_opt(query, &[&job_id, &key]).await?;
    Ok(row.map(|row| PriorRow {
        last_digest: row.get(0),
        sequence: row.get(1),
        status: ItemStatus::from_str(row.get(2)).expect("the status check admits four values"),
        run_id: row.get(3),
        prior_run_id: row.get(4),
        admitted_before: row.get(5),
        first_seen: row.get(6),
        event_time: row.get(7),
        delivery_attempt: row.get(8),
    }))
}

/// Freeze or verify the selected public receiver identity before a signed
/// delivery leaves the process. The write and lease renewal commit together.
/// A pending retry can proceed only under exact identity equality. Staging a
/// rescan of a refused row clears its stored identities, so the receiver
/// selected when it is next sent binds, even after a crash between staging
/// and this call. With `allow_rebind`, which the pass sets only for a rescan
/// of a refused row, the currently selected identities replace the stored
/// ones without comparison. The refusal answered the latest attempt, but a
/// row that carries `admitted_before` may have had an earlier attempt
/// admitted; this function does not guard that case. The destination does:
/// for such a row the Coordinator destination selects its revised trigger,
/// and without one, or on the direct BReg destination, it names no delivery
/// identity, so nothing binds and the item is held.
///
/// # Errors
///
/// A legacy pending row with no identity, a changed identity, a lost lease,
/// a missing row, or a failed write refuses before the destination is called.
#[allow(clippy::too_many_arguments)]
pub async fn bind_delivery_identity(
    client: &mut Object,
    job_id: &str,
    key: &str,
    receiver_identity: &[u8; 32],
    canonical_body_identity: &[u8; 32],
    delivery_attempt: i64,
    allow_rebind: bool,
    token: i64,
    ttl: Duration,
) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    renew_lease(&tx, job_id, token, ttl).await?;
    let row = tx
        .query_opt(
            "SELECT receiver_identity_known, receiver_identity, \
                    canonical_body_identity_known, canonical_body_identity \
             FROM adapter_job_items \
             WHERE job_id = $1 AND item_key = $2 FOR UPDATE",
            &[&job_id, &key],
        )
        .await?
        .ok_or_else(missing_item)?;
    let known: bool = row.get(0);
    let stored: Option<Vec<u8>> = row.get(1);
    let body_known: bool = row.get(2);
    let stored_body: Option<Vec<u8>> = row.get(3);
    let agrees = stored.as_deref() == Some(receiver_identity.as_slice());
    let body_agrees = stored_body.as_deref() == Some(canonical_body_identity.as_slice());
    if !allow_rebind && !known {
        return Err(StoreError::ReceiverIdentityUnknown);
    }
    if !allow_rebind && stored.is_some() && !agrees {
        return Err(StoreError::ReceiverIdentityChanged);
    }
    if !allow_rebind && !body_known {
        return Err(StoreError::CanonicalBodyIdentityUnknown);
    }
    if !allow_rebind && stored_body.is_some() && !body_agrees {
        return Err(StoreError::CanonicalBodyIdentityChanged);
    }
    tx.execute(
        "UPDATE adapter_job_items SET receiver_identity_known = true, receiver_identity = $3, \
         canonical_body_identity_known = true, canonical_body_identity = $4, \
         delivery_attempt = $5 WHERE job_id = $1 AND item_key = $2",
        &[
            &job_id,
            &key,
            &receiver_identity.as_slice(),
            &canonical_body_identity.as_slice(),
            &delivery_attempt,
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Record an acknowledged hand-off: the row settles, the destination's
/// reference is stored, and the key counts as admitted from here on. The
/// lease renewal and the row write commit together.
///
/// # Errors
///
/// A lost lease, a missing row, or a failed write refuses; the caller
/// treats the item as undelivered and a later pass re-delivers.
#[allow(clippy::too_many_arguments)]
pub async fn record_acknowledged(
    client: &mut Object,
    job_id: &str,
    key: &str,
    run_id: Option<&str>,
    now: SystemTime,
    token: i64,
    ttl: Duration,
) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    renew_lease(&tx, job_id, token, ttl).await?;
    let row = tx
        .execute(
            "UPDATE adapter_job_items SET status = 'acknowledged', run_id = $3, code = NULL, \
             admitted_before = true, last_seen = $4 WHERE job_id = $1 AND item_key = $2",
            &[&job_id, &key, &run_id, &now],
        )
        .await?;
    if row != 1 {
        return Err(missing_item());
    }
    tx.commit().await?;
    Ok(())
}

/// The refusal of an answer whose staged row is not there to record it.
fn missing_item() -> StoreError {
    StoreError::Pool("the item row the answer belongs to was not found".to_string())
}

/// Record an item-scoped refusal: the code is stored, the row stays
/// identified, and the pass continues. The lease renewal and the row
/// write commit together.
///
/// `possibly_admitted` is true when the refusal answered the retry of a
/// hand-off whose first answer was lost. The refusal proves nothing about
/// that first attempt, so the row is marked possibly admitted and a later
/// digest or rescan is a revision, never a second registration. A refusal
/// never clears an existing mark.
///
/// # Errors
///
/// A lost lease, a missing row, or a failed write refuses; the caller
/// treats the item as undelivered and a later pass re-delivers.
#[allow(clippy::too_many_arguments)]
pub async fn record_refused(
    client: &mut Object,
    job_id: &str,
    key: &str,
    code: &str,
    possibly_admitted: bool,
    now: SystemTime,
    token: i64,
    ttl: Duration,
) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    renew_lease(&tx, job_id, token, ttl).await?;
    let row = tx
        .execute(
            "UPDATE adapter_job_items SET status = 'refused', code = $3, run_id = NULL, \
             admitted_before = admitted_before OR $5, last_seen = $4 \
             WHERE job_id = $1 AND item_key = $2",
            &[&job_id, &key, &code, &now, &possibly_admitted],
        )
        .await?;
    if row != 1 {
        return Err(missing_item());
    }
    tx.commit().await?;
    Ok(())
}

/// Hold one item for an operator: the code and optional destination
/// reference are retained, and the row counts as possibly admitted so a
/// later digest is a revision. A held row has no automatic release or
/// mark-accepted transition; only a later source digest can move it back
/// through staging.
///
/// # Errors
///
/// A lost lease, a missing row, or a failed write refuses; the caller
/// stops rather than claiming the item was held durably.
#[allow(clippy::too_many_arguments)]
pub async fn record_held(
    client: &mut Object,
    job_id: &str,
    key: &str,
    code: &str,
    run_id: Option<&str>,
    now: SystemTime,
    token: i64,
    ttl: Duration,
) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    renew_lease(&tx, job_id, token, ttl).await?;
    let row = tx
        .execute(
            "UPDATE adapter_job_items SET status = 'held', code = $3, \
             run_id = COALESCE($4, run_id), admitted_before = true, last_seen = $5 \
             WHERE job_id = $1 AND item_key = $2",
            &[&job_id, &key, &code, &run_id, &now],
        )
        .await?;
    if row != 1 {
        return Err(missing_item());
    }
    tx.commit().await?;
    Ok(())
}

/// Create the job's state row when the job's first pass needs it;
/// existing rows are untouched.
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

/// Bind the governed file/SFTP item identity function before any source read.
/// A legacy state may adopt it only while both its cursor and item set are
/// empty. Equality is recoverable; mismatch or non-empty legacy state requires
/// an explicit operator migration and never rewrites existing identity.
///
/// # Errors
///
/// A mismatch, non-empty legacy state, lost lease, missing state row, or failed
/// query refuses without changing the saved position or item rows.
pub async fn bind_item_identity(
    client: &mut Object,
    job_id: &str,
    digest: Option<&[u8; 32]>,
    token: i64,
    ttl: Duration,
) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    renew_lease(&tx, job_id, token, ttl).await?;
    let state = tx
        .query_opt(
            "SELECT item_identity_digest, position FROM adapter_job_state \
             WHERE job_id = $1 FOR UPDATE",
            &[&job_id],
        )
        .await?
        .ok_or_else(|| {
            StoreError::Pool("the job state row disappeared while its lease was held".to_string())
        })?;
    let stored: Option<Vec<u8>> = state.get(0);
    let position: Option<Value> = state.get(1);
    let holds_state =
        unbound_state_present(&tx, job_id, stored.as_deref(), digest, &position).await?;
    match identity_verdict(stored.as_deref(), digest, holds_state) {
        IdentityVerdict::Bound => {
            tx.commit().await?;
            return Ok(());
        }
        IdentityVerdict::Refused => return Err(StoreError::ItemIdentityMigrationRequired),
        IdentityVerdict::Adopt => {}
    }
    let digest = digest.expect("the none/none identity state returned above");
    tx.execute(
        "UPDATE adapter_job_state SET item_identity_digest = $2 WHERE job_id = $1",
        &[&job_id, &digest.as_slice()],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// What the item-identity fence decides for one stored binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityVerdict {
    /// The stored binding already equals the job's, or neither exists.
    Bound,
    /// An unbound legacy state with no cursor and no items adopts it.
    Adopt,
    /// A different binding, or unbound state that already holds a cursor or
    /// items, needs the operator's explicit rebind.
    Refused,
}

/// Whether an unbound state already holds a cursor or items. Only that case
/// reads the item table, so a bound job pays no per-pass count.
async fn unbound_state_present(
    client: &impl GenericClient,
    job_id: &str,
    stored: Option<&[u8]>,
    digest: Option<&[u8; 32]>,
    position: &Option<Value>,
) -> Result<bool, StoreError> {
    if stored.is_some() || digest.is_none() {
        return Ok(false);
    }
    if position.is_some() {
        return Ok(true);
    }
    let item_count: i64 = client
        .query_one(
            "SELECT count(*) FROM adapter_job_items WHERE job_id = $1",
            &[&job_id],
        )
        .await?
        .get(0);
    Ok(item_count != 0)
}

fn identity_verdict(
    stored: Option<&[u8]>,
    digest: Option<&[u8; 32]>,
    holds_state: bool,
) -> IdentityVerdict {
    match (stored, digest) {
        (Some(stored), Some(digest)) if stored == digest.as_slice() => IdentityVerdict::Bound,
        (Some(_), _) => IdentityVerdict::Refused,
        (None, None) => IdentityVerdict::Bound,
        (None, Some(_)) if holds_state => IdentityVerdict::Refused,
        (None, Some(_)) => IdentityVerdict::Adopt,
    }
}

/// Apply the item-identity fence without writing, for the dry run: the same
/// verdict a real pass would reach, so a preview never looks clean over a
/// state the next real pass refuses. A job with no state row yet has no
/// binding to disagree with.
///
/// # Errors
///
/// [`StoreError::ItemIdentityMigrationRequired`] when a real pass would stop
/// at the fence; a failed query refuses.
pub async fn check_item_identity(
    client: &impl GenericClient,
    job_id: &str,
    digest: Option<&[u8; 32]>,
) -> Result<(), StoreError> {
    let Some(state) = client
        .query_opt(
            "SELECT item_identity_digest, position FROM adapter_job_state WHERE job_id = $1",
            &[&job_id],
        )
        .await?
    else {
        return Ok(());
    };
    let stored: Option<Vec<u8>> = state.get(0);
    let position: Option<Value> = state.get(1);
    let holds_state =
        unbound_state_present(client, job_id, stored.as_deref(), digest, &position).await?;
    match identity_verdict(stored.as_deref(), digest, holds_state) {
        IdentityVerdict::Refused => Err(StoreError::ItemIdentityMigrationRequired),
        IdentityVerdict::Bound | IdentityVerdict::Adopt => Ok(()),
    }
}

/// The outcome of an explicit item-identity rebind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRebind {
    /// False when the stored binding already equalled the job's.
    pub changed: bool,
    /// The item rows the job holds; a rebind never rewrites or removes them.
    pub items_kept: i64,
}

/// Move the stored item-identity binding to the job as it is authored now.
/// This is the operator's explicit acceptance after an intended `keyPointer`
/// or CSV change: the existing item rows keep the keys they were stored under
/// and are not rewritten. The job's lease must be free, so no pass is running
/// under the old identity.
///
/// # Errors
///
/// [`StoreError::LeaseHeld`] while a pass holds the lease; a failed query
/// refuses.
pub async fn rebind_item_identity(
    client: &mut Object,
    job_id: &str,
    digest: Option<&[u8; 32]>,
) -> Result<IdentityRebind, StoreError> {
    let tx = client.transaction().await?;
    let state = tx
        .query_opt(
            "SELECT item_identity_digest, (lease_expires IS NOT NULL AND lease_expires > now()) \
             FROM adapter_job_state WHERE job_id = $1 FOR UPDATE",
            &[&job_id],
        )
        .await?;
    let items_kept: i64 = tx
        .query_one(
            "SELECT count(*) FROM adapter_job_items WHERE job_id = $1",
            &[&job_id],
        )
        .await?
        .get(0);
    let Some(state) = state else {
        // A job that never ran has nothing to rebind; the first pass binds it.
        tx.commit().await?;
        return Ok(IdentityRebind {
            changed: false,
            items_kept,
        });
    };
    let leased: bool = state.get(1);
    if leased {
        return Err(StoreError::LeaseHeld);
    }
    let stored: Option<Vec<u8>> = state.get(0);
    let wanted = digest.map(<[u8; 32]>::as_slice);
    if stored.as_deref() == wanted {
        tx.commit().await?;
        return Ok(IdentityRebind {
            changed: false,
            items_kept,
        });
    }
    tx.execute(
        "UPDATE adapter_job_state SET item_identity_digest = $2 WHERE job_id = $1",
        &[&job_id, &wanted],
    )
    .await?;
    tx.commit().await?;
    Ok(IdentityRebind {
        changed: true,
        items_kept,
    })
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
    /// Whether a rescan traversal is between its first page and its
    /// end.
    pub rescan_active: bool,
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
             last_rescan_at, rescan_active, idle_streak, error_streak \
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
        rescan_active: row.get(6),
        idle_streak: row.get(7),
        error_streak: row.get(8),
    }))
}

/// The state one pass leases: the fencing token the lease wrote, and
/// the row's position and rescan marker read atomically with the grant,
/// so the pass can never act on a position a competing pass replaced.
pub struct LeasedState {
    /// The lease epoch this grant took; every fenced write must still
    /// name it. A renewal extends the expiry without moving the epoch,
    /// and the next grant's epoch invalidates this one.
    pub token: i64,
    /// The opaque page cursor the lease came with.
    pub position: Option<Value>,
    /// Whether a rescan traversal is between its first page and its
    /// end.
    pub rescan_active: bool,
}

/// Take the job's pass lease under the database clock: one pass at a
/// time per job. The lease refuses while another pass's lease is live
/// and grants when it is free, expired, or absent. The grant returns
/// the row's own state, read in the same statement that wrote the
/// lease, so the pass reads no position but its own.
///
/// # Errors
///
/// A failed write refuses; an error is never a held lease, which is
/// the `None` answer.
pub async fn take_lease(
    client: &impl GenericClient,
    job_id: &str,
    ttl: Duration,
) -> Result<Option<LeasedState>, StoreError> {
    // make_interval's secs member is double precision.
    let ttl = ttl.as_secs().min(i64::MAX as u64) as f64;
    let granted = client
        .query_opt(
            "UPDATE adapter_job_state SET lease_epoch = lease_epoch + 1, \
             lease_expires = now() + make_interval(secs => $2) \
             WHERE job_id = $1 AND (lease_expires IS NULL OR lease_expires <= now()) \
             RETURNING lease_epoch, position, rescan_active",
            &[&job_id, &ttl],
        )
        .await?;
    Ok(granted.map(|row| LeasedState {
        token: row.get(0),
        position: row.get(1),
        rescan_active: row.get(2),
    }))
}

/// Re-assert and renew the pass's lease: the write every fenced store
/// call begins with, so a delivery that outlived the lease, or a lease
/// another pass replaced, refuses before any state moves.
///
/// # Errors
///
/// [`StoreError::LeaseLost`] when the token no longer names the held
/// lease; a failed write refuses.
pub async fn renew_lease(
    client: &impl GenericClient,
    job_id: &str,
    token: i64,
    ttl: Duration,
) -> Result<(), StoreError> {
    let ttl = ttl.as_secs().min(i64::MAX as u64) as f64;
    let renewed = client
        .execute(
            "UPDATE adapter_job_state SET lease_expires = now() + make_interval(secs => $3) \
             WHERE job_id = $1 AND lease_epoch = $2 \
             AND lease_expires IS NOT NULL AND lease_expires > now()",
            &[&job_id, &token, &ttl],
        )
        .await?;
    if renewed != 1 {
        return Err(StoreError::LeaseLost);
    }
    Ok(())
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

/// Where a settled pass leaves the rescan traversal it ran in. The pass
/// decides, because only it knows the source's scan: a finite scan ends
/// where its cursor clears, and an ongoing scan, which holds its place
/// at the tail with a cursor on every page, ends at its first empty page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RescanProgress {
    /// The pass ran in no rescan traversal.
    None,
    /// The traversal has pages left; the marker holds.
    Continues,
    /// The traversal reached its end; the marker clears and the
    /// source's declared delay starts.
    Ended,
}

/// Settle a completed pass: save the page's next cursor, or clear the
/// position at a finite end, stamp the pass, count the pass into the
/// schedule streaks, and release the lease. A rescan pass that ends its
/// traversal stamps its completion, which starts the source's declared
/// delay.
///
/// # Errors
///
/// A position over the engine's cursor bound refuses under
/// [`StoreError::PositionBound`]; a lost lease or a failed write
/// refuses.
pub async fn complete_pass(
    client: &impl GenericClient,
    job_id: &str,
    token: i64,
    position: Option<&Value>,
    idle: bool,
    rescan: RescanProgress,
    now: SystemTime,
) -> Result<(), StoreError> {
    // A rescan traversal stays in progress while pages remain: the
    // marker clears and the delay clock starts only at its end.
    // The two outcomes are computed here, not in the statement: a
    // parameter that only answers IS NULL carries no type of its own.
    // The engine bounds a cursor by its compact serialization; the jsonb
    // text form PostgreSQL renders is longer, so the bound is checked
    // here rather than in the table.
    if let Some(position) = position {
        let bytes = serde_json::to_vec(position)
            .map_err(|error| StoreError::Pool(format!("the position does not serialize: {error}")))?
            .len();
        if bytes > registry_adapter_core::MAXIMUM_NEXT_BYTES {
            return Err(StoreError::PositionBound {
                bytes,
                maximum: registry_adapter_core::MAXIMUM_NEXT_BYTES,
            });
        }
    }
    let rescan_finished = rescan == RescanProgress::Ended;
    let rescan_continues = rescan == RescanProgress::Continues;
    let settled = client
        .execute(
            "UPDATE adapter_job_state SET \
             position = $2, last_pass_at = $3, last_pass_stop = NULL, lease_expires = NULL, \
             last_rescan_at = CASE WHEN $4 THEN $3 ELSE last_rescan_at END, \
             rescan_active = $5, \
             idle_streak = CASE WHEN $6 THEN idle_streak + 1 ELSE 0 END, \
             error_streak = 0 \
             WHERE job_id = $1 AND lease_epoch = $7",
            &[
                &job_id,
                &position,
                &now,
                &rescan_finished,
                &rescan_continues,
                &idle,
                &token,
            ],
        )
        .await?;
    if settled != 1 {
        return Err(StoreError::LeaseLost);
    }
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
    token: i64,
    stop_code: &str,
    now: SystemTime,
) -> Result<(), StoreError> {
    let stopped = client
        .execute(
            "UPDATE adapter_job_state SET \
             last_pass_at = $3, last_pass_stop = $4, lease_expires = NULL, \
             error_streak = error_streak + 1, idle_streak = 0 \
             WHERE job_id = $1 AND lease_epoch = $2",
            &[&job_id, &token, &now, &stop_code],
        )
        .await?;
    if stopped != 1 {
        return Err(StoreError::LeaseLost);
    }
    Ok(())
}

/// Mark a rescan due now, so the next pass starts a new traversal from
/// the first page regardless of the declared delay. An active traversal
/// is abandoned only through this explicit operator action, and never
/// under a pass that holds the lease: that pass saves its own position.
///
/// # Errors
///
/// [`StoreError::LeaseHeld`] while a pass holds the lease, or when no
/// state row exists; a failed write refuses.
pub async fn mark_rescan_due(client: &impl GenericClient, job_id: &str) -> Result<(), StoreError> {
    let marked = client
        .execute(
            "UPDATE adapter_job_state SET last_rescan_at = NULL, rescan_active = false \
             WHERE job_id = $1 AND (lease_expires IS NULL OR lease_expires <= now())",
            &[&job_id],
        )
        .await?;
    if marked != 1 {
        return Err(StoreError::LeaseHeld);
    }
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
    /// Rows waiting for an operator without another automatic attempt.
    pub held: u64,
    /// Refused rows by the destination's own code.
    pub refusals_by_code: BTreeMap<String, u64>,
    /// Held rows by their value-free reason code.
    pub holds_by_code: BTreeMap<String, u64>,
    /// The keys of the oldest pending rows, at most [`PENDING_KEYS_SHOWN`]:
    /// the rows a stopped pass keeps retrying first.
    pub pending_keys: Vec<String>,
}

/// How many pending keys status names.
pub const PENDING_KEYS_SHOWN: i64 = 5;

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
            Some(ItemStatus::Held) => counts.held = count.max(0) as u64,
            None => {}
        }
    }
    for row in client
        .query(
            "SELECT code, count(*) FROM adapter_job_items \
             WHERE job_id = $1 AND status = 'held' AND code IS NOT NULL GROUP BY code",
            &[&job_id],
        )
        .await?
    {
        let code: String = row.get(0);
        let count: i64 = row.get(1);
        counts.holds_by_code.insert(code, count.max(0) as u64);
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
    counts.pending_keys = client
        .query(
            "SELECT item_key FROM adapter_job_items \
             WHERE job_id = $1 AND status = 'pending' ORDER BY sequence, item_key LIMIT $2",
            &[&job_id, &PENDING_KEYS_SHOWN],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    Ok(counts)
}

/// Pending direct-BReg receipts close to, or already past, the job's
/// declared receipt horizon. The warning window is the last day of the
/// horizon and carries counts only, never item identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiptHorizonCounts {
    pub nearing: u64,
    pub expired: u64,
}

/// Count pending rows in the last day before the receipt horizon and rows
/// already past it. BReg's receipt belongs to the current sequence's command
/// key, so the horizon counts from the sequence's event time, not the key's
/// first sighting.
pub async fn receipt_horizon_counts(
    client: &impl GenericClient,
    job_id: &str,
    now: SystemTime,
    retention_days: u16,
) -> Result<ReceiptHorizonCounts, StoreError> {
    let horizon = Duration::from_secs(u64::from(retention_days) * 86_400);
    let warning_age = horizon.saturating_sub(Duration::from_secs(86_400));
    let warning_before = now
        .checked_sub(warning_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let expired_before = now.checked_sub(horizon).unwrap_or(SystemTime::UNIX_EPOCH);
    let row = client
        .query_one(
            "SELECT \
             count(*) FILTER (WHERE event_time <= $3 AND event_time > $2), \
             count(*) FILTER (WHERE event_time <= $2) \
             FROM adapter_job_items WHERE job_id = $1 AND status = 'pending'",
            &[&job_id, &expired_before, &warning_before],
        )
        .await?;
    let nearing: i64 = row.get(0);
    let expired: i64 = row.get(1);
    Ok(ReceiptHorizonCounts {
        nearing: nearing.max(0) as u64,
        expired: expired.max(0) as u64,
    })
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
        status: ItemStatus::from_str(row.get(3)).expect("the status check admits four values"),
        code: row.get(4),
        run_id: row.get(5),
        prior_run_id: row.get(6),
        admitted_before: row.get(7),
        first_seen: row.get(8),
        last_seen: row.get(9),
    }))
}

/// PostgreSQL `timestamptz` keeps microseconds, so a staged time is cut to
/// that precision before it is written or handed off. A re-delivery read
/// back from the row then carries the same event time the first hand-off
/// did, on hosts whose clock has finer resolution.
fn storage_time(time: SystemTime) -> SystemTime {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => time - Duration::from_nanos(u64::from(since.subsec_nanos() % 1_000)),
        Err(_) => time,
    }
}

#[cfg(test)]
mod identity_tests {
    use super::{identity_verdict, IdentityVerdict};

    const OLD: [u8; 32] = [1; 32];
    const NEW: [u8; 32] = [2; 32];

    #[test]
    fn the_fence_binds_equal_or_absent_identity_and_refuses_change() {
        let stored = OLD.as_slice();
        assert_eq!(
            identity_verdict(Some(stored), Some(&OLD), false),
            IdentityVerdict::Bound
        );
        assert_eq!(
            identity_verdict(Some(stored), Some(&NEW), false),
            IdentityVerdict::Refused,
            "a changed identity needs the explicit rebind"
        );
        assert_eq!(
            identity_verdict(Some(stored), None, false),
            IdentityVerdict::Refused
        );
        assert_eq!(identity_verdict(None, None, true), IdentityVerdict::Bound);
        assert_eq!(
            identity_verdict(None, Some(&NEW), false),
            IdentityVerdict::Adopt,
            "an empty legacy state adopts the identity"
        );
        assert_eq!(
            identity_verdict(None, Some(&NEW), true),
            IdentityVerdict::Refused,
            "a legacy state with items needs the explicit rebind"
        );
    }
}

#[cfg(test)]
mod storage_time_tests {
    use super::storage_time;
    use std::time::{Duration, SystemTime};

    #[test]
    fn a_staged_time_keeps_only_the_microseconds_postgresql_stores() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_696_979);
        assert_eq!(
            storage_time(base + Duration::from_nanos(56_268_933)),
            base + Duration::from_micros(56_268)
        );
        let exact = base + Duration::from_micros(56_268);
        assert_eq!(storage_time(exact), exact);
    }
}
