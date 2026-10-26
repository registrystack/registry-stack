//! The deployments the storage contract runs against.
//!
//! A [`Deployment`] is one body of state and the means to open more handles on
//! it. For the memory backend that state lives in one [`OfferStore`], and a
//! second handle is the same store with its keys replaced. For PostgreSQL it is
//! one isolated schema on the disposable server, and a second handle is a new
//! store with its own pool over that schema: what a second replica or a
//! restarted process would hold.
//!
//! Every key here is a fixed test value used nowhere else.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use registry_evidence_oid4vci::config::StoreConfig;
use registry_evidence_oid4vci::storage::{CatalogGeneration, KeyRing, Store, VersionedKey};
use registry_evidence_oid4vci::store::{OfferStore, PreparedRequest};

pub const NOW: i64 = 1_700_000_000;
pub const LIFETIME: i64 = 300;

pub const TAG_ONE: (u32, [u8; 32]) = (1, [0x11; 32]);
pub const TAG_TWO: (u32, [u8; 32]) = (2, [0x22; 32]);
pub const TAG_THREE: (u32, [u8; 32]) = (3, [0x33; 32]);
pub const SEAL_ONE: (u32, [u8; 32]) = (1, [0x44; 32]);
pub const SEAL_TWO: (u32, [u8; 32]) = (2, [0x55; 32]);
pub const SEAL_THREE: (u32, [u8; 32]) = (3, [0x66; 32]);

/// Which backend a contract case runs against.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Memory,
    #[cfg(feature = "postgres-test")]
    Postgres,
}

/// A current key and, during a rotation, the one it replaced.
#[derive(Clone, Copy)]
pub struct Ring {
    pub current: (u32, [u8; 32]),
    pub previous: Option<(u32, [u8; 32])>,
}

impl Ring {
    #[must_use]
    pub const fn of(current: (u32, [u8; 32])) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    #[must_use]
    pub const fn rotated(current: (u32, [u8; 32]), previous: (u32, [u8; 32])) -> Self {
        Self {
            current,
            previous: Some(previous),
        }
    }

    #[must_use]
    pub fn build(&self) -> KeyRing {
        let current =
            VersionedKey::new(self.current.0, &self.current.1).expect("a 32-byte test key");
        let previous = self.previous.map(|(version, bytes)| {
            VersionedKey::new(version, &bytes).expect("a 32-byte test key")
        });
        KeyRing::new(current, previous).expect("distinct test key versions")
    }
}

/// The tagging keys every backend uses and the sealing keys only PostgreSQL
/// needs, because only PostgreSQL holds a prepared request outside memory.
#[derive(Clone, Copy)]
pub struct Keys {
    pub tags: Ring,
    pub sealing: Ring,
}

impl Keys {
    #[must_use]
    pub const fn tagged(tags: Ring) -> Self {
        Self {
            tags,
            sealing: Ring::of(SEAL_ONE),
        }
    }
}

impl Default for Keys {
    fn default() -> Self {
        Self::tagged(Ring::of(TAG_ONE))
    }
}

#[must_use]
pub fn bounds() -> StoreConfig {
    StoreConfig {
        maximum_offers: 16,
        offer_lifetime_seconds: LIFETIME as u64,
        access_token_lifetime_seconds: LIFETIME as u64,
        nonce_lifetime_seconds: 120,
        maximum_transaction_code_attempts: 3,
    }
}

fn copy(bounds: &StoreConfig) -> StoreConfig {
    StoreConfig {
        maximum_offers: bounds.maximum_offers,
        offer_lifetime_seconds: bounds.offer_lifetime_seconds,
        access_token_lifetime_seconds: bounds.access_token_lifetime_seconds,
        nonce_lifetime_seconds: bounds.nonce_lifetime_seconds,
        maximum_transaction_code_attempts: bounds.maximum_transaction_code_attempts,
    }
}

#[must_use]
pub fn generation(value: &str) -> CatalogGeneration {
    CatalogGeneration::new(value).expect("a valid test catalog generation")
}

pub const BODY: &str = r#"{"selector":{"nationalId":"held-by-the-adopter"}}"#;

#[must_use]
pub fn prepared() -> PreparedRequest {
    PreparedRequest::new("exchange-1", "urn:example:kind", BODY, 4)
}

pub fn assert_prepared(prepared: &PreparedRequest) {
    assert_eq!(prepared.exchange_id(), "exchange-1");
    assert_eq!(prepared.kind(), "urn:example:kind");
    assert_eq!(prepared.body(), BODY);
    assert_eq!(prepared.maximum_holder_keys(), 4);
}

/// What the store logs while a test runs, rendered as an operator would read
/// it.
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    /// Capture every event logged on this thread until the guard drops. A
    /// test that awaits the store on a current-thread runtime sees all of the
    /// store's events.
    #[must_use]
    pub fn capture() -> (Self, tracing::subscriber::DefaultGuard) {
        let logs = Self::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    #[must_use]
    pub fn rendered(&self) -> String {
        String::from_utf8(self.0.lock().expect("the log buffer lock").clone())
            .expect("logs are UTF-8")
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the log buffer lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Logs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

/// One body of store state and the means to open more handles on it.
pub struct Deployment {
    bounds: StoreConfig,
    memory: Option<Arc<OfferStore>>,
    #[cfg(feature = "postgres-test")]
    schema: Option<String>,
}

impl Deployment {
    /// Fresh, empty state and a first handle on it.
    pub async fn open(kind: Kind, bounds: StoreConfig, keys: Keys) -> (Self, Arc<dyn Store>) {
        match kind {
            Kind::Memory => {
                let store = Arc::new(OfferStore::with_keys(&bounds, keys.tags.build()));
                let deployment = Self {
                    bounds,
                    memory: Some(Arc::clone(&store)),
                    #[cfg(feature = "postgres-test")]
                    schema: None,
                };
                (deployment, store)
            }
            #[cfg(feature = "postgres-test")]
            Kind::Postgres => {
                let schema = postgres::isolated_schema_name();
                let store = postgres::open(&schema, &bounds, keys).await;
                let deployment = Self {
                    bounds,
                    memory: None,
                    schema: Some(schema),
                };
                (deployment, store)
            }
        }
    }

    /// Another handle on the same state, holding `keys`.
    pub async fn reopen(&self, keys: Keys) -> Arc<dyn Store> {
        if let Some(store) = &self.memory {
            store
                .replace_keys(keys.tags.build())
                .expect("the memory store is not poisoned");
            return Arc::clone(store) as Arc<dyn Store>;
        }
        #[cfg(feature = "postgres-test")]
        if let Some(schema) = &self.schema {
            return postgres::open(schema, &copy(&self.bounds), keys).await;
        }
        unreachable!("a deployment holds one backend's state")
    }

    #[must_use]
    pub fn bounds(&self) -> StoreConfig {
        copy(&self.bounds)
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    pub fn schema(&self) -> &str {
        self.schema.as_deref().expect("a PostgreSQL deployment")
    }
}

#[cfg(feature = "postgres-test")]
pub mod postgres {
    //! The disposable PostgreSQL server the PostgreSQL half runs against.
    //!
    //! The server is named by `EVIDENCE_OID4VCI_TEST_DATABASE_URL`. Each
    //! deployment gets its own schema, so cases run in parallel without
    //! sharing a row.

    use std::sync::Arc;
    use std::time::Duration;

    use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
    use registry_evidence_oid4vci::config::StoreConfig;
    use registry_evidence_oid4vci::storage::postgres::PostgresStore;
    use registry_evidence_oid4vci::storage::Store;
    use tokio_postgres::NoTls;
    use uuid::Uuid;

    use super::Keys;

    const URL_VARIABLE: &str = "EVIDENCE_OID4VCI_TEST_DATABASE_URL";

    /// The request timeout a store is built for unless a case needs another:
    /// the service's default.
    pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

    /// The first half of every advisory lock the store takes, as the store
    /// defines it.
    pub const LOCK_NAMESPACE: i32 = 0x4f49_4434;

    fn config() -> tokio_postgres::Config {
        let url = std::env::var(URL_VARIABLE)
            .unwrap_or_else(|_| panic!("{URL_VARIABLE} names a disposable PostgreSQL test server"));
        url.parse()
            .unwrap_or_else(|_| panic!("{URL_VARIABLE} is not a PostgreSQL connection URL"))
    }

    #[must_use]
    pub fn isolated_schema_name() -> String {
        format!("evidence_oid4vci_{}", Uuid::new_v4().simple())
    }

    /// A pool of its own, as a separate replica would hold.
    #[must_use]
    pub fn pool() -> Pool {
        pool_over(config())
    }

    /// A pool of its own whose sessions start with the server settings in
    /// `options`, as a role or database default would set them.
    #[must_use]
    pub fn pool_with_options(options: &str) -> Pool {
        let mut config = config();
        config.options(options);
        pool_over(config)
    }

    fn pool_over(config: tokio_postgres::Config) -> Pool {
        let manager = Manager::from_config(
            config,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );
        Pool::builder(manager)
            .max_size(8)
            .runtime(Runtime::Tokio1)
            .build()
            .expect("a test connection pool")
    }

    /// A migrated store over `schema`, with a pool of its own.
    pub async fn open(schema: &str, bounds: &StoreConfig, keys: Keys) -> Arc<dyn Store> {
        open_over(pool(), schema, bounds, keys).await
    }

    /// A migrated store over `schema`, reached through `pool`.
    pub async fn open_over(
        pool: Pool,
        schema: &str,
        bounds: &StoreConfig,
        keys: Keys,
    ) -> Arc<dyn Store> {
        let store = unmigrated(pool, schema, bounds, keys, REQUEST_TIMEOUT);
        store.migrate().await.expect("the store schema migrates");
        Arc::new(store)
    }

    /// A store over `schema` built for a service whose requests time out
    /// after `request_timeout`. Nothing is migrated.
    #[must_use]
    pub fn unmigrated(
        pool: Pool,
        schema: &str,
        bounds: &StoreConfig,
        keys: Keys,
        request_timeout: Duration,
    ) -> PostgresStore {
        PostgresStore::new(
            pool,
            schema,
            bounds,
            request_timeout,
            keys.tags.build(),
            keys.sealing.build(),
        )
        .expect("a valid store schema name")
    }

    /// A direct session for reading what the store left at rest.
    pub async fn admin() -> tokio_postgres::Client {
        let (client, connection) = config()
            .connect(NoTls)
            .await
            .expect("connect the test database");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the admin connection failed: {error}");
            }
        });
        client
    }

    /// Every row of every table in `schema`, each rendered as PostgreSQL's
    /// own text form of the row, with the table it came from.
    pub async fn dump(schema: &str) -> Vec<(String, String)> {
        let admin = admin().await;
        let tables = admin
            .query(
                "SELECT table_name::text FROM information_schema.tables \
                 WHERE table_schema = $1 ORDER BY table_name",
                &[&schema],
            )
            .await
            .expect("list the store tables");
        assert!(!tables.is_empty(), "the store schema holds tables");
        let mut rows = Vec::new();
        for table in tables {
            let table: String = table.get(0);
            for row in admin
                .query(&format!("SELECT t::text FROM {schema}.{table} t"), &[])
                .await
                .expect("read a store table")
            {
                rows.push((table.clone(), row.get::<_, String>(0)));
            }
        }
        rows
    }

    /// How many rows `table` in `schema` holds.
    pub async fn count(schema: &str, table: &str) -> i64 {
        admin()
            .await
            .query_one(&format!("SELECT count(*) FROM {schema}.{table}"), &[])
            .await
            .expect("count a store table")
            .get(0)
    }
}
