// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL store: connections, the versioned schema, and readiness.
//!
//! The runtime reaches PostgreSQL through two credentials. The migration URL
//! applies the schema, once, from the `migrate` command; the runtime URL
//! serves requests and never changes the schema. Migrations are serialized on
//! one session advisory lock, so two migrators started together apply each
//! version once and both succeed.
//!
//! The package ledger records each package a deployment activated. The
//! operator records a package with the migration credential, through
//! `messagingctl apply`; the runtime reads the latest entry at startup and
//! serves only the package it names.

use std::str::FromStr;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use registry_platform_config::SecretResolver;
use thiserror::Error;
use tokio_postgres::Config as PgConfig;

use crate::config::{describe_secret_failure, DatabaseConfig};

const MESSAGING_MIGRATION: &str = include_str!("../migrations/0001_messaging.sql");
pub(crate) const MESSAGES_MIGRATION: &str = include_str!("../migrations/0002_messages.sql");
const RECEIPTS_MIGRATION: &str = include_str!("../migrations/0003_receipts.sql");

/// Every schema version, in the order it is applied. Readiness requires the
/// applied set to be exactly this list.
const MIGRATIONS: [(i64, &str); 3] = [
    (1, MESSAGING_MIGRATION),
    (2, MESSAGES_MIGRATION),
    (3, RECEIPTS_MIGRATION),
];

/// Serializes operator-run migrations on one session lock. A second migrator
/// waits here instead of racing the migrations table's primary key. The key
/// spells the ASCII bytes of "messagin".
const MIGRATION_LOCK_KEY: i64 = 0x6d65_7373_6167_696e;

/// Serializes package activations on one transaction lock, so two operators
/// applying the same package record it once. The key spells "msgledgr".
const LEDGER_LOCK_KEY: i64 = 0x6d73_676c_6564_6772;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the Messaging database configuration is invalid")]
    Configuration,
    #[error("the Messaging database secret could not be resolved: {0}")]
    SecretConfiguration(String),
    #[error("the Messaging database schema is not the version this runtime expects")]
    SchemaVersion,
    #[error("the Messaging migration lock was not held when it was released")]
    MigrationLock,
    // Both carry the driver's own account of what went wrong. Neither the
    // pool nor the driver repeats the connection string in its message, so
    // naming the cause costs no credential.
    #[error("the Messaging query failed: {0}")]
    Query(#[from] tokio_postgres::Error),
    #[error("the Messaging database connection could not be established: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),
}

#[derive(Clone)]
pub struct PostgresStore {
    pool: Pool,
}

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresStore")
            .finish_non_exhaustive()
    }
}

impl PostgresStore {
    pub fn connect_runtime(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, StoreError> {
        Self::connect_reference(
            config,
            secrets,
            "database.runtimeUrlRef",
            &config.runtime_url_ref,
        )
    }

    pub fn connect_migration(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
    ) -> Result<Self, StoreError> {
        Self::connect_reference(
            config,
            secrets,
            "database.migrationUrlRef",
            &config.migration_url_ref,
        )
    }

    fn connect_reference(
        config: &DatabaseConfig,
        secrets: &SecretResolver,
        field: &'static str,
        reference: &str,
    ) -> Result<Self, StoreError> {
        let protected = secrets.resolve(reference).map_err(|error| {
            StoreError::SecretConfiguration(describe_secret_failure(field, reference, &error))
        })?;
        let url = std::str::from_utf8(protected.expose_secret())
            .map_err(|_| StoreError::Configuration)?;
        let mut postgres = PgConfig::from_str(url).map_err(|_| StoreError::Configuration)?;
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(StoreError::Configuration);
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
            let connector = tls_connector(config, secrets)?;
            Manager::from_config(postgres, connector, manager_config)
        };
        #[cfg(not(feature = "postgres-test"))]
        let manager = {
            if config.test_only_plaintext {
                return Err(StoreError::Configuration);
            }
            postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
            let connector = tls_connector(config, secrets)?;
            Manager::from_config(postgres, connector, manager_config)
        };
        let pool = Pool::builder(manager)
            .max_size(32)
            .wait_timeout(Some(Duration::from_secs(5)))
            .create_timeout(Some(Duration::from_secs(5)))
            .recycle_timeout(Some(Duration::from_secs(5)))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| StoreError::Configuration)?;
        Ok(Self { pool })
    }

    pub(crate) async fn client(&self) -> Result<deadpool_postgres::Client, StoreError> {
        self.pool.get().await.map_err(StoreError::Pool)
    }

    /// The schema this store's sessions resolve unqualified names in: the
    /// first schema of the connection's `search_path` that exists.
    pub async fn current_schema(&self) -> Result<String, StoreError> {
        let client = self.client().await?;
        let row = client.query_one("SELECT current_schema()", &[]).await?;
        row.try_get::<_, Option<String>>(0)?
            .ok_or(StoreError::Configuration)
    }

    /// Apply every schema version not yet applied, under the migration lock.
    /// Running it again, or twice at once, applies nothing twice.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut client = self.client().await?;
        client
            .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
            .await?;
        let applied = apply_migrations(&mut client).await;
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

    /// Whether the store answers and carries exactly the schema versions
    /// this runtime expects.
    pub async fn ready(&self) -> Result<(), StoreError> {
        let client = self.client().await?;
        let applied = client
            .query(
                "SELECT version FROM messaging_schema_migrations ORDER BY version",
                &[],
            )
            .await?;
        let current = applied.len() == MIGRATIONS.len()
            && applied
                .iter()
                .zip(MIGRATIONS.iter())
                .all(|(row, (expected, _))| {
                    row.try_get::<_, i64>(0)
                        .is_ok_and(|version| version == *expected)
                });
        if current {
            Ok(())
        } else {
            Err(StoreError::SchemaVersion)
        }
    }

    /// The digest of the package the ledger names active: its latest entry,
    /// or none when no package was ever applied.
    pub async fn active_package_digest(&self) -> Result<Option<String>, StoreError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT package_digest FROM messaging_package_ledger \
                 ORDER BY sequence DESC LIMIT 1",
                &[],
            )
            .await?;
        Ok(row.map(|row| row.get(0)))
    }

    /// Record `digest` as the active package. Applying the package the
    /// ledger already names active records nothing and answers `false`.
    pub async fn apply_package(
        &self,
        digest: &str,
        runtime_version: &str,
    ) -> Result<bool, StoreError> {
        let mut client = self.client().await?;
        let transaction = client.transaction().await?;
        transaction
            .execute("SELECT pg_advisory_xact_lock($1)", &[&LEDGER_LOCK_KEY])
            .await?;
        let active: Option<String> = transaction
            .query_opt(
                "SELECT package_digest FROM messaging_package_ledger \
                 ORDER BY sequence DESC LIMIT 1",
                &[],
            )
            .await?
            .map(|row| row.get(0));
        if active.as_deref() == Some(digest) {
            transaction.commit().await?;
            return Ok(false);
        }
        transaction
            .execute(
                "INSERT INTO messaging_package_ledger(package_digest, runtime_version, activated_at) \
                 VALUES ($1, $2, now())",
                &[&digest, &runtime_version],
            )
            .await?;
        transaction.commit().await?;
        Ok(true)
    }
}

async fn apply_migrations(client: &mut deadpool_postgres::Client) -> Result<(), StoreError> {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS messaging_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL);",
        )
        .await?;
    for (version, migration) in MIGRATIONS {
        let transaction = client.transaction().await?;
        let applied: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM messaging_schema_migrations WHERE version=$1)",
                &[&version],
            )
            .await?
            .get(0);
        if !applied {
            transaction.batch_execute(migration).await?;
            transaction
                .execute(
                    "INSERT INTO messaging_schema_migrations(version,applied_at) \
                     VALUES($1,now()) ON CONFLICT(version) DO NOTHING",
                    &[&version],
                )
                .await?;
        }
        transaction.commit().await?;
    }
    Ok(())
}

fn tls_connector(
    config: &DatabaseConfig,
    secrets: &SecretResolver,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, StoreError> {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        return Err(StoreError::Configuration);
    }
    if let Some(reference) = &config.trusted_root_certificate_ref {
        let certificate = secrets.resolve(reference).map_err(|error| {
            StoreError::SecretConfiguration(describe_secret_failure(
                "database.trustedRootCertificateRef",
                reference,
                &error,
            ))
        })?;
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::pem::PemObject as _;
        let mut count = 0usize;
        for certificate in
            rustls::pki_types::CertificateDer::pem_slice_iter(certificate.expose_secret())
        {
            roots
                .add(certificate.map_err(|_| StoreError::Configuration)?)
                .map_err(|_| StoreError::Configuration)?;
            count += 1;
        }
        if count == 0 {
            return Err(StoreError::Configuration);
        }
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client))
    } else {
        tokio_postgres_rustls::MakeRustlsConnect::with_native_certs()
            .map(|value| value.0)
            .map_err(|_| StoreError::Configuration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_dispatch::postgres::JobTable;

    fn normalized(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_job_table_migration_is_exactly_the_dispatch_core_shape() {
        let table =
            JobTable::new("public", crate::dispatch::JOB_TABLE, "message_id", "part").unwrap();
        let declared = normalized(&table.create_statements().join("\n").replace("public.", ""));
        let start = MESSAGES_MIGRATION
            .find("CREATE TABLE IF NOT EXISTS messaging_dispatch_jobs")
            .expect("the job table");
        let end = MESSAGES_MIGRATION
            .find("ALTER TABLE messaging_dispatch_jobs")
            .expect("the job table's own constraints");
        assert_eq!(normalized(&MESSAGES_MIGRATION[start..end]), declared);
    }
}
