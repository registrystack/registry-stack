// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL store: connections, the versioned schema, and readiness.
//!
//! The runtime serves over the runtime URL and never changes the schema;
//! `documentsctl apply` applies it over the migration URL inside the
//! activation transaction, and [`PostgresStore::ready`] refuses a database
//! whose applied versions are not exactly the ones this release carries.

use std::str::FromStr;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use registry_platform_config::SecretResolver;
use thiserror::Error;
use tokio_postgres::Config as PgConfig;

use crate::config::{describe_secret_failure, DatabaseConfig};

const DOCUMENTS_MIGRATION: &str = include_str!("../migrations/0100_documents.sql");

/// Every schema version, in the order it is applied. Readiness requires the
/// applied set to be exactly this list. The 1.0 baseline is version
/// [`BASELINE_SCHEMA_VERSION`]; each later migration takes the next number.
pub(crate) const MIGRATIONS: [(i64, &str); 1] = [(100, DOCUMENTS_MIGRATION)];
/// The 1.0 baseline schema version, shared with the other products.
const BASELINE_SCHEMA_VERSION: i64 = 100;
const _: () = assert!(
    versions_start_at_baseline_and_increase(&MIGRATIONS),
    "Document Store migrations must start at BASELINE_SCHEMA_VERSION and strictly increase"
);

const fn versions_start_at_baseline_and_increase(migrations: &[(i64, &str)]) -> bool {
    if migrations.is_empty() || migrations[0].0 != BASELINE_SCHEMA_VERSION {
        return false;
    }
    let mut index = 1;
    while index < migrations.len() {
        if migrations[index].0 <= migrations[index - 1].0 {
            return false;
        }
        index += 1;
    }
    true
}

/// Advisory-lock key for schema migration. Its ASCII bytes spell "document".
pub(crate) const MIGRATION_LOCK_KEY: i64 = 0x646f_6375_6d65_6e74;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the Document Store database configuration is invalid")]
    Configuration,
    #[error("the Document Store database secret could not be resolved: {0}")]
    SecretConfiguration(String),
    #[error("the Document Store database schema is not the version this runtime expects; apply the schema with the migration connection")]
    SchemaVersion,
    #[error("the Document Store database server is older than PostgreSQL 17, which the activation ledger requires")]
    UnsupportedPostgres,
    // Both carry the driver's own account of what went wrong. Neither the
    // pool nor the driver repeats the connection string in its message, so
    // naming the cause costs no credential.
    #[error("the Document Store query failed: {0}")]
    Query(#[from] tokio_postgres::Error),
    #[error("the Document Store database connection could not be established: {0}")]
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

    /// The role this store's sessions run as.
    pub async fn current_user(&self) -> Result<String, StoreError> {
        let client = self.client().await?;
        Ok(client
            .query_one("SELECT current_user::text", &[])
            .await?
            .try_get(0)?)
    }

    /// Whether the store answers and carries exactly the schema versions
    /// this runtime expects. A database with no schema ledger is refused as
    /// a schema version mismatch, not as a query failure.
    pub async fn ready(&self) -> Result<(), StoreError> {
        let client = self.client().await?;
        let ledger: bool = client
            .query_one(
                "SELECT to_regclass('documents_schema_migrations') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        if !ledger {
            return Err(StoreError::SchemaVersion);
        }
        let applied = client
            .query(
                "SELECT version FROM documents_schema_migrations ORDER BY version",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| row.try_get::<_, i64>(0))
            .collect::<Result<Vec<_>, _>>()?;
        let expected = MIGRATIONS.iter().map(|(version, _)| *version);
        if applied.iter().copied().eq(expected) {
            Ok(())
        } else {
            Err(StoreError::SchemaVersion)
        }
    }

    /// Whether the database answers a query over the runtime connection.
    pub async fn ping(&self) -> Result<(), StoreError> {
        let client = self.pool.get().await?;
        client.query_one("SELECT 1", &[]).await?;
        Ok(())
    }
}

/// Apply every schema version not yet applied inside `transaction`, which
/// holds the migration lock, and return the versions it applied.
pub(crate) async fn migrate_in(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<Vec<i64>, StoreError> {
    transaction
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS documents_schema_migrations (\
             version bigint PRIMARY KEY CHECK (version > 0),\
             applied_at timestamptz NOT NULL);",
        )
        .await?;
    let applied = transaction
        .query(
            "SELECT version FROM documents_schema_migrations ORDER BY version",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| row.try_get::<_, i64>(0))
        .collect::<Result<Vec<_>, _>>()?;
    if applied
        .iter()
        .enumerate()
        .any(|(index, version)| MIGRATIONS.get(index).map(|(known, _)| known) != Some(version))
    {
        return Err(StoreError::SchemaVersion);
    }
    let mut added = Vec::new();
    for (version, migration) in MIGRATIONS {
        if applied.contains(&version) {
            continue;
        }
        transaction.batch_execute(migration).await?;
        transaction
            .execute(
                "INSERT INTO documents_schema_migrations(version,applied_at) VALUES($1,now())",
                &[&version],
            )
            .await?;
        added.push(version);
    }
    Ok(added)
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
        let table = JobTable::new(
            "public",
            crate::verification::JOB_TABLE,
            "version_id",
            "part",
        )
        .unwrap();
        let declared = normalized(&table.create_statements().join("\n").replace("public.", ""));
        let start = DOCUMENTS_MIGRATION
            .find("CREATE TABLE IF NOT EXISTS documents_verification_jobs")
            .expect("the job table");
        let end = DOCUMENTS_MIGRATION
            .find("ALTER TABLE documents_verification_jobs")
            .expect("the job table's own constraints");
        assert_eq!(normalized(&DOCUMENTS_MIGRATION[start..end]), declared);
    }

    #[test]
    fn the_baseline_is_version_100_and_later_versions_increase() {
        assert_eq!(MIGRATIONS[0].0, 100);
        assert!(versions_start_at_baseline_and_increase(&MIGRATIONS));
        assert!(versions_start_at_baseline_and_increase(&[
            (100, ""),
            (101, "")
        ]));
        assert!(!versions_start_at_baseline_and_increase(&[(1, "")]));
        assert!(!versions_start_at_baseline_and_increase(&[
            (100, ""),
            (100, "")
        ]));
    }
}
