// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL store: connections and reachability.
//!
//! The runtime reaches PostgreSQL through the runtime URL and never changes
//! the schema. The store holds no tables yet; the versioned schema arrives
//! with the first document records.

use std::str::FromStr;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use registry_platform_config::SecretResolver;
use thiserror::Error;
use tokio_postgres::Config as PgConfig;

use crate::config::{describe_secret_failure, DatabaseConfig};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("the Document Store database configuration is invalid")]
    Configuration,
    #[error("the Document Store database secret could not be resolved: {0}")]
    SecretConfiguration(String),
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
        let reference = &config.runtime_url_ref;
        let protected = secrets.resolve(reference).map_err(|error| {
            StoreError::SecretConfiguration(describe_secret_failure(
                "database.runtimeUrlRef",
                reference,
                &error,
            ))
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

    /// Whether the database answers a query over the runtime connection.
    pub async fn ping(&self) -> Result<(), StoreError> {
        let client = self.pool.get().await?;
        client.query_one("SELECT 1", &[]).await?;
        Ok(())
    }
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
