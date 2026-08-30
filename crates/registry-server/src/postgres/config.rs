// SPDX-License-Identifier: Apache-2.0

use std::{fmt, str::FromStr, time::Duration};

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
#[cfg(feature = "postgres-test")]
use tokio_postgres::NoTls;
use tokio_postgres::{config::SslMode, Config};
use tokio_postgres_rustls::MakeRustlsConnect;

use super::{PostgresKernelError, Result};

const MAX_POOL_SIZE: usize = 128;
const MAX_POOL_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CUSTOM_CA_DER_BYTES: usize = 1024 * 1024;

/// Explicit PostgreSQL TLS policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsPolicy {
    /// Require TLS and validate the server certificate with native roots.
    RequireNativeRoots,
    /// Require TLS and validate the server certificate with one explicit CA.
    RequireCustomCa,
    /// Permit plaintext only in an isolated test environment.
    #[cfg(feature = "postgres-test")]
    TestOnlyPlaintext,
}

/// Bounded runtime pool settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolBounds {
    pub max_size: usize,
    pub wait_timeout: Duration,
    pub create_timeout: Duration,
    pub recycle_timeout: Duration,
}

impl PoolBounds {
    pub fn new(
        max_size: usize,
        wait_timeout: Duration,
        create_timeout: Duration,
        recycle_timeout: Duration,
    ) -> Result<Self> {
        if max_size == 0 || max_size > MAX_POOL_SIZE {
            return Err(PostgresKernelError::Configuration(
                "pool size must be between 1 and 128",
            ));
        }
        if [wait_timeout, create_timeout, recycle_timeout]
            .into_iter()
            .any(|timeout| timeout.is_zero() || timeout > MAX_POOL_TIMEOUT)
        {
            return Err(PostgresKernelError::Configuration(
                "pool timeouts must be between 1 millisecond and 60 seconds",
            ));
        }
        Ok(Self {
            max_size,
            wait_timeout,
            create_timeout,
            recycle_timeout,
        })
    }
}

/// Parsed connection configuration that never formats its secret material.
#[derive(Clone)]
pub struct ConnectionConfig {
    postgres: Config,
    transport: Transport,
    pool_bounds: PoolBounds,
}

#[derive(Clone)]
enum Transport {
    Tls {
        policy: TlsPolicy,
        connector: MakeRustlsConnect,
    },
    #[cfg(feature = "postgres-test")]
    TestOnlyPlaintext,
}

pub(crate) enum ConnectionTls {
    Rustls(MakeRustlsConnect),
    #[cfg(feature = "postgres-test")]
    TestOnlyPlaintext,
}

impl fmt::Debug for ConnectionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionConfig")
            .field("tls_policy", &self.tls_policy())
            .field("pool_bounds", &self.pool_bounds)
            .finish_non_exhaustive()
    }
}

impl ConnectionConfig {
    pub fn require_tls(url: &str, pool_bounds: PoolBounds) -> Result<Self> {
        Self::require_tls_config(parse_connection(url)?, pool_bounds)
    }

    pub fn require_tls_config(mut postgres: Config, pool_bounds: PoolBounds) -> Result<Self> {
        postgres.ssl_mode(SslMode::Require);
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(PostgresKernelError::Configuration(
                "database configuration requires an explicit user and database",
            ));
        }
        let connector = native_roots_connector()?;
        Ok(Self {
            postgres,
            transport: Transport::Tls {
                policy: TlsPolicy::RequireNativeRoots,
                connector,
            },
            pool_bounds,
        })
    }

    /// Requires TLS using one explicit DER-encoded CA certificate.
    ///
    /// Hostname and certificate validation remain enabled. The CA bytes are
    /// bounded, parsed immediately, and never included in `Debug` output.
    pub fn require_tls_with_custom_ca(
        url: &str,
        ca_der: &[u8],
        pool_bounds: PoolBounds,
    ) -> Result<Self> {
        let mut postgres = parse_connection(url)?;
        postgres.ssl_mode(SslMode::Require);
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(PostgresKernelError::Configuration(
                "database configuration requires an explicit user and database",
            ));
        }
        let connector = custom_ca_connector(ca_der)?;
        Ok(Self {
            postgres,
            transport: Transport::Tls {
                policy: TlsPolicy::RequireCustomCa,
                connector,
            },
            pool_bounds,
        })
    }

    /// Constructs a plaintext connection for an isolated real-PostgreSQL test.
    ///
    /// Production configuration loaders must not expose this constructor.
    #[cfg(feature = "postgres-test")]
    pub fn test_only_plaintext(url: &str, pool_bounds: PoolBounds) -> Result<Self> {
        let mut postgres = parse_connection(url)?;
        postgres.ssl_mode(SslMode::Disable);
        Self::from_test_config(postgres, pool_bounds)
    }

    /// Constructs a plaintext connection from an already parsed configuration
    /// for isolated real-PostgreSQL tests.
    #[cfg(feature = "postgres-test")]
    pub fn from_test_config(mut postgres: Config, pool_bounds: PoolBounds) -> Result<Self> {
        postgres.ssl_mode(SslMode::Disable);
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(PostgresKernelError::Configuration(
                "test database configuration requires an explicit user and database",
            ));
        }
        Ok(Self {
            postgres,
            transport: Transport::TestOnlyPlaintext,
            pool_bounds,
        })
    }

    pub(crate) fn postgres(&self) -> Config {
        self.postgres.clone()
    }

    pub(crate) fn tls_policy(&self) -> TlsPolicy {
        match &self.transport {
            Transport::Tls { policy, .. } => *policy,
            #[cfg(feature = "postgres-test")]
            Transport::TestOnlyPlaintext => TlsPolicy::TestOnlyPlaintext,
        }
    }

    pub(crate) fn tls_connector(&self) -> ConnectionTls {
        match &self.transport {
            Transport::Tls { connector, .. } => ConnectionTls::Rustls(connector.clone()),
            #[cfg(feature = "postgres-test")]
            Transport::TestOnlyPlaintext => ConnectionTls::TestOnlyPlaintext,
        }
    }

    pub fn build_pool(&self) -> Result<RuntimePool> {
        let manager_config = ManagerConfig {
            recycling_method: RecyclingMethod::Verified,
        };
        let manager = match self.tls_connector() {
            ConnectionTls::Rustls(connector) => {
                Manager::from_config(self.postgres.clone(), connector, manager_config)
            }
            #[cfg(feature = "postgres-test")]
            ConnectionTls::TestOnlyPlaintext => {
                Manager::from_config(self.postgres.clone(), NoTls, manager_config)
            }
        };
        let pool = Pool::builder(manager)
            .max_size(self.pool_bounds.max_size)
            .wait_timeout(Some(self.pool_bounds.wait_timeout))
            .create_timeout(Some(self.pool_bounds.create_timeout))
            .recycle_timeout(Some(self.pool_bounds.recycle_timeout))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| PostgresKernelError::PoolBuild)?;
        Ok(RuntimePool { pool })
    }
}

fn parse_connection(url: &str) -> Result<Config> {
    if url.trim().is_empty() {
        return Err(PostgresKernelError::Configuration(
            "database URL must not be empty",
        ));
    }
    Config::from_str(url).map_err(|_| PostgresKernelError::Configuration("database URL is invalid"))
}

pub(crate) fn ensure_crypto_provider() -> Result<()> {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        return Err(PostgresKernelError::Configuration(
            "Rustls crypto provider could not be installed",
        ));
    }
    Ok(())
}

fn native_roots_connector() -> Result<MakeRustlsConnect> {
    ensure_crypto_provider()?;
    MakeRustlsConnect::with_native_certs()
        .map(|(connector, _certificate_errors)| connector)
        .map_err(|_| {
            PostgresKernelError::Configuration("native TLS certificate roots are unavailable")
        })
}

fn custom_ca_connector(ca_der: &[u8]) -> Result<MakeRustlsConnect> {
    if ca_der.is_empty() || ca_der.len() > MAX_CUSTOM_CA_DER_BYTES {
        return Err(PostgresKernelError::Configuration(
            "custom CA DER must be between 1 byte and 1 MiB",
        ));
    }
    ensure_crypto_provider()?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
        .map_err(|_| PostgresKernelError::Configuration("custom CA DER is invalid"))?;
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(client))
}

/// Runtime pool configured with verified recycling and finite acquisition bounds.
#[derive(Clone)]
pub struct RuntimePool {
    pool: Pool,
}

impl RuntimePool {
    pub(crate) async fn get(&self) -> Result<deadpool_postgres::Client> {
        self.pool.get().await.map_err(|_| PostgresKernelError::Pool)
    }

    pub fn status(&self) -> deadpool_postgres::Status {
        self.pool.status()
    }

    pub async fn startup_probe(&self) -> Result<()> {
        let client = self.get().await?;
        client.simple_query("SELECT 1").await?;
        Ok(())
    }

    #[cfg(any(feature = "postgres-test", feature = "postgres-tls-test"))]
    #[doc(hidden)]
    pub async fn get_for_test(&self) -> Result<deadpool_postgres::Client> {
        self.get().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_bounds() -> PoolBounds {
        PoolBounds::new(
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("bounds are valid")
    }

    #[test]
    fn pool_bounds_refuse_unbounded_or_zero_values() {
        assert!(PoolBounds::new(
            0,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(PoolBounds::new(
            129,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(PoolBounds::new(
            1,
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(PoolBounds::new(
            1,
            Duration::from_secs(1),
            Duration::from_secs(61),
            Duration::from_secs(1)
        )
        .is_err());
    }

    #[cfg(feature = "postgres-test")]
    #[test]
    fn connection_debug_never_contains_database_secrets() {
        let config = ConnectionConfig::test_only_plaintext(
            "postgresql://secret_user:secret_password@127.0.0.1/secret_database",
            valid_bounds(),
        )
        .expect("test connection configuration parses");
        let debug = format!("{config:?}");
        for secret in ["secret_user", "secret_password", "secret_database"] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn custom_ca_refuses_empty_invalid_or_oversized_der() {
        let url = "postgresql://registry_runtime@registry.example/registry";
        assert!(ConnectionConfig::require_tls_with_custom_ca(url, &[], valid_bounds()).is_err());
        assert!(
            ConnectionConfig::require_tls_with_custom_ca(url, &[1, 2, 3], valid_bounds()).is_err()
        );

        let oversized = vec![0; MAX_CUSTOM_CA_DER_BYTES + 1];
        assert!(
            ConnectionConfig::require_tls_with_custom_ca(url, &oversized, valid_bounds()).is_err()
        );
    }
}
