// SPDX-License-Identifier: Apache-2.0
//! The administrator connection: URL rules, verified TLS and bounded sessions.
//!
//! Nothing in this module echoes the URL, the password or a driver message
//! into an error. Errors name the rule that failed or the SQLSTATE.

use std::{future::Future, str::FromStr, time::Duration};

use rustls::pki_types::{pem::PemObject as _, CertificateDer};
use tokio_postgres::{
    config::{Host, SslMode},
    Client, Config,
};
use tokio_postgres_rustls::MakeRustlsConnect;
use url::Url;

pub(crate) const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const STATEMENT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const DEFAULT_PORT: u16 = 5432;

/// A validated administrator endpoint with its TLS settings. `Debug` prints
/// the host, port, user and database only.
#[derive(Clone)]
pub struct AdminConfig {
    config: Config,
    tls: MakeRustlsConnect,
    host: String,
    port: u16,
}

/// Why an administrator URL or CA file was refused. Each message names the
/// rule, never the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdminConfigError {
    #[error("the PostgreSQL admin URL is not a parseable URL")]
    NotParseable,
    #[error("the PostgreSQL admin URL must be an absolute postgres:// or postgresql:// URL")]
    NotAPostgresUrl,
    #[error("the PostgreSQL admin URL must include an explicit host, user, and password")]
    MissingEndpointOrCredentials,
    #[error("the PostgreSQL admin URL must include one explicit database name")]
    MissingDatabase,
    #[error("the PostgreSQL admin URL must not override its endpoint or credentials in the query")]
    QueryOverridesEndpoint,
    #[error(
        "the PostgreSQL admin URL sslmode must be require, verify-ca, or verify-full; \
         provisioning always uses verified TLS"
    )]
    UnsupportedSslMode,
    #[error("the PostgreSQL admin URL must not set sslrootcert; pass the CA PEM file instead")]
    SslRootCertInUrl,
    #[error(
        "the PostgreSQL admin URL has a query parameter that is not supported; \
         only connect_timeout and application_name are"
    )]
    UnsupportedQueryParameter,
    #[error("the PostgreSQL admin URL has an invalid query parameter value")]
    InvalidQueryValue,
    #[error("the PostgreSQL admin URL must name one TCP host, user, password, and database")]
    NotOneTcpEndpoint,
    #[error("the PostgreSQL CA PEM is invalid or holds no certificate")]
    CaInvalid,
    #[error("cannot initialize the PostgreSQL TLS provider")]
    TlsProvider,
    #[error("cannot load native roots for PostgreSQL TLS")]
    NativeRoots,
}

impl AdminConfigError {
    /// The diagnostic code of the report.
    pub fn code(&self) -> &'static str {
        match self {
            Self::CaInvalid | Self::TlsProvider | Self::NativeRoots => {
                "platform.provision.admin-ca-invalid"
            }
            _ => "platform.provision.admin-url-invalid",
        }
    }
}

/// Validates an administrator URL and builds its verified-TLS settings.
///
/// With `ca_pem`, the server certificate must chain to it. Without, the
/// platform's native roots are used. The connection always requires TLS.
pub fn admin_config(url: &str, ca_pem: Option<&[u8]>) -> Result<AdminConfig, AdminConfigError> {
    let parsed = Url::parse(url).map_err(|_| AdminConfigError::NotParseable)?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.cannot_be_a_base()
        || parsed.fragment().is_some()
    {
        return Err(AdminConfigError::NotAPostgresUrl);
    }
    if parsed.username().is_empty()
        || parsed.password().is_none_or(str::is_empty)
        || parsed.host().is_none()
    {
        return Err(AdminConfigError::MissingEndpointOrCredentials);
    }
    let database = parsed.path().strip_prefix('/').unwrap_or_default();
    if database.is_empty() || database.contains('/') {
        return Err(AdminConfigError::MissingDatabase);
    }
    if parsed.query_pairs().any(|(key, _)| {
        matches!(
            key.as_ref(),
            "host" | "hostaddr" | "port" | "user" | "password" | "dbname"
        )
    }) {
        return Err(AdminConfigError::QueryOverridesEndpoint);
    }
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "sslmode" => {
                if !matches!(value.as_ref(), "require" | "verify-ca" | "verify-full") {
                    return Err(AdminConfigError::UnsupportedSslMode);
                }
            }
            "sslrootcert" => return Err(AdminConfigError::SslRootCertInUrl),
            "connect_timeout" | "application_name" => {}
            _ => return Err(AdminConfigError::UnsupportedQueryParameter),
        }
    }

    // tokio-postgres does not parse verify-ca or verify-full, and provisioning
    // sets its own TLS mode, so the checked sslmode is not passed on.
    let mut sanitized = parsed.clone();
    let kept: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(key, _)| key != "sslmode")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if kept.is_empty() {
        sanitized.set_query(None);
    } else {
        sanitized.query_pairs_mut().clear().extend_pairs(kept);
    }
    let mut config =
        Config::from_str(sanitized.as_str()).map_err(|_| AdminConfigError::InvalidQueryValue)?;
    config.keepalives_idle(KEEPALIVE_IDLE);
    config.ssl_mode(SslMode::Require);
    if config.get_hosts().len() != 1
        || !matches!(config.get_hosts().first(), Some(Host::Tcp(_)))
        || !config.get_hostaddrs().is_empty()
        || config.get_user().is_none_or(str::is_empty)
        || config.get_password().is_none_or(<[u8]>::is_empty)
        || config.get_dbname().is_none_or(str::is_empty)
    {
        return Err(AdminConfigError::NotOneTcpEndpoint);
    }
    apply_session_options(&mut config);

    let host = match config.get_hosts().first() {
        Some(Host::Tcp(host)) => host.clone(),
        _ => return Err(AdminConfigError::NotOneTcpEndpoint),
    };
    let port = config.get_ports().first().copied().unwrap_or(DEFAULT_PORT);
    Ok(AdminConfig {
        config,
        tls: tls_connector(ca_pem)?,
        host,
        port,
    })
}

impl AdminConfig {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn user(&self) -> &str {
        self.config.get_user().unwrap_or_default()
    }

    /// The database the administrator URL names.
    pub fn database(&self) -> &str {
        self.config.get_dbname().unwrap_or_default()
    }

    /// Opens a session to `database` as the administrator.
    pub(crate) async fn connect(&self, database: Option<&str>) -> Result<Session, ConnectFailure> {
        let mut config = self.config.clone();
        if let Some(database) = database {
            config.dbname(database);
        }
        Session::open(&config, &self.tls).await
    }

    /// Opens a session to `database` as another role, over the same endpoint.
    pub(crate) async fn connect_as(
        &self,
        database: &str,
        role: &str,
        password: &str,
    ) -> Result<Session, ConnectFailure> {
        let mut config = self.config.clone();
        config.dbname(database).user(role).password(password);
        Session::open(&config, &self.tls).await
    }
}

#[cfg(feature = "test-support")]
impl AdminConfig {
    /// Opens a session to `database` whose connection task runs on the current
    /// runtime for as long as the client lives. The failure is the driver's,
    /// which carries neither the URL nor the password.
    pub(crate) async fn connect_detached(
        &self,
        database: Option<&str>,
    ) -> Result<Client, tokio_postgres::Error> {
        let mut config = self.config.clone();
        if let Some(database) = database {
            config.dbname(database);
        }
        let (client, connection) = config.connect(self.tls.clone()).await?;
        tokio::spawn(connection);
        Ok(client)
    }
}

impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user())
            .field("database", &self.database())
            .finish_non_exhaustive()
    }
}

/// Startup options for every administrator session: the statement deadline and
/// the CREATEROLE self-grant. The comma in the self-grant value is not a
/// separator for the server's startup option parser, which splits on spaces.
fn apply_session_options(config: &mut Config) {
    let added = format!(
        "-c statement_timeout={} -c createrole_self_grant={}",
        STATEMENT_TIMEOUT.as_millis(),
        crate::sql::CREATEROLE_SELF_GRANT
    );
    if let Some(existing) = config.get_options().filter(|value| !value.is_empty()) {
        config.options(format!("{existing} {added}"));
    } else {
        config.options(added);
    }
}

fn tls_connector(ca_pem: Option<&[u8]>) -> Result<MakeRustlsConnect, AdminConfigError> {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        return Err(AdminConfigError::TlsProvider);
    }

    if let Some(pem) = ca_pem {
        let mut roots = rustls::RootCertStore::empty();
        let mut count = 0usize;
        for certificate in CertificateDer::pem_slice_iter(pem) {
            let certificate = certificate.map_err(|_| AdminConfigError::CaInvalid)?;
            roots
                .add(certificate)
                .map_err(|_| AdminConfigError::CaInvalid)?;
            count += 1;
        }
        if count == 0 {
            return Err(AdminConfigError::CaInvalid);
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(MakeRustlsConnect::new(config))
    } else {
        MakeRustlsConnect::with_native_certs()
            .map(|value| value.0)
            .map_err(|_| AdminConfigError::NativeRoots)
    }
}

/// Why a session could not be opened. Carries the SQLSTATE when the server
/// answered, never the driver's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectFailure {
    pub sqlstate: Option<String>,
}

/// One open session. Dropping it ends the connection task.
pub(crate) struct Session {
    pub client: Client,
    task: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
}

impl Session {
    async fn open(config: &Config, tls: &MakeRustlsConnect) -> Result<Self, ConnectFailure> {
        let attempt = tokio::time::timeout(CONNECTION_TIMEOUT, config.connect(tls.clone())).await;
        match attempt {
            Ok(Ok((client, connection))) => Ok(Self {
                client,
                task: tokio::spawn(connection),
            }),
            Ok(Err(error)) => Err(ConnectFailure {
                sqlstate: error.code().map(|code| code.code().to_owned()),
            }),
            Err(_) => Err(ConnectFailure { sqlstate: None }),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// How one database call ended, without the driver's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallFailure {
    /// The server answered with this SQLSTATE.
    Server { sqlstate: String },
    /// The deadline passed or the connection broke: whether the server
    /// applied the call is unknown.
    Unconfirmed,
}

impl CallFailure {
    pub(crate) fn lacks_privilege(&self) -> bool {
        matches!(self, Self::Server { sqlstate } if sqlstate == "42501")
    }
}

pub(crate) async fn bounded_call<T>(
    future: impl Future<Output = Result<T, tokio_postgres::Error>>,
) -> Result<T, CallFailure> {
    match tokio::time::timeout(OPERATION_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(match error.as_db_error() {
            Some(db) => CallFailure::Server {
                sqlstate: db.code().code().to_owned(),
            },
            None => CallFailure::Unconfirmed,
        }),
        Err(_) => Err(CallFailure::Unconfirmed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "postgresql://admin:secret-pw@db.example:5433/postgres";

    /// A throwaway self-signed CA certificate. Only its structure matters here.
    fn test_ca_pem() -> &'static str {
        "-----BEGIN CERTIFICATE-----\n\
         MIIDGzCCAgOgAwIBAgIUXGhkX0Z058UoUVAxJidqxKazAaQwDQYJKoZIhvcNAQEL\n\
         BQAwHTEbMBkGA1UEAwwSbTMtczIgdGhyb3dhd2F5IENBMB4XDTI2MTEyNzAwMzA1\n\
         NVoXDTI2MTEyOTAwMzA1NVowHTEbMBkGA1UEAwwSbTMtczIgdGhyb3dhd2F5IENB\n\
         MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsKgPCAb1XWG8zeCpVIrg\n\
         IkAHtIqq7KlkqgGhTDBLTwFMoyBlnHUT+3qd87+0scqpv0IJA38DthaVVOo3UUkg\n\
         pPUBZySYSljOAfkDvBdJ3ev40Ww8uFl9br/XlWrrskfwC1HAjswdAzRUMSqnV/wH\n\
         In5Sb++75rnZbfUUYBbHcvT2MLlULWX98wDFGQXbEMvWbPsDlzFmYga3K98XUQDr\n\
         clbDEFACakpK2SpKFPS2azvfnRehN28eOauBlRbRHnZcS1gLDeqmnRviJoYsoOvE\n\
         tYIMN+YZCaSNZUpuD7bN1iHGOeTBDatT7ZSwArKDBV0yJHbhi/6nfPka/M3e8b1/\n\
         xQIDAQABo1MwUTAdBgNVHQ4EFgQUeaMUxXla07H5aYfj7dYnVJlTKHYwHwYDVR0j\n\
         BBgwFoAUeaMUxXla07H5aYfj7dYnVJlTKHYwDwYDVR0TAQH/BAUwAwEB/zANBgkq\n\
         hkiG9w0BAQsFAAOCAQEACC7s1MOYnU7322I3dvweCuwJvZ7a1T6KO0GyaMsw1uZZ\n\
         2vvaTrJgQBDi5n4/pNOgx9ZzQxyBQR7QvVEV/z20x/gVOH1uQq9gQnMGAA+rFdHR\n\
         LgoNLe1zY6THUkD4l+KWQgraUKtAf0Ko1ruLrrMbH4tq3w6bJX7KeHrWsKDY04/d\n\
         /HyACVlWnoGeuyPppd6009SuMwQvKMUDz+UU55Jj49FLHWAH9V9AbuLmHkbdKQ1x\n\
         qE5kizB4UytufC/y99522L3p2bD0pAvHSxDIXYtAlC3Fx4XyFbT+5/JY3hYRwbfs\n\
         6NlpU4TdevxbiVlIM5anyYHY+yhBKdIQH1D+0lOfvw==\n\
         -----END CERTIFICATE-----\n"
    }

    fn refused(url: &str) -> AdminConfigError {
        admin_config(url, Some(b"")).expect_err("the URL should be refused")
    }

    #[test]
    fn url_rules_are_named_and_never_echo_the_url() {
        let cases: [(&str, AdminConfigError); 9] = [
            ("not a url", AdminConfigError::NotParseable),
            ("mysql://a:b@h/db", AdminConfigError::NotAPostgresUrl),
            (
                "postgresql://h/db",
                AdminConfigError::MissingEndpointOrCredentials,
            ),
            (
                "postgresql://a:secret-pw@h/",
                AdminConfigError::MissingDatabase,
            ),
            (
                "postgresql://a:secret-pw@h/db?port=1",
                AdminConfigError::QueryOverridesEndpoint,
            ),
            (
                "postgresql://a:secret-pw@h/db?sslmode=disable",
                AdminConfigError::UnsupportedSslMode,
            ),
            (
                "postgresql://a:secret-pw@h/db?sslrootcert=/x",
                AdminConfigError::SslRootCertInUrl,
            ),
            (
                "postgresql://a:secret-pw@h/db?options=x",
                AdminConfigError::UnsupportedQueryParameter,
            ),
            (
                "postgresql://a:secret-pw@h/db?connect_timeout=soon",
                AdminConfigError::InvalidQueryValue,
            ),
        ];
        for (url, expected) in cases {
            let error = refused(url);
            // The CA is checked after the URL, so a URL rule is what fires first.
            assert_eq!(error, expected, "{url}");
            assert_eq!(error.code(), "platform.provision.admin-url-invalid");
            assert!(!error.to_string().contains("secret-pw"));
            assert!(!format!("{error:?}").contains("secret-pw"));
        }
    }

    #[test]
    fn a_ca_without_certificates_is_refused_with_its_own_code() {
        let error = admin_config(URL, Some(b"")).unwrap_err();
        assert_eq!(error, AdminConfigError::CaInvalid);
        assert_eq!(error.code(), "platform.provision.admin-ca-invalid");
        let error = admin_config(URL, Some(b"not a certificate")).unwrap_err();
        assert_eq!(error, AdminConfigError::CaInvalid);
    }

    #[test]
    fn debug_prints_the_endpoint_and_no_password() {
        let ca = test_ca_pem();
        let config = admin_config(URL, Some(ca.as_bytes())).expect("valid administrator URL");
        let printed = format!("{config:?}");
        assert!(printed.contains("db.example"));
        assert!(printed.contains("5433"));
        assert!(!printed.contains("secret-pw"));
        assert_eq!(config.host(), "db.example");
        assert_eq!(config.port(), 5433);
        assert_eq!(config.user(), "admin");
        assert_eq!(config.database(), "postgres");
    }

    #[test]
    fn session_options_carry_the_deadline_and_the_self_grant() {
        let ca = test_ca_pem();
        let config = admin_config(URL, Some(ca.as_bytes())).expect("valid administrator URL");
        let options = config.config.get_options().expect("options are set");
        assert!(options.contains("statement_timeout=10000"));
        assert!(options.contains("createrole_self_grant=set,inherit"));
    }

    #[test]
    fn the_port_defaults_to_5432() {
        let ca = test_ca_pem();
        let config = admin_config("postgresql://a:secret-pw@h/db", Some(ca.as_bytes()))
            .expect("valid administrator URL");
        assert_eq!(config.port(), 5432);
    }
}
