// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rustls::pki_types::{pem::PemObject as _, CertificateDer};
use tokio::runtime::{Builder, Runtime};
use tokio_postgres::{
    config::{Host, SslMode},
    Client, Config,
};
use tokio_postgres_rustls::MakeRustlsConnect;
use url::{Host as UrlHost, Url};
use zeroize::Zeroizing;

const BREG_SCHEMAS: [&str; 5] = [
    "registry_internal",
    "registry_data",
    "registry_source",
    "registry_derived",
    "registry_context",
];

pub(super) struct DatabaseUrls {
    pub runtime: String,
    pub migration: String,
}

#[derive(Clone)]
enum Acquisition {
    Database(String),
    Role(String),
}

pub(super) struct Database {
    client: Client,
    _connection_task: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
    tls: MakeRustlsConnect,
    admin_config: Config,
    endpoint: Endpoint,
    run_id: String,
    acquisitions: Vec<Acquisition>,
    runtime: Runtime,
}

#[derive(Clone)]
struct Endpoint {
    host: UrlHost<String>,
    port: Option<u16>,
}

impl Endpoint {
    fn product_url(&self, database: &str, user: &str, password: &str) -> Result<String> {
        let mut url =
            Url::parse("postgresql://localhost/").expect("the fixed PostgreSQL URL base is valid");
        match &self.host {
            UrlHost::Domain(host) => url.set_host(Some(host)).map_err(|_| {
                anyhow!("the PostgreSQL host cannot be represented in a product URL")
            })?,
            UrlHost::Ipv4(address) => url.set_ip_host((*address).into()).map_err(|_| {
                anyhow!("the PostgreSQL host cannot be represented in a product URL")
            })?,
            UrlHost::Ipv6(address) => url.set_ip_host((*address).into()).map_err(|_| {
                anyhow!("the PostgreSQL host cannot be represented in a product URL")
            })?,
        }
        url.set_port(self.port)
            .map_err(|_| anyhow!("the PostgreSQL port cannot be represented in a product URL"))?;
        url.set_username(user)
            .map_err(|_| anyhow!("the generated PostgreSQL role cannot be represented in a URL"))?;
        url.set_password(Some(password)).map_err(|_| {
            anyhow!("the generated PostgreSQL password cannot be represented in a URL")
        })?;
        url.set_path(&format!("/{database}"));
        url.query_pairs_mut().append_pair("sslmode", "require");
        Ok(url.into())
    }
}

impl Database {
    pub(super) fn connect(admin_url: &str, ca_pem: Option<&[u8]>, run_id: &str) -> Result<Self> {
        validate_run_id(run_id)?;
        let (mut admin_config, endpoint) = admin_config(admin_url)?;
        admin_config.ssl_mode(SslMode::Require);
        let tls = tls_connector(ca_pem)?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("cannot initialize the PostgreSQL executor")?;
        let (client, connection) = runtime
            .block_on(admin_config.connect(tls.clone()))
            .context("cannot connect to the PostgreSQL administrator database over verified TLS")?;
        let connection_task = runtime.spawn(connection);
        Ok(Self {
            client,
            _connection_task: connection_task,
            tls,
            admin_config,
            endpoint,
            run_id: run_id.to_owned(),
            acquisitions: Vec::new(),
            runtime,
        })
    }

    pub(super) fn provision(&mut self, label: &str, breg: bool) -> Result<DatabaseUrls> {
        validate_label(label)?;
        let names = Names::new(&self.run_id, label);
        if self.acquisitions.iter().any(|acquisition| {
            matches!(acquisition, Acquisition::Database(database) if database == &names.database)
        }) {
            bail!("the {label} database was already provisioned for this run");
        }

        let migration_password = random_password()?;
        let runtime_password = random_password()?;
        self.create_role(&names.migration_role, &migration_password)?;
        self.create_role(&names.runtime_role, &runtime_password)?;
        self.create_database(&names)?;
        self.configure_database(&names, breg)?;

        Ok(DatabaseUrls {
            runtime: self.product_url(&names.database, &names.runtime_role, &runtime_password)?,
            migration: self.product_url(
                &names.database,
                &names.migration_role,
                &migration_password,
            )?,
        })
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        let mut retained = Vec::new();
        let acquisitions = self.acquisitions.clone();
        for acquisition in acquisitions.into_iter().rev() {
            let result = match &acquisition {
                Acquisition::Database(name) => self.execute_cleanup(&format!(
                    "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                    quote_identifier(name)
                )),
                Acquisition::Role(name) => {
                    self.execute_cleanup(&format!("DROP ROLE IF EXISTS {}", quote_identifier(name)))
                }
            };
            if let Err(error) = result {
                failures.push(match &acquisition {
                    Acquisition::Database(_) => format!("database: {error:#}"),
                    Acquisition::Role(_) => format!("role: {error:#}"),
                });
                retained.push(acquisition);
            }
        }
        retained.reverse();
        self.acquisitions = retained;
        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "PostgreSQL cleanup is incomplete for {} resource(s): {}",
                failures.len(),
                failures.join("; ")
            )
        }
    }

    fn reconnect_admin(&mut self) -> Result<()> {
        let (client, connection) = self
            .runtime
            .block_on(self.admin_config.connect(self.tls.clone()))
            .context("cannot reconnect to the PostgreSQL administrator database")?;
        self._connection_task.abort();
        self.client = client;
        self._connection_task = self.runtime.spawn(connection);
        Ok(())
    }

    fn ensure_admin_connection(&mut self) -> Result<()> {
        if self.client.is_closed() {
            self.reconnect_admin()?;
        }
        Ok(())
    }

    fn execute_cleanup(&mut self, statement: &str) -> Result<()> {
        self.ensure_admin_connection()?;
        match self.runtime.block_on(self.client.batch_execute(statement)) {
            Ok(()) => Ok(()),
            Err(first) if self.client.is_closed() => {
                self.reconnect_admin()?;
                self.runtime
                    .block_on(self.client.batch_execute(statement))
                    .with_context(|| {
                        format!(
                            "the PostgreSQL cleanup operation failed after reconnecting ({first})"
                        )
                    })
            }
            Err(error) => Err(error).context("the PostgreSQL cleanup operation failed"),
        }
    }

    fn create_role(&mut self, role: &str, password: &str) -> Result<()> {
        let verifier = Zeroizing::new(postgres_protocol::password::scram_sha_256(
            password.as_bytes(),
        ));
        let statement = Zeroizing::new(create_role_sql(role, &verifier));
        let created = self.runtime.block_on(self.client.batch_execute(&statement));
        if created.is_ok() || created.as_ref().is_err_and(|error| error.is_closed()) {
            // A closed connection cannot tell us whether PostgreSQL committed
            // the statement. Retaining the exact run-owned name lets cleanup's
            // idempotent DROP cover both outcomes without replaying CREATE.
            self.acquisitions.push(Acquisition::Role(role.to_owned()));
        }
        created.context("cannot create a least-privilege PostgreSQL role")
    }

    fn create_database(&mut self, names: &Names) -> Result<()> {
        let created = self.runtime.block_on(self.client.batch_execute(&format!(
            "CREATE DATABASE {} WITH ALLOW_CONNECTIONS false",
            quote_identifier(&names.database)
        )));
        if created.is_ok() || created.as_ref().is_err_and(|error| error.is_closed()) {
            self.acquisitions
                .push(Acquisition::Database(names.database.clone()));
        }
        created.context("cannot create an isolated PostgreSQL database")?;

        self.execute_admin(&database_access_sql(names))
            .context("cannot restrict the PostgreSQL database to this run's roles")
    }

    fn configure_database(&self, names: &Names, breg: bool) -> Result<()> {
        let statement = database_setup_sql(names, breg);

        let mut target = self.admin_config.clone();
        target.dbname(&names.database).ssl_mode(SslMode::Require);
        self.runtime
            .block_on(async {
                let (client, connection) = target
                    .connect(self.tls.clone())
                    .await
                    .context("cannot connect to the provisioned PostgreSQL database")?;
                let connection_task = tokio::spawn(connection);
                let executed = client.batch_execute(&statement).await;
                drop(client);
                let closed = connection_task
                    .await
                    .context("the PostgreSQL connection task stopped unexpectedly")?;
                executed.context("cannot configure the provisioned PostgreSQL database")?;
                closed.context("the PostgreSQL configuration connection failed")?;
                Result::<()>::Ok(())
            })
            .context("cannot finish PostgreSQL database provisioning")
    }

    fn execute_admin(&self, statement: &str) -> Result<()> {
        self.runtime
            .block_on(self.client.batch_execute(statement))
            .context("the PostgreSQL administrator operation failed")
    }

    fn product_url(&self, database: &str, user: &str, password: &str) -> Result<String> {
        self.endpoint.product_url(database, user, password)
    }
}

struct Names {
    database: String,
    migration_role: String,
    runtime_role: String,
}

impl Names {
    fn new(run_id: &str, label: &str) -> Self {
        let database = format!("rstack_{run_id}_{label}");
        Self {
            migration_role: format!("{database}_migration"),
            runtime_role: format!("{database}_runtime"),
            database,
        }
    }
}

fn validate_run_id(run_id: &str) -> Result<()> {
    if run_id.len() == 32
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        bail!("the database run id must be exactly 32 lowercase hexadecimal characters")
    }
}

fn validate_label(label: &str) -> Result<()> {
    if matches!(label, "breg" | "breg_test" | "casework") {
        Ok(())
    } else {
        bail!("the database label must be breg, breg_test, or casework")
    }
}

fn database_access_sql(names: &Names) -> String {
    format!(
        "REVOKE ALL ON DATABASE {database} FROM PUBLIC; \
         GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}; \
         ALTER DATABASE {database} ALLOW_CONNECTIONS true",
        database = quote_identifier(&names.database),
        migration = quote_identifier(&names.migration_role),
        runtime = quote_identifier(&names.runtime_role),
    )
}

fn create_role_sql(role: &str, verifier: &str) -> String {
    format!(
        "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD {}",
        quote_identifier(role),
        quote_literal(verifier)
    )
}

fn database_setup_sql(names: &Names, breg: bool) -> String {
    if breg {
        let schemas = BREG_SCHEMAS
            .iter()
            .map(|schema| {
                format!(
                    "CREATE SCHEMA {schema} AUTHORIZATION {owner}; \
                     REVOKE ALL ON SCHEMA {schema} FROM PUBLIC",
                    schema = quote_identifier(schema),
                    owner = quote_identifier(&names.migration_role),
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        format!("CREATE EXTENSION btree_gist; {schemas}")
    } else {
        format!(
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC; \
             GRANT USAGE, CREATE ON SCHEMA public TO {}",
            quote_identifier(&names.migration_role)
        )
    }
}

fn admin_config(admin_url: &str) -> Result<(Config, Endpoint)> {
    let parsed =
        Url::parse(admin_url).map_err(|_| anyhow!("the PostgreSQL admin URL is invalid"))?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.cannot_be_a_base()
        || parsed.fragment().is_some()
    {
        bail!("the PostgreSQL admin URL must be an absolute postgres:// or postgresql:// URL");
    }
    if parsed.username().is_empty()
        || parsed.password().is_none_or(str::is_empty)
        || parsed.host().is_none()
    {
        bail!("the PostgreSQL admin URL must include an explicit host, user, and password");
    }
    let database = parsed.path().strip_prefix('/').unwrap_or_default();
    if database.is_empty() || database.contains('/') {
        bail!("the PostgreSQL admin URL must include one explicit database name");
    }
    if parsed.query_pairs().any(|(key, _)| {
        matches!(
            key.as_ref(),
            "host" | "hostaddr" | "port" | "user" | "password" | "dbname"
        )
    }) {
        bail!(
            "the PostgreSQL admin URL must not override its endpoint or credentials in the query"
        );
    }

    let config =
        Config::from_str(admin_url).map_err(|_| anyhow!("the PostgreSQL admin URL is invalid"))?;
    if config.get_hosts().len() != 1
        || !matches!(config.get_hosts().first(), Some(Host::Tcp(_)))
        || !config.get_hostaddrs().is_empty()
        || config.get_user().is_none_or(str::is_empty)
        || config.get_password().is_none_or(<[u8]>::is_empty)
        || config.get_dbname().is_none_or(str::is_empty)
    {
        bail!("the PostgreSQL admin URL must name one TCP host, user, password, and database");
    }

    let host = parsed.host().expect("the host was checked").to_owned();
    Ok((
        config,
        Endpoint {
            host,
            port: parsed.port(),
        },
    ))
}

fn tls_connector(ca_pem: Option<&[u8]>) -> Result<MakeRustlsConnect> {
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        bail!("cannot initialize the PostgreSQL TLS provider");
    }

    if let Some(pem) = ca_pem {
        let mut roots = rustls::RootCertStore::empty();
        let mut count = 0usize;
        for certificate in CertificateDer::pem_slice_iter(pem) {
            roots
                .add(certificate.context("the PostgreSQL CA PEM is invalid")?)
                .context("the PostgreSQL CA certificate is invalid")?;
            count += 1;
        }
        if count == 0 {
            bail!("the PostgreSQL CA PEM contains no certificates");
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(MakeRustlsConnect::new(config))
    } else {
        MakeRustlsConnect::with_native_certs()
            .map(|value| value.0)
            .map_err(|_| anyhow!("cannot load native roots for PostgreSQL TLS"))
    }
}

fn random_password() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).context("cannot generate a PostgreSQL credential")?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN_ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn run_ids_are_exact_lowercase_hex() {
        assert!(validate_run_id(RUN_ID).is_ok());
        for invalid in [
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(validate_run_id(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn only_owned_database_labels_are_accepted() {
        for label in ["breg", "breg_test", "casework"] {
            assert!(validate_label(label).is_ok(), "refused {label}");
        }
        for invalid in ["", "breg-test", "casework_test", "postgres"] {
            assert!(validate_label(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn generated_names_are_run_scoped_and_fit_postgresql() {
        let names = Names::new(RUN_ID, "breg_test");
        assert_eq!(
            names.database,
            "rstack_0123456789abcdef0123456789abcdef_breg_test"
        );
        assert!(names.migration_role.ends_with("_breg_test_migration"));
        assert!(names.runtime_role.ends_with("_breg_test_runtime"));
        assert!(names.database.len() <= 63);
        assert!(names.migration_role.len() <= 63);
        assert!(names.runtime_role.len() <= 63);
    }

    #[test]
    fn admin_urls_require_one_explicit_password_authenticated_tcp_database() {
        let password = random_password().unwrap();
        let password = password.as_str();
        let endpoint = format!("postgresql://admin:{password}@db.example");
        assert!(admin_config(&format!("{endpoint}:5432/postgres?sslmode=require")).is_ok());
        assert!(admin_config(&format!("postgres://admin:{password}@[::1]:5432/postgres")).is_ok());
        let invalid = [
            format!("http://admin:{password}@db.example/postgres"),
            "postgresql://db.example/postgres".to_owned(),
            "postgresql://admin@db.example/postgres".to_owned(),
            "postgresql://admin:@db.example/postgres".to_owned(),
            endpoint.clone(),
            format!("{endpoint}/one/two"),
            format!("{endpoint}/postgres?host=other.example"),
            format!("{endpoint}/postgres?dbname=other"),
            format!("{endpoint}/postgres?hostaddr=127.0.0.1"),
            "postgresql:///postgres".to_owned(),
        ];
        for (case, url) in invalid.iter().enumerate() {
            assert!(
                admin_config(url).is_err(),
                "accepted invalid admin URL case {case}"
            );
        }
    }

    #[test]
    fn generated_product_urls_contain_only_generated_credentials_and_required_tls() {
        let endpoint = Endpoint {
            host: UrlHost::Domain("db.example".to_owned()),
            port: Some(5543),
        };
        let password = random_password().unwrap();
        let password = password.as_str();
        let url = endpoint.product_url("owned", "runtime", password).unwrap();
        assert!(
            url == format!("postgresql://runtime:{password}@db.example:5543/owned?sslmode=require"),
            "unexpected product connection URL"
        );
    }

    #[test]
    fn generated_product_urls_round_trip_ipv6_hosts_and_credentials() {
        let admin_password = random_password().unwrap();
        let admin_password = admin_password.as_str();
        for address_text in ["::1", "2001:db8:1234:5678::9"] {
            let address = address_text.parse().unwrap();
            let (_, endpoint) = admin_config(&format!(
                "postgresql://admin:{admin_password}@[{address_text}]:5543/postgres"
            ))
            .unwrap();
            for (user, database) in [("runtime", "owned"), ("migration", "owned_test")] {
                let password = random_password().unwrap();
                let password = password.as_str();
                let rendered = endpoint.product_url(database, user, password).unwrap();
                let parsed = Url::parse(&rendered).unwrap();
                assert_eq!(parsed.host(), Some(UrlHost::Ipv6(address)));
                assert_eq!(parsed.port(), Some(5543));
                assert_eq!(parsed.username(), user);
                assert!(
                    parsed.password() == Some(password),
                    "unexpected product password"
                );
                assert_eq!(parsed.path(), format!("/{database}"));
                assert_eq!(parsed.query(), Some("sslmode=require"));
                assert!(rendered.contains(&format!("@[{address}]:5543/")));
            }
        }
    }

    #[test]
    fn database_access_is_closed_to_public_before_connections_are_enabled() {
        let names = Names::new(RUN_ID, "casework");
        let sql = database_access_sql(&names);
        let revoke = sql.find("REVOKE ALL ON DATABASE").unwrap();
        let grant = sql.find("GRANT CONNECT ON DATABASE").unwrap();
        let enable = sql.find("ALLOW_CONNECTIONS true").unwrap();
        assert!(revoke < grant && grant < enable, "{sql}");
        assert!(sql.contains(&quote_identifier(&names.migration_role)));
        assert!(sql.contains(&quote_identifier(&names.runtime_role)));
    }

    #[test]
    fn breg_setup_installs_extension_and_all_owned_schemas() {
        let names = Names::new(RUN_ID, "breg");
        let sql = database_setup_sql(&names, true);
        assert!(sql.starts_with("CREATE EXTENSION btree_gist;"), "{sql}");
        for schema in BREG_SCHEMAS {
            assert!(
                sql.contains(&format!(
                    "CREATE SCHEMA {} AUTHORIZATION {}",
                    quote_identifier(schema),
                    quote_identifier(&names.migration_role)
                )),
                "{sql}"
            );
            assert!(
                sql.contains(&format!(
                    "REVOKE ALL ON SCHEMA {} FROM PUBLIC",
                    quote_identifier(schema)
                )),
                "{sql}"
            );
        }
    }

    #[test]
    fn casework_setup_gives_only_migration_role_public_schema_creation() {
        let names = Names::new(RUN_ID, "casework");
        let sql = database_setup_sql(&names, false);
        assert!(
            sql.starts_with("REVOKE CREATE ON SCHEMA public FROM PUBLIC;"),
            "{sql}"
        );
        assert!(sql.contains(&format!(
            "GRANT USAGE, CREATE ON SCHEMA public TO {}",
            quote_identifier(&names.migration_role)
        )));
        assert!(!sql.contains(&names.runtime_role));
    }

    #[test]
    fn identifiers_and_passwords_are_quoted_for_postgresql() {
        assert_eq!(quote_identifier("a\"b"), "\"a\"\"b\"");
        assert_eq!(quote_literal("a'b"), "'a''b'");
    }

    #[test]
    fn role_statement_carries_a_postgresql_scram_verifier_not_cleartext() {
        let password = random_password().unwrap();
        let verifier = postgres_protocol::password::scram_sha_256(password.as_bytes());
        let sql = create_role_sql("rstack_role", &verifier);
        let expected = format!(
            "CREATE ROLE \"rstack_role\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{verifier}'"
        );
        assert!(verifier.starts_with("SCRAM-SHA-256$"));
        assert!(sql == expected && !sql.contains(password.as_str()));
    }

    #[test]
    fn empty_or_malformed_custom_root_sets_are_refused() {
        assert!(tls_connector(Some(b"")).is_err());
        assert!(tls_connector(Some(b"not a certificate")).is_err());
    }
}
