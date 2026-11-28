// SPDX-License-Identifier: Apache-2.0

use std::{
    future::Future,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_provision::{
    plan, sql::quote_identifier, Plan, ProductDatabase, ProvisionTarget, RoleCredential,
    SchemaLayout, Scope, Spatial,
};
use rustls::pki_types::{pem::PemObject as _, CertificateDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::runtime::{Builder, Runtime};
use tokio_postgres::{
    config::{Host, SslMode},
    error::SqlState,
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
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const STATEMENT_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// The first and longest pauses before a refused database drop is retried.
const DROP_RETRY_FIRST_PAUSE: Duration = Duration::from_millis(100);
const DROP_RETRY_MAX_PAUSE: Duration = Duration::from_secs(1);
/// Bounds the diagnostic read after the cleanup deadline has passed.
const BACKEND_REPORT_TIMEOUT: Duration = Duration::from_secs(2);
/// Counts the other backends in a database by type, without names. Without
/// `pg_read_all_stats` the administrator cannot read the type of a backend
/// whose role it does not hold, so such a backend is counted by whether it
/// has a role at all: an autovacuum worker has none.
const CONNECTED_BACKENDS_QUERY: &str = "SELECT coalesce(backend_type, \
         CASE WHEN usesysid IS NULL THEN 'background process without a role' \
              ELSE 'session of a role this administrator does not hold' END), \
       count(*) \
  FROM pg_catalog.pg_stat_activity \
 WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid() \
 GROUP BY 1 ORDER BY 1";
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const RECOVERY_IDENTITY_QUERY: &str = "SELECT system_identifier, \
       pg_catalog.current_database()::text \
  FROM pg_catalog.pg_control_system()";
/// Lets a role holding CREATEROLE use the roles it creates. PostgreSQL 16 and
/// later grant such a creator only ADMIN on them, which is not enough for
/// `CREATE SCHEMA ... AUTHORIZATION` or `CREATE DATABASE ... OWNER`.
const CREATEROLE_SELF_GRANT: &str = "set,inherit";
/// Mirrors the BReg kernel's supported PostGIS floor
/// (`MIN_POSTGIS_MAJOR` and `MIN_POSTGIS_MINOR` in
/// `registry-breg/src/postgres/roles.rs`), so the runner can name it before
/// the kernel refuses with a generic connection error.
const MIN_POSTGIS: (u32, u32) = (3, 5);

async fn bounded_connection<T>(
    connection: impl Future<Output = std::result::Result<T, tokio_postgres::Error>>,
    timeout: Duration,
) -> Result<T> {
    tokio::time::timeout(timeout, connection)
        .await
        .map_err(|_| anyhow!("the PostgreSQL connection handshake timed out"))?
        .context("the PostgreSQL connection handshake failed")
}

#[derive(Debug, thiserror::Error)]
enum OperationFailure {
    #[error("the PostgreSQL {operation} operation exceeded its I/O deadline")]
    IoDeadline { operation: &'static str },
    #[error(
        "the PostgreSQL {operation} operation was canceled or exceeded its statement deadline"
    )]
    StatementDeadline { operation: &'static str },
    #[error("the PostgreSQL {operation} operation failed")]
    PostgreSql {
        operation: &'static str,
        #[source]
        source: tokio_postgres::Error,
    },
}

impl OperationFailure {
    fn postgres(operation: &'static str, source: tokio_postgres::Error) -> Self {
        if source.code() == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED) {
            Self::StatementDeadline { operation }
        } else {
            Self::PostgreSql { operation, source }
        }
    }

    fn lacks_privilege(&self) -> bool {
        matches!(self, Self::PostgreSql { source, .. }
            if source.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE))
    }

    fn effect_is_unconfirmed(&self) -> bool {
        matches!(self, Self::IoDeadline { .. })
            || matches!(self, Self::PostgreSql { source, .. } if source.as_db_error().is_none())
    }
}

async fn bounded_operation<T>(
    operation: &'static str,
    future: impl Future<Output = std::result::Result<T, tokio_postgres::Error>>,
    timeout: Duration,
) -> std::result::Result<T, OperationFailure> {
    match tokio::time::timeout(timeout, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(OperationFailure::postgres(operation, error)),
        Err(_) => Err(OperationFailure::IoDeadline { operation }),
    }
}

fn lacks_privilege(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<OperationFailure>())
        .any(OperationFailure::lacks_privilege)
}

fn retain_create_acquisition<T>(
    acquisitions: &mut Vec<Acquisition>,
    acquisition: Acquisition,
    created: &std::result::Result<T, OperationFailure>,
) {
    if created.is_ok()
        || created
            .as_ref()
            .is_err_and(OperationFailure::effect_is_unconfirmed)
    {
        acquisitions.push(acquisition);
    }
}

/// Startup options for every administrator session: the statement deadline and
/// the CREATEROLE self-grant. The comma in the self-grant value is not a
/// separator for the server's startup option parser, which splits on spaces.
fn apply_session_options(config: &mut Config) {
    let added = format!(
        "-c statement_timeout={} -c createrole_self_grant={CREATEROLE_SELF_GRANT}",
        STATEMENT_TIMEOUT.as_millis()
    );
    if let Some(existing) = config.get_options().filter(|value| !value.is_empty()) {
        config.options(format!("{existing} {added}"));
    } else {
        config.options(added);
    }
}

fn postgis_version_supported(version: &str) -> bool {
    let mut parts = version.split('.');
    let mut next = || parts.next().and_then(|value| value.parse::<u32>().ok());
    match (next(), next()) {
        (Some(major), Some(minor)) => (major, minor) >= MIN_POSTGIS,
        _ => false,
    }
}

/// Refuses a spatial BReg run when the server does not offer a supported
/// PostGIS. `available` is the `default_version` of the `postgis` row in
/// `pg_available_extensions`, or `None` when there is no such row.
fn require_postgis(available: Option<&str>) -> Result<()> {
    match available {
        None => bail!(
            "spatial BReg needs PostGIS {}.{} or later installed on the PostgreSQL server; \
             the server does not offer the postgis extension",
            MIN_POSTGIS.0,
            MIN_POSTGIS.1
        ),
        Some(version) if !postgis_version_supported(version) => bail!(
            "spatial BReg needs PostGIS {}.{} or later installed on the PostgreSQL server; \
             the server offers {version}",
            MIN_POSTGIS.0,
            MIN_POSTGIS.1
        ),
        Some(_) => Ok(()),
    }
}

fn remaining_timeout(deadline: Instant, maximum: Duration) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("the PostgreSQL operation deadline expired");
    }
    Ok(remaining.min(maximum))
}

fn ownership_lock_statement(run_id: &str) -> Result<String> {
    let prefix = run_id
        .get(..16)
        .context("the database run id cannot form an ownership lock")?;
    let key = u64::from_str_radix(prefix, 16)
        .context("the validated database run id cannot form an ownership lock")?
        as i64;
    Ok(format!("SELECT pg_advisory_lock({key})"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct RecoveryIdentity {
    system_identifier: i64,
    database: String,
}

fn require_recovery_identity(expected: &RecoveryIdentity, actual: &RecoveryIdentity) -> Result<()> {
    if expected.system_identifier != actual.system_identifier {
        bail!(
            "this run belongs to a different PostgreSQL cluster; use the administrator URL from startup"
        );
    }
    if expected.database != actual.database {
        bail!(
            "this run belongs to a different PostgreSQL maintenance database; use the administrator URL from startup"
        );
    }
    Ok(())
}

fn read_recovery_identity(
    runtime: &Runtime,
    client: &Client,
    deadline: Instant,
) -> Result<RecoveryIdentity> {
    let row = runtime
        .block_on(bounded_operation(
            "recovery identity check",
            client.query_one(RECOVERY_IDENTITY_QUERY, &[]),
            remaining_timeout(deadline, OPERATION_TIMEOUT)?,
        ))
        .map_err(anyhow::Error::new)
        .context(
            "cannot identify the PostgreSQL cluster; the administrator must be allowed to execute pg_catalog.pg_control_system()",
        )?;
    Ok(RecoveryIdentity {
        system_identifier: row
            .try_get(0)
            .context("cannot read the PostgreSQL cluster identifier")?,
        database: row
            .try_get(1)
            .context("cannot read the PostgreSQL administrator database name")?,
    })
}

type AdminConnectionTask = tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>;

fn open_admin_session(
    runtime: &Runtime,
    config: &Config,
    tls: &MakeRustlsConnect,
    ownership_lock: &str,
    expected_identity: Option<&RecoveryIdentity>,
    deadline: Instant,
) -> Result<(Client, AdminConnectionTask, RecoveryIdentity)> {
    let (client, connection) = runtime.block_on(bounded_connection(
        config.connect(tls.clone()),
        remaining_timeout(deadline, CONNECTION_TIMEOUT)?,
    ))?;
    let connection_task = runtime.spawn(connection);
    // PostgreSQL advisory locks are scoped to one cluster and database. Bind
    // both before acquiring the lock, or the same run id at another target
    // could appear to be exclusively owned.
    let identity = match read_recovery_identity(runtime, &client, deadline) {
        Ok(identity) => identity,
        Err(error) => {
            connection_task.abort();
            return Err(error);
        }
    };
    if let Some(expected) = expected_identity {
        if let Err(error) = require_recovery_identity(expected, &identity) {
            connection_task.abort();
            return Err(error);
        }
    }
    let locked = runtime.block_on(bounded_operation(
        "run ownership lock acquisition",
        client.batch_execute(ownership_lock),
        remaining_timeout(deadline, OPERATION_TIMEOUT)?,
    ));
    if let Err(error) = locked {
        connection_task.abort();
        return Err(error).context("cannot acquire the PostgreSQL run ownership lock");
    }
    Ok((client, connection_task, identity))
}

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
    _connection_task: AdminConnectionTask,
    admin_session_failed: bool,
    tls: MakeRustlsConnect,
    admin_config: Config,
    ownership_lock: String,
    recovery_identity: RecoveryIdentity,
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
        Self::connect_checked(admin_url, ca_pem, run_id, None)
    }

    pub(super) fn connect_for_recovery(
        admin_url: &str,
        ca_pem: Option<&[u8]>,
        run_id: &str,
        expected_identity: &RecoveryIdentity,
    ) -> Result<Self> {
        Self::connect_checked(admin_url, ca_pem, run_id, Some(expected_identity))
    }

    fn connect_checked(
        admin_url: &str,
        ca_pem: Option<&[u8]>,
        run_id: &str,
        expected_identity: Option<&RecoveryIdentity>,
    ) -> Result<Self> {
        validate_run_id(run_id)?;
        let (mut admin_config, endpoint) = admin_config(admin_url)?;
        admin_config.ssl_mode(SslMode::Require);
        apply_session_options(&mut admin_config);
        let tls = tls_connector(ca_pem)?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("cannot initialize the PostgreSQL executor")?;
        let ownership_lock = ownership_lock_statement(run_id)?;
        let session_deadline = Instant::now() + CLEANUP_ATTEMPT_TIMEOUT;
        let (client, connection_task, recovery_identity) = open_admin_session(
            &runtime,
            &admin_config,
            &tls,
            &ownership_lock,
            expected_identity,
            session_deadline,
        )
        .context("cannot establish the PostgreSQL administrator session over verified TLS")
        // The server is unreachable or refused the session: the environment
        // failed, not the request.
        .map_err(super::operational)?;
        Ok(Self {
            client,
            _connection_task: connection_task,
            admin_session_failed: false,
            tls,
            admin_config,
            ownership_lock,
            recovery_identity,
            endpoint,
            run_id: run_id.to_owned(),
            acquisitions: Vec::new(),
            runtime,
        })
    }

    pub(super) fn recovery_identity(&self) -> &RecoveryIdentity {
        &self.recovery_identity
    }

    pub(super) fn provision(
        &mut self,
        label: &str,
        breg: bool,
        requires_postgis: bool,
    ) -> Result<DatabaseUrls> {
        validate_label(label)?;
        if requires_postgis && !breg {
            bail!("PostGIS prerequisites may be provisioned only for a BReg database");
        }
        let names = Names::new(&self.run_id, label);
        if self.acquisitions.iter().any(|acquisition| {
            matches!(acquisition, Acquisition::Database(database) if database == &names.database)
        }) {
            bail!("the {label} database was already provisioned for this run");
        }

        if requires_postgis {
            self.check_postgis_available()?;
        }

        let migration_password = random_password()?;
        let runtime_password = random_password()?;
        let batches = Batches::new(
            &names,
            label,
            breg,
            requires_postgis,
            &migration_password,
            &runtime_password,
        )?;
        self.create_role(&names.migration_role, &migration_password)?;
        self.create_role(&names.runtime_role, &runtime_password)?;
        if let Some(statement) = &batches.bbox_role {
            self.create_spatial_bbox_role(&spatial_bbox_role(&names), statement)?;
        }
        self.create_database(&names, &batches)?;
        self.configure_database(&names, &batches)?;

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
        self.cleanup_until(Instant::now() + CLEANUP_ATTEMPT_TIMEOUT)
    }

    fn cleanup_until(&mut self, deadline: Instant) -> Result<()> {
        let mut failures = Vec::new();
        let mut retained = Vec::new();
        let acquisitions = self.acquisitions.clone();
        for acquisition in acquisitions.into_iter().rev() {
            let result = match &acquisition {
                Acquisition::Database(name) => self.drop_database(name, deadline),
                Acquisition::Role(name) => self.execute_cleanup(
                    &format!("DROP ROLE IF EXISTS {}", quote_identifier(name)),
                    deadline,
                ),
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

    /// `WITH (FORCE)` terminates the database's other sessions, but
    /// PostgreSQL refuses the whole drop when one of them belongs to a role
    /// this administrator does not hold, or to no role, as a background
    /// worker does. Such a backend is normally about to exit, so the drop is
    /// retried until the cleanup deadline. A final refusal says what still
    /// holds the database.
    fn drop_database(&mut self, name: &str, deadline: Instant) -> Result<()> {
        let statement = format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            quote_identifier(name)
        );
        let mut pause = DROP_RETRY_FIRST_PAUSE;
        loop {
            let error = match self.execute_cleanup(&statement, deadline) {
                Err(error) if lacks_privilege(&error) => error,
                other => return other,
            };
            if deadline.saturating_duration_since(Instant::now()) <= pause {
                return Err(match self.connected_backends(name) {
                    Some(backends) => error.context(format!(
                        "backends still using the database, by type: {backends}"
                    )),
                    None => error,
                });
            }
            thread::sleep(pause);
            pause = (pause * 2).min(DROP_RETRY_MAX_PAUSE);
        }
    }

    fn connected_backends(&mut self, database: &str) -> Option<String> {
        let queried = self.runtime.block_on(bounded_operation(
            "connected backend count",
            self.client.query(CONNECTED_BACKENDS_QUERY, &[&database]),
            BACKEND_REPORT_TIMEOUT,
        ));
        if queried
            .as_ref()
            .is_err_and(OperationFailure::effect_is_unconfirmed)
        {
            self.retire_admin_session();
        }
        let counts = queried
            .ok()?
            .iter()
            .map(|row| {
                let kind: String = row.try_get(0).ok()?;
                let count: i64 = row.try_get(1).ok()?;
                Some(format!("{kind} ({count})"))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(if counts.is_empty() {
            "none".to_owned()
        } else {
            counts.join(", ")
        })
    }

    fn reconnect_admin(&mut self, deadline: Instant) -> Result<()> {
        // The old server backend can outlive the client-side I/O timeout. Its
        // session lock orders this replacement session after an unconfirmed
        // CREATE has committed or rolled back, so cleanup cannot run too early.
        self.retire_admin_session();
        let (client, connection_task, _) = open_admin_session(
            &self.runtime,
            &self.admin_config,
            &self.tls,
            &self.ownership_lock,
            Some(&self.recovery_identity),
            deadline,
        )
        .context("cannot reconnect to the PostgreSQL administrator database")?;
        self.client = client;
        self._connection_task = connection_task;
        self.admin_session_failed = false;
        Ok(())
    }

    fn retire_admin_session(&mut self) {
        self._connection_task.abort();
        self.admin_session_failed = true;
    }

    fn ensure_admin_connection(&mut self, deadline: Instant) -> Result<()> {
        if self.admin_session_failed || self.client.is_closed() {
            self.reconnect_admin(deadline)?;
        }
        Ok(())
    }

    fn execute_cleanup(&mut self, statement: &str, deadline: Instant) -> Result<()> {
        self.ensure_admin_connection(deadline)?;
        let first = self.execute_admin_operation(
            statement,
            "cleanup",
            remaining_timeout(deadline, OPERATION_TIMEOUT)?,
        );
        match first {
            Ok(()) => Ok(()),
            Err(first) if first.effect_is_unconfirmed() => {
                self.reconnect_admin(deadline)?;
                self.execute_admin_operation(
                    statement,
                    "cleanup",
                    remaining_timeout(deadline, OPERATION_TIMEOUT)?,
                )
                .with_context(|| {
                    format!("the PostgreSQL cleanup operation failed after reconnecting ({first})")
                })
            }
            Err(error) => Err(error).context("the PostgreSQL cleanup operation failed"),
        }
    }

    fn create_role(&mut self, role: &str, password: &str) -> Result<()> {
        let verifier = Zeroizing::new(postgres_protocol::password::scram_sha_256(
            password.as_bytes(),
        ));
        let statement = Zeroizing::new(registry_platform_provision::sql::create_role_sql(
            role, &verifier,
        ));
        self.create_owned_role(
            role,
            &statement,
            "cannot create a least-privilege PostgreSQL role",
        )
    }

    fn create_spatial_bbox_role(&mut self, role: &str, statement: &str) -> Result<()> {
        self.create_owned_role(role, statement, "cannot create the BReg spatial bbox role")
    }

    fn create_owned_role(
        &mut self,
        role: &str,
        statement: &str,
        context: &'static str,
    ) -> Result<()> {
        let created = self.execute_admin_operation(statement, "role creation", OPERATION_TIMEOUT);
        // A transport/protocol failure or I/O deadline cannot tell us whether
        // PostgreSQL committed the statement. Retaining the exact run-owned name
        // lets cleanup's idempotent DROP cover both outcomes without replaying CREATE.
        retain_create_acquisition(
            &mut self.acquisitions,
            Acquisition::Role(role.to_owned()),
            &created,
        );
        created.map_err(anyhow::Error::new).context(context)
    }

    fn create_database(&mut self, names: &Names, batches: &Batches) -> Result<()> {
        let created = self.execute_admin_operation(
            &batches.create_database,
            "database creation",
            OPERATION_TIMEOUT,
        );
        retain_create_acquisition(
            &mut self.acquisitions,
            Acquisition::Database(names.database.clone()),
            &created,
        );
        created
            .map_err(anyhow::Error::new)
            .context("cannot create an isolated PostgreSQL database")?;

        self.execute_admin(&batches.access)
            .context("cannot restrict the PostgreSQL database to this run's roles")
    }

    fn configure_database(&self, names: &Names, batches: &Batches) -> Result<()> {
        let statement = &batches.setup;
        let postgis = &batches.postgis;

        let mut target = self.admin_config.clone();
        target.dbname(&names.database).ssl_mode(SslMode::Require);
        self.runtime
            .block_on(async {
                let (client, connection) =
                    bounded_connection(target.connect(self.tls.clone()), CONNECTION_TIMEOUT)
                        .await
                        .context("cannot connect to the provisioned PostgreSQL database")?;
                let connection_task = tokio::spawn(connection);
                let executed = tokio::time::timeout(OPERATION_TIMEOUT, async {
                    client
                        .batch_execute(statement)
                        .await
                        .map_err(|error| {
                            OperationFailure::postgres("database configuration", error)
                        })
                        .map_err(anyhow::Error::new)
                        .context("cannot configure the provisioned PostgreSQL database")?;
                    if let Some(postgis) = postgis {
                        client
                            .batch_execute(postgis)
                            .await
                            .map_err(|error| {
                                OperationFailure::postgres("PostGIS provisioning", error)
                            })
                            .map_err(anyhow::Error::new)
                            .context(
                                "cannot provision BReg PostGIS prerequisites; the PostgreSQL \
                             administrator must be allowed to CREATE EXTENSION postgis, \
                             which normally needs a superuser",
                            )?;
                    }
                    Result::<()>::Ok(())
                })
                .await
                .map_err(|_| {
                    anyhow!(
                        "the PostgreSQL database configuration operation exceeded its I/O deadline"
                    )
                })
                .and_then(|result| result);
                connection_task.abort();
                executed
            })
            .context("cannot finish PostgreSQL database provisioning")
    }

    /// Reads the PostGIS version the server offers, before this run acquires
    /// any role or database.
    fn check_postgis_available(&mut self) -> Result<()> {
        let queried = self.runtime.block_on(bounded_operation(
            "PostGIS availability check",
            self.client.query_opt(
                "SELECT default_version FROM pg_available_extensions WHERE name = 'postgis'",
                &[],
            ),
            OPERATION_TIMEOUT,
        ));
        if queried
            .as_ref()
            .is_err_and(OperationFailure::effect_is_unconfirmed)
        {
            self.retire_admin_session();
        }
        let row = queried
            .map_err(anyhow::Error::new)
            .context("cannot check that the PostgreSQL server offers PostGIS")?;
        let version = row
            .map(|row| row.try_get::<_, Option<String>>(0))
            .transpose()
            .context("cannot read the PostGIS version the PostgreSQL server offers")?
            .flatten();
        require_postgis(version.as_deref())
    }

    fn execute_admin(&mut self, statement: &str) -> Result<()> {
        self.execute_admin_operation(statement, "administrator", OPERATION_TIMEOUT)
            .map_err(anyhow::Error::new)
            .context("the PostgreSQL administrator operation failed")
    }

    fn execute_admin_operation(
        &mut self,
        statement: &str,
        operation: &'static str,
        timeout: Duration,
    ) -> std::result::Result<(), OperationFailure> {
        let executed = self.runtime.block_on(bounded_operation(
            operation,
            self.client.batch_execute(statement),
            timeout,
        ));
        if executed
            .as_ref()
            .is_err_and(OperationFailure::effect_is_unconfirmed)
        {
            self.retire_admin_session();
        }
        executed
    }

    fn product_url(&self, database: &str, user: &str, password: &str) -> Result<String> {
        self.endpoint.product_url(database, user, password)
    }

    /// Take ownership of everything `provision` can create for one label, so
    /// that `cleanup` releases the objects of a run whose supervisor is lost.
    pub(super) fn adopt(&mut self, label: &str, spatial: bool) -> Result<()> {
        let mut names = run_object_names(&self.run_id, label, spatial)?;
        let database = names.pop().context("run has no database name")?;
        self.acquisitions
            .extend(names.into_iter().map(Acquisition::Role));
        self.acquisitions.push(Acquisition::Database(database));
        Ok(())
    }

    /// Names of the databases and roles this run still owns, oldest first.
    pub(super) fn pending_names(&self) -> Vec<String> {
        self.acquisitions
            .iter()
            .map(|acquisition| match acquisition {
                Acquisition::Database(name) | Acquisition::Role(name) => name.clone(),
            })
            .collect()
    }
}

/// Every database and role name `provision` can create for one label of a
/// run, in creation order. Recovery after a lost supervisor uses this list,
/// since the spatial bbox role does not carry the run id.
pub(super) fn run_object_names(run_id: &str, label: &str, spatial: bool) -> Result<Vec<String>> {
    validate_run_id(run_id)?;
    validate_label(label)?;
    let names = Names::new(run_id, label);
    let mut owned = vec![names.migration_role.clone(), names.runtime_role.clone()];
    if spatial {
        owned.push(spatial_bbox_role(&names));
    }
    owned.push(names.database);
    Ok(owned)
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

/// The statements one database run sends, taken from the shared provisioning
/// plan and grouped as they are executed: the access statements as one batch
/// on the administrator session, the setup statements as one batch inside the
/// new database, and the PostGIS statements as a second batch there. The login
/// roles are created from their password verifiers, which the plan keeps
/// private.
struct Batches {
    bbox_role: Option<String>,
    create_database: String,
    access: String,
    setup: String,
    postgis: Option<String>,
}

impl Batches {
    fn new(
        names: &Names,
        label: &str,
        breg: bool,
        requires_postgis: bool,
        migration_password: &str,
        runtime_password: &str,
    ) -> Result<Self> {
        let product = ProductDatabase {
            product: "rstack-dev",
            layout: if breg {
                SchemaLayout::Owned(
                    BREG_SCHEMAS
                        .iter()
                        .map(|schema| (*schema).to_owned())
                        .collect(),
                )
            } else if label == "coordinator" {
                SchemaLayout::CreatedByApply
            } else {
                SchemaLayout::PublicForMigration
            },
            btree_gist: breg,
            spatial: requires_postgis.then(|| Spatial {
                schema: POSTGIS_SCHEMA.to_owned(),
                bbox_role: spatial_bbox_role(names),
                minimum_postgis: MIN_POSTGIS,
            }),
        };
        let target = ProvisionTarget {
            database: names.database.clone(),
            migration: RoleCredential::new(&names.migration_role, migration_password),
            runtime: RoleCredential::new(&names.runtime_role, runtime_password),
        };
        let plan = plan(&product, &target).context("cannot plan the PostgreSQL provisioning")?;
        Self::from_plan(&plan)
    }

    fn from_plan(plan: &Plan) -> Result<Self> {
        let printable = |wanted: &dyn Fn(&str, Scope) -> bool| {
            plan.statements()
                .iter()
                .filter(|statement| wanted(statement.step, statement.scope))
                .map(|statement| statement.printable.clone())
                .collect::<Vec<_>>()
        };
        let one = |step: &str| {
            let mut found = printable(&|candidate, _| candidate == step);
            match (found.pop(), found.is_empty()) {
                (Some(statement), true) => Ok(statement),
                _ => Err(anyhow!(
                    "the provisioning plan has no single {step} statement"
                )),
            }
        };
        let postgis = printable(&|step, _| step == "extension.postgis");
        Ok(Self {
            bbox_role: printable(&|step, _| step == "role.spatial-bbox").pop(),
            create_database: one("database.create")?,
            access: printable(&|step, _| {
                step.starts_with("database.") && step != "database.create"
            })
            .join("; "),
            setup: printable(&|step, scope| {
                scope == Scope::Database && step != "extension.postgis"
            })
            .join("; "),
            postgis: postgis.into_iter().next(),
        })
    }
}

fn spatial_bbox_role(names: &Names) -> String {
    spatial_bbox_role_for(&names.runtime_role)
}

/// The no-login role BReg expects to own its spatial candidate views:
/// `<runtime>__spatial_bbox` when that fits PostgreSQL's 63-byte identifier
/// limit, else `breg_bbox_` and the first 16 hex digits of the SHA-256 of
/// `breg/spatial-bbox-role/v1:<runtime>`.
fn spatial_bbox_role_for(runtime_role: &str) -> String {
    let candidate = format!("{runtime_role}__spatial_bbox");
    if candidate.len() <= 63 {
        return candidate;
    }
    let digest = Sha256::digest(format!("breg/spatial-bbox-role/v1:{runtime_role}").as_bytes());
    let prefix: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("breg_bbox_{prefix}")
}

/// The schema BReg's generated spatial SQL reads PostGIS from.
const POSTGIS_SCHEMA: &str = "registry_spatial_ext";

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
    if matches!(
        label,
        "breg"
            | "breg_test"
            | "casework"
            | "messaging"
            | "scheduling"
            | "documents"
            | "coordinator"
            | "adapter"
    ) {
        Ok(())
    } else {
        bail!("the database label must identify a development PostgreSQL workload")
    }
}

fn admin_config(admin_url: &str) -> Result<(Config, Endpoint)> {
    let parsed = Url::parse(admin_url)
        .map_err(|_| anyhow!("the PostgreSQL admin URL is not a parseable URL"))?;
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
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "sslmode" => {
                if !matches!(value.as_ref(), "require" | "verify-ca" | "verify-full") {
                    bail!(
                        "the PostgreSQL admin URL sslmode must be require, verify-ca, or \
                         verify-full; the runner always uses verified TLS"
                    );
                }
            }
            "sslrootcert" => bail!(
                "the PostgreSQL admin URL must not set sslrootcert; set RSTACK_DEV_DATABASE_CA \
                 to a CA PEM file instead"
            ),
            "connect_timeout" | "application_name" => {}
            other => bail!("the PostgreSQL admin URL query parameter {other} is not supported"),
        }
    }

    // tokio-postgres does not parse verify-ca or verify-full, and the runner
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
    let mut config = Config::from_str(sanitized.as_str())
        .map_err(|_| anyhow!("the PostgreSQL admin URL has an invalid query parameter value"))?;
    config.keepalives_idle(KEEPALIVE_IDLE);
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

pub(super) fn random_password() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).context("cannot generate a PostgreSQL credential")?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_provision::sql::quote_literal;
    use std::{future::pending, time::Instant};

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
        for label in ["breg", "breg_test", "casework", "messaging"] {
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
    fn administrator_connection_attempt_has_a_deadline() {
        let runtime = Builder::new_current_thread().enable_time().build().unwrap();
        let started = Instant::now();
        let result: Result<()> = runtime.block_on(bounded_connection(
            pending::<std::result::Result<(), tokio_postgres::Error>>(),
            Duration::from_millis(20),
        ));
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));

        assert_eq!(
            runtime
                .block_on(bounded_connection(
                    async { Ok::<_, tokio_postgres::Error>(7_u8) },
                    Duration::from_secs(1),
                ))
                .unwrap(),
            7
        );
    }

    /// A loopback server that accepts one connection and never answers it, as a
    /// PostgreSQL server does whose TLS negotiation stalls. The thread ends when
    /// the client closes the connection.
    fn stalled_server() -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            std::io::copy(&mut stream, &mut std::io::sink()).unwrap();
        });
        (port, server)
    }

    /// The administrator configuration `Database::connect` builds for `port`.
    fn stalled_admin_config(port: u16) -> Config {
        let (mut config, _) = admin_config(&format!(
            "postgresql://admin:secret@127.0.0.1:{port}/postgres"
        ))
        .unwrap();
        config.ssl_mode(SslMode::Require);
        apply_session_options(&mut config);
        config
    }

    /// A TLS connector that trusts nothing; a stalled server never reaches TLS.
    fn untrusting_tls() -> MakeRustlsConnect {
        let _ = rustls::crypto::ring::default_provider().install_default();
        MakeRustlsConnect::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    #[test]
    fn a_stalled_server_cannot_hold_the_first_administrator_connection() {
        let (port, server) = stalled_server();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let started = Instant::now();

        let Err(error) = open_admin_session(
            &runtime,
            &stalled_admin_config(port),
            &untrusting_tls(),
            "SELECT 1",
            None,
            Instant::now() + Duration::from_millis(300),
        ) else {
            panic!("a server that never answers opened a session");
        };

        assert_eq!(
            format!("{error:#}"),
            "the PostgreSQL connection handshake timed out"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        // The abandoned attempt closed its connection.
        server.join().unwrap();
    }

    /// A plaintext server that completes one PostgreSQL startup without
    /// authentication, so a test can hold a real administrator `Client`.
    fn trusting_server() -> (u16, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut startup = vec![0_u8; u32::from_be_bytes(length) as usize - 4];
            stream.read_exact(&mut startup).unwrap();
            // AuthenticationOk, then ReadyForQuery while idle.
            stream
                .write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I")
                .unwrap();
            std::io::copy(&mut stream, &mut std::io::sink()).unwrap();
        });
        (port, server)
    }

    #[test]
    fn a_stalled_server_cannot_hold_the_cleanup_reconnection() {
        let (trusting_port, trusting) = trusting_server();
        let (stalled_port, stalled) = stalled_server();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let mut first = Config::new();
        first
            .host("127.0.0.1")
            .port(trusting_port)
            .user("admin")
            .dbname("postgres")
            .ssl_mode(SslMode::Disable);
        let (client, connection) = runtime
            .block_on(first.connect(tokio_postgres::NoTls))
            .unwrap();
        let connection_task = runtime.spawn(connection);
        // The first session failed mid-operation, so cleanup must reconnect
        // first, and the replacement server never answers.
        let mut database = Database {
            client,
            _connection_task: connection_task,
            admin_session_failed: true,
            tls: untrusting_tls(),
            admin_config: stalled_admin_config(stalled_port),
            ownership_lock: "SELECT 1".to_owned(),
            recovery_identity: RecoveryIdentity {
                system_identifier: 23,
                database: "postgres".to_owned(),
            },
            endpoint: Endpoint {
                host: UrlHost::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                port: Some(stalled_port),
            },
            run_id: RUN_ID.to_owned(),
            acquisitions: Vec::new(),
            runtime,
        };
        let started = Instant::now();

        let error = database
            .execute_cleanup(
                "DROP ROLE IF EXISTS rstack_stalled_role",
                Instant::now() + Duration::from_millis(300),
            )
            .unwrap_err();

        assert_eq!(
            format!("{error:#}"),
            "cannot reconnect to the PostgreSQL administrator database: \
             the PostgreSQL connection handshake timed out"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(database.admin_session_failed);
        stalled.join().unwrap();
        drop(database);
        trusting.join().unwrap();
    }

    #[test]
    fn post_handshake_operation_deadline_marks_the_effect_unconfirmed() {
        let runtime = Builder::new_current_thread().enable_time().build().unwrap();
        let started = Instant::now();
        let result: std::result::Result<(), OperationFailure> =
            runtime.block_on(bounded_operation(
                "role creation",
                pending::<std::result::Result<(), tokio_postgres::Error>>(),
                Duration::from_millis(20),
            ));
        let failure = result.unwrap_err();
        assert!(failure.effect_is_unconfirmed());
        assert_eq!(
            failure.to_string(),
            "the PostgreSQL role creation operation exceeded its I/O deadline"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn unconfirmed_create_retains_its_exact_acquisition_once() {
        let mut acquisitions = Vec::new();
        let created = Err::<(), _>(OperationFailure::IoDeadline {
            operation: "role creation",
        });
        retain_create_acquisition(
            &mut acquisitions,
            Acquisition::Role("rstack_exact_role".to_owned()),
            &created,
        );

        assert_eq!(acquisitions.len(), 1);
        assert!(matches!(
            &acquisitions[0],
            Acquisition::Role(role) if role == "rstack_exact_role"
        ));
    }

    #[test]
    fn confirmed_statement_cancellation_is_not_tracked_as_a_creation() {
        let mut acquisitions = Vec::new();
        let created = Err::<(), _>(OperationFailure::StatementDeadline {
            operation: "database creation",
        });
        retain_create_acquisition(
            &mut acquisitions,
            Acquisition::Database("rstack_refused_database".to_owned()),
            &created,
        );
        assert!(acquisitions.is_empty());
    }

    #[test]
    fn operation_deadlines_fit_the_worker_stop_budget() {
        let mut config = Config::new();
        config.options("-c application_name=rstack-dev");
        apply_session_options(&mut config);
        assert_eq!(
            config.get_options(),
            Some(
                "-c application_name=rstack-dev -c statement_timeout=10000 \
                 -c createrole_self_grant=set,inherit"
            )
        );
        let mut bare = Config::new();
        apply_session_options(&mut bare);
        assert_eq!(
            bare.get_options(),
            Some("-c statement_timeout=10000 -c createrole_self_grant=set,inherit")
        );
        assert!(STATEMENT_TIMEOUT < OPERATION_TIMEOUT);
        assert!(OPERATION_TIMEOUT < CLEANUP_ATTEMPT_TIMEOUT);
        assert!(CLEANUP_ATTEMPT_TIMEOUT < Duration::from_secs(60));
    }

    #[test]
    fn run_ownership_lock_uses_the_first_64_id_bits_as_a_session_key() {
        assert_eq!(
            ownership_lock_statement(RUN_ID).unwrap(),
            "SELECT pg_advisory_lock(81985529216486895)"
        );
        assert_eq!(
            ownership_lock_statement("fedcba98765432100123456789abcdef").unwrap(),
            "SELECT pg_advisory_lock(-81985529216486896)"
        );
        assert!(ownership_lock_statement("short").is_err());
    }

    #[test]
    fn recovery_refuses_a_different_postgresql_cluster() {
        let expected = RecoveryIdentity {
            system_identifier: 23,
            database: "postgres".to_owned(),
        };
        let actual = RecoveryIdentity {
            system_identifier: 42,
            database: "postgres".to_owned(),
        };
        let error = require_recovery_identity(&expected, &actual).unwrap_err();
        assert_eq!(
            error.to_string(),
            "this run belongs to a different PostgreSQL cluster; use the administrator URL from startup"
        );
    }

    #[test]
    fn recovery_refuses_a_different_administrator_database_in_the_same_cluster() {
        let expected = RecoveryIdentity {
            system_identifier: 23,
            database: "postgres".to_owned(),
        };
        let actual = RecoveryIdentity {
            system_identifier: 23,
            database: "template1".to_owned(),
        };
        let error = require_recovery_identity(&expected, &actual).unwrap_err();
        assert_eq!(
            error.to_string(),
            "this run belongs to a different PostgreSQL maintenance database; use the administrator URL from startup"
        );
    }

    #[test]
    fn recovery_accepts_the_original_postgresql_target() {
        let identity = RecoveryIdentity {
            system_identifier: 23,
            database: "postgres".to_owned(),
        };
        require_recovery_identity(&identity, &identity).unwrap();
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
    fn admin_url_query_keys_and_ssl_modes_are_checked_by_name() {
        let password = random_password().unwrap();
        let base = format!(
            "postgresql://admin:{}@db.example/postgres",
            password.as_str()
        );
        for accepted in [
            "sslmode=require",
            "sslmode=verify-ca",
            "sslmode=verify-full",
            "connect_timeout=5",
            "application_name=rstack",
        ] {
            assert!(
                admin_config(&format!("{base}?{accepted}")).is_ok(),
                "{accepted}"
            );
        }
        for (query, expected) in [
            ("sslmode=disable", "always uses verified TLS"),
            ("sslmode=allow", "always uses verified TLS"),
            ("sslmode=prefer", "always uses verified TLS"),
            ("sslrootcert=/tmp/ca.pem", "RSTACK_DEV_DATABASE_CA"),
            (
                "options=-csearch_path%3Dx",
                "query parameter options is not supported",
            ),
            (
                "channel_binding=require",
                "query parameter channel_binding is not supported",
            ),
        ] {
            let message = admin_config(&format!("{base}?{query}"))
                .err()
                .unwrap_or_else(|| panic!("accepted {query}"))
                .to_string();
            assert!(message.contains(expected), "{query}: {message}");
            assert!(
                !message.contains(password.as_str()),
                "{query} leaked the URL"
            );
        }
        let unparseable = admin_config("not a url").err().unwrap().to_string();
        assert!(unparseable.contains("not a parseable URL"), "{unparseable}");
        let bad_value = admin_config(&format!("{base}?connect_timeout=soon"))
            .err()
            .unwrap()
            .to_string();
        assert!(
            bad_value.contains("invalid query parameter value"),
            "{bad_value}"
        );
        assert!(!bad_value.contains(password.as_str()));
    }

    #[test]
    fn admin_config_keeps_idle_connections_alive() {
        let (config, _) = admin_config("postgresql://admin:secret@db.example/postgres").unwrap();
        assert_eq!(config.get_keepalives_idle(), Duration::from_secs(30));
    }

    #[test]
    fn spatial_runs_are_refused_without_a_supported_postgis() {
        assert!(require_postgis(Some("3.5.2")).is_ok());
        assert!(require_postgis(Some("3.5")).is_ok());
        assert!(require_postgis(Some("3.10.0")).is_ok());
        assert!(require_postgis(Some("4.0.0")).is_ok());
        let missing = require_postgis(None).unwrap_err().to_string();
        assert!(
            missing.starts_with(
                "spatial BReg needs PostGIS 3.5 or later installed on the PostgreSQL server"
            ),
            "{missing}"
        );
        for old in ["3.4.9", "2.5.5", "garbage", ""] {
            let message = require_postgis(Some(old)).unwrap_err().to_string();
            assert!(message.contains("PostGIS 3.5 or later"), "{old}: {message}");
            assert!(message.contains(&format!("offers {old}")), "{message}");
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
    fn spatial_breg_uses_the_governed_bbox_role_for_its_runtime() {
        for label in ["breg_test", "breg"] {
            let names = Names::new(RUN_ID, label);
            let expected = spatial_bbox_role_for(&names.runtime_role);
            assert_eq!(spatial_bbox_role(&names), expected);
            assert!(expected.starts_with("breg_bbox_"));
            assert!(expected.len() <= 63);
            let batches = Batches::new(
                &names,
                "breg",
                true,
                true,
                "migration-secret",
                "runtime-secret",
            )
            .unwrap();
            let statement = batches.bbox_role.unwrap();
            assert_eq!(
                statement,
                format!(
                    "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
                    quote_identifier(&expected)
                )
            );
            assert!(!statement.contains("PASSWORD"));
        }
    }

    /// Vectors for BReg's `spatial_bbox_role`, which names the role BReg
    /// checks for at startup. The run-shaped vector is the name BReg looked up
    /// on a PostgreSQL server for that runtime role.
    #[test]
    fn spatial_bbox_role_matches_breg() {
        assert_eq!(
            spatial_bbox_role_for("abc_runtime"),
            "abc_runtime__spatial_bbox"
        );
        let at_the_limit = "r".repeat(49);
        assert_eq!(
            spatial_bbox_role_for(&at_the_limit),
            format!("{at_the_limit}__spatial_bbox")
        );
        assert_eq!(
            spatial_bbox_role_for(&"r".repeat(60)),
            "breg_bbox_254fe84b299dbd51"
        );
        assert_eq!(
            spatial_bbox_role_for("rstack_9e563cecd9554dcca89e0615844796bd_breg_test_runtime"),
            "breg_bbox_a49e726b4d6452da"
        );
    }

    #[test]
    fn run_object_names_list_every_name_provision_creates() {
        for (label, spatial) in [
            ("breg", true),
            ("breg_test", false),
            ("casework", false),
            ("messaging", false),
        ] {
            let names = Names::new(RUN_ID, label);
            let mut expected = vec![names.migration_role.clone(), names.runtime_role.clone()];
            if spatial {
                let bbox = spatial_bbox_role(&names);
                assert!(!bbox.contains(RUN_ID), "the bbox role is not run-scoped");
                expected.push(bbox);
            }
            expected.push(names.database.clone());
            assert_eq!(run_object_names(RUN_ID, label, spatial).unwrap(), expected);
        }
        assert!(run_object_names("not-a-run", "breg", false).is_err());
        assert!(run_object_names(RUN_ID, "other", false).is_err());
    }

    #[test]
    fn coordinator_apply_can_create_its_own_schema() {
        let names = Names::new(RUN_ID, "coordinator");
        let batches = Batches::new(
            &names,
            "coordinator",
            false,
            false,
            "migration-secret",
            "runtime-secret",
        )
        .unwrap();
        let grant = registry_platform_provision::sql::grant_create_sql(
            &names.database,
            &names.migration_role,
        );
        assert!(batches.access.contains(&grant));
        assert!(!batches
            .access
            .contains(&registry_platform_provision::sql::grant_create_sql(
                &names.database,
                &names.runtime_role
            )));
    }

    /// The statements `rstack dev` issued before it used the shared plan,
    /// written out as text. The shared plan must keep rendering exactly this
    /// for the same input.
    #[test]
    fn shared_plan_renders_the_statements_rstack_dev_has_always_issued() {
        for (label, breg, postgis) in [
            ("breg", true, false),
            ("breg", true, true),
            ("casework", false, false),
            ("messaging", false, false),
        ] {
            let names = Names::new(RUN_ID, label);
            let batches = Batches::new(
                &names,
                label,
                breg,
                postgis,
                "migration-secret",
                "runtime-secret",
            )
            .unwrap();
            let (database, migration, runtime) = (
                quote_identifier(&names.database),
                quote_identifier(&names.migration_role),
                quote_identifier(&names.runtime_role),
            );
            assert_eq!(
                batches.create_database,
                format!("CREATE DATABASE {database} WITH ALLOW_CONNECTIONS false"),
                "{label}"
            );
            assert_eq!(
                batches.access,
                format!(
                    "REVOKE ALL ON DATABASE {database} FROM PUBLIC; \
                     GRANT CONNECT ON DATABASE {database} TO {migration}, {runtime}; \
                     ALTER DATABASE {database} ALLOW_CONNECTIONS true"
                ),
                "{label}"
            );
            let expected_setup = if breg {
                let schemas = BREG_SCHEMAS
                    .iter()
                    .map(|schema| {
                        format!(
                            "CREATE SCHEMA \"{schema}\" AUTHORIZATION {migration}; \
                             REVOKE ALL ON SCHEMA \"{schema}\" FROM PUBLIC"
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                format!("CREATE EXTENSION btree_gist; {schemas}")
            } else {
                format!(
                    "REVOKE CREATE ON SCHEMA public FROM PUBLIC; \
                     GRANT USAGE, CREATE ON SCHEMA public TO {migration}; \
                     GRANT USAGE ON SCHEMA public TO {runtime}"
                )
            };
            assert_eq!(batches.setup, expected_setup, "{label}");
            if postgis {
                let bbox_role = spatial_bbox_role(&names);
                let bbox = quote_identifier(&bbox_role);
                assert_eq!(
                    batches.bbox_role.as_deref(),
                    Some(
                        format!(
                            "CREATE ROLE {bbox} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                             NOINHERIT NOBYPASSRLS"
                        )
                        .as_str()
                    )
                );
                assert_eq!(
                    batches.postgis.as_deref(),
                    Some(
                        format!(
                            "CREATE SCHEMA IF NOT EXISTS registry_spatial_ext;\n\
                             REVOKE ALL ON SCHEMA registry_spatial_ext FROM PUBLIC;\n\
                             CREATE EXTENSION IF NOT EXISTS postgis WITH SCHEMA registry_spatial_ext;\n\
                             GRANT USAGE ON SCHEMA registry_spatial_ext TO {migration}, {runtime};\n\
                             GRANT {bbox} TO {migration} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;\n\
                             GRANT USAGE ON SCHEMA registry_spatial_ext TO {bbox};"
                        )
                        .as_str()
                    )
                );
            } else {
                assert!(
                    batches.bbox_role.is_none() && batches.postgis.is_none(),
                    "{label}"
                );
            }
        }
    }

    #[test]
    fn casework_setup_gives_the_runtime_role_usage_on_public_and_only_the_migration_role_creation()
    {
        let names = Names::new(RUN_ID, "casework");
        let sql = Batches::new(
            &names,
            "casework",
            false,
            false,
            "migration-secret",
            "runtime-secret",
        )
        .unwrap()
        .setup;
        assert!(
            sql.starts_with("REVOKE CREATE ON SCHEMA public FROM PUBLIC;"),
            "{sql}"
        );
        assert!(sql.contains(&format!(
            "GRANT USAGE, CREATE ON SCHEMA public TO {}",
            quote_identifier(&names.migration_role)
        )));
        assert!(sql.ends_with(&format!(
            "GRANT USAGE ON SCHEMA public TO {}",
            quote_identifier(&names.runtime_role)
        )));
        assert_eq!(sql.matches(&names.runtime_role).count(), 1, "{sql}");
    }

    #[test]
    fn messaging_setup_gives_the_runtime_role_no_public_schema_creation() {
        let names = Names::new(RUN_ID, "messaging");
        let sql = Batches::new(
            &names,
            "messaging",
            false,
            false,
            "migration-secret",
            "runtime-secret",
        )
        .unwrap()
        .setup;
        assert!(
            sql.starts_with("REVOKE CREATE ON SCHEMA public FROM PUBLIC;"),
            "{sql}"
        );
        assert!(!sql.contains(&format!(
            "CREATE ON SCHEMA public TO {}",
            quote_identifier(&names.runtime_role)
        )));
        assert_eq!(
            names.database,
            format!("rstack_{RUN_ID}_messaging"),
            "the messaging database is run-scoped"
        );
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
        let sql = registry_platform_provision::sql::create_role_sql("rstack_role", &verifier);
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

/// Cleanup against a real server. `RSTACK_DEV_TEST_DATABASE_URL` names a
/// disposable PostgreSQL superuser over TLS and `RSTACK_DEV_TEST_DATABASE_CA`
/// its CA PEM file. Each test creates its own least-privilege owner, which
/// holds only CREATEROLE and CREATEDB, like the administrator a developer
/// gives `rstack dev`.
#[cfg(all(test, feature = "postgres-test"))]
mod postgres_tests {
    use super::*;
    use registry_platform_provision::sql::quote_literal;
    use std::{sync::mpsc, thread};

    struct Server {
        runtime: Runtime,
        client: Client,
        _connection: AdminConnectionTask,
        url: Url,
        ca: Vec<u8>,
        suffix: String,
        owner_password: Zeroizing<String>,
        foreign_password: Zeroizing<String>,
    }

    impl Server {
        fn start() -> Self {
            let url = std::env::var("RSTACK_DEV_TEST_DATABASE_URL")
                .expect("the postgres-test feature needs RSTACK_DEV_TEST_DATABASE_URL");
            let ca_file = std::env::var_os("RSTACK_DEV_TEST_DATABASE_CA")
                .expect("the postgres-test feature needs RSTACK_DEV_TEST_DATABASE_CA");
            let ca = std::fs::read(ca_file).unwrap();
            let (mut config, _) = admin_config(&url).unwrap();
            config.ssl_mode(SslMode::Require);
            let runtime = Builder::new_current_thread().enable_all().build().unwrap();
            let (client, connection) = runtime
                .block_on(config.connect(tls_connector(Some(&ca)).unwrap()))
                .unwrap();
            let connection = runtime.spawn(connection);
            let mut suffix = [0_u8; 6];
            getrandom::fill(&mut suffix).unwrap();
            let server = Self {
                runtime,
                client,
                _connection: connection,
                url: Url::parse(&url).unwrap(),
                ca,
                suffix: suffix.iter().map(|byte| format!("{byte:02x}")).collect(),
                owner_password: random_password().unwrap(),
                foreign_password: random_password().unwrap(),
            };
            server.execute(&format!(
                "CREATE ROLE {} LOGIN CREATEROLE CREATEDB PASSWORD {}; \
                 CREATE ROLE {} LOGIN PASSWORD {}",
                quote_identifier(&server.owner()),
                quote_literal(&server.owner_password),
                quote_identifier(&server.foreign()),
                quote_literal(&server.foreign_password),
            ));
            server
        }

        fn owner(&self) -> String {
            format!("rstack_test_owner_{}", self.suffix)
        }

        /// A login role the owner neither created nor holds, so the owner
        /// may not signal its sessions.
        fn foreign(&self) -> String {
            format!("rstack_test_foreign_{}", self.suffix)
        }

        fn execute(&self, statement: &str) {
            self.runtime
                .block_on(self.client.batch_execute(statement))
                .unwrap();
        }

        fn exists(&self, catalog_query: &str, name: &str) -> bool {
            self.runtime
                .block_on(self.client.query_opt(catalog_query, &[&name]))
                .unwrap()
                .is_some()
        }

        fn url_as(&self, user: &str, password: &str, database: &str) -> String {
            let mut url = self.url.clone();
            url.set_username(user).unwrap();
            url.set_password(Some(password)).unwrap();
            url.set_path(&format!("/{database}"));
            url.into()
        }

        /// Connects the owner as `rstack dev` does and provisions one
        /// database the foreign role may also enter.
        fn provision(&self, run_id: &str) -> (Database, String) {
            let owner_url = self.url_as(&self.owner(), &self.owner_password, "postgres");
            let mut database = Database::connect(&owner_url, Some(&self.ca), run_id).unwrap();
            database.provision("breg_test", false, false).unwrap();
            let name = Names::new(run_id, "breg_test").database;
            self.execute(&format!(
                "GRANT CONNECT ON DATABASE {} TO {}",
                quote_identifier(&name),
                quote_identifier(&self.foreign()),
            ));
            (database, name)
        }

        /// Opens a session to `database` as the foreign role on its own
        /// thread, and closes it when `release` fires or is dropped.
        fn foreign_session(&self, database: &str) -> (mpsc::Sender<()>, thread::JoinHandle<()>) {
            let (mut config, _) =
                admin_config(&self.url_as(&self.foreign(), &self.foreign_password, database))
                    .unwrap();
            config.ssl_mode(SslMode::Require);
            let tls = tls_connector(Some(&self.ca)).unwrap();
            let (opened, ready) = mpsc::channel();
            let (release, released) = mpsc::channel::<()>();
            let session = thread::spawn(move || {
                let runtime = Builder::new_current_thread().enable_all().build().unwrap();
                runtime.block_on(async {
                    let (client, connection) = config.connect(tls).await.unwrap();
                    let connection = tokio::spawn(connection);
                    client.batch_execute("SELECT 1").await.unwrap();
                    opened.send(()).unwrap();
                    tokio::task::spawn_blocking(move || {
                        let _ = released.recv();
                    })
                    .await
                    .unwrap();
                    drop(client);
                    let _ = connection.await;
                });
            });
            ready.recv().expect("the foreign session opened");
            (release, session)
        }

        fn run_id() -> String {
            let mut bytes = [0_u8; 16];
            getrandom::fill(&mut bytes).unwrap();
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let leftovers = self.runtime.block_on(self.client.query(
                "SELECT datname FROM pg_database WHERE datname LIKE 'rstack\\_%' \
                 AND has_database_privilege($1, oid, 'CONNECT')",
                &[&self.foreign()],
            ));
            let mut statements = Vec::new();
            for row in leftovers.into_iter().flatten() {
                let name: String = row.get(0);
                statements.push(format!(
                    "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                    quote_identifier(&name)
                ));
            }
            let created = self.runtime.block_on(self.client.query(
                "SELECT r.rolname FROM pg_auth_members m \
                   JOIN pg_roles r ON r.oid = m.roleid \
                   JOIN pg_roles o ON o.oid = m.member \
                  WHERE o.rolname = $1 AND r.rolname LIKE 'rstack\\_%'",
                &[&self.owner()],
            ));
            for row in created.into_iter().flatten() {
                let name: String = row.get(0);
                statements.push(format!("DROP ROLE IF EXISTS {}", quote_identifier(&name)));
            }
            for role in [self.owner(), self.foreign()] {
                statements.push(format!("DROP ROLE IF EXISTS {}", quote_identifier(&role)));
            }
            // One statement at a time: DROP DATABASE refuses to run inside
            // the implicit transaction of a multi-statement batch.
            for statement in statements {
                let _ = self.runtime.block_on(self.client.batch_execute(&statement));
            }
        }
    }

    const DATABASE_EXISTS: &str = "SELECT 1 FROM pg_database WHERE datname = $1";
    const ROLE_EXISTS: &str = "SELECT 1 FROM pg_roles WHERE rolname = $1";

    #[test]
    fn cleanup_outlasts_a_session_it_may_not_signal() {
        let server = Server::start();
        let run_id = Server::run_id();
        let (mut database, name) = server.provision(&run_id);
        let (release, session) = server.foreign_session(&name);
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_secs(1));
            drop(release);
        });

        database
            .cleanup()
            .expect("cleanup waits out the foreign session");

        releaser.join().unwrap();
        session.join().unwrap();
        assert!(database.pending_names().is_empty());
        assert!(!server.exists(DATABASE_EXISTS, &name));
        let names = Names::new(&run_id, "breg_test");
        for role in [names.migration_role, names.runtime_role] {
            assert!(!server.exists(ROLE_EXISTS, &role), "{role} was dropped");
        }
    }

    #[test]
    fn cleanup_names_the_backends_it_could_not_outlast() {
        let server = Server::start();
        let run_id = Server::run_id();
        let (mut database, name) = server.provision(&run_id);
        let (release, session) = server.foreign_session(&name);
        let started = Instant::now();

        let error = database
            .cleanup_until(Instant::now() + Duration::from_secs(3))
            .unwrap_err();

        let elapsed = started.elapsed();
        let message = format!("{error:#}");
        assert!(
            elapsed >= Duration::from_secs(2),
            "cleanup retried until its deadline, not {elapsed:?}: {message}"
        );
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        assert!(
            message.starts_with("PostgreSQL cleanup is incomplete for 3 resource(s): database: "),
            "{message}"
        );
        assert!(
            message.contains("permission denied to terminate process"),
            "{message}"
        );
        assert!(
            message.contains(
                "backends still using the database, by type: \
                 session of a role this administrator does not hold (1): "
            ),
            "{message}"
        );
        assert!(!message.contains(&server.foreign()), "{message}");
        assert_eq!(
            database.pending_names(),
            run_object_names(&run_id, "breg_test", false).unwrap(),
            "the run keeps every resource it could not release"
        );
        assert!(server.exists(DATABASE_EXISTS, &name));

        drop(release);
        session.join().unwrap();
        database
            .cleanup()
            .expect("a later attempt releases the retained resources");
        assert!(database.pending_names().is_empty());
        assert!(!server.exists(DATABASE_EXISTS, &name));
    }
}
