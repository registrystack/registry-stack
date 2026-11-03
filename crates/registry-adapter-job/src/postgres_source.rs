// SPDX-License-Identifier: Apache-2.0

//! The job host's read-only PostgreSQL source client. The engine owns the
//! reviewed query, typed parameters, transaction preamble, and page bounds;
//! this module resolves one source credential, builds one finite dedicated
//! pool, executes the read in a cancellation-safe read-only transaction, and
//! returns only the engine's closed scalar row form.

use std::collections::BTreeMap;
use std::fmt;
#[cfg(feature = "postgres-test")]
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use futures::StreamExt as _;
use registry_adapter_core::{AdapterEndpointBindings, OutboundTls, TrustProfile};
use registry_adapter_engine::component::postgres::{
    PostgresRead, PostgresReadFault, PostgresRowBudget, PostgresRows, PostgresSource, SourceRow,
    SourceScalar,
};
use registry_adapter_engine::job::JobProgram;
use registry_adapter_engine::job_sources::{PostgresSourceBinding, PostgresSourceTls};
use registry_platform_config::SecretResolver;
use registry_platform_yaml::{LocalId, UniqueIdList, UniqueList};
use tokio_postgres::types::{IsNull, ToSql, Type};

use crate::store;

const MAXIMUM_SOURCE_CONNECTIONS: usize = 2;

/// Resolve and register every compiled PostgreSQL source before the first
/// page. Pool construction is eager and value-free; physical connections are
/// still opened lazily by the first read.
pub fn activate_postgres_sources(
    program: &mut JobProgram,
    resolver: &SecretResolver,
) -> Result<(), String> {
    let bindings = program
        .postgres_source_bindings()
        .cloned()
        .collect::<Vec<_>>();
    for binding in bindings {
        let endpoint = binding.endpoint.clone();
        let source = Arc::new(PooledPostgresSource::build(binding, resolver)?);
        program
            .register_postgres_source(&endpoint, source)
            .map_err(|_| "the PostgreSQL source client could not be registered".to_string())?;
    }
    Ok(())
}

struct PooledPostgresSource {
    pool: Pool,
    cancellation: PostgresCancellation,
}

#[derive(Clone)]
enum PostgresCancellation {
    Tls(tokio_postgres_rustls::MakeRustlsConnect),
    #[cfg(feature = "postgres-test")]
    Plaintext,
}

#[cfg(test)]
#[derive(Clone)]
struct CancellationTestBarrier {
    before_send: Arc<tokio::sync::Notify>,
    release_send: Arc<tokio::sync::Notify>,
    after_send: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
static CANCELLATION_TEST_BARRIER: std::sync::Mutex<Option<CancellationTestBarrier>> =
    std::sync::Mutex::new(None);

impl PostgresCancellation {
    async fn request(
        self,
        token: tokio_postgres::CancelToken,
    ) -> Result<(), tokio_postgres::Error> {
        match self {
            Self::Tls(tls) => token.cancel_query(tls).await,
            #[cfg(feature = "postgres-test")]
            Self::Plaintext => token.cancel_query(tokio_postgres::NoTls).await,
        }
    }
}

struct CancelReadOnDrop {
    client: Option<deadpool_postgres::Object>,
    token: Option<tokio_postgres::CancelToken>,
    transport: PostgresCancellation,
    runtime: tokio::runtime::Handle,
}

impl CancelReadOnDrop {
    fn new(
        client: deadpool_postgres::Object,
        token: tokio_postgres::CancelToken,
        transport: PostgresCancellation,
    ) -> Self {
        Self {
            client: Some(client),
            token: Some(token),
            transport,
            runtime: tokio::runtime::Handle::current(),
        }
    }

    fn client_mut(&mut self) -> &mut deadpool_postgres::Object {
        self.client
            .as_mut()
            .expect("the armed cancellation guard owns its pooled client")
    }

    fn disarm(&mut self) {
        self.token = None;
    }
}

impl Drop for CancelReadOnDrop {
    fn drop(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let client = self
            .client
            .take()
            .expect("the armed cancellation guard owns its pooled client");
        // A PostgreSQL cancel token identifies a backend, not a particular
        // query generation. Remove and close this client before sending the
        // out-of-band request, so a delayed request can never reach a later
        // borrower on the same backend. The pool replaces the detached slot.
        drop(deadpool_postgres::Object::take(client));
        let transport = self.transport.clone();
        #[cfg(test)]
        let barrier = CANCELLATION_TEST_BARRIER
            .lock()
            .expect("the cancellation test barrier lock is available")
            .clone();
        self.runtime.spawn(async move {
            #[cfg(test)]
            if let Some(barrier) = &barrier {
                barrier.before_send.notify_one();
                barrier.release_send.notified().await;
            }
            let cancellation =
                tokio::time::timeout(Duration::from_secs(5), transport.request(token)).await;
            #[cfg(test)]
            if let Some(barrier) = &barrier {
                barrier.after_send.notify_one();
            }
            if !matches!(cancellation, Ok(Ok(()))) {
                tracing::warn!("a PostgreSQL source cancellation request could not be sent");
            }
        });
    }
}

impl fmt::Debug for PooledPostgresSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PooledPostgresSource")
            .finish_non_exhaustive()
    }
}

impl PooledPostgresSource {
    fn build(binding: PostgresSourceBinding, resolver: &SecretResolver) -> Result<Self, String> {
        let invalid = || "the PostgreSQL source connection was refused".to_string();
        let password = resolver
            .resolve(binding.password_ref.as_str())
            .map_err(|_| invalid())?;
        let mut postgres = tokio_postgres::Config::new();
        postgres
            .host(&binding.host)
            .port(binding.port)
            .dbname(&binding.database)
            .user(&binding.user)
            .password(password.expose_secret());
        let (pool, cancellation) = match binding.tls {
            PostgresSourceTls::SystemRoots => {
                postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
                let tls = store::native_postgres_tls().map_err(|_| invalid())?;
                (
                    store::build_verified_pool(postgres, tls.clone(), MAXIMUM_SOURCE_CONNECTIONS),
                    PostgresCancellation::Tls(tls),
                )
            }
            PostgresSourceTls::CaBundle { ca_bundle_file } => {
                postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
                let ca = capture_ca_bundle(&ca_bundle_file)?;
                let tls = store::postgres_tls_from_native_and_pem(ca.as_bytes())
                    .map_err(|_| invalid())?;
                (
                    store::build_verified_pool(postgres, tls.clone(), MAXIMUM_SOURCE_CONNECTIONS),
                    PostgresCancellation::Tls(tls),
                )
            }
            #[cfg(feature = "postgres-test")]
            PostgresSourceTls::Plaintext => {
                let loopback = binding
                    .host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
                if !loopback {
                    return Err(
                        "the plaintext PostgreSQL test source is not numeric loopback".to_string(),
                    );
                }
                postgres.ssl_mode(tokio_postgres::config::SslMode::Disable);
                (
                    store::build_verified_pool(
                        postgres,
                        tokio_postgres::NoTls,
                        MAXIMUM_SOURCE_CONNECTIONS,
                    ),
                    PostgresCancellation::Plaintext,
                )
            }
        };
        let pool = pool.map_err(|_| invalid())?;
        Ok(Self { pool, cancellation })
    }
}

impl PostgresSource for PooledPostgresSource {
    fn read<'a>(
        &'a self,
        read: PostgresRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<PostgresRows, PostgresReadFault>> + Send + 'a>,
    > {
        Box::pin(async move {
            validate_preamble(&read.statements)?;
            let client = self
                .pool
                .get()
                .await
                .map_err(|_| PostgresReadFault::Connection)?;
            let token = client.cancel_token();
            let mut cancellation = CancelReadOnDrop::new(client, token, self.cancellation.clone());
            let result = async {
                // Use the driver's transaction guard rather than a bare BEGIN.
                // Dropping a page future queues rollback, detaches and closes
                // this connection, then requests server cancellation. The pool
                // creates a fresh backend; only completed reads recycle theirs.
                let transaction = cancellation
                    .client_mut()
                    .build_transaction()
                    .read_only(true)
                    .start()
                    .await
                    .map_err(statement_fault)?;
                transaction
                    .batch_execute(&read.statements[1])
                    .await
                    .map_err(statement_fault)?;
                let outcome = fetch_rows(&transaction, &read).await;
                let rollback = transaction.rollback().await;
                match (outcome, rollback) {
                    (Ok(rows), Ok(())) => Ok(rows),
                    (Err(fault), _) => Err(fault),
                    (Ok(_), Err(error)) => Err(statement_fault(error)),
                }
            }
            .await;
            cancellation.disarm();
            result
        })
    }
}

fn validate_preamble(statements: &[String]) -> Result<(), PostgresReadFault> {
    let [begin, timeout] = statements else {
        return Err(PostgresReadFault::Statement);
    };
    if begin != "BEGIN TRANSACTION READ ONLY" {
        return Err(PostgresReadFault::Statement);
    }
    let Some(milliseconds) = timeout.strip_prefix("SET LOCAL statement_timeout = ") else {
        return Err(PostgresReadFault::Statement);
    };
    let milliseconds = milliseconds
        .parse::<u64>()
        .map_err(|_| PostgresReadFault::Statement)?;
    if !(1..=10_000).contains(&milliseconds) {
        return Err(PostgresReadFault::Statement);
    }
    Ok(())
}

async fn fetch_rows(
    transaction: &tokio_postgres::Transaction<'_>,
    read: &PostgresRead,
) -> Result<PostgresRows, PostgresReadFault> {
    let parameters = read
        .parameters
        .iter()
        .map(NativeParameter::from_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let stream = transaction
        .query_raw(&read.sql, parameters.iter())
        .await
        .map_err(statement_fault)?;
    futures::pin_mut!(stream);
    let mut rows = Vec::with_capacity(read.maximum_rows as usize);
    let mut budget = PostgresRowBudget::new(read.maximum_rows, read.bounds)?;
    let mut complete = true;
    while let Some(row) = stream.next().await {
        let row = row.map_err(statement_fault)?;
        if rows.len() == read.maximum_rows as usize {
            complete = false;
            break;
        }
        let row = source_row(&row, &budget)?;
        budget.admit(&row)?;
        rows.push(row);
    }
    Ok(PostgresRows { rows, complete })
}

fn source_row(
    row: &tokio_postgres::Row,
    budget: &PostgresRowBudget,
) -> Result<SourceRow, PostgresReadFault> {
    let mut columns = Vec::with_capacity(row.len());
    for (index, column) in row.columns().iter().enumerate() {
        budget.check_field(column.name())?;
        let scalar = match *column.type_() {
            Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
                let value = row
                    .try_get::<_, &str>(index)
                    .map_err(|_| PostgresReadFault::Statement)?;
                budget.check_field(value)?;
                SourceScalar::Text(value.to_owned())
            }
            Type::INT8 => SourceScalar::Integer(
                row.try_get(index)
                    .map_err(|_| PostgresReadFault::Statement)?,
            ),
            Type::INT4 => SourceScalar::Integer(i64::from(
                row.try_get::<_, i32>(index)
                    .map_err(|_| PostgresReadFault::Statement)?,
            )),
            Type::INT2 => SourceScalar::Integer(i64::from(
                row.try_get::<_, i16>(index)
                    .map_err(|_| PostgresReadFault::Statement)?,
            )),
            Type::FLOAT8 => {
                let value = row
                    .try_get::<_, f64>(index)
                    .map_err(|_| PostgresReadFault::Statement)?;
                if !value.is_finite() {
                    return Err(PostgresReadFault::Malformed);
                }
                SourceScalar::Float(value)
            }
            Type::FLOAT4 => {
                let value = row
                    .try_get::<_, f32>(index)
                    .map_err(|_| PostgresReadFault::Statement)?;
                if !value.is_finite() {
                    return Err(PostgresReadFault::Malformed);
                }
                SourceScalar::Float(f64::from(value))
            }
            Type::BOOL => SourceScalar::Boolean(
                row.try_get(index)
                    .map_err(|_| PostgresReadFault::Statement)?,
            ),
            _ => return Err(PostgresReadFault::Statement),
        };
        columns.push((column.name().to_owned(), scalar));
    }
    Ok(SourceRow { columns })
}

fn statement_fault(error: tokio_postgres::Error) -> PostgresReadFault {
    if error.code() == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED) {
        PostgresReadFault::Timeout
    } else {
        PostgresReadFault::Statement
    }
}

enum NativeParameter {
    Text(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
}

impl NativeParameter {
    fn from_scalar(value: &SourceScalar) -> Result<Self, PostgresReadFault> {
        match value {
            SourceScalar::Text(value) => Ok(Self::Text(value.clone())),
            SourceScalar::Integer(value) => Ok(Self::Integer(*value)),
            SourceScalar::Float(value) => Ok(Self::Float(*value)),
            SourceScalar::Boolean(value) => Ok(Self::Boolean(*value)),
            // The engine currently emits Numeric only for a host-returned
            // value. Refuse rather than invent an imprecise binary encoding
            // if it ever crosses into a parameter.
            SourceScalar::Numeric(_) => Err(PostgresReadFault::Statement),
        }
    }
}

impl fmt::Debug for NativeParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeParameter(..)")
    }
}

impl ToSql for NativeParameter {
    fn to_sql(
        &self,
        ty: &Type,
        output: &mut tokio_postgres::types::private::BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match (self, ty) {
            (Self::Text(value), &Type::TEXT | &Type::VARCHAR | &Type::BPCHAR | &Type::NAME) => {
                value.to_sql(ty, output)
            }
            (Self::Integer(value), &Type::INT8) => value.to_sql(ty, output),
            (Self::Integer(value), &Type::INT4) => i32::try_from(*value)
                .map_err(|_| parameter_type_error())?
                .to_sql(ty, output),
            (Self::Integer(value), &Type::INT2) => i16::try_from(*value)
                .map_err(|_| parameter_type_error())?
                .to_sql(ty, output),
            (Self::Float(value), &Type::FLOAT8) => value.to_sql(ty, output),
            (Self::Boolean(value), &Type::BOOL) => value.to_sql(ty, output),
            _ => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the PostgreSQL parameter type does not match its reviewed scalar",
            ))),
        }
    }

    fn accepts(ty: &Type) -> bool {
        matches!(
            ty,
            &Type::TEXT
                | &Type::VARCHAR
                | &Type::BPCHAR
                | &Type::NAME
                | &Type::INT2
                | &Type::INT4
                | &Type::INT8
                | &Type::FLOAT8
                | &Type::BOOL
        )
    }

    tokio_postgres::types::to_sql_checked!();
}

fn parameter_type_error() -> Box<dyn std::error::Error + Sync + Send> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "the PostgreSQL parameter value is outside its reviewed scalar type",
    ))
}

fn capture_ca_bundle(
    ca_bundle_file: &str,
) -> Result<registry_adapter_engine::auth::ProtectedText, String> {
    let profile = "postgres-source";
    let runtime = AdapterEndpointBindings {
        id: LocalId::new("postgres-source")
            .map_err(|_| "the PostgreSQL source TLS state was refused".to_string())?,
        endpoints: UniqueIdList::default(),
        outbound_tls: Some(OutboundTls {
            trust_profiles: BTreeMap::from([(
                profile.to_owned(),
                TrustProfile {
                    ca_bundle_file: ca_bundle_file.to_owned(),
                },
            )]),
        }),
        allowed_private_cidrs: UniqueList::default(),
    };
    registry_adapter_engine::auth::capture_ca_bundle(&runtime, profile)
        .map_err(|_| "the PostgreSQL source CA bundle was refused".to_string())
}

#[cfg(all(test, feature = "postgres-test"))]
mod tests {
    use std::str::FromStr as _;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use registry_adapter_engine::component::postgres::PostgresReadBounds;
    use tokio::time::{timeout, Instant};

    use super::*;

    static CANCELLATION_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn test_config(application_name: &str) -> tokio_postgres::Config {
        let database_url = std::env::var("ADAPTER_TEST_DATABASE_URL")
            .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
        let mut config = tokio_postgres::Config::from_str(&database_url)
            .expect("the disposable PostgreSQL URL parses");
        config
            .application_name(application_name)
            .ssl_mode(tokio_postgres::config::SslMode::Disable);
        config
    }

    #[cfg(feature = "postgres-tls-test")]
    fn tls_test_config(application_name: &str) -> tokio_postgres::Config {
        let host = std::env::var("ADAPTER_POSTGRES_TLS_TEST_HOST")
            .expect("ADAPTER_POSTGRES_TLS_TEST_HOST names the verified TLS fixture");
        let port = std::env::var("ADAPTER_POSTGRES_TLS_TEST_PORT")
            .expect("ADAPTER_POSTGRES_TLS_TEST_PORT names the verified TLS fixture")
            .parse::<u16>()
            .expect("the verified TLS fixture port is a u16");
        let database = std::env::var("ADAPTER_POSTGRES_TLS_TEST_DATABASE")
            .expect("ADAPTER_POSTGRES_TLS_TEST_DATABASE names the disposable database");
        let user = std::env::var("ADAPTER_POSTGRES_TLS_TEST_USER")
            .expect("ADAPTER_POSTGRES_TLS_TEST_USER names the disposable database role");
        let password = std::env::var("ADAPTER_POSTGRES_TLS_TEST_PASSWORD")
            .expect("ADAPTER_POSTGRES_TLS_TEST_PASSWORD holds the synthetic fixture credential");
        let mut config = tokio_postgres::Config::new();
        config
            .host(&host)
            .port(port)
            .dbname(&database)
            .user(&user)
            .password(password)
            .application_name(application_name)
            .ssl_mode(tokio_postgres::config::SslMode::Require);
        config
    }

    #[cfg(feature = "postgres-tls-test")]
    fn tls_test_connector() -> tokio_postgres_rustls::MakeRustlsConnect {
        let ca_bundle_file = std::env::var("ADAPTER_POSTGRES_TLS_TEST_CA_BUNDLE_FILE")
            .expect("ADAPTER_POSTGRES_TLS_TEST_CA_BUNDLE_FILE names the trusted fixture CA");
        let ca = capture_ca_bundle(&ca_bundle_file)
            .expect("the trusted fixture CA passes the production bundle bounds");
        store::postgres_tls_from_native_and_pem(ca.as_bytes())
            .expect("the trusted fixture CA builds the production TLS connector")
    }

    fn read(sql: String, statement_timeout_milliseconds: u64) -> PostgresRead {
        PostgresRead {
            statements: vec![
                "BEGIN TRANSACTION READ ONLY".to_owned(),
                format!("SET LOCAL statement_timeout = {statement_timeout_milliseconds}"),
            ],
            sql,
            parameters: Vec::new(),
            maximum_rows: 1,
            bounds: PostgresReadBounds {
                maximum_response_bytes: 4_096,
                maximum_row_bytes: 2_048,
                maximum_field_bytes: 256,
            },
        }
    }

    async fn active_backend_pid(
        observer: &tokio_postgres::Client,
        application_name: &str,
        query_pattern: &str,
    ) -> i64 {
        timeout(Duration::from_secs(5), async {
            let mut poll = tokio::time::interval_at(Instant::now(), Duration::from_millis(10));
            loop {
                poll.tick().await;
                let active = observer
                    .query_opt(
                        "SELECT pid::bigint FROM pg_stat_activity \
                         WHERE application_name = $1 AND state = 'active' AND query LIKE $2",
                        &[&application_name, &query_pattern],
                    )
                    .await
                    .expect("inspect the active source read");
                if let Some(active) = active {
                    break active.get::<_, i64>(0);
                }
            }
        })
        .await
        .expect("the source read becomes active before its bound")
    }

    async fn assert_cancelled_read_is_detached_before_same_pool_creates_fresh_backend(
        source: Arc<PooledPostgresSource>,
        observer: &tokio_postgres::Client,
        application_name: &str,
        schema: &str,
        expected_tls: bool,
    ) {
        observer
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; CREATE TABLE {schema}.source_marker (id bigint)"
            ))
            .await
            .expect("create the isolated cancellation marker");

        let barrier = CancellationTestBarrier {
            before_send: Arc::new(tokio::sync::Notify::new()),
            release_send: Arc::new(tokio::sync::Notify::new()),
            after_send: Arc::new(tokio::sync::Notify::new()),
        };
        *CANCELLATION_TEST_BARRIER
            .lock()
            .expect("install the cancellation test barrier") = Some(barrier.clone());
        let slow_source = Arc::clone(&source);
        let slow_read = tokio::spawn(async move {
            slow_source
                .read(read(
                    "SELECT pg_backend_pid()::bigint AS backend_pid FROM pg_sleep(0.2) ORDER BY backend_pid"
                        .to_owned(),
                    2_000,
                ))
                .await
        });

        let first_backend_pid =
            active_backend_pid(observer, application_name, "%pg_sleep(0.2)%").await;

        slow_read.abort();
        assert!(
            slow_read
                .await
                .expect_err("the source read task is cancelled")
                .is_cancelled(),
            "dropping the in-flight read cancels its task"
        );
        timeout(Duration::from_secs(5), barrier.before_send.notified())
            .await
            .expect("the cancellation request reaches its test barrier");

        let reused_source = Arc::clone(&source);
        let reused_schema = schema.to_owned();
        let reused_read = tokio::spawn(async move {
            reused_source
                .read(read(
                    format!(
                        "SELECT pg_backend_pid()::bigint AS backend_pid, \
                         COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) AS transport_tls, \
                         current_setting('transaction_read_only') AS transaction_read_only, \
                         current_setting('statement_timeout') AS statement_timeout, \
                         (SELECT count(*)::bigint FROM {reused_schema}.source_marker) AS marker_rows \
                         FROM pg_sleep(1) ORDER BY backend_pid"
                    ),
                    1_234,
                ))
                .await
        });
        let second_backend_pid =
            active_backend_pid(observer, application_name, "%pg_sleep(1)%").await;
        barrier.release_send.notify_one();
        timeout(Duration::from_secs(5), barrier.after_send.notified())
            .await
            .expect("the delayed cancellation request is sent");
        let reused = timeout(Duration::from_secs(5), reused_read)
            .await
            .expect("the same pool becomes reusable after cancellation")
            .expect("the reused source read task joins")
            .expect("a delayed cancellation cannot reach the next source read");
        assert!(reused.complete);
        assert_eq!(reused.rows.len(), 1);
        assert_ne!(
            second_backend_pid, first_backend_pid,
            "a dropped read's backend is never recycled into the pool"
        );
        assert_eq!(
            reused.rows[0].columns,
            vec![
                (
                    "backend_pid".to_owned(),
                    SourceScalar::Integer(second_backend_pid),
                ),
                (
                    "transport_tls".to_owned(),
                    SourceScalar::Boolean(expected_tls),
                ),
                (
                    "transaction_read_only".to_owned(),
                    SourceScalar::Text("on".to_owned()),
                ),
                (
                    "statement_timeout".to_owned(),
                    SourceScalar::Text("1234ms".to_owned()),
                ),
                ("marker_rows".to_owned(), SourceScalar::Integer(0)),
            ]
        );
        let normally_reused = source
            .read(read(
                "SELECT pg_backend_pid()::bigint AS backend_pid ORDER BY backend_pid".to_owned(),
                1_234,
            ))
            .await
            .expect("a normally completed read returns its connection to the pool");
        assert_eq!(
            normally_reused.rows[0].columns,
            vec![(
                "backend_pid".to_owned(),
                SourceScalar::Integer(second_backend_pid),
            )],
            "normal completion reuses the replacement backend"
        );
        *CANCELLATION_TEST_BARRIER
            .lock()
            .expect("remove the cancellation test barrier") = None;
    }

    #[tokio::test]
    async fn cancelled_read_is_detached_before_same_pool_creates_fresh_backend() {
        let _exclusive = CANCELLATION_TEST_LOCK.lock().await;
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the test clock is after the Unix epoch")
            .as_nanos();
        let application_name = format!("adapter-source-cancel-{}-{suffix}", std::process::id());
        let schema = format!("adapter_source_cancel_{}_{suffix}", std::process::id());

        let (observer, observer_connection) = test_config("adapter-source-cancel-observer")
            .connect(tokio_postgres::NoTls)
            .await
            .expect("connect the cancellation observer");
        let observer_connection = tokio::spawn(async move {
            observer_connection
                .await
                .expect("the cancellation observer connection remains healthy");
        });

        let pool =
            store::build_verified_pool(test_config(&application_name), tokio_postgres::NoTls, 1)
                .expect("build the one-connection source pool");
        let source = Arc::new(PooledPostgresSource {
            pool,
            cancellation: PostgresCancellation::Plaintext,
        });
        assert_cancelled_read_is_detached_before_same_pool_creates_fresh_backend(
            Arc::clone(&source),
            &observer,
            &application_name,
            &schema,
            false,
        )
        .await;

        drop(source);
        drop(observer);
        observer_connection
            .await
            .expect("the cancellation observer task joins");
    }

    #[cfg(feature = "postgres-tls-test")]
    #[tokio::test]
    async fn tls_cancelled_read_is_detached_before_same_pool_creates_fresh_backend() {
        let _exclusive = CANCELLATION_TEST_LOCK.lock().await;
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the test clock is after the Unix epoch")
            .as_nanos();
        let application_name = format!("adapter-source-tls-cancel-{}-{suffix}", std::process::id());
        let schema = format!("adapter_source_tls_cancel_{}_{suffix}", std::process::id());
        let tls = tls_test_connector();

        let (observer, observer_connection) = tls_test_config("adapter-source-tls-cancel-observer")
            .connect(tls.clone())
            .await
            .expect("connect the verified TLS cancellation observer");
        let observer_connection = tokio::spawn(async move {
            observer_connection
                .await
                .expect("the verified TLS cancellation observer connection remains healthy");
        });
        let pool = store::build_verified_pool(tls_test_config(&application_name), tls.clone(), 1)
            .expect("build the one-connection verified TLS source pool");
        let source = Arc::new(PooledPostgresSource {
            pool,
            cancellation: PostgresCancellation::Tls(tls),
        });

        assert_cancelled_read_is_detached_before_same_pool_creates_fresh_backend(
            Arc::clone(&source),
            &observer,
            &application_name,
            &schema,
            true,
        )
        .await;

        drop(source);
        drop(observer);
        observer_connection
            .await
            .expect("the verified TLS cancellation observer task joins");
    }
}
