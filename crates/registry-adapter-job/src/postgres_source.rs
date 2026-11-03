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
use registry_platform_config::{describe_secret_failure, SecretResolver};
use registry_platform_yaml::{LocalId, UniqueIdList, UniqueList};
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type};

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
    /// Resolve the password and build the pool. Each refusal names the
    /// endpoint, the step that failed (secret, TLS, pool settings) and the
    /// runtime member to correct, and carries no reference text or value.
    /// A connection failure cannot appear here: connections open lazily at
    /// the first read.
    fn build(binding: PostgresSourceBinding, resolver: &SecretResolver) -> Result<Self, String> {
        let endpoint = binding.endpoint.clone();
        let member = |name: &str| format!("sources.postgres.{endpoint}.{name}");
        let password = resolver
            .resolve(binding.password_ref.as_str())
            .map_err(|error| {
                format!(
                    "the PostgreSQL source {endpoint} was refused at the secret step: {}",
                    describe_secret_failure(
                        &member("passwordRef"),
                        binding.password_ref.as_str(),
                        &error
                    )
                )
            })?;
        let tls_refused = |detail: &str| {
            format!(
                "the PostgreSQL source {endpoint} was refused at the TLS step: {detail}; correct {}",
                member("tls")
            )
        };
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
                let tls = store::native_postgres_tls()
                    .map_err(|_| tls_refused("the platform trust roots could not be loaded"))?;
                (
                    store::build_verified_pool(postgres, tls.clone(), MAXIMUM_SOURCE_CONNECTIONS),
                    PostgresCancellation::Tls(tls),
                )
            }
            PostgresSourceTls::CaBundle { ca_bundle_file } => {
                postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
                let ca = capture_ca_bundle(&ca_bundle_file).map_err(|error| {
                    format!(
                        "the PostgreSQL source {endpoint} was refused at the TLS step: {error}; correct {}",
                        member("tls.caBundleFile")
                    )
                })?;
                let tls = store::postgres_tls_from_native_and_pem(ca.as_bytes())
                    .map_err(|_| tls_refused("the CA bundle holds no usable certificate"))?;
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
                    return Err(format!(
                        "the plaintext PostgreSQL test source {endpoint} is not numeric loopback; correct {}",
                        member("host")
                    ));
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
        let pool = pool.map_err(|error| {
            format!(
                "the PostgreSQL source {endpoint} was refused at the pool step ({error}); check {}, {}, {} and {}",
                member("host"),
                member("port"),
                member("database"),
                member("user")
            )
        })?;
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
    // Execute through a portal that returns at most one row past the page
    // bound, which is enough to tell a full page from a complete result. The
    // engine pages with OFFSET and no LIMIT, so an unbounded execution would
    // drain the rest of the result until the statement timeout.
    let fetch_limit = i32::try_from(read.maximum_rows.saturating_add(1))
        .map_err(|_| PostgresReadFault::TooLarge)?;
    let portal = transaction
        .bind_raw(read.sql.as_str(), parameters.iter())
        .await
        .map_err(statement_fault)?;
    let stream = transaction
        .query_portal_raw(&portal, fetch_limit)
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
        let scalar = column_scalar(row, index, column.type_(), budget)?;
        columns.push((column.name().to_owned(), scalar));
    }
    Ok(SourceRow { columns })
}

/// Read one column as its closed scalar. Every supported type reads as
/// an `Option`, so a SQL NULL of any of them is [`SourceScalar::Null`].
/// Dates, times and UUIDs cross as canonical text: DATE as `YYYY-MM-DD`,
/// TIMESTAMP as ISO 8601 without an offset, TIMESTAMPTZ as RFC 3339 in
/// UTC, and UUID in lowercase hyphenated form. NUMERIC crosses as its
/// exact decimal text. Any other type refuses with its one-based column
/// position, never its value.
fn column_scalar(
    row: &tokio_postgres::Row,
    index: usize,
    column_type: &Type,
    budget: &PostgresRowBudget,
) -> Result<SourceScalar, PostgresReadFault> {
    let finite = |value: f64| {
        if value.is_finite() {
            Ok(SourceScalar::Float(value))
        } else {
            Err(PostgresReadFault::Malformed)
        }
    };
    Ok(match *column_type {
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
            match column::<&str>(row, index)? {
                Some(value) => {
                    budget.check_field(value)?;
                    SourceScalar::Text(value.to_owned())
                }
                None => SourceScalar::Null,
            }
        }
        Type::INT8 => column::<i64>(row, index)?.map_or(SourceScalar::Null, SourceScalar::Integer),
        Type::INT4 => column::<i32>(row, index)?.map_or(SourceScalar::Null, |value| {
            SourceScalar::Integer(value.into())
        }),
        Type::INT2 => column::<i16>(row, index)?.map_or(SourceScalar::Null, |value| {
            SourceScalar::Integer(value.into())
        }),
        Type::FLOAT8 => column::<f64>(row, index)?.map_or(Ok(SourceScalar::Null), finite)?,
        Type::FLOAT4 => column::<f32>(row, index)?
            .map_or(Ok(SourceScalar::Null), |value| finite(value.into()))?,
        Type::BOOL => column::<bool>(row, index)?.map_or(SourceScalar::Null, SourceScalar::Boolean),
        Type::NUMERIC => column::<NumericText>(row, index)?
            .map_or(SourceScalar::Null, |value| SourceScalar::Numeric(value.0)),
        Type::DATE => column::<chrono::NaiveDate>(row, index)?
            .map_or(SourceScalar::Null, |value| {
                SourceScalar::Text(value.format("%Y-%m-%d").to_string())
            }),
        Type::TIMESTAMP => column::<chrono::NaiveDateTime>(row, index)?
            .map_or(SourceScalar::Null, |value| {
                SourceScalar::Text(value.format("%Y-%m-%dT%H:%M:%S%.f").to_string())
            }),
        Type::TIMESTAMPTZ => column::<chrono::DateTime<chrono::Utc>>(row, index)?
            .map_or(SourceScalar::Null, |value| {
                SourceScalar::Text(value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
            }),
        Type::UUID => column::<uuid::Uuid>(row, index)?.map_or(SourceScalar::Null, |value| {
            SourceScalar::Text(value.hyphenated().to_string())
        }),
        _ => {
            return Err(PostgresReadFault::UnsupportedColumn {
                column: u32::try_from(index + 1).unwrap_or(u32::MAX),
            })
        }
    })
}

/// Decode one column of a supported type. A value the type's own decoder
/// cannot read, such as an infinite date, is outside the closed form.
fn column<'a, T: FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    index: usize,
) -> Result<Option<T>, PostgresReadFault> {
    row.try_get::<_, Option<T>>(index)
        .map_err(|_| PostgresReadFault::Malformed)
}

/// A NUMERIC value as its exact decimal text, decoded from the binary wire
/// form: digit count, weight, sign and display scale, then base-10000
/// digits. NaN and the infinities have no decimal text and refuse.
struct NumericText(String);

impl<'a> FromSql<'a> for NumericText {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let word = |at: usize| {
            raw.get(at..at + 2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                .ok_or("a numeric value is truncated")
        };
        let count = usize::from(word(0)?);
        let weight = i32::from(word(2)?.cast_signed());
        let negative = match word(4)? {
            0x0000 => false,
            0x4000 => true,
            _ => return Err("a numeric value has no decimal text".into()),
        };
        let scale = usize::from(word(6)?);
        if raw.len() != 8 + 2 * count {
            return Err("a numeric value has a malformed length".into());
        }
        let digits = (0..count)
            .map(|position| word(8 + 2 * position))
            .collect::<Result<Vec<_>, _>>()?;
        if digits.iter().any(|digit| *digit > 9_999) {
            return Err("a numeric digit is out of range".into());
        }
        // The digit at position `p` is worth 10000^(weight - p); a position
        // outside the transmitted digits is zero.
        let digit = |position: i32| {
            usize::try_from(position)
                .ok()
                .and_then(|position| digits.get(position))
                .copied()
                .unwrap_or(0)
        };
        let mut text = String::new();
        if negative {
            text.push('-');
        }
        if weight < 0 {
            text.push('0');
        } else {
            text.push_str(&digit(0).to_string());
            for position in 1..=weight {
                text.push_str(&format!("{:04}", digit(position)));
            }
        }
        if scale > 0 {
            let mut fraction = String::with_capacity(scale + 4);
            let mut position = weight + 1;
            while fraction.len() < scale {
                fraction.push_str(&format!("{:04}", digit(position)));
                position += 1;
            }
            fraction.truncate(scale);
            text.push('.');
            text.push_str(&fraction);
        }
        Ok(Self(text))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::NUMERIC
    }
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
            // The engine refuses a null parameter before the read, so a
            // NULL here is a seam fault, never a value to bind.
            SourceScalar::Null => Err(PostgresReadFault::Statement),
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

#[cfg(test)]
mod activation_tests {
    use registry_platform_config::SecretProvider;
    use registry_platform_yaml::SecretReference;

    use super::*;

    fn binding(password_ref: &str, tls: PostgresSourceTls) -> PostgresSourceBinding {
        PostgresSourceBinding {
            endpoint: "ledger".to_owned(),
            host: "db.example.org".to_owned(),
            port: 5432,
            database: "registry".to_owned(),
            user: "reader".to_owned(),
            password_ref: SecretReference::parse(password_ref).expect("an exact reference"),
            tls,
        }
    }

    /// An activation refusal names the endpoint, the step that failed and
    /// the member to correct, and never the reference text or a value.
    #[test]
    fn activation_refusals_name_the_endpoint_the_step_and_the_member() {
        let resolver = SecretResolver::new([SecretProvider::Environment], "")
            .expect("an environment resolver");
        let missing = "secret:env/RF_P3_POSTGRES_PASSWORD_THAT_IS_NOT_SET";
        let refused = PooledPostgresSource::build(
            binding(missing, PostgresSourceTls::SystemRoots),
            &resolver,
        )
        .expect_err("an unset password refuses");
        assert!(refused.contains("ledger"), "{refused}");
        assert!(
            refused.contains("sources.postgres.ledger.passwordRef"),
            "{refused}"
        );
        assert!(refused.contains("no readable secret"), "{refused}");
        assert!(
            !refused.contains("RF_P3_POSTGRES_PASSWORD_THAT_IS_NOT_SET"),
            "{refused}"
        );

        // The set password passes the secret step, so a bad CA bundle path
        // is the TLS step and names tls.caBundleFile.
        let present = "secret:env/PATH";
        let refused = PooledPostgresSource::build(
            binding(
                present,
                PostgresSourceTls::CaBundle {
                    ca_bundle_file: "/nonexistent/registry-ca.pem".to_owned(),
                },
            ),
            &resolver,
        )
        .expect_err("an unreadable CA bundle refuses");
        assert!(refused.contains("ledger"), "{refused}");
        assert!(
            refused.contains("sources.postgres.ledger.tls.caBundleFile"),
            "{refused}"
        );
    }
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

    /// A page stops at its row bound. The engine pages with OFFSET and no
    /// LIMIT, so a read that drained the rest of the result would hold its
    /// connection until the statement timeout instead of returning the page.
    #[tokio::test]
    async fn page_read_stops_at_its_row_bound_without_draining_the_result() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the test clock is after the Unix epoch")
            .as_nanos();
        let application_name = format!("adapter-source-bound-{}-{suffix}", std::process::id());
        let pool =
            store::build_verified_pool(test_config(&application_name), tokio_postgres::NoTls, 1)
                .expect("build the one-connection source pool");
        let source = PooledPostgresSource {
            pool,
            cancellation: PostgresCancellation::Plaintext,
        };

        let started = Instant::now();
        let page = source
            .read(read(
                "SELECT generate_series(1, 2000000000)::bigint AS n".to_owned(),
                10_000,
            ))
            .await
            .expect("a bounded page of a large result reads");
        let elapsed = started.elapsed();

        assert_eq!(
            page.rows[0].columns,
            vec![("n".to_owned(), SourceScalar::Integer(1))]
        );
        assert_eq!(page.rows.len(), 1);
        assert!(!page.complete, "a page cut at its bound is not complete");
        assert!(
            elapsed < Duration::from_secs(5),
            "the page returns without draining the result, took {elapsed:?}"
        );
    }
}
