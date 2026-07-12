// SPDX-License-Identifier: Apache-2.0
//! Table-level datasource connectors.
//!
//! Connectors are the boundary between configured private tables and
//! DataFusion. File and database sources produce snapshot batches through the
//! existing source/format stack. Request-time source access belongs behind a
//! request-aware backend, not this operator-controlled ingestion boundary.

use std::env;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use futures::stream::BoxStream;
use futures::StreamExt as _;
use postgres_native_tls::MakeTlsConnector;
use time::OffsetDateTime;
use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, Config as PostgresClientConfig};

use crate::config::{FieldType, PostgresTableConfig};
use crate::format::csv::CsvFormat;
use crate::format::{Format, FormatError, FormatHints};
use crate::ingest::declared_schema::DeclaredSchema;
use crate::source::{Source, SourceError, SourceMetadata};

/// A table-level datasource connector.
pub trait TableConnector: Send + Sync + 'static {
    fn descriptor(&self) -> ConnectorDescriptor;
    fn inspect<'a>(&'a self) -> ConnectorFuture<'a, ObservedTable>;
    fn snapshot<'a>(&'a self) -> ConnectorFuture<'a, SnapshotTable>;
    fn snapshot_bounded<'a>(
        &'a self,
        max_source_bytes: u64,
        _max_source_records: u64,
    ) -> ConnectorFuture<'a, SnapshotTable> {
        let _ = max_source_bytes;
        self.snapshot()
    }
    fn metadata<'a>(&'a self) -> ConnectorFuture<'a, ConnectorMetadata>;
}

/// Stable, secret-free connector identity for logs and audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorDescriptor {
    pub kind: &'static str,
    pub target: String,
}

/// Cheap connector-level change metadata used by refresh policies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectorMetadata {
    pub change_token: Option<String>,
    pub observed_at: Option<OffsetDateTime>,
}

/// Lightweight source observation.
#[derive(Clone)]
pub struct ObservedTable {
    pub schema: SchemaRef,
    pub change_token: Option<String>,
    pub observed_at: OffsetDateTime,
}

/// Snapshot table data for ingest validation and materialization.
pub struct SnapshotTable {
    pub observed_schema: SchemaRef,
    pub batches: BoxStream<'static, Result<RecordBatch, ConnectorError>>,
    pub metadata: SourceMetadata,
}

/// Boxed connector future following the project's existing trait style.
pub type ConnectorFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConnectorError>> + Send + 'a>>;

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("source not found")]
    SourceNotFound,
    #[error("source unreadable: {0}")]
    SourceUnreadable(String),
}

impl ConnectorError {
    pub fn source_unreadable(err: impl std::fmt::Display) -> Self {
        Self::SourceUnreadable(err.to_string())
    }
}

impl From<SourceError> for ConnectorError {
    fn from(value: SourceError) -> Self {
        match value {
            SourceError::NotFound => Self::SourceNotFound,
            SourceError::Unreadable(err) => Self::SourceUnreadable(err),
            SourceError::Io(err) => Self::SourceUnreadable(err.to_string()),
        }
    }
}

impl From<FormatError> for ConnectorError {
    fn from(value: FormatError) -> Self {
        Self::SourceUnreadable(value.to_string())
    }
}

/// Connector for byte-oriented file sources.
pub struct FileConnector {
    source: Arc<dyn Source>,
    format: Arc<dyn Format>,
    hints: FormatHints,
    format_name: &'static str,
    xlsx_max_file_bytes: u64,
    max_source_file_bytes: u64,
}

impl FileConnector {
    pub fn new(
        source: Arc<dyn Source>,
        format: Arc<dyn Format>,
        hints: FormatHints,
        xlsx_max_file_bytes: u64,
        max_source_file_bytes: u64,
    ) -> Self {
        let format_name = format.name();
        Self {
            source,
            format,
            hints,
            format_name,
            xlsx_max_file_bytes,
            max_source_file_bytes,
        }
    }

    fn enforce_size_limits(
        &self,
        metadata: &SourceMetadata,
        max_source_bytes: u64,
    ) -> Result<(), ConnectorError> {
        let Some(size_bytes) = metadata.size_bytes else {
            // Fail closed: refuse to read when size is unknown. Future streaming
            // or HTTP sources must always provide a size or implement their own caps.
            return Err(ConnectorError::SourceUnreadable(
                "source size is unknown; refusing to read without an enforceable size limit"
                    .to_string(),
            ));
        };
        let max_source_file_bytes = self.max_source_file_bytes.min(max_source_bytes);
        if size_bytes > max_source_file_bytes {
            return Err(ConnectorError::SourceUnreadable(format!(
                "source exceeds configured maximum: {size_bytes} > {max_source_file_bytes}",
            )));
        }
        if self.format_name == "xlsx" && size_bytes > self.xlsx_max_file_bytes {
            return Err(ConnectorError::SourceUnreadable(format!(
                "xlsx source exceeds configured maximum: {size_bytes} > {}",
                self.xlsx_max_file_bytes
            )));
        }
        Ok(())
    }

    fn change_token(metadata: &SourceMetadata) -> Option<String> {
        metadata
            .etag
            .clone()
            .or_else(|| metadata.mtime.map(|mtime| mtime.to_string()))
    }
}

impl TableConnector for FileConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        let descriptor = self.source.descriptor();
        ConnectorDescriptor {
            kind: descriptor.scheme,
            target: descriptor.target,
        }
    }

    fn inspect<'a>(&'a self) -> ConnectorFuture<'a, ObservedTable> {
        Box::pin(async move {
            let snapshot = self.snapshot().await?;
            let change_token = Self::change_token(&snapshot.metadata);
            Ok(ObservedTable {
                schema: snapshot.observed_schema,
                change_token,
                observed_at: OffsetDateTime::now_utc(),
            })
        })
    }

    fn snapshot<'a>(&'a self) -> ConnectorFuture<'a, SnapshotTable> {
        self.snapshot_bounded(self.max_source_file_bytes, u64::MAX)
    }

    fn snapshot_bounded<'a>(
        &'a self,
        max_source_bytes: u64,
        _max_source_records: u64,
    ) -> ConnectorFuture<'a, SnapshotTable> {
        Box::pin(async move {
            let opened = self.source.open().await.map_err(ConnectorError::from)?;
            self.enforce_size_limits(&opened.metadata, max_source_bytes)?;
            let decoded = self
                .format
                .decode(opened.reader, self.hints.clone())
                .await
                .map_err(ConnectorError::from)?;
            let batches = decoded
                .batches
                .map(|result| result.map_err(ConnectorError::from))
                .boxed();
            Ok(SnapshotTable {
                observed_schema: decoded.observed_schema,
                batches,
                metadata: opened.metadata,
            })
        })
    }

    fn metadata<'a>(&'a self) -> ConnectorFuture<'a, ConnectorMetadata> {
        Box::pin(async move {
            let metadata = self.source.metadata().await.map_err(ConnectorError::from)?;
            Ok(ConnectorMetadata {
                change_token: Self::change_token(&metadata),
                observed_at: metadata.mtime,
            })
        })
    }
}

/// Connector for PostgreSQL sources.
///
/// The connector uses PostgreSQL `COPY (SELECT ...) TO STDOUT WITH CSV HEADER`
/// and then feeds the bytes through the existing CSV decoder. This keeps
/// declared-schema coercion, projection, validation, and cache registration on
/// the same path as file ingest.
#[derive(Clone)]
pub struct PostgresConnector {
    connection_env: String,
    table: Option<PostgresTableConfig>,
    query: Option<String>,
    change_token_sql: Option<String>,
    declared: Arc<DeclaredSchema>,
    max_source_bytes: u64,
    connect_timeout: Duration,
    query_timeout: Duration,
}

impl PostgresConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_env: String,
        table: Option<PostgresTableConfig>,
        query: Option<String>,
        change_token_sql: Option<String>,
        declared: Arc<DeclaredSchema>,
        max_source_bytes: u64,
        connect_timeout: Duration,
        query_timeout: Duration,
    ) -> Self {
        Self {
            connection_env,
            table,
            query,
            change_token_sql,
            declared,
            max_source_bytes,
            connect_timeout,
            query_timeout,
        }
    }

    async fn connect(&self) -> Result<Client, ConnectorError> {
        let url = std::env::var(&self.connection_env).map_err(|_| {
            ConnectorError::SourceUnreadable(format!(
                "postgres connection environment variable {} is not set",
                self.connection_env
            ))
        })?;
        let client_config = postgres_config_require_tls(&url, &self.connection_env)?;
        let tls = postgres_tls_connector().await?;
        let connector = MakeTlsConnector::new(tls);
        let (client, connection) =
            tokio::time::timeout(self.connect_timeout, client_config.connect(connector))
                .await
                .map_err(|_| {
                    ConnectorError::SourceUnreadable("postgres connection timed out".into())
                })?
                .map_err(|_| {
                    ConnectorError::SourceUnreadable("postgres connection failed".into())
                })?;

        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::warn!(
                    event = "connector.postgres_connection_closed",
                    error = %error,
                );
            }
        });

        let statement_timeout_ms = self.query_timeout.as_millis().clamp(1, i32::MAX as u128);
        let session_setup = format!(
            "SET TIME ZONE 'UTC'; \
             SET default_transaction_read_only = on; \
             SET statement_timeout = {statement_timeout_ms}"
        );
        self.with_query_timeout("postgres session setup", async {
            client
                .batch_execute(&session_setup)
                .await
                .map_err(|e| ConnectorError::SourceUnreadable(e.to_string()))
        })
        .await?;

        Ok(client)
    }

    async fn with_query_timeout<T>(
        &self,
        operation: &'static str,
        future: impl Future<Output = Result<T, ConnectorError>>,
    ) -> Result<T, ConnectorError> {
        tokio::time::timeout(self.query_timeout, future)
            .await
            .map_err(|_| ConnectorError::SourceUnreadable(format!("{operation} timed out")))?
    }

    async fn read_change_token(
        &self,
        client: &Client,
    ) -> Result<(Option<String>, OffsetDateTime), ConnectorError> {
        let observed_at = OffsetDateTime::now_utc();
        let Some(sql) = self.change_token_sql.as_deref() else {
            return Ok((None, observed_at));
        };
        let row = self
            .with_query_timeout("postgres change token query", async {
                client
                    .query_one(sql, &[])
                    .await
                    .map_err(|e| ConnectorError::SourceUnreadable(e.to_string()))
            })
            .await?;
        let token = row.try_get::<_, Option<String>>(0).map_err(|_| {
            ConnectorError::SourceUnreadable(
                "postgres change_token_sql must return a nullable text value".into(),
            )
        })?;
        Ok((token, observed_at))
    }

    fn base_select_sql(&self) -> String {
        if let Some(table) = &self.table {
            return format!(
                "SELECT * FROM {}.{}",
                quote_ident(&table.schema),
                quote_ident(&table.name)
            );
        }

        let query = self
            .query
            .as_deref()
            .expect("config validation requires postgres table or query")
            .trim();
        query.trim_end_matches(';').trim().to_string()
    }

    fn projected_select_sql(&self, declared: &DeclaredSchema) -> String {
        let base = self.base_select_sql();
        let projections = declared
            .fields
            .iter()
            .map(|field| {
                postgres_projection_expr(
                    &format!("data_gate_source.{}", quote_ident(&field.name)),
                    &quote_ident(&field.name),
                    field.ty,
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("SELECT {projections} FROM ({base}) AS data_gate_source")
    }

    fn copy_sql_for(&self, declared: &DeclaredSchema, max_source_records: u64) -> String {
        let projected = self.projected_select_sql(declared);
        let bounded = if max_source_records == u64::MAX {
            projected
        } else {
            format!(
                "SELECT * FROM ({projected}) AS bounded_source LIMIT {}",
                max_source_records.saturating_add(1)
            )
        };
        format!("COPY ({bounded}) TO STDOUT WITH (FORMAT CSV, HEADER TRUE)")
    }

    async fn copy_decoded_for(
        &self,
        client: &Client,
        declared: Arc<DeclaredSchema>,
        max_source_bytes: u64,
        max_source_records: u64,
    ) -> Result<SnapshotTable, ConnectorError> {
        let copy_stream = client
            .copy_out(&self.copy_sql_for(&declared, max_source_records))
            .await
            .map_err(|e| ConnectorError::SourceUnreadable(e.to_string()))?;
        futures::pin_mut!(copy_stream);
        let mut bytes = Vec::new();
        while let Some(chunk) = copy_stream.next().await {
            let chunk = chunk.map_err(|e| ConnectorError::SourceUnreadable(e.to_string()))?;
            let next_len = bytes.len().saturating_add(chunk.len());
            let effective_max_source_bytes = self.max_source_bytes.min(max_source_bytes);
            if next_len > effective_max_source_bytes as usize {
                return Err(ConnectorError::SourceUnreadable(format!(
                    "postgres export exceeds configured maximum: {next_len} > {effective_max_source_bytes}",
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        let exported_bytes = bytes.len() as u64;
        let reader = std::io::Cursor::new(bytes);
        let hints = FormatHints {
            sheet: None,
            header_row: Some(1),
            data_range: None,
            delimiter: None,
            quote: None,
            declared,
        };
        let decoded = CsvFormat::new()
            .decode(Box::pin(reader), hints)
            .await
            .map_err(ConnectorError::from)?;
        Ok(SnapshotTable {
            observed_schema: decoded.observed_schema,
            batches: decoded
                .batches
                .map(|result| result.map_err(ConnectorError::from))
                .boxed(),
            metadata: SourceMetadata {
                mtime: None,
                size_bytes: Some(exported_bytes),
                etag: None,
                content_type: Some("text/csv".to_string()),
            },
        })
    }

    async fn timed_copy_decoded(
        &self,
        client: &Client,
        max_source_bytes: u64,
        max_source_records: u64,
    ) -> Result<SnapshotTable, ConnectorError> {
        self.with_query_timeout(
            "postgres export",
            self.copy_decoded_for(
                client,
                Arc::clone(&self.declared),
                max_source_bytes,
                max_source_records,
            ),
        )
        .await
    }
}

fn postgres_config_require_tls(
    url: &str,
    connection_env: &str,
) -> Result<PostgresClientConfig, ConnectorError> {
    let config = url.parse::<PostgresClientConfig>().map_err(|_| {
        ConnectorError::SourceUnreadable(format!(
            "postgres connection string in {connection_env} is invalid"
        ))
    })?;
    if config.get_ssl_mode() != SslMode::Require {
        return Err(ConnectorError::SourceUnreadable(format!(
            "postgres connection string in {connection_env} must set sslmode=require"
        )));
    }
    Ok(config)
}

async fn postgres_tls_connector() -> Result<native_tls::TlsConnector, ConnectorError> {
    let mut builder = native_tls::TlsConnector::builder();
    if let Ok(path) = env::var("DATA_GATE_POSTGRES_ROOT_CERT_PATH") {
        let pem = tokio::fs::read(path).await.map_err(|_| {
            ConnectorError::SourceUnreadable("postgres TLS root certificate is unreadable".into())
        })?;
        let certificate = native_tls::Certificate::from_pem(&pem).map_err(|_| {
            ConnectorError::SourceUnreadable("postgres TLS root certificate is invalid".into())
        })?;
        builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|_| ConnectorError::SourceUnreadable("postgres TLS setup failed".into()))
}

impl TableConnector for PostgresConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            kind: "postgres",
            target: self
                .table
                .as_ref()
                .map(|table| format!("{}.{}", table.schema, table.name))
                .unwrap_or_else(|| "configured query".to_string()),
        }
    }

    fn inspect<'a>(&'a self) -> ConnectorFuture<'a, ObservedTable> {
        Box::pin(async move {
            let client = self.connect().await?;
            let (change_token, observed_at) = self.read_change_token(&client).await?;
            Ok(ObservedTable {
                schema: self.declared.to_arrow_schema(),
                change_token,
                observed_at,
            })
        })
    }

    fn snapshot<'a>(&'a self) -> ConnectorFuture<'a, SnapshotTable> {
        self.snapshot_bounded(self.max_source_bytes, u64::MAX)
    }

    fn snapshot_bounded<'a>(
        &'a self,
        max_source_bytes: u64,
        max_source_records: u64,
    ) -> ConnectorFuture<'a, SnapshotTable> {
        Box::pin(async move {
            let client = self.connect().await?;
            let (change_token, observed_at) = self.read_change_token(&client).await?;
            let mut snapshot = self
                .timed_copy_decoded(&client, max_source_bytes, max_source_records)
                .await?;
            snapshot.metadata.mtime = Some(observed_at);
            snapshot.metadata.etag = change_token;
            Ok(snapshot)
        })
    }

    fn metadata<'a>(&'a self) -> ConnectorFuture<'a, ConnectorMetadata> {
        Box::pin(async move {
            let client = self.connect().await?;
            let (change_token, observed_at) = self.read_change_token(&client).await?;
            Ok(ConnectorMetadata {
                change_token,
                observed_at: Some(observed_at),
            })
        })
    }
}

fn quote_ident(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn postgres_projection_expr(source: &str, alias: &str, ty: FieldType) -> String {
    match ty {
        FieldType::String => format!("{source}::text AS {alias}"),
        FieldType::Integer => format!("{source}::bigint AS {alias}"),
        FieldType::Number => format!("{source}::double precision AS {alias}"),
        FieldType::Boolean => format!("{source}::boolean AS {alias}"),
        FieldType::Date => format!("{source}::date AS {alias}"),
        FieldType::Timestamp => format!(
            "to_char({source}::timestamptz AT TIME ZONE 'UTC', \
             'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS {alias}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::config::{FieldConfig, FieldType, SchemaConfig};

    fn declared(fields: Vec<(&str, FieldType)>) -> Arc<DeclaredSchema> {
        Arc::new(DeclaredSchema::from(&SchemaConfig {
            strict: true,
            fields: fields
                .into_iter()
                .map(|(name, ty)| FieldConfig {
                    name: name.to_string(),
                    r#type: ty,
                    nullable: true,
                    sensitive: false,
                    concept_uri: None,
                    codelist: None,
                    unit: None,
                    language: None,
                })
                .collect(),
        }))
    }

    #[test]
    fn postgres_copy_sql_projects_declared_columns_through_csv_friendly_casts() {
        let connector = PostgresConnector::new(
            "DATABASE_URL".to_string(),
            Some(PostgresTableConfig {
                schema: "public".to_string(),
                name: "people".to_string(),
            }),
            None,
            None,
            declared(vec![
                ("id", FieldType::Integer),
                ("active", FieldType::Boolean),
                ("updated_at", FieldType::Timestamp),
            ]),
            256 * 1024 * 1024,
            Duration::from_secs(5),
            Duration::from_secs(30),
        );

        let sql = connector.copy_sql_for(&connector.declared, u64::MAX);
        assert!(sql.contains(r#"FROM (SELECT * FROM "public"."people") AS data_gate_source"#));
        assert!(sql.contains(r#"data_gate_source."id"::bigint AS "id""#));
        assert!(sql.contains(r#"data_gate_source."active"::boolean AS "active""#));
        assert!(sql.contains(r#"to_char(data_gate_source."updated_at"::timestamptz"#));
        assert!(sql.starts_with("COPY (SELECT "));
        assert!(sql.ends_with(") TO STDOUT WITH (FORMAT CSV, HEADER TRUE)"));

        let bounded = connector.copy_sql_for(&connector.declared, 25);
        assert!(bounded.contains("AS bounded_source LIMIT 26"));
    }

    #[test]
    fn postgres_sslmode_rejects_default_prefer() {
        let err = postgres_config_require_tls(
            "host=localhost user=registry password=secret dbname=registry",
            "TEST_DATABASE_URL",
        )
        .expect_err("missing sslmode defaults to prefer");

        assert_eq!(
            err.to_string(),
            "source unreadable: postgres connection string in TEST_DATABASE_URL must set sslmode=require"
        );
    }

    #[test]
    fn postgres_sslmode_rejects_explicit_prefer() {
        let err = postgres_config_require_tls(
            "postgres://registry:secret@localhost/registry?sslmode=prefer",
            "TEST_DATABASE_URL",
        )
        .expect_err("prefer is too weak");

        assert!(err.to_string().contains("sslmode=require"));
    }

    #[test]
    fn postgres_sslmode_rejects_disable() {
        let err = postgres_config_require_tls(
            "postgres://registry:secret@localhost/registry?sslmode=disable",
            "TEST_DATABASE_URL",
        )
        .expect_err("disable is too weak");

        assert!(err.to_string().contains("sslmode=require"));
    }

    #[test]
    fn postgres_sslmode_accepts_require() {
        let config = postgres_config_require_tls(
            "postgres://registry:secret@localhost/registry?sslmode=require",
            "TEST_DATABASE_URL",
        )
        .expect("require is accepted");

        assert_eq!(config.get_ssl_mode(), SslMode::Require);
    }

    #[test]
    fn postgres_sslmode_parse_error_does_not_leak_url() {
        let err = postgres_config_require_tls(
            "postgres://registry:super-secret@localhost:bad-port/registry?sslmode=require",
            "TEST_DATABASE_URL",
        )
        .expect_err("invalid url is rejected");
        let message = err.to_string();

        assert!(message.contains("TEST_DATABASE_URL"));
        assert!(!message.contains("super-secret"));
        assert!(!message.contains("bad-port"));
    }

    #[test]
    fn quote_ident_escapes_double_quotes() {
        assert_eq!(quote_ident("a\"b"), r#""a""b""#);
    }

    #[test]
    fn enforce_size_limits_fails_closed_on_unknown_size() {
        use std::pin::Pin;
        use std::sync::Arc;

        use crate::format::{DecodedStream, Format, FormatError, FormatFuture, FormatHints};
        use crate::source::{OpenedSource, Source, SourceDescriptor, SourceFuture, SourceMetadata};

        // Minimal test helper: Source that returns size_bytes: None
        struct TestSource;

        impl Source for TestSource {
            fn descriptor(&self) -> SourceDescriptor {
                SourceDescriptor {
                    scheme: "test",
                    target: "unknown_size".to_string(),
                }
            }

            fn open<'a>(&'a self) -> SourceFuture<'a, OpenedSource> {
                Box::pin(async {
                    Ok(OpenedSource {
                        reader: Box::pin(tokio::io::empty()),
                        metadata: SourceMetadata {
                            size_bytes: None, // <-- unknown size
                            ..SourceMetadata::default()
                        },
                    })
                })
            }

            fn metadata<'a>(&'a self) -> SourceFuture<'a, SourceMetadata> {
                Box::pin(async {
                    Ok(SourceMetadata {
                        size_bytes: None,
                        ..SourceMetadata::default()
                    })
                })
            }
        }

        // Minimal test helper: dummy Format
        struct TestFormat;

        impl Format for TestFormat {
            fn name(&self) -> &'static str {
                "test"
            }

            fn decode<'a>(
                &'a self,
                _reader: Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
                _hints: FormatHints,
            ) -> FormatFuture<'a, DecodedStream> {
                Box::pin(async { Err(FormatError::Parse("test".to_string())) })
            }
        }

        let connector = FileConnector::new(
            Arc::new(TestSource),
            Arc::new(TestFormat),
            FormatHints {
                sheet: None,
                header_row: None,
                data_range: None,
                delimiter: None,
                quote: None,
                declared: crate::ingest::declared_schema::DeclaredSchema::empty(),
            },
            256 * 1024 * 1024,
            256 * 1024 * 1024,
        );

        let metadata = SourceMetadata {
            size_bytes: None,
            ..SourceMetadata::default()
        };

        let result = connector.enforce_size_limits(&metadata, connector.max_source_file_bytes);

        assert!(result.is_err());
        match result {
            Err(ConnectorError::SourceUnreadable(msg)) => {
                assert!(
                    msg.contains("unknown"),
                    "error message should mention unknown size"
                );
            }
            _ => panic!("expected SourceUnreadable error"),
        }
        let oversized_for_reviewed_bound = SourceMetadata {
            size_bytes: Some(101),
            ..SourceMetadata::default()
        };
        assert!(connector
            .enforce_size_limits(&oversized_for_reviewed_bound, 100)
            .is_err());
    }
}
