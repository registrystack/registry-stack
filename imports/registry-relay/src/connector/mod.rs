// SPDX-License-Identifier: Apache-2.0
//! Table-level datasource connectors.
//!
//! Connectors are the boundary between configured private tables and
//! DataFusion. File sources produce snapshot batches through the
//! existing source/format stack. Future database connectors can either
//! produce snapshot batches or a live `TableProvider`.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::{DataFusionError, Result as DataFusionResult, Statistics};
use datafusion::datasource::MemTable;
use datafusion::logical_expr::{Expr, TableProviderFilterPushDown, TableType};
use datafusion::physical_plan::ExecutionPlan;
use futures::stream::BoxStream;
use futures::StreamExt as _;
use postgres_native_tls::MakeTlsConnector;
use time::OffsetDateTime;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, Config as PostgresClientConfig};

use crate::config::{FieldType, PostgresTableConfig};
use crate::format::csv::CsvFormat;
use crate::format::{Format, FormatError, FormatHints};
use crate::ingest::declared_schema::DeclaredSchema;
use crate::observability::{observe_live_datasource_scan, LiveScanObservation};
use crate::source::{Source, SourceError, SourceMetadata};

/// A table-level datasource connector.
pub trait TableConnector: Send + Sync + 'static {
    fn descriptor(&self) -> ConnectorDescriptor;
    fn inspect<'a>(&'a self) -> ConnectorFuture<'a, ObservedTable>;
    fn snapshot<'a>(&'a self) -> ConnectorFuture<'a, SnapshotTable>;
    fn live_provider<'a>(&'a self) -> ConnectorFuture<'a, Option<Arc<dyn TableProvider>>>;
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
    #[error("live provider unsupported")]
    LiveUnsupported,
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

    fn enforce_size_limits(&self, metadata: &SourceMetadata) -> Result<(), ConnectorError> {
        let Some(size_bytes) = metadata.size_bytes else {
            return Ok(());
        };
        if size_bytes > self.max_source_file_bytes {
            return Err(ConnectorError::SourceUnreadable(format!(
                "source exceeds configured maximum: {size_bytes} > {}",
                self.max_source_file_bytes
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
        Box::pin(async move {
            let opened = self.source.open().await.map_err(ConnectorError::from)?;
            self.enforce_size_limits(&opened.metadata)?;
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

    fn live_provider<'a>(&'a self) -> ConnectorFuture<'a, Option<Arc<dyn TableProvider>>> {
        Box::pin(async { Ok(None) })
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
    live_semaphore: Arc<Semaphore>,
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
        live_max_connections: usize,
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
            live_semaphore: Arc::new(Semaphore::new(live_max_connections)),
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
        let tls = native_tls::TlsConnector::builder()
            .build()
            .map_err(|_| ConnectorError::SourceUnreadable("postgres TLS setup failed".into()))?;
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

    fn projected_select_sql_for(&self, declared: &DeclaredSchema) -> String {
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

    fn copy_sql_for(&self, declared: &DeclaredSchema) -> String {
        format!(
            "COPY ({}) TO STDOUT WITH (FORMAT CSV, HEADER TRUE)",
            self.projected_select_sql_for(declared)
        )
    }

    fn declared_for_projection(
        &self,
        projection: Option<&[usize]>,
    ) -> Result<Arc<DeclaredSchema>, ConnectorError> {
        match projection {
            Some(indices) => self.declared.project(indices).ok_or_else(|| {
                ConnectorError::SourceUnreadable(
                    "postgres projection references an unknown declared column".into(),
                )
            }),
            None => Ok(Arc::clone(&self.declared)),
        }
    }

    async fn copy_decoded_for(
        &self,
        client: &Client,
        declared: Arc<DeclaredSchema>,
    ) -> Result<SnapshotTable, ConnectorError> {
        let copy_stream = client
            .copy_out(&self.copy_sql_for(&declared))
            .await
            .map_err(|e| ConnectorError::SourceUnreadable(e.to_string()))?;
        futures::pin_mut!(copy_stream);
        let mut bytes = Vec::new();
        while let Some(chunk) = copy_stream.next().await {
            let chunk = chunk.map_err(|e| ConnectorError::SourceUnreadable(e.to_string()))?;
            let next_len = bytes.len().saturating_add(chunk.len());
            if next_len > self.max_source_bytes as usize {
                return Err(ConnectorError::SourceUnreadable(format!(
                    "postgres export exceeds configured maximum: {next_len} > {}",
                    self.max_source_bytes
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

    async fn timed_copy_decoded(&self, client: &Client) -> Result<SnapshotTable, ConnectorError> {
        self.timed_copy_decoded_projected(client, None).await
    }

    async fn timed_copy_decoded_projected(
        &self,
        client: &Client,
        projection: Option<&[usize]>,
    ) -> Result<SnapshotTable, ConnectorError> {
        let declared = self.declared_for_projection(projection)?;
        self.with_query_timeout("postgres export", self.copy_decoded_for(client, declared))
            .await
    }

    async fn acquire_live_permit(&self) -> Result<OwnedSemaphorePermit, ConnectorError> {
        self.with_query_timeout("postgres live concurrency wait", async {
            self.live_semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| {
                    ConnectorError::SourceUnreadable("postgres live concurrency gate closed".into())
                })
        })
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
        Box::pin(async move {
            let client = self.connect().await?;
            let (change_token, observed_at) = self.read_change_token(&client).await?;
            let mut snapshot = self.timed_copy_decoded(&client).await?;
            snapshot.metadata = SourceMetadata {
                mtime: Some(observed_at),
                size_bytes: None,
                etag: change_token,
                content_type: Some("text/csv".to_string()),
            };
            Ok(snapshot)
        })
    }

    fn live_provider<'a>(&'a self) -> ConnectorFuture<'a, Option<Arc<dyn TableProvider>>> {
        Box::pin(async move {
            if self.table.is_none() {
                return Err(ConnectorError::LiveUnsupported);
            }
            let provider: Arc<dyn TableProvider> = Arc::new(PostgresLiveTableProvider {
                connector: self.clone(),
                schema: self.declared.to_arrow_schema(),
            });
            Ok(Some(provider))
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

struct PostgresLiveTableProvider {
    connector: PostgresConnector,
    schema: SchemaRef,
}

impl fmt::Debug for PostgresLiveTableProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresLiveTableProvider")
            .field("descriptor", &self.connector.descriptor())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TableProvider for PostgresLiveTableProvider {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        let started = Instant::now();
        let remote_projection = if filters.is_empty() {
            projection
                .map(Vec::as_slice)
                .filter(|indices| is_pushdown_safe_projection(indices))
        } else {
            None
        };
        let projection_pushdown = remote_projection.is_some();
        let wait_started = Instant::now();
        let _permit = match self.connector.acquire_live_permit().await {
            Ok(permit) => permit,
            Err(error) => {
                observe_postgres_live_scan_error(
                    started,
                    wait_started.elapsed().as_secs_f64(),
                    projection_pushdown,
                );
                return Err(postgres_to_datafusion_error(error));
            }
        };
        let wait_seconds = wait_started.elapsed().as_secs_f64();
        let client = match self.connector.connect().await {
            Ok(client) => client,
            Err(error) => {
                observe_postgres_live_scan_error(started, wait_seconds, projection_pushdown);
                return Err(postgres_to_datafusion_error(error));
            }
        };
        let snapshot = match self
            .connector
            .timed_copy_decoded_projected(&client, remote_projection)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                observe_postgres_live_scan_error(started, wait_seconds, projection_pushdown);
                return Err(postgres_to_datafusion_error(error));
            }
        };
        let exported_bytes = snapshot.metadata.size_bytes.unwrap_or(0);
        let mut stream = snapshot.batches;
        let mut batches = Vec::new();
        let mut rows: u64 = 0;
        while let Some(result) = stream.next().await {
            let batch = match result {
                Ok(batch) => batch,
                Err(error) => {
                    observe_postgres_live_scan_error(started, wait_seconds, projection_pushdown);
                    return Err(postgres_to_datafusion_error(error));
                }
            };
            rows = rows.saturating_add(batch.num_rows() as u64);
            batches.push(batch);
        }

        let table = match MemTable::try_new(snapshot.observed_schema, vec![batches]) {
            Ok(table) => table,
            Err(error) => {
                observe_postgres_live_scan_error(started, wait_seconds, projection_pushdown);
                return Err(error);
            }
        };
        let local_projection = if remote_projection.is_some() {
            None
        } else {
            projection
        };
        match table.scan(state, local_projection, filters, limit).await {
            Ok(plan) => {
                observe_live_datasource_scan(LiveScanObservation {
                    datasource: "postgres",
                    status: "success",
                    projection_pushdown,
                    duration_seconds: started.elapsed().as_secs_f64(),
                    wait_seconds,
                    rows,
                    bytes: exported_bytes,
                });
                tracing::info!(
                    event = "connector.postgres_live_scan",
                    datasource = "postgres",
                    status = "success",
                    projection_pushdown,
                    rows,
                    bytes = exported_bytes,
                    duration_ms = started.elapsed().as_millis(),
                    wait_ms = (wait_seconds * 1000.0) as u64,
                );
                Ok(plan)
            }
            Err(error) => {
                observe_postgres_live_scan_error(started, wait_seconds, projection_pushdown);
                Err(error)
            }
        }
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DataFusionResult<Vec<TableProviderFilterPushDown>> {
        Ok(vec![
            TableProviderFilterPushDown::Unsupported;
            filters.len()
        ])
    }

    fn statistics(&self) -> Option<Statistics> {
        None
    }
}

fn postgres_to_datafusion_error(error: ConnectorError) -> DataFusionError {
    DataFusionError::Execution(error.to_string())
}

fn observe_postgres_live_scan_error(
    started: Instant,
    wait_seconds: f64,
    projection_pushdown: bool,
) {
    observe_live_datasource_scan(LiveScanObservation {
        datasource: "postgres",
        status: "error",
        projection_pushdown,
        duration_seconds: started.elapsed().as_secs_f64(),
        wait_seconds,
        rows: 0,
        bytes: 0,
    });
    tracing::warn!(
        event = "connector.postgres_live_scan",
        datasource = "postgres",
        status = "error",
        projection_pushdown,
        duration_ms = started.elapsed().as_millis(),
        wait_ms = (wait_seconds * 1000.0) as u64,
    );
}

fn is_pushdown_safe_projection(projection: &[usize]) -> bool {
    !projection.is_empty()
        && projection
            .iter()
            .enumerate()
            .all(|(offset, index)| !projection[..offset].contains(index))
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
            8,
        );

        let sql = connector.copy_sql_for(&connector.declared);
        assert!(sql.contains(r#"FROM (SELECT * FROM "public"."people") AS data_gate_source"#));
        assert!(sql.contains(r#"data_gate_source."id"::bigint AS "id""#));
        assert!(sql.contains(r#"data_gate_source."active"::boolean AS "active""#));
        assert!(sql.contains(r#"to_char(data_gate_source."updated_at"::timestamptz"#));
        assert!(sql.starts_with("COPY (SELECT "));
        assert!(sql.ends_with(") TO STDOUT WITH (FORMAT CSV, HEADER TRUE)"));
    }

    #[test]
    fn postgres_copy_sql_can_project_declared_column_subset() {
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
                ("name", FieldType::String),
                ("active", FieldType::Boolean),
            ]),
            256 * 1024 * 1024,
            Duration::from_secs(5),
            Duration::from_secs(30),
            8,
        );
        let projected = connector
            .declared_for_projection(Some(&[2, 0]))
            .expect("projection is valid");

        let sql = connector.copy_sql_for(&projected);

        assert!(sql.contains(r#"data_gate_source."active"::boolean AS "active""#));
        assert!(sql.contains(r#"data_gate_source."id"::bigint AS "id""#));
        assert!(!sql.contains(r#"data_gate_source."name"::text AS "name""#));
        assert!(
            sql.find(r#""active""#).expect("active appears")
                < sql.find(r#""id""#).expect("id appears")
        );
    }

    #[test]
    fn postgres_declared_projection_rejects_unknown_index() {
        let connector = PostgresConnector::new(
            "DATABASE_URL".to_string(),
            Some(PostgresTableConfig {
                schema: "public".to_string(),
                name: "people".to_string(),
            }),
            None,
            None,
            declared(vec![("id", FieldType::Integer)]),
            256 * 1024 * 1024,
            Duration::from_secs(5),
            Duration::from_secs(30),
            8,
        );

        assert!(connector.declared_for_projection(Some(&[1])).is_err());
    }

    #[test]
    fn postgres_live_projection_pushdown_requires_non_empty_unique_indices() {
        assert!(!is_pushdown_safe_projection(&[]));
        assert!(!is_pushdown_safe_projection(&[0, 0]));
        assert!(is_pushdown_safe_projection(&[2, 0]));
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
}
