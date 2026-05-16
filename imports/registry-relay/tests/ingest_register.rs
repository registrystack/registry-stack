// SPDX-License-Identifier: Apache-2.0
//! Integration tests for source -> format -> validation -> cache ->
//! DataFusion registration.

use std::path::Path;
use std::sync::Arc;

use datafusion::arrow::array::{ArrayRef, Int64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::catalog::TableProvider;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::config::{
    self, DatasetId, FieldConfig, FieldType, MaterializationMode, ResourceId, SchemaConfig,
};
use registry_relay::connector::{
    ConnectorDescriptor, ConnectorError, ConnectorFuture, ConnectorMetadata, ObservedTable,
    SnapshotTable, TableConnector,
};
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{table_name, IngestPlan, IngestRegistry, ReadinessSnapshot};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::sync::watch;

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn write_config(
    tmp: &TempDir,
    source_path: &str,
    resource_id: &str,
    sheet: Option<&str>,
    xlsx_max_file_bytes: Option<u64>,
    max_source_file_bytes: Option<u64>,
) -> std::path::PathBuf {
    let cache_dir = tmp.path().join("cache");
    let sheet_line = sheet
        .map(|s| format!("        sheet: {s}\n"))
        .unwrap_or_default();
    let xlsx_max_line = xlsx_max_file_bytes
        .map(|bytes| format!("  xlsx_max_file_bytes: {bytes}\n"))
        .unwrap_or_default();
    let max_source_line = max_source_file_bytes
        .map(|bytes| format!("  max_source_file_bytes: {bytes}\n"))
        .unwrap_or_default();
    let yaml = format!(
        r#"
server:
  bind: 127.0.0.1:0
  cache_dir: "{cache_dir}"
{xlsx_max_line}
{max_source_line}

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test Ministry

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    source:
      type: file
      path: "{source_path}"
      header_row: 1
    refresh:
      mode: manual
    resources:
      - id: {resource_id}
{sheet_line}        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: household_size
              type: integer
              nullable: false
            - name: municipality_code
              type: string
              nullable: false
            - name: program
              type: string
              nullable: false
            - name: amount_eur
              type: number
              nullable: false
            - name: joined_date
              type: date
              nullable: false
            - name: last_updated
              type: date
              nullable: true
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          row_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000

audit:
  sink: stdout
  format: jsonl
"#,
        cache_dir = cache_dir.to_string_lossy(),
        xlsx_max_line = xlsx_max_line,
        max_source_line = max_source_line,
    );
    let path = tmp.path().join(format!("{resource_id}.yaml"));
    std::fs::write(&path, yaml).expect("write config");
    path
}

async fn ingest_fixture(
    source_path: &str,
    resource_id: &str,
    sheet: Option<&str>,
) -> (TempDir, Arc<SessionContext>, ReadinessSnapshot) {
    let _ = tracing_subscriber::fmt::try_init();
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp, source_path, resource_id, sheet, None, None);
    let cfg = config::load(&config_path).expect("config loads");
    let ctx = Arc::new(SessionContext::new());
    let registry = IngestRegistry::from_config(
        &cfg,
        Arc::new(FormatRegistry::with_v1_defaults()),
        Arc::from(cfg.server.cache_dir.as_path()),
        Arc::clone(&ctx),
    )
    .expect("registry builds");
    let (tx, _rx) = watch::channel(registry.snapshot());

    registry.run_initial_ingest(tx).await;
    let snapshot = registry.snapshot();
    assert!(
        snapshot.fully_ready(),
        "expected all resources ready, got {snapshot:?}"
    );

    (tmp, ctx, snapshot)
}

async fn ingest_fixture_with_xlsx_limit(
    source_path: &str,
    resource_id: &str,
    sheet: Option<&str>,
    xlsx_max_file_bytes: u64,
) -> ReadinessSnapshot {
    let _ = tracing_subscriber::fmt::try_init();
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        source_path,
        resource_id,
        sheet,
        Some(xlsx_max_file_bytes),
        None,
    );
    let cfg = config::load(&config_path).expect("config loads");
    let ctx = Arc::new(SessionContext::new());
    let registry = IngestRegistry::from_config(
        &cfg,
        Arc::new(FormatRegistry::with_v1_defaults()),
        Arc::from(cfg.server.cache_dir.as_path()),
        ctx,
    )
    .expect("registry builds");
    let (tx, _rx) = watch::channel(registry.snapshot());

    registry.run_initial_ingest(tx).await;
    registry.snapshot()
}

async fn ingest_fixture_with_source_limit(
    source_path: &str,
    resource_id: &str,
    sheet: Option<&str>,
    max_source_file_bytes: u64,
) -> ReadinessSnapshot {
    let _ = tracing_subscriber::fmt::try_init();
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        source_path,
        resource_id,
        sheet,
        None,
        Some(max_source_file_bytes),
    );
    let cfg = config::load(&config_path).expect("config loads");
    let ctx = Arc::new(SessionContext::new());
    let registry = IngestRegistry::from_config(
        &cfg,
        Arc::new(FormatRegistry::with_v1_defaults()),
        Arc::from(cfg.server.cache_dir.as_path()),
        ctx,
    )
    .expect("registry builds");
    let (tx, _rx) = watch::channel(registry.snapshot());

    registry.run_initial_ingest(tx).await;
    registry.snapshot()
}

struct FakeLiveConnector {
    schema: SchemaRef,
    provider: Arc<dyn TableProvider>,
}

impl TableConnector for FakeLiveConnector {
    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            kind: "fake",
            target: "in-memory".to_string(),
        }
    }

    fn inspect<'a>(&'a self) -> ConnectorFuture<'a, ObservedTable> {
        Box::pin(async move {
            Ok(ObservedTable {
                schema: Arc::clone(&self.schema),
                change_token: Some("fake-token".to_string()),
                observed_at: OffsetDateTime::now_utc(),
            })
        })
    }

    fn snapshot<'a>(&'a self) -> ConnectorFuture<'a, SnapshotTable> {
        Box::pin(async { Err(ConnectorError::LiveUnsupported) })
    }

    fn live_provider<'a>(&'a self) -> ConnectorFuture<'a, Option<Arc<dyn TableProvider>>> {
        Box::pin(async move { Ok(Some(Arc::clone(&self.provider))) })
    }

    fn metadata<'a>(&'a self) -> ConnectorFuture<'a, ConnectorMetadata> {
        Box::pin(async {
            Ok(ConnectorMetadata {
                change_token: Some("fake-token".to_string()),
                observed_at: Some(OffsetDateTime::now_utc()),
            })
        })
    }
}

fn live_schema_config() -> SchemaConfig {
    SchemaConfig {
        strict: true,
        fields: vec![FieldConfig {
            name: "id".to_string(),
            r#type: FieldType::Integer,
            nullable: false,
            sensitive: false,
            concept_uri: None,
            codelist: None,
            unit: None,
            language: None,
        }],
    }
}

#[tokio::test]
async fn csv_fixture_ingests_and_registers() {
    let (_tmp, ctx, snapshot) =
        ingest_fixture(&fixture("social_registry.csv"), "beneficiaries_csv", None).await;

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_csv");
    let table = table_name(&dataset, &resource);
    assert!(ctx.table_exist(&table).expect("table_exist"));
    assert!(snapshot.ready.contains_key(&(dataset, resource)));
}

#[tokio::test]
async fn live_connector_registers_in_memory_provider() {
    let tmp = TempDir::new().expect("tempdir");
    let ctx = Arc::new(SessionContext::new());
    let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(Int64Array::from(vec![1_i64, 2, 3])) as ArrayRef],
    )
    .expect("record batch");
    let provider = Arc::new(MemTable::try_new(Arc::clone(&schema), vec![vec![batch]]).unwrap());
    let connector = Arc::new(FakeLiveConnector {
        schema: Arc::clone(&schema),
        provider,
    });
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_live");
    let plan = IngestPlan::new_with_connector(
        dataset.clone(),
        resource.clone(),
        connector,
        MaterializationMode::Live,
        live_schema_config(),
        Some("id".to_string()),
        Arc::from(tmp.path()),
        Arc::clone(&ctx),
    );

    plan.initial_ingest().await.expect("live ingest succeeds");

    let table = table_name(&dataset, &resource);
    assert!(ctx.table_exist(&table).expect("table_exist"));
    assert!(matches!(
        plan.readiness(),
        registry_relay::ingest::ResourceReadiness::Ready { .. }
    ));
}

#[tokio::test]
async fn postgres_snapshot_config_builds_registry_and_missing_env_fails_readiness() {
    let tmp = TempDir::new().expect("tempdir");
    let cache_dir = tmp.path().join("cache");
    std::env::remove_var("DATA_GATE_TEST_MISSING_DATABASE_URL");
    let config_path = tmp.path().join("postgres.yaml");
    std::fs::write(
        &config_path,
        format!(
            r#"
server:
  bind: 127.0.0.1:0
  cache_dir: "{}"

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test Ministry

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: beneficiaries_postgres
        materialization: snapshot
        source:
          type: postgres
          connection_env: DATA_GATE_TEST_MISSING_DATABASE_URL
          table:
            schema: public
            name: beneficiaries
        refresh:
          mode: manual
        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: program
              type: string
              nullable: true
    entities: []

audit:
  sink: stdout
  format: jsonl
"#,
            cache_dir.to_string_lossy()
        ),
    )
    .expect("write postgres config");

    let cfg = config::load(&config_path).expect("postgres config loads");
    let ctx = Arc::new(SessionContext::new());
    let registry = IngestRegistry::from_config(
        &cfg,
        Arc::new(FormatRegistry::with_v1_defaults()),
        Arc::from(cfg.server.cache_dir.as_path()),
        ctx,
    )
    .expect("registry builds");
    let (tx, _rx) = watch::channel(registry.snapshot());

    registry.run_initial_ingest(tx).await;

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_postgres");
    assert_eq!(
        registry
            .snapshot()
            .failed
            .get(&(dataset, resource))
            .copied(),
        Some("ingest.source_unreadable")
    );
}

#[tokio::test]
async fn xlsx_fixture_ingests_and_registers() {
    let (_tmp, ctx, snapshot) = ingest_fixture(
        &fixture("social_registry.xlsx"),
        "beneficiaries_xlsx",
        Some("data"),
    )
    .await;

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_xlsx");
    let table = table_name(&dataset, &resource);
    assert!(ctx.table_exist(&table).expect("table_exist"));
    assert!(snapshot.ready.contains_key(&(dataset, resource)));
}

#[tokio::test]
async fn xlsx_over_configured_max_fails_before_decode() {
    let source_path = fixture("social_registry.xlsx");
    let size = std::fs::metadata(&source_path)
        .expect("fixture metadata")
        .len();
    let snapshot = ingest_fixture_with_xlsx_limit(
        &source_path,
        "beneficiaries_xlsx_limit",
        Some("data"),
        size.saturating_sub(1),
    )
    .await;

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_xlsx_limit");
    assert_eq!(
        snapshot.failed.get(&(dataset, resource)).copied(),
        Some("ingest.source_unreadable")
    );
}

#[tokio::test]
async fn csv_over_configured_source_max_fails_before_decode() {
    let source_path = fixture("social_registry.csv");
    let size = std::fs::metadata(&source_path)
        .expect("fixture metadata")
        .len();
    let snapshot = ingest_fixture_with_source_limit(
        &source_path,
        "beneficiaries_csv_limit",
        None,
        size.saturating_sub(1),
    )
    .await;

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_csv_limit");
    assert_eq!(
        snapshot.failed.get(&(dataset, resource)).copied(),
        Some("ingest.source_unreadable")
    );
}

#[tokio::test]
async fn parquet_over_configured_source_max_fails_before_decode() {
    let source_path = fixture("social_registry.parquet");
    let size = std::fs::metadata(&source_path)
        .expect("fixture metadata")
        .len();
    let snapshot = ingest_fixture_with_source_limit(
        &source_path,
        "beneficiaries_parquet_limit",
        None,
        size.saturating_sub(1),
    )
    .await;

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_parquet_limit");
    assert_eq!(
        snapshot.failed.get(&(dataset, resource)).copied(),
        Some("ingest.source_unreadable")
    );
}

#[tokio::test]
async fn parquet_fixture_ingests_and_registers() {
    let (_tmp, ctx, snapshot) = ingest_fixture(
        &fixture("social_registry.parquet"),
        "beneficiaries_parquet",
        None,
    )
    .await;

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_parquet");
    let table = table_name(&dataset, &resource);
    assert!(ctx.table_exist(&table).expect("table_exist"));
    assert!(snapshot.ready.contains_key(&(dataset, resource)));
}
