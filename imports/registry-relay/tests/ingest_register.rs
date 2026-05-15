// SPDX-License-Identifier: Apache-2.0
//! Wave 1 integration tests for Source -> Format -> validation -> cache
//! -> DataFusion registration.

use std::path::Path;
use std::sync::Arc;

use data_gate::config::{self, DatasetId, ResourceId};
use data_gate::format::FormatRegistry;
use data_gate::ingest::{table_name, IngestRegistry, ReadinessSnapshot};
use datafusion::execution::context::SessionContext;
use tempfile::TempDir;
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
) -> std::path::PathBuf {
    let cache_dir = tmp.path().join("cache");
    let sheet_line = sheet
        .map(|s| format!("        sheet: {s}\n"))
        .unwrap_or_default();
    let yaml = format!(
        r#"
server:
  bind: 127.0.0.1:0
  cache_dir: "{cache_dir}"

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
    let config_path = write_config(&tmp, source_path, resource_id, sheet);
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
