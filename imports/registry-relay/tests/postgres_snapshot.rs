// SPDX-License-Identifier: Apache-2.0
//! Env-gated integration coverage for Postgres snapshot ingest.
//!
//! Run with:
//! DATA_GATE_POSTGRES_TEST_URL='postgres://...?sslmode=require' cargo test --test postgres_snapshot -- --ignored

use std::env;
use std::sync::Arc;

use datafusion::arrow::array::{Float64Array, Int64Array, StringArray};
use datafusion::execution::context::SessionContext;
use postgres_native_tls::MakeTlsConnector;
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{table_name, IngestRegistry};
use tempfile::TempDir;
use tokio::sync::watch;

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

async fn postgres_client(url: &str) -> Result<tokio_postgres::Client, Box<dyn std::error::Error>> {
    let tls = native_tls::TlsConnector::builder().build()?;
    let connector = MakeTlsConnector::new(tls);
    let (client, connection) = tokio_postgres::connect(url, connector).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

#[tokio::test]
#[ignore = "requires DATA_GATE_POSTGRES_TEST_URL"]
async fn postgres_snapshot_ingests_declared_schema() -> Result<(), Box<dyn std::error::Error>> {
    let db_url = env::var("DATA_GATE_POSTGRES_TEST_URL")?;
    let schema_name = format!(
        "data_gate_test_{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    let client = postgres_client(&db_url).await?;
    client
        .batch_execute(&format!(
            r#"
CREATE SCHEMA "{schema_name}";
CREATE TABLE "{schema_name}".beneficiaries (
  beneficiary_id integer primary key,
  program text,
  amount numeric,
  active boolean,
  joined_date date,
  updated_at timestamptz
);
INSERT INTO "{schema_name}".beneficiaries
  (beneficiary_id, program, amount, active, joined_date, updated_at)
VALUES
  (1, 'cash', 12.50, true, DATE '2024-01-01', TIMESTAMPTZ '2024-01-02T03:04:05Z'),
  (2, 'food', 8.25, false, DATE '2024-01-03', TIMESTAMPTZ '2024-01-04T05:06:07Z');
"#
        ))
        .await?;

    let result = run_ingest(&db_url, &schema_name).await;
    client
        .batch_execute(&format!(r#"DROP SCHEMA "{schema_name}" CASCADE"#))
        .await?;
    result
}

#[tokio::test]
#[ignore = "requires DATA_GATE_POSTGRES_TEST_URL"]
async fn postgres_session_rejects_mutating_change_token_sql(
) -> Result<(), Box<dyn std::error::Error>> {
    let db_url = env::var("DATA_GATE_POSTGRES_TEST_URL")?;
    let schema_name = format!(
        "data_gate_test_{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    let client = postgres_client(&db_url).await?;
    client
        .batch_execute(&format!(
            r#"
CREATE SCHEMA "{schema_name}";
CREATE TABLE "{schema_name}".beneficiaries (
  beneficiary_id integer primary key,
  program text,
  updated_at timestamptz
);
INSERT INTO "{schema_name}".beneficiaries
  (beneficiary_id, program, updated_at)
VALUES
  (1, 'cash', TIMESTAMPTZ '2024-01-02T03:04:05Z');
"#
        ))
        .await?;

    let result = run_ingest_expect_failure(
        &db_url,
        &schema_name,
        &format!(
            r#"WITH d AS (DELETE FROM "{schema_name}".beneficiaries RETURNING updated_at::text AS token) SELECT max(token) FROM d"#
        ),
    )
    .await;
    let count: i64 = client
        .query_one(
            &format!(r#"SELECT count(*) FROM "{schema_name}".beneficiaries"#),
            &[],
        )
        .await?
        .get(0);
    client
        .batch_execute(&format!(r#"DROP SCHEMA "{schema_name}" CASCADE"#))
        .await?;

    result?;
    assert_eq!(count, 1, "read-only connector session must not delete rows");
    Ok(())
}

#[tokio::test]
#[ignore = "requires DATA_GATE_POSTGRES_TEST_URL"]
async fn postgres_live_table_reads_current_rows_without_reingest(
) -> Result<(), Box<dyn std::error::Error>> {
    let db_url = env::var("DATA_GATE_POSTGRES_TEST_URL")?;
    let schema_name = format!(
        "data_gate_test_{}",
        ulid::Ulid::new().to_string().to_lowercase()
    );
    let client = postgres_client(&db_url).await?;
    client
        .batch_execute(&format!(
            r#"
CREATE SCHEMA "{schema_name}";
CREATE TABLE "{schema_name}".beneficiaries (
  beneficiary_id integer primary key,
  program text,
  amount numeric,
  unsafe_number text
);
INSERT INTO "{schema_name}".beneficiaries
  (beneficiary_id, program, amount, unsafe_number)
VALUES
  (1, 'cash', 12.50, 'not_an_integer');
"#
        ))
        .await?;

    let result = run_live_ingest(&db_url, &schema_name).await;
    client
        .batch_execute(&format!(r#"DROP SCHEMA "{schema_name}" CASCADE"#))
        .await?;
    result
}

async fn run_ingest(db_url: &str, schema_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let cache_dir = tmp.path().join("cache");
    env::set_var("DATA_GATE_POSTGRES_RUNTIME_URL", db_url);
    let config_path = tmp.path().join("config.yaml");
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
          connection_env: DATA_GATE_POSTGRES_RUNTIME_URL
          table:
            schema: {schema_name}
            name: beneficiaries
          change_token_sql: 'select max(updated_at)::text from "{schema_name}".beneficiaries'
        refresh:
          mode: mtime
          interval: 5m
        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: program
              type: string
              nullable: false
            - name: amount
              type: number
              nullable: false
            - name: active
              type: boolean
              nullable: false
            - name: joined_date
              type: date
              nullable: false
            - name: updated_at
              type: timestamp
              nullable: false
    entities: []

audit:
  sink: stdout
  format: jsonl
"#,
            cache_dir.to_string_lossy()
        ),
    )?;

    let cfg = config::load(&config_path)?;
    let ctx = Arc::new(SessionContext::new());
    let registry = IngestRegistry::from_config(
        &cfg,
        Arc::new(FormatRegistry::with_v1_defaults()),
        Arc::from(cfg.server.cache_dir.as_path()),
        Arc::clone(&ctx),
    )?;
    let (tx, _rx) = watch::channel(registry.snapshot());
    registry.run_initial_ingest(tx).await;
    assert!(
        registry.snapshot().fully_ready(),
        "{:?}",
        registry.snapshot()
    );

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_postgres");
    let table = table_name(&dataset, &resource);
    let batches = ctx
        .sql(&format!(
            "select beneficiary_id, program, amount from {table} order by beneficiary_id"
        ))
        .await?
        .collect()
        .await?;
    assert_eq!(batches.len(), 1);
    let batch = &batches[0];
    assert_eq!(
        batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("id array")
            .values(),
        &[1, 2]
    );
    assert_eq!(
        batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("program array")
            .value(0),
        "cash"
    );
    assert_eq!(
        batch
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("amount array")
            .value(1),
        8.25
    );

    Ok(())
}

async fn run_live_ingest(
    db_url: &str,
    schema_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let cache_dir = tmp.path().join("cache");
    env::set_var("DATA_GATE_POSTGRES_RUNTIME_URL", db_url);
    let config_path = tmp.path().join("config.yaml");
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
        materialization: live
        source:
          type: postgres
          connection_env: DATA_GATE_POSTGRES_RUNTIME_URL
          table:
            schema: {schema_name}
            name: beneficiaries
          query_timeout: 10s
          live_max_connections: 2
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
              nullable: false
            - name: amount
              type: number
              nullable: false
            - name: unsafe_number
              type: integer
              nullable: true
    entities: []

audit:
  sink: stdout
  format: jsonl
"#,
            cache_dir.to_string_lossy()
        ),
    )?;

    let cfg = config::load(&config_path)?;
    let ctx = Arc::new(SessionContext::new());
    let registry = IngestRegistry::from_config(
        &cfg,
        Arc::new(FormatRegistry::with_v1_defaults()),
        Arc::from(cfg.server.cache_dir.as_path()),
        Arc::clone(&ctx),
    )?;
    let (tx, _rx) = watch::channel(registry.snapshot());
    registry.run_initial_ingest(tx).await;
    assert!(
        registry.snapshot().fully_ready(),
        "{:?}",
        registry.snapshot()
    );

    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("beneficiaries_postgres");
    let table = table_name(&dataset, &resource);
    let initial = ctx
        .sql(&format!(
            "select beneficiary_id, program, amount from {table} order by beneficiary_id"
        ))
        .await?
        .collect()
        .await?;
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].num_rows(), 1);

    let client = postgres_client(db_url).await?;
    client
        .execute(
            &format!(
                r#"INSERT INTO "{schema_name}".beneficiaries
                   (beneficiary_id, program, amount, unsafe_number)
                   VALUES (2, 'food', 8.25, 'still_not_an_integer')"#
            ),
            &[],
        )
        .await?;

    let after_insert = ctx
        .sql(&format!(
            "select beneficiary_id, program, amount from {table} order by beneficiary_id"
        ))
        .await?
        .collect()
        .await?;
    assert_eq!(after_insert.len(), 1);
    let batch = &after_insert[0];
    assert_eq!(batch.num_rows(), 2);
    assert_eq!(
        batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("id array")
            .values(),
        &[1, 2]
    );
    assert_eq!(
        batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("program array")
            .value(1),
        "food"
    );
    assert_eq!(
        batch
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("amount array")
            .value(1),
        8.25
    );

    let projected = ctx
        .sql(&format!("select program from {table} order by program"))
        .await?
        .collect()
        .await?;
    assert_eq!(projected.len(), 1);
    assert_eq!(projected[0].num_columns(), 1);
    assert_eq!(projected[0].num_rows(), 2);
    let programs = projected[0]
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("projected program array");
    assert_eq!(programs.value(0), "cash");
    assert_eq!(programs.value(1), "food");

    let reordered = ctx
        .sql(&format!(
            "select program, beneficiary_id from {table} order by beneficiary_id"
        ))
        .await?
        .collect()
        .await?;
    assert_eq!(reordered.len(), 1);
    assert_eq!(reordered[0].num_columns(), 2);
    assert_eq!(
        reordered[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("reordered program array")
            .value(1),
        "food"
    );
    assert_eq!(
        reordered[0]
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("reordered id array")
            .values(),
        &[1, 2]
    );

    Ok(())
}

async fn run_ingest_expect_failure(
    db_url: &str,
    schema_name: &str,
    change_token_sql: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let cache_dir = tmp.path().join("cache");
    env::set_var("DATA_GATE_POSTGRES_RUNTIME_URL", db_url);
    let config_path = tmp.path().join("config.yaml");
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
          connection_env: DATA_GATE_POSTGRES_RUNTIME_URL
          table:
            schema: {schema_name}
            name: beneficiaries
          change_token_sql: '{change_token_sql}'
        refresh:
          mode: mtime
          interval: 5m
        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: program
              type: string
              nullable: false
    entities: []

audit:
  sink: stdout
  format: jsonl
"#,
            cache_dir.to_string_lossy()
        ),
    )?;

    let cfg = config::load(&config_path)?;
    let ctx = Arc::new(SessionContext::new());
    let registry = IngestRegistry::from_config(
        &cfg,
        Arc::new(FormatRegistry::with_v1_defaults()),
        Arc::from(cfg.server.cache_dir.as_path()),
        ctx,
    )?;
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
    Ok(())
}
