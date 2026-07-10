// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for `EntityQueryEngine::read_collection`.
//!
//! Constructs a minimal in-memory DataFusion session (100 rows, one entity)
//! and measures query planning + execution for a default-limit collection read.
//! Uses Criterion's async_tokio support because `read_collection` is async.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use datafusion::arrow::array::{Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::config::{DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::table_name;
use registry_relay::query::{EntityCollectionQuery, EntityQueryEngine};

const CONFIG_YAML: &str = r#"
deployment:
  profile: local

server:
  bind: 127.0.0.1:0

catalog:
  title: Bench
  base_url: https://bench.example.test
  publisher: Bench

vocabularies: {}

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: clinic_capacity
    title: Clinic Capacity
    description: Synthetic perf fixture
    owner: Bench
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    tables:
      - id: facility_table
        source:
          type: file
          path: fixtures/bench.csv
        refresh:
          mode: manual
        primary_key: facility_id
        schema:
          strict: true
          fields:
            - name: facility_id
              type: string
              nullable: false
            - name: region_code
              type: string
              nullable: true
            - name: capacity
              type: integer
              nullable: true
    entities:
      - name: facility
        table: facility_table
        fields:
          - name: id
            from: facility_id
          - name: region
            from: region_code
          - name: capacity
        access:
          metadata_scope: clinic_capacity:metadata
          aggregate_scope: clinic_capacity:aggregate
          read_scope: clinic_capacity:rows
          evidence_verification_scope: clinic_capacity:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: region
              ops: [eq]

audit:
  sink: stdout
  format: jsonl
"#;

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

async fn build_engine() -> EntityQueryEngine {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), CONFIG_YAML).expect("write config");
    let cfg = registry_relay::config::load(tmp.path()).expect("config loads");
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());

    // Build 100 synthetic rows.
    const NROWS: usize = 100;
    let ids: Vec<&str> = (0..NROWS)
        .map(|i| {
            // Leaking for static lifetime - bench only, not production code.
            Box::leak(format!("facility-{i:04}").into_boxed_str()) as &str
        })
        .collect();
    let regions: Vec<Option<&str>> = (0..NROWS)
        .map(|i| {
            if i % 3 == 0 {
                Some("north")
            } else if i % 3 == 1 {
                Some("south")
            } else {
                None
            }
        })
        .collect();
    let capacities: Vec<Option<i64>> = (0..NROWS).map(|i| Some(i as i64 * 10)).collect();

    let schema = Arc::new(Schema::new(vec![
        Field::new("facility_id", DataType::Utf8, false),
        Field::new("region_code", DataType::Utf8, true),
        Field::new("capacity", DataType::Int64, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(ids)),
            Arc::new(StringArray::from(regions)),
            Arc::new(Int64Array::from(capacities)),
        ],
    )
    .expect("record batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");

    let dataset: DatasetId = id("clinic_capacity");
    let resource: ResourceId = id("facility_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register table");

    EntityQueryEngine::new(ctx, registry)
}

fn benchmark_read_collection_default(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let engine = rt.block_on(build_engine());

    c.bench_function("query/read_collection_default_limit", |b| {
        b.to_async(&rt).iter(|| {
            engine.read_collection(
                black_box("clinic_capacity"),
                black_box("facility"),
                black_box(EntityCollectionQuery::default()),
            )
        });
    });
}

fn benchmark_read_collection_with_filter(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let engine = rt.block_on(build_engine());
    use registry_relay::query::{EntityFilter, EntityFilterOp};

    c.bench_function("query/read_collection_filtered", |b| {
        b.to_async(&rt).iter(|| {
            let query = EntityCollectionQuery {
                filters: vec![EntityFilter {
                    field: "region".to_string(),
                    op: EntityFilterOp::Eq,
                    value: serde_json::json!("north"),
                }],
                ..Default::default()
            };
            engine.read_collection(
                black_box("clinic_capacity"),
                black_box("facility"),
                black_box(query),
            )
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_read_collection_default, benchmark_read_collection_with_filter
}
criterion_main!(benches);
