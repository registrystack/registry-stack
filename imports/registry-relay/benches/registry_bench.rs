// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for dataset and entity lookup through `EntityRegistry`.
//!
//! Constructs a registry from a minimal in-memory config, then measures
//! the hot path: `registry.dataset()` and `dataset.entity()` lookups
//! that every authenticated request exercises.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_relay::entity::EntityRegistry;

// Minimal YAML config string. Inlined so the bench has no filesystem deps.
const CONFIG_YAML: &str = r#"
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
    source:
      type: file
      path: fixtures/bench.csv
    refresh:
      mode: manual
    tables:
      - id: facility_table
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
          verify_scope: clinic_capacity:verify
          bulk_export_scope: clinic_capacity:bulk_export
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

fn build_registry() -> EntityRegistry {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), CONFIG_YAML).expect("write config");
    let cfg = registry_relay::config::load(tmp.path()).expect("config loads");
    EntityRegistry::from_config(&cfg).expect("registry compiles")
}

fn benchmark_dataset_lookup_hit(c: &mut Criterion) {
    let registry = build_registry();

    c.bench_function("registry/dataset_hit", |b| {
        b.iter(|| registry.dataset(black_box("clinic_capacity")));
    });
}

fn benchmark_dataset_lookup_miss(c: &mut Criterion) {
    let registry = build_registry();

    c.bench_function("registry/dataset_miss", |b| {
        b.iter(|| registry.dataset(black_box("nonexistent_dataset")));
    });
}

fn benchmark_entity_lookup_hit(c: &mut Criterion) {
    let registry = build_registry();
    let dataset = registry
        .dataset("clinic_capacity")
        .expect("dataset present");

    c.bench_function("registry/entity_hit", |b| {
        b.iter(|| dataset.entity(black_box("facility")));
    });
}

fn benchmark_entity_lookup_miss(c: &mut Criterion) {
    let registry = build_registry();
    let dataset = registry
        .dataset("clinic_capacity")
        .expect("dataset present");

    c.bench_function("registry/entity_miss", |b| {
        b.iter(|| dataset.entity(black_box("nonexistent_entity")));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_dataset_lookup_hit,
        benchmark_dataset_lookup_miss,
        benchmark_entity_lookup_hit,
        benchmark_entity_lookup_miss
}
criterion_main!(benches);
