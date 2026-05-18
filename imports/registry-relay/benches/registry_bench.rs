// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for dataset and entity lookup through `EntityRegistry`.
//!
//! Constructs a registry from an in-memory config sized to a realistic
//! deployment (10 datasets, 5 entities per dataset) so that BTreeMap
//! lookup cost reflects production rather than the degenerate single-
//! entry best case. Hit-keys are picked from the middle of the
//! BTreeMap key order to exercise an O(log N) descent rather than a
//! root-node compare.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_relay::entity::EntityRegistry;

const BENCH_NUM_DATASETS: usize = 10;
const BENCH_ENTITIES_PER_DATASET: usize = 5;

const CONFIG_HEADER: &str = "server:
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
";

const DATASET_HEADER: &str = "  - id: {DS}
    title: Dataset {DS}
    description: bench fixture
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
      - id: tbl_{DS}
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
";

const ENTITY_TEMPLATE: &str = "      - name: {ENT}
        table: tbl_{DS}
        fields:
          - name: id
            from: facility_id
          - name: region
            from: region_code
          - name: capacity
        access:
          metadata_scope: {DS}:metadata
          aggregate_scope: {DS}:aggregate
          read_scope: {DS}:rows
          verify_scope: {DS}:verify
          bulk_export_scope: {DS}:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: region
              ops: [eq]
";

const CONFIG_FOOTER: &str = "
audit:
  sink: stdout
  format: jsonl
";

fn build_config_yaml(num_datasets: usize, entities_per_dataset: usize) -> String {
    let mut yaml = String::from(CONFIG_HEADER);
    for d in 0..num_datasets {
        let ds_id = format!("ds_{:02}", d);
        yaml.push_str(&DATASET_HEADER.replace("{DS}", &ds_id));
        for e in 0..entities_per_dataset {
            let ent_id = format!("ent_{:02}", e);
            yaml.push_str(
                &ENTITY_TEMPLATE
                    .replace("{ENT}", &ent_id)
                    .replace("{DS}", &ds_id),
            );
        }
    }
    yaml.push_str(CONFIG_FOOTER);
    yaml
}

fn build_registry() -> EntityRegistry {
    let yaml = build_config_yaml(BENCH_NUM_DATASETS, BENCH_ENTITIES_PER_DATASET);
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), yaml).expect("write config");
    let cfg = registry_relay::config::load(tmp.path()).expect("config loads");
    EntityRegistry::from_config(&cfg).expect("registry compiles")
}

// Hit-key chosen from the middle of the sorted BTreeMap range so that a
// lookup walks past the root node instead of resolving on the first
// compare.
const HIT_DATASET: &str = "ds_05";
const HIT_ENTITY: &str = "ent_02";

fn benchmark_dataset_lookup_hit(c: &mut Criterion) {
    let registry = build_registry();

    c.bench_function("registry/dataset_hit", |b| {
        b.iter(|| black_box(registry.dataset(black_box(HIT_DATASET))));
    });
}

fn benchmark_dataset_lookup_miss(c: &mut Criterion) {
    let registry = build_registry();

    c.bench_function("registry/dataset_miss", |b| {
        b.iter(|| black_box(registry.dataset(black_box("nonexistent_dataset"))));
    });
}

fn benchmark_entity_lookup_hit(c: &mut Criterion) {
    let registry = build_registry();
    let dataset = registry.dataset(HIT_DATASET).expect("dataset present");

    c.bench_function("registry/entity_hit", |b| {
        b.iter(|| black_box(dataset.entity(black_box(HIT_ENTITY))));
    });
}

fn benchmark_entity_lookup_miss(c: &mut Criterion) {
    let registry = build_registry();
    let dataset = registry.dataset(HIT_DATASET).expect("dataset present");

    c.bench_function("registry/entity_miss", |b| {
        b.iter(|| black_box(dataset.entity(black_box("nonexistent_entity"))));
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
