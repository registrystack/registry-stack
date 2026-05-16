// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for `serde_json::to_vec` on representative record shapes.
//!
//! These cover the JSON serialization cost for the shapes `data_gate`
//! actually emits on `GET /datasets/{dataset_id}/{entity}` responses:
//! narrow, medium, and wide rows, and a paginated collection envelope.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Representative record factories
// ---------------------------------------------------------------------------

fn narrow_record() -> Value {
    // 5 fields: typical small entity.
    json!({
        "id": "facility-0042",
        "region": "north_central",
        "capacity": 120,
        "status": "active",
        "updated_at": "2026-05-16T08:00:00Z"
    })
}

fn medium_record() -> Value {
    // ~30 fields: typical enriched entity.
    json!({
        "id": "facility-0042",
        "region": "north_central",
        "capacity": 120,
        "beds_available": 42,
        "beds_occupied": 78,
        "icu_capacity": 20,
        "icu_available": 5,
        "icu_occupied": 15,
        "er_capacity": 30,
        "er_available": 10,
        "status": "active",
        "tier": "tertiary",
        "ownership": "public",
        "district": "district_07",
        "province": "north",
        "lat": 12.3456,
        "lon": -34.5678,
        "phone": "+1-555-0100",
        "email": "bench@example.test",
        "website": "https://facility-0042.example.test",
        "accredited": true,
        "accreditation_body": "ACME",
        "accreditation_expiry": "2027-12-31",
        "last_inspection": "2025-09-01",
        "staff_count": 350,
        "doctors": 45,
        "nurses": 200,
        "admin_staff": 105,
        "updated_at": "2026-05-16T08:00:00Z",
        "created_at": "2020-01-15T00:00:00Z"
    })
}

fn wide_record() -> Value {
    // ~100 fields: stress test for wide-schema entities.
    let mut obj = serde_json::Map::new();
    obj.insert("id".to_string(), json!("facility-0042"));
    for i in 0..49_u32 {
        obj.insert(
            format!("str_field_{i}"),
            json!(format!("value_{i}_abcdefghij")),
        );
    }
    for i in 0..25_u32 {
        obj.insert(format!("num_field_{i}"), json!(i * 7 + 1));
    }
    for i in 0..12_u32 {
        obj.insert(format!("bool_field_{i}"), json!(i % 2 == 0));
    }
    for i in 0..12_u32 {
        obj.insert(format!("null_field_{i}"), Value::Null);
    }
    Value::Object(obj)
}

fn collection_envelope(records: Vec<Value>) -> Value {
    json!({
        "data": records,
        "pagination": {
            "has_more": false
        }
    })
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn benchmark_json_narrow_record(c: &mut Criterion) {
    let record = narrow_record();
    c.bench_function("json/narrow_record_to_vec", |b| {
        b.iter(|| serde_json::to_vec(black_box(&record)).expect("serialize"));
    });
}

fn benchmark_json_medium_record(c: &mut Criterion) {
    let record = medium_record();
    c.bench_function("json/medium_record_to_vec", |b| {
        b.iter(|| serde_json::to_vec(black_box(&record)).expect("serialize"));
    });
}

fn benchmark_json_wide_record(c: &mut Criterion) {
    let record = wide_record();
    c.bench_function("json/wide_record_to_vec", |b| {
        b.iter(|| serde_json::to_vec(black_box(&record)).expect("serialize"));
    });
}

fn benchmark_json_collection_100_narrow(c: &mut Criterion) {
    let records: Vec<Value> = (0..100).map(|_| narrow_record()).collect();
    let envelope = collection_envelope(records);
    c.bench_function("json/collection_100_narrow_to_vec", |b| {
        b.iter(|| serde_json::to_vec(black_box(&envelope)).expect("serialize"));
    });
}

fn benchmark_json_collection_100_medium(c: &mut Criterion) {
    let records: Vec<Value> = (0..100).map(|_| medium_record()).collect();
    let envelope = collection_envelope(records);
    c.bench_function("json/collection_100_medium_to_vec", |b| {
        b.iter(|| serde_json::to_vec(black_box(&envelope)).expect("serialize"));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_json_narrow_record,
        benchmark_json_medium_record,
        benchmark_json_wide_record,
        benchmark_json_collection_100_narrow,
        benchmark_json_collection_100_medium
}
criterion_main!(benches);
