// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for audit record construction and sink write.
//!
//! Uses `InMemorySink` - the in-process sink defined in `src/audit/mod.rs` -
//! so no filesystem I/O appears in the measured path.
//!
//! Covers:
//! - `AuditRecord` struct construction (field assignment, timestamp formatting).
//! - `AuditEnvelope::from(record)` wrapping.
//! - `InMemorySink::write(envelope).await` (serialize + mutex push).
//! - `AuditEnvelope::to_jsonl()` serialization in isolation.

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_relay::audit::{AuditEnvelope, AuditRecord, AuditSink, EndpointKind, InMemorySink};

fn sample_record() -> AuditRecord {
    AuditRecord {
        ts: registry_relay::audit::now_iso8601_millis(),
        request_id: "01HZXK3PQJR8M2N4WVBT6SCDE7".to_string(),
        principal_id: Some("statistics_office".to_string()),
        auth_mode: Some("api_key".to_string()),
        remote_addr: "127.0.0.1".to_string(),
        method: "GET".to_string(),
        path: "/datasets/clinic_capacity/facility".to_string(),
        endpoint_kind: EndpointKind::Rows,
        dataset_id: Some("clinic_capacity".to_string()),
        entity_name: Some("facility".to_string()),
        table_id: Some("facility_table".to_string()),
        relationship: None,
        aggregate_id: None,
        underlying_kind: None,
        collection_id: None,
        primary_key: None,
        scopes_used: vec!["clinic_capacity:rows".to_string()],
        query_params: serde_json::json!({ "limit": "100" }),
        purpose: None,
        status_code: 200,
        row_count: Some(100),
        null_geometry_count: None,
        invalid_geometry_count: None,
        suppressed_groups: None,
        duration_ms: 12,
        error_code: None,
        provenance: None,
    }
}

fn benchmark_record_construction(c: &mut Criterion) {
    c.bench_function("audit/record_construction", |b| {
        b.iter(|| {
            black_box(AuditRecord {
                ts: registry_relay::audit::now_iso8601_millis(),
                request_id: "01HZXK3PQJR8M2N4WVBT6SCDE7".to_string(),
                principal_id: Some("statistics_office".to_string()),
                auth_mode: Some("api_key".to_string()),
                remote_addr: "127.0.0.1".to_string(),
                method: "GET".to_string(),
                path: "/datasets/clinic_capacity/facility".to_string(),
                endpoint_kind: EndpointKind::Rows,
                dataset_id: Some("clinic_capacity".to_string()),
                entity_name: Some("facility".to_string()),
                table_id: Some("facility_table".to_string()),
                relationship: None,
                aggregate_id: None,
                underlying_kind: None,
                collection_id: None,
                primary_key: None,
                scopes_used: vec!["clinic_capacity:rows".to_string()],
                query_params: serde_json::json!({ "limit": "100" }),
                purpose: None,
                status_code: 200,
                row_count: Some(100),
                null_geometry_count: None,
                invalid_geometry_count: None,
                suppressed_groups: None,
                duration_ms: 12,
                error_code: None,
                provenance: None,
            })
        });
    });
}

fn benchmark_envelope_jsonl(c: &mut Criterion) {
    let record = sample_record();
    let envelope = AuditEnvelope::from(record);
    c.bench_function("audit/envelope_to_jsonl", |b| {
        b.iter(|| black_box(&envelope).to_jsonl().expect("serialize"));
    });
}

fn benchmark_sink_write(c: &mut Criterion) {
    let sink: Arc<InMemorySink> = Arc::new(InMemorySink::new());
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    c.bench_function("audit/memory_sink_write", |b| {
        b.to_async(&rt).iter(|| {
            let envelope = AuditEnvelope::from(sample_record());
            sink.write(black_box(envelope))
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_record_construction,
        benchmark_envelope_jsonl,
        benchmark_sink_write
}
criterion_main!(benches);
