// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for audit record construction and sink write.
//!
//! Uses `InMemorySink` - the in-process sink defined in `src/audit/mod.rs` -
//! so no filesystem I/O appears in the measured path.
//!
//! Covers:
//! - `AuditRecord` struct construction (field assignment, timestamp formatting).
//! - `AuditRecord` conversion into the platform envelope record body.
//! - `AuditPipeline::write_record(record).await` (chain + serialize + mutex push).

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_relay::audit::{AuditPipeline, AuditRecord, EndpointKind, InMemorySink};

fn sample_record() -> AuditRecord {
    AuditRecord {
        ts: registry_relay::audit::now_iso8601_millis(),
        request_id: "01HZXK3PQJR8M2N4WVBT6SCDE7".to_string(),
        principal_id: Some("statistics_office".to_string()),
        auth_mode: Some("api_key".to_string()),
        remote_addr: "127.0.0.1".to_string(),
        method: "GET".to_string(),
        path: "/v1/datasets/clinic_capacity/entities/facility/records".to_string(),
        endpoint_kind: EndpointKind::Rows,
        dataset_id: Some("clinic_capacity".to_string()),
        entity_name: Some("facility".to_string()),
        table_id: Some("hmac-sha256:bench-table-id".to_string()),
        relationship: None,
        aggregate_id: None,
        underlying_kind: None,
        collection_id: None,
        primary_key: None,
        offering_id: None,
        verification_id: None,
        verification_decision: None,
        claim_hash: None,
        evidence_hash: None,
        pdp_policy_id: None,
        pdp_policy_hash: None,
        pdp_evaluated_rule_ids: None,
        pdp_stable_problem_code: None,
        pdp_ecosystem_binding_id: None,
        pdp_ecosystem_binding_version: None,
        pdp_route_identity: None,
        pdp_source_binding: None,
        pdp_checked_scopes: None,
        pdp_trust_provenance: None,
        scopes_used: vec!["clinic_capacity:rows".to_string()],
        query_params: serde_json::json!({ "limit": "100" }),
        purpose: None,
        status_code: 200,
        row_count: Some(100),
        null_geometry_count: None,
        invalid_geometry_count: None,
        geometry_vertex_count: None,
        suppressed_groups: None,
        duration_ms: 12,
        error_code: None,
        provenance: None,
        config: None,
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
                path: "/v1/datasets/clinic_capacity/entities/facility/records".to_string(),
                endpoint_kind: EndpointKind::Rows,
                dataset_id: Some("clinic_capacity".to_string()),
                entity_name: Some("facility".to_string()),
                table_id: Some("hmac-sha256:bench-table-id".to_string()),
                relationship: None,
                aggregate_id: None,
                underlying_kind: None,
                collection_id: None,
                primary_key: None,
                offering_id: None,
                verification_id: None,
                verification_decision: None,
                claim_hash: None,
                evidence_hash: None,
                pdp_policy_id: None,
                pdp_policy_hash: None,
                pdp_evaluated_rule_ids: None,
                pdp_stable_problem_code: None,
                pdp_ecosystem_binding_id: None,
                pdp_ecosystem_binding_version: None,
                pdp_route_identity: None,
                pdp_source_binding: None,
                pdp_checked_scopes: None,
                pdp_trust_provenance: None,
                scopes_used: vec!["clinic_capacity:rows".to_string()],
                query_params: serde_json::json!({ "limit": "100" }),
                purpose: None,
                status_code: 200,
                row_count: Some(100),
                null_geometry_count: None,
                invalid_geometry_count: None,
                geometry_vertex_count: None,
                suppressed_groups: None,
                duration_ms: 12,
                error_code: None,
                provenance: None,
                config: None,
            })
        });
    });
}

fn benchmark_record_to_platform_value(c: &mut Criterion) {
    let record = sample_record();
    c.bench_function("audit/record_to_platform_value", |b| {
        b.iter(|| serde_json::to_value(black_box(&record)).expect("serialize"));
    });
}

fn benchmark_sink_write(c: &mut Criterion) {
    let sink = AuditPipeline::from_sink(InMemorySink::new());
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    c.bench_function("audit/memory_sink_write", |b| {
        b.to_async(&rt)
            .iter(|| sink.write_record(black_box(sample_record())));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_record_construction,
        benchmark_record_to_platform_value,
        benchmark_sink_write
}
criterion_main!(benches);
