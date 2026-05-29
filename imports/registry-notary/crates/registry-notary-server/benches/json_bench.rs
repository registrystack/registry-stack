// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for the JSON serialization/deserialization hot paths.
//!
//! Covers:
//! - `EvidenceAuditEvent` serialization (written as a JSONL line on every request).
//! - `ClaimResultView` serialization (returned in /claims/evaluate and
//!   /claims/batch-evaluate responses).
//! - DCI response envelope deserialization (parsed from an upstream source on
//!   every evaluate call that reaches the source).
//! - Stage-3 bulk response deserialization for RDA (one `{"data": [...N rows]}`
//!   envelope) and DCI (one envelope with N `search_response[]` entries) at
//!   N=10 and N=100. These shapes only appear in the bulk prefetch path, so
//!   they are not covered by the single-record DCI envelope bench above.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_notary_core::model::{
    ClaimProvenance, ClaimResultView, EvidenceAuditEvent, Hashed, PrincipalIdentifier,
    SubjectBinding, SubjectRefView,
};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

fn build_audit_event() -> EvidenceAuditEvent {
    EvidenceAuditEvent {
        event_id: "01HWQZPJ3VXKM8N2BF5CSRTE4D".to_string(),
        occurred_at: "2026-05-24T12:00:00Z".to_string(),
        principal_id_hash: Some(Hashed::<PrincipalIdentifier>::from_hash(
            "hmac-sha256:client-bench-001",
        )),
        decision: "allow".to_string(),
        method: "POST".to_string(),
        path: "/claims/evaluate".to_string(),
        status: 200,
        verification_id: Some("01HWQZPJ3VXKM8N2BF5CSRTE4E".to_string()),
        claim_hash: Some(
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        ),
        purposes: None,
        row_count: None,
        error_code: None,
        access_mode: None,
        federation_peer_id_hash: None,
        federation_issuer: None,
        federation_profile: None,
        federation_purpose: None,
        federation_request_jti: None,
        federation_subject_ref_hash: None,
        denial_code: None,
        token_claim_name: None,
        correlation_id: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_version: None,
        policy_hash: None,
    }
}

fn build_claim_result_view() -> ClaimResultView {
    let mut source_versions = BTreeMap::new();
    source_versions.insert("civil-registry-stub".to_string(), "v1.2.0".to_string());

    ClaimResultView {
        evaluation_id: "01HWQZPJ3VXKM8N2BF5CSRTE4F".to_string(),
        claim_id: "date-of-birth".to_string(),
        claim_version: "1.0.0".to_string(),
        subject_type: "national_id".to_string(),
        subject_ref: SubjectRefView {
            hash: Hashed::<SubjectBinding>::from_hash("hmac-sha256:subj-0000007"),
            id_type: "national_id".to_string(),
        },
        value: Some(json!("1990-01-01")),
        satisfied: Some(true),
        disclosure: "full_disclosure".to_string(),
        format: "json".to_string(),
        issued_at: "2026-05-24T12:00:00Z".to_string(),
        expires_at: None,
        provenance: ClaimProvenance {
            source_count: 1,
            source_versions,
            computed_by: "registry-notary-server".to_string(),
        },
    }
}

fn build_dci_response_bytes() -> Vec<u8> {
    let envelope = json!({
        "header": {
            "version": "1.0.0",
            "message_id": "msg-bench-0001",
            "message_ts": "2026-05-24T12:00:00Z",
            "action": "search",
            "status": "success",
            "sender_id": "stub-source",
            "receiver_id": "registry-notary"
        },
        "message": {
            "transaction_id": "txn-bench-0001",
            "search_response": [
                {
                    "reference_id": "subj-0000007",
                    "timestamp": "2026-05-24T12:00:00Z",
                    "status": "succ",
                    "data": {
                        "reg_records": [
                            {
                                "NATIONAL_ID": "subj-0000007",
                                "birth_date": "1954-09-16",
                                "farmed_land_size_hectares": 3.42
                            }
                        ]
                    }
                }
            ]
        }
    });
    serde_json::to_vec(&envelope).expect("DCI response envelope must serialize")
}

fn build_rda_bulk_response_bytes(n: usize) -> Vec<u8> {
    let rows: Vec<Value> = (0..n)
        .map(|i| {
            json!({
                "NATIONAL_ID": format!("subj-{i:07}"),
                "birth_date": "1954-09-16",
                "farmed_land_size_hectares": 3.42,
            })
        })
        .collect();
    let envelope = json!({ "data": rows });
    serde_json::to_vec(&envelope).expect("RDA bulk envelope must serialize")
}

fn build_dci_bulk_response_bytes(n: usize) -> Vec<u8> {
    let entries: Vec<Value> = (0..n)
        .map(|i| {
            json!({
                "reference_id": format!("ref-{i:07}"),
                "timestamp": "2026-05-24T12:00:00Z",
                "status": "succ",
                "data": {
                    "reg_records": [{
                        "NATIONAL_ID": format!("subj-{i:07}"),
                        "birth_date": "1954-09-16",
                        "farmed_land_size_hectares": 3.42,
                    }]
                }
            })
        })
        .collect();
    let envelope = json!({
        "header": {
            "version": "1.0.0",
            "message_id": "msg-bench-bulk",
            "message_ts": "2026-05-24T12:00:00Z",
            "action": "search",
            "status": "success",
            "sender_id": "stub-source",
            "receiver_id": "registry-notary",
        },
        "message": {
            "transaction_id": "txn-bench-bulk",
            "search_response": entries,
        },
    });
    serde_json::to_vec(&envelope).expect("DCI bulk envelope must serialize")
}

// ---------------------------------------------------------------------------
// Benchmark functions
// ---------------------------------------------------------------------------

fn benchmark_serialize_audit_event(c: &mut Criterion) {
    let event = build_audit_event();
    c.bench_function("json/serialize_audit_event", |b| {
        b.iter(|| serde_json::to_vec(black_box(&event)).expect("audit event must serialize"));
    });
}

fn benchmark_serialize_claim_result_view(c: &mut Criterion) {
    let view = build_claim_result_view();
    c.bench_function("json/serialize_claim_result_view", |b| {
        b.iter(|| serde_json::to_vec(black_box(&view)).expect("claim result view must serialize"));
    });
}

fn benchmark_deserialize_dci_response_envelope(c: &mut Criterion) {
    let payload_bytes = build_dci_response_bytes();
    c.bench_function("json/deserialize_dci_response_envelope", |b| {
        b.iter(|| {
            serde_json::from_slice::<Value>(black_box(&payload_bytes))
                .expect("DCI response envelope must deserialize")
        });
    });
}

fn benchmark_deserialize_rda_bulk_response(c: &mut Criterion) {
    for n in [10usize, 100] {
        let payload_bytes = build_rda_bulk_response_bytes(n);
        c.bench_function(&format!("json/deserialize_rda_bulk_n{n}"), |b| {
            b.iter(|| {
                serde_json::from_slice::<Value>(black_box(&payload_bytes))
                    .expect("RDA bulk envelope must deserialize")
            });
        });
    }
}

fn benchmark_deserialize_dci_bulk_response(c: &mut Criterion) {
    for n in [10usize, 100] {
        let payload_bytes = build_dci_bulk_response_bytes(n);
        c.bench_function(&format!("json/deserialize_dci_bulk_n{n}"), |b| {
            b.iter(|| {
                serde_json::from_slice::<Value>(black_box(&payload_bytes))
                    .expect("DCI bulk envelope must deserialize")
            });
        });
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_serialize_audit_event,
              benchmark_serialize_claim_result_view,
              benchmark_deserialize_dci_response_envelope,
              benchmark_deserialize_rda_bulk_response,
              benchmark_deserialize_dci_bulk_response
}
criterion_main!(benches);
