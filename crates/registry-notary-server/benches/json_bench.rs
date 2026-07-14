// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for the JSON serialization/deserialization hot paths.
//!
//! Covers:
//! - `EvidenceAuditEvent` serialization (written as a JSONL line on every request).
//! - `ClaimResultView` serialization (returned in `/v1/evaluations` and
//!   `/v1/batch-evaluations` responses).
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_notary_core::model::{
    ClaimProvenance, ClaimResultView, EvidenceAuditEvent, EvidenceEntityRef,
    EvidenceEntityReference, Hashed, PrincipalIdentifier, TargetRefView,
};
use serde_json::json;

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
        scopes_used: vec!["farmer_registry:evidence_verification".to_string()],
        decision: "allow".to_string(),
        method: "POST".to_string(),
        path: "/v1/evaluations".to_string(),
        status: 200,
        verification_id: Some("01HWQZPJ3VXKM8N2BF5CSRTE4E".to_string()),
        claim_hash: Some(
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        ),
        purposes: None,
        row_count: None,
        relay_consultation_count: None,
        relay_consultation_ids: Vec::new(),
        forwarded: None,
        error_code: None,
        access_mode: None,
        federation_peer_id_hash: None,
        federation_issuer: None,
        federation_profile: None,
        federation_purpose: None,
        federation_request_jti_hash: None,
        federation_subject_ref_hash: None,
        denial_code: None,
        token_claim_name: None,
        correlation_id_hash: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_version: None,
        policy_hash: None,
        target_type: Some("Person".to_string()),
        target_ref_hash: Some(Hashed::<EvidenceEntityReference>::from_hash(
            "hmac-sha256:target-bench-0000007",
        )),
        requester_type: Some("Agency".to_string()),
        requester_ref_hash: Some(Hashed::<EvidenceEntityReference>::from_hash(
            "hmac-sha256:requester-bench-001",
        )),
        redacted_fields: None,
        batch_items: None,
        config: None,
    }
}

fn build_claim_result_view() -> ClaimResultView {
    ClaimResultView {
        evaluation_id: "01HWQZPJ3VXKM8N2BF5CSRTE4F".to_string(),
        claim_id: "date-of-birth".to_string(),
        claim_version: "1.0.0".to_string(),
        subject_type: "national_id".to_string(),
        requester_ref: Some(EvidenceEntityRef {
            entity_type: "Agency".to_string(),
            handle: "rnref:v1:requester-bench-001".to_string(),
            identifier_schemes: vec!["agency_id".to_string()],
            profile: Some("civil-registry".to_string()),
        }),
        target_ref: TargetRefView {
            entity_type: "Person".to_string(),
            handle: "rnref:v1:target-bench-0000007".to_string(),
            identifier_schemes: vec!["national_id".to_string()],
            profile: Some("resident".to_string()),
        },
        value: Some(json!("1990-01-01")),
        satisfied: Some(true),
        disclosure: "full_disclosure".to_string(),
        redacted_fields: Vec::new(),
        format: "json".to_string(),
        issued_at: "2026-05-24T12:00:00Z".to_string(),
        expires_at: None,
        provenance: ClaimProvenance::new(
            "registry-notary-server".to_string(),
            "eval-bench".to_string(),
            "date-of-birth".to_string(),
            "1".to_string(),
            registry_notary_core::ProvenanceUsed {
                relay_consultation_count: 1,
            },
        ),
    }
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

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_serialize_audit_event,
              benchmark_serialize_claim_result_view
}
criterion_main!(benches);
