// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for the SD-JWT VC issuance hot path.
//!
//! Covers:
//! - `EvidenceIssuer::from_jwk_str`: JWK parsing and Ed25519 key loading.
//! - `issue` with one disclosure: the minimal single-claim credential.
//! - `issue` with three disclosures: a realistic multi-claim credential.
//!
//! All `issue` benches use holder_binding.mode = "none", holder_id = None,
//! and a fixed iat (OffsetDateTime::UNIX_EPOCH) to avoid wall-clock noise.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_notary_core::config::{
    CredentialDisclosureConfig, CredentialProfileConfig, HolderBindingConfig,
};
use registry_notary_core::model::{
    ClaimProvenance, ClaimResultView, EvidenceEntityRef, MatchingMetadata, TargetRefView,
};
use registry_notary_core::sd_jwt::{issue, EvidenceIssuer, IssueOptions};
use time::OffsetDateTime;

const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const VM_ID: &str = "did:web:perf.registry-notary.example#perf-key-1";

fn build_profile() -> CredentialProfileConfig {
    CredentialProfileConfig {
        format: registry_notary_core::FORMAT_SD_JWT_VC.to_string(),
        issuer: "did:web:perf.registry-notary.example".to_string(),
        signing_key: "perf-key".to_string(),
        vct: "https://data.example.gov/credentials/smallholder/v1".to_string(),
        validity_seconds: 24 * 60 * 60,
        holder_binding: HolderBindingConfig {
            mode: "none".to_string(),
            proof_of_possession: None,
            allowed_did_methods: Vec::new(),
        },
        allowed_claims: vec![
            "date-of-birth".into(),
            "farmer-under-4ha".into(),
            "farmed-land-size".into(),
        ],
        disclosure: CredentialDisclosureConfig::default(),
    }
}

fn build_issuer() -> EvidenceIssuer {
    EvidenceIssuer::from_jwk_str(TEST_ISSUER_JWK, VM_ID.to_string())
        .expect("test JWK must load without error")
}

fn claim_result(claim_id: &str, value: serde_json::Value) -> ClaimResultView {
    ClaimResultView {
        evaluation_id: "eval-perf-bench".to_string(),
        claim_id: claim_id.to_string(),
        claim_version: "1.0.0".to_string(),
        subject_type: "farmer".to_string(),
        requester_ref: Some(EvidenceEntityRef {
            entity_type: "Agency".to_string(),
            handle: "rnref:v1:requester-perf-ref".to_string(),
            identifier_schemes: vec!["agency_id".to_string()],
            profile: Some("benefits".to_string()),
        }),
        target_ref: TargetRefView {
            entity_type: "Farmer".to_string(),
            handle: "rnref:v1:target-perf-ref".to_string(),
            identifier_schemes: vec!["farmer_id".to_string()],
            profile: Some("smallholder".to_string()),
        },
        matching: Some(MatchingMetadata {
            policy_id: "farmer-id-exact-v1".to_string(),
            method: "identifier_exact".to_string(),
            confidence: "high".to_string(),
            score: Some(1.0),
            policy_hash: None,
            evaluated_rule_ids: Vec::new(),
            ecosystem_binding_id: None,
            ecosystem_binding_version: None,
            pack_id: None,
            pack_version: None,
        }),
        value: Some(value),
        satisfied: Some(true),
        disclosure: "value".to_string(),
        redacted_fields: Vec::new(),
        format: registry_notary_core::FORMAT_SD_JWT_VC.to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        provenance: ClaimProvenance::new(
            "bench".to_string(),
            "eval-bench".to_string(),
            "claim".to_string(),
            "1".to_string(),
            registry_notary_core::ProvenanceUsed {
                source_count: 1,
                source_versions: BTreeMap::new(),
                source_runtimes: Vec::new(),
            },
        ),
    }
}

fn build_single_claim() -> Vec<ClaimResultView> {
    vec![claim_result(
        "date-of-birth",
        serde_json::json!("1990-01-01"),
    )]
}

fn build_three_claims() -> Vec<ClaimResultView> {
    vec![
        claim_result("date-of-birth", serde_json::json!("1990-01-01")),
        claim_result("farmer-under-4ha", serde_json::json!(true)),
        claim_result("farmed-land-size", serde_json::json!(3.2)),
    ]
}

fn benchmark_evidence_issuer_from_jwk_str(c: &mut Criterion) {
    c.bench_function("sd_jwt/evidence_issuer_from_jwk_str", |b| {
        b.iter(|| {
            // `from_jwk_str` takes the verification-method id by value, so a
            // fresh `String` allocation per call is part of the measured path.
            let vm_id = black_box(VM_ID).to_string();
            EvidenceIssuer::from_jwk_str(black_box(TEST_ISSUER_JWK), vm_id).expect("JWK must load")
        });
    });
}

// `issue()` invokes `getrandom::fill` (16 bytes of CSPRNG) once per claim
// disclosure. That entropy cost is unavoidable on the production path and is
// included in the measurement. With 3 claims it accounts for 3 syscalls per
// iteration on Linux, which dominates the noise floor of these benches.
fn benchmark_issue_single_claim(c: &mut Criterion) {
    let profile = build_profile();
    let issuer = build_issuer();
    let results = build_single_claim();
    let iat = OffsetDateTime::UNIX_EPOCH;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds");
    c.bench_function("sd_jwt/issue_single_claim", |b| {
        b.iter(|| {
            runtime
                .block_on(issue(
                    black_box(&profile),
                    black_box(&issuer),
                    black_box(&results),
                    black_box("bench-subject"),
                    black_box(None),
                    black_box(iat),
                    black_box(IssueOptions::default()),
                ))
                .expect("issue must succeed")
        });
    });
}

fn benchmark_issue_three_claims(c: &mut Criterion) {
    let profile = build_profile();
    let issuer = build_issuer();
    let results = build_three_claims();
    let iat = OffsetDateTime::UNIX_EPOCH;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds");
    c.bench_function("sd_jwt/issue_three_claims", |b| {
        b.iter(|| {
            runtime
                .block_on(issue(
                    black_box(&profile),
                    black_box(&issuer),
                    black_box(&results),
                    black_box("bench-subject"),
                    black_box(None),
                    black_box(iat),
                    black_box(IssueOptions::default()),
                ))
                .expect("issue must succeed")
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_evidence_issuer_from_jwk_str,
              benchmark_issue_single_claim,
              benchmark_issue_three_claims
}
criterion_main!(benches);
