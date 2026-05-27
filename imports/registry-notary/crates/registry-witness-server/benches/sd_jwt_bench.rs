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
use registry_witness_core::config::{
    CredentialDisclosureConfig, CredentialProfileConfig, HolderBindingConfig,
};
use registry_witness_core::model::{
    ClaimProvenance, ClaimResultView, Hashed, SubjectBinding, SubjectRefView,
};
use registry_witness_core::sd_jwt::{issue, EvidenceIssuer};
use time::OffsetDateTime;

const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const VM_ID: &str = "did:web:perf.registry-witness.example#perf-key-1";

fn build_profile() -> CredentialProfileConfig {
    CredentialProfileConfig {
        format: registry_witness_core::FORMAT_SD_JWT_VC.to_string(),
        issuer: "did:web:perf.registry-witness.example".to_string(),
        issuer_key_env: "REGISTRY_WITNESS_ISSUER_JWK".to_string(),
        issuer_kid: Some(VM_ID.to_string()),
        vct: "https://data.example.gov/credentials/smallholder/v1".to_string(),
        validity_seconds: 24 * 60 * 60,
        holder_binding: HolderBindingConfig::default(),
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
        subject_ref: SubjectRefView {
            hash: Hashed::<SubjectBinding>::from_hash("hmac-sha256:subject-perf-ref"),
            id_type: "farmer_id".to_string(),
        },
        value: Some(value),
        satisfied: Some(true),
        disclosure: "value".to_string(),
        format: registry_witness_core::FORMAT_SD_JWT_VC.to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        provenance: ClaimProvenance {
            source_count: 1,
            source_versions: BTreeMap::new(),
            computed_by: "bench".to_string(),
        },
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
