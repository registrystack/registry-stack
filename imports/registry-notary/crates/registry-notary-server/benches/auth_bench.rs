// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for the standalone-notary auth hot path.
//!
//! Covers:
//! - `find_credential` linear scan with hashed API-key verification for a hit
//!   in a small token table and a miss against the same table.
//! - platform Bearer header parser on a typical "Bearer <token>" value
//!   and on an invalid input (missing scheme).
//!
//! Notary compares request tokens against fixed-length stored fingerprints.
//! These benches lock in the per-call cost at a realistic small N (4
//! credentials, matching the medium perf profile).

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_notary_server::standalone::{find_credential, ResolvedCredential};
use registry_platform_authcommon::parse_bearer_token;

const VALID_TOKEN: &str = "perf-bench-bearer-token-target0-0000000000-099";
const WRONG_TOKEN: &str = "perf-bench-bearer-token-wrong00-0000000000-000";

fn build_credentials() -> Vec<ResolvedCredential> {
    vec![
        cred("client_a", "perf-bench-bearer-token-clienta-0000000000-001"),
        cred("client_b", "perf-bench-bearer-token-clientb-0000000000-002"),
        cred("client_c", "perf-bench-bearer-token-clientc-0000000000-003"),
        cred("bench_client", VALID_TOKEN),
    ]
}

fn cred(id: &str, token: &str) -> ResolvedCredential {
    ResolvedCredential {
        id: id.to_string(),
        fingerprint: registry_platform_authcommon::fingerprint_api_key(token),
        scopes: vec!["civil-registry.read".into(), "farmer-registry.read".into()],
        authorization_details: None,
    }
}

fn benchmark_find_credential_hit(c: &mut Criterion) {
    let credentials = build_credentials();
    c.bench_function("auth/find_credential_hit", |b| {
        b.iter(|| find_credential(black_box(&credentials), black_box(VALID_TOKEN)));
    });
}

fn benchmark_find_credential_miss(c: &mut Criterion) {
    let credentials = build_credentials();
    c.bench_function("auth/find_credential_miss", |b| {
        b.iter(|| find_credential(black_box(&credentials), black_box(WRONG_TOKEN)));
    });
}

fn benchmark_parse_bearer_token_ok(c: &mut Criterion) {
    let header = format!("Bearer {VALID_TOKEN}");
    c.bench_function("auth/parse_bearer_token_ok", |b| {
        b.iter(|| parse_bearer_token(black_box(&header)));
    });
}

fn benchmark_parse_bearer_token_bad(c: &mut Criterion) {
    let header = format!("Basic {VALID_TOKEN}");
    c.bench_function("auth/parse_bearer_token_bad_scheme", |b| {
        b.iter(|| parse_bearer_token(black_box(&header)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_find_credential_hit,
              benchmark_find_credential_miss,
              benchmark_parse_bearer_token_ok,
              benchmark_parse_bearer_token_bad
}
criterion_main!(benches);
