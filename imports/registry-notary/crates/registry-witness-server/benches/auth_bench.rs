// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for the standalone-witness auth hot path.
//!
//! Covers:
//! - `find_credential` linear scan with `subtle::ConstantTimeEq` for a hit
//!   in a small token table and a miss against the same table.
//! - `bearer_auth_token` header parser on a typical "Bearer <token>" value
//!   and on an invalid input (missing scheme).
//!
//! Witness compares tokens raw (no hashing), so `find_credential` is O(N) in
//! the number of credentials. These benches lock in the per-call cost at a
//! realistic small N (4 credentials, matching the medium perf profile).
//!
//! All five tokens below are exactly 46 bytes long. This matters because
//! `subtle::ConstantTimeEq` for byte slices short-circuits on length mismatch
//! (length is not secret). If the target token had a different length from
//! the stored credentials, `find_credential` would skip the full byte compare
//! on the mismatched entries and the bench would under-report worst-case
//! linear-scan cost. Keep lengths equal when editing.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use registry_witness_server::standalone::{bearer_auth_token, find_credential, ResolvedCredential};

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
        token: token.to_string(),
        scopes: vec!["civil-registry.read".into(), "farmer-registry.read".into()],
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

fn benchmark_bearer_auth_token_parse(c: &mut Criterion) {
    let header = format!("Bearer {VALID_TOKEN}");
    c.bench_function("auth/bearer_auth_token_parse_ok", |b| {
        b.iter(|| bearer_auth_token(black_box(&header)));
    });
}

fn benchmark_bearer_auth_token_parse_bad(c: &mut Criterion) {
    let header = format!("Basic {VALID_TOKEN}");
    c.bench_function("auth/bearer_auth_token_parse_bad_scheme", |b| {
        b.iter(|| bearer_auth_token(black_box(&header)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_find_credential_hit,
              benchmark_find_credential_miss,
              benchmark_bearer_auth_token_parse,
              benchmark_bearer_auth_token_parse_bad
}
criterion_main!(benches);
