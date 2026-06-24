// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for the V1 API-key authentication path.
//!
//! Covers:
//! - `ApiKeyAuth::verify` (hash + map lookup) for a hit and a miss.
//! - `extract_credential` header parsing via `ApiKeyAuth::authenticate`
//!   (the public entry point).

use std::hint::black_box;
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue};
use criterion::{criterion_group, criterion_main, Criterion};
use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use registry_relay::auth::{AuthProvider, ScopeSet};
use sha2::{Digest, Sha256};

const VALID_KEY: &str = "perf-bench-api-key-abcdef-0123456789-xyz";
const WRONG_KEY: &str = "perf-bench-api-key-wrong-000000000000-000";

fn fingerprint(plain: &str) -> String {
    let hash = Sha256::digest(plain.as_bytes());
    let mut hex = String::with_capacity(70);
    hex.push_str("sha256:");
    for byte in hash.iter() {
        hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        hex.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    hex
}

fn build_provider() -> Arc<ApiKeyAuth> {
    let entry = ApiKeyEntry::new(
        "bench_client".to_string(),
        ScopeSet::from_iter(["rows", "metadata"]),
        fingerprint(VALID_KEY),
    )
    .expect("valid fingerprint");
    Arc::new(ApiKeyAuth::new(vec![entry]))
}

fn bearer_headers(token: &str) -> HeaderMap {
    let mut map = HeaderMap::new();
    let value = format!("Bearer {token}");
    map.insert(
        axum::http::header::AUTHORIZATION,
        HeaderValue::from_str(&value).expect("valid header value"),
    );
    map
}

fn benchmark_auth_hit(c: &mut Criterion) {
    let provider = build_provider();
    let headers = bearer_headers(VALID_KEY);
    let remote: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    c.bench_function("auth/api_key_hit", |b| {
        b.to_async(&rt)
            .iter(|| provider.authenticate(black_box(&headers), black_box(remote)));
    });
}

fn benchmark_auth_miss(c: &mut Criterion) {
    let provider = build_provider();
    let headers = bearer_headers(WRONG_KEY);
    let remote: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    c.bench_function("auth/api_key_miss", |b| {
        b.to_async(&rt)
            .iter(|| provider.authenticate(black_box(&headers), black_box(remote)));
    });
}

fn benchmark_auth_missing_header(c: &mut Criterion) {
    let provider = build_provider();
    let headers = HeaderMap::new();
    let remote: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    c.bench_function("auth/missing_header", |b| {
        b.to_async(&rt)
            .iter(|| provider.authenticate(black_box(&headers), black_box(remote)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = benchmark_auth_hit, benchmark_auth_miss, benchmark_auth_missing_header
}
criterion_main!(benches);
